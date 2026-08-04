package oidc

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// DirectoryProvisioner is `class OidcDirectoryProvisioner(private val dataSource: DataSource)`
// (auth/OidcDirectoryProvisioner.kt:10) — "the shared OIDC JIT directory reconciler used by every
// control-plane login surface, so app_user/app_group/group_member semantics cannot drift between web,
// device, and MCP OAuth flows."
//
// ⚠️ Lifecycle note, reproduced by being irrelevant: the Kotlin constructs a FRESH instance on every
// login (`Users.kt:350` is the only construction site). Free, because it holds nothing but the
// DataSource — but it means there is no place to hang per-principal state, which is why the
// concurrency caveat below has no lock to point at.
type DirectoryProvisioner struct{ db store.DB }

// NewDirectoryProvisioner wires the reconciler over the shared pool.
func NewDirectoryProvisioner(db store.DB) *DirectoryProvisioner { return &DirectoryProvisioner{db: db} }

// Provision is `fun provision(principal, email, idpGroups, mapping): Long` — returns the
// `app_user.id`.
//
// One transaction, seven steps (auth/OidcDirectoryProvisioner.kt:17-59):
//
//  1. Upsert the user.
//  2. Re-read the id, erroring if the row somehow is not there.
//  3. Resolve the claim through the mapping and ensure each target group exists.
//  4. Read the user's CURRENT group ids.
//  5. Insert target − current.
//  6. Delete current − target.
//  7. Commit.
//
// 🔒 INV-A14-37 — membership is FULLY RECONCILED to the claim, not merged into it. A3's own KDoc
// states the rule and its accepted cost (Users.kt:335-341): "the user's membership is reconciled to
// exactly it — added where missing, REMOVED where no longer claimed (so dropping someone from the IdP
// admin group revokes their `system:admin` on their next login) … a manual/SCIM group assignment for
// that user is reconciled away (accepted for now — no membership-origin column yet)."
//
// ⚠️ F40 — a STALE, CONTRADICTING KDoc sits immediately above that one (Users.kt:328-333) saying the
// function "never removes a membership". Kotlin attaches the LAST of two consecutive KDoc blocks, so
// the reconciling one wins; a port author who reads the first block implements the wrong semantics.
// This comment exists so that cannot happen here.
//
// 🔒 INV-A14-38 — the two membership writes deliberately BYPASS A3's route-level SYSTEM-group
// immutability guard, quoted from Users.kt:341-342: "membership of `system:admin` is system-managed
// here, not hand-edited." A port must not route them through A3's guarded membership service.
//
// ⚠️ Concurrency, reproduced: there is NO advisory lock and no row lock on the user, so two concurrent
// logins for the same principal can interleave their add/delete deltas. Two logins computing the same
// target set are harmless; two with different claims can leave either result, transiently a union or
// an intersection. Untested in the Kotlin too. Contrast A11's replaceDirectRoles, which DOES take the
// lock (A11/F19) — the asymmetry is real and is not this port's to resolve.
func (p *DirectoryProvisioner) Provision(
	ctx context.Context, principal string, email *string, idpGroups []string, mapping GroupMapping,
) (int64, error) {
	return store.InTx(ctx, p.db, func(ctx context.Context, tx pgx.Tx) (int64, error) {
		// Step 1 — the upsert.
		//
		// 🔒 INV-A14-35 — SCIM WINS, and the conflict is ABSORBED rather than raised. The
		// `WHERE app_user.source <> 'SCIM'` on the DO UPDATE leaves a SCIM-managed row COMPLETELY
		// untouched (email, source, active) while still letting the login succeed. A3's rule:
		// "never clobbers a source=SCIM user — SCIM is authoritative once it manages a principal."
		//
		// 🔒 `email = COALESCE(EXCLUDED.email, app_user.email)` — a login whose id_token omits
		// `email` must not ERASE a known address.
		//
		// 🔒 INV-A14-36 — `active` is set ONLY on INSERT. The DO UPDATE set-list is `email, source`
		// and deliberately omits it, so a JIT login CANNOT reactivate a deactivated account. That is
		// the containment for A3's deprovisioning: without it, anyone deactivated could log in again
		// and resurrect themselves. ⚠️ There is NO comment saying so in the Kotlin — the invariant
		// lives only in the shape of the set-list, which is exactly the kind of thing a port "tidies
		// up" (14-auth.md §8 Q2). Adding `active = TRUE` here is a privilege-restoration bug.
		if _, err := tx.Exec(ctx,
			`INSERT INTO app_user (principal, email, source, active)
			     VALUES ($1, $2, 'OIDC', TRUE)
			     ON CONFLICT (principal) DO UPDATE
			     SET email = COALESCE(EXCLUDED.email, app_user.email), source = EXCLUDED.source
			     WHERE app_user.source <> 'SCIM'`,
			principal, email); err != nil {
			return 0, fmt.Errorf("oidc provision: upsert app_user: %w", err)
		}

		// Step 2 — the defensive assertion. After step 1 the row exists whether inserted, updated,
		// or left alone (the SCIM case). The Kotlin throws IllegalStateException, rolling the
		// transaction back; the returned error does the same through InTx's deferred rollback.
		userID, err := userIDOf(ctx, tx, principal)
		if err != nil {
			return 0, err
		}
		if userID == nil {
			return 0, fmt.Errorf("OIDC provision did not leave an app_user row for %q", principal)
		}

		// Step 3 — resolve, then ensure. Resolve's order (first appearance in the claim) is
		// preserved into ensureGroup, so a fresh install creates rows in claim order.
		target := make(map[int64]struct{})
		targetOrder := make([]int64, 0, len(idpGroups))
		for _, name := range mapping.Resolve(idpGroups) {
			id, err := ensureGroup(ctx, tx, name)
			if err != nil {
				return 0, err
			}
			if _, dup := target[id]; !dup {
				target[id] = struct{}{}
				targetOrder = append(targetOrder, id)
			}
		}

		// Step 4 — EVERY group_member row for the user, regardless of the group's `source`. That
		// breadth is what makes step 6 revoke a manually-assigned group too (INV-A14-37's accepted
		// cost).
		current, err := groupIDs(ctx, tx, *userID)
		if err != nil {
			return 0, err
		}

		// Steps 5 and 6. JDBC's executeBatch() with ZERO added batches is legal and returns an empty
		// array, so an empty delta is a no-op rather than an error; the loops below have the same
		// property without needing an IN (...) or COPY special case (14-auth.md's "JDBC detail for
		// the port").
		for _, gid := range targetOrder {
			if _, have := current[gid]; have {
				continue
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO group_member (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
				gid, *userID); err != nil {
				return 0, fmt.Errorf("oidc provision: add group_member: %w", err)
			}
		}
		for gid := range current {
			if _, keep := target[gid]; keep {
				continue
			}
			if _, err := tx.Exec(ctx,
				`DELETE FROM group_member WHERE group_id = $1 AND user_id = $2`,
				gid, *userID); err != nil {
				return 0, fmt.Errorf("oidc provision: remove group_member: %w", err)
			}
		}
		return *userID, nil
	})
}

// ensureGroup is `private fun Connection.ensureGroup(name: String): Long`
// (auth/OidcDirectoryProvisioner.kt:68-76).
//
// 🔒 INV-A14-39 — `DO UPDATE SET name = EXCLUDED.name` is a deliberate NO-OP SELF-ASSIGNMENT, and
// changing it to touch `source` is a PRIVILEGE-ESCALATION bug. Two things depend on the exact shape:
//
//  1. It exists only so RETURNING id fires on conflict. `ON CONFLICT DO NOTHING … RETURNING id`
//     returns NO ROW in Postgres, and the Kotlin's unchecked `result.next(); getLong(1)` would then
//     throw.
//  2. Because it does not touch `source`, an EXISTING group keeps its own. A group already `SCIM` or
//     `SYSTEM` is not flipped to `OIDC`. "Simplifying" this to `DO UPDATE SET source = 'OIDC'` would
//     flip the seeded `system:admin` group to source='OIDC' and defeat every A3 guard keyed on
//     source='SYSTEM'. A3's ProvisionMergeDbTest case "provisionFromOidc reuses an existing group's
//     source, whatever it is" pins this.
//
// ⚠️ Minor cost, reproduced: the no-op UPDATE still takes a row lock and writes a dead tuple on every
// login for every claimed group.
//
// ⚠️ F41 — V1 documents `app_group.source` as `-- LOCAL | SCIM` (V1__identity.sql:32), but this writes
// 'OIDC' and A3 relies on 'SYSTEM'. Four values, two documented. Stale comment, not a behaviour bug.
func ensureGroup(ctx context.Context, c store.Queryer, name string) (int64, error) {
	var id int64
	err := c.QueryRow(ctx,
		`INSERT INTO app_group (name, source) VALUES ($1, 'OIDC')
		     ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		     RETURNING id`, name).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("oidc provision: ensure group %q: %w", name, err)
	}
	return id, nil
}

// userIDOf is `private fun Connection.userId(principal): Long?` (:62-66).
func userIDOf(ctx context.Context, c store.Queryer, principal string) (*int64, error) {
	var id int64
	err := c.QueryRow(ctx, `SELECT id FROM app_user WHERE principal = $1`, principal).Scan(&id)
	switch {
	case err == nil:
		return &id, nil
	case err == pgx.ErrNoRows:
		return nil, nil
	default:
		return nil, fmt.Errorf("oidc provision: read app_user id: %w", err)
	}
}

// groupIDs is `private fun Connection.groupIds(userId): Set<Long>` (:78-84).
func groupIDs(ctx context.Context, c store.Queryer, userID int64) (map[int64]struct{}, error) {
	rows, err := c.Query(ctx, `SELECT group_id FROM group_member WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("oidc provision: read group_member: %w", err)
	}
	defer rows.Close()
	out := map[int64]struct{}{}
	for rows.Next() {
		var gid int64
		if err := rows.Scan(&gid); err != nil {
			return nil, err
		}
		out[gid] = struct{}{}
	}
	return out, rows.Err()
}

// Provisioner adapts [DirectoryProvisioner] to the [UserGroupProvisioner] seam, so a composition root
// with no A3 store yet can still wire the callback.
//
//	TODO(A3): delete this once UserGroupStore.provisionFromOidc exists — Users.kt:350's delegation is
//	          the real shape, and this adapter is only here so the OIDC flow is testable end-to-end
//	          before A3's method lands.
type Provisioner struct{ *DirectoryProvisioner }

var _ UserGroupProvisioner = Provisioner{}

// ProvisionFromOidc discards the returned app_user.id, exactly as `oidcRoutes` does.
func (p Provisioner) ProvisionFromOidc(
	ctx context.Context, principal string, email *string, idpGroups []string, mapping GroupMapping,
) error {
	_, err := p.Provision(ctx, principal, email, idpGroups, mapping)
	return err
}
