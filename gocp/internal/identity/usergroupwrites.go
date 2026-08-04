package identity

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// The PRINCIPAL-MUTATING writes of `UserGroupStore` — Users.kt:103-240,735-830.
//
// 🔒 ALL SIX SHARE ONE SKELETON, AND THE ORDERING IS THE WHOLE SECURITY PROPERTY
// (03-identity-scim.md §"Principal-mutating writes"):
//
//  1. confirm the row exists (else nil/false)
//  2. current = lockCurrentPrincipal(c, id)   — locks the row's CURRENT principal, RE-READ under lock
//  3. releaseTombstone(c, targetPrincipal, id) — locks the TARGET principal; frees a stale tombstone
//  4. UPDATE app_user …                        — the actual mutation
//  5. if current != nil && current != target { deactivatePrincipalTombstone(current); revoke(current) }
//  6. if !active { revoke(target) }            — INDEPENDENT of step 5, not an else
//  7. all of the above inside ONE transaction
//
// 🔒 INV-A3-16 — STEPS 5 AND 6 ARE INDEPENDENT BRANCHES. A rename-and-deactivate onto a principal
// that already holds credentials "retires BOTH the old and the new string"
// (UserAdminDeprovisionDbTest case 3: the rename target has a live token/grant/session but no
// app_user row of its own). Collapsing them into if/else leaves the new string's credentials live and
// a later reactivation resurrects them.
//
// 🔒 INV-A3-17 — the retired principal is RE-READ UNDER THE LOCK, never taken from a pre-lock
// snapshot. See [lockCurrentPrincipal].
//
// 🔒 INV-A3-19 — DELETE DEPROVISIONS, NEVER HARD-DELETES. Both delete paths only flip `active`, so
// audit history keeps resolving the principal. `app_group` is the only hard delete in the area.
// ---------------------------------------------------------------------------------------------

// CreateUser is `createUser(input, tokenStore, accessStore, daemonSessionStore)` (Users.kt:113).
//
// The Kotlin runs the insert inside `inTx` and then re-reads through a FRESH connection
// (`getUser(id)!!`), so the returned row is read outside the transaction that wrote it. Reproduced.
func (s *UserGroupStore) CreateUser(
	ctx context.Context, input AppUserInput, creds CredentialTeardown,
) (AppUser, error) {
	id, err := store.InTx(ctx, s.beginner(), func(ctx context.Context, tx pgx.Tx) (int64, error) {
		created, err := s.CreateUserOn(ctx, tx, input, creds)
		if err != nil {
			return 0, err
		}
		return created.ID, nil
	})
	if err != nil {
		return AppUser{}, err
	}
	user, err := s.GetUser(ctx, id)
	if err != nil {
		return AppUser{}, err
	}
	if user == nil {
		return AppUser{}, errors.New("identity: app_user row disappeared between INSERT and re-read")
	}
	return *user, nil
}

// CreateUserOn is `createUser(input, …, c)` (Users.kt:123).
//
// 🔒 INV-A3-18 — `createUser(active = false)` MUST REVOKE, and the reason is easy to miss because
// "create" reads like it cannot need one. Users.kt:108-111: "a principal can accumulate a live wire
// token / daemon session BEFORE any app_user row exists for it at all (isDeactivated is false with no
// row), so deliberately creating it inactive must not leave those pre-existing credentials usable."
//
// `releaseTombstone(c, input.principal, null)` — excludeId is nil because there is no row to protect
// yet (INV-A3-26).
func (s *UserGroupStore) CreateUserOn(
	ctx context.Context, c store.Queryer, input AppUserInput, creds CredentialTeardown,
) (AppUser, error) {
	if err := s.releaseTombstone(ctx, c, input.Principal, nil); err != nil {
		return AppUser{}, err
	}
	var id int64
	err := c.QueryRow(ctx,
		`INSERT INTO app_user (principal, display_name, email, active) VALUES ($1, $2, $3, $4) RETURNING id`,
		input.Principal, input.DisplayName, input.Email, input.Active).Scan(&id)
	if err != nil {
		return AppUser{}, err
	}
	if !input.Active {
		if err := revoke(ctx, creds, c, input.Principal); err != nil {
			return AppUser{}, err
		}
	}
	created, err := s.GetUserOn(ctx, c, id)
	if err != nil {
		return AppUser{}, err
	}
	if created == nil {
		return AppUser{}, errors.New("identity: app_user row disappeared between INSERT and re-read")
	}
	return *created, nil
}

// UpdateUser is `updateUser(id, input, …)` (Users.kt:158); nil ⇒ no such row.
//
// The existence check runs on its OWN connection before the transaction, and the re-read after it —
// the Kotlin's shape, kept because it decides which reads can see a concurrent commit.
func (s *UserGroupStore) UpdateUser(
	ctx context.Context, id int64, input AppUserInput, creds CredentialTeardown,
) (*AppUser, error) {
	existing, err := s.GetUser(ctx, id)
	if err != nil || existing == nil {
		return nil, err
	}
	if err := store.InTxDo(ctx, s.beginner(), func(ctx context.Context, tx pgx.Tx) error {
		_, err := s.UpdateUserOn(ctx, tx, id, input, creds)
		return err
	}); err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

// UpdateUserOn is `updateUser(id, input, …, c)` (Users.kt:171) — the full skeleton, in order.
func (s *UserGroupStore) UpdateUserOn(
	ctx context.Context, c store.Queryer, id int64, input AppUserInput, creds CredentialTeardown,
) (*AppUser, error) {
	existing, err := s.GetUserOn(ctx, c, id)
	if err != nil || existing == nil {
		return nil, err
	}
	current, err := s.lockCurrentPrincipal(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if err := s.releaseTombstone(ctx, c, input.Principal, &id); err != nil {
		return nil, err
	}
	if err := updateAppUserRow(ctx, c, id, input); err != nil {
		return nil, err
	}
	// Step 5 — RENAME.
	if current != nil && *current != input.Principal {
		if err := deactivatePrincipalTombstone(ctx, c, *current); err != nil {
			return nil, err
		}
		if err := revoke(ctx, creds, c, *current); err != nil {
			return nil, err
		}
	}
	// Step 6 — DEACTIVATE. 🔒 INV-A3-16: NOT an `else`.
	if !input.Active {
		if err := revoke(ctx, creds, c, input.Principal); err != nil {
			return nil, err
		}
	}
	return s.GetUserOn(ctx, c, id)
}

// DeleteUser is the 4-arg `deleteUser(id, …)` (Users.kt:191) — a thin wrapper:
// `setActiveById(id, active = false, …) != null`.
//
// ⚠️ F37 / F27 — this overload has NO production caller: A11 always takes the 5-arg
// [UserGroupStore.DeleteUserOn]. It survives because UserAdminDeprovisionDbTest cases 7 and 8 call
// it, which means the two store-level "DELETE" tests exercise the SetActiveByID path and NOT the
// production body. REPRODUCED as a test-visible helper rather than dropped — OMIT never means "delete
// and move on" for a symbol a test still calls.
func (s *UserGroupStore) DeleteUser(ctx context.Context, id int64, creds CredentialTeardown) (bool, error) {
	updated, err := s.SetActiveByID(ctx, id, false, creds)
	if err != nil {
		return false, err
	}
	return updated != nil, nil
}

// DeleteUserOn is the 5-arg `deleteUser(id, …, c)` (Users.kt:194) — the overload A11 calls, so both
// `DELETE /api/users/{id}` and the by-principal deprovision land here.
//
// Its body is NOT the wrapper's: it has a SECOND false exit (the row vanished between the existence
// check and the locked re-read), it does not tombstone-release, and it does not rename — no target
// principal is involved.
func (s *UserGroupStore) DeleteUserOn(
	ctx context.Context, c store.Queryer, id int64, creds CredentialTeardown,
) (bool, error) {
	existing, err := s.GetUserOn(ctx, c, id)
	if err != nil || existing == nil {
		return false, err
	}
	current, err := s.lockCurrentPrincipal(ctx, c, id)
	if err != nil {
		return false, err
	}
	if current == nil {
		return false, nil
	}
	if _, err := c.Exec(ctx, `UPDATE app_user SET active = FALSE WHERE id = $1`, id); err != nil {
		return false, err
	}
	if err := revoke(ctx, creds, c, *current); err != nil {
		return false, err
	}
	return true, nil
}

// SetActiveByID is `setActiveById(id, active, …)` (Users.kt:237) — the id-stable teardown shared by
// local-admin DELETE, SCIM `PATCH replace:active=false` and SCIM DELETE. ONE implementation,
// deliberately (INV-A3-19).
//
// 🔒 The returned user's `principal` is the string the row ACTUALLY carries now, re-read under the
// lock — which is why the SCIM DELETE route can log it and be right about which identity it just
// deprovisioned.
//
// ⚠️ Note where the revoke is gated: `if !active && current != nil`. Reactivation
// (`active = true`) revokes NOTHING, which is exactly the hole F22 drives a PUT through.
func (s *UserGroupStore) SetActiveByID(
	ctx context.Context, id int64, active bool, creds CredentialTeardown,
) (*AppUser, error) {
	existing, err := s.GetUser(ctx, id)
	if err != nil || existing == nil {
		return nil, err
	}
	if err := store.InTxDo(ctx, s.beginner(), func(ctx context.Context, tx pgx.Tx) error {
		current, err := s.lockCurrentPrincipal(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE app_user SET active = $1 WHERE id = $2`, active, id); err != nil {
			return err
		}
		if !active && current != nil {
			return revoke(ctx, creds, tx, *current)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

// SetUserActive is `setUserActive(principal, active)` (Users.kt:638):
// `UPDATE app_user SET active=? WHERE principal=?`, returning `rows > 0`. **No lock, no revoke.**
//
// ⚠️ F27 — PRODUCTION-DEAD BUT FIXTURE-LIVE. Its kdoc claims it is the "SCIM active=true reactivate,
// or a local admin action" path; verified, it is not — SCIM reactivate goes through
// [UserGroupStore.SetActiveByID] (Scim.kt:454) and grep finds no other caller in main. It survives
// because NINE Kotlin suites across five areas use it as a fixture shortcut, which puts it outside
// the OMIT boundary: dropping it would mean rewriting all nine.
//
// The one correct half of that stale kdoc IS the rule that matters and is preserved: the
// credential-affecting DEACTIVATE paths go through SetActiveByID instead.
func (s *UserGroupStore) SetUserActive(ctx context.Context, principal string, active bool) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE app_user SET active=$1 WHERE principal=$2`, active, principal)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// FindUserByExternalID is `findUserByExternalId(id)` (Users.kt:565).
//
// ⚠️ F27 — public but production-dead: verified zero callers in main. It is REPRODUCED rather than
// omitted because three Kotlin suites name it (ScimUsersDbTest 6, ProvisionMergeDbTest 15, plus a
// fixture use), so it is test-visible behaviour.
func (s *UserGroupStore) FindUserByExternalID(ctx context.Context, externalID string) (*AppUser, error) {
	id, err := s.findUserIDByExternalID(ctx, s.db, externalID)
	if err != nil || id == nil {
		return nil, err
	}
	return s.GetUser(ctx, *id)
}

// FindGroupByExternalID is `findGroupByExternalId(id)` (Users.kt:566) — same F27 disposition.
func (s *UserGroupStore) FindGroupByExternalID(ctx context.Context, externalID string) (*AppGroup, error) {
	id, err := s.findGroupIDByExternalID(ctx, s.db, externalID)
	if err != nil || id == nil {
		return nil, err
	}
	return s.GetGroup(ctx, *id)
}

// ---- the private ordering primitives -------------------------------------------------------------

// updateAppUserRow is `private fun updateAppUserRow(c, id, principal, displayName, email, active)`
// (Users.kt:238). Note it does NOT touch `source` or `external_id` — only the SCIM writers do.
func updateAppUserRow(ctx context.Context, c store.Queryer, id int64, input AppUserInput) error {
	_, err := c.Exec(ctx,
		`UPDATE app_user SET principal=$1, display_name=$2, email=$3, active=$4 WHERE id=$5`,
		input.Principal, input.DisplayName, input.Email, input.Active, id)
	return err
}

// principalForUserID is `private fun principalForUserId(id, c)` (Users.kt:743) — the row's principal,
// read on the CALLER's handle so the locked re-read sees the transaction's own view.
func principalForUserID(ctx context.Context, c store.Queryer, id int64) (*string, error) {
	var out string
	err := c.QueryRow(ctx, `SELECT principal FROM app_user WHERE id=$1`, id).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// lockCurrentPrincipal is `private fun lockCurrentPrincipal(c, id): String?` (Users.kt:760).
//
// Contract: take the per-principal advisory lock on the row's principal and return THAT PRINCIPAL
// RE-READ UNDER THE LOCK, guaranteed to be the string c actually holds the lock for. nil if the row
// does not exist (defensive — every caller confirmed it moments earlier).
//
// 🔒 INV-A3-20 — THE LOOP IS LOAD-BEARING; a single-shot lock-then-read is the bug it fixes. Quoted
// from Users.kt:749-759: "the single-shot version of this could lock a stale snapshot, then re-read a
// DIFFERENT, unlocked value if a concurrent rename committed in between, and return THAT unlocked."
// Locking the new value too is harmless — the lock is re-entrant and every lock taken here releases
// together at commit.
//
// Termination, quoted: "each iteration either returns or observes a value it hasn't tried yet, and
// only a bounded number of concurrent renames can interleave with this transaction." So there is
// deliberately NO iteration cap: adding one would turn a bounded wait into a spurious error on a busy
// row. It holds an unbounded set of advisory locks in pathological cases, which is acceptable because
// they all release at commit.
func (s *UserGroupStore) lockCurrentPrincipal(
	ctx context.Context, c store.Queryer, id int64,
) (*string, error) {
	seen, err := principalForUserID(ctx, c, id)
	if err != nil || seen == nil {
		return nil, err
	}
	for {
		if err := store.AdvisoryLockPrincipal(ctx, c, *seen); err != nil {
			return nil, err
		}
		current, err := principalForUserID(ctx, c, id)
		if err != nil || current == nil {
			return nil, err
		}
		if *current == *seen {
			return current, nil
		}
		seen = current
	}
}

// deactivatePrincipalTombstone is `private fun deactivatePrincipalTombstone(principal, c)`
// (Users.kt:787).
//
// 🔒 INV-A3-21 — A RENAMED-AWAY PRINCIPAL STRING MUST BE LEFT DEPROVISIONED, NOT MERELY ORPHANED.
// Everything that authenticates or authorizes is keyed on the principal STRING and every chokepoint
// gates on `isDeactivated(principal)`; an orphaned old string with NO row at all would read
// `isDeactivated == false` (INV-A3-10) and its still-live token/session/roles would sail past.
//
// INV-A3-22 — `external_id` is left NULL DELIBERATELY, so the tombstone never collides with the
// renamed row's external_id (the unique index is partial, `WHERE external_id IS NOT NULL`) and so it
// is the marker [UserGroupStore.releaseTombstone] matches on.
//
// ⚠️ The ON CONFLICT branch sets only `active`; it does NOT normalise `source` to 'SCIM'. A
// conflicting LOCAL/OIDC row would therefore be deactivated but never match releaseTombstone's narrow
// shape, permanently squatting the string. Narrow (the renamed row just vacated the string, so a
// conflict needs a concurrent third writer) and untested — 03-identity-scim.md Q3. REPRODUCE.
func deactivatePrincipalTombstone(ctx context.Context, c store.Queryer, principal string) error {
	_, err := c.Exec(ctx,
		`INSERT INTO app_user (principal, source, active) VALUES ($1, 'SCIM', FALSE)
		 ON CONFLICT (principal) DO UPDATE SET active = FALSE`, principal)
	return err
}

// releaseTombstone is `private fun releaseTombstone(c, principal, excludeId)` (Users.kt:820).
//
// Contract: free principal for reuse by a genuinely new or renamed-back identity, and purge the stale
// direct grants attached to that string — WITHOUT ever deleting a real inactive user.
//
// 🔒 The advisory lock is taken FIRST, "so this can't race a concurrent writer reusing the same
// retired string."
//
// 🔒 INV-A3-23 — THE TOMBSTONE MATCH IS DELIBERATELY NARROW: ALL FOUR PREDICATES, ALWAYS. It "matches
// ONLY the exact shape deactivatePrincipalTombstone creates … so a genuinely distinct inactive
// identity — a real SCIM user with its own external_id, or a local admin's deliberately-deactivated
// user — is NEVER silently deleted, only our own synthetic teardown artifact is." Dropping any one
// predicate turns a rename into silent deletion of a real user.
//
// 🔒 INV-A3-24 — THE principal_role PURGE IS A PRIVILEGE-ESCALATION FIX AND RUNS BEFORE THE excludeId
// FILTER. Revoking tokens/grants/sessions does NOT touch `principal_role`, which is keyed purely on
// the principal STRING and independent of `app_user`. While the string stays tombstoned that is
// harmless (Resolve short-circuits to empty), but the moment the string is handed to a genuinely
// different identity and goes active again, a stale direct grant would silently reattach — privilege
// escalation via principal recycling. The ordering matters because `upsertScimUser`'s fallback
// principal-match can resolve existingId onto the TOMBSTONE ROW ITSELF, in which case the app_user
// DELETE below is correctly excluded but the STRING is still being handed to a new identity and the
// stale grant must still go.
//
// 🔒 INV-A3-25 — without the release, a tombstone squats a UNIQUE column forever: `app_user.principal`
// is globally UNIQUE, so renaming a different identity onto that string would 500.
//
// INV-A3-26 — excludeId guards the very row the caller is about to update. CreateUser passes nil; every
// other caller passes the row's id.
func (s *UserGroupStore) releaseTombstone(
	ctx context.Context, c store.Queryer, principal string, excludeID *int64,
) error {
	if err := store.AdvisoryLockPrincipal(ctx, c, principal); err != nil {
		return err
	}
	var probe int
	err := c.QueryRow(ctx,
		`SELECT 1 FROM app_user WHERE principal = $1 AND source = 'SCIM' AND external_id IS NULL AND NOT active`,
		principal).Scan(&probe)
	if errors.Is(err, pgx.ErrNoRows) {
		// Not a tombstone ⇒ return, doing nothing.
		return nil
	}
	if err != nil {
		return err
	}

	if _, err := c.Exec(ctx, `DELETE FROM principal_role WHERE principal = $1`, principal); err != nil {
		return err
	}

	sql := `DELETE FROM app_user WHERE principal = $1 AND source = 'SCIM' AND external_id IS NULL AND NOT active`
	args := []any{principal}
	if excludeID != nil {
		sql += ` AND id <> $2`
		args = append(args, *excludeID)
	}
	_, err = c.Exec(ctx, sql, args...)
	return err
}

// userIDForPrincipal is `private fun userIdForPrincipal(principal)` (Users.kt:735) — the third and
// last arm of upsertScimUser's match order.
func (s *UserGroupStore) userIDForPrincipal(ctx context.Context, c store.Queryer, principal string) (*int64, error) {
	return scanOptionalID(ctx, c, `SELECT id FROM app_user WHERE principal=$1`, principal)
}

// findUserIDByExternalID is `private fun findUserIdByExternalId(externalId)` (Users.kt:832).
func (s *UserGroupStore) findUserIDByExternalID(ctx context.Context, c store.Queryer, externalID string) (*int64, error) {
	return scanOptionalID(ctx, c, `SELECT id FROM app_user WHERE external_id=$1`, externalID)
}

// findUserIDByEmail is `private fun findUserIdByEmail(email)` (Users.kt:839).
//
// ⚠️ F23 — `app_user.email` has NO unique constraint and NO index at all (V1__identity.sql:19 gives
// UNIQUE only to `principal`, :41 a partial unique index to `external_id`), and this query has no
// ORDER BY and no LIMIT, so with two rows sharing an email the match is whichever row Postgres
// returns first — i.e. nondeterministic. V1's own comment explains exactly this hazard for
// external_id ("a later active=false push would deactivate whichever row Postgres returned first
// while the real one stayed credentialed") yet email escapes it. REPRODUCE: no ORDER BY is added
// here, because adding one would make a nondeterministic bug deterministic and hide it.
func (s *UserGroupStore) findUserIDByEmail(ctx context.Context, c store.Queryer, email string) (*int64, error) {
	return scanOptionalID(ctx, c, `SELECT id FROM app_user WHERE email=$1`, email)
}

// findGroupIDByExternalID is `private fun findGroupIdByExternalId(externalId)` (Users.kt:846) — the
// STANDALONE resolver, which opens its own connection.
//
// ⚠️ It must NOT be mixed into [UserGroupStore.UpsertScimGroup]'s atomic path; that method has its own
// connection-scoped twin. Users.kt:823 warns about exactly this and INV-A3-33 is why.
func (s *UserGroupStore) findGroupIDByExternalID(ctx context.Context, c store.Queryer, externalID string) (*int64, error) {
	return scanOptionalID(ctx, c, `SELECT id FROM app_group WHERE external_id=$1`, externalID)
}

func scanOptionalID(ctx context.Context, c store.Queryer, sql string, arg any) (*int64, error) {
	var id int64
	err := c.QueryRow(ctx, sql, arg).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// beginner is the pool as a transaction starter. [UserGroupStore] holds a store.DB, which is both a
// Beginner and a Queryer; the Kotlin's `dataSource.inTx { … }` is exactly this.
func (s *UserGroupStore) beginner() store.Beginner { return s.db }
