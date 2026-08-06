package identity

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// The SCIM upsert / replace half of `UserGroupStore` — Users.kt:370-560.
// ---------------------------------------------------------------------------------------------

// SystemGroupImmutableError is
// `class SystemGroupImmutableException : RuntimeException("system-managed group is immutable")`
// (Users.kt:562).
//
// 🔒 It is raised INSIDE the resolve/check/mutate transaction "so the check is atomic with the
// write"; the SCIM route catches it and answers 409 `mutability`. A port must keep the failure inside
// the transaction boundary — returning a sentinel from a helper that runs OUTSIDE it re-opens
// INV-A3-33.
type SystemGroupImmutableError struct{}

func (*SystemGroupImmutableError) Error() string { return "system-managed group is immutable" }

// ErrSystemGroupImmutable is the value every call site matches with errors.Is/As.
var ErrSystemGroupImmutable = &SystemGroupImmutableError{}

// UpsertScimUser is
// `upsertScimUser(externalId, principal, email, displayName, active, tokenStore, accessStore,
// daemonSessionStore)` (Users.kt:398) — the 8-arg overload, the one both POST /Users and the tests
// reach.
//
// 🔒 INV-A3-31 — THE MATCH ORDER external_id → email → principal IS THE ANTI-DUPLICATION RULE: "so a
// prior JIT (source=OIDC) row is reconciled to source=SCIM instead of duplicated once the IdP starts
// managing the principal via SCIM." external_id comes first because the IdP may have changed both
// userName and email on the same identity.
//
// ⚠️ F34 — the three resolution reads happen on the STORE's handle, OUTSIDE the transaction, and the
// Groups twin was deliberately hardened the other way (see [UserGroupStore.UpsertScimGroup] and
// INV-A3-33). The Users path never got the same treatment; lockCurrentPrincipal's re-read loop
// mitigates but does not close it. REPRODUCE — moving the resolution inside the transaction here
// would be a security FIX during a port, i.e. an unreviewed behaviour change on the hottest
// provisioning path.
//
// ⚠️ The Kotlin's 5-arg convenience overload — which self-constructs `TokenStore(dataSource)`,
// `AccessStore(dataSource)`, `PrincipalSessionStore(dataSource, null)` so that "no 'half-safe' upsert
// path tombstones without revoking" — is a JVM/DI artifact with no Go analogue: this package cannot
// import internal/token or internal/access without inverting the dependency direction. DEVIATION,
// recorded: Go callers pass the teardown explicitly, and passing nil is the only way to get the
// half-safe path the Kotlin makes impossible. ProvisionMergeDbTest case 9 (which exists solely to
// prove the convenience overload still tears down) becomes an assertion that THIS overload does.
func (s *UserGroupStore) UpsertScimUser(
	ctx context.Context,
	externalID, principal string,
	email, displayName *string,
	active bool,
	creds CredentialTeardown,
) (AppUser, error) {
	existingID, err := s.resolveScimUserID(ctx, externalID, principal, email)
	if err != nil {
		return AppUser{}, err
	}

	id, err := store.InTx(ctx, s.beginner(), func(ctx context.Context, tx pgx.Tx) (int64, error) {
		// Lock + RE-READ the row's current principal before mutating it (INV-A3-17/-20).
		var current *string
		if existingID != nil {
			current, err = s.lockCurrentPrincipal(ctx, tx, *existingID)
			if err != nil {
				return 0, err
			}
		}
		if err := s.releaseTombstone(ctx, tx, principal, existingID); err != nil {
			return 0, err
		}

		var rowID int64
		if existingID != nil {
			if err := updateScimAppUserRow(ctx, tx, *existingID, principal, displayName, email, externalID, active); err != nil {
				return 0, err
			}
			rowID = *existingID
		} else {
			rowID, err = insertScimAppUserRow(ctx, tx, principal, displayName, email, externalID, active)
			if err != nil {
				return 0, err
			}
		}

		// Rename: retire the orphaned old string — tombstone + revoke its credentials.
		if current != nil && *current != principal {
			if err := deactivatePrincipalTombstone(ctx, tx, *current); err != nil {
				return 0, err
			}
			if err := revoke(ctx, creds, tx, *current); err != nil {
				return 0, err
			}
		}
		// Deactivate: revoke the current principal atomically with the app_user write.
		// 🔒 INV-A3-16 — independent of the rename branch above.
		if !active {
			if err := revoke(ctx, creds, tx, principal); err != nil {
				return 0, err
			}
		}
		return rowID, nil
	})
	if err != nil {
		return AppUser{}, err
	}

	user, err := s.GetUser(ctx, id)
	if err != nil {
		return AppUser{}, err
	}
	if user == nil {
		return AppUser{}, errors.New("identity: app_user row disappeared after upsertScimUser")
	}
	return *user, nil
}

// resolveScimUserID is Users.kt:405-407 verbatim:
// `findUserIdByExternalId(externalId) ?: email?.let { findUserIdByEmail(it) } ?: userIdForPrincipal(principal)`
// — each on its own connection, all three outside the transaction (F34).
func (s *UserGroupStore) resolveScimUserID(
	ctx context.Context, externalID, principal string, email *string,
) (*int64, error) {
	id, err := s.findUserIDByExternalID(ctx, s.db, externalID)
	if err != nil || id != nil {
		return id, err
	}
	if email != nil {
		id, err = s.findUserIDByEmail(ctx, s.db, *email)
		if err != nil || id != nil {
			return id, err
		}
	}
	return s.userIDForPrincipal(ctx, s.db, principal)
}

// ReplaceScimUserByID is
// `replaceScimUserById(id, principal, email, displayName, externalId, active, …)` (Users.kt:441) —
// the SCIM PUT path. nil ⇒ no such row (404 at the route).
//
// 🔒 INV-A3-32 — PUT ADDRESSES THIS ID AND MUST NEVER RE-DISCOVER A DIFFERENT ROW. Quoted: "a PUT
// whose body fields happen to match some other existing row must not silently mutate THAT row instead
// of the one at this URI — that's not a 'replace', it's an accidental cross-resource write."
// ScimUsersDbTest case 9 constructs exactly the trap (a second row owning the email the PUT body
// reuses) and asserts the other row is untouched. **This is the sharpest behavioural difference
// between POST and PUT and the easiest thing to "simplify" wrongly in a port** — there is deliberately
// NO call to resolveScimUserID here.
//
// Identical teardown skeleton otherwise: tombstone-release, rename branch, deactivate branch, one
// transaction, per-principal lock, retired principal re-read under it.
func (s *UserGroupStore) ReplaceScimUserByID(
	ctx context.Context,
	id int64,
	principal string,
	email, displayName *string,
	externalID string,
	active bool,
	creds CredentialTeardown,
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
		if err := s.releaseTombstone(ctx, tx, principal, &id); err != nil {
			return err
		}
		if err := updateScimAppUserRow(ctx, tx, id, principal, displayName, email, externalID, active); err != nil {
			return err
		}
		if current != nil && *current != principal {
			if err := deactivatePrincipalTombstone(ctx, tx, *current); err != nil {
				return err
			}
			if err := revoke(ctx, creds, tx, *current); err != nil {
				return err
			}
		}
		if !active {
			return revoke(ctx, creds, tx, principal)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

// updateScimAppUserRow is `private fun updateScimAppUserRow(...)` (Users.kt:466). It sets `source` to
// the literal 'SCIM' — this is the statement that reconciles a prior OIDC row (INV-A3-31).
func updateScimAppUserRow(
	ctx context.Context, c store.Queryer, id int64,
	principal string, displayName, email *string, externalID string, active bool,
) error {
	_, err := c.Exec(ctx,
		`UPDATE app_user
		    SET principal=$1, display_name=$2, email=$3, source='SCIM', external_id=$4, active=$5
		  WHERE id=$6`,
		principal, displayName, email, externalID, active, id)
	return err
}

// insertScimAppUserRow is `private fun insertScimAppUserRow(...)` (Users.kt:487).
func insertScimAppUserRow(
	ctx context.Context, c store.Queryer,
	principal string, displayName, email *string, externalID string, active bool,
) (int64, error) {
	var id int64
	err := c.QueryRow(ctx,
		`INSERT INTO app_user (principal, display_name, email, source, external_id, active)
		 VALUES ($1, $2, $3, 'SCIM', $4, $5) RETURNING id`,
		principal, displayName, email, externalID, active).Scan(&id)
	return id, err
}

// UpsertScimGroup is `upsertScimGroup(externalId, displayName)` (Users.kt:512) — matching an existing
// row by `external_id → name`, EVERYTHING inside ONE transaction.
//
// 🔒 INV-A3-33 — RESOLVE, CHECK AND MUTATE MUST TARGET ONE ID INSIDE ONE TRANSACTION UNDER A ROW LOCK.
// The reason is a FIXED TOCTOU, quoted in full because a port that moves the guard back to the route
// reintroduces an admin-conferring bug: "A route-level guard that resolved external_id→name on its own
// connection and then let this method re-resolve on another was defeatable by a TOCTOU: a concurrent
// PUT /Groups/{id} moving an external_id off an ordinary group BETWEEN the two resolutions made the
// guard inspect the ordinary group (pass) while this method then re-resolved to the seeded
// system:admin by name and flipped it to source=SCIM — conferring admin and defeating every
// source-based guard."
//
// 🔒 INV-A3-34 — the seeded `system:admin` group always matches BY NAME, so it can never be created
// or hijacked here. The three resolvers below are connection-scoped ON PURPOSE; the standalone
// [UserGroupStore.findGroupIDByExternalID] opens its own connection and must NOT be mixed in.
//
// ⚠️ F36 — the guard compares the `source` COLUMN against 'SYSTEM', never the string "system:admin".
// V8__seed.sql seeds SEVEN source=SYSTEM groups and only one of them is ever named in a Kotlin test.
func (s *UserGroupStore) UpsertScimGroup(ctx context.Context, externalID, displayName string) (AppGroup, error) {
	id, err := store.InTx(ctx, s.beginner(), func(ctx context.Context, tx pgx.Tx) (int64, error) {
		existingID, err := groupIDByExternalID(ctx, tx, externalID)
		if err != nil {
			return 0, err
		}
		if existingID == nil {
			existingID, err = groupIDByName(ctx, tx, displayName)
			if err != nil {
				return 0, err
			}
		}

		if existingID != nil {
			// Re-read the resolved row's source UNDER a row lock, then mutate that SAME id.
			source, err := lockGroupSource(ctx, tx, *existingID)
			if err != nil {
				return 0, err
			}
			if source != nil && *source == SystemSource {
				return 0, ErrSystemGroupImmutable
			}
			if _, err := tx.Exec(ctx,
				`UPDATE app_group SET name=$1, source='SCIM', external_id=$2 WHERE id=$3`,
				displayName, externalID, *existingID); err != nil {
				return 0, err
			}
			return *existingID, nil
		}

		var created int64
		err = tx.QueryRow(ctx,
			`INSERT INTO app_group (name, source, external_id) VALUES ($1, 'SCIM', $2) RETURNING id`,
			displayName, externalID).Scan(&created)
		return created, err
	})
	if err != nil {
		return AppGroup{}, err
	}
	group, err := s.GetGroup(ctx, id)
	if err != nil {
		return AppGroup{}, err
	}
	if group == nil {
		return AppGroup{}, errors.New("identity: app_group row disappeared after upsertScimGroup")
	}
	return *group, nil
}

// ReplaceScimGroupByID is `replaceScimGroupById(id, externalId, displayName)` (Users.kt:551) — the
// SCIM PUT path. nil ⇒ no such row.
//
// ⚠️ ASYMMETRIC WITH UpsertScimGroup, and deliberately so: the UPDATE runs on its OWN connection,
// with NO transaction and NO `FOR UPDATE`, and there is NO SYSTEM check here at all — the route
// checks `isSystemGroup(existing.id)` BEFORE calling (Scim.kt:524), i.e. the very route-level,
// separate-connection pattern INV-A3-33 was hardened away from, still in place on the PUT path. It is
// narrower (a PUT addresses an id, so there is no re-resolution to race) but it is not the same
// guarantee. INV-A3-45's weaker half; 03-identity-scim.md Q2. REPRODUCE — moving the guard in here
// would silently make the port stronger than the system it is replacing.
func (s *UserGroupStore) ReplaceScimGroupByID(
	ctx context.Context, id int64, externalID, displayName string,
) (*AppGroup, error) {
	existing, err := s.GetGroup(ctx, id)
	if err != nil || existing == nil {
		return nil, err
	}
	if _, err := s.db.Exec(ctx,
		`UPDATE app_group SET name=$1, source='SCIM', external_id=$2 WHERE id=$3`,
		displayName, externalID, id); err != nil {
		return nil, err
	}
	return s.GetGroup(ctx, id)
}

// The three connection-scoped group resolvers UpsertScimGroup uses (Users.kt:534-548). They take the
// caller's handle so the resolve, the check and the write share ONE transaction.

func groupIDByExternalID(ctx context.Context, c store.Queryer, externalID string) (*int64, error) {
	return scanOptionalID(ctx, c, `SELECT id FROM app_group WHERE external_id=$1`, externalID)
}

func groupIDByName(ctx context.Context, c store.Queryer, name string) (*int64, error) {
	return scanOptionalID(ctx, c, `SELECT id FROM app_group WHERE name=$1`, name)
}

// lockGroupSource is `SELECT source FROM app_group WHERE id=? FOR UPDATE` — the row lock INV-A3-33
// rests on.
//
// ⚠️ It is a FOURTH statement, distinct from [UserGroupStore.LockMutableGroupSource] (A11's
// `lockMutableGroup`, which raises `group.system_immutable`) and from
// LockMutableGroupSourceByName. The Kotlin keeps them separate and so does the port: INV-A11-32
// counts distinct mechanisms, not one shared helper, and unifying them would erase the asymmetry the
// two docs record.
func lockGroupSource(ctx context.Context, c store.Queryer, id int64) (*string, error) {
	var source string
	err := c.QueryRow(ctx, `SELECT source FROM app_group WHERE id=$1 FOR UPDATE`, id).Scan(&source)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &source, nil
}
