package identity

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `UserAdminDeprovisionDbTest.kt` (10 cases) and the teardown half of `DeprovisionDbTest.kt`
// (cases 4, 5, 8), ported at the STORE level exactly as the Kotlin has them — "equivalent coverage,
// no HTTP/admin-gate scaffolding needed".
//
// Two cases from the Kotlin's ten are NOT here and the reason is ownership, not omission:
//   - case 9 (`REST-shaped ID deprovision still targets the original row after a rename`) goes
//     through A11's `IdentityManagementService.deprovisionUser(id)`; the id-stability it asserts is
//     TestSetActiveByIDActsOnTheRowsRePrincipalNotAStaleSnapshot below, and the management wrapper is
//     covered in internal/management.
//   - case 10 (`concurrent REST-shaped group role additions`) is A11's `lockMutableGroup`, and
//     internal/management owns that guard and its concurrency test.
//
// Added beyond the Kotlin: the OTHER DIRECTION of INV-A3-23 (coverage gap 4 — nothing proved a real
// inactive user survives a rename onto its string) and INV-A3-24's purge (coverage gap ranked
// highest among the recycling bugs).
// ---------------------------------------------------------------------------------------------

// 🔒 Case 1 — `PUT rename atomically retires the old principal — tombstoned, token + grant + session
// revoked`. INV-A3-21 + INV-A3-6.
// KT: UserAdminDeprovisionDbTest.kt#PUT rename atomically retires the old principal — tombstoned, token + grant + session revoked
func TestRenameRetiresTheOldPrincipalAndRevokesItsCredentials(t *testing.T) {
	f := newWriteFixture(t)
	const old = "old@example.com"
	const renamed = "new@example.com"

	created, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: old, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	oldCreds := f.seedCredentials(old, "reader")
	bystander := f.seedCredentials("bystander@example.com", "bystander-role")

	updated, err := f.store.UpdateUser(f.ctx, created.ID,
		AppUserInput{Principal: renamed, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("updateUser: %v", err)
	}
	if updated == nil || updated.Principal != renamed {
		t.Fatalf("the row must carry the new principal, got %+v", updated)
	}

	// 🔒 INV-A3-21 — the vacated string is left DEPROVISIONED, not merely orphaned. An orphaned string
	// with no row reads isDeactivated == false (INV-A3-10) and everything it still holds sails past.
	tombstone := f.userByPrincipal(old)
	if tombstone == nil {
		t.Fatalf("the old principal has NO row: it is orphaned, not tombstoned (INV-A3-21)")
	}
	if tombstone.Active {
		t.Errorf("the tombstone must be inactive, got active=%v", tombstone.Active)
	}
	if tombstone.Source != "SCIM" || tombstone.ExternalID != nil {
		t.Errorf("the tombstone shape is source=SCIM + external_id NULL (INV-A3-22), got source=%q externalId=%v",
			tombstone.Source, tombstone.ExternalID)
	}
	if !f.isDeactivated(old) {
		t.Errorf("isDeactivated(%q) must be true after a rename away from it", old)
	}

	f.assertAllRevoked(oldCreds, "the retired principal")
	f.assertAllLive(bystander, "an unrelated principal")
}

// 🔒 Case 2 — `PUT active flip (true to false, no rename) revokes token + grant + session in the same
// transaction`. INV-A3-6.
// KT: UserAdminDeprovisionDbTest.kt#PUT active flip (true to false, no rename) revokes token + grant + session in the same transaction
func TestDeactivatingWithoutRenamingRevokesTheCurrentPrincipal(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "alice@example.com"

	created, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: principal, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	creds := f.seedCredentials(principal, "reader")

	if _, err := f.store.UpdateUser(f.ctx, created.ID,
		AppUserInput{Principal: principal, Active: false}, f.creds); err != nil {
		t.Fatalf("updateUser: %v", err)
	}

	f.assertAllRevoked(creds, "the deactivated principal")
	// No rename ⇒ no tombstone row was created for anything: the one row is simply inactive.
	if f.user(created.ID, "after deactivate").Active {
		t.Errorf("the row must be inactive")
	}
	if got := f.scalarInt64(`SELECT count(*) FROM app_user`); got != 1 {
		t.Errorf("%d app_user rows, want 1 — a deactivate must not tombstone a second string", got)
	}
}

// 🔒 Case 3 — `PUT rename and deactivate revokes credentials held by BOTH principal strings`.
//
// **INV-A3-16, the not-if/else case, and the single easiest thing to collapse in a port.** The rename
// target here has a live token/grant/session but NO app_user row of its own, so its credentials exist
// only under the string. Collapsing steps 5 and 6 into if/else leaves them live, and a later
// reactivation resurrects them.
// KT: UserAdminDeprovisionDbTest.kt#PUT rename and deactivate revokes credentials held by both principal strings
func TestRenameAndDeactivateRetiresBothPrincipalStrings(t *testing.T) {
	f := newWriteFixture(t)
	const old = "old@example.com"
	const target = "new@example.com"

	created, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: old, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	oldCreds := f.seedCredentials(old, "reader")
	// The target string holds credentials WITHOUT an app_user row of its own — the trap.
	targetCreds := f.seedCredentials(target, "writer")
	if f.userByPrincipal(target) != nil {
		t.Fatalf("the rename target must not have a row of its own for this case to mean anything")
	}

	if _, err := f.store.UpdateUser(f.ctx, created.ID,
		AppUserInput{Principal: target, Active: false}, f.creds); err != nil {
		t.Fatalf("updateUser: %v", err)
	}

	f.assertAllRevoked(oldCreds, "the RENAMED-AWAY principal (step 5)")
	f.assertAllRevoked(targetCreds, "the NEW principal, deactivated (step 6)")

	// And the counting fake proves the two branches both fired, in the Kotlin's order, which the rows
	// alone cannot show.
	f2 := newWriteFixture(t)
	rec := &recordingTeardown{}
	second, err := f2.store.CreateUser(f2.ctx, AppUserInput{Principal: old, Active: true}, rec)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	rec.principals = nil
	if _, err := f2.store.UpdateUser(f2.ctx, second.ID,
		AppUserInput{Principal: target, Active: false}, rec); err != nil {
		t.Fatalf("updateUser: %v", err)
	}
	rec.assert(t, "rename-and-deactivate", old, target)
}

// 🔒 Case 4 — `createUser with active=false revokes credentials held before the row existed`.
//
// **INV-A3-18.** Users.kt:108-111: "a principal can accumulate a live wire token / daemon session
// BEFORE any app_user row exists for it at all (isDeactivated is false with no row), so deliberately
// creating it inactive must not leave those pre-existing credentials usable." "Create" reads like it
// cannot need a revoke, which is exactly why this is easy to lose.
// KT: UserAdminDeprovisionDbTest.kt#createUser with active=false revokes credentials held before the row existed
func TestCreateUserInactiveRevokesCredentialsHeldBeforeTheRowExisted(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "preexisting@example.com"

	creds := f.seedCredentials(principal, "reader")
	if f.userByPrincipal(principal) != nil {
		t.Fatalf("the point of this case is that no app_user row exists yet")
	}
	if f.isDeactivated(principal) {
		t.Fatalf("INV-A3-10: with no row, isDeactivated must be false")
	}

	if _, err := f.store.CreateUser(f.ctx,
		AppUserInput{Principal: principal, Active: false}, f.creds); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	f.assertAllRevoked(creds, "credentials predating the row")
}

// Case 5 — `createUser with active=true does not touch an unrelated principal's credentials`: the
// negative half of INV-A3-18.
// KT: UserAdminDeprovisionDbTest.kt#createUser with active=true does not touch an unrelated principal's credentials
func TestCreateUserActiveRevokesNothing(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "fresh@example.com"

	own := f.seedCredentials(principal, "reader")
	other := f.seedCredentials("other@example.com", "writer")

	rec := &recordingTeardown{}
	if _, err := f.store.CreateUser(f.ctx,
		AppUserInput{Principal: principal, Active: true}, rec); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	rec.assert(t, "createUser(active=true)")

	f.assertAllLive(own, "the created principal's own pre-existing credentials")
	f.assertAllLive(other, "an unrelated principal")
}

// Case 6 — `PUT with no rename and no active flip does not revoke anything`: the no-op guard. A port
// that revoked unconditionally would pass every case above and log every admin edit out.
// KT: UserAdminDeprovisionDbTest.kt#PUT with no rename and no active flip does not revoke anything
func TestUpdateWithNoRenameAndNoDeactivateRevokesNothing(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "alice@example.com"

	created, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: principal, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	creds := f.seedCredentials(principal, "reader")

	rec := &recordingTeardown{}
	updated, err := f.store.UpdateUser(f.ctx, created.ID, AppUserInput{
		Principal: principal, DisplayName: types.Ptr("Alice A."), Email: types.Ptr("alice@corp.example"),
		Active: true,
	}, rec)
	if err != nil {
		t.Fatalf("updateUser: %v", err)
	}
	rec.assert(t, "a pure field edit")
	if updated.DisplayName == nil || *updated.DisplayName != "Alice A." {
		t.Errorf("the edit must still land, got %+v", updated)
	}
	f.assertAllLive(creds, "an untouched principal")
}

// 🔒 Case 7 — `DELETE tombstones (never hard-deletes) and revokes token + grant + session
// atomically`. INV-A3-19.
//
// ⚠️ F37 — this drives the 4-ARG wrapper, which is what the Kotlin case does, and the 4-arg wrapper is
// a SetActiveByID alias with no production caller. The 5-arg overload A11 actually calls has a
// different body and is driven by TestDeleteUserOnHasItsOwnSecondFalseExit below.
// KT: UserAdminDeprovisionDbTest.kt#DELETE tombstones (never hard-deletes) and revokes token + grant + session atomically
func TestDeleteUserDeprovisionsAndNeverHardDeletes(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "alice@example.com"

	created, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: principal, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	creds := f.seedCredentials(principal, "reader")

	deleted, err := f.store.DeleteUser(f.ctx, created.ID, f.creds)
	if err != nil || !deleted {
		t.Fatalf("deleteUser: %v %v", deleted, err)
	}

	row := f.user(created.ID, "after DELETE")
	if row.Active {
		t.Errorf("the row must be inactive after DELETE, got active=true")
	}
	if row.Principal != principal {
		t.Errorf("the principal must survive so audit history keeps resolving it, got %q", row.Principal)
	}
	f.assertAllRevoked(creds, "the deprovisioned principal")
}

// Case 8 — `DELETE on a nonexistent id returns false (404 at the route)`.
// KT: UserAdminDeprovisionDbTest.kt#DELETE on a nonexistent id returns false (404 at the route)
func TestDeleteUserOnANonexistentIDIsFalse(t *testing.T) {
	f := newWriteFixture(t)
	deleted, err := f.store.DeleteUser(f.ctx, 987654321, f.creds)
	if err != nil {
		t.Fatalf("deleteUser: %v", err)
	}
	if deleted {
		t.Errorf("deleted=true for a nonexistent id")
	}
}

// ⚠️ F37 — the 5-arg `deleteUser(id, …, c)` A11 actually calls. Different body from the wrapper: it
// has a SECOND false exit when the locked re-read finds no row, it does NOT tombstone-release, and it
// does NOT rename. The Kotlin covers it only indirectly.
func TestDeleteUserOnHasItsOwnSecondFalseExit(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "alice@example.com"

	created, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: principal, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	creds := f.seedCredentials(principal, "reader")

	var deleted bool
	if err := store.InTxDo(f.ctx, f.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		deleted, err = f.store.DeleteUserOn(ctx, tx, created.ID, f.creds)
		return err
	}); err != nil {
		t.Fatalf("deleteUserOn: %v", err)
	}
	if !deleted {
		t.Errorf("deleted=false for a real row")
	}
	f.assertAllRevoked(creds, "the 5-arg overload's teardown")

	// First false exit — no row at all.
	if err := store.InTxDo(f.ctx, f.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		deleted, err = f.store.DeleteUserOn(ctx, tx, 987654321, f.creds)
		return err
	}); err != nil {
		t.Fatalf("deleteUserOn(missing): %v", err)
	}
	if deleted {
		t.Errorf("deleted=true for a nonexistent id")
	}
}

// 🔒 DeprovisionDbTest case 4 — `revokeActiveCredentials sums tokens grants daemon windows and web
// sessions`. INV-A3-5: ALL FOUR CLASSES OR NONE.
//
// The Kotlin asserts the EXACT SUM (6 there, with two tokens and two grants). The sum is the only
// assertion that distinguishes "revoked four classes" from "revoked three and returned a plausible
// number", which is why 03-identity-scim.md:382 says to keep the return value.
// KT: DeprovisionDbTest.kt#revokeActiveCredentials sums tokens grants daemon windows and web sessions
func TestRevokeActiveCredentialsSumsAllFourClassesAndIsIdempotent(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "alice@example.com"

	// Two tokens and two grants, plus one daemon window and one web session ⇒ 6.
	first := f.seedCredentials(principal, "reader")
	roleID := f.seed.Role("writer")
	if _, err := f.tokens.Issue(f.ctx, f.db.Pool, "SESSION", principal, []string{"writer"}, nil, 3600); err != nil {
		t.Fatalf("second token: %v", err)
	}
	f.exec(`INSERT INTO access_grant (principal, role_id, granted_by, expires_at)
	        VALUES ($1, $2, 'approver@example.com', now() + interval '1 hour')`, principal, roleID)
	bystander := f.seedCredentials("bystander@example.com", "bystander-role")

	revoked, err := f.creds.RevokeActiveCredentials(f.ctx, principal)
	if err != nil {
		t.Fatalf("revokeActiveCredentials: %v", err)
	}
	if revoked != 6 {
		t.Errorf("revoked %d, want exactly 6 (2 tokens + 2 grants + 1 daemon window + 1 web session)", revoked)
	}
	f.assertAllRevoked(first, "the deprovisioned principal")
	f.assertAllLive(bystander, "a bystander")

	// Idempotent: a second sweep finds nothing.
	again, err := f.creds.RevokeActiveCredentials(f.ctx, principal)
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if again != 0 {
		t.Errorf("second revoke returned %d, want 0", again)
	}
}

// 🔒 DeprovisionDbTest case 5 — `revokeActiveCredentials closes the principal's daemon session windows
// so a renewal secret can't survive`.
//
// This is the half of INV-A3-5 a port is most likely to drop, because a closed daemon window is
// invisible from every other angle: the token is gone, the session row still LOOKS like a row, and
// only `absolute_expires_at <= now()` says the renewal secret can no longer mint.
// KT: DeprovisionDbTest.kt#revokeActiveCredentials closes the principal's daemon session windows so a renewal secret can't survive
func TestRevokeClosesDaemonWindowsSoAReactivationCannotResurrectARenewalSecret(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "daemon@example.com"
	creds := f.seedCredentials(principal, "reader")

	if _, err := f.creds.RevokeActiveCredentials(f.ctx, principal); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	f.assertDaemonWindowClosed(creds.daemonID, true, "after revoke")

	// Reactivating the directory row must NOT reopen the window — that is what "durable" means.
	if _, err := f.store.SetUserActive(f.ctx, principal, true); err != nil {
		t.Fatalf("setUserActive: %v", err)
	}
	f.assertDaemonWindowClosed(creds.daemonID, true, "after a later reactivation")
}

// 🔒 ProvisionMergeDbTest case 12 / INV-A3-20 — `setActiveById re-reads the current principal UNDER
// the lock — deactivates the row's real identity, not a stale snapshot`.
//
// **The hardest case in the area to port and the one that decides whether the advisory-lock plumbing
// is right.** A second connection holds `pg_advisory_xact_lock(hashtext('sa-old'))` AND renames the
// row UNCOMMITTED. The call under test must:
//
//  1. read 'sa-old' (READ COMMITTED sees the pre-rename value),
//  2. BLOCK on the advisory lock — proved by asserting it has not completed after ~300 ms,
//  3. after the holder commits, RE-READ and observe 'sa-mid', and
//  4. revoke 'sa-mid' — the row's real identity — not the stale 'sa-old'.
//
// A single-shot lock-then-read passes steps 1-3 and fails step 4, which is precisely the bug
// lockCurrentPrincipal's loop exists to fix.
// KT: ProvisionMergeDbTest.kt#setActiveById re-reads the current principal under the lock — deactivates the row's real identity, not a stale snapshot (SCIM PATCH-DELETE)
func TestSetActiveByIDActsOnTheRowsRePrincipalNotAStaleSnapshot(t *testing.T) {
	f := newWriteFixture(t)
	const old = "sa-old@example.com"
	const mid = "sa-mid@example.com"

	created, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: old, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	oldCreds := f.seedCredentials(old, "reader")
	midCreds := f.seedCredentials(mid, "writer")

	holder, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin holder: %v", err)
	}
	defer func() { _ = holder.Rollback(f.ctx) }()

	// 🔒 The literal expression, not store.AdvisoryLockPrincipal — so this test pins the KEY as well
	// as the behaviour. A port that hashed client-side would sail past a helper-based holder.
	if _, err := holder.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, old); err != nil {
		t.Fatalf("hold the lock: %v", err)
	}
	if _, err := holder.Exec(f.ctx, `UPDATE app_user SET principal = $1 WHERE id = $2`, mid, created.ID); err != nil {
		t.Fatalf("uncommitted rename: %v", err)
	}

	done := make(chan error, 1)
	var updated *AppUser
	go func() {
		var err error
		updated, err = f.store.SetActiveByID(context.Background(), created.ID, false, f.creds)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("setActiveById completed (%v) while another transaction held the principal's "+
			"advisory lock — it did not block, so the lock is not being taken", err)
	case <-time.After(300 * time.Millisecond):
		// Blocked, as required.
	}

	if err := holder.Commit(f.ctx); err != nil {
		t.Fatalf("commit holder: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("setActiveById after release: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("setActiveById never completed after the lock was released")
	}

	if updated == nil || updated.Principal != mid {
		t.Fatalf("the returned row must carry the RE-READ principal %q, got %+v", mid, updated)
	}
	f.assertAllRevoked(midCreds, "the row's real identity, re-read under the lock")
	f.assertAllLive(oldCreds, "the stale pre-lock snapshot — it must NOT be the one torn down")
}

// 🔒 INV-A3-23, THE OTHER DIRECTION — 03-identity-scim.md coverage gap 4: "cases 11/13/14 prove a
// tombstone IS released; nothing proves a genuinely inactive real user is NOT deleted when a rename
// targets its principal string."
//
// Two real inactive identities that must survive a rename onto their string: a SCIM user with its own
// external_id, and a local admin's deliberately-deactivated user. Dropping any one of
// releaseTombstone's four predicates turns a rename into silent deletion of a real user — and the
// rename would then SUCCEED, so nothing else would notice.
func TestReleaseTombstoneNeverDeletesAGenuinelyInactiveRealUser(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(f *writeFixture, principal string) int64
	}{
		{
			name: "a real SCIM user with its own external_id",
			plant: func(f *writeFixture, principal string) int64 {
				return f.scalarInt64(
					`INSERT INTO app_user (principal, source, external_id, active)
					 VALUES ($1, 'SCIM', 'okta-real', FALSE) RETURNING id`, principal)
			},
		},
		{
			name: "a local admin's deliberately-deactivated user",
			plant: func(f *writeFixture, principal string) int64 {
				return f.scalarInt64(
					`INSERT INTO app_user (principal, source, active) VALUES ($1, 'LOCAL', FALSE) RETURNING id`,
					principal)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWriteFixture(t)
			const occupied = "taken@example.com"
			victimID := tc.plant(f, occupied)

			mover, err := f.store.CreateUser(f.ctx,
				AppUserInput{Principal: "mover@example.com", Active: true}, f.creds)
			if err != nil {
				t.Fatalf("createUser: %v", err)
			}

			// The rename must FAIL on the unique constraint rather than quietly deleting the victim.
			_, err = f.store.UpdateUser(f.ctx, mover.ID,
				AppUserInput{Principal: occupied, Active: true}, f.creds)
			if err == nil {
				t.Fatalf("renaming onto a REAL inactive user's principal must not succeed — " +
					"a success means releaseTombstone deleted it (INV-A3-23)")
			}
			if !store.IsUniqueViolation(err) {
				t.Errorf("want a 23505 unique violation, got %v", err)
			}
			if f.store == nil {
				return
			}
			survivor, err := f.store.GetUser(f.ctx, victimID)
			if err != nil {
				t.Fatalf("re-read victim: %v", err)
			}
			if survivor == nil {
				t.Fatalf("the real inactive user was DELETED — INV-A3-23's narrow match was widened")
			}
		})
	}
}

// 🔒 INV-A3-24 — `a retired principal's direct principal_role grant does not silently transfer to
// whoever reuses the string` (ScimUsersDbTest case 11's subject, driven here through the local-admin
// rename because both paths call releaseTombstone).
//
// Revoking tokens/grants/sessions does NOT touch `principal_role`: it is keyed purely on the
// principal STRING. While the string stays tombstoned that is harmless — Resolve short-circuits to
// empty for a deactivated principal — but the moment the string is handed to a genuinely different
// identity and goes ACTIVE again, a stale direct grant reattaches to whoever claims it. Privilege
// escalation via principal recycling.
// KT: ScimUsersDbTest.kt#a retired principal's direct principal_role grant does not silently transfer to whoever reuses the string — local-admin rename half of the split
func TestATombstonedPrincipalsDirectRoleDoesNotTransferToWhoeverReusesTheString(t *testing.T) {
	f := newWriteFixture(t)
	const recycled = "recycled@example.com"

	// Identity #1 holds the string and a DIRECT role.
	firstID := f.scalarInt64(
		`INSERT INTO app_user (principal, source, active) VALUES ($1, 'LOCAL', TRUE) RETURNING id`, recycled)
	adminRole := f.seed.Role("secret-admin")
	f.exec(`INSERT INTO principal_role (principal, role_id) VALUES ($1, $2)`, recycled, adminRole)

	// It is renamed away, which tombstones the string.
	if _, err := f.store.UpdateUser(f.ctx, firstID,
		AppUserInput{Principal: "moved-on@example.com", Active: true}, f.creds); err != nil {
		t.Fatalf("rename away: %v", err)
	}
	if f.userByPrincipal(recycled) == nil {
		t.Fatalf("expected a tombstone on the vacated string")
	}

	// Identity #2 — a genuinely different person — is handed the string.
	second, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: recycled, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("recreate on the recycled string: %v", err)
	}
	if second.Principal != recycled || !second.Active {
		t.Fatalf("the new identity must hold the string, active: %+v", second)
	}

	stale := f.scalarInt64(`SELECT count(*) FROM principal_role WHERE principal = $1`, recycled)
	if stale != 0 {
		t.Errorf("%d stale principal_role row(s) survived onto the recycled string — "+
			"INV-A3-24's purge did not run", stale)
	}
}

// 🔒 INV-A3-25 — a tombstone must not squat the globally-UNIQUE `principal` column forever. Without
// releaseTombstone, both of these 500 on a unique-constraint violation.
func TestARetiredPrincipalCanBeReusedAndRenamedBackOnto(t *testing.T) {
	f := newWriteFixture(t)
	const original = "a@example.com"
	const other = "b@example.com"

	first, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: original, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	// Rename away, leaving a tombstone on `original`.
	if _, err := f.store.UpdateUser(f.ctx, first.ID,
		AppUserInput{Principal: other, Active: true}, f.creds); err != nil {
		t.Fatalf("rename away: %v", err)
	}

	// Case 14's half — rename BACK onto its own just-retired string. INV-A3-26's excludeId is what
	// stops this from deleting the very row being updated.
	back, err := f.store.UpdateUser(f.ctx, first.ID, AppUserInput{Principal: original, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("rename back onto the just-retired string: %v", err)
	}
	if back == nil || back.Principal != original {
		t.Fatalf("the rename back must land, got %+v", back)
	}
	if got := f.scalarInt64(`SELECT count(*) FROM app_user WHERE principal = $1`, original); got != 1 {
		t.Errorf("%d rows on the reused string, want exactly 1", got)
	}
}

// The teardown and the directory write are ONE transaction: when the teardown fails, the write rolls
// back with it. 🔒 INV-A3-6 in its strongest form — the alternative the Kotlin rejects is "a separate
// follow-up a crash could skip, leaving a principal inactive-but-still-credentialed".
func TestAFailedTeardownRollsTheDirectoryWriteBack(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "alice@example.com"

	created, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: principal, Active: true}, f.creds)
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}

	boom := &recordingTeardown{err: context.DeadlineExceeded}
	if _, err := f.store.UpdateUser(f.ctx, created.ID,
		AppUserInput{Principal: "renamed@example.com", Active: false}, boom); err == nil {
		t.Fatalf("a failing teardown must fail the whole write")
	}

	row := f.user(created.ID, "after the failed write")
	if row.Principal != principal {
		t.Errorf("the rename committed despite the teardown failing: principal is %q", row.Principal)
	}
	if !row.Active {
		t.Errorf("the deactivation committed despite the teardown failing")
	}
	if f.userByPrincipal("renamed@example.com") != nil {
		t.Errorf("a tombstone survived a rolled-back rename")
	}
}

// `setUserActive` is production-dead and fixture-live (F27): no lock, no revoke, keyed on the string.
// It is reproduced as a test-visible helper because NINE Kotlin suites across five areas use it, and
// the property that matters is the one its stale kdoc gets right — it must NOT tear anything down.
// KT: ProvisionMergeDbTest.kt#setUserActive and isDeactivated
// KT: ScimUsersDbTest.kt#setUserActive toggles active and persists
func TestSetUserActiveFlipsTheFlagAndTearsNothingDown(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "alice@example.com"

	if _, err := f.store.CreateUser(f.ctx, AppUserInput{Principal: principal, Active: true}, f.creds); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	creds := f.seedCredentials(principal, "reader")

	flipped, err := f.store.SetUserActive(f.ctx, principal, false)
	if err != nil || !flipped {
		t.Fatalf("setUserActive: %v %v", flipped, err)
	}
	if !f.isDeactivated(principal) {
		t.Errorf("the flag must be false")
	}
	f.assertAllLive(creds, "setUserActive must NOT revoke — the credential-affecting path is SetActiveByID")

	// The Kotlin's two cases both TOGGLE BACK: `setUserActive(p, true)` must answer true, clear the
	// flag, and persist that on the row — the reactivate half, without which the test would pass for a
	// one-way implementation.
	flipped, err = f.store.SetUserActive(f.ctx, principal, true)
	if err != nil || !flipped {
		t.Fatalf("setUserActive(true): %v %v", flipped, err)
	}
	if f.isDeactivated(principal) {
		t.Errorf("isDeactivated must be false again after setUserActive(true)")
	}
	if !f.userByPrincipal(principal).Active {
		t.Errorf("the row must read active=true after the toggle back — the flip has to PERSIST")
	}

	// An unknown principal matches nothing.
	flipped, err = f.store.SetUserActive(f.ctx, "nobody@example.com", false)
	if err != nil || flipped {
		t.Errorf("an unknown principal must answer false, got %v %v", flipped, err)
	}
}
