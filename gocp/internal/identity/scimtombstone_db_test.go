package identity

import (
	"context"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------------------------
// The SCIM-PATH half of A3's tombstone recycling, plus the two by-id write paths — the five Kotlin
// cases that drive `UpsertScimUser` / `ReplaceScimUserByID` / `SetActiveByID` rather than the
// local-admin `UpdateUser` wrapper.
//
// 🔴 WHY THESE ARE NOT REDUNDANT with usergroupwrites_db_test.go. That file drives every one of these
// properties through `UpdateUser`, which reaches the same releaseTombstone / lockCurrentPrincipal
// helpers — so "the helper works" is already covered. What is NOT covered is that the SCIM entry
// points CALL them: `UpsertScimUser`, `ReplaceScimUserByID` and `SetActiveByID` each assemble the
// resolve → lock → release → mutate → retire sequence THEMSELVES (see scimstore.go:66-108 and
// :157-210, four separate copies of that skeleton). Dropping releaseTombstone from one of them leaves
// the local-admin tests green and 500s every IdP push that reuses a retired userName.
// ---------------------------------------------------------------------------------------------

// 🔒 ProvisionMergeDbTest case 11 — `setActiveById deactivates and revokes atomically by id (SCIM
// PATCH SetActive false, and DELETE)`.
//
// This is the path BOTH `PATCH {op:replace, path:active, value:false}` and `DELETE /Users/{id}` take,
// which is why the Kotlin case name carries both: the SCIM surface never deletes a user, it addresses
// the row by id and deactivates it. The four credential classes must be gone in the same committed
// transaction as the `active = false` write.
// KT: ProvisionMergeDbTest.kt#setActiveById deactivates and revokes atomically by id (SCIM PATCH SetActive false, and DELETE)
func TestSetActiveByIDDeactivatesAndRevokesInOneTransaction(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "scim-patch-delete@example.com"

	user, err := f.store.UpsertScimUser(f.ctx, "ext-patchdel", principal, nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	creds := f.seedCredentials(principal, "reader")
	bystander := f.seedCredentials("bystander@example.com", "bystander-role")

	updated, err := f.store.SetActiveByID(f.ctx, user.ID, false, f.creds)
	if err != nil {
		t.Fatalf("setActiveById: %v", err)
	}
	if updated == nil || updated.Active {
		t.Fatalf("the returned row must be inactive, got %+v", updated)
	}
	if !f.isDeactivated(principal) {
		t.Errorf("isDeactivated(%q) must be true after a PATCH active=false / DELETE", principal)
	}
	f.assertAllRevoked(creds, "a SCIM PATCH active=false addressed by id")
	f.assertAllLive(bystander, "an unrelated principal")

	// The row is TOMBSTONED, never removed: the SCIM DELETE is a soft delete (INV-A3-19), so a later
	// GET /Users/{id} and every audit row that names the principal keep resolving.
	if f.user(user.ID, "after PATCH active=false").Principal != principal {
		t.Errorf("the principal must survive on the row")
	}

	// active=true takes the other arm: no teardown at all. Without this the test would pass for an
	// implementation that revoked on EVERY setActiveById, which would log a reactivated user straight
	// back out.
	reactivated, err := f.store.SetActiveByID(f.ctx, user.ID, true, f.creds)
	if err != nil {
		t.Fatalf("setActiveById(true): %v", err)
	}
	if reactivated == nil || !reactivated.Active {
		t.Fatalf("the row must be active again, got %+v", reactivated)
	}
	fresh := f.seedCredentials(principal, "reader-after-reactivate")
	if _, err := f.store.SetActiveByID(f.ctx, user.ID, true, f.creds); err != nil {
		t.Fatalf("setActiveById(true) again: %v", err)
	}
	f.assertAllLive(fresh, "an active=true push must revoke NOTHING")
}

// 🔒 ProvisionMergeDbTest case 13 — `a blocked rename retires the principal carried by the row after
// lock release`. **INV-A3-17/-20 on the UPSERT path**, the twin of case 12 (which pins it on
// SetActiveByID and is already covered by TestSetActiveByIDActsOnTheRowsRePrincipalNotAStaleSnapshot).
//
// externalId X starts as `old`; a SEPARATE `mid` identity holds a live token. A concurrent holder takes
// the principal's advisory lock AND renames the row old → mid, uncommitted — so the upsert's three
// resolution reads (which run OUTSIDE the transaction, F34) see `old`, and it then blocks acquiring the
// same lock. Once it gets in it must RE-READ the row, find `mid`, and retire THAT.
//
// A port whose rename branch used the pre-lock snapshot would tombstone `old` — a string nobody holds
// any more — and leave mid's token live under a principal that no longer exists on any row, where
// isDeactivated answers false (INV-A3-10) and every gate waves it through.
// KT: ProvisionMergeDbTest.kt#a blocked rename retires the principal carried by the row after lock release
func TestABlockedScimRenameRetiresThePrincipalTheRowActuallyCarries(t *testing.T) {
	f := newWriteFixture(t)
	const extID = "ext-reread-under-lock"
	const old = "reread-old@example.com"
	const mid = "reread-mid@example.com"
	const renamed = "reread-new@example.com"

	if _, err := f.store.UpsertScimUser(f.ctx, extID, old, nil, nil, true, f.creds); err != nil {
		t.Fatalf("provision: %v", err)
	}
	existing, err := f.store.FindUserByExternalID(f.ctx, extID)
	if err != nil || existing == nil {
		t.Fatalf("findUserByExternalId: %+v, %v", existing, err)
	}
	oldCreds := f.seedCredentials(old, "reader")
	midCreds := f.seedCredentials(mid, "writer")

	holder, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin holder: %v", err)
	}
	defer func() { _ = holder.Rollback(f.ctx) }()

	// 🔒 The LITERAL lock expression, not store.AdvisoryLockPrincipal — so this pins the KEY too. A port
	// that hashed client-side would not contend with the real Kotlin control plane during a cutover.
	if _, err := holder.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, old); err != nil {
		t.Fatalf("hold the lock: %v", err)
	}
	if _, err := holder.Exec(f.ctx,
		`UPDATE app_user SET principal = $1 WHERE id = $2`, mid, existing.ID); err != nil {
		t.Fatalf("uncommitted rename: %v", err)
	}

	type result struct {
		user AppUser
		err  error
	}
	done := make(chan result, 1)
	go func() {
		u, err := f.store.UpsertScimUser(context.Background(), extID, renamed, nil, nil, true, f.creds)
		done <- result{u, err}
	}()

	select {
	case r := <-done:
		t.Fatalf("the rename completed (%+v, %v) while another transaction held the principal's "+
			"advisory lock — it never took the lock, so it can act on a stale snapshot", r.user, r.err)
	case <-time.After(300 * time.Millisecond):
		// Blocked, as required.
	}

	if err := holder.Commit(f.ctx); err != nil {
		t.Fatalf("commit holder: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("upsert after the lock was released: %v", r.err)
		}
		if r.user.Principal != renamed {
			t.Fatalf("the row must carry %q, got %+v", renamed, r.user)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the rename never completed after the lock was released")
	}

	f.assertAllRevoked(midCreds, "the RE-READ current principal (mid)")
	if !f.isDeactivated(mid) {
		t.Errorf("isDeactivated(%q) must be true — mid is what the row carried when the rename "+
			"observed it, so mid is what gets tombstoned", mid)
	}
	// `old` was already vacated by the holder's own UPDATE, which wrote no tombstone, so nothing
	// re-tombstones it here. Its credentials therefore stay live — and that is the Kotlin's shape too:
	// the case asserts about `mid`, because `old` is a string the row stopped carrying before the
	// upsert's transaction ever began.
	f.assertAllLive(oldCreds, "the stale pre-lock snapshot (old)")
}

// 🔒 ScimUsersDbTest case 13 — `a retired (tombstoned) principal can be reused by a later rename — no
// permanent unique-constraint block`. **INV-A3-25 on the SCIM path.**
//
// A tombstone occupies the globally-UNIQUE `app_user.principal`. Without releaseTombstone, the IdP's
// entirely legitimate second push — a DIFFERENT identity (different externalId) taking over a userName
// somebody vacated — 500s on 23505 forever, and no amount of retrying at the IdP fixes it.
// KT: ScimUsersDbTest.kt#a retired (tombstoned) principal can be reused by a later rename — no permanent unique-constraint block
func TestARetiredScimPrincipalCanBeReusedByALaterRename(t *testing.T) {
	f := newWriteFixture(t)
	const vacated = "away@example.com"

	first, err := f.store.UpsertScimUser(f.ctx, "okta-tombstone-reuse", vacated, nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := f.store.UpsertScimUser(f.ctx, "okta-tombstone-reuse",
		"elsewhere@example.com", nil, nil, true, f.creds); err != nil {
		t.Fatalf("rename away: %v", err)
	}
	if !f.isDeactivated(vacated) {
		t.Fatalf("fixture: the vacated string must be tombstoned before it can be reused")
	}

	reused, err := f.store.UpsertScimUser(f.ctx, "okta-tombstone-reuse-2", vacated, nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("a second identity claiming the retired string: %v — INV-A3-25 says the tombstone "+
			"must be RELEASED, not squat the unique column forever", err)
	}
	if reused.Principal != vacated || reused.Source != "SCIM" {
		t.Errorf("the new owner must hold the string as a SCIM row, got %+v", reused)
	}
	if f.isDeactivated(vacated) {
		t.Errorf("the reused string must be ACTIVE under its new owner — otherwise the new identity is " +
			"provisioned already deprovisioned")
	}
	if reused.ID == first.ID {
		t.Errorf("the reuse merged into the ORIGINAL row (%d): a different externalId is a genuinely "+
			"different identity and must not inherit the old one's row", first.ID)
	}
	if got := f.scalarInt64(`SELECT count(*) FROM app_user WHERE principal = $1`, vacated); got != 1 {
		t.Errorf("%d rows hold the reused string, want exactly 1", got)
	}
}

// 🔒 ScimUsersDbTest case 14 — `replaceScimUserById can rename BACK onto its own just-retired principal
// string`. **INV-A3-26's excludeId.**
//
// The row renames a → b, which tombstones `a`; the very next PUT sends it back to `a`. releaseTombstone
// must exclude the row being updated, or the write deletes the tombstone it is about to collide
// with — or, worse, deletes the row itself. An IdP that reverts a mistaken userName change does exactly
// this, seconds later.
// KT: ScimUsersDbTest.kt#replaceScimUserById can rename BACK onto its own just-retired principal string
func TestReplaceScimUserByIDCanRenameBackOntoItsOwnJustRetiredPrincipal(t *testing.T) {
	f := newWriteFixture(t)
	const extID = "okta-put-rename-back"
	const a = "back-a@example.com"
	const b = "back-b@example.com"

	user, err := f.store.UpsertScimUser(f.ctx, extID, a, nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := f.store.ReplaceScimUserByID(f.ctx, user.ID, b, nil, nil, extID, true, f.creds); err != nil {
		t.Fatalf("PUT a → b: %v", err)
	}
	if !f.isDeactivated(a) {
		t.Fatalf("fixture: the PUT must have tombstoned the vacated string for this case to bite")
	}

	back, err := f.store.ReplaceScimUserByID(f.ctx, user.ID, a, nil, nil, extID, true, f.creds)
	if err != nil {
		t.Fatalf("PUT b → a (back onto its own tombstone): %v", err)
	}
	if back == nil || back.Principal != a {
		t.Fatalf("the rename back must land on the same row, got %+v", back)
	}
	if back.ID != user.ID {
		t.Errorf("the PUT must stay on id %d, got %d", user.ID, back.ID)
	}
	if f.isDeactivated(a) {
		t.Errorf("the row must be ACTIVE on the string it renamed back onto — a surviving tombstone " +
			"would mean isDeactivated is answering for the wrong row")
	}
	if got := f.scalarInt64(`SELECT count(*) FROM app_user WHERE principal = $1`, a); got != 1 {
		t.Errorf("%d rows hold %q, want exactly 1 — the tombstone the first PUT left there must have "+
			"been released rather than accumulated alongside the live row", got, a)
	}
	// And the second rename left its OWN tombstone on `b`, which is the same retire-the-vacated-string
	// rule applied in the other direction — not an accounting error in the count above.
	if !f.isDeactivated(b) {
		t.Errorf("the string vacated by the rename back (%q) must itself be tombstoned", b)
	}
}

// 🔒 ScimUsersDbTest case 11 — `a retired principal's direct principal_role grant does not silently
// transfer to whoever reuses the string`, **on the SCIM path the Kotlin case actually drives.**
//
// `principal_role` is keyed on the principal STRING and is untouched by credential revocation. While
// the string stays tombstoned that is harmless — Resolve short-circuits a deactivated principal to zero
// roles — but the moment an IdP hands the userName to a different human and that row goes active, a
// stale direct grant reattaches to them. INV-A3-24's purge is what stops it, and it has to fire from
// releaseTombstone on THIS path too, not just from the local-admin rename.
// KT: ScimUsersDbTest.kt#a retired principal's direct principal_role grant does not silently transfer to whoever reuses the string — SCIM-path half of the split
func TestARetiredScimPrincipalsDirectRoleDoesNotTransferToTheNextOwner(t *testing.T) {
	f := newWriteFixture(t)
	const recycled = "role-leak-a@example.com"
	roleID := f.seed.Role("role-leak-test-role")

	if _, err := f.store.UpsertScimUser(f.ctx, "okta-role-leak", recycled, nil, nil, true, f.creds); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// A direct grant, independent of app_user entirely.
	f.exec(`INSERT INTO principal_role (principal, role_id) VALUES ($1, $2)`, recycled, roleID)

	// The IdP renames that identity away, tombstoning the string.
	if _, err := f.store.UpsertScimUser(f.ctx, "okta-role-leak",
		"role-leak-b@example.com", nil, nil, true, f.creds); err != nil {
		t.Fatalf("rename away: %v", err)
	}
	if !f.isDeactivated(recycled) {
		t.Fatalf("fixture: the vacated string must be tombstoned")
	}

	// A DIFFERENT identity is provisioned onto the freed string.
	if _, err := f.store.UpsertScimUser(f.ctx, "okta-role-leak-2", recycled, nil, nil, true, f.creds); err != nil {
		t.Fatalf("provision the new owner: %v", err)
	}
	if f.isDeactivated(recycled) {
		t.Fatalf("sanity: the string must be active again under its new owner")
	}

	if stale := f.scalarInt64(
		`SELECT count(*) FROM principal_role WHERE principal = $1`, recycled); stale != 0 {
		t.Errorf("%d stale principal_role row(s) survived onto the recycled string — the new owner "+
			"silently inherited the retired identity's direct role (INV-A3-24)", stale)
	}
}
