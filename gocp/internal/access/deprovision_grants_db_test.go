package access_test

import (
	"context"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `DeprovisionDbTest.kt` case 3 — `AccessStore.revokeAllForPrincipal`, the JIT-grant half of the
// deprovisioning backstop (docs/auth-model.md "Deprovisioning propagates two ways").
//
// internal/identity's TestRevokeActiveCredentialsSumsAllFourClassesAndIsIdempotent exercises this
// method through the four-class TEARDOWN and asserts the combined sum, which is a different claim: it
// cannot tell a grant sweep that returned the right total from one that revoked a bystander's grant
// too, and it says nothing about this method's own return value. The Kotlin case asserts exactly those
// two things, so it is ported here, on the store that owns them.
// ---------------------------------------------------------------------------------------------

// 🔒 TestRevokeAllForPrincipalRevokesEveryActiveGrantForThatPrincipalOnly is the port of
// `AccessStore revokeAllForPrincipal revokes every active grant for that principal only`.
//
// Two principals hold one approved (active) grant each. The sweep must return 1 — not 2, and not "some
// non-zero number" — leave the target with zero active grants, and leave the other principal's grant
// completely alone. `WHERE principal = $1` is one clause away from `WHERE TRUE`, and a deprovision that
// revoked the whole table would look like a success from the target's side.
// KT: DeprovisionDbTest.kt#AccessStore revokeAllForPrincipal revokes every active grant for that principal only
func TestRevokeAllForPrincipalRevokesEveryActiveGrantForThatPrincipalOnly(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.MigratedStore(t)
	seed := dbtest.NewSeed(t, db)
	store := access.NewStore(db.Pool)

	roleID := seed.Role("deprovision-grant-role")
	const target = "revoke-grants@example.com"
	const bystander = "grant-untouched@example.com"

	// Both grants go through the production request→approve path, so what is swept is a grant row the
	// approval flow really writes rather than one this test invented.
	grant := func(principal string) {
		t.Helper()
		req, err := store.CreateRequest(ctx, principal, access.AccessRequestInput{RoleID: roleID})
		if err != nil || req == nil {
			t.Fatalf("createRequest(%s): %v", principal, err)
		}
		if _, err := store.Approve(ctx, req.ID, types.Ptr(int64(3600)), "approver@example.com"); err != nil {
			t.Fatalf("approve(%s): %v", principal, err)
		}
	}
	grant(target)
	grant(bystander)

	active := func(principal string) int {
		t.Helper()
		grants, err := store.ListGrants(ctx, &principal, true)
		if err != nil {
			t.Fatalf("listGrants(%s): %v", principal, err)
		}
		return len(grants)
	}
	if active(target) != 1 || active(bystander) != 1 {
		t.Fatalf("fixture: want one active grant each, got target=%d bystander=%d",
			active(target), active(bystander))
	}

	revoked, err := store.RevokeAllForPrincipal(ctx, target)
	if err != nil {
		t.Fatalf("revokeAllForPrincipal: %v", err)
	}
	if revoked != 1 {
		t.Errorf("revoked %d, want exactly 1 — the count is what tells a scoped sweep from a table-wide one", revoked)
	}
	if got := active(target); got != 0 {
		t.Errorf("%d active grant(s) left on the deprovisioned principal, want 0", got)
	}
	if got := active(bystander); got != 1 {
		t.Errorf("a DIFFERENT principal's grant was revoked (%d active left, want 1) — "+
			"revokeAllForPrincipal is scoped to its argument", got)
	}

	// The sweep is idempotent: nothing active is left to revoke, so the second call reports 0 rather
	// than re-stamping revoked_at on rows it already closed.
	again, err := store.RevokeAllForPrincipal(ctx, target)
	if err != nil {
		t.Fatalf("second revokeAllForPrincipal: %v", err)
	}
	if again != 0 {
		t.Errorf("second sweep returned %d, want 0", again)
	}
}
