package policy

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The two halves of CedarPolicyRoutesTest.kt that cedarroutes_db_test.go does not state.
//
// Both are about a mutation landing on the RIGHT ROW: one is the reserved namespace closing on the
// RENAME path (a separate code path from create, and the one an operator reaches by editing an
// existing policy), the other is that an update is bound to the numeric id even when the NAME it
// carries now belongs to a different, live row.
// ---------------------------------------------------------------------------------------------

// 🔒 `CedarPolicyRoutesTest` case 2, SECOND half — "… and USER RENAME reject the reserved `system:`
// namespace", through the PUT route.
//
// cedarroutes_db_test.go's TestCreateRejectsTheReservedSystemNamespace is the POST half, and
// cedarwrite_db_test.go's TestUpdateRejectsRenamingAUserPolicyIntoTheReservedNamespace is the rename
// guard at the STORE. Neither states the route-level rename, which is what an operator actually hits
// and which has its own rendering: 400 `policy.reserved_name` (not the 409 a SYSTEM row's PUT gets),
// with the row's name unchanged.
// KT: CedarPolicyRoutesTest.kt#POST and USER rename reject the reserved system namespace — the rename half
func TestUpdateRejectsRenamingIntoTheReservedNamespaceThroughTheRoute(t *testing.T) {
	f := newRouteFixture(t)
	user := f.seedUserPolicy("route-user", validCedarSrc)

	rec := f.admin(http.MethodPut, "/api/policies/"+strconv.FormatInt(user.ID, 10),
		`{"name":"system:renamed-user","cedarSrc":"`+validCedarSrcJSON+`"}`)

	assertStatus(t, rec, http.StatusBadRequest, "rename into the reserved namespace")
	body := assertAPIError(t, rec, "policy.reserved_name", "rename into the reserved namespace")
	if body.Params["name"] != "system:renamed-user" {
		t.Errorf("params.name: got %q, want the offending name", body.Params["name"])
	}
	if got := f.mustGetPolicy(user.ID); got == nil || got.Name != "route-user" {
		t.Errorf("the rejected rename altered the row: %+v", got)
	}
}

// 🔒 `CedarPolicyRoutesTest` case 5 — "REST-shaped policy mutation remains bound to its numeric id
// after name reuse".
//
// THE KOTLIN'S OWN STAGING, which is the sharp one: the original row is RENAMED and a NEW row takes
// its old name, so BOTH are alive. An implementation that re-resolved by name would edit the
// namesake and leave the original untouched — and both rows would still exist afterwards, so only
// checking WHICH row moved can detect it.
//
// cedarroutes_db_test.go's TestPolicyMutationStaysBoundToItsNumericIdAfterNameReuse stages the same
// property differently (delete, then recreate under the old name, then expect a 404 on the dead id).
// That catches name-resolution too, but it cannot distinguish "edited the wrong live row" — there is
// only one live row in it. This case is deliberately the two-live-rows form, and it goes through
// PolicyManagement exactly as the Kotlin goes through PolicyManagementService.
// KT: CedarPolicyRoutesTest.kt#REST-shaped policy mutation remains bound to its numeric id after name reuse
func TestRESTShapedPolicyMutationRemainsBoundToItsNumericIDAfterNameReuse(t *testing.T) {
	f := newRouteFixture(t)
	operator := types.Ptr("operator@example.com")

	original, err := f.policies.Create(f.ctx, NewCedarPolicyInput("id-stable-policy", validCedarSrc), operator)
	if err != nil {
		t.Fatalf("create the original: %v", err)
	}
	if _, err := f.policies.Update(f.ctx, original.ID,
		NewCedarPolicyInput("id-stable-policy-renamed", validCedarSrc), operator); err != nil {
		t.Fatalf("rename the original: %v", err)
	}
	replacement, err := f.policies.Create(f.ctx, NewCedarPolicyInput("id-stable-policy", validCedarSrc), operator)
	if err != nil {
		t.Fatalf("create the namesake: %v", err)
	}
	if replacement.ID == original.ID {
		t.Fatal("the namesake must be a different row; the case is vacuous otherwise")
	}

	updated, err := f.management.UpdatePolicy(f.ctx, original.ID,
		NewCedarPolicyInput("id-stable-policy-final", validCedarSrc), operator)
	if err != nil {
		t.Fatalf("update by id: %v", err)
	}

	if updated.ID != original.ID {
		t.Errorf("the update answered id %d, want the id it was given (%d)", updated.ID, original.ID)
	}
	if got := f.mustGetPolicy(original.ID); got == nil || got.Name != "id-stable-policy-final" {
		t.Errorf("the original row did not take the update: %+v", got)
	}
	if got := f.mustGetPolicy(replacement.ID); got == nil || got.Name != "id-stable-policy" {
		t.Errorf("the namesake was edited instead of the row addressed by id: %+v", got)
	}
}
