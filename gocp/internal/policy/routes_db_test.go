package policy

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A9's eleven routes — 09-policies.md §3.
//
// 🔴 THERE IS NOTHING TO MIGRATE. 09-policies.md §4 verified by search that NO Kotlin test HTTP-calls
// `/api/roles`, `/api/role-assignments` or `/api/mask-fns`, that there is no `PolicyStoreTest`, and
// that neither INV-A9-3 nor INV-A9-4 has a single assertion anywhere (00-INDEX.md F10). So:
//
//	"A9 cannot be validated by 1:1 test migration — there is nothing to migrate. It is the one area
//	 where Step 3's plan does not apply. […] Step 3 should WRITE NEW TESTS here: 11 route tests
//	 (gate + status + shape) […] and the two flagged inconsistencies (INV-A9-3, INV-A9-4) so they
//	 become DELIBERATE rather than incidental."  — 09-policies.md:180-190
//
// ORACLE: 09-policies.md §3's route table (:112-125) for the gate and success status of each of the
// eleven, §1's DTO table for the shapes, and §2 for the store behaviour underneath. Every case below
// cites the line it comes from. There is no JVM here and no Kotlin assertion to defer to, which is
// exactly why the citations are to the SPEC and are stated as such.
// ---------------------------------------------------------------------------------------------

// a9Routes is 09-policies.md §3's table, transcribed. `action` is the gate each row demands;
// requireAPI is spelled as the zero AuthzAction because [Routes.listRoles] calls RequireAPI and never
// reaches Cedar at all.
var a9Routes = []struct {
	method string
	path   string
	body   string
	// action is the Cedar action the route demands, or requireAPIOnly for the one route that asks
	// only "is there a session".
	action  authz.AuthzAction
	success int
}{
	{http.MethodGet, "/api/roles", "", requireAPIOnly, http.StatusOK},
	{http.MethodPost, "/api/roles", `{"name":"gate-probe-role"}`, authz.ActionAdminPolicies, http.StatusCreated},
	{http.MethodPut, "/api/roles/{id}", `{"name":"renamed-role"}`, authz.ActionAdminPolicies, http.StatusOK},
	{http.MethodDelete, "/api/roles/{id}", "", authz.ActionAdminPolicies, http.StatusNoContent},

	{http.MethodGet, "/api/role-assignments", "", authz.ActionAdminIdentity, http.StatusOK},
	{http.MethodPost, "/api/role-assignments", `{"principal":"p","roleId":{roleId}}`, authz.ActionAdminIdentity, http.StatusCreated},
	{http.MethodDelete, "/api/role-assignments/{assignmentId}", "", authz.ActionAdminIdentity, http.StatusNoContent},

	{http.MethodGet, "/api/mask-fns", "", authz.ActionAdminPolicies, http.StatusOK},
	{http.MethodPost, "/api/mask-fns", `{"name":"gate-probe-fn","kind":"FIXED"}`, authz.ActionAdminPolicies, http.StatusCreated},
	{http.MethodPut, "/api/mask-fns/{maskFnId}", `{"name":"renamed-fn","kind":"LAST_N"}`, authz.ActionAdminPolicies, http.StatusOK},
	{http.MethodDelete, "/api/mask-fns/{maskFnId}", "", authz.ActionAdminPolicies, http.StatusNoContent},
}

// requireAPIOnly marks the one row whose gate is requireApi rather than a Cedar action. It is a
// sentinel, not an action: [authz.AuthzAction] is a string type, and no real action is empty.
const requireAPIOnly authz.AuthzAction = ""

// ---- The gate map ----------------------------------------------------------------------------

// 🔒 THE WHOLE GATE MAP IN ONE SWEEP, including INV-A9-3's exception.
//
// The split is by RESOURCE, not by file: roles and mask functions are `admin.policies`, assignments
// are `admin.identity` (09-policies.md:112-125). An assignment is a statement about a PERSON, so it
// belongs to whoever administers the directory.
//
// A test that only checked "403 when denied" would pass with every route demanding the same action.
// Recording WHICH action is asked is the only way this table is actually asserted.
func TestTheA9GateMapIsExactlyTheSpecTable(t *testing.T) {
	f := newRouteFixture(t)
	cookie := f.login("admin@example.com")
	ids := f.seedA9Fixtures()

	for _, rt := range a9Routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			f.authz.allowed = true
			f.authz.reset()

			f.do(rt.method, ids.expand(rt.path), ids.expand(rt.body), cookie)

			if rt.action == requireAPIOnly {
				// 🔒 INV-A9-3 — requireApi NEVER reaches Cedar. Not "Cedar allowed it": Cedar was not
				// asked, which is the observable difference between requireApi and requireAdmin and the
				// only way to tell a mis-gated route from a permissively-gated one.
				if len(f.authz.actions) != 0 {
					t.Errorf("GET /api/roles is requireApi and must not consult Cedar; it asked %v",
						f.authz.actions)
				}
				return
			}
			if got := f.authz.only(t); got != rt.action {
				t.Errorf("action: got %v, want %v", got, rt.action)
			}
			if _, ok := f.authz.resources[0].(authz.ResourceSystem); !ok {
				t.Errorf("resource: got %T, want authz.ResourceSystem (requireAdmin's default)",
					f.authz.resources[0])
			}
		})
	}
}

// 🔒 INV-A9-3 — `GET /api/roles` IS `requireApi`, NOT `requireAdmin`, AND THAT IS DELIBERATE.
//
// 09-policies.md:127-138 verified the reason rather than assuming one: `web/src/lib/hooks.ts:131`'s
// `useRoles()` is consumed by two NON-ADMIN surfaces — `components/query/request-access-dialog.tsx:58`
// and `components/workflows/role-request-composer.tsx:51` — where an ordinary user picks the role to
// request elevation TO. Tightening this to requireAdmin breaks JIT elevation for every non-admin
// user, which is the product.
//
// So this asserts the LOOSE behaviour on purpose: a session Cedar DENIES everything to still lists
// every role. It is the pin a well-meaning "why is this route not admin-gated?" fix must change.
//
// The contrast in the same file is the proof it is considered rather than accidental: `GET
// /api/mask-fns`, two handlers below, IS `admin.policies` and 403s for the same caller.
func TestListRolesIsOpenToAnySessionWhileListMaskFnsIsNot(t *testing.T) {
	f := newRouteFixture(t)
	f.store.CreateRole(f.ctx, RoleInput{Name: "pii-accessor", Description: types.Ptr("reads PII")})

	// A principal Cedar denies EVERYTHING.
	f.authz.allowed = false
	f.authz.reset()
	cookie := f.login("ordinary@example.com")

	rec := f.do(http.MethodGet, "/api/roles", "", cookie)
	assertStatus(t, rec, http.StatusOK, "GET /api/roles for a non-admin")
	var roles []Role
	decodeJSON(t, rec, &roles)
	if len(roles) == 0 {
		t.Fatal("an ordinary session must see the role list — JIT elevation depends on it")
	}
	found := false
	for _, r := range roles {
		if r.Name == "pii-accessor" {
			found = true
			if r.Description == nil || *r.Description != "reads PII" {
				t.Errorf("description: got %v, want the stored one", r.Description)
			}
		}
	}
	if !found {
		t.Error("the role the user would request elevation to must be listed")
	}

	// The contrast, in the same file, for the same caller.
	f.authz.reset()
	rec = f.do(http.MethodGet, "/api/mask-fns", "", cookie)
	assertStatus(t, rec, http.StatusForbidden, "GET /api/mask-fns for a non-admin")
	assertAPIError(t, rec, "common.forbidden", "GET /api/mask-fns for a non-admin")
}

// What leaks through INV-A9-3 is a role's NAME and DESCRIPTION, nothing more — no membership, no
// policy source, no principal. That bound is the argument for the looseness, so it is asserted
// rather than assumed: if `Role` ever grows a field, this test is what notices.
func TestTheRoleListLeaksOnlyNameAndDescription(t *testing.T) {
	f := newRouteFixture(t)
	role := f.mustCreateRoleViaStore("leaky", types.Ptr("d"))
	f.mustAssignRole("someone@example.com", role.ID)

	f.authz.allowed = false
	rec := f.do(http.MethodGet, "/api/roles", "", f.login("ordinary@example.com"))
	assertStatus(t, rec, http.StatusOK, "list roles")

	var rows []map[string]any
	decodeJSON(t, rec, &rows)
	for _, row := range rows {
		for key := range row {
			switch key {
			case "id", "name", "description":
			default:
				t.Errorf("Role exposes an unexpected field %q — INV-A9-3's disclosure bound is "+
					"name + description only", key)
			}
		}
	}
}

// Every admin-gated A9 route answers 401 with no session and 403 when Cedar denies. `GET /api/roles`
// is excluded from the 403 half by INV-A9-3 and asserted above instead.
func TestAdminGatedA9RoutesAnswer401And403(t *testing.T) {
	f := newRouteFixture(t)
	ids := f.seedA9Fixtures()

	for _, rt := range a9Routes {
		if rt.action == requireAPIOnly {
			continue
		}
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			f.authz.allowed = true
			f.authz.reset()
			rec := f.do(rt.method, ids.expand(rt.path), ids.expand(rt.body))
			assertStatus(t, rec, http.StatusUnauthorized, "no session")
			assertAPIError(t, rec, "common.unauthenticated", "no session")
			if len(f.authz.actions) != 0 {
				t.Errorf("Cedar was consulted for an unauthenticated request: %v", f.authz.actions)
			}

			f.authz.allowed = false
			f.authz.reset()
			rec = f.do(rt.method, ids.expand(rt.path), ids.expand(rt.body), f.login("nobody@example.com"))
			assertStatus(t, rec, http.StatusForbidden, "denied")
			assertAPIError(t, rec, "common.forbidden", "denied")
		})
	}
}

// GET /api/roles still requires A session — requireApi is not "no gate".
func TestListRolesStillRequiresASession(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.do(http.MethodGet, "/api/roles", "")

	assertStatus(t, rec, http.StatusUnauthorized, "no session")
	assertAPIError(t, rec, "common.unauthenticated", "no session")
}

// ---- The success statuses --------------------------------------------------------------------

// 09-policies.md §3's success column, swept: POST is **201**, DELETE is **204**, GET and PUT are 200.
//
// The statuses are bolded in the spec table precisely because they are the easy thing to get wrong —
// a Go handler that falls through to the implicit 200 is indistinguishable from a correct one until
// a client checks for 201.
func TestEveryA9RouteAnswersItsSpecifiedSuccessStatus(t *testing.T) {
	for _, rt := range a9Routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			// A fresh fixture per row: the DELETE rows consume the ids the others read.
			f := newRouteFixture(t)
			ids := f.seedA9Fixtures()

			rec := f.admin(rt.method, ids.expand(rt.path), ids.expand(rt.body))

			assertStatus(t, rec, rt.success, "success status")
			if rt.success == http.StatusNoContent && rec.Body.Len() != 0 {
				t.Errorf("204 must carry no body, got %q", rec.Body.String())
			}
		})
	}
}

// ---- Body shapes -----------------------------------------------------------------------------

// The six DTOs of 09-policies.md §1, as the routes actually emit them. `roleName` is DENORMALIZED
// from the join — the UI shows the name, so every read path joins `app_role` — and an assignment
// response that omitted it would render a blank row in the console.
func TestAssignmentBodiesCarryTheDenormalizedRoleName(t *testing.T) {
	f := newRouteFixture(t)
	role := f.mustCreateRoleViaStore("analyst", nil)

	rec := f.admin(http.MethodPost, "/api/role-assignments",
		`{"principal":"alice@example.com","roleId":`+strconv.FormatInt(role.ID, 10)+`}`)
	assertStatus(t, rec, http.StatusCreated, "create assignment")

	var created RoleAssignment
	decodeJSON(t, rec, &created)
	if created.RoleName != "analyst" {
		t.Errorf("roleName: got %q, want \"analyst\" from the join", created.RoleName)
	}
	if created.Principal != "alice@example.com" || created.RoleID != role.ID || created.ID <= 0 {
		t.Errorf("body: %+v", created)
	}

	rec = f.admin(http.MethodGet, "/api/role-assignments", "")
	var listed []RoleAssignment
	decodeJSON(t, rec, &listed)
	if len(listed) != 1 || listed[0].RoleName != "analyst" {
		t.Errorf("list: %+v", listed)
	}
}

// 🔒 INV-A9-2 — the assignment upsert is IDEMPOTENT. Re-posting an existing (principal, roleId) pair
// answers **201 with the EXISTING row's id**, not a conflict, because the store's
// `ON CONFLICT … DO UPDATE SET principal=EXCLUDED.principal RETURNING id` absorbs it.
//
// 09-policies.md:70-76: "a deliberate no-op write whose only purpose is to make `RETURNING id` fire
// on conflict (a plain `DO NOTHING` returns no row). […] do not 'simplify' it to `DO NOTHING`, which
// would return zero rows and NPE the caller." The console's "grant role" button is safe to
// double-click, and that is the behaviour rather than an accident.
func TestRepostingAnAssignmentIsIdempotentAndReturnsTheExistingId(t *testing.T) {
	f := newRouteFixture(t)
	role := f.mustCreateRoleViaStore("idem", nil)
	body := `{"principal":"alice@example.com","roleId":` + strconv.FormatInt(role.ID, 10) + `}`

	rec := f.admin(http.MethodPost, "/api/role-assignments", body)
	assertStatus(t, rec, http.StatusCreated, "first POST")
	var first RoleAssignment
	decodeJSON(t, rec, &first)

	rec = f.admin(http.MethodPost, "/api/role-assignments", body)
	assertStatus(t, rec, http.StatusCreated, "second POST — still 201, not 409")
	var second RoleAssignment
	decodeJSON(t, rec, &second)

	if second.ID != first.ID {
		t.Errorf("the upsert must return the EXISTING id: %d then %d", first.ID, second.ID)
	}
	rec = f.admin(http.MethodGet, "/api/role-assignments", "")
	var listed []RoleAssignment
	decodeJSON(t, rec, &listed)
	if len(listed) != 1 {
		t.Errorf("re-posting must not create a second row, got %d", len(listed))
	}
}

// ⚠️ INV-A9-4 — `GET /api/role-assignments` ANSWERS `[]` FOR A MALFORMED `roleId`, not
// `400 common.bad_id` like every other id-taking route in the port.
//
// The Kotlin is one line (09-policies.md:143-145):
//
//	if (roleIdRaw != null && roleId == null) return@get call.respond(emptyList<RoleAssignment>())
//
// 09-policies.md:146-147: "An inconsistency in the wire contract. `web/` may depend on it. Replicate,
// flag, do NOT 'fix' during the port."
//
// This is the pin routes.go:196-197 names by exactly this test name. A deliberate alignment with
// common.bad_id must change it, and 09-policies.md Q3 — does `web/` actually depend on the `[]`? — is
// what must be answered first.
func TestListAssignmentsAnswersEmptyForMalformedRoleId(t *testing.T) {
	f := newRouteFixture(t)
	role := f.mustCreateRoleViaStore("present", nil)
	f.mustAssignRole("alice@example.com", role.ID)

	rec := f.admin(http.MethodGet, "/api/role-assignments?roleId=abc", "")

	assertStatus(t, rec, http.StatusOK, "malformed roleId")
	if got := rec.Body.String(); got != `[]` {
		t.Errorf("body: got %s, want [] (INV-A9-4)", got)
	}

	// The contrast, on the SAME parameter name, one route over: an id in the PATH is a 400.
	rec = f.admin(http.MethodDelete, "/api/role-assignments/abc", "")
	assertStatus(t, rec, http.StatusBadRequest, "malformed id in the path")
	assertAPIError(t, rec, "common.bad_id", "malformed id in the path")

	t.Log("INV-A9-4 is a REPRODUCED INCONSISTENCY, not a design choice. TODO(A9): 09-policies.md Q3 " +
		"— confirm web/ depends on the [] before anyone aligns this with common.bad_id.")
}

// The distinction INV-A9-4 turns on is PRESENCE, not emptiness, and Go's `Query().Get()` collapses
// the two (it returns "" for both "absent" and "?roleId="). routes.go uses `Has()` for exactly this
// reason: using Get alone would turn "no filter" into "empty filter" and silently answer `[]` to the
// console's unfiltered list.
func TestAnAbsentRoleIdIsAnUnfilteredListWhileAnEmptyOneIsMalformed(t *testing.T) {
	f := newRouteFixture(t)
	role := f.mustCreateRoleViaStore("filterme", nil)
	f.mustAssignRole("alice@example.com", role.ID)

	rec := f.admin(http.MethodGet, "/api/role-assignments", "")
	var unfiltered []RoleAssignment
	decodeJSON(t, rec, &unfiltered)
	if len(unfiltered) != 1 {
		t.Fatalf("no roleId at all must be the UNFILTERED list, got %d rows", len(unfiltered))
	}

	// `?roleId=` is PRESENT and unparseable, so INV-A9-4 applies and the answer is [].
	rec = f.admin(http.MethodGet, "/api/role-assignments?roleId=", "")
	if got := rec.Body.String(); got != `[]` {
		t.Errorf("?roleId= (present, empty) must be []: got %s", got)
	}

	// ⚠️ `principal` has NO such special case: `?principal=` filters on the empty string and
	// legitimately returns [] because no assignment has a blank principal. Same bytes, different
	// reason — reproduced by the same Has/Get pair.
	rec = f.admin(http.MethodGet, "/api/role-assignments?principal=", "")
	if got := rec.Body.String(); got != `[]` {
		t.Errorf("?principal= filters on \"\" and matches nothing: got %s", got)
	}

	rec = f.admin(http.MethodGet, "/api/role-assignments?principal=alice@example.com", "")
	var filtered []RoleAssignment
	decodeJSON(t, rec, &filtered)
	if len(filtered) != 1 {
		t.Errorf("?principal=alice@example.com must match: got %d rows", len(filtered))
	}
}

// A well-formed but nonexistent roleId is an ordinary empty result — the filter matched nothing. The
// bytes are the same `[]` INV-A9-4 produces, which is why that case needs the malformed input to be
// meaningful at all.
func TestAWellFormedUnknownRoleIdIsAnOrdinaryEmptyResult(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodGet, "/api/role-assignments?roleId=987654", "")

	assertStatus(t, rec, http.StatusOK, "unknown roleId")
	if got := rec.Body.String(); got != `[]` {
		t.Errorf("body: got %s, want []", got)
	}
}

// 🔒 INV-A1-4 — an empty collection is `[]`, never `null`. All three list routes, because a nil slice
// reaching the wire is the single most common Go-vs-kotlinx shape break and the console renders
// `.length` on every one of these.
func TestEveryA9ListRouteEmitsAnEmptyArrayNotNull(t *testing.T) {
	f := newRouteFixture(t)

	for _, path := range []string{"/api/role-assignments", "/api/mask-fns"} {
		t.Run(path, func(t *testing.T) {
			rec := f.admin(http.MethodGet, path, "")
			assertStatus(t, rec, http.StatusOK, "empty list")
			if got := rec.Body.String(); got != `[]` {
				t.Errorf("body: got %s, want []", got)
			}
		})
	}
	// /api/roles is never empty — V8 seeds twelve roles — so its non-null shape is asserted by the
	// decode in TestListRolesIsOpenToAnySessionWhileListMaskFnsIsNot instead.
}

// ---- Roles: the system-role guard --------------------------------------------------------------

// 🔒 INV-A11-30 / F6 — the `isSystemRole` guard lives in the MANAGEMENT layer, and this is the test
// management_crud.go:283-284 names by exactly this name ("it has NO Kotlin test (00-INDEX.md F19)…
// so TestUpdateRoleRejectsASystemRole below is NEW").
//
// 🔒 INV-A9-1 — "system role" is DERIVED, not a column: a role is a system role iff at least one
// group with `source = 'SYSTEM'` grants it. There is no `app_role.is_system` flag, and adding one
// would change the semantics — a role would stop being protected only by an explicit edit rather
// than by the last SYSTEM mapping going away. The fixture therefore MAKES a role systemic by
// mapping it, and the "not protected any more" half is asserted by removing the mapping.
func TestUpdateRoleRejectsASystemRole(t *testing.T) {
	f := newRouteFixture(t)
	role := f.mustCreateRoleViaStore("derived-system", nil)
	groupID := f.systemGroup("idp-admins")
	f.mapGroupRole(groupID, role.ID)

	id := strconv.FormatInt(role.ID, 10)

	rec := f.admin(http.MethodPut, "/api/roles/"+id, `{"name":"renamed"}`)
	assertStatus(t, rec, http.StatusConflict, "PUT a system role")
	assertAPIError(t, rec, "role.system_immutable", "PUT a system role")

	rec = f.admin(http.MethodDelete, "/api/roles/"+id, "")
	assertStatus(t, rec, http.StatusConflict, "DELETE a system role")
	assertAPIError(t, rec, "role.system_immutable", "DELETE a system role")

	if got := f.mustGetRole(role.ID); got == nil || got.Name != "derived-system" {
		t.Errorf("the role was mutated despite the guard: %+v", got)
	}

	// 🔒 INV-A9-1 — DERIVED. Drop the SYSTEM mapping and the same role becomes mutable, with no edit
	// to the role row itself. A port that added an `is_system` column would fail here.
	f.exec(`DELETE FROM group_role WHERE group_id = $1 AND role_id = $2`, groupID, role.ID)
	rec = f.admin(http.MethodPut, "/api/roles/"+id, `{"name":"now-mutable"}`)
	assertStatus(t, rec, http.StatusOK, "PUT after the SYSTEM mapping is gone")
}

// A role granted only by a LOCAL group is NOT a system role — `isSystemRole` keys on
// `app_group.source = 'SYSTEM'` and nothing else.
func TestARoleGrantedOnlyByALocalGroupIsNotProtected(t *testing.T) {
	f := newRouteFixture(t)
	role := f.mustCreateRoleViaStore("local-only", nil)
	groupID := f.localGroup("team-analytics")
	f.mapGroupRole(groupID, role.ID)

	rec := f.admin(http.MethodPut, "/api/roles/"+strconv.FormatInt(role.ID, 10), `{"name":"renamed"}`)

	assertStatus(t, rec, http.StatusOK, "PUT a LOCAL-granted role")
}

// ---- Roles / mask functions: the ordinary error paths -------------------------------------------

// A duplicate name is `common.already_exists`, which ⚠️ is NOT an arm of respondManagementError's
// switch and therefore answers **400**, not the 409 a route responding directly would give
// (management_crud.go:54-57). Reproduced, and pinned here so the difference is visible rather than
// surprising.
func TestADuplicateRoleNameIsAlreadyExistsAt400(t *testing.T) {
	f := newRouteFixture(t)
	f.mustCreateRoleViaStore("taken", nil)

	rec := f.admin(http.MethodPost, "/api/roles", `{"name":"taken"}`)

	assertStatus(t, rec, http.StatusBadRequest, "duplicate role name")
	body := assertAPIError(t, rec, "common.already_exists", "duplicate role name")
	if body.Params["resource"] != ResourceRole {
		t.Errorf("params.resource: got %q, want %q", body.Params["resource"], ResourceRole)
	}
	if body.Params["name"] != "taken" {
		t.Errorf("params.name: got %q, want \"taken\"", body.Params["name"])
	}
}

// The missing-row answer on every A9 id-taking route is the same inferred 404 the policy delete path
// uses, with the per-resource literal interpolated into `params.resource`.
func TestMissingIdsAnswerNotFoundWithTheResourceLiteral(t *testing.T) {
	f := newRouteFixture(t)

	for _, probe := range []struct {
		method, path, body, resource string
	}{
		{http.MethodPut, "/api/roles/987654", `{"name":"ghost"}`, ResourceRole},
		{http.MethodDelete, "/api/roles/987654", "", ResourceRole},
		{http.MethodDelete, "/api/role-assignments/987654", "", ResourceRoleAssignment},
		{http.MethodPut, "/api/mask-fns/987654", `{"name":"ghost","kind":"FIXED"}`, ResourceMaskFn},
		{http.MethodDelete, "/api/mask-fns/987654", "", ResourceMaskFn},
	} {
		t.Run(probe.method+" "+probe.path, func(t *testing.T) {
			rec := f.admin(probe.method, probe.path, probe.body)
			assertStatus(t, rec, http.StatusNotFound, "missing id")
			body := assertAPIError(t, rec, "common.not_found", "missing id")
			if body.Params["resource"] != probe.resource {
				t.Errorf("params.resource: got %q, want %q", body.Params["resource"], probe.resource)
			}
		})
	}
}

// ⚠️ ALL FOUR `resource` LITERALS ARE INFERRED, not quoted anywhere in the spec set
// (management_crud.go:68-79). They are WIRE-VISIBLE: `web/` interpolates `{resource}` into a
// localized sentence and a missing key renders as the raw code.
//
// This is the pin management_crud.go:77 names by exactly this test name — TODO(A11) is to confirm
// all four against ManagementServices.kt at cutover, and a correction there is a one-line change
// here.
func TestManagementResourceLiterals(t *testing.T) {
	for _, c := range []struct{ got, want, why string }{
		{ResourcePolicy, "policy", "the ONE literal the spec quotes — 11-mcp-oauth-management.md:463"},
		{ResourceRole, "role", "INFERRED — matches internal/types.NotFound's own doc example"},
		{ResourceRoleAssignment, "role assignment", "INFERRED — follows A3's \"group role mapping\" phrasing"},
		{ResourceMaskFn, "mask function", "INFERRED — spells the table name out, as A3 does"},
	} {
		if c.got != c.want {
			t.Errorf("resource literal: got %q, want %q (%s)", c.got, c.want, c.why)
		}
	}
}

// An unparseable id in the PATH is 400 `common.bad_id` on every A9 route that takes one — the
// contrast INV-A9-4 is an exception TO.
func TestUnparseableIdsAreBadIdOnEveryA9PathParameter(t *testing.T) {
	f := newRouteFixture(t)

	for _, probe := range []struct{ method, path, body string }{
		{http.MethodPut, "/api/roles/abc", `{"name":"x"}`},
		{http.MethodDelete, "/api/roles/abc", ""},
		{http.MethodDelete, "/api/role-assignments/abc", ""},
		{http.MethodPut, "/api/mask-fns/abc", `{"name":"x","kind":"FIXED"}`},
		{http.MethodDelete, "/api/mask-fns/abc", ""},
	} {
		t.Run(probe.method+" "+probe.path, func(t *testing.T) {
			rec := f.admin(probe.method, probe.path, probe.body)
			assertStatus(t, rec, http.StatusBadRequest, "bad id")
			assertAPIError(t, rec, "common.bad_id", "bad id")
		})
	}
}

// ⚠️ `mask_fn.kind` is FREE-FORM — `TEXT NOT NULL` with no CHECK (V2__catalog.sql:67-71) and no
// validation in `Policies.kt`, so an admin can create a mask fn whose kind the engine cannot apply.
// 09-policies.md Q4 is open on whether anything validates it anywhere; nothing does. REPRODUCE.
func TestMaskFnKindIsNotValidated(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/mask-fns", `{"name":"nonsense","kind":"NOT_A_REAL_KIND"}`)

	assertStatus(t, rec, http.StatusCreated, "an unknown kind is accepted")
	var got MaskFn
	decodeJSON(t, rec, &got)
	if got.Kind != "NOT_A_REAL_KIND" {
		t.Errorf("kind: got %q, want it stored verbatim", got.Kind)
	}
	t.Log("REPRODUCED: 09-policies.md Q4 is open on whether anything validates mask_fn.kind. " +
		"Nothing does, at any layer.")
}

// ⚠️ An unknown `roleId` on POST /api/role-assignments violates the `principal_role.role_id` FOREIGN
// KEY (SQLSTATE 23503), which store.IsUniqueViolation deliberately does not match and which nothing
// else maps either. It therefore reaches StatusPages as 500 common.fallback.
//
// REPRODUCE: the Kotlin has no 23503 arm, and inventing a 404 `notFound("role")` here would be a fix,
// not a port (management_crud.go:369-372). This test is the pin such a fix must change.
func TestAnUnknownRoleIdOnAssignmentCreateIs404(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/role-assignments", `{"principal":"alice","roleId":987654}`)

	// 🔒 404, NOT the 500 this case used to assert. It was written from the reading that the route calls
	// the raw store passthrough, whose FK violation (23503) reaches StatusPages as common.fallback —
	// "the Kotlin has no 23503 arm either". That reading was wrong: `post("/api/role-assignments")` calls
	// `management.assignRole(input.principal, input.roleId)` (Policies.kt:197), which RESOLVES the role
	// first and throws notFound("role") (ManagementServices.kt:397). The 23503 arm is unnecessary because
	// the FK is never reached.
	//
	// Measured, not re-read: internal/conformance/differential booted both control-planes and asked them
	// (r2-create-assignment-missing-role → kotlin=404, go=500 before the route was rewired).
	assertStatus(t, rec, http.StatusNotFound, "unknown roleId")
	assertAPIError(t, rec, "common.not_found", "unknown roleId")
}

// TestABlankPrincipalOnAssignmentCreateIs400 is the other half of the same rewiring.
//
// 🔒 THIS WAS A REAL HOLE: the route accepted `{"principal":"","roleId":1}` and returned 201 with a
// persisted `principal_role` row keyed on the empty string, where the Kotlin answers 400
// common.required. A blank-principal grant is a row no identity can ever match and none can be revoked
// by principal, so it is a silent corruption of the assignment table rather than a cosmetic difference.
func TestABlankPrincipalOnAssignmentCreateIs400(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/role-assignments", `{"principal":"","roleId":1}`)

	assertStatus(t, rec, http.StatusBadRequest, "blank principal")
	assertAPIError(t, rec, "common.field_required", "blank principal")
}

// ---- fixture helpers -----------------------------------------------------------------------------

// a9IDs are the ids the sweep tables interpolate into their paths and bodies.
type a9IDs struct {
	role       int64
	assignment int64
	maskFn     int64
}

// expand substitutes the `{…}` placeholders in a sweep row. Deliberately NOT text/template: the
// placeholders share their syntax with ServeMux's wildcards, and a reader scanning the table should
// see the same braces the route patterns use.
func (ids a9IDs) expand(s string) string {
	repl := map[string]int64{
		"{id}":           ids.role,
		"{roleId}":       ids.role,
		"{assignmentId}": ids.assignment,
		"{maskFnId}":     ids.maskFn,
	}
	out := s
	for k, v := range repl {
		out = strings.ReplaceAll(out, k, strconv.FormatInt(v, 10))
	}
	return out
}

// seedA9Fixtures creates one row of each kind so the sweeps have live ids to address.
func (f *routeFixture) seedA9Fixtures() a9IDs {
	f.t.Helper()
	role := f.mustCreateRoleViaStore("sweep-role", nil)
	assignment := f.mustAssignRole("sweep@example.com", role.ID)
	fn := f.mustCreateMaskFn("sweep-fn", "FIXED")
	return a9IDs{role: role.ID, assignment: assignment.ID, maskFn: fn.ID}
}

func (f *routeFixture) mustCreateRoleViaStore(name string, description *string) Role {
	f.t.Helper()
	role, err := f.store.CreateRole(f.ctx, RoleInput{Name: name, Description: description})
	if err != nil {
		f.t.Fatalf("create role %s: %v", name, err)
	}
	return role
}

func (f *routeFixture) mustAssignRole(principal string, roleID int64) RoleAssignment {
	f.t.Helper()
	a, err := f.store.CreateAssignment(f.ctx, RoleAssignmentInput{Principal: principal, RoleID: roleID})
	if err != nil {
		f.t.Fatalf("assign %s: %v", principal, err)
	}
	return a
}

func (f *routeFixture) mustCreateMaskFn(name, kind string) MaskFn {
	f.t.Helper()
	fn, err := f.store.CreateMaskFn(f.ctx, MaskFnInput{Name: name, Kind: kind})
	if err != nil {
		f.t.Fatalf("create mask fn %s: %v", name, err)
	}
	return fn
}

func (f *routeFixture) mustGetRole(id int64) *Role {
	f.t.Helper()
	role, err := f.store.GetRole(f.ctx, id)
	if err != nil {
		f.t.Fatalf("get role %d: %v", id, err)
	}
	return role
}

// systemGroup inserts an `app_group` with `source = 'SYSTEM'` — the ONLY thing isSystemRole keys on
// (INV-A9-1).
func (f *routeFixture) systemGroup(name string) int64 {
	f.t.Helper()
	return f.scalarInt64(`INSERT INTO app_group (name, source) VALUES ($1, 'SYSTEM') RETURNING id`, name)
}

// localGroup takes the column default, so the derived guard must NOT fire for it.
func (f *routeFixture) localGroup(name string) int64 {
	f.t.Helper()
	return f.scalarInt64(`INSERT INTO app_group (name) VALUES ($1) RETURNING id`, name)
}

func (f *routeFixture) mapGroupRole(groupID, roleID int64) {
	f.t.Helper()
	f.exec(`INSERT INTO group_role (group_id, role_id) VALUES ($1, $2)`, groupID, roleID)
}

func (f *routeFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (f *routeFixture) scalarInt64(sql string, args ...any) int64 {
	f.t.Helper()
	var out int64
	if err := f.db.Pool.QueryRow(f.ctx, sql, args...).Scan(&out); err != nil {
		f.t.Fatalf("scalar %q: %v", sql, err)
	}
	return out
}
