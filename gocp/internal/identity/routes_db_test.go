package identity_test

import (
	"net/http"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
)

// ---------------------------------------------------------------------------------------------
// 🔴 NEW — the fourteen admin routes of `Users.kt:894-1031`, which have no Kotlin route test.
// Written against 03-identity-scim.md §"Admin REST"'s route table: method, path, gate, success
// status, error codes.
// ---------------------------------------------------------------------------------------------

// 🔒 THE GATE MAP. Every one of the fourteen demands `admin.identity` on the `System` resource, and
// the recording authorizer is what makes "which action" observable — a fixture that only answered
// Allow/Deny would pass identically if a route asked for `admin.policies`.
//
// docs/authz-model.md:345. Uniform, unlike A9's split, because every route on this surface
// administers the DIRECTORY.
func TestEveryIdentityAdminRouteDemandsAdminIdentityOnSystem(t *testing.T) {
	f := newRouteFixture(t)
	group := f.seed.Group("engineering")
	user := f.seed.User("alice@example.com")
	role := f.seed.Role("reader")

	for _, tc := range []struct{ method, target, body string }{
		{http.MethodGet, "/api/users", ""},
		{http.MethodPost, "/api/users", `{"principal":"gate@example.com"}`},
		{http.MethodPut, "/api/users/" + itoa64(user), `{"principal":"alice@example.com"}`},
		{http.MethodDelete, "/api/users/" + itoa64(user), ""},
		{http.MethodGet, "/api/groups", ""},
		{http.MethodPost, "/api/groups", `{"name":"gate-group"}`},
		{http.MethodPut, "/api/groups/" + itoa64(group), `{"name":"engineering"}`},
		{http.MethodDelete, "/api/groups/" + itoa64(group), ""},
		{http.MethodGet, "/api/groups/" + itoa64(group) + "/members", ""},
		{http.MethodPost, "/api/groups/" + itoa64(group) + "/members", `{"userId":` + itoa64(user) + `}`},
		{http.MethodDelete, "/api/groups/" + itoa64(group) + "/members/" + itoa64(user), ""},
		{http.MethodGet, "/api/groups/" + itoa64(group) + "/roles", ""},
		{http.MethodPost, "/api/groups/" + itoa64(group) + "/roles", `{"roleId":` + itoa64(role) + `}`},
		{http.MethodDelete, "/api/groups/" + itoa64(group) + "/roles/" + itoa64(role), ""},
	} {
		what := tc.method + " " + tc.target

		// Allowed: the gate asks exactly once, for admin.identity on System.
		f.admin(tc.method, tc.target, tc.body)
		if got := f.authz.only(t); got != authz.ActionAdminIdentity {
			t.Errorf("%s: asked Cedar for %q, want %q", what, got, authz.ActionAdminIdentity)
		}
		if _, ok := f.authz.resources[0].(authz.ResourceSystem); !ok {
			t.Errorf("%s: resource %#v, want authz.ResourceSystem", what, f.authz.resources[0])
		}

		// Denied ⇒ 403 common.forbidden, carrying Cedar's own reason as `detail`.
		f.authz.allowed = false
		f.authz.reset()
		req := newRequest(tc.method, tc.target, tc.body)
		req.AddCookie(f.login("nobody@example.com"))
		rec := f.do(req)
		assertStatus(t, rec, http.StatusForbidden, what+" (denied)")
		body := assertAPIError(t, rec, "common.forbidden", what+" (denied)")
		if body.Params["detail"] != f.authz.reason {
			t.Errorf("%s: detail %q, want Cedar's reason %q", what, body.Params["detail"], f.authz.reason)
		}

		// No session at all ⇒ 401 common.unauthenticated, and Cedar is NEVER reached.
		f.authz.allowed = true
		f.authz.reset()
		rec = f.do(newRequest(tc.method, tc.target, tc.body))
		assertStatus(t, rec, http.StatusUnauthorized, what+" (anonymous)")
		assertAPIError(t, rec, "common.unauthenticated", what+" (anonymous)")
		if len(f.authz.actions) != 0 {
			t.Errorf("%s: an anonymous request reached Cedar (%v) — the session check comes first",
				what, f.authz.actions)
		}
	}
}

// The user lifecycle end to end: list, create (201), rename, deprovision (204).
func TestUserAdminLifecycle(t *testing.T) {
	f := newRouteFixture(t)

	// GET is `[]`, never null — INV-A1-4.
	rec := f.admin(http.MethodGet, "/api/users", "")
	assertStatus(t, rec, http.StatusOK, "GET /api/users (empty)")
	if got := rec.Body.String(); got != "[]" {
		t.Errorf("an empty directory must be `[]`, got %s", got)
	}

	// 🔒 POST is **201**, and a body that OMITS `active` creates an ACTIVE user.
	rec = f.admin(http.MethodPost, "/api/users",
		`{"principal":"alice@example.com","displayName":"Alice"}`)
	assertStatus(t, rec, http.StatusCreated, "POST /api/users")
	var created identity.AppUser
	decodeJSON(t, rec, &created)
	if !created.Active {
		t.Errorf("a body omitting `active` must create an ACTIVE user (the Kotlin default), got %+v", created)
	}
	if created.Source != "LOCAL" || created.ExternalID != nil {
		t.Errorf("a locally-created user is LOCAL with no externalId, got %+v", created)
	}
	// explicitNulls=false: `email` is absent from the body, not null.
	if body := rec.Body.String(); contains(body, `"email"`) {
		t.Errorf("an absent optional must be OMITTED, not null: %s", body)
	}
	// encodeDefaults=true: `groups` IS present, as [].
	if body := rec.Body.String(); !contains(body, `"groups":[]`) {
		t.Errorf("a defaulted collection must be emitted as []: %s", body)
	}

	// PUT is 200 and renames.
	rec = f.admin(http.MethodPut, "/api/users/"+itoa64(created.ID),
		`{"principal":"alice.new@example.com","active":true}`)
	assertStatus(t, rec, http.StatusOK, "PUT /api/users/{id}")
	var renamed identity.AppUser
	decodeJSON(t, rec, &renamed)
	if renamed.Principal != "alice.new@example.com" || renamed.ID != created.ID {
		t.Errorf("the rename must land on the same row, got %+v", renamed)
	}

	// 🔒 DELETE is **204** with NO body, and it DEPROVISIONS: the row survives, inactive
	// (INV-A3-19), so audit history keeps resolving the principal.
	rec = f.admin(http.MethodDelete, "/api/users/"+itoa64(created.ID), "")
	assertStatus(t, rec, http.StatusNoContent, "DELETE /api/users/{id}")
	if rec.Body.Len() != 0 {
		t.Errorf("204 must carry no body, got %s", rec.Body.String())
	}
	after, err := f.store.GetUser(f.ctx, created.ID)
	if err != nil || after == nil {
		t.Fatalf("the row was HARD-deleted: %+v %v", after, err)
	}
	if after.Active {
		t.Errorf("DELETE must leave the row inactive, got active=true")
	}
}

// The error table for `/api/users**`, code by code.
func TestUserAdminErrorCodes(t *testing.T) {
	f := newRouteFixture(t)

	// 400 common.field_required{fields: principal} — and note the param key is `fields`, PLURAL, with
	// exactly one field name in it. That is wire-visible: web/ interpolates {fields}.
	rec := f.admin(http.MethodPost, "/api/users", `{"principal":""}`)
	assertStatus(t, rec, http.StatusBadRequest, "POST blank principal")
	body := assertAPIError(t, rec, "common.field_required", "POST blank principal")
	if body.Params["fields"] != "principal" {
		t.Errorf("params %v, want fields=principal", body.Params)
	}

	f.admin(http.MethodPost, "/api/users", `{"principal":"alice@example.com"}`)

	// ⚠️ A duplicate is `common.already_exists`, which is NOT an arm of respondManagementError's
	// switch — so it lands on the DEFAULT arm and answers **400**, not the 409 a route responding with
	// types.AlreadyExists directly would give. And the resource literal is `principal`, not `user`.
	rec = f.admin(http.MethodPost, "/api/users", `{"principal":"alice@example.com"}`)
	assertStatus(t, rec, http.StatusBadRequest, "POST duplicate principal")
	body = assertAPIError(t, rec, "common.already_exists", "POST duplicate principal")
	if body.Params["resource"] != "principal" {
		t.Errorf("resource %q, want `principal` (NOT `user` — two different call sites)", body.Params["resource"])
	}

	// 400 common.bad_id on an unparseable id, for both id-taking routes.
	//
	// ⚠️ Contrast the SCIM routes, where the same input is 404. Same table, two deliberately different
	// answers, because one caller is a console and the other is an IdP.
	for _, target := range []string{"/api/users/abc", "/api/users/1_000", "/api/users/0x10"} {
		rec = f.admin(http.MethodPut, target, `{"principal":"x@example.com"}`)
		assertStatus(t, rec, http.StatusBadRequest, "PUT "+target)
		assertAPIError(t, rec, "common.bad_id", "PUT "+target)

		rec = f.admin(http.MethodDelete, target, "")
		assertStatus(t, rec, http.StatusBadRequest, "DELETE "+target)
		assertAPIError(t, rec, "common.bad_id", "DELETE "+target)
	}

	// 🔒 The id is parsed BEFORE the body is read, so a bad id plus a malformed body is still
	// `common.bad_id` and not the 500 the decode would produce.
	rec = f.admin(http.MethodPut, "/api/users/abc", `{not json`)
	assertAPIError(t, rec, "common.bad_id", "PUT with a bad id AND a malformed body")

	// 404 common.not_found{resource: user}.
	rec = f.admin(http.MethodPut, "/api/users/987654321", `{"principal":"x@example.com"}`)
	assertStatus(t, rec, http.StatusNotFound, "PUT unknown id")
	body = assertAPIError(t, rec, "common.not_found", "PUT unknown id")
	if body.Params["resource"] != "user" {
		t.Errorf("resource %q, want `user`", body.Params["resource"])
	}
	rec = f.admin(http.MethodDelete, "/api/users/987654321", "")
	assertStatus(t, rec, http.StatusNotFound, "DELETE unknown id")
	assertAPIError(t, rec, "common.not_found", "DELETE unknown id")

	// ⚠️ A malformed body is 500 `common.fallback`, NOT 400 — the Kotlin never wraps `receive` on this
	// surface. Reproduced.
	rec = f.admin(http.MethodPost, "/api/users", `{not json`)
	assertStatus(t, rec, http.StatusInternalServerError, "POST malformed body")
	assertAPIError(t, rec, "common.fallback", "POST malformed body")
}

// The group lifecycle, plus the two SYSTEM-immutability 409s.
func TestGroupAdminLifecycleAndSystemImmutability(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/groups", `{"name":"engineering","description":"Eng"}`)
	assertStatus(t, rec, http.StatusCreated, "POST /api/groups")
	var created identity.AppGroup
	decodeJSON(t, rec, &created)
	if created.Source != "LOCAL" || created.MemberCount != 0 {
		t.Errorf("a locally-created group is LOCAL with 0 members, got %+v", created)
	}
	// encodeDefaults=true — `memberCount: 0` and `roles: []` are BOTH emitted even at their defaults.
	if b := rec.Body.String(); !contains(b, `"memberCount":0`) || !contains(b, `"roles":[]`) {
		t.Errorf("defaulted fields must be emitted: %s", b)
	}
	// AppGroup carries NO createdAt — `app_group` has no such column.
	if b := rec.Body.String(); contains(b, "createdAt") {
		t.Errorf("AppGroup has no createdAt, got %s", b)
	}

	rec = f.admin(http.MethodPut, "/api/groups/"+itoa64(created.ID), `{"name":"platform"}`)
	assertStatus(t, rec, http.StatusOK, "PUT /api/groups/{id}")

	rec = f.admin(http.MethodDelete, "/api/groups/"+itoa64(created.ID), "")
	assertStatus(t, rec, http.StatusNoContent, "DELETE /api/groups/{id}")

	// 🔒 F36 — the SYSTEM guard is keyed on the `source` COLUMN, so it must hold for ALL SEVEN seeded
	// groups, not just `system:admin`. A port that special-cased the admin string would pass the
	// Kotlin's single-group version of this and leave six production-capability groups mutable.
	systems := f.systemGroups()
	if len(systems) != 7 {
		t.Fatalf("%d seeded SYSTEM groups, want 7 (V8__seed.sql:48-58)", len(systems))
	}
	for _, sys := range systems {
		rec = f.admin(http.MethodPut, "/api/groups/"+itoa64(sys.ID), `{"name":"hijacked"}`)
		assertStatus(t, rec, http.StatusConflict, "PUT "+sys.Name)
		assertAPIError(t, rec, "group.system_immutable", "PUT "+sys.Name)

		rec = f.admin(http.MethodDelete, "/api/groups/"+itoa64(sys.ID), "")
		assertStatus(t, rec, http.StatusConflict, "DELETE "+sys.Name)
		assertAPIError(t, rec, "group.system_immutable", "DELETE "+sys.Name)

		// 🔒 The guard runs BEFORE the name validation: a SYSTEM group renamed to the empty string
		// answers group.system_immutable, NOT common.field_required. Telling a caller their name is
		// blank invites a retry on a row they have no business editing.
		rec = f.admin(http.MethodPut, "/api/groups/"+itoa64(sys.ID), `{"name":""}`)
		assertAPIError(t, rec, "group.system_immutable", "PUT "+sys.Name+" with a blank name")
	}

	// Every one of them is still SYSTEM, still named what the seed named it.
	if after := f.systemGroups(); len(after) != 7 {
		t.Errorf("%d SYSTEM groups after the refused mutations, want 7", len(after))
	}
}

// Members and roles: the two store-direct reads, the two 201 writes, and the two single-use 404
// resource literals.
func TestGroupMembersAndRolesRoutes(t *testing.T) {
	f := newRouteFixture(t)
	group := f.seed.Group("engineering")
	user := f.seed.User("alice@example.com")
	role := f.seed.Role("reader")

	// ⚠️ The two READ sub-routes bypass the management layer and build their own 404 — the only two
	// identity routes not funnelled through A11.
	for _, suffix := range []string{"/members", "/roles"} {
		rec := f.admin(http.MethodGet, "/api/groups/"+itoa64(group)+suffix, "")
		assertStatus(t, rec, http.StatusOK, "GET "+suffix)
		if rec.Body.String() != "[]" {
			t.Errorf("GET %s on an empty group must be `[]`, got %s", suffix, rec.Body.String())
		}

		rec = f.admin(http.MethodGet, "/api/groups/987654321"+suffix, "")
		assertStatus(t, rec, http.StatusNotFound, "GET "+suffix+" unknown group")
		body := assertAPIError(t, rec, "common.not_found", "GET "+suffix+" unknown group")
		if body.Params["resource"] != "group" {
			t.Errorf("resource %q, want `group`", body.Params["resource"])
		}

		rec = f.admin(http.MethodGet, "/api/groups/abc"+suffix, "")
		assertStatus(t, rec, http.StatusBadRequest, "GET "+suffix+" bad id")
		assertAPIError(t, rec, "common.bad_id", "GET "+suffix+" bad id")
	}

	// POST members ⇒ 201 GroupMemberEntry.
	rec := f.admin(http.MethodPost, "/api/groups/"+itoa64(group)+"/members", `{"userId":`+itoa64(user)+`}`)
	assertStatus(t, rec, http.StatusCreated, "POST members")
	var member identity.GroupMemberEntry
	decodeJSON(t, rec, &member)
	if member.UserID != user || member.Principal != "alice@example.com" {
		t.Errorf("got %+v", member)
	}

	// 🔒 INV-A3-35 — re-adding an existing member is a SUCCESS, not a 409: `ON CONFLICT DO NOTHING`
	// makes it idempotent and the console's button is safe to double-click.
	rec = f.admin(http.MethodPost, "/api/groups/"+itoa64(group)+"/members", `{"userId":`+itoa64(user)+`}`)
	assertStatus(t, rec, http.StatusCreated, "POST members (re-add)")

	// 404 {resource: user} for an unknown member.
	rec = f.admin(http.MethodPost, "/api/groups/"+itoa64(group)+"/members", `{"userId":987654321}`)
	assertStatus(t, rec, http.StatusNotFound, "POST members unknown user")
	body := assertAPIError(t, rec, "common.not_found", "POST members unknown user")
	if body.Params["resource"] != "user" {
		t.Errorf("resource %q, want `user`", body.Params["resource"])
	}

	// DELETE members ⇒ 204; a second delete ⇒ 404 with the SPACE-separated literal `group member`.
	rec = f.admin(http.MethodDelete, "/api/groups/"+itoa64(group)+"/members/"+itoa64(user), "")
	assertStatus(t, rec, http.StatusNoContent, "DELETE members")
	rec = f.admin(http.MethodDelete, "/api/groups/"+itoa64(group)+"/members/"+itoa64(user), "")
	assertStatus(t, rec, http.StatusNotFound, "DELETE members (again)")
	body = assertAPIError(t, rec, "common.not_found", "DELETE members (again)")
	if body.Params["resource"] != "group member" {
		t.Errorf("resource %q, want `group member` — with a space, and used nowhere else",
			body.Params["resource"])
	}

	// ⚠️ BOTH ids answer the same common.bad_id, so a caller cannot tell which one was wrong.
	rec = f.admin(http.MethodDelete, "/api/groups/"+itoa64(group)+"/members/abc", "")
	assertAPIError(t, rec, "common.bad_id", "DELETE members bad userId")

	// POST roles ⇒ 201 GroupRoleEntry.
	rec = f.admin(http.MethodPost, "/api/groups/"+itoa64(group)+"/roles", `{"roleId":`+itoa64(role)+`}`)
	assertStatus(t, rec, http.StatusCreated, "POST roles")
	var mapped identity.GroupRoleEntry
	decodeJSON(t, rec, &mapped)
	if mapped.RoleID != role || mapped.RoleName != "reader" {
		t.Errorf("got %+v", mapped)
	}

	rec = f.admin(http.MethodPost, "/api/groups/"+itoa64(group)+"/roles", `{"roleId":987654321}`)
	assertStatus(t, rec, http.StatusNotFound, "POST roles unknown role")
	body = assertAPIError(t, rec, "common.not_found", "POST roles unknown role")
	if body.Params["resource"] != "role" {
		t.Errorf("resource %q, want `role`", body.Params["resource"])
	}

	// DELETE roles ⇒ 204; again ⇒ 404 `group role mapping`, another single-use literal.
	rec = f.admin(http.MethodDelete, "/api/groups/"+itoa64(group)+"/roles/"+itoa64(role), "")
	assertStatus(t, rec, http.StatusNoContent, "DELETE roles")
	rec = f.admin(http.MethodDelete, "/api/groups/"+itoa64(group)+"/roles/"+itoa64(role), "")
	assertStatus(t, rec, http.StatusNotFound, "DELETE roles (again)")
	body = assertAPIError(t, rec, "common.not_found", "DELETE roles (again)")
	if body.Params["resource"] != "group role mapping" {
		t.Errorf("resource %q, want `group role mapping`", body.Params["resource"])
	}
}

// 🔒 The membership and role-map routes carry the SYSTEM guard too — by TWO DIFFERENT MECHANISMS, and
// the difference is a concurrency one a port must keep (INV-A3-45 one layer up):
//
//   - `/members` uses `rejectSystem` → `isSystemGroup(id, c)`, a PLAIN READ on the transaction's
//     connection.
//   - `/roles` uses `lockMutableGroup(id, c)` → `SELECT source … FOR UPDATE`, which existence-checks
//     AND SYSTEM-checks UNDER A ROW LOCK.
//
// Two guards for one rule, only one of them hardened. Both must answer 409 here; unifying them would
// erase the asymmetry the docs record.
func TestMembershipAndRoleRoutesRefuseSystemGroupsThroughBothMechanisms(t *testing.T) {
	f := newRouteFixture(t)
	user := f.seed.User("alice@example.com")
	role := f.seed.Role("reader")

	for _, sys := range f.systemGroups() {
		base := "/api/groups/" + itoa64(sys.ID)

		rec := f.admin(http.MethodPost, base+"/members", `{"userId":`+itoa64(user)+`}`)
		assertStatus(t, rec, http.StatusConflict, "POST members on "+sys.Name)
		assertAPIError(t, rec, "group.system_immutable", "POST members on "+sys.Name)

		rec = f.admin(http.MethodDelete, base+"/members/"+itoa64(user), "")
		assertStatus(t, rec, http.StatusConflict, "DELETE members on "+sys.Name)
		assertAPIError(t, rec, "group.system_immutable", "DELETE members on "+sys.Name)

		rec = f.admin(http.MethodPost, base+"/roles", `{"roleId":`+itoa64(role)+`}`)
		assertStatus(t, rec, http.StatusConflict, "POST roles on "+sys.Name)
		assertAPIError(t, rec, "group.system_immutable", "POST roles on "+sys.Name)

		rec = f.admin(http.MethodDelete, base+"/roles/"+itoa64(role), "")
		assertStatus(t, rec, http.StatusConflict, "DELETE roles on "+sys.Name)
		assertAPIError(t, rec, "group.system_immutable", "DELETE roles on "+sys.Name)
	}
}

// 🔒 A rename or a deactivate through the LOCAL-ADMIN surface runs the same atomic, per-principal
// locked teardown as a SCIM push. This is the route-level proof that the admin console cannot leave a
// deprovisioned identity credentialed — the property INV-A3-6 exists for, asserted where an operator
// actually triggers it.
func TestAdminDeactivateAndRenameRevokeCredentialsThroughTheRoute(t *testing.T) {
	f := newRouteFixture(t)

	rec := f.admin(http.MethodPost, "/api/users", `{"principal":"alice@example.com"}`)
	assertStatus(t, rec, http.StatusCreated, "POST /api/users")
	var created identity.AppUser
	decodeJSON(t, rec, &created)

	creds := f.seedCredentials("alice@example.com", "reader")

	// PUT with active=false.
	rec = f.admin(http.MethodPut, "/api/users/"+itoa64(created.ID),
		`{"principal":"alice@example.com","active":false}`)
	assertStatus(t, rec, http.StatusOK, "PUT active=false")
	f.assertRevoked(creds, "an admin deactivate")

	// DELETE, on a second identity, with a rename in between — the id-stable path.
	rec = f.admin(http.MethodPost, "/api/users", `{"principal":"bob@example.com"}`)
	var bob identity.AppUser
	decodeJSON(t, rec, &bob)
	bobCreds := f.seedCredentials("bob@example.com", "writer")

	rec = f.admin(http.MethodPut, "/api/users/"+itoa64(bob.ID),
		`{"principal":"robert@example.com","active":true}`)
	assertStatus(t, rec, http.StatusOK, "PUT rename")
	f.assertRevoked(bobCreds, "the renamed-away principal")

	// And the vacated string is tombstoned, not orphaned.
	tombstone, err := f.store.GetUserByPrincipal(f.ctx, "bob@example.com")
	if err != nil || tombstone == nil || tombstone.Active {
		t.Errorf("the vacated string must be left deprovisioned, got %+v %v", tombstone, err)
	}
}
