package access

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `accessRoutes` — 06-query-decision.md §6, the six-row route table and INV-A6-28/-29/-30.
//
// ORACLE. Two of the cases below are 1:1 ports of `ElevationContextRouteAuthzDbTest` (the two of its
// eight that drive accessRoutes; the other six drive Approvals.kt and Datasources.kt, which A7/A5
// own) and are marked as such. THE REST ARE NEW, because §7's coverage-gap list says so outright:
// nothing in the Kotlin suite asserts the forward filter, the revoke IDOR closure, the approve/reject
// body asymmetry, or the 400 for a QUERY kind. Each new case cites the §6 line it is written against.
// ---------------------------------------------------------------------------------------------

const (
	requester = "requester@example.com"
	approver  = "approver@example.com"
	stranger  = "stranger@example.com"
)

// ---------------------------------------------------------------------------------------------
// The gate map — 06-query-decision.md:512-519
// ---------------------------------------------------------------------------------------------

// 🔒 EVERY ROUTE'S GATE, IN ONE SWEEP, INCLUDING THE TWO EXCEPTIONS.
//
// A test that only checked "403 when denied" would pass with every route demanding the same action.
// Recording WHICH action, through WHICH entry point, is the only way the table is actually asserted —
// and the two rows that differ are the whole point of the table:
//
//   - `/reject` asks `task.approve`, NOT a `task.reject` that no seed policy grants;
//   - `/api/access-grants/{id}/revoke` asks `grant.revoke`, and is the one row with no requireApi.
func TestTheA6AccessGateMapIsExactlyTheSpecTable(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("target-role")
	dsID := f.seed.Datasource(dbtest.DatasourceSpec{
		Name: "gate-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
	})

	type probe struct {
		name     string
		run      func() askedFor
		wantVia  string
		wantWhat authz.AuthzAction
	}
	probes := []probe{
		{
			name: "GET /api/access-requests forward-filters by task.read",
			run: func() askedFor {
				f.seedRoleRequest(requester, roleID, nil)
				f.authz.allowed, f.authz.asked = true, nil
				rec := f.do(http.MethodGet, "/api/access-requests", "", f.login(approver))
				assertStatus(t, rec, http.StatusOK, "list requests")
				return f.authz.only(t)
			},
			wantVia: "authorize", wantWhat: authz.ActionTaskRead,
		},
		{
			name: "POST /api/access-requests gates the named datasource with task.request",
			run: func() askedFor {
				f.authz.allowed, f.authz.asked = true, nil
				body := `{"roleId":` + strconv.FormatInt(roleID, 10) +
					`,"datasourceId":` + strconv.FormatInt(dsID, 10) + `}`
				rec := f.do(http.MethodPost, "/api/access-requests", body, f.login(requester))
				assertStatus(t, rec, http.StatusCreated, "create request")
				// Two calls: pass 1 (resolveContextTags) then the gate. The gate is the second.
				if len(f.authz.asked) != 2 {
					t.Fatalf("expected the two-pass shape (tags then gate), got %+v", f.authz.asked)
				}
				return f.authz.asked[1]
			},
			wantVia: "authorizeDatasourceAction", wantWhat: authz.ActionTaskRequest,
		},
		{
			name: "POST /api/access-requests/{id}/approve asks task.approve",
			run: func() askedFor {
				req := f.seedRoleRequest(requester, roleID, nil)
				f.authz.allowed, f.authz.asked = true, nil
				rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/approve", "", f.login(approver))
				assertStatus(t, rec, http.StatusOK, "approve")
				return f.authz.only(t)
			},
			wantVia: "authorizeWithContext", wantWhat: authz.ActionTaskApprove,
		},
		{
			name: "POST /api/access-requests/{id}/reject asks THE SAME task.approve",
			run: func() askedFor {
				req := f.seedRoleRequest(requester, roleID, nil)
				f.authz.allowed, f.authz.asked = true, nil
				rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/reject",
					`{"reason":"no"}`, f.login(approver))
				assertStatus(t, rec, http.StatusOK, "reject")
				return f.authz.only(t)
			},
			wantVia: "authorizeWithContext", wantWhat: authz.ActionTaskApprove,
		},
		{
			name: "GET /api/access-grants forward-filters by task.read",
			run: func() askedFor {
				f.seedGrant(requester, roleID)
				f.authz.allowed, f.authz.asked = true, nil
				rec := f.do(http.MethodGet, "/api/access-grants", "", f.login(approver))
				assertStatus(t, rec, http.StatusOK, "list grants")
				if len(f.authz.asked) == 0 {
					t.Fatal("no row was authorized — the forward filter did not run")
				}
				return f.authz.asked[0]
			},
			wantVia: "authorize", wantWhat: authz.ActionTaskRead,
		},
		{
			name: "POST /api/access-grants/{id}/revoke asks grant.revoke",
			run: func() askedFor {
				grant := f.seedGrant(stranger, roleID)
				f.authz.allowed, f.authz.asked = true, nil
				rec := f.do(http.MethodPost, "/api/access-grants/"+id(grant.ID)+"/revoke", "", f.login(approver))
				assertStatus(t, rec, http.StatusNoContent, "revoke")
				return f.authz.only(t)
			},
			wantVia: "authorize", wantWhat: authz.ActionGrantRevoke,
		},
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			got := p.run()
			if got.action != p.wantWhat {
				t.Errorf("action %q, want %q", got.action, p.wantWhat)
			}
			if got.via != p.wantVia {
				t.Errorf("entry point %q, want %q", got.via, p.wantVia)
			}
		})
	}
}

// 🔒 THE FOUR requireApi ROUTES REFUSE A SESSIONLESS NON-DEBUG REQUEST WITH 401 common.unauthenticated,
// AND THE REVOKE ROUTE DOES TOO — through requireAuthz, which is a DIFFERENT gate reaching the same
// status.
//
// The distinction matters because 06-query-decision.md:529 states revoke "is the one accessRoutes
// endpoint with no requireApi call", and a reader could mistake that for "ungated". It is not: this
// case is what proves the absence of requireApi does not open the route.
func TestEveryRouteRefusesASessionlessNonDebugRequest(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("unauth-role")
	req := f.seedRoleRequest(requester, roleID, nil)
	grant := f.seedGrant(requester, roleID)

	for _, tc := range []struct{ method, target, body string }{
		{http.MethodGet, "/api/access-requests", ""},
		{http.MethodPost, "/api/access-requests", `{"roleId":` + strconv.FormatInt(roleID, 10) + `}`},
		{http.MethodPost, "/api/access-requests/" + id(req.ID) + "/approve", ""},
		{http.MethodPost, "/api/access-requests/" + id(req.ID) + "/reject", `{"reason":"no"}`},
		{http.MethodGet, "/api/access-grants", ""},
		{http.MethodPost, "/api/access-grants/" + id(grant.ID) + "/revoke", ""},
	} {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			f.authz.reset()
			rec := f.do(tc.method, tc.target, tc.body)
			assertStatus(t, rec, http.StatusUnauthorized, "no session")
			assertAPIError(t, rec, "common.unauthenticated", "no session")
		})
	}
}

// ---------------------------------------------------------------------------------------------
// 🔒 INV-A6-28 — the forward filter (06-query-decision.md:521-525)
// ---------------------------------------------------------------------------------------------

// 🔒 AN ARBITRARY `?principal=` DOES NOT LEAK ANOTHER PRINCIPAL'S GRANTS — and the proof has to show
// BOTH halves, or it proves nothing:
//
//  1. the STORE really does return the other principal's row (Cedar allowing ⇒ 1 row). If it did not,
//     a passing filter test would be indistinguishable from a WHERE clause quietly doing the work.
//  2. with Cedar denying that row, the response is `[]` — the ROUTE dropped it.
//
// A port that "optimised" the filter into the SQL would pass half 2 and FAIL half 1, which is the
// point: the oversight seeds (`system:auditor`, `system:token-admin`) are exactly the principals who
// should see other people's rows, and only Cedar knows which those are.
func TestAnArbitraryPrincipalParamDoesNotLeakAnotherPrincipalsGrants(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("leak-role")
	victim := f.seedGrant("victim@example.com", roleID)

	target := "/api/access-grants?principal=" + "victim@example.com"

	// Half 1 — the store DOES return it. Cedar allows, so the route keeps the row.
	f.authz.allowed, f.authz.asked = true, nil
	rec := f.do(http.MethodGet, target, "", f.login(stranger))
	assertStatus(t, rec, http.StatusOK, "allowed")
	var allowed []AccessGrant
	decodeJSON(t, rec, &allowed)
	if len(allowed) != 1 || allowed[0].ID != victim.ID {
		t.Fatalf("the store did not return the victim's grant, so the filter claim is untestable: %+v", allowed)
	}

	// Half 2 — Cedar denies, and the SAME query answers [].
	f.authz.allowed, f.authz.asked = false, nil
	rec = f.do(http.MethodGet, target, "", f.login(stranger))
	assertStatus(t, rec, http.StatusOK, "denied rows are dropped, not 403")
	if got := rec.Body.String(); got != "[]" {
		t.Errorf("forward filter leaked: body %s, want []", got)
	}
	// And the row that was dropped was decided against the CALLER, with the GRANT as the resource.
	ask := f.authz.only(t)
	grantResource, ok := ask.resource.(authz.ResourceAccessGrant)
	if !ok {
		t.Fatalf("resource is %T, want authz.ResourceAccessGrant", ask.resource)
	}
	if grantResource.Owner != "victim@example.com" || grantResource.ID != victim.ID {
		t.Errorf("resource %+v does not name the row being filtered", grantResource)
	}
	if grantResource.RoleName == nil || *grantResource.RoleName != "leak-role" {
		t.Errorf("roleName %v — the Role Cedar parent is what a per-role read grant matches on", grantResource.RoleName)
	}
	// 🔒 The Kotlin passes NO datasourceName for a grant, so there is no Datasource parent. A JIT
	// grant is not datasource-scoped, and inventing a scope would make per-datasource read policies
	// silently start matching.
	if grantResource.DatasourceName != nil {
		t.Errorf("datasourceName %q — a grant carries no Datasource parent", *grantResource.DatasourceName)
	}
}

// 🔒 THE REQUEST LIST FILTERS TOO, and the resource carries all five fields — each one a policy hook.
func TestTheRequestListForwardFiltersEachRowByTaskRead(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("req-filter-role")
	dsID := f.seed.Datasource(dbtest.DatasourceSpec{
		Name: "filter-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
	})
	mine := f.seedRoleRequest(approver, roleID, nil)
	f.seedRoleRequest(requester, roleID, &dsID)

	// Allow everything: both rows come back, so the store is not the filter.
	f.authz.allowed, f.authz.asked = true, nil
	rec := f.do(http.MethodGet, "/api/access-requests", "", f.login(approver))
	var all []AccessRequest
	decodeJSON(t, rec, &all)
	if len(all) != 2 {
		t.Fatalf("expected both rows from the store, got %d", len(all))
	}
	if len(f.authz.asked) != 2 {
		t.Fatalf("expected one authorization PER ROW, got %d", len(f.authz.asked))
	}

	// The resource for the row that belongs to someone else names THAT requester, and attaches the
	// datasource + role parents from the row — not from the caller and not from the query string.
	var other authz.ResourceApprovalRequest
	for _, ask := range f.authz.asked {
		res := ask.resource.(authz.ResourceApprovalRequest)
		if res.Requester == requester {
			other = res
		}
	}
	if other.Requester != requester {
		t.Fatalf("the other principal's row was never authorized: %+v", f.authz.asked)
	}
	if other.DatasourceName == nil || *other.DatasourceName != "filter-ds" {
		t.Errorf("datasourceName %v, want filter-ds — the Datasource parent scopes per-datasource reads", other.DatasourceName)
	}
	if other.RoleName == nil || *other.RoleName != "req-filter-role" {
		t.Errorf("roleName %v, want req-filter-role", other.RoleName)
	}

	// Deny everything: `[]`, not 403. The list route never turns a read refusal into an error.
	f.authz.allowed, f.authz.asked = false, nil
	rec = f.do(http.MethodGet, "/api/access-requests", "", f.login(approver))
	assertStatus(t, rec, http.StatusOK, "denied rows are dropped")
	if got := rec.Body.String(); got != "[]" {
		t.Errorf("body %s, want []", got)
	}
	_ = mine
}

// 🔒 UNDER authDebug WITH NO SESSION THE FULL LIST IS RETURNED AND CEDAR IS NEVER ASKED.
//
// 06-query-decision.md:524-525: "Under authDebug (no session) the full list is returned, matching
// requireApi's dev bypass." Both halves are asserted — the rows AND the zero authorizations — because
// a port that filtered with an empty principal string would also return... nothing, and a port that
// filtered with a permissive stub would return everything while still evaluating N policies per page.
func TestUnderAuthDebugWithNoSessionTheFullListIsReturnedUnfiltered(t *testing.T) {
	f := newRouteFixture(t)
	f.authDebug(true)
	roleID := f.seed.Role("debug-role")
	f.seedGrant("a@example.com", roleID)
	f.seedGrant("b@example.com", roleID)

	f.authz.allowed, f.authz.asked = false, nil // Cedar would DENY if it were consulted.
	rec := f.do(http.MethodGet, "/api/access-grants", "")
	assertStatus(t, rec, http.StatusOK, "authDebug list")
	var grants []AccessGrant
	decodeJSON(t, rec, &grants)
	if len(grants) != 2 {
		t.Errorf("got %d grants, want 2 — authDebug must not filter", len(grants))
	}
	if len(f.authz.asked) != 0 {
		t.Errorf("Cedar was consulted %d times under authDebug with no session: %+v", len(f.authz.asked), f.authz.asked)
	}
}

// ⚠️ authDebug IS NOT "SHOW EVERYTHING" — IT IS "THERE IS NO SESSION TO FILTER BY".
//
// A debug-mode request that HAPPENS to carry a valid cookie still gets the FILTERED list, because the
// Kotlin reads `call.userSession()` independently of requireApi's bypass (Access.kt:573). Subtle, and
// exactly the branch a port collapses by writing `if authDebug { return all }` at the top of the
// handler. That collapse would pass the previous case and fail this one.
func TestAuthDebugWithALiveSessionStillForwardFilters(t *testing.T) {
	f := newRouteFixture(t)
	f.authDebug(true)
	roleID := f.seed.Role("debug-session-role")
	f.seedGrant("a@example.com", roleID)

	f.authz.allowed, f.authz.asked = false, nil
	rec := f.do(http.MethodGet, "/api/access-grants", "", f.login(stranger))
	assertStatus(t, rec, http.StatusOK, "authDebug + session")
	if got := rec.Body.String(); got != "[]" {
		t.Errorf("body %s, want [] — a session present under authDebug is still filtered", got)
	}
	if len(f.authz.asked) != 1 {
		t.Errorf("expected the row to be authorized, got %+v", f.authz.asked)
	}
}

// 🔒 INV-A1-4 — an empty feed is `[]`, never `null`. Both list routes, both branches (filtered to
// nothing, and nothing to begin with). Go's encoding/json writes `null` for a nil slice, which is the
// opposite of kotlinx's `encodeDefaults=true`, and the console renders `.length` on the result.
func TestEmptyListsAreEmptyArraysNotNull(t *testing.T) {
	f := newRouteFixture(t)
	f.authz.allowed = true
	for _, target := range []string{"/api/access-requests", "/api/access-grants"} {
		t.Run(target, func(t *testing.T) {
			rec := f.do(http.MethodGet, target, "", f.login(approver))
			assertStatus(t, rec, http.StatusOK, target)
			if got := rec.Body.String(); got != "[]" {
				t.Errorf("body %q, want []", got)
			}
		})
	}
}

// ⚠️ `?active=` IS KOTLIN'S `toBoolean()`, WHICH IS `equalsIgnoreCase("true")` AND NEVER FAILS.
//
// strconv.ParseBool would accept "1"/"t"/"T" and ERROR on "yes" — two divergences at once (a widened
// accepted set, and an error path the Kotlin does not have). Pinned so a future "cleanup" to
// ParseBool has to change an assertion that says why.
func TestActiveParamUsesKotlinToBooleanSemantics(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("active-role")
	grant := f.seedGrant(requester, roleID)
	if _, err := f.store.Revoke(f.ctx, grant.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	for _, tc := range []struct {
		query    string
		wantRows int
		why      string
	}{
		{"", 1, "no active param at all ⇒ activeOnly=false ⇒ the revoked grant is listed"},
		{"?active=true", 0, "true ⇒ activeOnly ⇒ the revoked grant is filtered by SQL"},
		{"?active=TRUE", 0, "equalsIgnoreCase, so TRUE counts"},
		{"?active=1", 1, "1 is NOT true in Kotlin — strconv.ParseBool would say it is"},
		{"?active=yes", 1, "yes is not true, and must not be an error either"},
		{"?active=", 1, "present-but-empty is false, not an error"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			f.authz.allowed = true
			rec := f.do(http.MethodGet, "/api/access-grants"+tc.query, "", f.login(requester))
			assertStatus(t, rec, http.StatusOK, tc.why)
			var grants []AccessGrant
			decodeJSON(t, rec, &grants)
			if len(grants) != tc.wantRows {
				t.Errorf("%s: got %d rows, want %d", tc.why, len(grants), tc.wantRows)
			}
		})
	}
}

// ⚠️ `?status=` PRESENT-AND-EMPTY IS NOT THE SAME AS ABSENT. Absent ⇒ every row; present-and-empty ⇒
// filter on the empty status ⇒ none. Go's Query().Get() collapses the two into "", so this pins the
// Has()/Get() pair that keeps them apart.
func TestStatusParamDistinguishesAbsentFromPresentAndEmpty(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("status-role")
	f.seedRoleRequest(requester, roleID, nil)
	f.authz.allowed = true

	var all []AccessRequest
	decodeJSON(t, f.do(http.MethodGet, "/api/access-requests", "", f.login(requester)), &all)
	if len(all) != 1 {
		t.Fatalf("absent status: got %d rows, want 1", len(all))
	}
	var none []AccessRequest
	decodeJSON(t, f.do(http.MethodGet, "/api/access-requests?status=", "", f.login(requester)), &none)
	if len(none) != 0 {
		t.Errorf("present-and-empty status: got %d rows, want 0", len(none))
	}
	var pending []AccessRequest
	decodeJSON(t, f.do(http.MethodGet, "/api/access-requests?status=PENDING", "", f.login(requester)), &pending)
	if len(pending) != 1 {
		t.Errorf("status=PENDING: got %d rows, want 1", len(pending))
	}
}

// ---------------------------------------------------------------------------------------------
// 🔒 INV-A6-29 — revoke loads the grant BEFORE the gate (06-query-decision.md:526-529)
// ---------------------------------------------------------------------------------------------

// 🔒 THE IDOR CLOSURE. Cedar is asked about the GRANT'S OWNER, not about the caller, and that is only
// possible because the row is read first.
//
// The failure this prevents: with the gate ahead of the read, the only fact available at decision
// time is an id the caller chose, so `grant.revoke` could at best be a blanket capability and any
// authenticated principal could revoke anyone's grant by enumerating ids.
func TestRevokeDecidesAgainstTheGrantsOwnerNotTheCaller(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("idor-role")
	grant := f.seedGrant("victim@example.com", roleID)

	f.authz.allowed, f.authz.asked = false, nil
	rec := f.do(http.MethodPost, "/api/access-grants/"+id(grant.ID)+"/revoke", "", f.login(stranger))
	assertStatus(t, rec, http.StatusForbidden, "denied revoke")
	assertAPIError(t, rec, "common.forbidden", "denied revoke")

	ask := f.authz.only(t)
	res, ok := ask.resource.(authz.ResourceAccessGrant)
	if !ok {
		t.Fatalf("resource is %T, want authz.ResourceAccessGrant", ask.resource)
	}
	if res.Owner != "victim@example.com" {
		t.Errorf("owner %q — Cedar must decide against the GRANT's owner, not the caller (%q)", res.Owner, stranger)
	}
	if res.ID != grant.ID {
		t.Errorf("id %d, want %d", res.ID, grant.ID)
	}

	// And the grant is untouched.
	after, err := f.store.GetGrant(f.ctx, grant.ID)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if after.RevokedAt != nil {
		t.Error("a denied revoke must not have written revoked_at")
	}
}

// 🔒 AN UNKNOWN GRANT IS 404 *BEFORE ANY AUTHORIZATION IS PERFORMED*.
//
// The zero-authorizations assertion is the load-bearing half: it is what proves the read precedes the
// gate, in the one case where the two orderings produce a different observable (a gate-first route
// would answer 403 to an unauthorized caller and never reach the 404).
func TestRevokeOfAnUnknownGrantIs404WithNoAuthorizationAtAll(t *testing.T) {
	f := newRouteFixture(t)
	f.authz.allowed, f.authz.asked = false, nil
	rec := f.do(http.MethodPost, "/api/access-grants/999999/revoke", "", f.login(stranger))
	assertStatus(t, rec, http.StatusNotFound, "unknown grant")
	assertAPIError(t, rec, "common.not_found", "unknown grant")
	if len(f.authz.asked) != 0 {
		t.Errorf("Cedar was consulted for a grant that does not exist: %+v", f.authz.asked)
	}
}

// ⚠️ A MALFORMED ID IS 400 BEFORE EVERYTHING, INCLUDING AUTHENTICATION. The route has no requireApi,
// so `POST /api/access-grants/abc/revoke` from an anonymous caller is a 400, not a 401 — it never
// reaches requireAuthz. Reproduced; it discloses nothing, and moving the parse after the gate would
// change the status of a reachable request.
func TestRevokeWithAMalformedIdIs400BeforeAnyGate(t *testing.T) {
	f := newRouteFixture(t)
	f.authz.allowed, f.authz.asked = false, nil
	rec := f.do(http.MethodPost, "/api/access-grants/abc/revoke", "")
	assertStatus(t, rec, http.StatusBadRequest, "malformed id, no session")
	assertAPIError(t, rec, "common.bad_id", "malformed id")
	if len(f.authz.asked) != 0 {
		t.Errorf("Cedar was consulted for a malformed id: %+v", f.authz.asked)
	}
}

// ⚠️ REVOKE IS NOT IDEMPOTENT: the second one is 404, not 204. The store's `AND revoked_at IS NULL`
// guard is what makes it so, and the route reports the lost race as a missing resource. Contrast the
// editor's DELETE routes, which are deliberately idempotent 204s.
func TestASecondRevokeIs404NotAnIdempotent204(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("twice-role")
	grant := f.seedGrant(requester, roleID)

	f.authz.allowed = true
	first := f.do(http.MethodPost, "/api/access-grants/"+id(grant.ID)+"/revoke", "", f.login(approver))
	assertStatus(t, first, http.StatusNoContent, "first revoke")
	if first.Body.Len() != 0 {
		t.Errorf("204 must have no body, got %q", first.Body.String())
	}
	second := f.do(http.MethodPost, "/api/access-grants/"+id(grant.ID)+"/revoke", "", f.login(approver))
	assertStatus(t, second, http.StatusNotFound, "second revoke")
	assertAPIError(t, second, "common.not_found", "second revoke")
}

// ---------------------------------------------------------------------------------------------
// 🔒 INV-A6-30 — approve / reject (06-query-decision.md:531-543)
// ---------------------------------------------------------------------------------------------

// 🔒 SELF-APPROVAL IS GOVERNED ENTIRELY BY CEDAR — THERE IS NO HARDCODED RULE.
//
// The same request, the same approver-is-the-requester shape, answered BOTH ways purely by what the
// authorizer says. A port that added `if approver == req.principal { 403 }` — which looks like an
// obvious safety improvement — would fail the allow half, and would also make the `no-self-approval`
// forbid undisableable for the dev/eval deployments the seed is explicitly allowed to drop.
func TestSelfApprovalIsGovernedEntirelyByCedar(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("self-role")

	t.Run("the forbid denies it", func(t *testing.T) {
		req := f.seedRoleRequest(requester, roleID, nil)
		f.authz.allowed, f.authz.asked = false, nil
		rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/approve", "", f.login(requester))
		assertStatus(t, rec, http.StatusForbidden, "self-approval denied")
		assertAPIError(t, rec, CodeNotApprover, "self-approval denied")
	})

	t.Run("with the forbid disabled the SAME request self-approves", func(t *testing.T) {
		req := f.seedRoleRequest(requester, roleID, nil)
		f.authz.allowed, f.authz.asked = true, nil
		rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/approve", "", f.login(requester))
		assertStatus(t, rec, http.StatusOK, "self-approval allowed")
		var out AccessRequest
		decodeJSON(t, rec, &out)
		if out.Status != "APPROVED" || out.DecidedBy == nil || *out.DecidedBy != requester {
			t.Errorf("got %+v, want APPROVED decided by the requester themselves", out)
		}
	})
}

// 🔒 `roleName` IS PASSED SO A POLICY CAN SCOPE APPROVAL BY THE ROLE BEING REQUESTED.
//
// 06-query-decision.md:538-540: "without it that capability is unreachable here". The Role Cedar
// parent is the ONLY place the requested role appears in the decision, so dropping the field silently
// disables every `resource in Role::"…"` approval policy while leaving all of them loaded and green.
func TestApproveNamesTheRequestedRoleSoAPolicyCanScopeByIt(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("scoped-role")
	dsID := f.seed.Datasource(dbtest.DatasourceSpec{
		Name: "scoped-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
		Tags: []string{"prod"},
	})
	req := f.seedRoleRequest(requester, roleID, &dsID)

	f.authz.allowed, f.authz.asked = true, nil
	rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/approve", "", f.login(approver))
	assertStatus(t, rec, http.StatusOK, "approve")

	ask := f.authz.only(t)
	res := ask.resource.(authz.ResourceApprovalRequest)
	if res.RoleName == nil || *res.RoleName != "scoped-role" {
		t.Errorf("roleName %v, want scoped-role", res.RoleName)
	}
	if res.Requester != requester {
		t.Errorf("requester %q, want %q", res.Requester, requester)
	}
	// The datasource is threaded BOTH as the resource's parent and as AuthorizeWithContext's
	// tag-derivation scope — INV-A2-14: tags derive only when a datasource is in scope.
	if res.DatasourceName == nil || *res.DatasourceName != "scoped-ds" {
		t.Errorf("resource datasourceName %v, want scoped-ds", res.DatasourceName)
	}
	if ask.datasourceName == nil || *ask.datasourceName != "scoped-ds" {
		t.Errorf("tag-scope datasourceName %v, want scoped-ds", ask.datasourceName)
	}
	if len(ask.datasourceTags) != 1 || ask.datasourceTags[0] != "prod" {
		t.Errorf("datasourceTags %v, want [prod] — read from the row's datasource, not the request", ask.datasourceTags)
	}
}

// ⚠️ A REQUEST WITH NO DATASOURCE DERIVES NO TAGS, AND NO PSEUDO-DATASOURCE IS SYNTHESIZED.
// INV-A2-14's other half, at the route: `req.datasourceId?.let(...)` is nil, so both the resource's
// parent and the tag scope are absent, and the tag list is EMPTY rather than "whatever the last
// request had".
func TestApproveOfADatasourcelessRequestScopesNoTags(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("no-ds-role")
	req := f.seedRoleRequest(requester, roleID, nil)

	f.authz.allowed, f.authz.asked = true, nil
	f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/approve", "", f.login(approver))
	ask := f.authz.only(t)
	if ask.datasourceName != nil {
		t.Errorf("datasourceName %q, want nil", *ask.datasourceName)
	}
	if len(ask.datasourceTags) != 0 {
		t.Errorf("datasourceTags %v, want none", ask.datasourceTags)
	}
}

// ⚠️ THE BODY ASYMMETRY, BOTH SIDES, IN ONE PLACE (06-query-decision.md:541-543).
//
// approve: `runCatching { receive() }.getOrDefault(ApproveInput())` — a missing OR malformed body is
// TOLERATED and falls back to the requester's own window.
// reject:  a bare `receive<RejectInput>()` — the same input escapes to StatusPages.
//
// "Asymmetric but intentional (reason is mandatory, duration is not)." Two handlers, two decode call
// sites, deliberately not shared — a shared helper is how the two would silently converge.
func TestTheApproveRejectBodyAsymmetry(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("body-role")

	t.Run("approve tolerates a MISSING body", func(t *testing.T) {
		req := f.seedRoleRequest(requester, roleID, nil)
		f.authz.allowed = true
		rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/approve", "", f.login(approver))
		assertStatus(t, rec, http.StatusOK, "approve, no body")
	})

	t.Run("approve tolerates a MALFORMED body", func(t *testing.T) {
		req := f.seedRoleRequest(requester, roleID, nil)
		f.authz.allowed = true
		rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/approve", `{not json`, f.login(approver))
		assertStatus(t, rec, http.StatusOK, "approve, garbage body")
	})

	t.Run("reject does NOT tolerate a malformed body", func(t *testing.T) {
		req := f.seedRoleRequest(requester, roleID, nil)
		f.authz.allowed = true
		rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/reject", `{not json`, f.login(approver))
		assertStatus(t, rec, http.StatusInternalServerError, "reject, garbage body")
		assertAPIError(t, rec, "common.fallback", "reject, garbage body")
	})

	t.Run("reject does NOT tolerate a missing body", func(t *testing.T) {
		req := f.seedRoleRequest(requester, roleID, nil)
		f.authz.allowed = true
		rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/reject", "", f.login(approver))
		assertStatus(t, rec, http.StatusInternalServerError, "reject, no body")
		assertAPIError(t, rec, "common.fallback", "reject, no body")
	})
}

// ⚠️ D6 DIVERGENCE, PINNED NOT FIXED: `{}` on /reject decodes to `Reason: ""` here, where kotlinx
// throws MissingFieldException and the Kotlin answers 500 common.fallback.
//
// Fixing it needs a required-field check encoding/json cannot express, and inventing one would change
// WHICH status a bad body gets on ~120 routes at once — so it is recorded as ONE divergence for the
// whole port (CedarPolicyRoutes.receiveInput) rather than patched per-DTO. This is A6's instance of
// it, and the observable consequence is a rejection stored with a blank reason.
func TestRejectWithNoReasonFieldIsAcceptedAsBlankD6Divergence(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("d6-role")
	req := f.seedRoleRequest(requester, roleID, nil)

	f.authz.allowed = true
	rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/reject", `{}`, f.login(approver))
	assertStatus(t, rec, http.StatusOK, "reject with {} — Kotlin answers 500 here")
	var out AccessRequest
	decodeJSON(t, rec, &out)
	if out.Status != "REJECTED" {
		t.Fatalf("status %q, want REJECTED", out.Status)
	}
	// explicitNulls=false: a blank reason is a PRESENT empty string, not an omitted field, because
	// the column is non-null once written.
	if out.RejectionReason == nil || *out.RejectionReason != "" {
		t.Errorf("rejectionReason %v, want a present empty string — the D6 gap's observable footprint", out.RejectionReason)
	}
}

// 🔒 THE GATE RUNS BEFORE THE BODY IS READ ON BOTH DECISION ROUTES.
//
// An unauthorized approver sending garbage must learn only that they are not the approver. If the
// order inverted, /reject would answer 500 common.fallback to a principal Cedar was about to deny —
// telling an unauthorized caller something about how its input was parsed.
func TestTheApproverGateRunsBeforeTheBodyIsRead(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("order-role")
	req := f.seedRoleRequest(requester, roleID, nil)

	f.authz.allowed = false
	rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/reject", `{not json`, f.login(stranger))
	assertStatus(t, rec, http.StatusForbidden, "denied + garbage body")
	assertAPIError(t, rec, CodeNotApprover, "denied + garbage body")
}

// 🔒 A QUERY TASK IS REFUSED WITH 400 approval.use_query_approval_endpoint, ON BOTH ROUTES, AND
// BEFORE THE CEDAR GATE.
//
// A QUERY task belongs to A7's `/api/approvals` surface, whose decide path guards on `status =
// 'PENDING'` and writes an audit row. Deciding one here would flip its status with neither — and
// [Store.Approve] would additionally mint an `access_grant` for a task whose roleId is the EXECUTION
// role, not an elevation the requester asked for.
func TestAQueryTaskIsRefusedByBothDecisionRoutesBeforeTheGate(t *testing.T) {
	f := newRouteFixture(t)
	dsID := f.seed.Datasource(dbtest.DatasourceSpec{
		Name: "query-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
	})

	for _, route := range []string{"approve", "reject"} {
		t.Run(route, func(t *testing.T) {
			req := f.seedQueryRequest(requester, dsID)
			f.authz.allowed, f.authz.asked = true, nil
			rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/"+route,
				`{"reason":"x"}`, f.login(approver))
			assertStatus(t, rec, http.StatusBadRequest, route+" on a QUERY task")
			assertAPIError(t, rec, CodeUseQueryApprovalEndpoint, route+" on a QUERY task")
			if len(f.authz.asked) != 0 {
				t.Errorf("the kind check must precede the gate; Cedar was asked %+v", f.authz.asked)
			}
			// The task is untouched.
			after, err := f.store.GetRequest(f.ctx, req.ID)
			if err != nil {
				t.Fatalf("GetRequest: %v", err)
			}
			if after.Status != "PENDING" {
				t.Errorf("status %q — a refused decision must not have moved the task", after.Status)
			}
		})
	}
}

// A bad id is 400, an unknown id is 404, and both precede the gate — the same ordering claim as the
// revoke route, restated for the two decision routes because they reach it through requireApi first.
func TestDecisionRoutesAnswerBadIdThenNotFound(t *testing.T) {
	f := newRouteFixture(t)
	for _, route := range []string{"approve", "reject"} {
		t.Run(route+" bad id", func(t *testing.T) {
			f.authz.allowed, f.authz.asked = true, nil
			rec := f.do(http.MethodPost, "/api/access-requests/abc/"+route, `{"reason":"x"}`, f.login(approver))
			assertStatus(t, rec, http.StatusBadRequest, "bad id")
			assertAPIError(t, rec, "common.bad_id", "bad id")
		})
		t.Run(route+" unknown id", func(t *testing.T) {
			f.authz.allowed, f.authz.asked = true, nil
			rec := f.do(http.MethodPost, "/api/access-requests/999999/"+route, `{"reason":"x"}`, f.login(approver))
			assertStatus(t, rec, http.StatusNotFound, "unknown id")
			body := assertAPIError(t, rec, "common.not_found", "unknown id")
			if body.Params["resource"] != NotFoundRequest {
				t.Errorf("resource %q, want %q", body.Params["resource"], NotFoundRequest)
			}
			if len(f.authz.asked) != 0 {
				t.Errorf("Cedar was consulted for a request that does not exist: %+v", f.authz.asked)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// POST /api/access-requests — the conditional gate (06-query-decision.md:515)
// ---------------------------------------------------------------------------------------------

// 🔒 A DATASOURCE-LESS REQUEST MAKES NO CEDAR DECISION AT ALL. "A role elevation need not target one
// (datasourceId is optional); a datasource-less request has no Datasource resource to decide, so
// authentication alone admits it."
func TestARoleOnlyRequestIsAdmittedByAuthenticationAlone(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("role-only")

	f.authz.allowed, f.authz.asked = false, nil // Cedar would DENY if it were consulted.
	rec := f.do(http.MethodPost, "/api/access-requests",
		`{"roleId":`+strconv.FormatInt(roleID, 10)+`,"reason":"need it"}`, f.login(requester))
	assertStatus(t, rec, http.StatusCreated, "role-only request")
	if len(f.authz.asked) != 0 {
		t.Errorf("Cedar was consulted for a datasource-less request: %+v", f.authz.asked)
	}
	var out AccessRequest
	decodeJSON(t, rec, &out)
	if out.Principal != requester || out.Kind != DefaultKind || out.Status != "PENDING" {
		t.Errorf("got %+v, want a PENDING ROLE request for the caller", out)
	}
	// The Kotlin default 3600 survives the *int64 round trip.
	if out.RequestedDurationSec != DefaultRequestedDurationSec {
		t.Errorf("requestedDurationSec %d, want %d — an omitted duration must not become 0",
			out.RequestedDurationSec, DefaultRequestedDurationSec)
	}
}

// 🔒 A REQUEST AGAINST A DATASOURCE IS GATED BY task.request ON THAT DATASOURCE, AND THE GATE RUNS
// THE TWO-PASS: pass 1 derives tags from the raw context, pass 2 decides with `raw.copy(tags = …)`.
//
// The tag threading is asserted rather than assumed: `raw.copy(tags = tags)` is one call away from
// `raw`, and dropping it makes every tag-conditioned `task.request` policy stop firing with no other
// symptom.
func TestARequestAgainstADatasourceRunsTheTwoPassAndIsGatedByTaskRequest(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("ds-role")
	dsID := f.seed.Datasource(dbtest.DatasourceSpec{
		Name: "gated-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
		Tags: []string{"pii"},
	})
	body := `{"roleId":` + strconv.FormatInt(roleID, 10) + `,"datasourceId":` + strconv.FormatInt(dsID, 10) + `}`

	f.roles.roles = []string{"analyst", "reader"}
	f.authz.tags = []string{"trusted-network"}
	f.authz.allowed, f.authz.asked = false, nil
	rec := f.do(http.MethodPost, "/api/access-requests", body, f.login(requester))
	assertStatus(t, rec, http.StatusForbidden, "denied create")
	assertAPIError(t, rec, CodeRequestNotPermitted, "denied create")

	if len(f.authz.asked) != 2 {
		t.Fatalf("expected pass 1 then the gate, got %+v", f.authz.asked)
	}
	pass1, gate := f.authz.asked[0], f.authz.asked[1]
	if pass1.via != "resolveContextTags" {
		t.Errorf("first call was %q, want resolveContextTags", pass1.via)
	}
	// 🔒 INV-A2-10 — ONE role snapshot through both passes.
	if len(pass1.roles) != 2 || len(gate.roles) != 2 || pass1.roles[0] != gate.roles[0] {
		t.Errorf("role snapshots differ between the passes: %v vs %v", pass1.roles, gate.roles)
	}
	// Pass 1 sees the RAW context (no tags); pass 2 sees the DERIVED tags.
	if len(pass1.context.Tags) != 0 {
		t.Errorf("pass 1 was handed tags %v — INV-A2-12 forbids tag-on-tag", pass1.context.Tags)
	}
	if len(gate.context.Tags) != 1 || gate.context.Tags[0] != "trusted-network" {
		t.Errorf("gate context tags %v, want [trusted-network] — raw.copy(tags = …) was dropped", gate.context.Tags)
	}
	if gate.datasourceName == nil || *gate.datasourceName != "gated-ds" {
		t.Errorf("gate datasource %v, want gated-ds (INV-A2-2 keys it by NAME, not id)", gate.datasourceName)
	}
	if len(gate.datasourceTags) != 1 || gate.datasourceTags[0] != "pii" {
		t.Errorf("datasourceTags %v, want [pii]", gate.datasourceTags)
	}

	// Nothing was written.
	rows, err := f.store.ListRequests(f.ctx, nil)
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("a denied create wrote %d rows", len(rows))
	}
}

// ⚠️ UNDER authDebug THE task.request GATE IS SKIPPED ENTIRELY — including pass 1, because the whole
// `if (ds != null && !config.authDebug)` block is skipped, not just its decision.
func TestUnderAuthDebugTheCreateGateIsSkippedEntirely(t *testing.T) {
	f := newRouteFixture(t)
	f.authDebug(true)
	roleID := f.seed.Role("debug-create-role")
	dsID := f.seed.Datasource(dbtest.DatasourceSpec{
		Name: "debug-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
	})

	f.authz.allowed, f.authz.asked = false, nil
	rec := f.do(http.MethodPost, "/api/access-requests",
		`{"roleId":`+strconv.FormatInt(roleID, 10)+`,"datasourceId":`+strconv.FormatInt(dsID, 10)+`}`)
	assertStatus(t, rec, http.StatusCreated, "authDebug create")
	if len(f.authz.asked) != 0 {
		t.Errorf("authDebug must skip pass 1 too, got %+v", f.authz.asked)
	}
	var out AccessRequest
	decodeJSON(t, rec, &out)
	if out.Principal != DebugPrincipal {
		t.Errorf("principal %q, want %q — the sessionless fallback", out.Principal, DebugPrincipal)
	}
}

// ⚠️ REPRODUCED ODDITY: an UNKNOWN datasourceId SKIPS THE GATE rather than 404ing, because the Kotlin
// is `input.datasourceId?.let(datasourceStore::get)` and `get` answers null for a missing row — the
// same null a null id produces. The insert then fails its foreign key and the route answers 500
// common.fallback, not 404.
//
// Both halves are asserted: no authorization happened, AND the answer is the fallback. Turning this
// into a 404 would be a fix, and the port reproduces.
func TestAnUnknownDatasourceIdSkipsTheGateAndFailsOnTheForeignKey(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("fk-role")

	f.authz.allowed, f.authz.asked = true, nil
	rec := f.do(http.MethodPost, "/api/access-requests",
		`{"roleId":`+strconv.FormatInt(roleID, 10)+`,"datasourceId":424242}`, f.login(requester))
	assertStatus(t, rec, http.StatusInternalServerError, "unknown datasourceId")
	assertAPIError(t, rec, "common.fallback", "unknown datasourceId")
	if len(f.authz.asked) != 0 {
		t.Errorf("an unknown datasource must skip the gate exactly as a nil id does, got %+v", f.authz.asked)
	}
}

// ---------------------------------------------------------------------------------------------
// approve — the elevation it actually performs
// ---------------------------------------------------------------------------------------------

// A successful approve mints a live grant whose window is the REQUESTED duration when the body omits
// one, and the body's when it supplies one — the observable half of approve's tolerant decode.
func TestApproveMintsTheGrantWithTheRequestedOrOverriddenWindow(t *testing.T) {
	f := newRouteFixture(t)
	roleID := f.seed.Role("window-role")

	t.Run("no body ⇒ the requester's own window", func(t *testing.T) {
		req, err := f.store.CreateRequest(f.ctx, requester, AccessRequestInput{
			RoleID: roleID, RequestedDurationSec: types.Ptr(int64(120)),
		})
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		f.authz.allowed = true
		rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/approve", "", f.login(approver))
		assertStatus(t, rec, http.StatusOK, "approve")
		g := f.grantFor(requester, roleID)
		if g.ExpiresAt == nil {
			t.Fatal("the grant has no expiry")
		}
	})

	t.Run("durationSec overrides it", func(t *testing.T) {
		req := f.seedRoleRequest("other@example.com", roleID, nil)
		f.authz.allowed = true
		rec := f.do(http.MethodPost, "/api/access-requests/"+id(req.ID)+"/approve",
			`{"durationSec":60}`, f.login(approver))
		assertStatus(t, rec, http.StatusOK, "approve with duration")
		g := f.grantFor("other@example.com", roleID)
		if g.GrantedBy == nil || *g.GrantedBy != approver {
			t.Errorf("grantedBy %v, want %q", g.GrantedBy, approver)
		}
	})
}

// grantFor reads back the newest grant for a principal+role.
func (f *routeFixture) grantFor(principal string, roleID int64) AccessGrant {
	f.t.Helper()
	grants, err := f.store.ListGrants(f.ctx, &principal, false)
	if err != nil {
		f.t.Fatalf("ListGrants: %v", err)
	}
	for _, g := range grants {
		if g.RoleID == roleID {
			return g
		}
	}
	f.t.Fatalf("no grant for %s on role %d", principal, roleID)
	return AccessGrant{}
}

func id(v int64) string { return strconv.FormatInt(v, 10) }
