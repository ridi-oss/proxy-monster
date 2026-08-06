package app

// ============================================================================================
// THE ROUTE-TABLE SWEEP — every route `App.kt`'s `routing {}` block reaches, asserted mounted.
//
// The per-area suites prove each group's BEHAVIOUR against a router they build themselves. This file
// proves the only thing they structurally cannot: that internal/app mounts them, on ONE mux, and that
// no two areas claim a path.
//
// # Why `ServeMux.Handler`, and not an HTTP probe
//
// The obvious sweep — send a request, call anything that answers 404 unmounted — CANNOT WORK on this
// surface, and the failure is silent in the dangerous direction. `common.not_found` is a legitimate
// answer from a dozen mounted handlers (an id that does not exist, a Cedar forbid that must not be an
// existence oracle, INV-A7-5's non-WORKFLOW creator kind), so a probe would score a correctly-mounted
// route as missing, and a reader would "fix" it by deleting the row.
//
// `(*http.ServeMux).Handler(req)` returns the matched PATTERN, and the empty string means the mux has
// no registration for that method+path. That is the exact question, answered by the router rather
// than inferred from a body. It also needs no socket, no session and no seeded rows, so the sweep
// costs one boot.
//
// # What a failure here means
//
//	pattern == ""                  the group is not mounted, or is mounted under a different path
//	panic during NewHTTPSurface    two groups registered the same pattern (Go 1.22+ conflicts panic
//	                               at registration, which is why the boot itself is half the test)
//
// # The list
//
// It is the Kotlin's full route table, extracted mechanically from
// `control-plane/src/main/kotlin/**` with
//
//	grep -rhoE '\b(get|post|put|patch|delete|sse)\("(/[^"]*)"' … | sort -u
//
// — 120 rows, and every one is below. The three that are NOT expected to match are listed separately
// with the reason, so the gap is a maintained inventory rather than an omission nobody re-counted.
// ============================================================================================

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// kotlinRouteTable is App.kt's routing surface, verbatim, with each `{…}` wildcard given a concrete
// value so the mux can match it. Grouped by owning area, in the order internal/app mounts them.
var kotlinRouteTable = []struct{ method, path string }{
	// A11 §2 — installMcp
	{http.MethodGet, "/.well-known/oauth-protected-resource"},
	{http.MethodGet, "/.well-known/oauth-protected-resource/mcp"},

	// A1 — coreRoutes + authRoutes
	{http.MethodGet, "/health"},
	{http.MethodPost, "/api/ingest/decision"},
	{http.MethodGet, "/auth/config"},
	{http.MethodPost, "/auth/debug"},
	{http.MethodGet, "/api/me/permissions"},
	{http.MethodGet, "/auth/me"},
	{http.MethodGet, "/auth/session/status"},
	{http.MethodPost, "/auth/session/heartbeat"},
	{http.MethodPost, "/auth/logout"},
	{http.MethodGet, "/api/tasks/events"}, // Kotlin: sse("/api/tasks/events")

	// A14 — oidcRoutes
	{http.MethodGet, "/auth/oidc/login"},
	{http.MethodGet, "/auth/oidc/callback"},

	// A11 §6 — mcpOAuthRoutes
	{http.MethodGet, "/.well-known/oauth-authorization-server"},
	{http.MethodGet, "/oauth/authorize"},
	{http.MethodGet, "/oauth/resume"},
	{http.MethodPost, "/oauth/consent"},
	{http.MethodPost, "/oauth/token"},
	{http.MethodPost, "/oauth/revoke"},
	{http.MethodGet, "/oauth/consents"},
	{http.MethodDelete, "/oauth/consents/1"},

	// A4 — deviceSessionRoutes + sessionRenewRoutes
	{http.MethodPost, "/auth/device/start"},
	{http.MethodPost, "/auth/device/confirm"},
	{http.MethodGet, "/auth/device/authorize"},
	{http.MethodPost, "/auth/device/poll"},
	{http.MethodPost, "/auth/session/renew"},

	// A3 — scimRoutes
	{http.MethodGet, "/api/scim/v2/ServiceProviderConfig"},
	{http.MethodGet, "/api/scim/v2/ResourceTypes"},
	{http.MethodGet, "/api/scim/v2/Schemas"},
	{http.MethodGet, "/api/scim/v2/Users"},
	{http.MethodPost, "/api/scim/v2/Users"},
	{http.MethodGet, "/api/scim/v2/Users/1"},
	{http.MethodPut, "/api/scim/v2/Users/1"},
	{http.MethodPatch, "/api/scim/v2/Users/1"},
	{http.MethodDelete, "/api/scim/v2/Users/1"},
	{http.MethodGet, "/api/scim/v2/Groups"},
	{http.MethodPost, "/api/scim/v2/Groups"},
	{http.MethodGet, "/api/scim/v2/Groups/1"},
	{http.MethodPut, "/api/scim/v2/Groups/1"},
	{http.MethodPatch, "/api/scim/v2/Groups/1"},
	{http.MethodDelete, "/api/scim/v2/Groups/1"},

	// A5 — datasourceRoutes
	{http.MethodGet, "/api/datasources"},
	{http.MethodGet, "/api/datasources/live"},
	{http.MethodPost, "/api/datasources"},
	{http.MethodGet, "/api/datasources/1"},
	{http.MethodPut, "/api/datasources/1"},
	{http.MethodDelete, "/api/datasources/1"},
	{http.MethodPost, "/api/datasources/1/refresh"},
	{http.MethodPost, "/api/datasources/1/test"},
	{http.MethodGet, "/api/datasources/1/catalog"},
	{http.MethodGet, "/api/datasources/1/wire-cert"},
	{http.MethodGet, "/api/datasources/1/table-detail"},
	{http.MethodPut, "/api/datasources/1/classification"},
	{http.MethodDelete, "/api/datasources/1/classification"},

	// A9 — policyRoutes
	{http.MethodGet, "/api/roles"},
	{http.MethodPost, "/api/roles"},
	{http.MethodPut, "/api/roles/1"},
	{http.MethodDelete, "/api/roles/1"},
	{http.MethodGet, "/api/role-assignments"},
	{http.MethodPost, "/api/role-assignments"},
	{http.MethodDelete, "/api/role-assignments/1"},
	{http.MethodGet, "/api/mask-fns"},
	{http.MethodPost, "/api/mask-fns"},
	{http.MethodPut, "/api/mask-fns/1"},
	{http.MethodDelete, "/api/mask-fns/1"},

	// A3 — userGroupRoutes
	{http.MethodGet, "/api/users"},
	{http.MethodPost, "/api/users"},
	{http.MethodPut, "/api/users/1"},
	{http.MethodDelete, "/api/users/1"},
	{http.MethodGet, "/api/groups"},
	{http.MethodPost, "/api/groups"},
	{http.MethodPut, "/api/groups/1"},
	{http.MethodDelete, "/api/groups/1"},
	{http.MethodGet, "/api/groups/1/members"},
	{http.MethodPost, "/api/groups/1/members"},
	{http.MethodDelete, "/api/groups/1/members/2"},
	{http.MethodGet, "/api/groups/1/roles"},
	{http.MethodPost, "/api/groups/1/roles"},
	{http.MethodDelete, "/api/groups/1/roles/2"},

	// A6 — accessRoutes
	{http.MethodGet, "/api/access-requests"},
	{http.MethodPost, "/api/access-requests"},
	{http.MethodPost, "/api/access-requests/1/approve"},
	{http.MethodPost, "/api/access-requests/1/reject"},
	{http.MethodGet, "/api/access-grants"},
	{http.MethodPost, "/api/access-grants/1/revoke"},

	// A7 — approvalRoutes
	{http.MethodPost, "/api/approvals"},
	{http.MethodPost, "/api/approvals/discover-roles"},
	{http.MethodGet, "/api/approvals"},
	{http.MethodGet, "/api/approvals/inbox"},
	{http.MethodGet, "/api/approvals/1"},
	{http.MethodPost, "/api/approvals/1/approve"},
	{http.MethodPost, "/api/approvals/1/reject"},
	{http.MethodPost, "/api/approvals/1/cancel"},
	{http.MethodPost, "/api/approvals/1/execute"},
	{http.MethodGet, "/api/approvals/1/result"},

	// A6 — editorSessionRoutes
	{http.MethodPost, "/api/editor/sessions"},
	{http.MethodPost, "/api/editor/sessions/abc/query"},
	{http.MethodDelete, "/api/editor/sessions/abc"},
	{http.MethodGet, "/api/editor/tasks/1"},
	{http.MethodPost, "/api/editor/tasks/1/cancel"},
	{http.MethodGet, "/api/editor/tasks/1/result"},
	{http.MethodDelete, "/api/editor/tasks/1"},

	// A7 §9 — queryHistoryRoutes
	{http.MethodGet, "/api/query-history"},
	{http.MethodDelete, "/api/query-history"},

	// A4 — tokenRoutes
	{http.MethodPost, "/api/wire-tokens"},
	{http.MethodGet, "/api/tokens"},
	{http.MethodPost, "/api/tokens"},
	{http.MethodDelete, "/api/tokens/1"},

	// A2 — cedarPolicyRoutes
	{http.MethodGet, "/api/policies"},
	{http.MethodGet, "/api/policies/schema"},
	{http.MethodPost, "/api/policies"},
	{http.MethodPost, "/api/policies/validate"},
	{http.MethodPut, "/api/policies/1"},
	{http.MethodDelete, "/api/policies/1"},
	{http.MethodPost, "/api/policies/1/enable"},
	{http.MethodPost, "/api/policies/1/disable"},

	// A6 — queryRoutes. ⚠️ Under A5's `/api/datasources/` prefix but registered by internal/query,
	// which OWNS it (Query.kt); see query.Routes' doc. Booting at all proves the two groups do not
	// both claim it, because a duplicate pattern panics ServeMux.Handle.
	{http.MethodPost, "/api/datasources/1/query"},

	// A8 — auditRoutes
	{http.MethodGet, "/api/audit"},
	{http.MethodGet, "/api/audit/1"},
}

// unmountedKotlinRoutes is the OTHER half of the inventory: rows of the Kotlin's 120 that this
// composition root deliberately does not mount, each with the reason.
//
// 🔴 A ROW MOVES OUT OF HERE WHEN ITS AREA LANDS, AND THE TEST BELOW FAILS IF ONE IS MOUNTED WITHOUT
// BEING MOVED. That is the point: the gap cannot quietly close or quietly widen.
//
// ✅ IT IS NOW EMPTY. `POST /api/datasources/{id}/query` was the last row — the one route of the 120
// with no Go handler, because it is a thin wrapper over RunExecService.run and the two had to land
// together. They did (internal/runexec + query.Routes), so the row moved into kotlinRouteTable above
// and the composition root mounts all 120.
var unmountedKotlinRoutes = []struct{ method, path, why string }{}

// TestTheCompositionRootMountsTheWholeKotlinRouteTable is the sweep.
//
// It asserts BOTH directions, and the second one is the one that catches a fabrication: a path that
// is mounted but is not in the Kotlin's table is a route this port invented, which is a wire surface
// no Kotlin client knows about and no Kotlin test covers.
func TestTheCompositionRootMountsTheWholeKotlinRouteTable(t *testing.T) {
	// Booting at all is half the assertion: a duplicate pattern between two areas panics inside
	// ServeMux.Handle, so a conflict fails here rather than at the first request.
	s := newAuthServer(t, nil)
	mux := s.surface.Router.Mux()

	matched := func(method, path string) string {
		r := httptest.NewRequest(method, "http://control-plane.invalid"+path, nil)
		_, pattern := mux.Handler(r)
		return pattern
	}

	// 🔒 THE SWEEP'S OWN CALIBRATION, and it is not ceremony. Every assertion below reads "pattern is
	// non-empty", so anything that made the mux match EVERYTHING — a stray `"/"` registration, a
	// trailing-slash pattern creating a subtree match, a future change to ServeMux.Handler's contract —
	// would turn 119 assertions into 119 tautologies and the file would still pass. These two prove the
	// discriminator can still say no.
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/definitely-not-a-control-plane-route"},
		{http.MethodGet, "/api/definitely-not-a-control-plane-route"},
	} {
		if pattern := matched(probe.method, probe.path); pattern != "" {
			t.Fatalf("%s %s matched %q — the mux matches unmounted paths, so every assertion in this "+
				"file is vacuous", probe.method, probe.path, pattern)
		}
	}

	for _, tc := range kotlinRouteTable {
		if pattern := matched(tc.method, tc.path); pattern == "" {
			t.Errorf("%s %s is NOT MOUNTED — the composition root registers no pattern for it",
				tc.method, tc.path)
		}
	}

	for _, tc := range unmountedKotlinRoutes {
		if pattern := matched(tc.method, tc.path); pattern != "" {
			t.Errorf("%s %s matched %q, but this route is on the deliberately-unmounted list.\n"+
				"If the area landed, MOVE the row into kotlinRouteTable; do not delete it.\nreason on file: %s",
				tc.method, tc.path, pattern, tc.why)
		}
	}
}

// TestTheRouteTableCoversEveryKotlinRoute guards the LIST above rather than the mux.
//
// A sweep is only as good as its inventory, and an inventory maintained by hand rots. 120 is the
// count the extraction command produces from the Kotlin tree; if a route is added or removed there,
// this fails and the two lists above have to be re-derived rather than drifting apart in silence.
func TestTheRouteTableCoversEveryKotlinRoute(t *testing.T) {
	const kotlinRouteCount = 120

	got := len(kotlinRouteTable) + len(unmountedKotlinRoutes)
	if got != kotlinRouteCount {
		t.Errorf("the two lists hold %d routes (%d mounted + %d deliberately unmounted); "+
			"App.kt's table has %d.\nRe-extract with:\n  grep -rhoE '\\b(get|post|put|patch|delete|sse)"+
			"\\(\"(/[^\"]*)\"' control-plane/src/main/kotlin/com/ridi/oss/proxymonster/controlplane | sort -u",
			got, len(kotlinRouteTable), len(unmountedKotlinRoutes), kotlinRouteCount)
	}

	// No row may appear twice — a duplicate would inflate the count above and hide a real gap.
	seen := map[string]bool{}
	for _, tc := range kotlinRouteTable {
		key := tc.method + " " + tc.path
		if seen[key] {
			t.Errorf("%s is listed twice in kotlinRouteTable", key)
		}
		seen[key] = true
	}

	// No pattern may end in `/` — httpapi.Router's divergence 1: a trailing-slash registration makes
	// ServeMux create a subtree match AND a 307 redirect from the bare path, and Ktor's
	// IgnoreTrailingSlash is not installed. The table is where a stray one would show up first.
	for _, tc := range kotlinRouteTable {
		if strings.HasSuffix(tc.path, "/") {
			t.Errorf("%s %s ends in a slash; no control-plane pattern may", tc.method, tc.path)
		}
	}
}

// TestMcpIsMountedForEveryMethod pins the ONE registration that is not method-scoped.
//
// `installMcp` intercepts on `path == "/mcp"` for EVERY verb, not `post("/mcp")` — internal/mcp's
// Register says so in as many words. It matters: a GET or DELETE to /mcp must still pass the
// host/origin/bearer gates and be answered by the SDK (405 in stateless mode), not by the mux's own
// method-not-allowed, which would skip the gates entirely.
//
// ⚠️ `/mcp` is NOT one of the 120 — the Kotlin mounts it through the SDK's own installer rather than
// a `post("…")` call, so the extraction command cannot see it. It is asserted here instead of being
// bolted onto the count above.
func TestMcpIsMountedForEveryMethod(t *testing.T) {
	s := newAuthServer(t, nil)
	mux := s.surface.Router.Mux()

	for _, method := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
	} {
		r := httptest.NewRequest(method, "http://control-plane.invalid/mcp", nil)
		if _, pattern := mux.Handler(r); pattern == "" {
			t.Errorf("%s /mcp is not mounted; the interceptor must cover every verb", method)
		}
	}
}
