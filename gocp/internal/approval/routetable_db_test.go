package approval

import (
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------------------------
// The route table itself — 18 patterns across three groups.
//
// ⚠️ A ROUTE THAT IS NOT REGISTERED FAILS NOTHING. Nothing in Go's test tooling notices an absent
// pattern, so the inventory has to be asserted on purpose. This suite is that assertion, and it also
// pins the two properties the mux gives us for free and could silently lose: no pattern conflicts
// (ServeMux PANICS at registration, so a passing fixture construction already proves it) and
// method-awareness.
// ---------------------------------------------------------------------------------------------

// registeredRoutes is the complete surface this package owns, as METHOD /path.
var registeredRoutes = []string{
	"POST /api/approvals",
	"POST /api/approvals/discover-roles",
	"GET /api/approvals",
	"GET /api/approvals/inbox",
	"GET /api/approvals/{id}",
	"POST /api/approvals/{id}/approve",
	"POST /api/approvals/{id}/reject",
	"POST /api/approvals/{id}/cancel",
	"POST /api/approvals/{id}/execute",
	"GET /api/approvals/{id}/result",
	"POST /api/editor/sessions",
	"POST /api/editor/sessions/{sessionId}/query",
	"DELETE /api/editor/sessions/{sessionId}",
	"GET /api/editor/tasks/{taskId}",
	"POST /api/editor/tasks/{taskId}/cancel",
	"GET /api/editor/tasks/{taskId}/result",
	"DELETE /api/editor/tasks/{taskId}",
	"GET /api/tasks/events",
}

// Every route is MOUNTED — i.e. it does not 404 with Go's own "404 page not found" body, which is
// what an unregistered pattern answers. A registered route's own 404 is an ApiError, so the two are
// distinguishable.
func TestEveryRouteInTheAreaIsRegistered(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{AuthDebug: true})

	for _, route := range registeredRoutes {
		method, pattern, _ := strings.Cut(route, " ")
		if method == http.MethodGet && pattern == "/api/tasks/events" {
			continue // an SSE stream would block this probe; taskevents_db_test.go opens it properly.
		}
		t.Run(route, func(t *testing.T) {
			// A concrete id/session that resolves to nothing: the handler answers its own error, an
			// unregistered pattern answers net/http's.
			path := strings.NewReplacer("{id}", "999999", "{taskId}", "999999", "{sessionId}", "nope").Replace(pattern)
			rec := f.do(method, path, map[string]any{}, nil)

			if rec.Code == http.StatusNotFound && strings.Contains(rec.Body.String(), "404 page not found") {
				t.Fatalf("%s is NOT REGISTERED (net/http answered its own 404)", route)
			}
			if rec.Code == http.StatusMethodNotAllowed {
				t.Fatalf("%s is registered under a different method (405, Allow: %q)",
					route, rec.Header().Get("Allow"))
			}
		})
	}
}

// 🔒 METHOD-AWARENESS: a GET-only route answers 405 to a POST rather than running the handler. Free
// from ServeMux, and worth pinning because losing it would make every read route writable-looking.
func TestAWrongMethodIs405NotAHandlerRun(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{AuthDebug: true})

	rec := f.do(http.MethodDelete, "/api/approvals/inbox", nil, nil)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /api/approvals/inbox: got %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Errorf("Allow: got %q, want it to name GET", allow)
	}
}

// The removed release/withhold routes stay removed — `ApprovalExecuteRouteDbTest` case 7 is a
// NEGATIVE route test, and the only way to keep one in Go is to assert the 404 deliberately.
// KT: ApprovalExecuteRouteDbTest.kt#removed release and withhold routes return 404
func TestTheRemovedReleaseAndWithholdRoutesStayRemoved(t *testing.T) {
	f := newHTTPFixture(t, fixtureOptions{AuthDebug: true})

	for _, path := range []string{"/api/approvals/1/release", "/api/approvals/1/withhold"} {
		rec := f.do(http.MethodPost, path, map[string]any{}, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404 — the route was removed and must stay removed", path, rec.Code)
		}
	}
}
