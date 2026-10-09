package routes_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestUnauthenticated(t *testing.T) {
	e := routetest.Setup(t)
	for _, path := range []string{"/api/query-history", "/api/audit", "/api/audit/1", "/api/roles", "/api/role-assignments", "/api/mask-fns", "/api/policies", "/api/me/permissions", "/api/access-requests", "/api/access-grants", "/api/approvals", "/api/datasources"} {
		status, body := e.Do(t, http.MethodGet, path, "", nil)
		if status != http.StatusUnauthorized || body != `{"code":"common.unauthenticated","params":{}}` {
			t.Fatalf("%s: %d %s", path, status, body)
		}
	}
}

func TestDeviceMismatchIsEndedByKotlin(t *testing.T) {
	e := routetest.Setup(t)
	c := e.St.WebSession(t, "alice@example.com", "k1", "dev-1")
	status, body := e.Do(t, http.MethodGet, "/api/query-history", "", []*http.Cookie{c[0], {Name: "pm_did", Value: "dev-2"}})
	if status != http.StatusUnauthorized || body != `{"code":"common.unauthenticated","params":{}}` {
		t.Fatalf("status %d %s", status, body)
	}
	if len(e.Ended) != 1 || !strings.Contains(e.Ended[0], "pm_did=dev-2") || len(e.Forwarded) != 0 {
		t.Fatalf("ended %v forwarded %v", e.Ended, e.Forwarded)
	}
}

func TestUnportedRequestsAreForwarded(t *testing.T) {
	e := routetest.Setup(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/query-history"},
		{http.MethodGet, "/api/me/locale"},
		{http.MethodGet, "/api//query-history"},
		{http.MethodGet, "/api/query-history/"},
		{http.MethodHead, "/api/query-history"},
		{http.MethodGet, "/api/datasources/live"},
		{http.MethodGet, "/api/datasources/1/catalog"},
		{http.MethodGet, "/api/datasources/1/table-detail"},
		{http.MethodPost, "/api/datasources/1/refresh"},
		{http.MethodGet, "/api/approvals/inbox"},
		{http.MethodGet, "/api/approvals/1"},
		{http.MethodPost, "/api/approvals/1/approve"},
		{http.MethodGet, "/api/policies/schema"},
	} {
		if status, _ := e.Do(t, tc.method, tc.path, "", nil); status != http.StatusTeapot {
			t.Fatalf("%s %s: status %d, want forwarded", tc.method, tc.path, status)
		}
	}
}
