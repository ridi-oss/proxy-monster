package front

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplit(t *testing.T) {
	to := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, name) })
	}
	h := Split(to("control-plane"), to("web"))
	for path, want := range map[string]string{
		"/api/datasources": "control-plane",
		"/auth/oidc/login": "control-plane",
		"/oauth/authorize": "control-plane",
		"/mcp":             "control-plane",
		"/mcp/tools":       "control-plane",
		"/.well-known/oauth-authorization-server": "control-plane",
		"/health":                   "control-plane",
		"/auth/reauth-complete":     "web",
		"/":                         "web",
		"/editor":                   "web",
		"/_next/static/app.js":      "web",
		"/api":                      "web",
		"/.well-known/security.txt": "web",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Body.String(); got != want {
			t.Errorf("%s went to %s, want %s", path, got, want)
		}
	}
}
