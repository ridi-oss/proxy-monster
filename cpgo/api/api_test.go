package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestKotlinSessionCheckAsksKotlinWithTheCallersCookies(t *testing.T) {
	var gotPath, gotCookie string
	kotlin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotCookie = r.URL.Path, r.Header.Get("Cookie")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer kotlin.Close()
	u, _ := url.Parse(kotlin.URL)

	r := httptest.NewRequest(http.MethodGet, "/api/query-history", nil)
	r.Header.Set("Cookie", "pm_session=k%2Fsig; pm_did=dev-2")
	KotlinSessionCheck(u)(r)
	if gotPath != "/auth/session/status" || gotCookie != "pm_session=k%2Fsig; pm_did=dev-2" {
		t.Fatalf("Kotlin saw %q with cookies %q", gotPath, gotCookie)
	}
}
