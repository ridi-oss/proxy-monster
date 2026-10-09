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

func TestWriteJSONMatchesKotlinBytes(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON(w, http.StatusOK, map[string]string{"cedarSrc": `when { a < 1 && b > 2 }`})
	if got := w.Body.String(); got != `{"cedarSrc":"when { a < 1 && b > 2 }"}` {
		t.Fatalf("body %q", got)
	}
}

func TestErrorParamsKeepOrderWithoutEscaping(t *testing.T) {
	w := httptest.NewRecorder()
	WriteErrorParams(w, http.StatusBadRequest, "common.already_exists", Params{{"resource", "role"}, {"name", "R&D <x>"}})
	if got := w.Body.String(); got != `{"code":"common.already_exists","params":{"resource":"role","name":"R&D <x>"}}` {
		t.Fatalf("body %q", got)
	}
}
