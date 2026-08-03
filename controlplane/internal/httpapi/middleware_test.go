package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// StatusPages — App.kt:454-462, and AuthAndIngestRoutesDbTest.kt:91-111's catch-all case.

// SENTINEL is AuthAndIngestRoutesDbTest.kt:219's constant: "A distinctive marker only ever present in
// a thrown exception's message — asserted ABSENT from the 500 body, so a catch-all that leaked
// cause.message would be caught."
const sentinel = "sentinel-secret-9f83c2-do-not-leak"

// boom is the `get("/__boom") { throw RuntimeException(SENTINEL) }` test route: a handler registered
// so the SAME application-level handler catches its throw, which is the only way to exercise the
// catch-all end to end.
func boom(http.ResponseWriter, *http.Request) { panic(sentinel) }

// quietLogger discards output but keeps it inspectable, so a case can assert the cause WAS logged
// even though it was not served.
func quietLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func serveThroughStatusPages(t *testing.T, path string, h http.HandlerFunc) (*httptest.ResponseRecorder, *bytes.Buffer) {
	t.Helper()
	log, buf := quietLogger()
	rec := httptest.NewRecorder()
	StatusPages(log)(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec, buf
}

// AuthAndIngestRoutesDbTest — "an unhandled exception is caught by the StatusPages fallback without
// leaking the cause".
func TestStatusPagesAnswersCommonFallbackWithoutLeakingTheCause(t *testing.T) {
	rec, logged := serveThroughStatusPages(t, "/__boom", boom)

	assertStatus(t, rec, http.StatusInternalServerError, "unhandled panic")

	if strings.Contains(rec.Body.String(), sentinel) {
		t.Errorf("the catch-all serialized the cause — an internal exception must never reach the "+
			"client: %s", rec.Body.String())
	}

	var body types.ApiError
	decodeBody(t, rec, &body)
	if body.Code != "common.fallback" {
		t.Errorf("code: got %q, want \"common.fallback\"", body.Code)
	}
	if len(body.Params) != 0 {
		t.Errorf("params: got %v, want an empty map", body.Params)
	}

	// The cause is LOGGED, though — swallowing it entirely would make a production 500 undiagnosable.
	if !strings.Contains(logged.String(), sentinel) {
		t.Errorf("the cause must be logged even though it is not served; log was: %s", logged.String())
	}
	if !strings.Contains(logged.String(), "Unhandled exception") {
		t.Errorf("the log message must be App.kt's \"Unhandled exception\"; log was: %s", logged.String())
	}
}

// 🔒 The OAuth branch: an OAuth/MCP client parses `{"error": …}` and has no schema for `{"code": …}`.
func TestStatusPagesAnswersOAuthServerErrorOnTheOAuthSurface(t *testing.T) {
	oauthPaths := []string{
		"/oauth/token",
		"/oauth/authorize",
		"/oauth/resume",
		"/oauth/register",
		OAuthMetadataPath,
	}
	for _, path := range oauthPaths {
		t.Run(path, func(t *testing.T) {
			rec, _ := serveThroughStatusPages(t, path, boom)
			assertStatus(t, rec, http.StatusInternalServerError, path)

			var body types.OAuthError
			decodeBody(t, rec, &body)
			if body.Error != "server_error" {
				t.Errorf("error: got %q, want \"server_error\"", body.Error)
			}
			// explicitNulls=false — the key must be ABSENT, not null.
			if strings.Contains(rec.Body.String(), "error_description") {
				t.Errorf("error_description must be omitted entirely, got: %s", rec.Body.String())
			}
		})
	}
}

// The two path tests are DIFFERENT SHAPES and the difference is observable: `/oauth/` is a PREFIX
// (note the trailing slash) and the metadata path is an EXACT match.
func TestStatusPagesOAuthPathTestIsPrefixForOauthAndExactForTheMetadataPath(t *testing.T) {
	apiErrorPaths := []string{
		// No trailing slash, so it is not under the `/oauth/` prefix.
		"/oauth",
		// The metadata path is compared with `==`, so a longer path is NOT the OAuth surface.
		OAuthMetadataPath + "/extra",
		"/.well-known/oauth-protected-resource",
		"/api/tokens",
	}
	for _, path := range apiErrorPaths {
		t.Run(path, func(t *testing.T) {
			if IsOAuthSurface(path) {
				t.Fatalf("%q must not be treated as the OAuth surface", path)
			}
			rec, _ := serveThroughStatusPages(t, path, boom)
			var body types.ApiError
			decodeBody(t, rec, &body)
			if body.Code != "common.fallback" {
				t.Errorf("code: got %q, want \"common.fallback\"", body.Code)
			}
		})
	}
}

// ⚠️ F41 / A3 F30 — THE PIN. 99-reconciliation-report.md:245: "StatusPages' catch-all answers
// ApiError(\"common.fallback\") for ANY uncaught exception, including on /api/scim/v2/** — breaking
// the documented SCIM error-body exemption (INV-A1-13 / INV-A3-2) exactly where an IdP is least able
// to parse it."
//
// It is a DEFECT. The PORT POLICY says REPRODUCE, and because it sits on the identity-provisioning
// path it is REPRODUCE + PIN: this test asserts the WRONG-BUT-REAL body, so a later fix has to change
// it deliberately and visibly instead of silently passing.
func TestStatusPagesAnswersApiErrorOnScimPaths(t *testing.T) {
	scimPaths := []string{
		"/api/scim/v2/Users",
		"/api/scim/v2/Groups/17",
		"/api/scim/v2/ServiceProviderConfig",
	}
	for _, path := range scimPaths {
		t.Run(path, func(t *testing.T) {
			rec, _ := serveThroughStatusPages(t, path, boom)
			assertStatus(t, rec, http.StatusInternalServerError, path)

			// The DEFECT, asserted: an ApiError envelope, not a ScimError.
			var body types.ApiError
			decodeBody(t, rec, &body)
			if body.Code != "common.fallback" {
				t.Errorf("code: got %q, want \"common.fallback\" — F41 says the catch-all does NOT "+
					"exempt SCIM, and this test pins the defect", body.Code)
			}

			// And, positively, the SCIM shape the IdP expects is absent. If this ever starts holding a
			// ScimError, F41 has been FIXED — which is fine, but it must be a deliberate change to this
			// test, not a silent one.
			if strings.Contains(rec.Body.String(), ScimErrorSchema) {
				t.Errorf("the body is now SCIM-shaped: F41 appears fixed. That is a behaviour change — "+
					"update this pin and 00-INDEX.md's finding table together. Body: %s", rec.Body.String())
			}
		})
	}
}

// A handler that already started the response cannot have its status rewritten. Ktor has the same
// limitation; the port must not pretend otherwise by writing a second status line, which net/http
// would log as a superfluous WriteHeader and the client would never see.
func TestStatusPagesDoesNotRewriteAnAlreadyStartedResponse(t *testing.T) {
	log, logged := quietLogger()
	rec := httptest.NewRecorder()

	handler := StatusPages(log)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"partial":`))
		panic(sentinel)
	}))

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Error("the panic must be re-raised so net/http closes the connection rather than " +
				"leaving the client waiting on a body that never finishes")
		}
		if !strings.Contains(logged.String(), "response already started") {
			t.Errorf("the situation must be logged; log was: %s", logged.String())
		}
	}()

	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/partial", nil))
}

// A handler that returns normally is untouched — StatusPages only fires on the unhandled path.
func TestStatusPagesPassesANormalResponseThrough(t *testing.T) {
	log, _ := quietLogger()
	rec := httptest.NewRecorder()

	StatusPages(log)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = RespondJSON(w, http.StatusTeapot, map[string]string{"ok": "yes"})
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fine", nil))

	assertStatus(t, rec, http.StatusTeapot, "normal response")
	if rec.Body.String() != `{"ok":"yes"}` {
		t.Errorf("body: got %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------------------------
// CallLogging — App.kt:453
// ---------------------------------------------------------------------------------------------

// 🔒 The ORDER of the two wrappers is what this case is about: CallLogging must observe the 500 that
// StatusPages produced, not the status a panicking handler never wrote. Swapping them logs `200`
// for every crashed request, which is exactly the log line an operator would trust.
func TestCallLoggingLogsTheStatusStatusPagesProduced(t *testing.T) {
	log, logged := quietLogger()
	rec := httptest.NewRecorder()

	Chain(http.HandlerFunc(boom), CallLogging(log), StatusPages(log)).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/__boom", nil))

	assertStatus(t, rec, http.StatusInternalServerError, "panic through the full stack")
	if !strings.Contains(logged.String(), "status=500") {
		t.Errorf("CallLogging must report the status that went out (500); log was: %s", logged.String())
	}
	if !strings.Contains(logged.String(), "path=/__boom") || !strings.Contains(logged.String(), "method=GET") {
		t.Errorf("the log line must carry the method and path; log was: %s", logged.String())
	}
}

func TestCallLoggingReportsAnImplicit200(t *testing.T) {
	log, logged := quietLogger()
	rec := httptest.NewRecorder()

	CallLogging(log)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/implicit", nil))

	if !strings.Contains(logged.String(), "status=200") {
		t.Errorf("a handler that only writes a body still produced 200; log was: %s", logged.String())
	}
}

// Chain's first argument is OUTERMOST, so an App.kt install list transcribes top to bottom without
// being inverted. A reversed Chain would silently put StatusPages outside CallLogging.
func TestChainAppliesTheFirstMiddlewareOutermost(t *testing.T) {
	var order []string
	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { order = append(order, "handler") }),
		mark("outer"), mark("inner")).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"outer", "inner", "handler"}
	if len(order) != len(want) {
		t.Fatalf("order: got %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order: got %v, want %v", order, want)
		}
	}
}
