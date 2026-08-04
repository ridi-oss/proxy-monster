package app

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ============================================================================================
// Port of the three AuthAndIngestRoutesDbTest.kt cases that are not already covered elsewhere:
// `POST /api/ingest/decision`'s two halves and `GET /api/datasources`' wire-token Bearer path.
//
// 🔴 WHY THESE HAVE TO BE HERE. The Kotlin suite's own KDoc says it: "these three routes
// (`/auth/me`, `/auth/debug`, `/api/ingest/decision`) live inline in `Application.module()`, not in a
// dedicated `Route.xRoutes()` extension, so they can only be exercised by booting the full module."
// The Go form is the same — [coreRoutes] declares ingest inline in [NewHTTPSurface] — so the fixture
// is [newAuthServer], which IS `application { module(config, ControlPlaneCore(dataSource)) }` over a
// fresh migrated database.
//
// The other three cases of the suite are covered where their mechanism lives, and carry their markers
// there:
//
//	`auth me without a session is unauthenticated`          → authroutes_test.go
//	                                                          TestTheThreeSessionRoutesChallengeWithReasonNone
//	`auth debug is a 404 endpoint when PM_AUTH_DEBUG is off` → authroutes_test.go
//	                                                          TestDebugLoginIs404WhenTheBypassIsOff
//	`an unhandled exception is caught by the StatusPages
//	 fallback without leaking the cause`                    → internal/httpapi middleware_test.go
//	                                                          TestStatusPagesAnswersCommonFallbackWithoutLeakingTheCause
// ============================================================================================

const ingestSecret = "test-ingest-token"

// ingest POSTS a decision record with the given X-PM-Ingest-Token header ("" = header absent).
func (s *authServer) ingest(headerValue, body string) *http.Response {
	s.t.Helper()
	r, err := http.NewRequest(http.MethodPost, s.server.URL+"/api/ingest/decision", strings.NewReader(body))
	if err != nil {
		s.t.Fatalf("build request: %v", err)
	}
	r.Header.Set("Content-Type", "application/json")
	if headerValue != "" {
		r.Header.Set(IngestTokenHeader, headerValue)
	}
	return s.send(s.bare(), r)
}

// bearerGet GETs path with an Authorization header ("" = header absent).
func (s *authServer) bearerGet(header, path string) *http.Response {
	s.t.Helper()
	r, err := http.NewRequest(http.MethodGet, s.server.URL+path, nil)
	if err != nil {
		s.t.Fatalf("build request: %v", err)
	}
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return s.send(s.bare(), r)
}

// ---------------------------------------------------------------------------------------------
// `ingest with a wrong token is an invalid ingest token`
// ---------------------------------------------------------------------------------------------

// 🔒 THE CODE AND THE PARAM ARE BOTH THE ASSERTION. The Kotlin checks `common.invalid_token` AND
// `params["kind"] == "ingest"`, because the proxy's ingest credential is PM_SECRET_TOKEN — a different
// secret from anything a browser or a daemon presents — and "which credential did you get wrong" is
// the one useful fact in this 401. A bare `common.unauthenticated` reads to an operator as "log in".
//
// 🔴 THIS CASE FOUND A REAL PORT DIVERGENCE. Before this test, http.go answered
// `ApiError("common.unauthenticated")` with no params where App.kt:673 calls
// `call.invalidToken("ingest")` → `common.invalid_token {kind: ingest}`. The PORT POLICY is reproduce,
// so the handler was corrected rather than the assertion relaxed. `boot_e2e_db_test.go`'s
// TestIngestRouteIsGatedByTheSameSecret asserted only the STATUS, which is why the wrong code
// survived: 401 was right and the body was never read.
//
// The header comparison is also asserted to be a comparison and not a presence check — an empty
// header value must be refused too, which `subtle.ConstantTimeCompare` gives for free and a
// `!= ""` guard would not.
// KT: AuthAndIngestRoutesDbTest.kt#ingest with a wrong token is an invalid ingest token
func TestIngestWithAWrongTokenIsAnInvalidIngestToken(t *testing.T) {
	s := newAuthServer(t, map[string]string{"PM_SECRET_TOKEN": ingestSecret})
	const body = `{"principal":"alice","datasource":"ds","statement":"select 1","decision":"ALLOW"}`

	for _, tc := range []struct {
		name   string
		header string
	}{
		{"a wrong token", "wrong"},
		{"no header at all", ""},
		{"an empty header value", " "},
		{"a prefix of the real secret", ingestSecret[:len(ingestSecret)-1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := s.ingest(tc.header, body)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body %s)", resp.StatusCode, readBody(t, resp))
			}
			var err types.ApiError
			decodeBody(t, resp, &err)
			if err.Code != "common.invalid_token" {
				t.Errorf("code = %q, want common.invalid_token (App.kt:673 is call.invalidToken(\"ingest\"))", err.Code)
			}
			if err.Params["kind"] != "ingest" {
				t.Errorf("params = %v, want kind=ingest — the param names WHICH credential was wrong", err.Params)
			}
		})
	}

	// The control: nothing above passes because the route answers 401 unconditionally.
	if resp := s.ingest(ingestSecret, body); resp.StatusCode != http.StatusAccepted {
		t.Errorf("control: the correct token → %d, want 202", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------------------------
// `ingest with the correct token and a minimal record is accepted`
// ---------------------------------------------------------------------------------------------

// 🔒 202 IS NOT THE ASSERTION — THE ROW IS. The Kotlin posts a MINIMAL record (four fields, no `kind`,
// no lists, no `ts`) and then reads the stored row back for four things: `kind` defaulted to
// "decision", a 32-byte `prev_hash`, a 32-byte `row_hash`, and a `ts` inside a window taken around the
// call. Each one is a different way for an accepted ingest to have stored nothing usable:
//
//   - `kind` — kotlinx applies the data class default for an absent field; Go would leave "". An audit
//     row with an empty kind is invisible to every reader that filters by kind.
//   - the two 32-byte hashes — the row is IN THE CHAIN. A store that accepted the event and left the
//     hashes NULL or short would make the whole trail unverifiable while every ingest returned 202.
//   - `ts` filled from the server clock (INV-A8-3) — absent means "now", not zero. A zero timestamp
//     sorts before every genuine row and would silently head the feed.
//
// KT: AuthAndIngestRoutesDbTest.kt#ingest with the correct token and a minimal record is accepted
func TestIngestWithTheCorrectTokenAndAMinimalRecordIsAccepted(t *testing.T) {
	s := newAuthServer(t, map[string]string{"PM_SECRET_TOKEN": ingestSecret})

	before := time.Now()
	resp := s.ingest(ingestSecret,
		`{"principal":"alice","datasource":"ds","statement":"select 1","decision":"ALLOW"}`)
	after := time.Now()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body %s)", resp.StatusCode, readBody(t, resp))
	}
	var accepted IngestResponse
	decodeBody(t, resp, &accepted)
	if accepted.Status != "accepted" {
		t.Errorf("body status = %q, want accepted", accepted.Status)
	}

	var (
		ts       time.Time
		kind     string
		prevHash []byte
		rowHash  []byte
	)
	if err := s.db.Pool.QueryRow(context.Background(),
		`SELECT ts, kind, prev_hash, row_hash FROM audit_event WHERE principal = 'alice'`,
	).Scan(&ts, &kind, &prevHash, &rowHash); err != nil {
		t.Fatalf("read the stored audit row: %v", err)
	}
	if kind != "decision" {
		t.Errorf("kind = %q, want the defaulted \"decision\" — an absent field takes the data class "+
			"default, it does not become the empty string", kind)
	}
	if len(prevHash) != 32 {
		t.Errorf("prev_hash is %d bytes, want 32 — the row must be linked into the hash chain", len(prevHash))
	}
	if len(rowHash) != 32 {
		t.Errorf("row_hash is %d bytes, want 32", len(rowHash))
	}
	// A two-second slack each way: `ts` is stamped by the SERVER (the Kotlin brackets the call with
	// Instant.now()), and the process clock and the database clock are not the same clock.
	if ts.Before(before.Add(-2*time.Second)) || ts.After(after.Add(2*time.Second)) {
		t.Errorf("ts = %s, outside the window [%s, %s] — an absent ts means \"now\", not zero",
			ts, before, after)
	}
}

// ---------------------------------------------------------------------------------------------
// `datasource discovery accepts a wire-token Bearer and rejects missing or bad auth`
// ---------------------------------------------------------------------------------------------

// 🔒 THE pmon DISCOVERY PATH, THROUGH THE REAL TOKEN STORE. The `pmon` CLI is authenticated after
// `pmon login`, but the device-auth flow hands the BROWSER the web-session cookie, not the CLI — so
// the CLI presents its own wire token as an `Authorization: Bearer` to reach read-only datasource
// discovery.
//
// 🔴 WHY THIS IS NOT ALREADY COVERED. internal/datasource's bearer_db_test.go asserts every one of
// these rules against a FAKE TokenResolver (a map from plaintext to identity). That is the right shape
// for the gate's own logic and it is thorough. What it structurally cannot see is the WIRING: whether
// the composition root hands the bearer path a resolver backed by the real token store, hashed the
// production way. A `wireTokens` adapter that resolved nothing at all would leave every one of those
// tests green and every `pmon login` broken — the refusals would still refuse, for the wrong reason,
// and the one case that must SUCCEED is the one a fake cannot vouch for.
//
// PM_AUTH_DEBUG is OFF here, as in the Kotlin: with the bypass on, no-auth would be 200 and three of
// the four refusals would be untestable.
// KT: AuthAndIngestRoutesDbTest.kt#datasource discovery accepts a wire-token Bearer and rejects missing or bad auth
func TestDatasourceDiscoveryAcceptsAWireTokenBearerAndRejectsMissingOrBadAuth(t *testing.T) {
	// ⚠️ FOUR OTHER SETTINGS HAVE TO MOVE WITH THE BYPASS, and none of them is incidental. Turning
	// PM_AUTH_DEBUG off makes the DEFAULT config INVALID, by four validation rules at once: V6 wants a
	// non-default PM_SESSION_SECRET of ≥32 characters, V7 wants PM_OIDC_* configured, V8 wants an HTTPS
	// issuer, V9 pins the redirect URI to the co-hosted callback, and V10 wants an HTTPS
	// PM_MCP_RESOURCE (the default is plain-HTTP localhost).
	//
	// The Kotlin has NO such coupling — its `config(authDebug = false)` builds the data class directly
	// and never runs `Config.fromEnv`'s validation — so this block is a Go port fact stated rather than
	// worked around: the bypass cannot be switched off in isolation, because the validator reads "no
	// bypass" as "this looks like production" and demands the rest of a production posture with it. The
	// issuer is never dialled: nothing on the discovery path runs in this test.
	s := newAuthServer(t, map[string]string{
		"PM_AUTH_DEBUG":         "false",
		"PM_MCP_RESOURCE":       "https://control-plane.test/mcp",
		"PM_SESSION_SECRET":     "auth-ingest-route-test-secret-32-bytes-long",
		"PM_OIDC_ISSUER":        "https://idp.control-plane.test",
		"PM_OIDC_CLIENT_ID":     "control-plane",
		"PM_OIDC_CLIENT_SECRET": "idp-client-secret",
		"PM_OIDC_REDIRECT_URI":  "https://control-plane.test/auth/oidc/callback",
	})
	ctx := context.Background()

	if _, err := s.core.DatasourceStore.Create(ctx, datasource.DatasourceInput{
		Name: "ds-bearer", Engine: "mysql", Host: "h", Port: 3306, DBName: "app",
	}); err != nil {
		t.Fatalf("create datasource: %v", err)
	}
	issue := func(kind token.Kind, principal string) string {
		t.Helper()
		out, err := s.core.TokenStore.Issue(ctx, s.db.Pool, kind, principal, nil, nil, 3600)
		if err != nil {
			t.Fatalf("Issue(%s): %v", kind, err)
		}
		return out.Token
	}

	// A valid USER wire token authenticates discovery and lists the datasource.
	t.Run("a valid wire-token Bearer lists the datasource", func(t *testing.T) {
		resp := s.bearerGet("Bearer "+issue(token.KindUser, "alice@example.com"), "/api/datasources")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, readBody(t, resp))
		}
		if body := readBody(t, resp); !strings.Contains(body, "ds-bearer") {
			t.Errorf("the discovery response does not name the datasource: %s", body)
		}
	})

	// With the bypass off, no auth and a garbage Bearer are both unauthorized.
	t.Run("no auth at all is 401", func(t *testing.T) {
		if resp := s.bearerGet("", "/api/datasources"); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})
	t.Run("a garbage Bearer is 401", func(t *testing.T) {
		resp := s.bearerGet("Bearer pmk_not-a-real-token", "/api/datasources")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	// 🔒 A non-native-wire kind must NOT authenticate discovery: only SESSION/USER are the pmon-client
	// kinds, and EDITOR / APPROVER_EXEC are wire-only ephemerals. An EDITOR token that could enumerate
	// datasources would turn a single query's credential into an inventory read.
	t.Run("an EDITOR-kind token is 401", func(t *testing.T) {
		resp := s.bearerGet("Bearer "+issue(token.KindEditor, "editor@example.com"), "/api/datasources")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 — EDITOR is not a native-wire kind", resp.StatusCode)
		}
	})

	// 🔒 A deactivated principal's STILL-VALID token fails closed, matching the gRPC decide path. The
	// token row is untouched; the refusal comes from the app_user lookup, so a port that resolved the
	// token and stopped there would pass every case above.
	t.Run("a deactivated principal's live token is 401", func(t *testing.T) {
		if _, err := s.db.Pool.Exec(ctx,
			`INSERT INTO app_user (principal, active) VALUES ('deact@example.com', false)`); err != nil {
			t.Fatalf("seed the deactivated user: %v", err)
		}
		tok := issue(token.KindUser, "deact@example.com")
		// The token itself is live — that is the premise.
		if id, err := s.core.TokenStore.Validate(ctx, tok); err != nil || id == nil {
			t.Fatalf("premise: the token must still validate (%v, %v)", id, err)
		}
		if resp := s.bearerGet("Bearer "+tok, "/api/datasources"); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 — a deactivated principal must not enumerate datasources",
				resp.StatusCode)
		}
	})
}
