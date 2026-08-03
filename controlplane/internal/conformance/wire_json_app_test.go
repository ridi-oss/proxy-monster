package conformance

import (
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/app"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ============================================================================================
// A1's APP-LOCAL DTOs — 01-bootstrap.md §3 "App-local DTOs", declared in `App.kt:186-224`.
//
//	MePermissions       App.kt:186   GET  /api/me/permissions
//	SessionStatus       App.kt:193   GET  /auth/session/status, POST /auth/session/heartbeat
//	LogoutRequest       App.kt:205   POST /auth/logout  (REQUEST)
//	LogoutResponse      App.kt:208   POST /auth/logout
//	AuthConfigResponse  App.kt:211   GET  /auth/config
//	SessionUxConfig     App.kt:218   nested in AuthConfigResponse
//	HealthResponse      App.kt:558   GET  /health
//	IngestResponse      App.kt:672   POST /api/ingest/decision
//
// Same rule as every other file in this package: EXACT bytes through types.MarshalWire, never a
// semantic compare, one golden file per shape.
//
// 🔴 WHY THESE NEED GOLDEN BYTES AT ALL, given that the route suites already decode them. Because
// decoding is exactly the check that cannot see the failure. `json.Unmarshal` into a Go struct is
// blind to a renamed key it does not know, to a `[]` that became `null`, to an absent optional that
// became an explicit `null`, and to key ORDER — and the consumer here is the Next.js console, which
// is not exercised by any Go test at all. INV-A1-4's two rules (always emit `[]`, always OMIT an
// absent optional) are wire rules, so only a wire assertion can hold them.
//
// ⚠️ KEY ORDER IS CONTRACT-ADJACENT, and it is asserted implicitly by the byte comparison. kotlinx
// emits in DECLARATION order and so does encoding/json, so the two agree as long as the Go struct
// keeps the Kotlin's field order. Nothing else in the port enforces that; reordering a struct field
// is an ordinary-looking edit that these files turn into a failure.
// ============================================================================================

// MePermissions — the console's three coarse navigation hints.
//
// 🔒 THE KEY SET IS THE CONTRACT. MePermissionsRouteTest.kt:117 asserts
// `setOf("isAdmin","canReadAllAudit","canApprove") == payload.keys` rather than only the values,
// because the console branches on these three and a fourth capability appearing on the wire is a
// change of meaning, not an addition. The golden files carry that here: a new field cannot land
// without editing a fixture.
//
// All three are non-nullable Booleans with no default, so there is nothing for encodeDefaults or
// explicitNulls to change — every key is always present, including the false ones. An `omitempty` on
// any of them would drop `false` and leave the console reading `undefined`, which its guards treat
// as… whatever `!undefined` happens to be at that call site.
func TestMePermissionsGoldenBytes(t *testing.T) {
	// The authDebug answer, and the shape MePermissionsRouteTest case 2 asserts key-for-key.
	t.Run("all three granted", func(t *testing.T) {
		assertWireBytes(t, app.MePermissions{IsAdmin: true, CanReadAllAudit: true, CanApprove: true},
			"me_permissions_all.json")
	})

	// The ZERO VALUE — case 7's "ordinary principal has no coarse capabilities". This is the one a
	// naive `omitempty` sweep turns into `{}`.
	t.Run("none granted — every false key still present", func(t *testing.T) {
		assertWireBytes(t, app.MePermissions{}, "me_permissions_none.json")
	})

	// Case 3's shape: one admin domain permits, so isAdmin and canApprove are true while
	// canReadAllAudit stays false — the three-decision independence, on the wire.
	t.Run("admin without the audit collection", func(t *testing.T) {
		assertWireBytes(t, app.MePermissions{IsAdmin: true, CanApprove: true},
			"me_permissions_admin_only.json")
	})

	// A guard on the key set itself, independent of the fixtures, so the reason is legible at the
	// point of failure rather than only as a byte diff.
	t.Run("exactly three keys", func(t *testing.T) {
		raw, err := types.MarshalWire(app.MePermissions{})
		if err != nil {
			t.Fatalf("MarshalWire: %v", err)
		}
		if got := strings.Count(string(raw), `":`); got != 3 {
			t.Errorf("bytes = %s, want exactly three keys (isAdmin, canReadAllAudit, canApprove)", raw)
		}
	})
}

// SessionStatus — the console's countdown source, from `/auth/session/status` and the heartbeat.
//
// 🔒 THE THREE TIMESTAMPS ARE `java.time.Instant.toString()`, NOT RFC3339Nano. instant.Format owns
// that difference and internal/conformance/instant_test.go pins it across every fraction-width
// boundary; what this file adds is that the DTO actually carries the formatted string rather than a
// time.Time some other encoder would render its own way.
//
// ⚠️ `sessionId` is a JSON NUMBER, not a string. It is a Kotlin `Long`, and the console compares it
// against the id it sends back in `LogoutRequest` — INV-A1-9's conditional logout is that comparison.
// A port that rendered it as a string would make every conditional logout fall through to the
// unconditional arm, silently, because `"42" != 42` is simply false rather than an error.
func TestSessionStatusGoldenBytes(t *testing.T) {
	assertWireBytes(t, app.SessionStatus{
		// Whole-second and sub-second forms, so the fixture also carries instant.Format's
		// variable-precision fraction rather than only its easy case.
		Now:               "2026-08-02T14:03:07.123456Z",
		IdleExpiresAt:     "2026-08-02T14:18:07.123456Z",
		AbsoluteExpiresAt: "2026-08-02T16:03:07Z",
		Principal:         "status@example.com",
		SessionID:         42,
	}, "session_status.json")
}

// LogoutRequest — the ONE request DTO in this file, and the only A1 shape with an optional field.
//
// 🔒 `sessionId: Long? = null` with explicitNulls=false means the key is ABSENT when unset, never
// `null`. Both shapes decode identically on the server (INV-A1-9 reads a nullable), so this is
// pinned for the OTHER direction: the console builds this body, and a Go-side change from
// `omitempty` to an explicit null would be invisible to every Go test while changing what the
// contract says an unconditional logout looks like.
func TestLogoutRequestGoldenBytes(t *testing.T) {
	t.Run("unconditional — sessionId ABSENT, not null", func(t *testing.T) {
		assertWireBytes(t, app.LogoutRequest{}, "logout_request_unconditional.json")
	})
	t.Run("conditional — the id the client observed", func(t *testing.T) {
		assertWireBytes(t, app.LogoutRequest{SessionID: types.Ptr(int64(42))}, "logout_request_conditional.json")
	})
}

// LogoutResponse — 🔒 INV-A1-9's two answers, and the console distinguishes them.
//
// `{ended:false}` means "I did nothing, the session you named is not the one you hold"; the console
// keeps the tab signed in. `{ended:true}` sends it to the login page. One boolean, two very
// different UX outcomes, so both bytes are frozen.
func TestLogoutResponseGoldenBytes(t *testing.T) {
	t.Run("ended", func(t *testing.T) {
		assertWireBytes(t, app.LogoutResponse{Ended: true}, "logout_response_ended.json")
	})
	t.Run("not ended — the conditional arm", func(t *testing.T) {
		assertWireBytes(t, app.LogoutResponse{}, "logout_response_not_ended.json")
	})
}

// AuthConfigResponse + SessionUxConfig — `GET /auth/config`, the PUBLIC body the login shell reads
// before it can authenticate anything.
//
// ⚠️ The three `*Ms` fields are `seconds * 1000`; the absolute cap deliberately is NOT, because
// [app.normalizeDuration] splits it into an amount and a unit so the console renders "2 hours"
// rather than "7200000 ms". That asymmetry looks like an oversight and is not — freezing both shapes
// is what stops a later "consistency" pass turning absoluteCap into milliseconds and breaking the
// one string a user actually reads.
//
// The nested `session` object is a non-nullable value, so it is always present.
func TestAuthConfigResponseGoldenBytes(t *testing.T) {
	// The shipped defaults, exactly as WebSessionRoutesDbTest.kt:104-120 asserts them.
	t.Run("the shipped defaults", func(t *testing.T) {
		assertWireBytes(t, app.AuthConfigResponse{
			OidcEnabled: false,
			AuthDebug:   true,
			Session: app.SessionUxConfig{
				HeartbeatMs:        90_000,
				IdleWarnLeadMs:     60_000,
				AbsoluteWarnLeadMs: 300_000,
				AbsoluteCapAmount:  2,
				AbsoluteCapUnit:    "hours",
			},
		}, "auth_config_defaults.json")
	})

	// The production posture (SSO on, bypass off) with the mixed-unit cap of
	// WebSessionRoutesDbTest.kt:123-136: `1h30m` is 90 MINUTES, never 1.5 hours.
	t.Run("oidc on, bypass off, a minutes cap", func(t *testing.T) {
		assertWireBytes(t, app.AuthConfigResponse{
			OidcEnabled: true,
			AuthDebug:   false,
			Session: app.SessionUxConfig{
				HeartbeatMs:        90_000,
				IdleWarnLeadMs:     60_000,
				AbsoluteWarnLeadMs: 300_000,
				AbsoluteCapAmount:  90,
				AbsoluteCapUnit:    "minutes",
			},
		}, "auth_config_oidc_minutes.json")
	})
}

// HealthResponse — `GET /health`, read by a readiness probe and by ReadinessDiagnosticDbTest.
//
// 🔒 INV-A1-4 — `diagnostics` is a non-null Kotlin List, so encodeDefaults=true makes it ALWAYS
// PRESENT, as `[]` at minimum. A probe or a dashboard doing `body.diagnostics.length` gets a
// TypeError on `null` and a clean 0 on `[]`.
func TestHealthResponseGoldenBytes(t *testing.T) {
	t.Run("healthy with nothing to report", func(t *testing.T) {
		assertWireBytes(t, app.HealthResponse{Status: "ok", Diagnostics: []string{}}, "health_ok_empty.json")
	})

	// The clean-install shape: the diagnostic is REPORTED and the status stays "ok", because a
	// readiness probe that failed on a fresh install would prevent the very first login that fixes it.
	t.Run("a clean install reports its diagnostic and stays ok", func(t *testing.T) {
		assertWireBytes(t, app.HealthResponse{
			Status:      "ok",
			Diagnostics: []string{"system:admin role has no active assignee"},
		}, "health_ok_diagnostic.json")
	})
}

// 🔴 TestHealthResponseEmptyDiagnosticsNormalisationLivesInTheHandler is a RECORDED FRAGILITY, not a
// blessing of the shape it asserts.
//
// [types.ApiError] and [httpapi.ScimError] both normalise their defaulted collection inside
// MarshalJSON, so no construction site can get the wire shape wrong. [app.HealthResponse] does NOT:
// its `[]string{}` initialisation lives in the HANDLER (http.go's healthHandler), one call site
// away, and a nil slice marshals as `null`. Today there is exactly one construction site and it is
// correct, so nothing is broken and nothing is "improved" here — but a second site (a cached health
// snapshot, a gRPC-side readiness echo, a test double) would produce `"diagnostics":null` and no
// existing test would notice.
//
// The assertion is deliberately on the CURRENT behaviour so the day someone adds the MarshalJSON
// this test fails and has to be read.
//
//	TODO(A1): give HealthResponse a MarshalJSON that normalises nil → [], the way ApiError does, and
//	flip this case. It is a hardening, not a behaviour change: the only emitter today already sends
//	[], so no consumer sees a different byte.
func TestHealthResponseEmptyDiagnosticsNormalisationLivesInTheHandler(t *testing.T) {
	raw, err := types.MarshalWire(app.HealthResponse{Status: "ok"})
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	if string(raw) != `{"status":"ok","diagnostics":null}` {
		t.Errorf("bytes = %s — HealthResponse gained a nil-slice normalisation. That is the TODO on "+
			"this test; update it (and the doc comment) rather than reverting the type.", raw)
	}
}

// IngestResponse — `POST /api/ingest/decision`'s 202 body.
//
// ⚠️ In the Kotlin this is not a data class at all: `call.respond(Accepted, mapOf("status" to
// "accepted"))` (App.kt:678). A one-key map and a one-field struct serialise identically, so the
// port's struct is a faithful encoding of an unfaithful-looking construct — which is precisely why
// it wants a byte fixture: the equivalence is an argument, and this file turns it into a check.
func TestIngestResponseGoldenBytes(t *testing.T) {
	assertWireBytes(t, app.IngestResponse{Status: "accepted"}, "ingest_accepted.json")
}
