package conformance

import (
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ============================================================================================
// The HTTP-plumbing DTOs — 01-bootstrap.md §2 (StatusPages, the Authentication challenge),
// 03-identity-scim.md §"Scim.kt" (the SCIM error envelope).
//
// Same rule as wire_json_test.go and wire_json_a4_test.go: EXACT bytes through types.MarshalWire,
// never a semantic compare.
//
// These three are the port's ERROR bodies, and error bodies are the worst possible place for a
// silent shape change: they are emitted on the path where nothing else is working, they are read by
// three different consumers with three different parsers (the console's i18n lookup, an OAuth/MCP
// client's `{"error":…}` schema, an IdP's SCIM 2.0 schema), and none of those consumers is exercised
// by a Go test. A golden-bytes layer is the only thing standing between a renamed field and an IdP
// silently logging "unparseable response" during a provisioning outage.
// ============================================================================================

// OAuthError — the StatusPages OAuth branch (App.kt:456), and A11's routes once they land.
//
// 🔒 THE FIELD NAME IS `error_description`, SNAKE_CASE, because RFC 6749 says so and kotlinx emits
// the Kotlin property name verbatim (there is no @SerialName on it). Every other DTO in the port is
// camelCase and this one deliberately is not — which is exactly the kind of "inconsistency" a
// well-meaning cleanup removes and no unit test notices.
func TestOAuthErrorGoldenBytes(t *testing.T) {
	// The catch-all's body: `OAuthError("server_error")` with NO description. explicitNulls=false
	// means the key is ABSENT, never `null` — an MCP client's Zod schema models it as `.optional()`.
	t.Run("the StatusPages catch-all body", func(t *testing.T) {
		assertWireBytes(t, types.OAuthServerError().Body, "oauth_error_server_error.json")
	})

	t.Run("with a description", func(t *testing.T) {
		assertWireBytes(t, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: types.Ptr("resource parameter does not match the configured MCP resource"),
		}, "oauth_error_with_description.json")
	})

	// An `error_description` routinely quotes a client-supplied `redirect_uri` or `resource`, so it
	// is a real HTML-escaping surface: encoding/json would rewrite `<`, `>` and `&`, kotlinx does
	// not, and an OAuth client comparing the description against a fixture would see two different
	// strings.
	t.Run("html metacharacters in the description", func(t *testing.T) {
		assertWireBytes(t, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: types.Ptr(`redirect_uri <script> & query must match exactly`),
		}, "oauth_error_metacharacters.json")
	})
}

// ScimError — 🔒 INV-A1-13's ONE exemption. Every other error body on the wire is an ApiError, a
// dot-namespaced i18n key with no English prose; SCIM is exempt because its consumer is an IdP with
// no locale to look anything up in.
//
// The three `detail` strings are what an operator reads out of Okta's or Entra's provisioning log
// when they are debugging a 501, so they are part of the contract in a way English prose normally is
// not in this codebase.
func TestScimErrorGoldenBytes(t *testing.T) {
	// The three bodies requireScimAuth emits, in gate order (Scim.kt:153-162). Their ORDER is itself
	// the security property INV-A3-37 pins: TLS before bearer, so a correct token sent in the clear
	// is rejected before any comparison touches it.
	t.Run("501 — SCIM is not configured", func(t *testing.T) {
		assertWireBytes(t, httpapi.NewScimError("501", "SCIM provisioning is not configured"),
			"scim_error_not_configured.json")
	})
	t.Run("403 — SCIM requires TLS", func(t *testing.T) {
		assertWireBytes(t, httpapi.NewScimError("403", "SCIM requires TLS"),
			"scim_error_requires_tls.json")
	})
	t.Run("401 — invalid bearer token", func(t *testing.T) {
		assertWireBytes(t, httpapi.NewScimError("401", "invalid bearer token"),
			"scim_error_invalid_bearer.json")
	})

	// `scimType` is nullable with a null default, so it is ABSENT above and PRESENT here — the shape
	// A3's route errors use. Declaration order is (schemas, status, scimType, detail), matching
	// Scim.kt:77; kotlinx and encoding/json both emit in declaration order, so the order IS contract.
	t.Run("with a scimType", func(t *testing.T) {
		assertWireBytes(t, httpapi.ScimError{
			Schemas:  []string{httpapi.ScimErrorSchema},
			Status:   "409",
			ScimType: types.Ptr("uniqueness"),
			Detail:   types.Ptr("userName already exists"),
		}, "scim_error_with_scim_type.json")
	})

	// 🔒 `status` is a STRING, not a number, per RFC 7644 §3.12. An IdP parsing `"status": 501` as a
	// number-typed field where it expects a string is a schema violation, and the failure surfaces as
	// an opaque provisioning error rather than as anything pointing here.
	t.Run("status is a JSON string", func(t *testing.T) {
		raw, err := types.MarshalWire(httpapi.NewScimError("501", "x"))
		if err != nil {
			t.Fatalf("MarshalWire: %v", err)
		}
		if !strings.Contains(string(raw), `"status":"501"`) {
			t.Errorf("bytes = %s, want status as a quoted string", raw)
		}
	})

	// The Kotlin default is `listOf(SCIM_ERROR_SCHEMA)`, not `emptyList()`, so a zero-value
	// construction must yield the ONE-ELEMENT default rather than `[]`. `"schemas": []` tells an IdP
	// nothing about what it is holding, and every construction site writes `ScimError{Status: …}`.
	t.Run("a nil schemas slice defaults to the URN, not to []", func(t *testing.T) {
		assertWireBytes(t, httpapi.ScimError{
			Status: "409",
			// Schemas deliberately omitted.
			ScimType: types.Ptr("uniqueness"),
			Detail:   types.Ptr("userName already exists"),
		}, "scim_error_with_scim_type.json")
	})
}

// SessionStatusError — the Authentication plugin's challenge body (App.kt:224, written by
// respondSessionUnauthorized at App.kt:242-253).
//
// 🔒 INV-A4-3 — `reason` is a CLOSED FOUR-VALUE VOCABULARY collapsed from the six stored ENDED_*
// reasons. One golden file PER VALUE, deliberately: the vocabulary being closed is the contract, so
// a fifth value appearing has to show up as a new file in a diff rather than as a passing test.
//
// DEACTIVATED is the one that must NOT be reachable — an unauthenticated caller is never told that a
// specific account was deprovisioned. TestChallengeCollapsesTheSixEndedReasonsToFour in
// internal/httpapi pins the mapping; this pins the bytes each mapped value produces.
func TestSessionStatusErrorGoldenBytes(t *testing.T) {
	for _, tc := range []struct {
		reason string
		golden string
	}{
		{session.WireReasonNone, "session_status_error_none.json"},
		{session.WireReasonDisplaced, "session_status_error_displaced.json"},
		{session.WireReasonBindMismatch, "session_status_error_bind_mismatch.json"},
		{session.WireReasonExpired, "session_status_error_expired.json"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			assertWireBytes(t, httpapi.SessionStatusError{Reason: tc.reason}, tc.golden)
		})
	}

	// The six stored reasons must never reach the wire verbatim. Asserted as bytes because the
	// mapping test and this one fail for different causes: the mapping test catches a wrong branch,
	// this catches a DTO that started carrying the stored reason in a second field.
	t.Run("no stored ENDED_ reason reaches the wire", func(t *testing.T) {
		for _, stored := range []string{
			session.EndedSignedOut, session.EndedDisplaced, session.EndedDeactivated,
			session.EndedGroupRevoked, session.EndedIdpRejected, session.EndedDeviceBindMismatch,
		} {
			for _, wire := range []string{
				session.WireReasonNone, session.WireReasonDisplaced,
				session.WireReasonBindMismatch, session.WireReasonExpired,
			} {
				raw, err := types.MarshalWire(httpapi.SessionStatusError{Reason: wire})
				if err != nil {
					t.Fatalf("MarshalWire: %v", err)
				}
				if strings.Contains(string(raw), stored) {
					t.Errorf("the challenge body for %q carries the stored reason %q: %s",
						wire, stored, raw)
				}
			}
		}
	})
}
