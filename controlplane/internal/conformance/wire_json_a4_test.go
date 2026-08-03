package conformance

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/token"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ============================================================================================
// A4's wire DTOs — 04-auth-session-tokens.md §1.3 (`Tokens.kt`) and §1.4 (`Auth.kt` / `Oidc.kt`).
//
// Same rule as wire_json_test.go: EXACT bytes through types.MarshalWire, never a semantic compare.
// The four properties this layer defends that a unit test cannot see are field ORDER (kotlinx emits
// in declaration order and so does encoding/json, so the order IS the contract), `[]` vs `null` for
// an empty list, an ABSENT key vs an explicit `null` for a nullable, and the HTML escaping of
// `<`/`>`/`&` that encoding/json performs and kotlinx does not.
//
// The cookie payloads are here rather than only in internal/session because their bytes are what the
// cookie MAC covers: a payload whose encoding drifts is a cookie that stops verifying, and the
// failure looks like "everyone is logged out" rather than like a serialization bug.
// ============================================================================================

// WireTokenInfo — `GET /api/tokens`'s element and the row `DELETE /api/tokens/{id}` authorizes
// against. Eight fields; three of them nullable.
func TestWireTokenInfoGoldenBytes(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		assertWireBytes(t, token.Info{
			ID:         42,
			Kind:       "USER",
			Principal:  "alice@example.com",
			Name:       types.Ptr("laptop"),
			CreatedAt:  "2026-07-01T01:02:03.123456Z",
			ExpiresAt:  "2026-07-02T01:02:03.123456Z",
			RevokedAt:  types.Ptr("2026-07-01T09:00:00Z"),
			LastUsedAt: types.Ptr("2026-07-01T08:00:00Z"),
		}, "wire_token_info_full.json")
	})

	// 🔒 The three nullables — `name`, `revokedAt`, `lastUsedAt` — must be ABSENT, not `null`.
	// explicitNulls=false (INV-A1-4). This is the shape a freshly-minted, never-used SESSION token
	// has, which is the overwhelmingly common one in the console's token list.
	t.Run("nullables absent", func(t *testing.T) {
		assertWireBytes(t, token.Info{
			ID:        1,
			Kind:      "SESSION",
			Principal: "alice@example.com",
			CreatedAt: "2026-07-01T01:02:03Z",
			ExpiresAt: "2026-07-01T13:02:03Z",
		}, "wire_token_info_minimal.json")
	})

	// A token NAME is user-supplied free text, so it is a real HTML-escaping surface: encoding/json
	// would rewrite `<`, `>` and `&` and kotlinx does not.
	t.Run("html metacharacters in the name", func(t *testing.T) {
		assertWireBytes(t, token.Info{
			ID:        7,
			Kind:      "USER",
			Principal: "alice@example.com",
			Name:      types.Ptr(`a<b> & c`),
			CreatedAt: "2026-07-01T01:02:03Z",
			ExpiresAt: "2026-07-01T02:02:03Z",
		}, "wire_token_info_metacharacters.json")
	})
}

// IssuedToken — the ONE response that ever carries a plaintext token.
func TestIssuedTokenGoldenBytes(t *testing.T) {
	t.Run("a named USER token", func(t *testing.T) {
		assertWireBytes(t, token.Issued{
			Token:     "pmk_TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTE",
			ID:        9,
			Kind:      "USER",
			Name:      types.Ptr("ci-runner"),
			ExpiresAt: "2026-07-01T02:02:03Z",
		}, "issued_token_named.json")
	})
	// A SESSION token has no name, so the key is absent — the shape `pmon` reads from the device
	// poll and from `/auth/session/renew`.
	t.Run("an unnamed SESSION token", func(t *testing.T) {
		assertWireBytes(t, token.Issued{
			Token:     "pmt_TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTE",
			ID:        10,
			Kind:      "SESSION",
			ExpiresAt: "2026-07-01T13:02:03Z",
		}, "issued_token_session.json")
	})
}

// The four signed-cookie payloads (§1.4) plus UserSession, the response DTO.
//
// 🔒 These bytes are inside the HMAC. A drift here does not produce a visibly wrong response — it
// produces a cookie the next release cannot verify.
func TestCookiePayloadGoldenBytes(t *testing.T) {
	t.Run("WebSessionRef", func(t *testing.T) {
		assertWireBytes(t, session.WebSessionRef{SessionID: 4242}, "web_session_ref.json")
	})
	t.Run("OAuthStateSession with returnTo", func(t *testing.T) {
		assertWireBytes(t, session.OAuthStateSession{
			State:    "0123456789abcdef",
			ReturnTo: types.Ptr("/auth/device/authorize?user_code=ABCD-EFGH"),
		}, "oauth_state_session_full.json")
	})
	// `returnTo` is nullable with a null default, so it is OMITTED — the shape a plain console login
	// produces.
	t.Run("OAuthStateSession without returnTo", func(t *testing.T) {
		assertWireBytes(t, session.OAuthStateSession{State: "0123456789abcdef"}, "oauth_state_session_minimal.json")
	})
	t.Run("OAuthNonceSession", func(t *testing.T) {
		assertWireBytes(t, session.OAuthNonceSession{Nonce: "fedcba9876543210"}, "oauth_nonce_session.json")
	})
	t.Run("DeviceVerifySession", func(t *testing.T) {
		assertWireBytes(t, session.DeviceVerifySession{UserCode: "ABCD-EFGH"}, "device_verify_session.json")
	})

	// 🔒 INV-A4-2 — UserSession is a RESPONSE DTO, never a cookie payload and never an authority.
	// `roles` defaults to emptyList() and encodeDefaults=true emits it, so it is `[]` and never
	// absent and never null. `requesterIp` is populated only for a debug-login session.
	t.Run("UserSession with no roles and no requesterIp", func(t *testing.T) {
		assertWireBytes(t, session.UserSession{Principal: "alice@example.com"}, "user_session_minimal.json")
	})
	t.Run("UserSession with roles and a simulated requesterIp", func(t *testing.T) {
		assertWireBytes(t, session.UserSession{
			Principal:   "alice@example.com",
			Roles:       []string{"analyst", "auditor"},
			RequesterIP: types.Ptr("198.51.100.7"),
		}, "user_session_full.json")
	})
}
