package oauth

import (
	"encoding/json"
	"fmt"

	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// On the wire — 14-auth.md §1, 11-mcp-oauth-management.md §6
// ---------------------------------------------------------------------------------------------

// Consent is `@Serializable data class OAuthConsent` (McpOAuth.kt:91-100) — the ONE type in this
// area that reaches a browser, through `GET /oauth/consents`.
//
// Every field is non-null with no default, so INV-A1-4's explicitNulls=false never applies and there
// are no pointers here. `createdAt`/`updatedAt` are `Instant.toString()` renderings of TIMESTAMPTZ
// columns, produced by internal/instant — NOT time.RFC3339Nano, which strips trailing zeros one
// digit at a time where Java pads to whole groups of 3 (14-auth.md Q12).
type Consent struct {
	ID        int64  `json:"id"`
	Principal string `json:"principal"`
	ClientID  string `json:"clientId"`
	Resource  string `json:"resource"`
	Scope     string `json:"scope"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// TokenResponse is `@Serializable private data class TokenResponse` (OAuthRoutes.kt:66-73) — RFC 6749
// §5.1, so every field is snake_case and none is optional.
//
// ⚠️ F27 — [TokenPair] is `@Serializable` but never serialized; the route remaps it into this shape
// (`OAuthRoutes.kt:400`). Keeping the two types distinct is not redundancy: TokenPair is camelCase
// and carries no `token_type` default on the wire.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// AuthorizationServerMetadata is RFC 8414's document, as
// `@Serializable private data class AuthorizationServerMetadata` (OAuthRoutes.kt:75-87).
//
// 🔒 `token_endpoint_auth_methods_supported = ["none"]` — THERE IS NO CLIENT SECRET ANYWHERE IN THIS
// DESIGN, which is why PKCE is mandatory at three layers (INV-A14-14): it is the only thing binding a
// code to the client that requested it.
//
// ⚠️ There is deliberately NO `registration_endpoint`. `client_id_metadata_document_supported = true`
// is the replacement: a client is identified by a URL its own metadata document lives at, so nothing
// is registered. `OAuthRoutesDbTest` case 1 asserts the field's ABSENCE (`:86`).
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported"`
}

// ProtectedResourceMetadata is RFC 9728's document —
// `@Serializable private data class ProtectedResourceMetadata` (McpServer.kt:170-176).
//
// It is A11 §2's, not §6's; see the package doc for why it is mounted here.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// ConsentListResponse is `@Serializable private data class ConsentListResponse` (OAuthRoutes.kt:89-93).
type ConsentListResponse struct {
	Consents  []Consent `json:"consents"`
	CSRFToken string    `json:"csrfToken"`
}

// MarshalJSON emits `consents: []` for a nil slice.
//
// 🔒 INV-A1-4 — encodeDefaults=true over a kotlinx `List` produces `[]`, never `null`, and the
// console's `consents.map` throws on null. [AuthorizationStore.ListConsents] already returns a
// non-nil slice; this is the belt that survives a future caller building the DTO by hand.
func (c ConsentListResponse) MarshalJSON() ([]byte, error) {
	type alias ConsentListResponse
	out := alias(c)
	if out.Consents == nil {
		out.Consents = []Consent{}
	}
	return types.MarshalWire(out)
}

// ---------------------------------------------------------------------------------------------
// Not on the wire — 14-auth.md §1 "NOT on the wire"
// ---------------------------------------------------------------------------------------------

// TokenPair is `data class OAuthTokenPair` (McpOAuth.kt:82-89), the store's issuance result.
//
// `TokenType` is Kotlin's `= "Bearer"` default argument; Go has none, so [AuthorizationStore.issuePair]
// — the ONE constructor — sets it explicitly.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
	Scope        string
}

// AccessIdentity is `data class McpAccessIdentity` (McpOAuth.kt:45-52) — what a valid MCP bearer
// resolves to, and the SOLE authorization to enter the `/mcp` surface.
//
// `Scopes` is a slice rather than a map because A11 does `capability.requiredScope in context.scopes`,
// a membership test over at most four elements, and because the ORDER it comes back in is the stored
// scope string's order, which a map would discard.
type AccessIdentity struct {
	Principal string
	ClientID  string
	Resource  string
	Scopes    []string
	ConsentID int64
}

// HasScope is Kotlin's `scope in identity.scopes`.
func (i AccessIdentity) HasScope(scope string) bool {
	for _, s := range i.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AuthorizationCodeInput is `data class AuthorizationCodeInput` (McpOAuth.kt:102-111).
type AuthorizationCodeInput struct {
	ClientID      string
	Principal     string
	RedirectURI   string
	Resource      string
	Scopes        []string
	CodeChallenge string
	// TTLSeconds is Kotlin's `ttlSeconds: Long = 300` DEFAULT ARGUMENT, so nil means "not supplied"
	// and takes 300.
	//
	// A pointer rather than a zero-means-default int64 because the two are observably different:
	// [AuthorizationStore.CreateAuthorizationCode] clamps with `coerceIn(60, 600)`, so an EXPLICIT 0
	// yields a 60-second code while an omitted argument yields 300. Collapsing them would silently
	// shorten any future caller that passes a computed zero.
	TTLSeconds *int64
	ConsentID  int64
}

// DefaultAuthorizationCodeTTLSeconds is `ttlSeconds: Long = 300` (McpOAuth.kt:109).
const DefaultAuthorizationCodeTTLSeconds int64 = 300

// ttlSeconds resolves the default argument.
func (in AuthorizationCodeInput) ttlSeconds() int64 {
	if in.TTLSeconds == nil {
		return DefaultAuthorizationCodeTTLSeconds
	}
	return *in.TTLSeconds
}

// ConsumeAuthorizationCodeInput is `data class ConsumeAuthorizationCodeInput` (McpOAuth.kt:113-121).
type ConsumeAuthorizationCodeInput struct {
	Code              string
	ClientID          string
	RedirectURI       string
	Resource          string
	CodeVerifier      string
	AccessTTLSeconds  int64
	RefreshTTLSeconds int64
}

// RefreshTokenInput is `data class RefreshTokenInput` (McpOAuth.kt:123-129).
type RefreshTokenInput struct {
	RefreshToken      string
	ClientID          string
	Resource          string
	AccessTTLSeconds  int64
	RefreshTTLSeconds int64
}

// ---------------------------------------------------------------------------------------------
// The pending-authorization cookie — OAuthRoutes.kt:49-61
// ---------------------------------------------------------------------------------------------

// PendingCookie is `MCP_OAUTH_PENDING_COOKIE` (OAuthRoutes.kt:49), the SIXTH signed cookie.
//
// internal/session/cookie.go carries a TODO saying the NAME literal appears in no area doc and was
// deliberately not invented there ("a guessed cookie name is a silent cutover break that no test
// would catch. A11 supplies it"). This is A11 supplying it, read off OAuthRoutes.kt:49. The maxAge
// stays [session.MCPOAuthPendingMaxAgeSeconds] so there is still exactly one place it is written.
const PendingCookie = "pm_oauth_pending"

// PendingCookieSpec is the pending cookie's registration. Every other attribute — path=/, httpOnly,
// secure per the issuer scheme, SameSite=Lax — comes from [session.CookieCodec], which is what makes
// this cookie survive the cross-site top-level GET back from the IdP.
var PendingCookieSpec = session.CookieSpec{
	Name:          PendingCookie,
	MaxAgeSeconds: session.MCPOAuthPendingMaxAgeSeconds,
}

// PendingAuthorization is `@Serializable internal data class McpPendingAuthorization`
// (OAuthRoutes.kt:51-61) — the authorization request, parked in a MAC'd cookie across the login and
// consent round trips.
//
// Two fields carry Kotlin defaults and are therefore OPTIONAL on read:
//
//   - `principal` is `String? = null`, and INV-A1-4's explicitNulls=false OMITS it when absent — so
//     it must be a pointer, and an absent key must decode to nil rather than "".
//   - `csrf` is `randomSecret("csrf_", 18)`, i.e. a DEFAULT EXPRESSION evaluated per construction.
//     Go has no such thing; [NewPendingAuthorization] is that constructor.
//
// The other six are non-null with no default, so kotlinx throws MissingFieldException when one is
// absent and Ktor's `sessions.get<T>()` turns the throw into null — "no pending authorization",
// never a 500. [UnmarshalJSON] reproduces the required-ness that encoding/json would zero-fill away,
// exactly as [session.WebSessionRef] does for `sessionId`.
type PendingAuthorization struct {
	ClientID      string  `json:"clientId"`
	RedirectURI   string  `json:"redirectUri"`
	Resource      string  `json:"resource"`
	Scope         string  `json:"scope"`
	State         string  `json:"state"`
	CodeChallenge string  `json:"codeChallenge"`
	Principal     *string `json:"principal,omitempty"`
	CSRF          string  `json:"csrf"`
}

// NewPendingAuthorization is the Kotlin constructor, including `csrf`'s default expression.
func NewPendingAuthorization(clientID, redirectURI, resource, scope, state, codeChallenge string, principal *string) (PendingAuthorization, error) {
	csrf, err := RandomSecret("csrf_", 18)
	if err != nil {
		return PendingAuthorization{}, err
	}
	return PendingAuthorization{
		ClientID: clientID, RedirectURI: redirectURI, Resource: resource, Scope: scope,
		State: state, CodeChallenge: codeChallenge, Principal: principal, CSRF: csrf,
	}, nil
}

// UnmarshalJSON reproduces kotlinx's required-field enforcement for the six non-defaulted fields.
// See [PendingAuthorization].
func (p *PendingAuthorization) UnmarshalJSON(b []byte) error {
	var raw struct {
		ClientID      *string `json:"clientId"`
		RedirectURI   *string `json:"redirectUri"`
		Resource      *string `json:"resource"`
		Scope         *string `json:"scope"`
		State         *string `json:"state"`
		CodeChallenge *string `json:"codeChallenge"`
		Principal     *string `json:"principal"`
		CSRF          *string `json:"csrf"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	required := []struct {
		name string
		v    *string
	}{
		{"clientId", raw.ClientID}, {"redirectUri", raw.RedirectURI}, {"resource", raw.Resource},
		{"scope", raw.Scope}, {"state", raw.State}, {"codeChallenge", raw.CodeChallenge},
	}
	for _, f := range required {
		if f.v == nil {
			return fmt.Errorf("%w: %s (McpPendingAuthorization)", session.ErrMissingField, f.name)
		}
	}
	p.ClientID, p.RedirectURI, p.Resource = *raw.ClientID, *raw.RedirectURI, *raw.Resource
	p.Scope, p.State, p.CodeChallenge = *raw.Scope, *raw.State, *raw.CodeChallenge
	p.Principal = raw.Principal
	// `csrf` HAS a default, so an absent key is legal and leaves the zero value — which then cannot
	// match any submitted form field, so the consent post fails closed rather than succeeding on "".
	p.CSRF = ""
	if raw.CSRF != nil {
		p.CSRF = *raw.CSRF
	}
	return nil
}
