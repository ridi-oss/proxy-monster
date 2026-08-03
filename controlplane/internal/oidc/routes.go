package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/config"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// RandomOpaqueToken is `private fun randomOpaqueToken(): String` (Oidc.kt:59-63) — used for BOTH the
// CSRF `state` and the `nonce`.
//
// ⚠️ Two things a port must not copy, both recorded so the difference is not read as significant:
// (a) F27 — the Kotlin KDoc says "A 32-byte random" over a 24-byte body; 24 bytes = 192 bits is what
// it actually produces, and 192 bits is what this returns. (b) it constructs a FRESH SecureRandom()
// on every call, unlike Tokens.kt/DaemonSession.kt/DeviceLoginStore which each hold one long-lived
// instance. Harmless on the JVM and meaningless in Go, where crypto/rand.Read is the only correct
// call and there is no instance to hold.
//
// An error is returned rather than swallowed: a CSPRNG failure must not silently yield a predictable
// state or nonce.
func RandomOpaqueToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// deviceAuthorizeContinuation is the third accepted `return_to` shape.
//
// 🔒 Anchored (Kotlin's `matches` is whole-string) and the code class is `[A-Za-z0-9-]{1,16}` — so a
// user code containing anything else silently loses its continuation and the user lands on "/"
// instead of completing the device login. That is REPRODUCED, not tightened: today's user codes are
// `XXXX-XXXX` from an alphanumeric alphabet, so nothing legitimate is excluded.
var deviceAuthorizeContinuation = regexp.MustCompile(`^/auth/device/authorize\?user_code=[A-Za-z0-9-]{1,16}$`)

// ReturnTarget is `internal fun oidcReturnTarget(raw: String?): String?` (Oidc.kt:212-219).
//
// 🔒 INV-A4-59 — `return_to` is an ALLOWLIST, never an echo. Quoted from Oidc.kt:95-96 and :217-218:
// "Only the co-hosted OAuth resume and popup re-auth landing routes are valid continuations. Treat
// every other value as absent, so this can never become an open redirect." Exactly three shapes pass;
// everything else — including `https://evil.example/callback`, `//evil.example/callback`, `/other`
// and `/` — becomes nil. OidcCallbackTest case 1 pins all six.
func ReturnTarget(raw *string) *string {
	if raw == nil {
		return nil
	}
	v := *raw
	if v == "/oauth/resume" || v == "/auth/reauth-complete" || deviceAuthorizeContinuation.MatchString(v) {
		return &v
	}
	return nil
}

// FailureTarget is `internal fun oidcFailureTarget(state, oauthError, consoleError): String`
// (Oidc.kt:221-233).
//
//	| state.ReturnTo         | result                                                              |
//	|------------------------|---------------------------------------------------------------------|
//	| "/oauth/resume"        | /oauth/resume?error=<oauthError>                                    |
//	| "/auth/reauth-complete"| /login?error=<consoleError>&callbackUrl=%2Fauth%2Freauth-complete   |
//	| any other non-nil      | /login?error=<consoleError>&return_to=<encoded returnTo>            |
//	| nil                    | /login?error=<consoleError>                                         |
//
// 🔒 INV-A4-64 — a RECOVERABLE failure keeps its continuation. Quoted from Oidc.kt:229-231: "A device
// login that hit a recoverable failure (a cancelled consent, a transient token-endpoint error) keeps
// its continuation, so retrying the sign-in still completes the pmon login instead of silently
// becoming an ordinary console login and stranding the handle until it expires."
//
// That is also why the function takes TWO error vocabularies: `oauthError` is RFC-shaped, for the
// OAuth AS resume route which must receive an OAuth error code; `consoleError` is an i18n key
// fragment for the console login screen. Collapsing them to one breaks whichever consumer loses its
// vocabulary. OidcCallbackTest cases 3-6 cover the matrix.
//
// The `callbackUrl=%2Fauth%2Freauth-complete` arm is a PRE-ENCODED literal in the Kotlin — reproduced
// verbatim rather than re-derived through the encoder, because re-deriving it is how a port
// accidentally emits `/auth/reauth-complete` unencoded.
func FailureTarget(state *OAuthStateSession, oauthError, consoleError string) string {
	var returnTo *string
	if state != nil {
		returnTo = state.ReturnTo
	}
	switch {
	case returnTo != nil && *returnTo == "/oauth/resume":
		return "/oauth/resume?error=" + encodeURLParameter(oauthError)
	case returnTo != nil && *returnTo == "/auth/reauth-complete":
		return "/login?error=" + encodeURLParameter(consoleError) + "&callbackUrl=%2Fauth%2Freauth-complete"
	case returnTo != nil:
		return "/login?error=" + encodeURLParameter(consoleError) + "&return_to=" + encodeURLParameter(*returnTo)
	default:
		return "/login?error=" + encodeURLParameter(consoleError)
	}
}

// Routes is `fun Route.oidcRoutes(config, discovery, validator, http, userGroupStore, roleResolver,
// store, log)` (Oidc.kt:76-210), as a struct because Go has no receiver-scoped route DSL.
//
// Discovery and Validator are POINTERS and may be nil. That is not defensive coding: the Kotlin's
// 501 guard checks all three of `config.oidc`, `discovery` and `validator` "so the unconfigured
// deployment never NPEs", and a port that made them non-nil-by-construction would have no way to
// express the unconfigured state that OidcCallbackTest case 2 asserts on.
type Routes struct {
	Config    config.Config
	Discovery *Discovery
	Validator *IDTokenValidator
	HTTP      *http.Client
	// Cookies is internal/session's codec — the ONE encoding for all six control-plane cookies.
	// This package never writes a cookie any other way; see cookies.go.
	Cookies    *session.CookieCodec
	UserGroups UserGroupProvisioner
	Roles      RoleResolver
	Sessions   WebSessions
	Log        *slog.Logger
}

// Register mounts the two routes on a stdlib mux (D6).
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/oidc/login", rt.Login)
	mux.HandleFunc("GET /auth/oidc/callback", rt.Callback)
}

func (rt *Routes) log() *slog.Logger {
	if rt.Log != nil {
		return rt.Log
	}
	return slog.Default()
}

// configured is the shared 501 guard: `config.oidc == null || discovery == null || validator == null`.
func (rt *Routes) configured() (*config.OIDCConfig, bool) {
	if rt.Config.OIDC == nil || rt.Discovery == nil || rt.Validator == nil {
		return nil, false
	}
	return rt.Config.OIDC, true
}

// Login is `GET /auth/oidc/login` (Oidc.kt:86-113): stash the CSRF state + nonce, then 302 to the
// IdP's authorize endpoint.
//
// ⚠️ No PKCE, deliberately — contrast A11's MCP AS, where V7's CHECK makes `code_challenge`
// mandatory. This is a confidential client with a client_secret, so PKCE is optional per OAuth 2.1.
// Recorded so a port does not "restore" it and break the IdP-side redirect-URI registration.
//
// ⚠️ Step 5's `discovery.document()` is NOT wrapped (see [Discovery.Document]): a misconfigured
// PM_OIDC_ISSUER surfaces here as a 500 on the login redirect, not as `common.oidc_not_configured`.
// Reproduced.
func (rt *Routes) Login(w http.ResponseWriter, r *http.Request) {
	oidc, ok := rt.configured()
	if !ok {
		_ = types.RespondError(w, http.StatusNotImplemented, "common.oidc_not_configured", nil)
		return
	}

	state, err := RandomOpaqueToken()
	if err != nil {
		rt.log().Error("OIDC login could not generate state", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := RandomOpaqueToken()
	if err != nil {
		rt.log().Error("OIDC login could not generate nonce", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	returnTo := ReturnTarget(queryParam(r, "return_to"))
	if err := rt.Cookies.Set(w, StateCookieSpec, OAuthStateSession{State: state, ReturnTo: returnTo}); err != nil {
		rt.log().Error("OIDC login could not write the state cookie", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := rt.Cookies.Set(w, NonceCookieSpec, OAuthNonceSession{Nonce: nonce}); err != nil {
		rt.log().Error("OIDC login could not write the nonce cookie", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	doc, err := rt.Discovery.Document(r.Context())
	if err != nil {
		rt.log().Error("OIDC discovery failed on login", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// The Kotlin appends "?" UNCONDITIONALLY, so an authorization_endpoint that already carries a
	// query string produces a malformed URL. Reproduced: no IdP in the wild does that, and "fixing"
	// it changes the bytes of every authorize redirect.
	var b strings.Builder
	b.WriteString(doc.AuthorizationEndpoint)
	b.WriteString("?client_id=")
	b.WriteString(encodeURLParameter(oidc.ClientID))
	b.WriteString("&response_type=code")
	b.WriteString("&scope=")
	b.WriteString(encodeURLParameter(oidc.Scopes))
	b.WriteString("&redirect_uri=")
	b.WriteString(encodeURLParameter(oidc.RedirectURI))
	b.WriteString("&state=")
	b.WriteString(encodeURLParameter(state))
	b.WriteString("&nonce=")
	b.WriteString(encodeURLParameter(nonce))
	redirect(w, b.String())
}

// tokenResponse is `@Serializable private data class TokenResponse` (Oidc.kt:52-57).
//
// 🔒 `id_token` is NON-NULLABLE in the Kotlin, so an IdP response omitting it throws inside the
// callback's try and lands on the `server_error` failure redirect — deliberate, because identity
// comes only from the id_token. The pointer plus the explicit nil check below reproduces the
// required-ness that encoding/json would otherwise zero-fill away.
type tokenResponse struct {
	IDToken      *string `json:"id_token"`
	AccessToken  *string `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
}

// Callback is `GET /auth/oidc/callback` (Oidc.kt:117-209).
//
// 🔒 INV-A4-60 — identity comes from the id_token ONLY, and a zero-role principal never gets a
// session. Quoted from the oidcRoutes KDoc (Oidc.kt:72-74): "Identity is established from the
// id_token (validated signature + issuer + audience + expiry + nonce via [validator]), never from the
// userinfo endpoint or client-asserted claims — userinfo is optional/absent on some providers and was
// never signed to begin with." The role gate runs BEFORE the mint, so the no-access screen is reached
// with no principal_session row created (OidcWebSessionDbTest case 2).
//
// 🔒 INV-A4-62 — `state` and `nonce` are ONE-TIME, cleared BEFORE any validation, and check different
// things. Quoted from Oidc.kt:129: "One-time use: drop both cookies regardless of the outcome below."
// OidcCallbackTest cases 7 and 8 assert each cookie is consumed even on failure — which is what stops
// a replay of a FAILED callback.
//
// 🔒 INV-A4-61 — the refresh token is kept only when `offline_access` was actually requested, so an
// IdP that returns one unbidden does not get it persisted.
func (rt *Routes) Callback(w http.ResponseWriter, r *http.Request) {
	oidc, ok := rt.configured()
	if !ok {
		_ = types.RespondError(w, http.StatusNotImplemented, "common.oidc_not_configured", nil)
		return
	}

	code := queryParam(r, "code")
	state := queryParam(r, "state")
	providerError := queryParam(r, "error")

	// A missing cookie, a forged one and a malformed one all collapse to "absent" here, exactly as
	// Ktor's `sessions.get<T>()` returns null for all three — a caller that could tell them apart
	// would be an oracle.
	var stateSession *OAuthStateSession
	var got OAuthStateSession
	if err := rt.Cookies.Read(r, StateCookieSpec, &got); err == nil {
		stateSession = &got
	}
	var expectedNonce *string
	var nonceSession OAuthNonceSession
	if err := rt.Cookies.Read(r, NonceCookieSpec, &nonceSession); err == nil {
		expectedNonce = &nonceSession.Nonce
	}
	// INV-A4-62 — before ANY validation, unconditionally.
	rt.Cookies.Clear(w, StateCookieSpec)
	rt.Cookies.Clear(w, NonceCookieSpec)

	// Step 4. Note the asymmetry, and reproduce it: on a STATE failure only `/auth/reauth-complete`
	// keeps its continuation. A `/oauth/resume` continuation does NOT — it falls to the flat
	// "/login?error=state". Routing a state failure through FailureTarget unconditionally would send
	// the OAuth AS resume an `access_denied` it never gets today.
	if state == nil || stateSession == nil || *state != stateSession.State {
		rt.log().Warn("OIDC callback state validation failed")
		target := "/login?error=state"
		if stateSession != nil && stateSession.ReturnTo != nil && *stateSession.ReturnTo == "/auth/reauth-complete" {
			target = FailureTarget(stateSession, "access_denied", "state")
		}
		redirect(w, target)
		return
	}
	if providerError != nil {
		rt.log().Warn("OIDC callback returned error", "error", *providerError)
		redirect(w, FailureTarget(stateSession, "access_denied", "oidc"))
		return
	}
	if code == nil {
		rt.log().Warn("OIDC callback omitted both code and error")
		redirect(w, FailureTarget(stateSession, "server_error", "state"))
		return
	}
	if expectedNonce == nil {
		rt.log().Warn("OIDC callback nonce state is absent")
		redirect(w, FailureTarget(stateSession, "access_denied", "nonce"))
		return
	}

	// Everything from here is inside the Kotlin's `try`, whose catch is the server_error arm at the
	// bottom. Go has no exceptions, so each fallible step returns to that arm explicitly — the
	// `fail` closure keeps the two shapes readable side by side.
	fail := func(msg string, err error) {
		rt.log().Error(msg, "err", err)
		redirect(w, FailureTarget(stateSession, "server_error", "oidc"))
	}

	doc, err := rt.Discovery.Document(r.Context())
	if err != nil {
		fail("OIDC token exchange failed", err)
		return
	}
	var token tokenResponse
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {*code},
		"redirect_uri":  {oidc.RedirectURI},
		"client_id":     {oidc.ClientID},
		"client_secret": {oidc.ClientSecret},
	}
	if err := postFormJSON(r.Context(), rt.HTTP, doc.TokenEndpoint, form, &token); err != nil {
		fail("OIDC token exchange failed", err)
		return
	}
	if token.IDToken == nil {
		fail("OIDC token exchange failed", errMissingIDToken)
		return
	}

	// Signature + iss/aud/exp + nonce are all verified inside Validate; nil means one of them failed
	// (including a nonce mismatch — the one-time cookie above already guards replay of the STATE,
	// this guards injection of a DIFFERENT authorization result).
	claims := rt.Validator.Validate(r.Context(), *token.IDToken, expectedNonce)
	if claims == nil {
		rt.log().Warn("OIDC callback id_token validation failed")
		redirect(w, FailureTarget(stateSession, "access_denied", "nonce"))
		return
	}

	// `claims.email ?: claims.subject` — an email-less token changes the identity KEY, which is why
	// the provisioner's COALESCE-on-email branch is reachable (14-auth.md INV-A14-35).
	principal := claims.Subject
	if claims.Email != nil {
		principal = *claims.Email
	}

	if err := rt.UserGroups.ProvisionFromOidc(
		r.Context(), principal, claims.Email, claims.Groups, FromConfig(oidc.GroupMapping),
	); err != nil {
		fail("OIDC token exchange failed", err)
		return
	}

	roles, err := rt.Roles.Resolve(r.Context(), principal)
	if err != nil {
		fail("OIDC token exchange failed", err)
		return
	}
	if len(roles) == 0 {
		rt.log().Warn("OIDC callback principal has no effective roles", "principal", principal)
		redirect(w, FailureTarget(stateSession, "access_denied", "no_access"))
		return
	}

	refreshToken := offlineAccessRefreshToken(token.RefreshToken, oidc.Scopes)

	// `config.mcpIssuer.startsWith("https://")` — the same derivation the five signed cookies use.
	deviceID, err := rt.Sessions.EnsureDeviceCookie(w, r, strings.HasPrefix(rt.Config.MCPIssuer(), "https://"))
	if err != nil {
		fail("OIDC token exchange failed", err)
		return
	}
	sessionID, err := rt.Sessions.MintWeb(
		r.Context(), principal, refreshToken,
		rt.Config.WebSessionAbsoluteSeconds, rt.Config.WebSessionIdleSeconds, deviceID,
	)
	if err != nil {
		fail("OIDC token exchange failed", err)
		return
	}
	if err := rt.Sessions.SetSessionCookie(w, r, sessionID); err != nil {
		fail("OIDC token exchange failed", err)
		return
	}

	target := "/"
	if stateSession.ReturnTo != nil {
		target = *stateSession.ReturnTo
	}
	redirect(w, target)
}

// errMissingIDToken stands in for kotlinx's MissingFieldException on the non-nullable `id_token`.
var errMissingIDToken = &missingFieldError{field: "id_token"}

type missingFieldError struct{ field string }

func (e *missingFieldError) Error() string {
	return "token endpoint response is missing required field " + e.field
}

// offlineAccessRefreshToken is
// `token.refresh_token?.takeIf { "offline_access" in oidc.scopes.split(Regex("\\s+")).filter(String::isNotBlank) }`
// (Oidc.kt:190-192).
//
// 🔒 INV-A4-61. The predicate is on the CONFIGURED scope string, whitespace-split and blank-filtered —
// not on what the IdP echoed back. Combined with INV-A4-14 (no PM_RESULT_KEY ⇒ no persistence), that
// is the full condition OidcWebSessionDbTest case 1's title states: "stores refresh only when
// encrypted offline access is available".
func offlineAccessRefreshToken(refreshToken *string, scopes string) *string {
	if refreshToken == nil {
		return nil
	}
	for _, s := range strings.Fields(scopes) {
		// strings.Fields splits on any run of Unicode whitespace and drops empties, which is
		// exactly `split(Regex("\\s+")).filter(String::isNotBlank)`.
		if s == "offline_access" {
			return refreshToken
		}
	}
	return nil
}

// queryParam reads a query parameter, distinguishing ABSENT from PRESENT-BUT-EMPTY. Ktor's
// `queryParameters["x"]` is null only when the key is absent, and the callback's `code == null` and
// `params["error"] != null` branches both depend on that distinction.
func queryParam(r *http.Request, name string) *string {
	q := r.URL.Query()
	if !q.Has(name) {
		return nil
	}
	v := q.Get(name)
	return &v
}

// redirect is `call.respondRedirect(url)` — a 302 with a Location header and NO body.
//
// http.Redirect is deliberately not used: it writes an HTML body for GET requests, which Ktor does
// not, and these responses are asserted on header-only in the ported suites.
func redirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// encodeURLParameter is ktor's `String.encodeURLParameter()`.
//
// It percent-encodes everything outside RFC 3986's unreserved set (ALPHA / DIGIT / "-" / "." / "_" /
// "~"), uppercase hex, one byte at a time over the UTF-8 encoding.
//
// ⚠️ url.QueryEscape is NOT a substitute: it encodes a space as "+", while ktor's default
// (spaceToPlus = false) emits "%20". `oidc.scopes` is space-separated — "openid profile email groups
// offline_access" — so this is the single highest-traffic string in the package and the one place the
// difference would show up on every login redirect. url.PathEscape is not a substitute either: it
// leaves "$&+,/:;=?@" unescaped, and "/" appears in every return_to.
func encodeURLParameter(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0F])
		}
	}
	return b.String()
}
