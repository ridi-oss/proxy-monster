package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// MCPAScopes is `val MCPA_SCOPES` (OAuthRoutes.kt:47) — the four scopes `/oauth/authorize` will
// accept, in the Kotlin's declaration order. It is a SET there, so nothing may depend on this order;
// [sortedMCPAScopes] is what the discovery document publishes.
var MCPAScopes = []string{
	"mcp:read", "mcp:datasources:write", "mcp:policies:write", "mcp:identity:write",
}

// sortedMCPAScopes is `MCPA_SCOPES.sorted()` (OAuthRoutes.kt:123).
func sortedMCPAScopes() []string {
	out := append([]string(nil), MCPAScopes...)
	slices.Sort(out)
	return out
}

// MCPCapabilityScopes is `McpCapabilityRegistry.supportedScopes.toList()`
// (McpCapabilityRegistry.kt:112, consumed at McpServer.kt:182) — the sorted set of every scope any
// MCP tool requires.
//
//	TODO(A11-MCP): source this from the ported McpCapabilityRegistry once A11's MCP half lands, and
//	delete this literal. Its VALUE is asserted equal to sortedMCPAScopes() by
//	TestTheProtectedResourceScopesAreExactlyTheAuthorizationServerScopes, which is what makes the
//	duplication safe to carry until then: the registry's verify() already requires every capability
//	scope to be an MCPA scope, so the two lists cannot legitimately diverge.
func MCPCapabilityScopes() []string { return sortedMCPAScopes() }

// ---------------------------------------------------------------------------------------------
// The seams this package needs from areas it does not own
// ---------------------------------------------------------------------------------------------

// WebSessions is the slice of A4's `PrincipalSessionStore` plus `Auth.kt`'s cookie helpers that the
// DEBUG authorize branch touches, and nothing else.
//
// It is a separate interface from [oidc.WebSessions] rather than a reuse, because of one parameter:
// `debugRequesterIp`. INV-A11-19 is entirely about that argument being carried across the remint, and
// an interface that cannot express it cannot implement the invariant. The OIDC callback has the
// opposite requirement (an SSO login has a real peer, so it passes nil), which is why the Kotlin's
// `mintWeb` has the parameter defaulted and the two callers differ.
//
//	TODO(A1): internal/app supplies this. Its existing `oidcWebSessions` adapter is three lines from
//	satisfying it — MintWeb needs the extra argument threaded into session.MintWebInput.DebugRequesterIP.
type WebSessions interface {
	// MintWeb is `principalSessionStore.mintWeb(principal, refreshToken, absoluteSeconds,
	// idleSeconds, deviceId, debugRequesterIp)`. NEWEST-WINS: it DISPLACES the principal's other live
	// web sessions, which is the whole reason INV-A11-19 exists.
	MintWeb(ctx context.Context, principal string, refreshToken *string, absoluteSeconds, idleSeconds int64, deviceID string, debugRequesterIP *string) (int64, error)
	// SetSessionCookie is `call.sessions.set(WebSessionRef(sessionId))` — the storage link AND the
	// `pm_session` cookie, in that order.
	SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID int64) error
	// EnsureDeviceCookie is `ApplicationCall.ensureDeviceCookie(secure)`.
	EnsureDeviceCookie(w http.ResponseWriter, r *http.Request, secure bool) (string, error)
}

// ---------------------------------------------------------------------------------------------
// The route group — OAuthRoutes.kt:105-308
// ---------------------------------------------------------------------------------------------

// Routes is `fun Route.mcpOAuthRoutes(config, dataSource, principalSessionStore, cimdResolver)`
// (OAuthRoutes.kt:105-308), as a struct because Go has no receiver-scoped route DSL.
//
// # The route table — 11-mcp-oauth-management.md §6
//
//	GET    /.well-known/oauth-authorization-server   none   200 AuthorizationServerMetadata
//	GET    /.well-known/oauth-protected-resource     none   200 ProtectedResourceMetadata   (A11 §2)
//	GET    /.well-known/oauth-protected-resource/mcp none   200 ProtectedResourceMetadata   (A11 §2)
//	GET    /oauth/authorize                          none   302 | 200 consent HTML | 400 invalid_request/invalid_client
//	GET    /oauth/resume                             none   302 | 200 consent HTML | 400 invalid_request/invalid_client
//	POST   /oauth/consent                            none   302 | 400 invalid_request
//	POST   /oauth/token                              none   200 TokenResponse | 400 invalid_request/invalid_grant/unsupported_grant_type
//	POST   /oauth/revoke                             none   200 {}                (RFC 7009: ALWAYS 200)
//	GET    /oauth/consents                           session 200 ConsentListResponse | 401 login_required
//	DELETE /oauth/consents/{id}                      session 204 | 400 invalid_request | 401 login_required | 404 invalid_request
//
// 🔒 NOT ONE OF THESE CALLS A GATE HELPER, and that is correct rather than an omission. `requireApi`
// and friends answer with an `ApiError`, and every response on this surface must be an RFC 6749
// `OAuthError` — INV-A11-22, "every OAuth error is a 400 with an OAuthError body, including
// invalid_grant. Not 401. Uniform shape." The two consent-management routes do their own session
// check and answer `401 login_required` in the OAuth vocabulary. A port that reached for
// [httpapi.Gates] here would put `{"code": …}` in front of a client that has no schema for it.
//
// 🔒 INV-A11-20 — ONE ORIGIN, ONE SIGNED SESSION, NO SERVICE CREDENTIAL. Production OAuth reuses the
// control plane's OWN OIDC login: there is no service call and no service credential between the
// authorization server and the resource server, because they are the same process.
type Routes struct {
	Config config.Config
	Store  *AuthorizationStore
	// Cookies is internal/session's codec — the pending cookie is the sixth control-plane cookie and
	// is written no other way.
	Cookies *session.CookieCodec
	// Sessions answers `call.userSession()` / `call.webSession()`. Resolution is cached per request
	// by [httpapi.Sessions.Install], which the debug branch depends on: it reads BOTH accessors and
	// must see one row, not two resolutions.
	Sessions    *httpapi.Sessions
	WebSessions WebSessions
	// Resolver is `cimdResolver: CimdResolver = HttpCimdResolver(productionChecks = !config.authDebug)`.
	// Nil takes that default; see [NewRoutes].
	Resolver CimdResolver
	Log      *slog.Logger

	// MountProtectedResourceMetadata mounts the two `/.well-known/oauth-protected-resource[/mcp]`
	// paths from HERE. It defaults to FALSE and should stay false in production wiring.
	//
	// 🔴 THE TWO PATHS HAVE EXACTLY ONE OWNER, AND IT IS internal/mcp. `McpServer.kt:143-144` mounts
	// them inside `installMcp`'s own `routing { }` block, so A11 §2 owns them, not §6 — and
	// internal/mcp/doc.go says so in as many words ("the only OAuth-adjacent thing this package
	// serves is the two unauthenticated PROTECTED-RESOURCE discovery documents"). Registering the
	// same pattern twice on a stdlib ServeMux PANICS AT STARTUP, which is a boot failure, not a
	// degraded route.
	//
	// The flag exists at all because the documents are pure functions of [config.Config] and
	// `OAuthRoutesDbTest` case 2 asserts that the authorization-server document and the
	// protected-resource document agree on ONE ORIGIN (INV-A11-20) — a claim about both halves that
	// this package's suite can only make if it can serve both. So: on in tests, off in production.
	// [Routes.ProtectedResourceMetadata] is exported for whichever group ends up owning them.
	MountProtectedResourceMetadata bool
}

// NewRoutes applies the Kotlin's default argument for the resolver.
func NewRoutes(cfg config.Config, store *AuthorizationStore, cookies *session.CookieCodec, sessions *httpapi.Sessions, web WebSessions, resolver CimdResolver, log *slog.Logger) *Routes {
	if resolver == nil {
		resolver = NewHTTPCimdResolver(!cfg.AuthDebug)
	}
	return &Routes{
		Config: cfg, Store: store, Cookies: cookies, Sessions: sessions,
		WebSessions: web, Resolver: resolver, Log: log,
	}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the nine patterns. No pattern ends in `/` — see httpapi.Router's D6 note.
//
// The `/oauth/…` handlers are wrapped in [ProtocolGuard] individually, not only globally: the guard
// is `installMcpOAuthProtocolGuard()` (OAuthRoutes.kt:95-102), an APPLICATION-level intercept that
// A1's composition root installs, and this package cannot install it. Wrapping here means the
// no-store/no-cache headers are correct even before the wiring agent adds the middleware; adding it
// then is still worth doing, because only a pipeline-level intercept also covers a 404 under
// `/oauth/`, which a mux cannot route to a handler at all.
//
// ⚠️ The two well-known handlers are deliberately NOT wrapped. The Kotlin's guard tests
// `path().startsWith("/oauth/")`, so the discovery documents carry no cache directives and are
// cacheable — which is the point of a discovery document.
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", rt.authorizationServerMetadata)
	if rt.MountProtectedResourceMetadata {
		mux.HandleFunc("GET /.well-known/oauth-protected-resource", rt.ProtectedResourceMetadata)
		mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", rt.ProtectedResourceMetadata)
	}

	mux.Handle("GET /oauth/authorize", ProtocolGuard(http.HandlerFunc(rt.authorize)))
	mux.Handle("GET /oauth/resume", ProtocolGuard(http.HandlerFunc(rt.resume)))
	mux.Handle("POST /oauth/consent", ProtocolGuard(http.HandlerFunc(rt.consent)))
	mux.Handle("POST /oauth/token", ProtocolGuard(http.HandlerFunc(rt.token)))
	mux.Handle("POST /oauth/revoke", ProtocolGuard(http.HandlerFunc(rt.revoke)))
	mux.Handle("GET /oauth/consents", ProtocolGuard(http.HandlerFunc(rt.listConsents)))
	mux.Handle("DELETE /oauth/consents/{id}", ProtocolGuard(http.HandlerFunc(rt.deleteConsent)))
}

// ProtocolGuard is `fun Application.installMcpOAuthProtocolGuard()` (OAuthRoutes.kt:95-102): every
// request whose path starts with `/oauth/` gets `Cache-Control: no-store` and `Pragma: no-cache`.
//
// 🔒 A cached authorization code, token response or consent page is a credential sitting in a shared
// proxy. `Pragma` is there for HTTP/1.0 intermediaries that ignore Cache-Control.
//
// The headers are set BEFORE the handler runs, so a handler that writes its own status still carries
// them; net/http only freezes the header map at the first WriteHeader.
//
//	TODO(A1): add this to the router's middleware chain so it also covers a 404 under /oauth/.
func ProtocolGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, httpapi.OAuthPathPrefix) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

func (rt *Routes) logger() *slog.Logger {
	if rt.Log != nil {
		return rt.Log
	}
	return slog.Default()
}

// fail is the Kotlin's "an exception escaped the handler" path: StatusPages answers
// `500 OAuthError("server_error")` for `/oauth/**` and for the authorization-server metadata path,
// and `500 ApiError("common.fallback")` elsewhere. [httpapi.RespondFallback] is that same branch, so
// a handler that returns here produces byte-identical bytes to one that panicked.
//
// Using it rather than panicking is deliberate: the two are indistinguishable to the client, and a
// returned error keeps the failure on the normal control flow where a reader can see which step
// produced it.
func (rt *Routes) fail(w http.ResponseWriter, r *http.Request, err error) {
	httpapi.RespondFallback(w, r, rt.logger(), err)
}

// oauthError is `private suspend fun ApplicationCall.oauthError(error)` (OAuthRoutes.kt:409-411) —
// INV-A11-22's uniform 400.
func (rt *Routes) oauthError(w http.ResponseWriter, code string) {
	rt.respondOAuth(w, http.StatusBadRequest, code)
}

func (rt *Routes) respondOAuth(w http.ResponseWriter, status int, code string) {
	err := httpapi.RespondOAuthError(w, types.OAuthErrorResponse{
		Status: status,
		Body:   types.OAuthError{Error: code},
	})
	if err != nil {
		rt.logger().Error("failed to write OAuth error", "error", code, "err", err)
	}
}

func (rt *Routes) respondJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.logger().Error("failed to write OAuth response", "path", r.URL.Path, "err", err)
	}
}

// ---------------------------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------------------------

// authorizationServerMetadata is `GET /.well-known/oauth-authorization-server` (OAuthRoutes.kt:112-127).
//
// Every endpoint is derived from `config.mcpIssuer`, the ORIGIN of `PM_MCP_RESOURCE` — so the
// authorization server, the resource server and the console are one origin by construction rather
// than by configuration (INV-A11-20).
func (rt *Routes) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := rt.Config.MCPIssuer()
	rt.respondJSON(w, r, http.StatusOK, AuthorizationServerMetadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oauth/authorize",
		TokenEndpoint:                     issuer + "/oauth/token",
		RevocationEndpoint:                issuer + "/oauth/revoke",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		ScopesSupported:                   sortedMCPAScopes(),
		ClientIDMetadataDocumentSupported: true,
	})
}

// ProtectedResourceMetadata is `resourceMetadata(config)` on both of McpServer.kt:143-144's paths.
//
// Both paths answer the SAME document — A11 §2 registers them separately because RFC 9728 locates the
// document at `/.well-known/oauth-protected-resource<resource-path>` while some clients probe the
// bare path.
//
// Exported and mounted only under [Routes.MountProtectedResourceMetadata]; internal/mcp owns these
// paths in production wiring. See that field.
func (rt *Routes) ProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	rt.respondJSON(w, r, http.StatusOK, ProtectedResourceMetadata{
		Resource:               rt.Config.MCPResource,
		AuthorizationServers:   []string{rt.Config.MCPIssuer()},
		ScopesSupported:        MCPCapabilityScopes(),
		BearerMethodsSupported: []string{"header"},
	})
}

// ---------------------------------------------------------------------------------------------
// GET /oauth/authorize — OAuthRoutes.kt:129-206
// ---------------------------------------------------------------------------------------------

// authorize is the authorization endpoint.
//
// 🔒 VALIDATION IS ALL-OR-NOTHING AND ANSWERS ONE CODE. Eight conditions are ANDed into a single
// `valid` and any failure is `400 invalid_request` with no description — the endpoint must not tell a
// probing client WHICH parameter it got wrong.
//
// 🔒 INV-A11-18 — `resource` MUST EQUAL config.MCPResource EXACTLY, here and at both token grants.
// This is the audience binding: an access token minted for one resource cannot be exchanged against
// another. The comparison is `==` on the raw parameter, with no normalization, no trailing-slash
// tolerance and no case folding.
//
// The CIMD resolve and the metadata validation are two SEPARATE `runCatching`s that answer the same
// `400 invalid_client`, so an unreachable metadata document and a redirect_uri the document does not
// declare are indistinguishable to the client.
func (rt *Routes) authorize(w http.ResponseWriter, r *http.Request) {
	clientID := queryParam(r, "client_id")
	redirectURI := queryParam(r, "redirect_uri")
	state := queryParam(r, "state")
	resource := queryParam(r, "resource")
	challenge := queryParam(r, "code_challenge")
	requestedScopes := requestedScopeSet(queryParam(r, "scope"))

	valid := equalsStr(queryParam(r, "response_type"), "code") &&
		notNullOrBlank(clientID) && notNullOrBlank(redirectURI) && notNullOrBlank(state) &&
		equalsStr(resource, rt.Config.MCPResource) &&
		equalsStr(queryParam(r, "code_challenge_method"), "S256") &&
		challenge != nil && IsValidPKCEChallenge(*challenge) &&
		len(requestedScopes) > 0 && allIn(requestedScopes, MCPAScopes)
	if !valid {
		rt.oauthError(w, "invalid_request")
		return
	}

	metadata, err := rt.Resolver.Resolve(r.Context(), *clientID)
	if err != nil {
		rt.oauthError(w, "invalid_client")
		return
	}
	if err := metadata.ValidateRequest(*redirectURI, requestedScopes); err != nil {
		rt.oauthError(w, "invalid_client")
		return
	}
	canonicalScope := CanonicalScopes(requestedScopes)

	if rt.Config.AuthDebug {
		rt.authorizeDebug(w, r, *clientID, *redirectURI, *resource, canonicalScope, *state, *challenge,
			requestedScopes, metadata)
		return
	}

	// PRODUCTION. `principal = call.userSession()?.principal` — may be nil, and that is the branch.
	principal, err := rt.principal(r)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	pending, err := NewPendingAuthorization(*clientID, *redirectURI, *resource, canonicalScope, *state, *challenge, principal)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if err := rt.Cookies.Set(w, PendingCookieSpec, pending); err != nil {
		rt.fail(w, r, err)
		return
	}
	if pending.Principal == nil {
		// 🔒 INV-A11-20, verbatim from OAuthRoutes.kt:200-201: "One origin and one signed session: use
		// the existing control-plane OIDC login, then return to /oauth/resume. No service call or
		// service credential exists between them."
		redirect(w, "/auth/oidc/login?return_to="+encodeURLParameter("/oauth/resume"))
		return
	}
	rt.continueAuthorization(w, r, pending)
}

// authorizeDebug is OAuthRoutes.kt:153-192, the `config.authDebug` branch.
//
// ⚠️ 🔒 INV-A11-19 — THE DEBUG MINT INHERITS `debugRequesterIp` ONLY WHEN THE PRINCIPAL IS UNCHANGED.
// Quoted from OAuthRoutes.kt:159-167:
//
//	"Debug OAuth and the web console intentionally share the same authenticated session, matching the
//	 production co-hosted flow without a second identity boundary. Sharing the session means REPLACING
//	 it: mintWeb is newest-wins, so this ends the console's current session. Carry that session's
//	 simulated source address onto the new row, or an MCP authorization in the same browser would
//	 silently drop it and every later console decision would fall back to the observed peer — the
//	 console's authorization context changing as a side effect of an unrelated login. Only when the
//	 principal is unchanged: an explicit ?principal= switches identity, and one identity's simulated
//	 network must not follow another's."
//
// Both branches are pinned by `OAuthRoutesDbTest` case 10 and by
// TestDebugAuthorizeCarriesTheSimulatedSourceAddressAcrossItsSessionRemint.
//
// ORDER IS OBSERVABLE and is reproduced exactly: the pending cookie is written BEFORE the session is
// reminted, and the inherited address is read from the OLD session after that write.
func (rt *Routes) authorizeDebug(
	w http.ResponseWriter, r *http.Request,
	clientID, redirectURI, resource, canonicalScope, state, challenge string,
	requestedScopes []string, metadata *CimdClientMetadata,
) {
	// `params["principal"]?.takeIf(String::isNotBlank) ?: call.userSession()?.principal ?: "debug-user"`
	principal := ""
	if p := queryParam(r, "principal"); p != nil && !isBlankKotlin(*p) {
		principal = *p
	} else {
		session, err := rt.principal(r)
		if err != nil {
			rt.fail(w, r, err)
			return
		}
		if session != nil {
			principal = *session
		} else {
			principal = "debug-user"
		}
	}

	pending, err := NewPendingAuthorization(clientID, redirectURI, resource, canonicalScope, state, challenge, &principal)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if err := rt.Cookies.Set(w, PendingCookieSpec, pending); err != nil {
		rt.fail(w, r, err)
		return
	}

	// INV-A11-19. `call.webSession()?.takeIf { it.principal == principal }?.debugRequesterIp`.
	var inheritedRequesterIP *string
	row, err := rt.Sessions.WebSession(r)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if row != nil && row.Principal == principal {
		inheritedRequesterIP = row.DebugRequesterIP
	}

	// `config.mcpIssuer.startsWith("https://")` — the same derivation all six cookies use.
	deviceID, err := rt.WebSessions.EnsureDeviceCookie(w, r, strings.HasPrefix(rt.Config.MCPIssuer(), "https://"))
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	sessionID, err := rt.WebSessions.MintWeb(r.Context(), principal, nil,
		rt.Config.WebSessionAbsoluteSeconds, rt.Config.WebSessionIdleSeconds, deviceID, inheritedRequesterIP)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if err := rt.WebSessions.SetSessionCookie(w, r, sessionID); err != nil {
		rt.fail(w, r, err)
		return
	}

	if rt.Config.MCPDebugAutoConsent || equalsStr(queryParam(r, "auto_consent"), "true") {
		consent, err := rt.Store.FindActiveConsent(r.Context(), principal, clientID, resource, requestedScopes)
		if err != nil {
			rt.fail(w, r, err)
			return
		}
		if consent == nil {
			consent, err = rt.Store.RememberConsent(r.Context(), principal, clientID, resource, requestedScopes)
			if err != nil {
				rt.fail(w, r, err)
				return
			}
		}
		rt.issueAuthorizationCode(w, r, pending, consent.ID)
		return
	}
	rt.renderConsent(w, r, pending, metadata.ClientName, metadata.ClientID)
}

// ---------------------------------------------------------------------------------------------
// GET /oauth/resume — OAuthRoutes.kt:208-235
// ---------------------------------------------------------------------------------------------

// resume is the post-OIDC-login continuation.
//
// 🔒 INV-A11-21 — CSRF IS ROTATED AT EVERY AUTHENTICATION STEP, AND THE CLIENT IS RE-VALIDATED BEFORE
// ANY REDIRECT BACK TO IT. Two separate properties, both here:
//
//   - on the ERROR path the pending cookie's client is re-resolved and re-validated BEFORE the error
//     is bounced to `redirect_uri`, so a stale or hostile pending cookie cannot be used to bounce an
//     error to an unregistered destination;
//   - on the SUCCESS path the cookie is REWRITTEN with a fresh `csrf`, so the token the consent form
//     will carry was minted after authentication, not before it.
//
// 🔒 Only `access_denied` and `server_error` are relayed. Any other upstream `error` value is
// `400 invalid_request` and never reaches the client — the AS does not forward an arbitrary
// attacker-chosen error code into a redirect it signs off on.
//
// 🔒 `pending.principal != null && pending.principal != principal` — if the pending request was
// started by an authenticated user, only THAT user may resume it. Reproduced exactly, including that
// a pending request with NO principal may be resumed by whoever is now signed in, which is the
// ordinary "logged out, logged back in" case.
func (rt *Routes) resume(w http.ResponseWriter, r *http.Request) {
	pending := rt.readPending(r)
	upstreamError := queryParam(r, "error")

	if upstreamError != nil {
		if pending == nil || (*upstreamError != "access_denied" && *upstreamError != "server_error") {
			rt.oauthError(w, "invalid_request")
			return
		}
		scopes := splitScopesNotBlank(pending.Scope)
		validClient := false
		if metadata, err := rt.Resolver.Resolve(r.Context(), pending.ClientID); err == nil {
			validClient = metadata.ValidateRequest(pending.RedirectURI, scopes) == nil
		}
		if !validClient {
			rt.oauthError(w, "invalid_client")
			return
		}
		rt.Cookies.Clear(w, PendingCookieSpec)
		redirect(w, oauthRedirect(pending.RedirectURI,
			[2]string{"error", *upstreamError}, [2]string{"state", pending.State}))
		return
	}

	principal, err := rt.principal(r)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if pending == nil || principal == nil ||
		(pending.Principal != nil && *pending.Principal != *principal) {
		rt.oauthError(w, "invalid_request")
		return
	}

	// `pending.copy(principal = principal, csrf = randomSecret("csrf_", 18))` — INV-A11-21's rotation.
	authenticated := *pending
	authenticated.Principal = principal
	csrf, err := RandomSecret("csrf_", 18)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	authenticated.CSRF = csrf
	if err := rt.Cookies.Set(w, PendingCookieSpec, authenticated); err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.continueAuthorization(w, r, authenticated)
}

// ---------------------------------------------------------------------------------------------
// POST /oauth/consent — OAuthRoutes.kt:237-251
// ---------------------------------------------------------------------------------------------

// consent is the consent-form post.
//
// 🔒 FOUR conditions, all required: a pending cookie, a principal ON it, a LIVE SESSION for the same
// principal, and `form["csrf"] == pending.csrf`. The session check is what stops a signed-out
// browser (or a different user in the same browser) from completing someone else's authorization; the
// CSRF check is what stops a cross-site form post from doing it silently.
//
// ⚠️ The CSRF comparison here is a plain `!=`, NOT constant-time — unlike
// [Routes.deleteConsent]'s, which uses MessageDigest.isEqual. Both values are secrets, so the
// asymmetry is a real inconsistency in the Kotlin. REPRODUCE: tightening it is a security improvement
// and therefore its own change, and the token is single-use and lives 10 minutes behind a MAC'd
// cookie, so the exposure is a timing side channel on a value the attacker would also have to make
// the victim's browser submit.
//
// ⚠️ `pending.scope.split(' ')` — WITHOUT the blank filter every other split on this surface applies.
// Harmless (CanonicalScopes drops the empties), and reproduced rather than tidied.
func (rt *Routes) consent(w http.ResponseWriter, r *http.Request) {
	pending := rt.readPending(r)
	form := rt.form(r)

	principal, err := rt.principal(r)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if pending == nil || pending.Principal == nil ||
		principal == nil || *principal != *pending.Principal ||
		!equalsStr(formParam(form, "csrf"), pending.CSRF) {
		rt.oauthError(w, "invalid_request")
		return
	}
	if !equalsStr(formParam(form, "decision"), "approve") {
		rt.Cookies.Clear(w, PendingCookieSpec)
		redirect(w, oauthRedirect(pending.RedirectURI,
			[2]string{"error", "access_denied"}, [2]string{"state", pending.State}))
		return
	}
	consent, err := rt.Store.RememberConsent(r.Context(), *pending.Principal, pending.ClientID,
		pending.Resource, strings.Split(pending.Scope, " "))
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.issueAuthorizationCode(w, r, *pending, consent.ID)
}

// ---------------------------------------------------------------------------------------------
// POST /oauth/token — OAuthRoutes.kt:253-281
// ---------------------------------------------------------------------------------------------

// token is the token endpoint, both grants.
//
// 🔒 INV-A11-18 at the grant: `resource != config.mcpResource` produces a NIL PAIR, which then becomes
// `invalid_grant` — deliberately the same answer as a bad code, so the endpoint does not distinguish
// "wrong audience" from "wrong code" for a probing client.
//
// 🔒 INV-A11-22 — every failure is a 400 with an OAuthError body, including `invalid_grant`. Not 401.
//
// Note the ordering inside each grant: a missing REQUIRED form field is `invalid_request` and returns
// immediately, while a present-but-wrong one falls through to `invalid_grant`. An UNKNOWN grant_type
// (including an absent one) is `unsupported_grant_type`.
func (rt *Routes) token(w http.ResponseWriter, r *http.Request) {
	form := rt.form(r)
	var pair *TokenPair

	switch form.Get("grant_type") {
	case "authorization_code":
		code, ok1 := form["code"]
		clientID, ok2 := form["client_id"]
		redirectURI, ok3 := form["redirect_uri"]
		resource, ok4 := form["resource"]
		verifier, ok5 := form["code_verifier"]
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
			rt.oauthError(w, "invalid_request")
			return
		}
		if resource[0] != rt.Config.MCPResource {
			break // null pair ⇒ invalid_grant
		}
		p, err := rt.Store.ConsumeAuthorizationCode(r.Context(), ConsumeAuthorizationCodeInput{
			Code: code[0], ClientID: clientID[0], RedirectURI: redirectURI[0], Resource: resource[0],
			CodeVerifier:     verifier[0],
			AccessTTLSeconds: rt.Config.MCPAccessTTLSeconds, RefreshTTLSeconds: rt.Config.MCPRefreshTTLSeconds,
		})
		if err != nil {
			rt.fail(w, r, err)
			return
		}
		pair = p
	case "refresh_token":
		refresh, ok1 := form["refresh_token"]
		clientID, ok2 := form["client_id"]
		resource, ok3 := form["resource"]
		if !ok1 || !ok2 || !ok3 {
			rt.oauthError(w, "invalid_request")
			return
		}
		if resource[0] != rt.Config.MCPResource {
			break
		}
		p, err := rt.Store.RotateRefresh(r.Context(), RefreshTokenInput{
			RefreshToken: refresh[0], ClientID: clientID[0], Resource: resource[0],
			AccessTTLSeconds: rt.Config.MCPAccessTTLSeconds, RefreshTTLSeconds: rt.Config.MCPRefreshTTLSeconds,
		})
		if err != nil {
			rt.fail(w, r, err)
			return
		}
		pair = p
	default:
		rt.oauthError(w, "unsupported_grant_type")
		return
	}

	if pair == nil {
		rt.oauthError(w, "invalid_grant")
		return
	}
	rt.respondJSON(w, r, http.StatusOK, TokenResponse{
		AccessToken:  pair.AccessToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
		RefreshToken: pair.RefreshToken,
		Scope:        pair.Scope,
	})
}

// ---------------------------------------------------------------------------------------------
// POST /oauth/revoke — OAuthRoutes.kt:283-287
// ---------------------------------------------------------------------------------------------

// revoke is RFC 7009's revocation endpoint.
//
// 🔒 INV-A14-23 — ALWAYS 200 `{}`, even for an unknown token, an absent `token` parameter or a token
// of a kind this endpoint refuses to touch. RFC 7009 requires it: revocation must not become an
// existence oracle.
//
// 🔒 THE ENDPOINT IS UNAUTHENTICATED. That is safe only because of INV-A14-22's kind filter in
// [AuthorizationStore.Revoke] — the caller must already hold the plaintext token, and even then only
// MCP kinds can be destroyed through this surface.
func (rt *Routes) revoke(w http.ResponseWriter, r *http.Request) {
	form := rt.form(r)
	if token := formParam(form, "token"); token != nil {
		if err := rt.Store.Revoke(r.Context(), *token); err != nil {
			rt.fail(w, r, err)
			return
		}
	}
	// `call.respond(HttpStatusCode.OK, emptyMap<String, String>())` — literally `{}`.
	rt.respondJSON(w, r, http.StatusOK, map[string]string{})
}

// ---------------------------------------------------------------------------------------------
// Consent management — OAuthRoutes.kt:289-307
// ---------------------------------------------------------------------------------------------

// listConsents is `GET /oauth/consents`: the principal's live consents plus a CSRF token to spend on
// the DELETE.
func (rt *Routes) listConsents(w http.ResponseWriter, r *http.Request) {
	principal, err := rt.principal(r)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if principal == nil {
		rt.respondOAuth(w, http.StatusUnauthorized, "login_required")
		return
	}
	consents, err := rt.Store.ListConsents(r.Context(), *principal)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respondJSON(w, r, http.StatusOK, ConsentListResponse{
		Consents:  consents,
		CSRFToken: consentCSRF(rt.Config.SessionSecret, *principal),
	})
}

// deleteConsent is `DELETE /oauth/consents/{id}`.
//
// 🔒 ORDER: session, then CSRF, then the id parse. A malformed id with a WRONG CSRF answers the CSRF
// failure, so the endpoint never reveals that it got as far as parsing.
//
// 🔒 INV-A14-19 does the rest: `revokeConsent(id, principal)` carries `AND principal = $2` in SQL, so
// even a valid CSRF cannot revoke someone else's consent — 404, not 403, because the row simply does
// not exist for this principal.
//
// ⚠️ The 404 body is `invalid_request`, the same code as the 400s. Only the status distinguishes them.
func (rt *Routes) deleteConsent(w http.ResponseWriter, r *http.Request) {
	principal, err := rt.principal(r)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	id := httpapi.IDParam(r)
	if principal == nil {
		rt.respondOAuth(w, http.StatusUnauthorized, "login_required")
		return
	}
	expected := consentCSRF(rt.Config.SessionSecret, *principal)
	supplied, present := headerValue(r, "X-PM-CSRF")
	if !present || !constantTimeEquals(supplied, expected) {
		rt.oauthError(w, "invalid_request")
		return
	}
	if id == nil {
		rt.oauthError(w, "invalid_request")
		return
	}
	revoked, err := rt.Store.RevokeConsent(r.Context(), *id, *principal)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if !revoked {
		rt.respondOAuth(w, http.StatusNotFound, "invalid_request")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// consentCSRF is `private fun consentCsrf(sessionSecret, principal)` (OAuthRoutes.kt:402-407).
//
// 🔒 INV-A11-23 — THE CONSENT CSRF TOKEN IS A KEYED HMAC, NOT RANDOM STATE:
// `base64url_nopad(HMAC-SHA256(sessionSecret, "mcp-oauth-consent\u0000" + principal))`. Stateless and
// per-principal, so it needs no server-side storage but cannot be replayed across principals.
//
// ⚠️ Note this one uses a REAL NUL byte as the separator — contrast A11 §4's idempotency key, which
// joins with the six-character SOURCE literal `\u0000`. Getting it wrong here does not fail loudly: it
// produces a different-but-stable token, so the console keeps working and only a cutover mid-flight
// (or a mixed Kotlin/Go fleet) sees rejections.
//
// The key is `sessionSecret.toByteArray()`, the RAW UTF-8 bytes — not a derived key — exactly as
// [session.NewCookieCodec] uses them.
func consentCSRF(sessionSecret, principal string) string {
	mac := hmac.New(sha256.New, []byte(sessionSecret))
	mac.Write([]byte("mcp-oauth-consent\x00" + principal))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// constantTimeEquals is `MessageDigest.isEqual(supplied.toByteArray(), expected.toByteArray())`
// (OAuthRoutes.kt:301).
//
// 🔒 It compares SHA-256 DIGESTS rather than the raw bytes, for the reason httpapi's identical helper
// records: Java's MessageDigest.isEqual folds a length difference into its accumulator, whereas
// crypto/subtle.ConstantTimeCompare RETURNS 0 IMMEDIATELY on a length mismatch — a length oracle the
// Kotlin does not have. Hashing both sides to a fixed 32 bytes removes the oracle and keeps the
// comparison constant-time via hmac.Equal.
//
// A local copy rather than a call into httpapi because that one is unexported; 09-policies.md's
// disposition of the Kotlin's three JDBC-helper copies applies — duplication is not grounds for a
// refactor mid-port.
func constantTimeEquals(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return hmac.Equal(ha[:], hb[:])
}

// ---------------------------------------------------------------------------------------------
// The two shared continuations — OAuthRoutes.kt:310-348
// ---------------------------------------------------------------------------------------------

// continueAuthorization is `private suspend fun continueAuthorization(...)` (OAuthRoutes.kt:310-323):
// re-resolve the client, re-validate the request, then either issue a code against a standing consent
// or render the consent page.
//
// ⚠️ NEITHER the resolve NOR the validate is wrapped in runCatching here, unlike in the authorize
// route — so a client whose metadata document became unreachable BETWEEN the authorize call and the
// resume produces a 500 `server_error`, not `400 invalid_client`. Reproduced: the difference is
// observable and the inconsistency is the Kotlin's.
func (rt *Routes) continueAuthorization(w http.ResponseWriter, r *http.Request, pending PendingAuthorization) {
	if pending.Principal == nil {
		// `requireNotNull(pending.principal)` — unreachable from either caller, and an exception if it
		// ever were.
		rt.fail(w, r, errNoPendingPrincipal)
		return
	}
	scopes := splitScopesNotBlank(pending.Scope)
	metadata, err := rt.Resolver.Resolve(r.Context(), pending.ClientID)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if err := metadata.ValidateRequest(pending.RedirectURI, scopes); err != nil {
		rt.fail(w, r, err)
		return
	}
	consent, err := rt.Store.FindActiveConsent(r.Context(), *pending.Principal, pending.ClientID, pending.Resource, scopes)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if consent != nil {
		rt.issueAuthorizationCode(w, r, pending, consent.ID)
		return
	}
	rt.renderConsent(w, r, pending, metadata.ClientName, metadata.ClientID)
}

// issueAuthorizationCode is `private suspend fun issueAuthorizationCode(...)` (OAuthRoutes.kt:325-348).
//
// ⚠️ TWO REPRODUCED ODDITIES, neither tidied:
//
//  1. `pending.scope.split(' ').toSet()` — WITHOUT the blank filter [Routes.continueAuthorization]
//     applies three lines earlier. Harmless because CanonicalScopes drops empties before the string
//     reaches the database, but the two call sites genuinely disagree.
//  2. The CIMD document is resolved AGAIN, a second network fetch for a value the caller already
//     holds — on the auto-consent path that is the THIRD resolve of one authorize request.
//     Inefficiency, which the port policy makes REPRODUCE, not OMIT.
//
// ⚠️ F30 — `createAuthorizationCode` THROWS on a consent that is absent, revoked or mismatched, and
// nothing here catches it, so a consent revoked between the find and the create surfaces as a 500
// rather than an OAuth error. [Routes.fail] is that 500.
func (rt *Routes) issueAuthorizationCode(w http.ResponseWriter, r *http.Request, pending PendingAuthorization, consentID int64) {
	if pending.Principal == nil {
		rt.fail(w, r, errNoPendingPrincipal)
		return
	}
	scopes := dedupe(strings.Split(pending.Scope, " "))
	metadata, err := rt.Resolver.Resolve(r.Context(), pending.ClientID)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if err := metadata.ValidateRequest(pending.RedirectURI, scopes); err != nil {
		rt.fail(w, r, err)
		return
	}
	code, err := rt.Store.CreateAuthorizationCode(r.Context(), AuthorizationCodeInput{
		ClientID:      pending.ClientID,
		Principal:     *pending.Principal,
		RedirectURI:   pending.RedirectURI,
		Resource:      pending.Resource,
		Scopes:        scopes,
		CodeChallenge: pending.CodeChallenge,
		ConsentID:     consentID,
	})
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.Cookies.Clear(w, PendingCookieSpec)
	redirect(w, oauthRedirect(pending.RedirectURI,
		[2]string{"code", code}, [2]string{"state", pending.State}))
}

// errNoPendingPrincipal stands in for `requireNotNull(pending.principal)`.
var errNoPendingPrincipal = &pendingPrincipalError{}

type pendingPrincipalError struct{}

func (*pendingPrincipalError) Error() string { return "pending authorization has no principal" }

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

// principal is `call.userSession()?.principal`.
func (rt *Routes) principal(r *http.Request) (*string, error) {
	if rt.Sessions == nil {
		return nil, nil
	}
	user, err := rt.Sessions.UserSession(r)
	if err != nil || user == nil {
		return nil, err
	}
	return &user.Principal, nil
}

// readPending is `call.sessions.get<McpPendingAuthorization>()`: EVERY failure — no cookie, a bad
// MAC, a stale payload shape — is nil, exactly as Ktor's accessor is. Distinguishing them would tell
// a forger which half of the attempt was wrong.
func (rt *Routes) readPending(r *http.Request) *PendingAuthorization {
	var pending PendingAuthorization
	if err := rt.Cookies.Read(r, PendingCookieSpec, &pending); err != nil {
		return nil
	}
	return &pending
}

// form is `call.receiveParameters()` — the BODY parameters only.
//
// ⚠️ r.PostForm, never r.Form: ParseForm merges the URL query into r.Form for a POST, and Ktor's
// receiveParameters does not. A token endpoint that accepted `?code=` from the query string would let
// a code leak into an access log that the body would have kept out of it.
//
// A body that is not form-encoded yields an empty set rather than Ktor's 415. Divergence recorded: no
// route here distinguishes "no parameters" from "wrong media type", so every such request lands on
// the same `invalid_request` / `unsupported_grant_type` answer it would otherwise reach.
func (rt *Routes) form(r *http.Request) url.Values {
	if err := r.ParseForm(); err != nil {
		rt.logger().Debug("OAuth form body could not be parsed", "path", r.URL.Path, "err", err)
	}
	if r.PostForm == nil {
		return url.Values{}
	}
	return r.PostForm
}

// queryParam distinguishes ABSENT (nil) from PRESENT-BUT-EMPTY (""), which Ktor's
// `queryParameters["x"]` does and `Values.Get` does not.
func queryParam(r *http.Request, name string) *string {
	q := r.URL.Query()
	if !q.Has(name) {
		return nil
	}
	v := q.Get(name)
	return &v
}

// formParam is [queryParam] over a parsed body.
func formParam(form url.Values, name string) *string {
	if !form.Has(name) {
		return nil
	}
	v := form.Get(name)
	return &v
}

// headerValue distinguishes an absent header from a present-but-empty one, which
// `request.headers["X"] == null` does.
func headerValue(r *http.Request, name string) (string, bool) {
	values, ok := r.Header[http.CanonicalHeaderKey(name)]
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// equalsStr is Kotlin's `nullable == "literal"`: an absent parameter never matches.
func equalsStr(v *string, want string) bool { return v != nil && *v == want }

// notNullOrBlank is Kotlin's `!x.isNullOrBlank()`.
func notNullOrBlank(v *string) bool { return v != nil && !isBlankKotlin(*v) }

// requestedScopeSet is `scope?.split(' ')?.filter(String::isNotBlank)?.toSet().orEmpty()`
// (OAuthRoutes.kt:137) — split on the single space, drop blanks, DEDUPE while preserving first-seen
// order (Kotlin's `toSet()` is a LinkedHashSet).
func requestedScopeSet(scope *string) []string {
	if scope == nil {
		return nil
	}
	return dedupe(splitScopesNotBlank(*scope))
}

// dedupe is `toSet()`: first-seen order, no sort.
func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// allIn is `requestedScopes.all { it in MCPA_SCOPES }`.
func allIn(values, allowed []string) bool {
	for _, v := range values {
		if !contains(allowed, v) {
			return false
		}
	}
	return true
}

// oauthRedirect is `private fun oauthRedirect(uri, values)` (OAuthRoutes.kt:394-398).
//
// ⚠️ The separator test is `'?' in uri` over the WHOLE string, so a `?` anywhere — including inside a
// fragment or a path segment — makes it append `&`. Reproduced.
//
// The pairs are an ordered slice, not a map, because Kotlin's `mapOf(...)` is a LinkedHashMap and the
// query-parameter ORDER is wire-visible: every caller passes `code`/`error` first and `state` second.
func oauthRedirect(uri string, values ...[2]string) string {
	var b strings.Builder
	b.WriteString(uri)
	if strings.ContainsRune(uri, '?') {
		b.WriteByte('&')
	} else {
		b.WriteByte('?')
	}
	for i, kv := range values {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(encodeURLParameter(kv[0]))
		b.WriteByte('=')
		b.WriteString(encodeURLParameter(kv[1]))
	}
	return b.String()
}

// redirect is `call.respondRedirect(url)` — a 302 with a Location header and NO body.
//
// http.Redirect is deliberately not used: it writes an HTML body for a GET, which Ktor does not, and
// these responses are asserted header-only.
func redirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// encodeURLParameter is Ktor's `String.encodeURLParameter()` — percent-encoding everything outside
// RFC 3986's unreserved set, uppercase hex, one UTF-8 byte at a time.
//
// ⚠️ url.QueryEscape is NOT a substitute: it encodes a space as `+` where Ktor's default emits `%20`.
// A verbatim copy of internal/oidc's identical unexported helper; see 09-policies.md on why a
// mid-port refactor to share it is not taken.
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
