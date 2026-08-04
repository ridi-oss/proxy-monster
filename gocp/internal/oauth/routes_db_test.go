package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// OAuthRoutesDbTest.kt — the eight route cases (3 and 4 are pure CIMD and live in cimd_test.go),
// plus the route-level invariants A11 §6 names that the Kotlin suite leaves untested.
//
// ORACLE: OAuthRoutesDbTest.kt:71-457 and 11-mcp-oauth-management.md §6.
//
// WHAT IS REAL AND WHAT IS NOT, and why:
//
//   - the STORE and the SESSION STORE are real, over a migrated Postgres. INV-A11-19 is a claim about
//     a COLUMN on `principal_session` (`debug_requester_ip`) surviving a newest-wins remint, so a
//     faked session store could not state it at all; and every consent/code/token assertion is
//     downstream of a SQL predicate.
//   - the CIMD RESOLVER is a fake, exactly as `OAuthRoutesDbTest.resolver()` (`:459-462`) is. The real
//     one makes an outbound HTTPS request; its own defences are pinned in cimd_test.go against a live
//     TLS server. What the route suite needs from it is "this client is known" / "this client is not".
// ---------------------------------------------------------------------------------------------

const (
	routeOrigin      = "http://control-plane.local"
	routeResource    = routeOrigin + "/mcp"
	routeClientID    = "https://client.example/client.json"
	routeRedirectURI = "http://127.0.0.1:43110/callback"
)

var (
	routeVerifier  = strings.Repeat("v", 43)
	routeChallenge = PKCES256(routeVerifier)
)

// routeConfig is `OAuthRoutesDbTest.config()` (`:471-488`) — authDebug ON, auto-consent ON.
func routeConfig() config.Config {
	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = true
	cfg.SecretToken = nil
	cfg.SessionSecret = "control-plane-oauth-test-secret-32-bytes"
	cfg.OIDC = nil
	cfg.ResultKey = nil
	cfg.ScimToken = nil
	cfg.TrustedProxies = map[string]struct{}{}
	cfg.MCPResource = routeResource
	cfg.MCPAccessTTLSeconds = 600
	cfg.MCPRefreshTTLSeconds = 3_600
	cfg.MCPDebugAutoConsent = true
	return cfg
}

// routeWebSessions is the [WebSessions] adapter internal/app owes this package — three lines each,
// exactly as internal/oidc's seams.go describes its own. Written here so the suite exercises the
// SEAM and not a stub: MintWeb goes to the real store, and SetSessionCookie does BOTH halves.
type routeWebSessions struct {
	store    *session.Store
	sessions *httpapi.Sessions
}

func (a *routeWebSessions) MintWeb(
	ctx context.Context, principal string, refreshToken *string,
	absoluteSeconds, idleSeconds int64, deviceID string, debugRequesterIP *string,
) (int64, error) {
	return a.store.MintWeb(ctx, nil, session.MintWebInput{
		Principal:        principal,
		RefreshToken:     refreshToken,
		AbsoluteSeconds:  absoluteSeconds,
		IdleSeconds:      idleSeconds,
		DeviceID:         &deviceID,
		DebugRequesterIP: debugRequesterIP,
	})
}

func (a *routeWebSessions) SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID int64) error {
	return a.sessions.SetWebSession(r.Context(), w, sessionID)
}

func (a *routeWebSessions) EnsureDeviceCookie(w http.ResponseWriter, r *http.Request, secure bool) (string, error) {
	return session.EnsureDeviceCookie(w, r, secure)
}

type routeFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *store.Db
	cfg      config.Config
	handler  http.Handler
	store    *AuthorizationStore
	sessions *session.Store
	web      *routeWebSessions
	// jar is the browser: every request carries it and every Set-Cookie updates it, which is what
	// makes the pending cookie and the session cookie behave as they do in a real flow.
	jar map[string]string
	// resolveErr, when non-nil, makes the fake CIMD resolver fail — the "client metadata became
	// unreachable" arm.
	resolveErr error
	// metadata is what the fake resolver returns.
	metadata *CimdClientMetadata
	// resolves counts CIMD resolutions, so the double- and triple-resolve the Kotlin does can be
	// asserted rather than assumed.
	resolves int
}

func newRouteFixture(t *testing.T, mutate ...func(*config.Config)) *routeFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	cfg := routeConfig()
	for _, m := range mutate {
		m(&cfg)
	}

	sessionStore := session.NewStore(db.Pool, session.Options{
		WebSessionIdleSeconds:  cfg.WebSessionIdleSeconds,
		WebSessionSlideSeconds: cfg.WebSessionSlideSeconds,
	})
	sessions := &httpapi.Sessions{
		Codec:           session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		Storage:         httpapi.StoreSessionStorage{Store: sessionStore},
		Resolver:        sessionStore,
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
	}

	f := &routeFixture{
		t: t, ctx: t.Context(), db: db, cfg: cfg,
		store:    NewAuthorizationStore(db.Pool),
		sessions: sessionStore,
		jar:      map[string]string{},
		metadata: &CimdClientMetadata{
			ClientID:                routeClientID,
			ClientName:              "Test MCP Client",
			RedirectURIs:            []string{routeRedirectURI},
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		},
	}
	f.web = &routeWebSessions{store: sessionStore, sessions: sessions}

	routes := NewRoutes(cfg, f.store, sessions.Codec, sessions, f.web,
		CimdResolverFunc(func(_ context.Context, clientID string) (*CimdClientMetadata, error) {
			f.resolves++
			if f.resolveErr != nil {
				return nil, f.resolveErr
			}
			if clientID != routeClientID {
				return nil, errUnknownTestClient
			}
			return f.metadata, nil
		}), nil)
	// 🔒 On in the suite, off in production — internal/mcp owns these two paths. See the field.
	routes.MountProtectedResourceMetadata = true

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(routes)
	// `POST /test/login/{principal}` is OAuthRoutesDbTest's own helper (`:516-530`): it establishes
	// exactly the shared UserSession a successful OIDC callback sets.
	router.Mux().HandleFunc("POST /test/login/{principal}", f.testLogin)
	f.handler = router.Handler()
	return f
}

var errUnknownTestClient = &pendingPrincipalError{} // any non-nil error; the routes never read it

// testLogin is the Kotlin helper route. `requesterIp` is optional so existing callers are unchanged;
// the INV-A11-19 case needs a session that ALREADY carries a simulated address before OAuth remints.
func (f *routeFixture) testLogin(w http.ResponseWriter, r *http.Request) {
	principal := r.PathValue("principal")
	deviceID, err := session.EnsureDeviceCookie(w, r, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var requesterIP *string
	if v := r.URL.Query().Get("requesterIp"); v != "" {
		requesterIP = &v
	}
	id, err := f.web.MintWeb(r.Context(), principal, nil,
		f.cfg.WebSessionAbsoluteSeconds, f.cfg.WebSessionIdleSeconds, deviceID, requesterIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := f.web.SetSessionCookie(w, r, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// do issues a request through the browser jar. `followRedirects = false` in every Kotlin case, so
// nothing here follows one either.
func (f *routeFixture) do(method, target string, body url.Values) *httptest.ResponseRecorder {
	f.t.Helper()
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for name, value := range f.jar {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(f.jar, ck.Name)
			continue
		}
		f.jar[ck.Name] = ck.Value
	}
	return rec
}

func (f *routeFixture) get(target string) *httptest.ResponseRecorder {
	return f.do(http.MethodGet, target, nil)
}

// authorizeURL builds a well-formed authorize request; overrides replace or delete parameters.
func authorizeURL(overrides map[string]string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {routeClientID},
		"redirect_uri":          {routeRedirectURI},
		"scope":                 {"mcp:read mcp:policies:write"},
		"state":                 {"state-1"},
		"resource":              {routeResource},
		"code_challenge":        {routeChallenge},
		"code_challenge_method": {"S256"},
	}
	for k, v := range overrides {
		if v == "" {
			q.Del(k)
			continue
		}
		q.Set(k, v)
	}
	return "/oauth/authorize?" + q.Encode()
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

func locationOf(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	raw := rec.Header().Get("Location")
	if raw == "" {
		t.Fatalf("no Location header on a %d", rec.Code)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse Location %q: %v", raw, err)
	}
	return u
}

// ---- Case 1 -------------------------------------------------------------------------------------

// `debug authorization code PKCE refresh and discovery work end to end` (`:71-147`) — the whole happy
// path in one case, exactly as the Kotlin has it.
// KT: OAuthRoutesDbTest.kt#debug authorization code PKCE refresh and discovery work end to end
func TestDebugAuthorizationCodePKCERefreshAndDiscoveryWorkEndToEnd(t *testing.T) {
	f := newRouteFixture(t)

	discovery := f.get("/.well-known/oauth-authorization-server")
	if discovery.Code != http.StatusOK {
		t.Fatalf("discovery = %d", discovery.Code)
	}
	metadata := decodeJSON(t, discovery)
	if metadata["issuer"] != routeOrigin {
		t.Errorf("issuer = %v, want %q", metadata["issuer"], routeOrigin)
	}
	if metadata["client_id_metadata_document_supported"] != true {
		t.Errorf("client_id_metadata_document_supported = %v", metadata["client_id_metadata_document_supported"])
	}
	if _, present := metadata["registration_endpoint"]; present {
		t.Error("there is no registration endpoint — CIMD replaces it")
	}

	authorization := f.get(authorizeURL(map[string]string{"principal": "mcp-debug@example.com"}))
	if authorization.Code != http.StatusFound {
		t.Fatalf("authorize = %d, body %s", authorization.Code, authorization.Body)
	}
	// 🔒 The protocol guard: an authorization redirect carrying a code must never be cached.
	if cc := authorization.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	redirect := locationOf(t, authorization)
	if got := redirect.Query().Get("state"); got != "state-1" {
		t.Errorf("state = %q", got)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatal("no code on the redirect")
	}

	token := f.do(http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {routeClientID},
		"redirect_uri":  {routeRedirectURI},
		"resource":      {routeResource},
		"code_verifier": {routeVerifier},
	})
	if token.Code != http.StatusOK {
		t.Fatalf("token = %d, body %s", token.Code, token.Body)
	}
	first := decodeJSON(t, token)
	if first["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", first["token_type"])
	}
	if first["expires_in"] != float64(600) {
		t.Errorf("expires_in = %v, want 600", first["expires_in"])
	}
	if first["scope"] != "mcp:policies:write mcp:read" {
		t.Errorf("scope = %v, want the canonical form", first["scope"])
	}
	refresh, _ := first["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("no refresh_token")
	}

	rotated := f.do(http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {routeClientID},
		"resource":      {routeResource},
	})
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate = %d, body %s", rotated.Code, rotated.Body)
	}
	if decodeJSON(t, rotated)["refresh_token"] == refresh {
		t.Error("a rotation must mint a new refresh token")
	}

	replay := f.do(http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {routeClientID},
		"resource":      {routeResource},
	})
	// 🔒 INV-A11-22 — 400 with an OAuthError body, NOT 401.
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay = %d, want 400", replay.Code)
	}
	if got := decodeJSON(t, replay)["error"]; got != "invalid_grant" {
		t.Errorf("replay error = %v, want invalid_grant", got)
	}

	// The debug OAuth login and the console share ONE authenticated session, so the consent-management
	// route is reachable straight afterwards with no second login.
	if consents := f.get("/oauth/consents"); consents.Code != http.StatusOK {
		t.Errorf("/oauth/consents = %d, want 200 — the sessions are shared", consents.Code)
	}
}

// ---- Case 2 -------------------------------------------------------------------------------------

// `control-plane application mounts both OAuth AS and MCP resource discovery on one origin`
// (`:149-163`).
//
// 🔒 INV-A11-20 — the authorization server and the protected resource are ONE ORIGIN by construction:
// both documents derive from `config.mcpIssuer`, which is the origin of PM_MCP_RESOURCE.
//
// ⚠️ The Kotlin case reaches both documents through the REAL application (`module(config(), …)`), so it
// also states that the control-plane app MOUNTS both. That half cannot be stated from this file: the
// production owner of `/.well-known/oauth-protected-resource[/mcp]` is internal/mcp (see
// [Routes.MountProtectedResourceMetadata] and internal/app/http.go's 🔴 note), and this is an
// in-package test file, so importing internal/app here would be an import cycle. It is pinned by
// internal/app/routetable_db_test.go, which asserts both paths AND
// `/.well-known/oauth-authorization-server` are registered on the assembled app.
//
// What this test owns is the ONE-ORIGIN half, and it asserts it BY CONSTRUCTION rather than against a
// literal: the second fixture below moves PM_MCP_RESOURCE to a different origin (and a port), and both
// documents have to follow. Against the fixed `routeOrigin` alone, a hardcoded issuer in either
// document would pass.
// KT: OAuthRoutesDbTest.kt#control-plane application mounts both OAuth AS and MCP resource discovery on one origin
func TestBothDiscoveryDocumentsAgreeOnOneOrigin(t *testing.T) {
	f := newRouteFixture(t)

	oauthMetadata := decodeJSON(t, f.get("/.well-known/oauth-authorization-server"))
	resourceMetadata := decodeJSON(t, f.get("/.well-known/oauth-protected-resource/mcp"))

	if oauthMetadata["issuer"] != routeOrigin {
		t.Errorf("issuer = %v, want %q", oauthMetadata["issuer"], routeOrigin)
	}
	servers, _ := resourceMetadata["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != routeOrigin {
		t.Fatalf("authorization_servers = %v, want [%q]", servers, routeOrigin)
	}
	if resourceMetadata["resource"] != routeResource {
		t.Errorf("resource = %v, want %q", resourceMetadata["resource"], routeResource)
	}
	// The bare path answers the same document.
	if bare := decodeJSON(t, f.get("/.well-known/oauth-protected-resource")); bare["resource"] != routeResource {
		t.Errorf("the bare path must answer the same document, got %v", bare)
	}
	// ⚠️ The discovery documents carry NO cache directives — the guard is `/oauth/` only, and a
	// discovery document is meant to be cacheable.
	if cc := f.get("/.well-known/oauth-authorization-server").Header().Get("Cache-Control"); cc != "" {
		t.Errorf("the discovery document must not be no-store, got %q", cc)
	}

	// 🔒 ONE ORIGIN BY CONSTRUCTION. Move PM_MCP_RESOURCE and BOTH documents must move with it — an
	// issuer (or an authorization_servers entry) that were spelled out anywhere would be caught here and
	// nowhere above.
	const movedResource = "https://moved.example:8443/mcp"
	const movedOrigin = "https://moved.example:8443"
	moved := newRouteFixture(t, func(c *config.Config) { c.MCPResource = movedResource })
	movedAS := decodeJSON(t, moved.get("/.well-known/oauth-authorization-server"))
	movedPRM := decodeJSON(t, moved.get("/.well-known/oauth-protected-resource/mcp"))
	if movedAS["issuer"] != movedOrigin {
		t.Errorf("issuer = %v, want %q — the AS document must derive its origin from PM_MCP_RESOURCE",
			movedAS["issuer"], movedOrigin)
	}
	movedServers, _ := movedPRM["authorization_servers"].([]any)
	if len(movedServers) != 1 || movedServers[0] != movedOrigin {
		t.Errorf("authorization_servers = %v, want [%q] — the two documents must stay on ONE origin",
			movedServers, movedOrigin)
	}
	if movedPRM["resource"] != movedResource {
		t.Errorf("resource = %v, want %q", movedPRM["resource"], movedResource)
	}
	// And the two endpoints the AS document advertises live on that same origin, so a client that read
	// only this document never leaves it.
	for _, key := range []string{"authorization_endpoint", "token_endpoint"} {
		endpoint, _ := movedAS[key].(string)
		if !strings.HasPrefix(endpoint, movedOrigin+"/") {
			t.Errorf("%s = %q, want it on %s", key, endpoint, movedOrigin)
		}
	}
}

// The two scope lists must agree, which is what lets MCPCapabilityScopes carry a literal until A11's
// registry lands. `McpCapabilityRegistry.verify()` already requires every capability scope to be an
// MCPA scope, so a divergence here means one of the two lists was edited alone.
func TestTheProtectedResourceScopesAreExactlyTheAuthorizationServerScopes(t *testing.T) {
	as, prm := sortedMCPAScopes(), MCPCapabilityScopes()
	if len(as) != len(prm) {
		t.Fatalf("scopes_supported differ: AS %v, resource %v", as, prm)
	}
	for i := range as {
		if as[i] != prm[i] {
			t.Fatalf("scopes_supported differ at %d: AS %v, resource %v", i, as, prm)
		}
	}
	want := []string{"mcp:datasources:write", "mcp:identity:write", "mcp:policies:write", "mcp:read"}
	for i := range want {
		if as[i] != want[i] {
			t.Fatalf("scopes_supported = %v, want %v", as, want)
		}
	}
}

// ---- Case 5 -------------------------------------------------------------------------------------

// `consent discloses redirect destination and warns for loopback clients` (`:224-243`).
//
// 🔒 INV-A11-24 — both halves. A local listener means any process on the user's machine could receive
// the code, so the destination is shown and the loopback case is called out.
// KT: OAuthRoutesDbTest.kt#consent discloses redirect destination and warns for loopback clients
func TestConsentDisclosesRedirectDestinationAndWarnsForLoopbackClients(t *testing.T) {
	f := newRouteFixture(t, func(c *config.Config) { c.MCPDebugAutoConsent = false })

	response := f.get(authorizeURL(map[string]string{
		"scope":     "mcp:read",
		"state":     "state-consent",
		"principal": "mcp-debug@example.com",
	}))
	if response.Code != http.StatusOK {
		t.Fatalf("authorize = %d, body %s", response.Code, response.Body)
	}
	body := response.Body.String()
	if !strings.Contains(body, routeRedirectURI) {
		t.Errorf("the consent page must disclose the redirect destination:\n%s", body)
	}
	if !strings.Contains(body, "Verify that you started the local client") {
		t.Errorf("the consent page must warn about a loopback redirect:\n%s", body)
	}
	if !strings.Contains(body, "Test MCP Client") {
		t.Errorf("the consent page must name the client:\n%s", body)
	}
	if !strings.Contains(body, routeClientID) {
		t.Errorf("the consent page must show the client id:\n%s", body)
	}

	// 🔒 The three protective headers, and the content type.
	wantHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Content-Type":            "text/html; charset=UTF-8",
		"Cache-Control":           "no-store",
		"Pragma":                  "no-cache",
	}
	for name, want := range wantHeaders {
		if got := response.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// An HTTPS client gets NO loopback warning — the warning must not be decoration that always fires.
func TestConsentOmitsTheLoopbackWarningForAnHTTPSRedirect(t *testing.T) {
	f := newRouteFixture(t, func(c *config.Config) { c.MCPDebugAutoConsent = false })
	const httpsRedirect = "https://client.example/callback"
	f.metadata.RedirectURIs = []string{httpsRedirect}

	response := f.get(authorizeURL(map[string]string{
		"redirect_uri": httpsRedirect,
		"scope":        "mcp:read",
		"principal":    "mcp-debug@example.com",
	}))
	if response.Code != http.StatusOK {
		t.Fatalf("authorize = %d, body %s", response.Code, response.Body)
	}
	body := response.Body.String()
	if strings.Contains(body, "Verify that you started the local client") {
		t.Error("an HTTPS redirect must not raise the loopback warning")
	}
	if !strings.Contains(body, httpsRedirect) {
		t.Error("the destination is disclosed for every client, loopback or not")
	}
}

// The consent page is localized off `Accept-Language`, with a `ko` PREFIX test on the whole header —
// not RFC 7231 negotiation. Both arms, because the prefix rule is the observable part.
func TestConsentPageLocaleIsAKoreanPrefixTestOnTheWholeHeader(t *testing.T) {
	cases := []struct {
		header string
		korean bool
	}{
		{"", false},
		{"en-US", false},
		{"ko", true},
		{"ko-KR", true},
		{"KO-kr", true},
		{"en-US,ko;q=0.9", false}, // ⚠️ NOT negotiated: the header does not START with ko
		{"ko-KR,en;q=0.9", true},
	}
	for _, c := range cases {
		t.Run(c.header, func(t *testing.T) {
			f := newRouteFixture(t, func(cfg *config.Config) { cfg.MCPDebugAutoConsent = false })
			req := httptest.NewRequest(http.MethodGet,
				authorizeURL(map[string]string{"scope": "mcp:read", "principal": "loc@example.com"}), nil)
			if c.header != "" {
				req.Header.Set("Accept-Language", c.header)
			}
			rec := httptest.NewRecorder()
			f.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("authorize = %d, body %s", rec.Code, rec.Body)
			}
			isKorean := strings.Contains(rec.Body.String(), "MCP 클라이언트 승인")
			if isKorean != c.korean {
				t.Errorf("Accept-Language %q gave Korean=%v, want %v", c.header, isKorean, c.korean)
			}
		})
	}
}

// ---- Case 6 -------------------------------------------------------------------------------------

// `production OAuth reuses the existing control-plane user session without another auth boundary`
// (`:245-291`).
//
// 🔒 INV-A11-20 — no service credential between the AS and the resource server, because there is no
// second identity boundary at all: the console's own session is the authorization. Ending that
// session sends the very next authorize back to the OIDC login.
// KT: OAuthRoutesDbTest.kt#production OAuth reuses the existing control-plane user session without another auth boundary
func TestProductionOAuthReusesTheExistingControlPlaneUserSession(t *testing.T) {
	f := newRouteFixture(t, func(c *config.Config) {
		c.AuthDebug = false
		c.MCPDebugAutoConsent = false
	})

	if login := f.do(http.MethodPost, "/test/login/mcp-user@example.com", url.Values{}); login.Code != http.StatusNoContent {
		t.Fatalf("test login = %d", login.Code)
	}

	response := f.get(authorizeURL(map[string]string{"scope": "mcp:read", "state": "state-shared-session"}))
	if response.Code != http.StatusOK {
		t.Fatalf("authorize = %d, body %s", response.Code, response.Body)
	}
	if !strings.Contains(response.Body.String(), "Test MCP Client") {
		t.Error("the signed-in user must land straight on the consent page")
	}

	// End the session out from under the browser, exactly as the Kotlin does.
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE principal_session SET ended_at = now(), ended_reason = 'SIGNED_OUT'
		     WHERE principal = $1 AND kind = 'WEB'`, "mcp-user@example.com"); err != nil {
		t.Fatalf("end the session: %v", err)
	}

	ended := f.get(authorizeURL(map[string]string{"scope": "mcp:read", "state": "state-ended-session"}))
	if ended.Code != http.StatusFound {
		t.Fatalf("authorize after sign-out = %d, want 302", ended.Code)
	}
	if loc := ended.Header().Get("Location"); !strings.Contains(loc, "/auth/oidc/login") {
		t.Errorf("Location = %q, want the OIDC login", loc)
	}
}

// ---- Case 7 -------------------------------------------------------------------------------------

// `production OAuth without a session enters the existing control-plane OIDC login` (`:293-325`).
//
// 🔒 INV-A11-21 — the pending request is ONE-TIME-USE even on the cancellation path, and the client is
// re-validated before the error is bounced back to it.
// KT: OAuthRoutesDbTest.kt#production OAuth without a session enters the existing control-plane OIDC login
func TestProductionOAuthWithoutASessionEntersTheControlPlaneOIDCLogin(t *testing.T) {
	f := newRouteFixture(t, func(c *config.Config) { c.AuthDebug = false })

	response := f.get(authorizeURL(map[string]string{"scope": "mcp:read", "state": "state-shared-oidc"}))
	if response.Code != http.StatusFound {
		t.Fatalf("authorize = %d, want 302", response.Code)
	}
	if got := response.Header().Get("Location"); got != "/auth/oidc/login?return_to=%2Foauth%2Fresume" {
		t.Fatalf("Location = %q", got)
	}

	canceled := f.get("/oauth/resume?error=access_denied")
	if canceled.Code != http.StatusFound {
		t.Fatalf("resume(access_denied) = %d, body %s", canceled.Code, canceled.Body)
	}
	redirect := locationOf(t, canceled)
	base := redirect.Scheme + "://" + redirect.Host + redirect.Path
	if base != routeRedirectURI {
		t.Errorf("the error must go to the registered redirect_uri, got %q", base)
	}
	if got := redirect.Query().Get("error"); got != "access_denied" {
		t.Errorf("error = %q", got)
	}
	if got := redirect.Query().Get("state"); got != "state-shared-oidc" {
		t.Errorf("state = %q", got)
	}

	// The signed pending request is one-time-use even on the cancellation path.
	if again := f.get("/oauth/resume?error=access_denied"); again.Code != http.StatusBadRequest {
		t.Errorf("a second resume = %d, want 400", again.Code)
	}
}

// 🔒 INV-A11-21's other half — only `access_denied` and `server_error` are relayed, and the CLIENT is
// re-validated before the redirect. NEW: the Kotlin case only exercises `access_denied`.
func TestResumeRelaysOnlyTwoUpstreamErrorsAndRevalidatesTheClientFirst(t *testing.T) {
	start := func(f *routeFixture) {
		f.t.Helper()
		if rec := f.get(authorizeURL(map[string]string{"scope": "mcp:read"})); rec.Code != http.StatusFound {
			f.t.Fatalf("authorize = %d", rec.Code)
		}
	}

	t.Run("server_error is relayed", func(t *testing.T) {
		f := newRouteFixture(t, func(c *config.Config) { c.AuthDebug = false })
		start(f)
		rec := f.get("/oauth/resume?error=server_error")
		if rec.Code != http.StatusFound {
			t.Fatalf("= %d, want 302", rec.Code)
		}
		if got := locationOf(t, rec).Query().Get("error"); got != "server_error" {
			t.Errorf("error = %q", got)
		}
	})

	for _, upstream := range []string{"temporarily_unavailable", "consent_required", "anything"} {
		t.Run(upstream+" is NOT relayed", func(t *testing.T) {
			f := newRouteFixture(t, func(c *config.Config) { c.AuthDebug = false })
			start(f)
			rec := f.get("/oauth/resume?error=" + upstream)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("= %d, want 400 — an arbitrary upstream error must not be forwarded", rec.Code)
			}
			if got := decodeJSON(t, rec)["error"]; got != "invalid_request" {
				t.Errorf("error = %v, want invalid_request", got)
			}
		})
	}

	// 🔒 THE CLIENT IS RE-VALIDATED FIRST. A pending cookie whose client is no longer resolvable must
	// NOT be used to bounce an error to its redirect_uri.
	t.Run("an unresolvable client is refused before any redirect", func(t *testing.T) {
		f := newRouteFixture(t, func(c *config.Config) { c.AuthDebug = false })
		start(f)
		f.resolveErr = errUnknownTestClient
		rec := f.get("/oauth/resume?error=access_denied")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400", rec.Code)
		}
		if got := decodeJSON(t, rec)["error"]; got != "invalid_client" {
			t.Errorf("error = %v, want invalid_client", got)
		}
		if rec.Header().Get("Location") != "" {
			t.Error("nothing may be redirected to an unvalidated client")
		}
	})

	// With NO pending cookie at all, even a relayable error is refused.
	t.Run("no pending cookie means no relay", func(t *testing.T) {
		f := newRouteFixture(t, func(c *config.Config) { c.AuthDebug = false })
		if rec := f.get("/oauth/resume?error=access_denied"); rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400", rec.Code)
		}
	})
}

// ---- Case 8 -------------------------------------------------------------------------------------

// `production OAuth resumes through the shared session and issues a code after consent` (`:327-369`).
// KT: OAuthRoutesDbTest.kt#production OAuth resumes through the shared session and issues a code after consent
func TestProductionOAuthResumesThroughTheSharedSessionAndIssuesACodeAfterConsent(t *testing.T) {
	f := newRouteFixture(t, func(c *config.Config) {
		c.AuthDebug = false
		c.MCPDebugAutoConsent = false
	})

	authorization := f.get(authorizeURL(map[string]string{
		"scope": "mcp:identity:write",
		"state": "state-resumed",
	}))
	if authorization.Code != http.StatusFound {
		t.Fatalf("authorize = %d", authorization.Code)
	}
	if got := authorization.Header().Get("Location"); got != "/auth/oidc/login?return_to=%2Foauth%2Fresume" {
		t.Fatalf("Location = %q", got)
	}

	if login := f.do(http.MethodPost, "/test/login/resume-user@example.com", url.Values{}); login.Code != http.StatusNoContent {
		t.Fatalf("test login = %d", login.Code)
	}
	consent := f.get("/oauth/resume")
	if consent.Code != http.StatusOK {
		t.Fatalf("resume = %d, body %s", consent.Code, consent.Body)
	}
	csrf := csrfFromConsentPage(t, consent.Body.String())

	approved := f.do(http.MethodPost, "/oauth/consent", url.Values{
		"csrf":     {csrf},
		"decision": {"approve"},
	})
	if approved.Code != http.StatusFound {
		t.Fatalf("consent = %d, body %s", approved.Code, approved.Body)
	}
	redirect := locationOf(t, approved)
	if redirect.Query().Get("code") == "" {
		t.Error("approving must issue a code")
	}
	if got := redirect.Query().Get("state"); got != "state-resumed" {
		t.Errorf("state = %q", got)
	}
}

var consentCSRFPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfFromConsentPage(t *testing.T, body string) string {
	t.Helper()
	m := consentCSRFPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token on the consent page:\n%s", body)
	}
	return m[1]
}

// 🔒 INV-A11-21 — CSRF IS ROTATED AT EVERY AUTHENTICATION STEP. The token on the page after `/resume`
// must differ from the one minted at `/authorize`, or a token captured before authentication would
// still be spendable after it.
//
// NEW: the Kotlin never reads the pre-authentication token, so nothing pinned the rotation.
func TestResumeRotatesTheConsentCSRFToken(t *testing.T) {
	f := newRouteFixture(t, func(c *config.Config) {
		c.AuthDebug = false
		c.MCPDebugAutoConsent = false
	})
	if rec := f.get(authorizeURL(map[string]string{"scope": "mcp:read"})); rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d", rec.Code)
	}
	before := f.decodePending(t)

	if login := f.do(http.MethodPost, "/test/login/rotate@example.com", url.Values{}); login.Code != http.StatusNoContent {
		t.Fatalf("test login = %d", login.Code)
	}
	page := f.get("/oauth/resume")
	if page.Code != http.StatusOK {
		t.Fatalf("resume = %d, body %s", page.Code, page.Body)
	}
	after := csrfFromConsentPage(t, page.Body.String())

	if before.CSRF == "" || after == "" {
		t.Fatalf("both tokens must exist: %q then %q", before.CSRF, after)
	}
	if before.CSRF == after {
		t.Error("INV-A11-21: the CSRF token must be rotated at the authentication step")
	}
	// And the STALE token no longer works.
	stale := f.do(http.MethodPost, "/oauth/consent", url.Values{"csrf": {before.CSRF}, "decision": {"approve"}})
	if stale.Code != http.StatusBadRequest {
		t.Errorf("a stale CSRF token must be refused, got %d", stale.Code)
	}
}

// decodePending reads the pending cookie out of the jar, through the same MAC the routes use.
func (f *routeFixture) decodePending(t *testing.T) PendingAuthorization {
	t.Helper()
	raw, ok := f.jar[PendingCookie]
	if !ok {
		t.Fatal("no pending cookie in the jar")
	}
	codec := session.NewCookieCodec(f.cfg.SessionSecret, f.cfg.MCPIssuer())
	var pending PendingAuthorization
	if err := codec.Decode(raw, &pending); err != nil {
		t.Fatalf("decode the pending cookie: %v", err)
	}
	return pending
}

// The four conditions on `POST /oauth/consent`, one at a time. The SESSION check is what stops a
// signed-out browser (or a different user in the same browser) from completing someone else's
// authorization; the CSRF check is what stops a cross-site form post.
func TestConsentPostRequiresAPendingCookieAPrincipalASessionAndTheCSRFToken(t *testing.T) {
	setup := func(t *testing.T) (*routeFixture, string) {
		t.Helper()
		f := newRouteFixture(t, func(c *config.Config) {
			c.AuthDebug = false
			c.MCPDebugAutoConsent = false
		})
		if rec := f.get(authorizeURL(map[string]string{"scope": "mcp:read"})); rec.Code != http.StatusFound {
			t.Fatalf("authorize = %d", rec.Code)
		}
		if rec := f.do(http.MethodPost, "/test/login/consent@example.com", url.Values{}); rec.Code != http.StatusNoContent {
			t.Fatalf("login = %d", rec.Code)
		}
		page := f.get("/oauth/resume")
		if page.Code != http.StatusOK {
			t.Fatalf("resume = %d", page.Code)
		}
		return f, csrfFromConsentPage(t, page.Body.String())
	}

	t.Run("a wrong csrf is refused", func(t *testing.T) {
		f, _ := setup(t)
		rec := f.do(http.MethodPost, "/oauth/consent", url.Values{"csrf": {"csrf_wrong"}, "decision": {"approve"}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400", rec.Code)
		}
	})
	t.Run("an absent csrf is refused", func(t *testing.T) {
		f, _ := setup(t)
		rec := f.do(http.MethodPost, "/oauth/consent", url.Values{"decision": {"approve"}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400", rec.Code)
		}
	})
	t.Run("no pending cookie is refused", func(t *testing.T) {
		f, csrf := setup(t)
		delete(f.jar, PendingCookie)
		rec := f.do(http.MethodPost, "/oauth/consent", url.Values{"csrf": {csrf}, "decision": {"approve"}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400", rec.Code)
		}
	})
	t.Run("a signed-out browser is refused even with the right csrf", func(t *testing.T) {
		f, csrf := setup(t)
		if _, err := f.db.Pool.Exec(f.ctx,
			`UPDATE principal_session SET ended_at = now(), ended_reason = 'SIGNED_OUT' WHERE kind = 'WEB'`); err != nil {
			t.Fatalf("end the session: %v", err)
		}
		rec := f.do(http.MethodPost, "/oauth/consent", url.Values{"csrf": {csrf}, "decision": {"approve"}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400 — the pending cookie alone is not authorization", rec.Code)
		}
	})
	t.Run("a denial clears the cookie and redirects access_denied", func(t *testing.T) {
		f, csrf := setup(t)
		rec := f.do(http.MethodPost, "/oauth/consent", url.Values{"csrf": {csrf}, "decision": {"deny"}})
		if rec.Code != http.StatusFound {
			t.Fatalf("= %d, want 302", rec.Code)
		}
		redirect := locationOf(t, rec)
		if got := redirect.Query().Get("error"); got != "access_denied" {
			t.Errorf("error = %q", got)
		}
		if redirect.Query().Get("code") != "" {
			t.Error("a denial must not issue a code")
		}
		if _, present := f.jar[PendingCookie]; present {
			t.Error("a denial must clear the pending cookie")
		}
	})
	t.Run("anything other than approve is a denial", func(t *testing.T) {
		f, csrf := setup(t)
		rec := f.do(http.MethodPost, "/oauth/consent", url.Values{"csrf": {csrf}, "decision": {"APPROVE"}})
		if rec.Code != http.StatusFound {
			t.Fatalf("= %d, want 302", rec.Code)
		}
		if got := locationOf(t, rec).Query().Get("error"); got != "access_denied" {
			t.Errorf("the decision comparison is case-SENSITIVE: got %q", got)
		}
	})
}

// ---- Case 9 -------------------------------------------------------------------------------------

// `production configuration rejects the public dev session secret and insecure origins` (`:371-389`).
//
// The symbol under test is A1's `Config.fromEnv`, not this package's — but the case is part of
// OAuthRoutesDbTest because the two rules it checks are what make the OAuth surface safe to co-host:
// a shared dev secret would let anyone forge the pending cookie AND the consent CSRF, and a plaintext
// `PM_MCP_RESOURCE` would put every authorization code on the wire in the clear.
// KT: OAuthRoutesDbTest.kt#production configuration rejects the public dev session secret and insecure origins
func TestProductionConfigurationRejectsTheDevSessionSecretAndInsecureOrigins(t *testing.T) {
	base := map[string]string{
		"PM_AUTH_DEBUG":         "false",
		"PM_MCP_RESOURCE":       "https://proxy.example/mcp",
		"PM_OIDC_ISSUER":        "https://idp.example/oauth2/default",
		"PM_OIDC_CLIENT_ID":     "client",
		"PM_OIDC_CLIENT_SECRET": "secret",
		"PM_OIDC_REDIRECT_URI":  "https://proxy.example/auth/oidc/callback",
	}
	lookup := func(env map[string]string) config.Lookup {
		return func(k string) (string, bool) {
			v, ok := env[k]
			return v, ok
		}
	}

	if _, err := config.FromEnv(lookup(base)); err == nil {
		t.Fatal("production must reject the public dev session secret")
	}

	base["PM_SESSION_SECRET"] = strings.Repeat("x", 32)
	cfg, err := config.FromEnv(lookup(base))
	if err != nil {
		t.Fatalf("a 32-character secret must be accepted: %v", err)
	}
	if got := cfg.MCPIssuer(); got != "https://proxy.example" {
		t.Errorf("mcpIssuer = %q, want https://proxy.example", got)
	}

	base["PM_MCP_RESOURCE"] = "http://proxy.example/mcp"
	_, err = config.FromEnv(lookup(base))
	if err == nil {
		t.Fatal("production must reject a plaintext MCP resource")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("the rejection must name HTTPS, got %v", err)
	}
}

// ---- Case 10 ------------------------------------------------------------------------------------

// `debug authorize carries the simulated source address across its session remint` (`:401-442`).
//
// ⚠️ 🔒 INV-A11-19, and the Kotlin's own reason for pinning it HERE rather than in a session suite,
// verbatim (`:391-399`):
//
//	"The debug /oauth/authorize shares the console's authenticated session, and sharing means
//	 REPLACING it — mintWeb is newest-wins. So the simulated source address the console is deciding
//	 under has to survive that remint, or an MCP authorization in the same browser silently changes
//	 the console's authorization context: tag rules stop firing, and nothing on screen says why.
//	 Pinned here rather than in DebugRequesterIpDbTest because the bug lives in THIS route. Both
//	 branches are asserted — the carry-over, and the deliberate drop when ?principal= names someone
//	 else, since one identity's simulated network must never follow another's."
//
// KT: OAuthRoutesDbTest.kt#debug authorize carries the simulated source address across its session remint
func TestDebugAuthorizeCarriesTheSimulatedSourceAddressAcrossItsSessionRemint(t *testing.T) {
	f := newRouteFixture(t)

	authorizeAs := func(principal string) int {
		return f.get(authorizeURL(map[string]string{"scope": "mcp:read", "state": "state-ip", "principal": principal})).Code
	}

	// The console session: signed in, deciding as if from the trusted network.
	const owner = "ip-owner@example.com"
	if rec := f.do(http.MethodPost, "/test/login/"+owner+"?requesterIp=100.100.1.10", url.Values{}); rec.Code != http.StatusNoContent {
		t.Fatalf("test login = %d", rec.Code)
	}
	if got := f.liveDebugIP(t, owner); got == nil || *got != "100.100.1.10" {
		t.Fatalf("setup: liveDebugIp(%s) = %v, want 100.100.1.10", owner, got)
	}

	// Same principal: the remint must carry the address over.
	if code := authorizeAs(owner); code != http.StatusFound {
		t.Fatalf("authorize = %d", code)
	}
	if got := f.liveDebugIP(t, owner); got == nil || *got != "100.100.1.10" {
		t.Errorf("an MCP authorization must not silently drop the console's simulated address, got %v", got)
	}

	// A DIFFERENT principal: the new session must start with no simulated address at all.
	const other = "ip-other@example.com"
	if code := authorizeAs(other); code != http.StatusFound {
		t.Fatalf("authorize = %d", code)
	}
	if got := f.liveDebugIP(t, other); got != nil {
		t.Errorf("one principal's simulated network must not follow another's identity, got %v", *got)
	}
}

// liveDebugIP is the Kotlin helper (`:445-457`): the simulated address on the principal's single LIVE
// web session — the row a decision would resolve.
func (f *routeFixture) liveDebugIP(t *testing.T, principal string) *string {
	t.Helper()
	var ip *string
	err := f.db.Pool.QueryRow(f.ctx,
		`SELECT debug_requester_ip FROM principal_session
		     WHERE principal = $1 AND kind = 'WEB' AND ended_at IS NULL
		     ORDER BY id DESC LIMIT 1`, principal).Scan(&ip)
	if err != nil {
		t.Fatalf("no live web session for %s: %v", principal, err)
	}
	return ip
}

// ---- The authorize validation table -------------------------------------------------------------

// 🔒 VALIDATION IS ALL-OR-NOTHING AND ANSWERS ONE CODE. Eight conditions, each broken in turn, each
// answering `400 invalid_request` with no description — the endpoint must not tell a probing client
// WHICH parameter it got wrong.
//
// 🔒 INV-A11-18 is the row that matters most: `resource` must equal config.MCPResource EXACTLY, with
// no normalization, no trailing-slash tolerance and no case folding.
//
// NEW: the Kotlin suite never sends a malformed authorize request at all.
func TestAuthorizeValidationIsAllOrNothingAndAnswersInvalidRequest(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]string
	}{
		{"response_type must be code", map[string]string{"response_type": "token"}},
		{"response_type is required", map[string]string{"response_type": ""}},
		{"client_id is required", map[string]string{"client_id": ""}},
		{"client_id must not be blank", map[string]string{"client_id": "   "}},
		{"redirect_uri is required", map[string]string{"redirect_uri": ""}},
		{"state is required", map[string]string{"state": ""}},
		{"state must not be blank", map[string]string{"state": " "}},
		{"resource is required", map[string]string{"resource": ""}},
		{"INV-A11-18: a trailing slash is NOT the same resource", map[string]string{"resource": routeResource + "/"}},
		{"INV-A11-18: a different case is NOT the same resource", map[string]string{"resource": strings.ToUpper(routeResource)}},
		{"INV-A11-18: another resource is refused", map[string]string{"resource": "https://other.example/mcp"}},
		{"code_challenge_method must be S256", map[string]string{"code_challenge_method": "plain"}},
		{"code_challenge_method is required", map[string]string{"code_challenge_method": ""}},
		{"code_challenge is required", map[string]string{"code_challenge": ""}},
		{"code_challenge must be 43 characters", map[string]string{"code_challenge": strings.Repeat("a", 42)}},
		{"scope is required", map[string]string{"scope": ""}},
		{"scope must not be empty", map[string]string{"scope": "   "}},
		{"every scope must be an MCPA scope", map[string]string{"scope": "mcp:read admin:everything"}},
		{"a near-miss scope is still refused", map[string]string{"scope": "mcp:Read"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRouteFixture(t)
			rec := f.get(authorizeURL(c.overrides))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("= %d, want 400 (body %s)", rec.Code, rec.Body)
			}
			body := decodeJSON(t, rec)
			if body["error"] != "invalid_request" {
				t.Errorf("error = %v, want invalid_request", body["error"])
			}
			if _, present := body["error_description"]; present {
				t.Error("no description: the endpoint must not say which parameter was wrong")
			}
			// Nothing was resolved, so a probe cannot use the endpoint to make the server fetch a URL.
			if f.resolves != 0 {
				t.Errorf("a malformed request must not reach the CIMD resolver (%d resolves)", f.resolves)
			}
		})
	}
}

// An unresolvable or non-conforming client is `invalid_client` — a DIFFERENT code from
// `invalid_request`, and the two CIMD failures are indistinguishable from each other.
func TestAuthorizeAnswersInvalidClientForACIMDFailure(t *testing.T) {
	t.Run("the metadata document cannot be resolved", func(t *testing.T) {
		f := newRouteFixture(t)
		f.resolveErr = errUnknownTestClient
		rec := f.get(authorizeURL(nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400", rec.Code)
		}
		if got := decodeJSON(t, rec)["error"]; got != "invalid_client" {
			t.Errorf("error = %v, want invalid_client", got)
		}
	})
	t.Run("the redirect_uri is not declared by the metadata", func(t *testing.T) {
		f := newRouteFixture(t)
		f.metadata.RedirectURIs = []string{"http://127.0.0.1:1/other"}
		rec := f.get(authorizeURL(nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400", rec.Code)
		}
		if got := decodeJSON(t, rec)["error"]; got != "invalid_client" {
			t.Errorf("error = %v, want invalid_client", got)
		}
	})
}

// ---- The token endpoint's error vocabulary ------------------------------------------------------

// 🔒 INV-A11-22 — EVERY OAuth error is a 400 with an OAuthError body. Not 401, not 403, and the body
// shape never varies. A missing required field is `invalid_request`; a present-but-wrong one falls
// through to `invalid_grant`; an unknown grant is `unsupported_grant_type`.
func TestTokenEndpointErrorVocabulary(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{"no grant_type at all", url.Values{}, "unsupported_grant_type"},
		{"an unknown grant", url.Values{"grant_type": {"password"}}, "unsupported_grant_type"},
		{"authorization_code without a code", url.Values{
			"grant_type": {"authorization_code"}, "client_id": {routeClientID},
			"redirect_uri": {routeRedirectURI}, "resource": {routeResource}, "code_verifier": {routeVerifier},
		}, "invalid_request"},
		{"authorization_code without a verifier", url.Values{
			"grant_type": {"authorization_code"}, "code": {"pmc_x"}, "client_id": {routeClientID},
			"redirect_uri": {routeRedirectURI}, "resource": {routeResource},
		}, "invalid_request"},
		{"authorization_code with an unknown code", url.Values{
			"grant_type": {"authorization_code"}, "code": {"pmc_never-existed"}, "client_id": {routeClientID},
			"redirect_uri": {routeRedirectURI}, "resource": {routeResource}, "code_verifier": {routeVerifier},
		}, "invalid_grant"},
		{"INV-A11-18: authorization_code for another resource", url.Values{
			"grant_type": {"authorization_code"}, "code": {"pmc_x"}, "client_id": {routeClientID},
			"redirect_uri": {routeRedirectURI}, "resource": {"https://other.example/mcp"},
			"code_verifier": {routeVerifier},
		}, "invalid_grant"},
		{"refresh_token without a token", url.Values{
			"grant_type": {"refresh_token"}, "client_id": {routeClientID}, "resource": {routeResource},
		}, "invalid_request"},
		{"refresh_token with an unknown token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {"pmr_never-existed"},
			"client_id": {routeClientID}, "resource": {routeResource},
		}, "invalid_grant"},
		{"INV-A11-18: refresh_token for another resource", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {"pmr_x"},
			"client_id": {routeClientID}, "resource": {"https://other.example/mcp"},
		}, "invalid_grant"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRouteFixture(t)
			rec := f.do(http.MethodPost, "/oauth/token", c.form)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("= %d, want 400 (body %s)", rec.Code, rec.Body)
			}
			if got := decodeJSON(t, rec)["error"]; got != c.want {
				t.Errorf("error = %v, want %v", got, c.want)
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
		})
	}
}

// 🔒 An empty-but-PRESENT `resource` is a resource mismatch (invalid_grant), not a missing field —
// the Kotlin reads `form["resource"] ?: return invalid_request`, and "" is not null. The distinction
// is invisible from the outside except in the error code, which is exactly why it is asserted.
func TestAPresentButEmptyResourceIsAGrantFailureNotAMissingField(t *testing.T) {
	f := newRouteFixture(t)
	rec := f.do(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {"pmr_x"},
		"client_id": {routeClientID}, "resource": {""},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("= %d", rec.Code)
	}
	if got := decodeJSON(t, rec)["error"]; got != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant — an empty value is present, not absent", got)
	}
}

// ---- /oauth/revoke ------------------------------------------------------------------------------

// 🔒 INV-A14-23 — RFC 7009: ALWAYS 200 `{}`, even for an unknown token or no token at all.
// Revocation must not become an existence oracle.
func TestRevokeAlwaysAnswers200AnEmptyObject(t *testing.T) {
	f := newRouteFixture(t)
	for _, form := range []url.Values{
		{},
		{"token": {"pmr_never-existed"}},
		{"token": {""}},
		{"token": {"not-even-a-token-shape"}},
	} {
		rec := f.do(http.MethodPost, "/oauth/revoke", form)
		if rec.Code != http.StatusOK {
			t.Errorf("revoke(%v) = %d, want 200", form, rec.Code)
		}
		if body := strings.TrimSpace(rec.Body.String()); body != "{}" {
			t.Errorf("revoke(%v) body = %q, want {}", form, body)
		}
	}

	// And a real token really is revoked, so the uniform 200 is not hiding a no-op.
	consent, err := f.store.RememberConsent(f.ctx, "revoke-route@example.com", routeClientID, routeResource, []string{"mcp:read"})
	if err != nil {
		t.Fatalf("RememberConsent: %v", err)
	}
	ttl := int64(300)
	code, err := f.store.CreateAuthorizationCode(f.ctx, AuthorizationCodeInput{
		ClientID: routeClientID, Principal: "revoke-route@example.com", RedirectURI: routeRedirectURI,
		Resource: routeResource, Scopes: []string{"mcp:read"}, CodeChallenge: routeChallenge,
		TTLSeconds: &ttl, ConsentID: consent.ID,
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	pair, err := f.store.ConsumeAuthorizationCode(f.ctx, ConsumeAuthorizationCodeInput{
		Code: code, ClientID: routeClientID, RedirectURI: routeRedirectURI, Resource: routeResource,
		CodeVerifier: routeVerifier, AccessTTLSeconds: 600, RefreshTTLSeconds: 3_600,
	})
	if err != nil || pair == nil {
		t.Fatalf("ConsumeAuthorizationCode: %v (%v)", err, pair)
	}
	if rec := f.do(http.MethodPost, "/oauth/revoke", url.Values{"token": {pair.AccessToken}}); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	tokens := NewMCPTokenStore(f.db.Pool)
	identity, err := tokens.ResolveAccess(f.ctx, pair.AccessToken, routeResource)
	if err != nil {
		t.Fatalf("ResolveAccess: %v", err)
	}
	if identity != nil {
		t.Error("the revoked access token must not resolve")
	}
}

// ---- Consent management -------------------------------------------------------------------------

// 🔒 INV-A11-23 — the consent CSRF token is a KEYED HMAC over the session secret and the principal:
// stateless, per-principal, and therefore not replayable across principals.
func TestConsentCSRFIsAKeyedHMACPerPrincipal(t *testing.T) {
	const secret = "control-plane-oauth-test-secret-32-bytes"
	a := consentCSRF(secret, "alice@example.com")
	b := consentCSRF(secret, "bob@example.com")
	if a == b {
		t.Fatal("two principals must not share a token")
	}
	if a != consentCSRF(secret, "alice@example.com") {
		t.Error("the token must be stateless — the same inputs give the same token")
	}
	if a == consentCSRF("a-different-session-secret-of-32b!!", "alice@example.com") {
		t.Error("the token must be keyed on the session secret")
	}
	if strings.ContainsAny(a, "=+/") {
		t.Errorf("the token must be unpadded base64url: %q", a)
	}
	// The separator is a REAL NUL, so `("a\x00b", "")` and `("a", "b")` cannot collide. Without it,
	// two principals whose names concatenate the same way would share a token.
	if consentCSRF(secret, "a\x00b") == consentCSRF(secret, "ab") {
		t.Error("the NUL separator must be part of the MAC input")
	}
}

// `GET /oauth/consents` needs a session and answers `401 login_required` — the ONE 401 on this
// surface, and it is in the OAuth vocabulary, not the ApiError one.
func TestConsentManagementRequiresASessionAndTheCSRFHeader(t *testing.T) {
	t.Run("listing without a session is 401 login_required", func(t *testing.T) {
		f := newRouteFixture(t, func(c *config.Config) { c.AuthDebug = false })
		rec := f.get("/oauth/consents")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("= %d, want 401", rec.Code)
		}
		if got := decodeJSON(t, rec)["error"]; got != "login_required" {
			t.Errorf("error = %v, want login_required", got)
		}
	})
	t.Run("deleting without a session is 401 login_required", func(t *testing.T) {
		f := newRouteFixture(t, func(c *config.Config) { c.AuthDebug = false })
		rec := f.do(http.MethodDelete, "/oauth/consents/1", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("= %d, want 401", rec.Code)
		}
	})

	t.Run("the list carries a csrf token and the delete spends it", func(t *testing.T) {
		f := newRouteFixture(t, func(c *config.Config) { c.AuthDebug = false })
		const principal = "consents@example.com"
		if rec := f.do(http.MethodPost, "/test/login/"+principal, url.Values{}); rec.Code != http.StatusNoContent {
			t.Fatalf("login = %d", rec.Code)
		}
		consent, err := f.store.RememberConsent(f.ctx, principal, routeClientID, routeResource, []string{"mcp:read"})
		if err != nil {
			t.Fatalf("RememberConsent: %v", err)
		}

		list := f.get("/oauth/consents")
		if list.Code != http.StatusOK {
			t.Fatalf("list = %d, body %s", list.Code, list.Body)
		}
		body := decodeJSON(t, list)
		csrf, _ := body["csrfToken"].(string)
		if csrf == "" {
			t.Fatal("no csrfToken in the list response")
		}
		consents, _ := body["consents"].([]any)
		if len(consents) != 1 {
			t.Fatalf("consents = %v, want one", consents)
		}
		row, _ := consents[0].(map[string]any)
		for _, key := range []string{"id", "principal", "clientId", "resource", "scope", "createdAt", "updatedAt"} {
			if _, present := row[key]; !present {
				t.Errorf("the consent DTO is missing %q: %v", key, row)
			}
		}

		// 🔒 ORDER: the CSRF check runs BEFORE the id parse, so a malformed id with a wrong token
		// answers the CSRF failure and never reveals that parsing was reached.
		if rec := f.do(http.MethodDelete, "/oauth/consents/999", nil); rec.Code != http.StatusBadRequest {
			t.Errorf("a missing CSRF header must be 400, got %d", rec.Code)
		}
		if rec := f.deleteWithCSRF("/oauth/consents/999", "csrf_wrong"); rec.Code != http.StatusBadRequest {
			t.Errorf("a wrong CSRF header must be 400, got %d", rec.Code)
		}
		// A valid token with an unknown id is 404 — with the SAME `invalid_request` body, so only the
		// status distinguishes them.
		notFound := f.deleteWithCSRF("/oauth/consents/999999", csrf)
		if notFound.Code != http.StatusNotFound {
			t.Errorf("an unknown id must be 404, got %d", notFound.Code)
		}
		if got := decodeJSON(t, notFound)["error"]; got != "invalid_request" {
			t.Errorf("the 404 body is invalid_request too, got %v", got)
		}

		deleted := f.deleteWithCSRF("/oauth/consents/"+itoa(consent.ID), csrf)
		if deleted.Code != http.StatusNoContent {
			t.Fatalf("delete = %d, body %s", deleted.Code, deleted.Body)
		}
		after := decodeJSON(t, f.get("/oauth/consents"))
		if remaining, _ := after["consents"].([]any); len(remaining) != 0 {
			t.Errorf("the consent must be gone from the list, got %v", remaining)
		}
	})

	// 🔒 INV-A14-19 at the route: another principal's CSRF token does not authorize anything, because
	// the token is per-principal AND the store's predicate is per-principal.
	t.Run("another principals csrf token does not work", func(t *testing.T) {
		f := newRouteFixture(t, func(c *config.Config) { c.AuthDebug = false })
		if rec := f.do(http.MethodPost, "/test/login/victim@example.com", url.Values{}); rec.Code != http.StatusNoContent {
			t.Fatalf("login = %d", rec.Code)
		}
		consent, err := f.store.RememberConsent(f.ctx, "victim@example.com", routeClientID, routeResource, []string{"mcp:read"})
		if err != nil {
			t.Fatalf("RememberConsent: %v", err)
		}
		attackerToken := consentCSRF(f.cfg.SessionSecret, "attacker@example.com")
		rec := f.deleteWithCSRF("/oauth/consents/"+itoa(consent.ID), attackerToken)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400", rec.Code)
		}
	})
}

func (f *routeFixture) deleteWithCSRF(target, csrf string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodDelete, target, nil)
	req.Header.Set("X-PM-CSRF", csrf)
	for name, value := range f.jar {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// ---- The protocol guard --------------------------------------------------------------------------

// 🔒 `installMcpOAuthProtocolGuard` — `/oauth/**` is `no-store` + `no-cache` on EVERY response,
// including the error ones. A cached authorization code, token response or consent page is a
// credential sitting in a shared proxy.
func TestTheProtocolGuardMarksEveryOAuthResponseNoStore(t *testing.T) {
	f := newRouteFixture(t)
	responses := []*httptest.ResponseRecorder{
		f.get("/oauth/authorize?response_type=nonsense"),
		f.get("/oauth/resume"),
		f.do(http.MethodPost, "/oauth/consent", url.Values{}),
		f.do(http.MethodPost, "/oauth/token", url.Values{}),
		f.do(http.MethodPost, "/oauth/revoke", url.Values{}),
		f.get("/oauth/consents"),
	}
	for i, rec := range responses {
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("response %d: Cache-Control = %q, want no-store", i, got)
		}
		if got := rec.Header().Get("Pragma"); got != "no-cache" {
			t.Errorf("response %d: Pragma = %q, want no-cache", i, got)
		}
	}
}

// ---- The pending cookie ---------------------------------------------------------------------------

// The pending cookie is a SIGNED cookie, and every read failure — no cookie, a forged MAC, a stale
// payload shape — collapses to "no pending authorization", never to a 500.
func TestAForgedOrStalePendingCookieIsSimplyAbsent(t *testing.T) {
	cases := []struct{ name, value string }{
		{"a forged value", "v1.eyJjbGllbnRJZCI6IngifQ.AAAA"},
		{"not even the right shape", "garbage"},
		{"an empty value", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRouteFixture(t, func(cfg *config.Config) { cfg.AuthDebug = false })
			f.jar[PendingCookie] = c.value
			rec := f.get("/oauth/resume?error=access_denied")
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("= %d, want 400 (never a 500)", rec.Code)
			}
			if got := decodeJSON(t, rec)["error"]; got != "invalid_request" {
				t.Errorf("error = %v", got)
			}
		})
	}

	// A cookie whose MAC is VALID but whose payload lacks a required field is also just absent —
	// kotlinx's MissingFieldException behind Ktor's `sessions.get`, reproduced by
	// [PendingAuthorization.UnmarshalJSON].
	t.Run("a validly signed but wrong-shape payload", func(t *testing.T) {
		f := newRouteFixture(t, func(cfg *config.Config) { cfg.AuthDebug = false })
		codec := session.NewCookieCodec(f.cfg.SessionSecret, f.cfg.MCPIssuer())
		signed := codec.EncodeRaw([]byte(`{"clientId":"x"}`))
		f.jar[PendingCookie] = signed
		rec := f.get("/oauth/resume?error=access_denied")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400 (never a 500)", rec.Code)
		}
	})
}

// The pending cookie's payload: `principal` is OMITTED when absent (explicitNulls=false) and present
// when set. Asserted on the bytes, because a `"principal":null` would decode back to a non-nil empty
// string in some readers and silently authorize the empty principal.
func TestThePendingCookiePayloadOmitsAnAbsentPrincipal(t *testing.T) {
	pending, err := NewPendingAuthorization("c", "r", "res", "mcp:read", "st", routeChallenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "principal") {
		t.Errorf("an absent principal must be OMITTED, got %s", raw)
	}
	if !strings.Contains(string(raw), `"csrf":"csrf_`) {
		t.Errorf("csrf is a default-valued field and is always emitted, got %s", raw)
	}

	principal := "p@example.com"
	pending.Principal = &principal
	raw, err = json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"principal":"p@example.com"`) {
		t.Errorf("a present principal must be emitted, got %s", raw)
	}
}
