package oidc

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/config"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// Port of OidcCallbackTest.kt — 8 cases: "[oidcRoutes] exercised through a real Ktor test host: the
// CSRF `state` + `nonce` cookies' one-time-use, callback errors, and the allowlisted co-hosted OAuth
// continuation."
//
// ORACLE: control-plane/src/test/kotlin/.../OidcCallbackTest.kt, read this session.
//
// Fidelity note on the fake IdP: the Kotlin colocates the discovery + token doubles in the SAME test
// application (relative URLs through the in-process client, `issuer = ""`). Go's http.Client has no
// in-process transport, so the double is a second httptest.Server and `issuer` is its real URL. Same
// shape, one real loopback socket. jwks_uri is deliberately unreachable and never hit — see
// unparseableIDToken.
//
// 🔒 The stores are ExplodingSeams, the port of the Kotlin's `UnusedDataSource`: "a DataSource that
// must never be touched. Every scenario fails CSRF/id_token validation before
// UserGroupStore.provisionFromOidc would ever run." A scenario that starts touching them is a
// scenario that changed meaning, and the t.Fatal says so.

// unparseableIDToken is the Kotlin's UNPARSEABLE_ID_TOKEN. Validate fails to even parse it, so it
// returns nil WITHOUT ever fetching jwks_uri — which is what lets this suite exercise the REAL
// Discovery + IDTokenValidator with no signing infrastructure.
const unparseableIDToken = "not-a-real-jwt"

// explodingSeams fails the test if any A3/A4 seam is reached.
type explodingSeams struct{ t *testing.T }

func (e explodingSeams) ProvisionFromOidc(context.Context, string, *string, []string, GroupMapping) error {
	e.t.Fatal("OidcCallbackTest: no scenario here may reach provisionFromOidc")
	return nil
}

func (e explodingSeams) Resolve(context.Context, string) ([]string, error) {
	e.t.Fatal("OidcCallbackTest: no scenario here may reach roleResolver.resolve")
	return nil, nil
}

func (e explodingSeams) MintWeb(context.Context, string, *string, int64, int64, string) (int64, error) {
	e.t.Fatal("OidcCallbackTest: no scenario here may mint a web session")
	return 0, nil
}

func (e explodingSeams) SetSessionCookie(http.ResponseWriter, *http.Request, int64) error {
	e.t.Fatal("OidcCallbackTest: no scenario here may set a session cookie")
	return nil
}

func (e explodingSeams) EnsureDeviceCookie(http.ResponseWriter, *http.Request, bool) (string, error) {
	e.t.Fatal("OidcCallbackTest: no scenario here may touch the device cookie")
	return "", nil
}

// callbackFixture is the wired test host plus a cookie-jar client with redirects DISABLED, so the
// 3xx responses under test are inspectable rather than silently followed.
type callbackFixture struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client
}

func newCallbackFixture(t *testing.T, oidcConfigured bool) *callbackFixture {
	t.Helper()

	// The fake IdP double: a discovery document + a token endpoint. jwks_uri points at a host that
	// does not resolve, exactly as the Kotlin's does.
	idpMux := http.NewServeMux()
	idp := httptest.NewServer(idpMux)
	t.Cleanup(idp.Close)
	idpMux.HandleFunc("GET "+WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"issuer":"`+idp.URL+`","authorization_endpoint":"`+idp.URL+
			`/authorize","token_endpoint":"`+idp.URL+`/token","jwks_uri":"http://jwks.invalid/keys"}`)
	})
	idpMux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id_token":"`+unparseableIDToken+`"}`)
	})

	cfg := config.Defaults()
	cfg.SessionSecret = "oidc-callback-test-secret-not-for-prod"
	if oidcConfigured {
		cfg.OIDC = &config.OIDCConfig{
			Issuer:       idp.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURI:  "https://cp.example.test/auth/oidc/callback",
			Scopes:       "openid profile email groups offline_access",
			GroupMapping: config.OIDCGroupMapping{Map: map[string]string{}},
		}
	}

	hc := NewHTTPClient()
	rt := &Routes{
		Config:     cfg,
		HTTP:       hc,
		Cookies:    session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		UserGroups: explodingSeams{t},
		Roles:      explodingSeams{t},
		Sessions:   explodingSeams{t},
		Log:        discardLogger(),
	}
	if oidcConfigured {
		rt.Discovery = NewDiscovery(hc, cfg.OIDC.Issuer)
		rt.Validator = NewIDTokenValidator(rt.Discovery, cfg.OIDC.Issuer, cfg.OIDC.ClientID, hc, discardLogger())
	}

	mux := http.NewServeMux()
	rt.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &callbackFixture{
		t:      t,
		server: srv,
		client: &http.Client{
			Jar:           jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (f *callbackFixture) get(path string) *http.Response {
	f.t.Helper()
	resp, err := f.client.Get(f.server.URL + path)
	if err != nil {
		f.t.Fatalf("GET %s: %v", path, err)
	}
	f.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// login drives GET /auth/oidc/login and returns the `state` the IdP redirect carries.
func (f *callbackFixture) login(returnTo string) string {
	f.t.Helper()
	path := "/auth/oidc/login"
	if returnTo != "" {
		path += "?return_to=" + url.QueryEscape(returnTo)
	}
	resp := f.get(path)
	if resp.StatusCode != http.StatusFound {
		f.t.Fatalf("login status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		f.t.Fatalf("parse Location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		f.t.Fatalf("login redirect carries no state: %s", resp.Header.Get("Location"))
	}
	return state
}

func (f *callbackFixture) assertRedirect(resp *http.Response, want string) {
	f.t.Helper()
	if resp.StatusCode != http.StatusFound {
		f.t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != want {
		f.t.Fatalf("Location = %q, want %q", got, want)
	}
}

// --- Case 1 🔒 · `OIDC continuation accepts only the co-hosted resume and reauth routes`
func TestReturnTarget_AcceptsOnlyTheCoHostedContinuations(t *testing.T) {
	if got := ReturnTarget(types.Ptr("/oauth/resume")); got == nil || *got != "/oauth/resume" {
		t.Errorf("/oauth/resume = %v", got)
	}
	if got := ReturnTarget(types.Ptr("/auth/reauth-complete")); got == nil || *got != "/auth/reauth-complete" {
		t.Errorf("/auth/reauth-complete = %v", got)
	}
	for _, raw := range []string{"https://evil.example/callback", "//evil.example/callback", "/other", "/"} {
		if got := ReturnTarget(types.Ptr(raw)); got != nil {
			t.Errorf("ReturnTarget(%q) = %q, want nil — this would be an open redirect", raw, *got)
		}
	}
	if got := ReturnTarget(nil); got != nil {
		t.Errorf("ReturnTarget(nil) = %q, want nil", *got)
	}

	t.Run("the device-authorize continuation is accepted, anchored, and code-constrained", func(t *testing.T) {
		ok := "/auth/device/authorize?user_code=WDJB-MJHT"
		if got := ReturnTarget(types.Ptr(ok)); got == nil || *got != ok {
			t.Errorf("ReturnTarget(%q) = %v, want it accepted", ok, got)
		}
		for _, bad := range []string{
			// Not anchored at the end — `matches` is whole-string.
			"/auth/device/authorize?user_code=WDJB-MJHT&next=https://evil.example",
			// Not anchored at the start.
			"https://evil.example/auth/device/authorize?user_code=WDJB-MJHT",
			// Character class is [A-Za-z0-9-] only.
			"/auth/device/authorize?user_code=WDJB_MJHT",
			"/auth/device/authorize?user_code=",
			// 17 characters exceeds {1,16}.
			"/auth/device/authorize?user_code=ABCDEFGHIJKLMNOPQ",
		} {
			if got := ReturnTarget(types.Ptr(bad)); got != nil {
				t.Errorf("ReturnTarget(%q) = %q, want nil", bad, *got)
			}
		}
	})
}

// --- Case 2 · `unconfigured oidc degrades both routes to 501`
func TestCallback_UnconfiguredOidcDegradesBothRoutesTo501(t *testing.T) {
	f := newCallbackFixture(t, false)

	for _, path := range []string{"/auth/oidc/login", "/auth/oidc/callback"} {
		resp := f.get(path)
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("%s status = %d, want 501", path, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if want := `"code":"common.oidc_not_configured"`; !strings.Contains(string(body), want) {
			t.Errorf("%s body = %s, want it to carry %s", path, body, want)
		}
	}
}

// --- Case 3 · `provider error param redirects to error=oidc`
func TestCallback_ProviderErrorRedirectsToErrorOidc(t *testing.T) {
	f := newCallbackFixture(t, true)
	state := f.login("")
	f.assertRedirect(f.get("/auth/oidc/callback?error=access_denied&state="+state), "/login?error=oidc")
}

// --- Case 4 · `provider error preserves the popup reauth continuation`
func TestCallback_ProviderErrorPreservesReauthContinuation(t *testing.T) {
	f := newCallbackFixture(t, true)
	state := f.login("/auth/reauth-complete")
	f.assertRedirect(f.get("/auth/oidc/callback?error=access_denied&state="+state),
		"/login?error=oidc&callbackUrl=%2Fauth%2Freauth-complete")
}

// --- Case 5 · `state failure preserves the popup reauth continuation`
//
// ⚠️ The state branch is the ONE that does not route through FailureTarget unconditionally: only
// `/auth/reauth-complete` keeps its continuation, and every other returnTo — including
// `/oauth/resume` — falls to the flat "/login?error=state". Reproduced; the sub-test pins the
// asymmetry the Kotlin suite does not cover.
func TestCallback_StateFailurePreservesReauthContinuation(t *testing.T) {
	f := newCallbackFixture(t, true)
	f.login("/auth/reauth-complete")
	f.assertRedirect(f.get("/auth/oidc/callback?code=abc&state=wrong-state"),
		"/login?error=state&callbackUrl=%2Fauth%2Freauth-complete")

	t.Run("a state failure does NOT preserve the /oauth/resume continuation", func(t *testing.T) {
		f := newCallbackFixture(t, true)
		f.login("/oauth/resume")
		f.assertRedirect(f.get("/auth/oidc/callback?code=abc&state=wrong-state"), "/login?error=state")
	})
}

// --- Case 6 · `provider error returns to the co-hosted OAuth resume route`
//
// 🔒 INV-A4-64's two vocabularies: the AS resume gets the RFC-shaped `access_denied`, not the console
// i18n fragment.
func TestCallback_ProviderErrorReturnsToOAuthResume(t *testing.T) {
	f := newCallbackFixture(t, true)
	state := f.login("/oauth/resume")
	f.assertRedirect(f.get("/auth/oidc/callback?error=access_denied&state="+state),
		"/oauth/resume?error=access_denied")
}

// --- Case 7 🔒 · `state mismatch redirects to error=state, and the state cookie is one-time-use`
//
// 🔒 INV-A4-62. The second assertion is the load-bearing one: replaying with the ORIGINAL, CORRECT
// state also fails, which proves the cookie is GONE rather than merely that the comparison rejected a
// bad value.
func TestCallback_StateMismatchAndTheStateCookieIsOneTimeUse(t *testing.T) {
	f := newCallbackFixture(t, true)
	realState := f.login("")

	f.assertRedirect(f.get("/auth/oidc/callback?code=abc&state=not-the-real-state"), "/login?error=state")
	f.assertRedirect(f.get("/auth/oidc/callback?code=abc&state="+realState), "/login?error=state")
}

// --- Case 8 🔒 · `invalid id_token redirects to error=nonce, and the nonce cookie is one-time-use`
//
// The first call gets as far as the token exchange, fails id_token validation, and lands on
// error=nonce. The replay then hits the (now-empty) STATE guard, proving BOTH cookies were cleared on
// the first attempt regardless of outcome.
func TestCallback_InvalidIDTokenAndTheNonceCookieIsOneTimeUse(t *testing.T) {
	f := newCallbackFixture(t, true)
	realState := f.login("")

	f.assertRedirect(f.get("/auth/oidc/callback?code=abc&state="+realState), "/login?error=nonce")
	f.assertRedirect(f.get("/auth/oidc/callback?code=abc&state="+realState), "/login?error=state")
}

// --- Extra · the two callback branches the Kotlin suite leaves uncovered.
func TestCallback_MissingCodeAndMissingNonceBranches(t *testing.T) {
	t.Run("neither code nor error yields server_error/state", func(t *testing.T) {
		f := newCallbackFixture(t, true)
		state := f.login("/oauth/resume")
		// oauthError = server_error, and the resume continuation takes the OAuth vocabulary.
		f.assertRedirect(f.get("/auth/oidc/callback?state="+state), "/oauth/resume?error=server_error")
	})
}

// --- Extra 🔒 · the login redirect carries every required authorize parameter, url-encoded.
//
// Ktor's encodeURLParameter renders a space as %20; url.QueryEscape renders it as "+". `scope` is the
// space-separated string on every single login, so this is where that difference would surface.
func TestLogin_RedirectCarriesTheAuthorizeParameters(t *testing.T) {
	f := newCallbackFixture(t, true)
	resp := f.get("/auth/oidc/login")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	raw := resp.Header.Get("Location")
	if !strings.Contains(raw, "scope=openid%20profile%20email%20groups%20offline_access") {
		t.Errorf("scope is not %%20-encoded in %q — Go's QueryEscape would emit '+'", raw)
	}
	if !strings.Contains(raw, "redirect_uri=https%3A%2F%2Fcp.example.test%2Fauth%2Foidc%2Fcallback") {
		t.Errorf("redirect_uri is not fully encoded in %q", raw)
	}
	loc, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	q := loc.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("client_id") != "test-client" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if len(q.Get("nonce")) == 0 || q.Get("nonce") == q.Get("state") {
		t.Error("state and nonce must both be present and independently drawn")
	}
	// 24 bytes base64url-nopad = 32 characters. F27's KDoc says "32-byte"; the body is 24.
	if len(q.Get("state")) != 32 {
		t.Errorf("state is %d chars, want 32 (24 random bytes, base64url-nopad)", len(q.Get("state")))
	}
	// ⚠️ No PKCE, deliberately — a confidential client with a client_secret.
	if q.Has("code_challenge") {
		t.Error("the web flow must NOT send a code_challenge; restoring PKCE breaks the IdP registration")
	}
}

// --- Extra 🔒 · FailureTarget's full four-row matrix, directly.
func TestFailureTarget_Matrix(t *testing.T) {
	cases := []struct {
		name     string
		returnTo *string
		want     string
	}{
		{"resume takes the OAuth vocabulary", types.Ptr("/oauth/resume"), "/oauth/resume?error=access_denied"},
		{"reauth takes the pre-encoded literal", types.Ptr("/auth/reauth-complete"),
			"/login?error=state&callbackUrl=%2Fauth%2Freauth-complete"},
		{"any other continuation is preserved, encoded", types.Ptr("/auth/device/authorize?user_code=WDJB-MJHT"),
			"/login?error=state&return_to=%2Fauth%2Fdevice%2Fauthorize%3Fuser_code%3DWDJB-MJHT"},
		{"no continuation", nil, "/login?error=state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var st *OAuthStateSession
			if tc.returnTo != nil || tc.name == "no continuation" {
				st = &OAuthStateSession{State: "s", ReturnTo: tc.returnTo}
			}
			if got := FailureTarget(st, "access_denied", "state"); got != tc.want {
				t.Errorf("FailureTarget = %q, want %q", got, tc.want)
			}
		})
	}
	if got := FailureTarget(nil, "access_denied", "state"); got != "/login?error=state" {
		t.Errorf("FailureTarget(nil) = %q", got)
	}
}
