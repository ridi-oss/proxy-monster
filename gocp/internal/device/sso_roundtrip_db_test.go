package device

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/oidc"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

// OidcWebSessionDbTest.kt case 4 — "a device login with no session logs in via SSO and comes back to
// approve the handle" (INV-A4-59), plus case 5's counterpart assertion on the same wiring.
//
// ORACLE: 04-auth-session-tokens.md §4.8's frozen case list; the branch-4 analysis quoted in
// [Routes.Authorize]'s KDoc ("Clear it here and the whole SSO-then-approve path breaks: every
// first-time `pmon login` loops between /login and /device forever").
//
// 🔴 WHY THIS LIVES IN internal/device AND NOT internal/oidc. The case spans both route sets, and
// internal/device imports internal/oidc (the `pm_device_verify` cookie is declared in
// control-plane/Oidc.kt, so its spec lives there). Only this side of the edge can see both. The
// oidc-side cases 1-3 are in internal/oidc/websession_db_test.go, which cross-references here.
//
// 🔴 WHY A SECOND FIXTURE RATHER THAN AN OPTION ON [newDeviceFixture]. This one resolves the web
// session from the REAL signed `pm_session` cookie, because that is the cookie the OIDC callback
// writes — the DeviceLoginStoreDbTest fixture's plaintext `pm_session_test` shortcut cannot receive
// an SSO login at all. Duplicated wiring is the port-policy-cheaper of the two: threading a mode flag
// through the shared fixture would change what 29 already-passing cases exercise.

// -------------------------------------------------------------------------------------------
// A fake IdP, enough for one successful authorization-code round trip
// -------------------------------------------------------------------------------------------

// ssoIdP serves discovery + JWKS + token. It is a second, smaller copy of internal/oidc's
// `fakeIdP` because that one is an unexported test helper in another package; the shape is the same
// (a real loopback socket, RS256, one kid) since the JWKS fetch is real HTTP either way.
type ssoIdP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	// nonce is set from the authorize redirect before the token exchange, so the id_token echoes the
	// nonce THIS browser's login generated. Without the echo the callback fails closed at
	// INV-A4-62's nonce check and the round trip never completes — which is the check working.
	nonce string
	// principal is the `email` claim, i.e. the identity the whole flow ends up approving with.
	principal string
	// groups is the `groups` claim; membership in one of these is what produces a role.
	groups []string
}

const ssoKid = "sso-roundtrip-kid"

func newSSOIdP(t *testing.T, principal string, groups []string) *ssoIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	idp := &ssoIdP{t: t, key: key, principal: principal, groups: groups}
	mux := http.NewServeMux()
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)

	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		idp.writeJSON(w, map[string]any{
			"issuer":                 idp.server.URL,
			"authorization_endpoint": idp.server.URL + "/authorize",
			"token_endpoint":         idp.server.URL + "/token",
			"jwks_uri":               idp.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: ssoKid, Algorithm: string(jose.RS256), Use: "sig",
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		idp.writeJSON(w, map[string]any{
			"access_token":  "unused",
			"refresh_token": "the-idp-refresh-token",
			"id_token":      idp.signIDToken(),
		})
	})
	return idp
}

func (f *ssoIdP) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Errorf("fake IdP write: %v", err)
	}
}

func (f *ssoIdP) signIDToken() string {
	f.t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss":    f.server.URL,
		"aud":    "test-client",
		"sub":    "user-123",
		"email":  f.principal,
		"nonce":  f.nonce,
		"groups": f.groups,
		"exp":    time.Now().Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", ssoKid),
	)
	if err != nil {
		f.t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// -------------------------------------------------------------------------------------------
// The two A4 seams, over the REAL signed pm_session cookie
// -------------------------------------------------------------------------------------------

// signedWebLogin is `ApplicationCall.webSession()` (Auth.kt:413) over the real cookie: decode
// `pm_session` with the production codec, then resolve through the real store WITH the request's
// pm_did, so INV-A4-19's bind is enforced exactly as in production.
//
// It is closer to Auth.kt than [testWebLogin] is, and deliberately so — this suite's whole subject is
// the handoff between the OIDC callback's cookie write and the device route's cookie read.
type signedWebLogin struct {
	store   *session.Store
	cookies *session.CookieCodec
}

func (s signedWebLogin) WebSession(ctx context.Context, r *http.Request) (*WebSession, error) {
	var ref session.WebSessionRef
	if err := s.cookies.Read(r, session.SessionSpec(0), &ref); err != nil {
		// A missing, forged, malformed or pre-cutover-shaped cookie all collapse to "no session",
		// as Ktor's `sessions.get<WebSessionRef>()` does (INV-A4-2).
		return nil, nil
	}
	row, err := s.store.ResolveWeb(ctx, ref.SessionID, session.DeviceCookieID(r))
	if err != nil || row == nil {
		return nil, err
	}
	return &WebSession{ID: row.ID, Principal: row.Principal}, nil
}

// ssoWebSessions is the [oidc.WebSessions] adapter — the same three-line-per-method composition
// internal/oidc's seams.go specifies.
type ssoWebSessions struct {
	store   *session.Store
	cookies *session.CookieCodec
	cfg     config.Config
}

func (s ssoWebSessions) MintWeb(
	ctx context.Context, principal string, refreshToken *string, absoluteSeconds, idleSeconds int64, deviceID string,
) (int64, error) {
	return s.store.MintWeb(ctx, nil, session.MintWebInput{
		Principal: principal, RefreshToken: refreshToken,
		AbsoluteSeconds: absoluteSeconds, IdleSeconds: idleSeconds, DeviceID: &deviceID,
	})
}

func (s ssoWebSessions) SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID int64) error {
	if err := s.cookies.Set(w, session.SessionSpec(s.cfg.WebSessionAbsoluteSeconds),
		session.WebSessionRef{SessionID: sessionID}); err != nil {
		return err
	}
	key, err := oidc.RandomOpaqueToken()
	if err != nil {
		return err
	}
	return s.store.LinkWebSessionKey(r.Context(), sessionID, key)
}

func (s ssoWebSessions) EnsureDeviceCookie(w http.ResponseWriter, r *http.Request, secure bool) (string, error) {
	return session.EnsureDeviceCookie(w, r, secure)
}

type ssoGrantRoles struct{ s *access.Store }

func (g ssoGrantRoles) ListGrantRoles(ctx context.Context, principal string, activeOnly bool) ([]string, error) {
	grants, err := g.s.ListGrants(ctx, &principal, activeOnly)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(grants))
	for _, gr := range grants {
		out = append(out, gr.RoleName)
	}
	return out, nil
}

// -------------------------------------------------------------------------------------------
// Fixture
// -------------------------------------------------------------------------------------------

type ssoFixture struct {
	t      *testing.T
	ctx    context.Context
	db     *store.Db
	store  *LoginStore
	idp    *ssoIdP
	server *httptest.Server
	client *http.Client
}

const ssoPrincipal = "alice@example.com"

func newSSOFixture(t *testing.T) *ssoFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	idp := newSSOIdP(t, ssoPrincipal, []string{"engineering"})

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	crypto, err := result.NewCrypto(key)
	if err != nil {
		t.Fatalf("result crypto: %v", err)
	}

	cfg := config.Defaults()
	cfg.SessionSecret = "sso-roundtrip-secret-not-for-prod!!!"
	cfg.SessionWindowSeconds = 3600
	cfg.ResultKey = key
	cfg.OIDC = &config.OIDCConfig{
		Issuer:       idp.server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       "openid profile email groups offline_access",
		RedirectURI:  "https://cp.example.test/auth/oidc/callback",
		GroupMapping: config.OIDCGroupMapping{Map: map[string]string{}},
	}

	sessions := session.NewStore(db.Pool, session.Options{
		Crypto:                 crypto,
		WebSessionIdleSeconds:  cfg.WebSessionIdleSeconds,
		WebSessionSlideSeconds: cfg.WebSessionSlideSeconds,
	})
	cookies := session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer())
	users := identity.NewUserGroupStore(db.Pool)

	f := &ssoFixture{t: t, ctx: context.Background(), db: db, store: NewLoginStore(db.Pool, crypto), idp: idp}

	mux := http.NewServeMux()
	(&Routes{
		Config:   cfg,
		Store:    f.store,
		Web:      signedWebLogin{store: sessions, cookies: cookies},
		Sessions: sessions,
		Tokens:   token.NewStore(db.Pool),
		Minter:   testMinter{db: db.Pool, users: users},
		Cookies:  cookies,
	}).Register(mux)

	hc := oidc.NewHTTPClient()
	discovery := oidc.NewDiscovery(hc, cfg.OIDC.Issuer)
	(&oidc.Routes{
		Config:     cfg,
		Discovery:  discovery,
		Validator:  oidc.NewIDTokenValidator(discovery, cfg.OIDC.Issuer, cfg.OIDC.ClientID, hc, ssoDiscardLogger()),
		HTTP:       hc,
		Cookies:    cookies,
		UserGroups: oidc.Provisioner{DirectoryProvisioner: oidc.NewDirectoryProvisioner(db.Pool)},
		Roles:      identity.NewRoleResolver(db.Pool, users, ssoGrantRoles{access.NewStore(db.Pool)}),
		Sessions:   ssoWebSessions{store: sessions, cookies: cookies, cfg: cfg},
		Log:        ssoDiscardLogger(),
	}).Register(mux)

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	f.client = &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// The `engineering` group claim is what earns the role. The group_role link pre-exists; the
	// membership is created by the OIDC provisioner during the callback.
	seed := dbtest.NewSeed(t, db)
	seed.GroupRole(seed.Group("engineering"), seed.Role("analyst"))
	return f
}

func (f *ssoFixture) do(method, path, body string) *http.Response {
	f.t.Helper()
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, f.server.URL+path, strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequest(method, f.server.URL+path, nil)
	}
	if err != nil {
		f.t.Fatalf("build %s %s: %v", method, path, err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	f.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// statusOf reads a handle's status straight from the store, the same read
// [deviceFixture.statusOf] does.
func (f *ssoFixture) statusOf(handle string) string {
	f.t.Helper()
	row, err := f.store.Get(f.ctx, handle)
	if err != nil {
		f.t.Fatalf("Get(%q): %v", handle, err)
	}
	if row == nil {
		f.t.Fatalf("no device_login row for %q", handle)
	}
	return row.Status
}

// ssoLogin is the browser leg the CONSOLE owns in production: /login is the web console's page, not a
// control-plane route, and all it does is send the browser on to /auth/oidc/login carrying the same
// return_to. This helper is that hop, and nothing more — it must not be read as a CP route.
func (f *ssoFixture) ssoLogin(consoleLoginURL string) *http.Response {
	f.t.Helper()
	u, err := url.Parse(consoleLoginURL)
	if err != nil {
		f.t.Fatalf("parse the console login URL: %v", err)
	}
	returnTo := u.Query().Get("return_to")
	if returnTo == "" {
		f.t.Fatalf("the login redirect carries no return_to: %s", consoleLoginURL)
	}

	resp := f.do(http.MethodGet, "/auth/oidc/login?return_to="+url.QueryEscape(returnTo), "")
	authorize, err := url.Parse(location(f.t, resp))
	if err != nil {
		f.t.Fatalf("parse the authorize redirect: %v", err)
	}
	// The IdP's job: echo this browser's nonce back inside the id_token.
	f.idp.nonce = authorize.Query().Get("nonce")
	state := authorize.Query().Get("state")
	if f.idp.nonce == "" || state == "" {
		f.t.Fatalf("authorize redirect carries no state/nonce: %s", authorize.String())
	}
	return f.do(http.MethodGet, "/auth/oidc/callback?code=the-code&state="+url.QueryEscape(state), "")
}

// ssoDiscardLogger keeps the OIDC routes' log lines out of the test output. internal/device itself
// takes no logger at all — F33's reproduced silence — so this exists only for the oidc half.
func ssoDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- OidcWebSessionDbTest case 4 · `a device login with no session logs in via SSO and comes back to
// approve the handle` (INV-A4-59)
//
// The full first-time `pmon login`: no console session anywhere, no app_user row, no groups. Every
// hop is a real request against a real database and a real (fake) IdP.
//
// KT: OidcWebSessionDbTest.kt#a device login with no session logs in via SSO and comes back to approve the handle
//
//	The case cannot live in internal/oidc — internal/device imports internal/oidc and Go forbids the
//	cycle — so oidc/websession_db_test.go's header hands it here. Its decomposition in
//	TestAuthorize_WithNoSessionGoesToLoginAndApprovesNothing and
//	TestAuthorize_LoginRedirectKeepsTheVerifyCookie is a split of the same case.
func TestSSO_DeviceLoginWithNoSessionCompletesThroughOidc(t *testing.T) {
	f := newSSOFixture(t)

	// 1. pmon starts the login.
	resp := f.do(http.MethodPost, "/auth/device/start", "{}")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start status = %d, want 200", resp.StatusCode)
	}
	var start StartResponse
	decode(t, resp, &start)

	// 2. The human opens the console's /device page, which confirms the code and gets the
	//    pm_device_verify cookie.
	if got := f.do(http.MethodPost, "/auth/device/confirm",
		`{"userCode":"`+start.UserCode+`"}`).StatusCode; got != http.StatusOK {
		t.Fatalf("confirm status = %d, want 200", got)
	}

	// 3. Authorize with NO console session — branch 4. It approves nothing and sends the browser to
	//    /login carrying this exact URL as its continuation.
	authorizePath := "/auth/device/authorize?user_code=" + start.UserCode
	loginRedirect := location(t, f.do(http.MethodGet, authorizePath, ""))
	if want := "/login?return_to=" + url.QueryEscape(authorizePath); loginRedirect != want {
		// encodeURLParameter and url.QueryEscape differ on spaces only, and a user code has none.
		t.Fatalf("login redirect = %q, want %q", loginRedirect, want)
	}
	if f.statusOf(start.Handle) != StatusPending {
		t.Fatal("the no-session bounce approved the handle")
	}

	// 4. SSO. The console forwards to /auth/oidc/login, the IdP round-trips, the callback provisions
	//    the user + group, resolves the role, mints the web session and honours the continuation.
	//
	// 🔒 INV-A4-59 — the continuation survives inside the SIGNED state cookie and is allowlisted on
	// the way in. `/auth/device/authorize?user_code=…` is the third accepted shape; if it were not,
	// the user would land on "/" and the handle would strand until it expired.
	back := location(t, f.ssoLogin(loginRedirect))
	if back != authorizePath {
		t.Fatalf("the OIDC callback returned to %q, want the device continuation %q", back, authorizePath)
	}

	// 5. Back on authorize, now WITH a session — and still with the verify cookie, because branch 4
	//    deliberately did not clear it. This is the assertion that catches the "clear it on every
	//    terminating branch" over-tightening: with the cookie gone, this hop falls to branch 2 and
	//    every first-time pmon login loops between /login and /device forever.
	if got := location(t, f.do(http.MethodGet, authorizePath, "")); got != "/device/success" {
		t.Fatalf("the post-SSO authorize landed on %q, want /device/success", got)
	}
	if f.statusOf(start.Handle) != StatusApproved {
		t.Fatal("the post-SSO authorize did not approve the handle")
	}

	// 🔒 The Kotlin's last two assertions, on the APPROVED ROW itself.
	//
	//   - it is approved FOR THE SSO PRINCIPAL, never a debug default: the row is what the poll mints
	//     from, so a row carrying the wrong principal is a credential issued to the wrong person;
	//   - the approving session's IdP REFRESH TOKEN rode onto the device login. Without it the daemon
	//     session minted at poll has nothing for its timer-driven IdP-liveness revalidation to run, so a
	//     deprovisioned user's `pmon` session would never be revalidated against the IdP.
	approved, err := f.store.Get(f.ctx, start.Handle)
	if err != nil || approved == nil {
		t.Fatalf("read the approved device_login row: %v (row %v)", err, approved)
	}
	if approved.Principal == nil || *approved.Principal != ssoPrincipal {
		t.Errorf("the approved row's principal = %v, want the SSO principal %q", approved.Principal, ssoPrincipal)
	}
	refresh, err := f.store.DecryptRefresh(approved)
	if err != nil {
		t.Fatalf("decrypt the carried refresh token: %v", err)
	}
	if refresh == nil || *refresh != "the-idp-refresh-token" {
		t.Errorf("the device login's refresh token = %v, want the IdP's %q carried on for daemon "+
			"IdP-liveness", refresh, "the-idp-refresh-token")
	}

	// 6. pmon polls and gets its token, minted for the principal the ID TOKEN named — never one the
	//    device flow could assert (INV-A4-4: there is no principal in any request body anywhere).
	pollResp := f.do(http.MethodPost, "/auth/device/poll", `{"handle":"`+start.Handle+`"}`)
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("poll status = %d, want 200", pollResp.StatusCode)
	}
	var polled PollResult
	decode(t, pollResp, &polled)
	if polled.Token == "" || polled.RenewalToken == "" {
		t.Fatalf("poll returned no credential pair: %+v", polled)
	}
	if polled.Principal != ssoPrincipal {
		t.Errorf("minted for %q, want the id_token's email claim %q", polled.Principal, ssoPrincipal)
	}

	var daemonRows int
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM principal_session WHERE kind = 'DAEMON' AND principal = $1`,
		ssoPrincipal).Scan(&daemonRows); err != nil {
		t.Fatal(err)
	}
	if daemonRows != 1 {
		t.Errorf("daemon session rows = %d, want exactly 1", daemonRows)
	}
}

// --- OidcWebSessionDbTest case 5 🔒 · `a direct authorize link with no device-page confirm approves
// no handle` (INV-A4-46) — asserted here on the SSO-capable wiring.
//
// DeviceLoginStoreDbTest case 9 already pins the no-cookie bounce with no session at all. This is the
// sharper version and the actual phishing scenario: the victim HAS a live console session, and the
// attacker mails them a bare `/auth/device/authorize?user_code=…` for a handle the attacker started.
// The only thing standing between that link and a stolen `pmon` credential is the verify cookie.
func TestSSO_ADirectAuthorizeLinkWithALiveSessionStillApprovesNothing(t *testing.T) {
	f := newSSOFixture(t)

	// The attacker's handle, started from somewhere else entirely.
	resp := f.do(http.MethodPost, "/auth/device/start", "{}")
	var attacker StartResponse
	decode(t, resp, &attacker)

	// The victim signs in normally — a console login with no device flow involved at all.
	victimLogin := "/login?return_to=" + url.QueryEscape("/oauth/resume")
	if got := location(t, f.ssoLogin(victimLogin)); got != "/oauth/resume" {
		t.Fatalf("the plain console login landed on %q", got)
	}

	// …and then follows the mailed link. A live session, a real pending handle, and NO confirm.
	got := location(t, f.do(http.MethodGet, "/auth/device/authorize?user_code="+attacker.UserCode, ""))
	if want := "/device?user_code=" + attacker.UserCode; got != want {
		t.Fatalf("the phishing link landed on %q, want the device page %q", got, want)
	}
	if f.statusOf(attacker.Handle) != StatusPending {
		t.Fatal("a direct authorize link approved a handle the user never confirmed on /device")
	}

	// And the credential is not obtainable: the poll still reads as pending.
	pollResp := f.do(http.MethodPost, "/auth/device/poll", `{"handle":"`+attacker.Handle+`"}`)
	if pollResp.StatusCode != http.StatusAccepted {
		t.Fatalf("poll status = %d, want 202 (still pending)", pollResp.StatusCode)
	}
}
