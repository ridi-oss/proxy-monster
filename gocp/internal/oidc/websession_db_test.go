package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// Port of OidcWebSessionDbTest.kt — 5 cases (04-auth-session-tokens.md §4.8): the callback's SUCCESS
// path, driven end-to-end against a REAL database.
//
// ORACLE: 04-auth-session-tokens.md §4.8's frozen case list, plus §6 steps 1-17 and INV-A4-14 /
// INV-A4-60 / INV-A4-61 / INV-A4-59 / INV-A4-46. No Java runtime here, so the case titles in that
// list are the oracle, not Kotlin output.
//
// 🔴 WHERE THE FIVE CASES LIVE. Cases 1-3 are the callback and are here. Cases 4 and 5 are the
// device-login interplay and CANNOT be here: internal/device imports internal/oidc (the
// `pm_device_verify` cookie is declared in control-plane/Oidc.kt, so its spec lives in this package),
// and Go forbids the cycle. They are ported in internal/device, which can see both halves:
//
//	case 4 (a device login with no session logs in via SSO and comes back to approve the handle,
//	        INV-A4-59) → internal/device TestSSO_DeviceLoginWithNoSessionCompletesThroughOidc, plus
//	        its decomposition in TestAuthorize_WithNoSessionGoesToLoginAndApprovesNothing and
//	        TestAuthorize_LoginRedirectKeepsTheVerifyCookie
//	case 5 (a direct authorize link with no device-page confirm approves no handle, INV-A4-46) →
//	        internal/device TestAuthorize_WithoutAPriorConfirmApprovesNothing
//
// 🔴 UNLIKE OidcCallbackTest, NOTHING HERE IS A DOUBLE ON THE SEAM SIDE. The provisioner is the real
// [DirectoryProvisioner], the role resolver is the real [identity.RoleResolver] over real
// `principal_role` / `group_role` rows, and the session store is the real [session.Store]. That is
// the point of the suite: the callback's step ORDER (provision → resolve → gate → mint) is only
// observable when each step actually writes.

// -------------------------------------------------------------------------------------------
// The composition-root adapter seams.go documents
// -------------------------------------------------------------------------------------------

// realWebSessions is the three-line-per-method adapter seams.go's [WebSessions] KDoc specifies,
// written out so this suite exercises the composition A1 will ship rather than a convenience double.
//
//	TODO(A1): lift this into the composition root verbatim — it is the whole adapter.
type realWebSessions struct {
	t       *testing.T
	store   *session.Store
	cookies *session.CookieCodec
	cfg     config.Config

	// lastSessionKey is the tracker id the fixture linked, so a case can assert the link happened.
	lastSessionKey string
}

func (s *realWebSessions) MintWeb(
	ctx context.Context, principal string, refreshToken *string, absoluteSeconds, idleSeconds int64, deviceID string,
) (int64, error) {
	return s.store.MintWeb(ctx, nil, session.MintWebInput{
		Principal:       principal,
		RefreshToken:    refreshToken,
		AbsoluteSeconds: absoluteSeconds,
		IdleSeconds:     idleSeconds,
		DeviceID:        &deviceID,
	})
}

// SetSessionCookie writes `pm_session` AND links the tracker id to the row.
//
// 🔒 BOTH halves, per seams.go: Ktor's session storage does the link implicitly, so a Go port that
// writes only the cookie leaves `session_key` NULL and /auth/logout's EndWebBySessionKey then ends
// nothing (INV-A4-7, INV-A4-25).
func (s *realWebSessions) SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID int64) error {
	if err := s.cookies.Set(w, session.SessionSpec(s.cfg.WebSessionAbsoluteSeconds),
		session.WebSessionRef{SessionID: sessionID}); err != nil {
		return err
	}
	key, err := RandomOpaqueToken()
	if err != nil {
		return err
	}
	s.lastSessionKey = key
	return s.store.LinkWebSessionKey(r.Context(), sessionID, key)
}

func (s *realWebSessions) EnsureDeviceCookie(w http.ResponseWriter, r *http.Request, secure bool) (string, error) {
	return session.EnsureDeviceCookie(w, r, secure)
}

// webGrantRoles is A6's `AccessStore.listGrants(principal, activeOnly).map { it.roleName }` — the
// same one-line adapter internal/query's suite documents under `TODO(A6)`. The REAL store, so a JIT
// grant would show up in Resolve exactly as it does in production; this suite seeds none, which is
// itself the fidelity point (case 2's zero-role principal must be zero through all THREE arms).
type webGrantRoles struct{ s *access.Store }

func (g webGrantRoles) ListGrantRoles(ctx context.Context, principal string, activeOnly bool) ([]string, error) {
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

type webFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *store.Db
	seed     *dbtest.Seed
	idp      *fakeIdP
	sessions *session.Store
	web      *realWebSessions
	server   *httptest.Server
	client   *http.Client
	cfg      config.Config

	// nonce is captured off the authorize redirect so the fake IdP can echo it into the id_token —
	// the round trip INV-A4-62's nonce check exists for.
	nonce string
	// refreshToken is what the token endpoint returns; "" omits the field entirely.
	refreshToken string
}

type webFixtureOpts struct {
	// scopes is `PM_OIDC_SCOPES`. INV-A4-61 filters on THIS string, never on what the IdP echoed.
	scopes string
	// withCrypto is INV-A4-14's `PM_RESULT_KEY`: false ⇒ session.Store has no Crypto ⇒ no refresh
	// token is ever persisted.
	withCrypto bool
	// refreshToken is the `refresh_token` the token endpoint returns; "" omits it.
	refreshToken string
}

func newWebFixture(t *testing.T, o webFixtureOpts) *webFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	idp := newFakeIdP(t, "web-kid")

	cfg := config.Defaults()
	cfg.SessionSecret = "oidc-websession-test-secret-not-for-prod"
	cfg.OIDC = &config.OIDCConfig{
		Issuer:       idp.issuer(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURI:  "https://cp.example.test/auth/oidc/callback",
		Scopes:       o.scopes,
		GroupMapping: config.OIDCGroupMapping{Map: map[string]string{}},
	}

	var crypto session.Crypto
	if o.withCrypto {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		c, err := result.NewCrypto(key)
		if err != nil {
			t.Fatalf("result crypto: %v", err)
		}
		crypto = c
		cfg.ResultKey = key
	}

	sessions := session.NewStore(db.Pool, session.Options{
		Crypto:                 crypto,
		WebSessionIdleSeconds:  cfg.WebSessionIdleSeconds,
		WebSessionSlideSeconds: cfg.WebSessionSlideSeconds,
	})
	users := identity.NewUserGroupStore(db.Pool)

	f := &webFixture{
		t: t, ctx: context.Background(), db: db,
		seed:         dbtest.NewSeed(t, db),
		idp:          idp,
		sessions:     sessions,
		cfg:          cfg,
		refreshToken: o.refreshToken,
	}
	f.web = &realWebSessions{t: t, store: sessions, cookies: session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()), cfg: cfg}

	// The IdP's token endpoint. It signs an id_token carrying the nonce THIS browser's authorize
	// redirect carried — the fake IdP's whole job on the success path.
	idp.mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		claims := idp.defaultClaims(cfg.OIDC.ClientID)
		claims.nonce = f.nonce
		body := map[string]any{
			"access_token": "unused",
			"id_token":     idp.sign(claims, nil),
		}
		if f.refreshToken != "" {
			body["refresh_token"] = f.refreshToken
		}
		idp.writeJSON(w, body)
	})

	hc := NewHTTPClient()
	discovery := NewDiscovery(hc, cfg.OIDC.Issuer)
	rt := &Routes{
		Config:     cfg,
		Discovery:  discovery,
		Validator:  NewIDTokenValidator(discovery, cfg.OIDC.Issuer, cfg.OIDC.ClientID, hc, discardLogger()),
		HTTP:       hc,
		Cookies:    session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		UserGroups: Provisioner{NewDirectoryProvisioner(db.Pool)},
		Roles:      identity.NewRoleResolver(db.Pool, users, webGrantRoles{access.NewStore(db.Pool)}),
		Sessions:   f.web,
		Log:        discardLogger(),
	}
	mux := http.NewServeMux()
	rt.Register(mux)
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
	return f
}

func (f *webFixture) get(path string) *http.Response {
	f.t.Helper()
	resp, err := f.client.Get(f.server.URL + path)
	if err != nil {
		f.t.Fatalf("GET %s: %v", path, err)
	}
	f.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// sso drives the WHOLE browser round trip: /auth/oidc/login → (the IdP, elided — the fake one has no
// consent screen) → /auth/oidc/callback, carrying the state + nonce cookies in the jar exactly as a
// browser would.
func (f *webFixture) sso(returnTo string) *http.Response {
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
		f.t.Fatalf("parse authorize Location: %v", err)
	}
	f.nonce = loc.Query().Get("nonce")
	state := loc.Query().Get("state")
	if f.nonce == "" || state == "" {
		f.t.Fatalf("authorize redirect carries no state/nonce: %s", resp.Header.Get("Location"))
	}
	return f.get("/auth/oidc/callback?code=the-authorization-code&state=" + url.QueryEscape(state))
}

// webRows is every principal_session WEB row, newest first.
type webRow struct {
	id         int64
	principal  string
	deviceID   *string
	refreshEnc []byte
	sessionKey *string
}

func (f *webFixture) webRows() []webRow {
	f.t.Helper()
	rows, err := f.db.Pool.Query(f.ctx,
		`SELECT id, principal, device_id, refresh_token_enc, session_key
		   FROM principal_session WHERE kind = 'WEB' ORDER BY id DESC`)
	if err != nil {
		f.t.Fatalf("read principal_session: %v", err)
	}
	defer rows.Close()
	var out []webRow
	for rows.Next() {
		var r webRow
		if err := rows.Scan(&r.id, &r.principal, &r.deviceID, &r.refreshEnc, &r.sessionKey); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *webFixture) onlyWebRow() webRow {
	f.t.Helper()
	rows := f.webRows()
	if len(rows) != 1 {
		f.t.Fatalf("principal_session WEB rows = %d, want exactly 1", len(rows))
	}
	return rows[0]
}

// cookieValue reads a cookie the jar holds for the test server.
func (f *webFixture) cookieValue(name string) string {
	f.t.Helper()
	u, err := url.Parse(f.server.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func (f *webFixture) assertRedirect(resp *http.Response, want string) {
	f.t.Helper()
	if resp.StatusCode != http.StatusFound {
		f.t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != want {
		f.t.Fatalf("Location = %q, want %q", got, want)
	}
}

// assertMintedSessionShape is the block Kotlin's `verifyCallback` helper runs after EVERY successful
// callback, and which both mapped cases therefore assert: the two Set-Cookie attribute sets and the
// minted row's clock arithmetic.
//
// 🔒 The cookie attributes are not cosmetic. `pm_session`'s Max-Age is the ABSOLUTE cap, so the browser
// stops presenting the cookie no later than the row stops resolving; `pm_did`'s 90 days outlive every
// session on purpose (it is the device correlator, not a credential), and its `HttpOnly` +
// `SameSite=Lax` + `Path=/` are what keep a script from reading it and a cross-site POST from
// replaying it. None of that is observable from the database.
func (f *webFixture) assertMintedSessionShape(resp *http.Response, row webRow) {
	f.t.Helper()

	var sessionCookie, deviceCookie *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case session.SessionCookie:
			sessionCookie = c
		case session.DeviceCookie:
			deviceCookie = c
		}
	}
	if sessionCookie == nil {
		f.t.Fatalf("the callback set no %s cookie", session.SessionCookie)
	}
	if int64(sessionCookie.MaxAge) != f.cfg.WebSessionAbsoluteSeconds {
		f.t.Errorf("%s Max-Age = %d, want %d — the cookie's lifetime is the row's ABSOLUTE cap",
			session.SessionCookie, sessionCookie.MaxAge, f.cfg.WebSessionAbsoluteSeconds)
	}
	if deviceCookie == nil {
		f.t.Fatalf("the callback set no %s cookie", session.DeviceCookie)
	}
	if deviceCookie.MaxAge != session.DeviceCookieMaxAgeSeconds {
		f.t.Errorf("%s Max-Age = %d, want %d (90 days)", session.DeviceCookie,
			deviceCookie.MaxAge, session.DeviceCookieMaxAgeSeconds)
	}
	if deviceCookie.Path != "/" {
		f.t.Errorf("%s Path = %q, want \"/\" — a narrower path makes the bind unenforceable on other routes",
			session.DeviceCookie, deviceCookie.Path)
	}
	if !deviceCookie.HttpOnly {
		f.t.Errorf("%s is not HttpOnly", session.DeviceCookie)
	}
	if deviceCookie.SameSite != http.SameSiteLaxMode {
		f.t.Errorf("%s SameSite = %v, want Lax", session.DeviceCookie, deviceCookie.SameSite)
	}

	// The row's clocks. The idle window is exactly `PM_WEB_SESSION_IDLE` past created_at and the
	// absolute cap is strictly later — a mint that set them equal (or reversed) would make the
	// session's idle slide meaningless.
	var idleOffset float64
	var absoluteAfterIdle bool
	if err := f.db.Pool.QueryRow(f.ctx, `
		SELECT extract(epoch from (idle_expires_at - created_at)),
		       absolute_expires_at > idle_expires_at
		  FROM principal_session WHERE id = $1`, row.id,
	).Scan(&idleOffset, &absoluteAfterIdle); err != nil {
		f.t.Fatalf("read the minted row's clocks: %v", err)
	}
	if want := float64(f.cfg.WebSessionIdleSeconds); idleOffset < want-1 || idleOffset > want+1 {
		f.t.Errorf("idle_expires_at - created_at = %.3fs, want %.0fs (PM_WEB_SESSION_IDLE)", idleOffset, want)
	}
	if !absoluteAfterIdle {
		f.t.Error("absolute_expires_at is not after idle_expires_at; the absolute cap must outlive the idle window")
	}
}

// assertBoundAndLinked is the other half of Kotlin's per-callback block: `device_id` equals the
// browser's `pm_did` and `session_key` is non-NULL. Both are part of "a web row was minted" on EVERY
// arm — the device bind is what INV-A4-8/INV-A4-19 enforce, and the tracker link is what makes
// /auth/logout able to end the row at all (INV-A4-25).
func (f *webFixture) assertBoundAndLinked(row webRow) {
	f.t.Helper()

	did := f.cookieValue(session.DeviceCookie)
	if did == "" {
		f.t.Fatal("no pm_did cookie was issued")
	}
	if row.deviceID == nil || *row.deviceID != did {
		f.t.Errorf("device_id = %v, want the pm_did cookie %q", row.deviceID, did)
	}
	if row.sessionKey == nil || *row.sessionKey != f.web.lastSessionKey {
		f.t.Errorf("session_key = %v, want the linked tracker id %q", row.sessionKey, f.web.lastSessionKey)
	}
	if f.cookieValue(session.SessionCookie) == "" {
		f.t.Error("no pm_session cookie was issued")
	}
}

// grantARole makes the fixture's principal role-bearing THROUGH THE GROUP CLAIM, which is the only
// path a first-ever SSO login has: the `engineering` group claim provisions membership, and this
// pre-existing group_role link is what turns that membership into a role. A direct principal_role
// assignment would work too and would test less — it would pass even if provisioning never ran.
func (f *webFixture) grantARole() {
	f.t.Helper()
	gid := f.seed.Group("engineering")
	rid := f.seed.Role("analyst")
	f.seed.GroupRole(gid, rid)
}

// --- Case 1 · `oidc callback mints web row and stores refresh only when encrypted offline access is
// available` (INV-A4-14, INV-A4-61)
//
// The title states a CONJUNCTION, and each sub-case knocks out one conjunct. All three run the same
// successful login; only the storage of the refresh token differs.
// KT: OidcWebSessionDbTest.kt#oidc callback mints web row and stores refresh only when encrypted offline access is available
func TestOidcCallback_MintsAWebRowAndStoresRefreshOnlyWhenEncryptedOfflineAccessIsAvailable(t *testing.T) {
	t.Run("offline_access requested and a result key configured — the refresh token is stored, encrypted", func(t *testing.T) {
		f := newWebFixture(t, webFixtureOpts{
			scopes:       "openid profile email groups offline_access",
			withCrypto:   true,
			refreshToken: "the-idp-refresh-token",
		})
		f.grantARole()

		// The principal is the EMAIL claim, not the subject — Oidc.kt's `claims.email ?: subject`.
		resp := f.sso("")
		f.assertRedirect(resp, "/")

		row := f.onlyWebRow()
		if row.principal != "alice@example.com" {
			t.Errorf("principal = %q, want the email claim", row.principal)
		}
		f.assertMintedSessionShape(resp, row)
		if len(row.refreshEnc) == 0 {
			t.Fatal("refresh_token_enc is NULL — offline_access + a result key must persist it")
		}
		got, err := f.sessions.WebRefreshToken(f.ctx, row.id)
		if err != nil {
			t.Fatalf("WebRefreshToken: %v", err)
		}
		if got == nil || *got != "the-idp-refresh-token" {
			t.Errorf("stored refresh token = %v, want the IdP's", got)
		}

		// 🔒 INV-A4-8 / INV-A4-19 — the row is BOUND to the browser's pm_did, so a later resolve
		// from a different browser fails. A mint that stored NULL here would pass every other
		// assertion in this file and break the bind silently.
		did := f.cookieValue(session.DeviceCookie)
		if did == "" {
			t.Fatal("no pm_did cookie was issued")
		}
		if row.deviceID == nil || *row.deviceID != did {
			t.Errorf("device_id = %v, want the pm_did cookie %q", row.deviceID, did)
		}

		// 🔒 INV-A4-25 — the tracker id is LINKED, not just written to the cookie. Without this,
		// /auth/logout's EndWebBySessionKey ends nothing.
		if row.sessionKey == nil || *row.sessionKey != f.web.lastSessionKey {
			t.Errorf("session_key = %v, want the linked tracker id %q", row.sessionKey, f.web.lastSessionKey)
		}
		if f.cookieValue(session.SessionCookie) == "" {
			t.Error("no pm_session cookie was issued")
		}
	})

	t.Run("offline_access NOT in the configured scopes — an unbidden refresh token is dropped", func(t *testing.T) {
		// 🔒 INV-A4-61. The IdP returns one anyway, which is the whole point: the predicate is on
		// the CONFIGURED scope string, not on what came back.
		f := newWebFixture(t, webFixtureOpts{
			scopes:       "openid profile email groups",
			withCrypto:   true,
			refreshToken: "the-idp-refresh-token",
		})
		f.grantARole()

		resp := f.sso("")
		f.assertRedirect(resp, "/")

		row := f.onlyWebRow()
		// Kotlin's `verifyCallback` runs the SAME success block for this arm, so the mint is asserted to
		// be a full one: only the refresh token differs between the three arms, never the cookies, the
		// clocks, the device bind or the tracker link.
		f.assertMintedSessionShape(resp, row)
		f.assertBoundAndLinked(row)
		if len(row.refreshEnc) != 0 {
			t.Error("refresh_token_enc is set — an IdP that returns a refresh token unbidden must not get it persisted")
		}
	})

	t.Run("no result key — INV-A4-14 drops the refresh token even with offline_access", func(t *testing.T) {
		f := newWebFixture(t, webFixtureOpts{
			scopes:       "openid profile email groups offline_access",
			withCrypto:   false,
			refreshToken: "the-idp-refresh-token",
		})
		f.grantARole()

		resp := f.sso("")
		f.assertRedirect(resp, "/")

		row := f.onlyWebRow()
		// Same again: a deployment with no PM_RESULT_KEY still gets a FULL web session — the dropped
		// refresh token is the only difference. A port that failed the mint (or degraded its clocks) when
		// crypto is absent would lock out every keyless deployment.
		f.assertMintedSessionShape(resp, row)
		f.assertBoundAndLinked(row)
		if len(row.refreshEnc) != 0 {
			t.Error("refresh_token_enc is set with no crypto configured — INV-A4-14 says a refresh token is NEVER stored in plaintext")
		}
	})
}

// --- Case 2 🔒 · `oidc callback denies a principal with zero effective roles without minting a
// session` (INV-A4-60)
// KT: OidcWebSessionDbTest.kt#oidc callback denies a principal with zero effective roles without minting a session
func TestOidcCallback_ZeroEffectiveRolesMintsNothing(t *testing.T) {
	f := newWebFixture(t, webFixtureOpts{
		scopes:       "openid profile email groups offline_access",
		withCrypto:   true,
		refreshToken: "the-idp-refresh-token",
	})
	// Deliberately NO grantARole(): the `engineering` group is created by the provisioner, has no
	// group_role link, the principal has no principal_role row and no access_grant. Zero through
	// all three arms of RoleResolver.Resolve.

	f.assertRedirect(f.sso(""), "/login?error=no_access")

	// 🔒 The ordering assertion. Step 12 (the role gate) runs BEFORE step 15 (the mint), so the
	// no-access screen is reached with NO principal_session row. Minting first and checking second
	// would leave a live cookie for an unauthorized user.
	if rows := f.webRows(); len(rows) != 0 {
		t.Fatalf("principal_session WEB rows = %d, want 0 — a zero-role principal must not get a session", len(rows))
	}
	// The Kotlin counts `principal_session` for the principal with NO kind predicate, so a refused login
	// must leave no session row of ANY kind behind — not a DAEMON row either.
	var anyKind int
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM principal_session WHERE principal = 'alice@example.com'`).Scan(&anyKind); err != nil {
		t.Fatal(err)
	}
	if anyKind != 0 {
		t.Errorf("principal_session rows of any kind for the refused principal = %d, want 0", anyKind)
	}
	if f.cookieValue(session.SessionCookie) != "" {
		t.Error("a pm_session cookie was issued to a principal with no effective roles")
	}

	// ⚠️ …and the OTHER half of the same ordering: step 11 (provision) runs BEFORE the gate, so a
	// refused login STILL creates the directory user and its groups. That is not a bug to fix here;
	// it is what makes "grant them a role and they can log in" work without a second login.
	var users int
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM app_user WHERE principal = 'alice@example.com'`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 1 {
		t.Errorf("app_user rows for the refused principal = %d, want 1 — provisioning precedes the role gate", users)
	}
}

// --- Case 3 · `oidc callback returns a successful popup reauth to its landing route`
//
// 🔒 INV-A4-59 — the continuation survives the whole round trip in the SIGNED state cookie, and it is
// an allowlisted value, never an echo of the query string. The success redirect is the bare
// `returnTo`, NOT a FailureTarget-shaped URL.
// KT: OidcWebSessionDbTest.kt#oidc callback returns a successful popup reauth to its landing route
func TestOidcCallback_SuccessfulPopupReauthReturnsToItsLandingRoute(t *testing.T) {
	// The Kotlin runs this case through `verifyCallback(… offline_access, resultKey, expectRefresh =
	// true)`, so a reauth is asserted to be a FULL login: same cookies, same clocks, and the refresh
	// token re-stored. A reauth that landed on the right route but minted a degraded row would answer
	// the popup and then fail the daemon's IdP-liveness recheck.
	f := newWebFixture(t, webFixtureOpts{
		scopes:       "openid profile email groups offline_access",
		withCrypto:   true,
		refreshToken: "the-reauth-refresh-token",
	})
	f.grantARole()

	resp := f.sso("/auth/reauth-complete")
	f.assertRedirect(resp, "/auth/reauth-complete")

	if len(f.webRows()) != 1 {
		t.Fatalf("a successful popup reauth must still mint exactly one web row, got %d", len(f.webRows()))
	}
	row := f.onlyWebRow()
	f.assertMintedSessionShape(resp, row)
	if row.principal != "alice@example.com" {
		t.Errorf("principal = %q, want the email claim", row.principal)
	}
	// expectRefresh = true: offline_access is configured and a key exists, so the reauth re-stores it.
	if len(row.refreshEnc) == 0 {
		t.Error("refresh_token_enc is NULL on a reauth with offline_access + a result key")
	}
	if got, err := f.sessions.WebRefreshToken(f.ctx, row.id); err != nil || got == nil || *got != "the-reauth-refresh-token" {
		t.Errorf("the reauth's stored refresh token = %v, %v; want the IdP's", got, err)
	}
	// The device bind and the tracker link are part of "a web row was minted", not extras.
	did := f.cookieValue(session.DeviceCookie)
	if row.deviceID == nil || *row.deviceID != did {
		t.Errorf("device_id = %v, want the pm_did cookie %q", row.deviceID, did)
	}
	if row.sessionKey == nil || *row.sessionKey != f.web.lastSessionKey {
		t.Errorf("session_key = %v, want the linked tracker id %q", row.sessionKey, f.web.lastSessionKey)
	}

	t.Run("the OAuth AS resume continuation lands the same way", func(t *testing.T) {
		f := newWebFixture(t, webFixtureOpts{scopes: "openid profile email groups", withCrypto: true})
		f.grantARole()
		f.assertRedirect(f.sso("/oauth/resume"), "/oauth/resume")
	})

	t.Run("a non-allowlisted continuation is dropped and the login lands on /", func(t *testing.T) {
		// The open-redirect guard, asserted on the SUCCESS path rather than only in ReturnTarget's
		// unit test: if the allowlist were bypassed anywhere in the round trip, this is where a
		// browser would actually be sent to the attacker.
		f := newWebFixture(t, webFixtureOpts{scopes: "openid profile email groups", withCrypto: true})
		f.grantARole()
		f.assertRedirect(f.sso("https://evil.example/callback"), "/")
	})
}

// --- The success path's own regression guard: the id_token is the ONLY identity source.
//
// 🔒 INV-A4-60's first half. The fake IdP serves a userinfo_endpoint (support_test.go advertises one
// in the discovery document), and the callback must never call it — identity comes from the signed
// id_token or not at all. A port that "enriched" the claims from userinfo would take an unsigned
// claim set on an authentication path.
func TestOidcCallback_NeverCallsTheUserinfoEndpoint(t *testing.T) {
	f := newWebFixture(t, webFixtureOpts{scopes: "openid profile email groups", withCrypto: true})
	f.grantARole()

	var userinfoHits int
	f.idp.mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		userinfoHits++
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "user-123"})
	})

	f.assertRedirect(f.sso(""), "/")

	if userinfoHits != 0 {
		t.Errorf("userinfo was called %d time(s); identity must come from the id_token only", userinfoHits)
	}
}
