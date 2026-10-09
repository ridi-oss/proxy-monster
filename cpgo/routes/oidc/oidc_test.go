package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/idp"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/fakeidp"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/oidc"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

func setupOIDC(t *testing.T) (*routetest.Env, *fakeidp.IdP, *idp.Crypto, *idp.Provider) {
	t.Helper()
	return setupOIDCWith(t, "openid profile email groups offline_access", true, dbtest.Settings)
}

// setupOIDCWith is setupOIDC with the scopes, whether refresh tokens can be stored, and the session settings.
func setupOIDCWith(t *testing.T, scopes string, withCrypto bool, settings session.Settings) (*routetest.Env, *fakeidp.IdP, *idp.Crypto, *idp.Provider) {
	t.Helper()
	fake := fakeidp.New(t)
	var crypto *idp.Crypto
	if withCrypto {
		t.Setenv("PM_RESULT_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
		var err error
		if crypto, err = idp.CryptoFromEnv(); err != nil {
			t.Fatal(err)
		}
	}
	provider := idp.NewProvider(idp.Config{
		Issuer: fake.URL, ClientID: fake.ClientID, ClientSecret: fake.ClientSecret, RedirectURI: "http://cp.example/auth/oidc/callback",
		Scopes: scopes, RecheckInterval: time.Minute,
		Groups: idp.ParseGroupMapping("idp-eng=eng", "okta-"),
	})
	e := routetest.SetupSettings(t, settings, nil, oidc.Login{Provider: provider, Crypto: crypto})
	if _, err := e.St.Pool.Exec(context.Background(), `INSERT INTO app_role (name) VALUES ('analyst');
		INSERT INTO app_group (name) VALUES ('eng');
		INSERT INTO group_role (group_id, role_id) SELECT g.id, r.id FROM app_group g, app_role r WHERE g.name = 'eng' AND r.name = 'analyst'`); err != nil {
		t.Fatal(err)
	}
	return e, fake, crypto, provider
}

// startLogin follows /auth/oidc/login to the IdP and returns the authorize query.
func startLogin(t *testing.T, b *routetest.Browser, returnTo string) url.Values {
	t.Helper()
	path := "/auth/oidc/login"
	if returnTo != "" {
		path += "?return_to=" + url.QueryEscape(returnTo)
	}
	resp, body := b.NoFollow(http.MethodGet, path)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || body != "" || loc == nil {
		t.Fatalf("login: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	return loc.Query()
}

func TestOIDCLogin(t *testing.T) {
	e, fake, crypto, _ := setupOIDC(t)
	ctx := context.Background()
	b := e.Browser(t)

	q := startLogin(t, b, "/device")
	if q.Get("client_id") != fake.ClientID || q.Get("response_type") != "code" || q.Get("scope") != "openid profile email groups offline_access" ||
		q.Get("code_challenge_method") != "S256" || len(q.Get("state")) != 32 || len(q.Get("nonce")) != 32 {
		t.Fatalf("authorize query %v", q)
	}
	fake.Code("c1", fakeidp.Identity{Subject: "s-alice", Email: "alice@example.com", Groups: []string{"okta-eng", "system:admin", "idp-eng"}}, q.Get("nonce"), "rt-1")
	resp, _ := b.NoFollow(http.MethodGet, "/auth/oidc/callback?code=c1&state="+q.Get("state"))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/device" {
		t.Fatalf("callback: %d %v", resp.StatusCode, resp.Header)
	}
	form := fake.Forms[len(fake.Forms)-1]
	sum := sha256.Sum256([]byte(form["code_verifier"]))
	if form["grant_type"] != "authorization_code" || len(form["code_verifier"]) != 43 || form["client_secret"] != fake.ClientSecret ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
		t.Fatalf("token form %v does not answer challenge %q", form, q.Get("code_challenge"))
	}
	b.Expect(http.MethodGet, "/auth/me", "", http.StatusOK, `{"principal":"alice@example.com","roles":["analyst"]}`)
	var (
		groups string
		enc    []byte
		source string
	)
	_ = e.St.Pool.QueryRow(ctx, `SELECT u.source, string_agg(g.name, ',' ORDER BY g.name) FROM app_user u JOIN group_member gm ON gm.user_id = u.id JOIN app_group g ON g.id = gm.group_id WHERE u.principal = 'alice@example.com' GROUP BY u.source`).Scan(&source, &groups)
	_ = e.St.Pool.QueryRow(ctx, `SELECT refresh_token_enc FROM principal_session WHERE principal = 'alice@example.com' AND kind = 'WEB'`).Scan(&enc)
	if refresh, err := crypto.Decrypt(enc); source != "OIDC" || groups != "eng" || err != nil || refresh != "rt-1" {
		t.Fatalf("provisioned %s %s, refresh %q %v", source, groups, refresh, err)
	}

	resp, _ = b.NoFollow(http.MethodGet, "/auth/oidc/callback?code=c1&state="+q.Get("state"))
	if resp.Header.Get("Location") != "/login?error=state" {
		t.Fatalf("a replayed state: %v", resp.Header.Get("Location"))
	}
	for _, tc := range []struct {
		name, returnTo, state, query, want string
		register                           func(q url.Values)
	}{
		{"idp error", "/device", "", "error=access_denied", "/login?error=oidc&return_to=%2Fdevice", nil},
		{"missing code", "", "", "", "/login?error=state", nil},
		{"unknown code", "/oauth/resume", "", "code=nope", "/oauth/resume?error=server_error", nil},
		{"wrong nonce", "", "", "code=c2", "/login?error=nonce", func(q url.Values) {
			fake.Code("c2", fakeidp.Identity{Subject: "s", Email: "alice@example.com"}, "other-nonce", "")
		}},
		{"no roles", "/auth/reauth-complete", "", "code=c3", "/login?error=no_access&callbackUrl=%2Fauth%2Freauth-complete", func(q url.Values) {
			fake.Code("c3", fakeidp.Identity{Subject: "s-bob", Email: "bob@example.com"}, q.Get("nonce"), "")
		}},
		{"oversized idp error", "", "", "error=" + strings.Repeat("a", 5000), "/login?error=oidc", nil},
		{"idp error without a continuation", "", "", "error=access_denied", "/login?error=oidc", nil},
		{"failed exchange without a continuation", "", "", "code=nope", "/login?error=oidc", nil},
		{"idp error on reauth", "/auth/reauth-complete", "", "error=access_denied", "/login?error=oidc&callbackUrl=%2Fauth%2Freauth-complete", nil},
		{"idp error on resume", "/oauth/resume", "", "error=access_denied", "/oauth/resume?error=access_denied", nil},
		{"wrong state on reauth", "/auth/reauth-complete", "wrong-state", "code=abc", "/login?error=state&callbackUrl=%2Fauth%2Freauth-complete", nil},
	} {
		q := startLogin(t, b, tc.returnTo)
		if tc.register != nil {
			tc.register(q)
		}
		state := q.Get("state")
		if tc.state != "" {
			state = tc.state
		}
		path := "/auth/oidc/callback?state=" + state
		if tc.query != "" {
			path += "&" + tc.query
		}
		resp, _ := b.NoFollow(http.MethodGet, path)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != tc.want {
			t.Errorf("%s: %d %s, want %s", tc.name, resp.StatusCode, resp.Header.Get("Location"), tc.want)
		}
	}

	callback := func(br *routetest.Browser, query string) string {
		t.Helper()
		resp, _ := br.NoFollow(http.MethodGet, "/auth/oidc/callback?"+query)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("callback %s: %d", query, resp.StatusCode)
		}
		return resp.Header.Get("Location")
	}
	q = startLogin(t, b, "")
	if wrong, replay := callback(b, "code=abc&state=not-the-real-state"), callback(b, "code=abc&state="+q.Get("state")); wrong != "/login?error=state" || replay != "/login?error=state" {
		t.Errorf("a wrong state must burn the cookie: %s, then %s", wrong, replay)
	}
	q = startLogin(t, b, "")
	fake.Code("c4", fakeidp.Identity{Subject: "s", Email: "alice@example.com"}, "other-nonce", "")
	if invalid, replay := callback(b, "code=c4&state="+q.Get("state")), callback(b, "code=c4&state="+q.Get("state")); invalid != "/login?error=nonce" || replay != "/login?error=state" {
		t.Errorf("an invalid id_token must burn the cookies: %s, then %s", invalid, replay)
	}
	q = startLogin(t, b, "")
	srv, _ := url.Parse(e.Srv.URL)
	stateOnly := e.Browser(t)
	for _, c := range b.Jar.Cookies(srv) {
		if c.Name == "pm_oauth_state" {
			stateOnly.Jar.SetCookies(srv, []*http.Cookie{c})
		}
	}
	if loc := callback(stateOnly, "code=abc&state="+q.Get("state")); loc != "/login?error=nonce" {
		t.Errorf("a callback without its nonce cookie: %s", loc)
	}

	rows, _ := e.St.Pool.Query(ctx, `SELECT principal || '|' || action || '|' || resource || '|' || statement || '|' || outcome || '|' || decision || '|' || coalesce(detail, '') || '|' || channel || '|' || coalesce(client_addr, '')
		FROM audit_event WHERE kind = 'auth' ORDER BY id`)
	var got []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		got = append(got, s)
	}
	rows.Close()
	client := `Client::"` + fake.ClientID + `"`
	var first string
	_ = e.St.Pool.QueryRow(ctx, `SELECT min(id)::text FROM principal_session WHERE principal = 'alice@example.com'`).Scan(&first)
	failure := func(detail string) string {
		return "unknown|auth.oidc.login|" + client + "|OIDC login failed|FAILURE|DENY|" + detail + "|oidc|127.0.0.1"
	}
	want := []string{
		`alice@example.com|auth.oidc.login|Session::"` + first + `"|OIDC login established session|SUCCESS|ALLOW||oidc|127.0.0.1`,
		failure("invalid_state"),
		failure("idp_error=access_denied"),
		failure("missing_code"),
		failure("token_exchange_failed"),
		failure("invalid_id_token"),
		`bob@example.com|auth.oidc.login|User::"bob@example.com"|OIDC login failed|FAILURE|DENY|no_effective_roles|oidc|127.0.0.1`,
		failure("idp_error=" + strings.Repeat("a", 200)),
		failure("idp_error=access_denied"),
		failure("token_exchange_failed"),
		failure("idp_error=access_denied"),
		failure("idp_error=access_denied"),
		failure("invalid_state"),
		failure("invalid_state"),
		failure("invalid_state"),
		failure("invalid_id_token"),
		failure("invalid_state"),
		failure("missing_nonce"),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("auth audit:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	routetest.VerifyChain(t, e)
}

func TestOIDCUnconfigured(t *testing.T) {
	e := routetest.Setup(t)
	for _, path := range []string{"/auth/oidc/login", "/auth/oidc/callback"} {
		if status, body := e.Do(t, http.MethodGet, path, "", nil); status != http.StatusNotImplemented || body != `{"code":"common.oidc_not_configured","params":{}}` {
			t.Fatalf("%s: %d %s", path, status, body)
		}
	}
}

func TestOIDCPKCE(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []string
		want    string
	}{{"none advertised", nil, ""}, {"only plain", []string{"plain"}, ""}, {"lowercase s256", []string{"s256"}, "S256"}} {
		e, fake, _, _ := setupOIDC(t)
		fake.PKCEMethods = tc.methods
		b := e.Browser(t)
		q := startLogin(t, b, "")
		if q.Get("code_challenge_method") != tc.want || (tc.want == "") != !q.Has("code_challenge") || (tc.want == "") != !q.Has("code_challenge_method") {
			t.Errorf("%s: authorize query %v", tc.name, q)
			continue
		}
		fake.Code("c", fakeidp.Identity{Subject: "s", Email: "alice@example.com", Groups: []string{"idp-eng"}}, q.Get("nonce"), "")
		b.NoFollow(http.MethodGet, "/auth/oidc/callback?code=c&state="+q.Get("state"))
		if _, sent := fake.Forms[len(fake.Forms)-1]["code_verifier"]; sent != (tc.want != "") {
			t.Errorf("%s: token form %v", tc.name, fake.Forms[len(fake.Forms)-1])
		}
		if tc.want != "" && startLogin(t, b, "").Get("code_challenge") == q.Get("code_challenge") {
			t.Errorf("%s: a second login reused the verifier", tc.name)
		}
	}
}

func TestOIDCWebSession(t *testing.T) {
	ctx := context.Background()
	login := func(t *testing.T, e *routetest.Env, fake *fakeidp.IdP, b *routetest.Browser, email, returnTo string) *http.Response {
		t.Helper()
		q := startLogin(t, b, returnTo)
		fake.Code("c-"+email, fakeidp.Identity{Subject: "s-" + email, Email: email, Groups: []string{"idp-eng"}}, q.Get("nonce"), "rt-"+email)
		resp, _ := b.NoFollow(http.MethodGet, "/auth/oidc/callback?code=c-"+email+"&state="+q.Get("state"))
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("callback %d", resp.StatusCode)
		}
		return resp
	}
	cookie := func(resp *http.Response, name string) string {
		for _, c := range resp.Header.Values("Set-Cookie") {
			if strings.HasPrefix(c, name+"=") {
				return c
			}
		}
		return ""
	}
	sessions := func(e *routetest.Env, principal string) int {
		return e.Count(t, `SELECT count(*) FROM principal_session WHERE principal = $1`, principal)
	}

	t.Run("minted session", func(t *testing.T) {
		e, fake, _, _ := setupOIDC(t)
		resp := login(t, e, fake, e.Browser(t), "alice@example.com", "")
		did := cookie(resp, "pm_did")
		if loc := resp.Header.Get("Location"); loc != "/" || !strings.Contains(cookie(resp, "pm_session"), "; Max-Age=7200; ") ||
			!regexp.MustCompile(`^pm_did=[0-9a-f-]{36}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax`).MatchString(did) {
			t.Fatalf("callback %s %q", loc, resp.Header.Values("Set-Cookie"))
		}
		var (
			kind, device       string
			idleSecs           float64
			absoluteAfterIdle  bool
			hasRefresh, hasKey bool
		)
		if err := e.St.Pool.QueryRow(ctx, `SELECT kind, device_id, extract(epoch FROM idle_expires_at - created_at), absolute_expires_at > idle_expires_at,
			refresh_token_enc IS NOT NULL, session_key IS NOT NULL FROM principal_session WHERE principal = 'alice@example.com'`).
			Scan(&kind, &device, &idleSecs, &absoluteAfterIdle, &hasRefresh, &hasKey); err != nil {
			t.Fatal(err)
		}
		if kind != "WEB" || "pm_did="+device != did[:len("pm_did=")+36] || int(idleSecs) != 900 || !absoluteAfterIdle || !hasRefresh || !hasKey {
			t.Fatalf("row %s %s %v %v %v %v", kind, device, idleSecs, absoluteAfterIdle, hasRefresh, hasKey)
		}

		if loc := login(t, e, fake, e.Browser(t), "carol@example.com", "/auth/reauth-complete").Header.Get("Location"); loc != "/auth/reauth-complete" {
			t.Fatalf("a reauth login returned to %s", loc)
		}

		b := e.Browser(t)
		q := startLogin(t, b, "")
		fake.Code("c-bob", fakeidp.Identity{Subject: "s-bob", Email: "bob@example.com"}, q.Get("nonce"), "rt-bob")
		resp, _ = b.NoFollow(http.MethodGet, "/auth/oidc/callback?code=c-bob&state="+q.Get("state"))
		if resp.Header.Get("Location") != "/login?error=no_access" || cookie(resp, "pm_session") != "" || sessions(e, "bob@example.com") != 0 {
			t.Fatalf("no roles: %s %q %d", resp.Header.Get("Location"), resp.Header.Values("Set-Cookie"), sessions(e, "bob@example.com"))
		}
	})

	for _, tc := range []struct {
		name, scopes string
		crypto       bool
	}{{"no result key", "openid email offline_access", false}, {"no offline_access", "openid email", true}} {
		t.Run(tc.name, func(t *testing.T) {
			e, fake, _, _ := setupOIDCWith(t, tc.scopes, tc.crypto, dbtest.Settings)
			login(t, e, fake, e.Browser(t), "alice@example.com", "")
			if n := e.Count(t, `SELECT count(*) FROM principal_session WHERE principal = 'alice@example.com' AND refresh_token_enc IS NULL`); n != 1 {
				t.Fatalf("a refresh token was stored: %d", n)
			}
		})
	}

	t.Run("mint failure", func(t *testing.T) {
		e, fake, _, _ := setupOIDC(t)
		e.Exec(t, `CREATE FUNCTION pm_test_reject_session_insert() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'forced session mint failure'; END $$ LANGUAGE plpgsql;
			CREATE TRIGGER pm_test_reject_session_insert BEFORE INSERT ON principal_session FOR EACH ROW EXECUTE FUNCTION pm_test_reject_session_insert()`)
		resp := login(t, e, fake, e.Browser(t), "alice@example.com", "")
		if resp.Header.Get("Location") != "/login?error=oidc" || cookie(resp, "pm_session") != "" || sessions(e, "alice@example.com") != 0 {
			t.Fatalf("mint failure: %s %q", resp.Header.Get("Location"), resp.Header.Values("Set-Cookie"))
		}
		if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE kind = 'auth' AND principal = 'alice@example.com' AND action = 'auth.oidc.login'
			AND outcome = 'FAILURE' AND decision = 'DENY' AND channel = 'oidc' AND detail = 'session_mint_failed'
			AND resource = 'User::"alice@example.com"' AND client_addr = '127.0.0.1'`); n != 1 {
			t.Fatalf("mint failure rows %d", n)
		}
	})

}

func TestLivenessSweep(t *testing.T) {
	attrs, _ := authz.ParseUserAttributes("manager:User")
	if err := authz.DeclareUserAttributes(attrs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authz.DeclareUserAttributes(nil) })
	e, fake, crypto, provider := setupOIDC(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.St.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	newSession := func(principal, kind, refresh string) int64 {
		t.Helper()
		var id int64
		if err := e.St.Pool.QueryRow(ctx, `INSERT INTO principal_session (kind, principal, refresh_token_enc, idle_expires_at, absolute_expires_at)
			VALUES ($1, $2, $3, now() + interval '15 minutes', now() + interval '2 hours') RETURNING id`, kind, principal, crypto.Encrypt(refresh)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	state := func(id int64) string {
		var s string
		_ = e.St.Pool.QueryRow(ctx, `SELECT coalesce(ended_reason, '-') || '|' || liveness_status || '|' || (last_idp_check_at IS NOT NULL) FROM principal_session WHERE id = $1`, id).Scan(&s)
		return s
	}
	exec(`INSERT INTO app_user (principal, attributes) VALUES ('alice@example.com', '{"manager": "old@example.com"}'), ('carol@example.com', '{"manager": "old@example.com"}')`)
	exec(`INSERT INTO group_member (group_id, user_id) SELECT g.id, u.id FROM app_group g, app_user u WHERE g.name = 'eng'`)

	live := newSession("alice@example.com", "WEB", "rt-live")
	fake.OnRefresh("rt-live", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "alice@example.com", Groups: []string{"okta-eng"},
		Extra: map[string]any{"manager": "lead@example.com"}}, Rotate: "rt-live-2", Nonce: "from-login"})
	rejected := newSession("alice@example.com", "WEB", "rt-gone")
	fake.OnRefresh("rt-gone", fakeidp.Refresh{Error: "invalid_grant"})
	daemon := newSession("alice@example.com", "DAEMON", "rt-gone")
	transient := newSession("alice@example.com", "WEB", "rt-flaky")
	fake.OnRefresh("rt-flaky", fakeidp.Refresh{Error: "invalid_client"})
	revoked := newSession("carol@example.com", "WEB", "rt-carol")
	fake.OnRefresh("rt-carol", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "carol@example.com"}})
	mismatch := newSession("dave@example.com", "WEB", "rt-dave")
	fake.OnRefresh("rt-dave", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "mallory@example.com"}})

	oidc.Liveness{Pool: e.St.Pool, Sessions: session.NewResolver(e.St.Pool, dbtest.Settings), Kotlin: &e.Kotlin, Provider: provider, Crypto: crypto}.Sweep(ctx)

	for id, want := range map[int64]string{
		live: "-|ACTIVE|true", rejected: "IDP_REJECTED|INACTIVE|false", daemon: "-|INACTIVE|false",
		transient: "-|ACTIVE|false", revoked: "GROUP_REVOKED|INACTIVE|true", mismatch: "-|ACTIVE|false",
	} {
		if got := state(id); got != want {
			t.Errorf("session %d: %s, want %s", id, got, want)
		}
	}
	var enc []byte
	_ = e.St.Pool.QueryRow(ctx, `SELECT refresh_token_enc FROM principal_session WHERE id = $1`, live).Scan(&enc)
	if rotated, _ := crypto.Decrypt(enc); rotated != "rt-live-2" {
		t.Fatalf("rotated refresh %q", rotated)
	}
	if got := strings.Join(e.Kotlin.Ended, ","); got != "alice@example.com,carol@example.com" {
		t.Fatalf("signalled %s", got)
	}
	for principal, want := range map[string]string{"alice@example.com": `{"manager": "lead@example.com"}`, "carol@example.com": `{}`} {
		var got string
		_ = e.St.Pool.QueryRow(ctx, `SELECT attributes::text FROM app_user WHERE principal = $1`, principal).Scan(&got)
		if got != want {
			t.Errorf("%s attributes after the refresh: %s, want %s", principal, got, want)
		}
	}
}

func TestOIDCLoginStoresDeclaredClaims(t *testing.T) {
	attrs, err := authz.ParseUserAttributes("manager:User,level:Long")
	if err != nil {
		t.Fatal(err)
	}
	if err := authz.DeclareUserAttributes(attrs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authz.DeclareUserAttributes(nil) })
	e, fake, _, _ := setupOIDC(t)
	ctx := context.Background()
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO app_user (principal, email, source, external_id) VALUES ('scim@example.com', 'scim@example.com', 'SCIM', 'ext-1');
		INSERT INTO group_member (group_id, user_id) SELECT g.id, u.id FROM app_group g, app_user u WHERE g.name = 'eng' AND u.principal = 'scim@example.com'`); err != nil {
		t.Fatal(err)
	}
	login := func(code, email string, extra map[string]any) string {
		t.Helper()
		b := e.Browser(t)
		q := startLogin(t, b, "")
		fake.Code(code, fakeidp.Identity{Subject: "s-" + email, Email: email, Groups: []string{"idp-eng"}, Extra: extra}, q.Get("nonce"), "")
		if resp, _ := b.NoFollow(http.MethodGet, "/auth/oidc/callback?code="+code+"&state="+q.Get("state")); resp.StatusCode != http.StatusFound {
			t.Fatalf("callback %d", resp.StatusCode)
		}
		var stored string
		if err := e.St.Pool.QueryRow(ctx, `SELECT attributes::text FROM app_user WHERE principal = $1`, email).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		return stored
	}
	for _, tc := range []struct {
		name, code, email string
		extra             map[string]any
		want              string
	}{
		{"a declared claim", "a1", "alice@example.com", map[string]any{"manager": "lead@example.com", "department": "data"}, `{"manager": "lead@example.com"}`},
		{"the claim gone", "a2", "alice@example.com", nil, `{}`},
		{"the claim of the wrong type", "a3", "alice@example.com", map[string]any{"manager": []string{"lead@example.com"}}, `{}`},
		{"a SCIM-owned user", "s1", "scim@example.com", map[string]any{"manager": "lead@example.com"}, `{"manager": "lead@example.com"}`},
		{"a Long sent as 3.0", "l1", "alice@example.com", map[string]any{"level": json.Number("3.0")}, `{}`},
		{"a Long past 2^53", "l2", "alice@example.com", map[string]any{"level": json.Number("9007199254740993")}, `{"level": 9007199254740993}`},
	} {
		if got := login(tc.code, tc.email, tc.extra); got != tc.want {
			t.Errorf("%s: stored %s, want %s", tc.name, got, tc.want)
		}
	}
}
