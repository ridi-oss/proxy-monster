package routes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/idp"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/fakeidp"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

func setupOIDC(t *testing.T) (*env, *fakeidp.IdP, *idp.Crypto, *idp.Provider) {
	t.Helper()
	fake := fakeidp.New(t)
	t.Setenv("PM_RESULT_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	crypto, err := idp.CryptoFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	provider := idp.NewProvider(idp.Config{
		Issuer: fake.URL, ClientID: fake.ClientID, ClientSecret: fake.ClientSecret, RedirectURI: "http://cp.example/auth/oidc/callback",
		Scopes: "openid profile email groups offline_access", RecheckInterval: time.Minute,
		Groups: idp.ParseGroupMapping("idp-eng=eng", "okta-"),
	})
	e := setupWith(t, nil, Login{Provider: provider, Crypto: crypto})
	if _, err := e.st.Pool.Exec(context.Background(), `INSERT INTO app_role (name) VALUES ('analyst');
		INSERT INTO app_group (name) VALUES ('eng');
		INSERT INTO group_role (group_id, role_id) SELECT g.id, r.id FROM app_group g, app_role r WHERE g.name = 'eng' AND r.name = 'analyst'`); err != nil {
		t.Fatal(err)
	}
	return e, fake, crypto, provider
}

// startLogin follows /auth/oidc/login to the IdP and returns the authorize query.
func startLogin(t *testing.T, b *browser, returnTo string) url.Values {
	t.Helper()
	path := "/auth/oidc/login"
	if returnTo != "" {
		path += "?return_to=" + url.QueryEscape(returnTo)
	}
	resp, body := b.noFollow(http.MethodGet, path)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || body != "" || loc == nil {
		t.Fatalf("login: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	return loc.Query()
}

func (b *browser) noFollow(method, path string) (*http.Response, string) {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.e.srv.URL+path, nil)
	c := &http.Client{Jar: b.jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, sb.String()
}

func TestOIDCLogin(t *testing.T) {
	e, fake, crypto, _ := setupOIDC(t)
	ctx := context.Background()
	b := e.browser(t)

	q := startLogin(t, b, "/device")
	if q.Get("client_id") != fake.ClientID || q.Get("response_type") != "code" || q.Get("scope") != "openid profile email groups offline_access" ||
		q.Get("code_challenge_method") != "S256" || len(q.Get("state")) != 32 || len(q.Get("nonce")) != 32 {
		t.Fatalf("authorize query %v", q)
	}
	fake.Code("c1", fakeidp.Identity{Subject: "s-alice", Email: "alice@example.com", Groups: []string{"okta-eng", "system:admin", "idp-eng"}}, q.Get("nonce"), "rt-1")
	resp, _ := b.noFollow(http.MethodGet, "/auth/oidc/callback?code=c1&state="+q.Get("state"))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/device" {
		t.Fatalf("callback: %d %v", resp.StatusCode, resp.Header)
	}
	form := fake.Forms[len(fake.Forms)-1]
	sum := sha256.Sum256([]byte(form["code_verifier"]))
	if form["grant_type"] != "authorization_code" || len(form["code_verifier"]) != 43 || form["client_secret"] != fake.ClientSecret ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
		t.Fatalf("token form %v does not answer challenge %q", form, q.Get("code_challenge"))
	}
	b.expect(http.MethodGet, "/auth/me", "", http.StatusOK, `{"principal":"alice@example.com","roles":["analyst"]}`)
	var (
		groups string
		enc    []byte
		source string
	)
	_ = e.st.Pool.QueryRow(ctx, `SELECT u.source, string_agg(g.name, ',' ORDER BY g.name) FROM app_user u JOIN group_member gm ON gm.user_id = u.id JOIN app_group g ON g.id = gm.group_id WHERE u.principal = 'alice@example.com' GROUP BY u.source`).Scan(&source, &groups)
	_ = e.st.Pool.QueryRow(ctx, `SELECT refresh_token_enc FROM principal_session WHERE principal = 'alice@example.com' AND kind = 'WEB'`).Scan(&enc)
	if refresh, err := crypto.Decrypt(enc); source != "OIDC" || groups != "eng" || err != nil || refresh != "rt-1" {
		t.Fatalf("provisioned %s %s, refresh %q %v", source, groups, refresh, err)
	}

	resp, _ = b.noFollow(http.MethodGet, "/auth/oidc/callback?code=c1&state="+q.Get("state"))
	if resp.Header.Get("Location") != "/login?error=state" {
		t.Fatalf("a replayed state: %v", resp.Header.Get("Location"))
	}
	for _, tc := range []struct {
		name, returnTo, query, want string
		register                    func(q url.Values)
	}{
		{"idp error", "/device", "error=access_denied", "/login?error=oidc&return_to=%2Fdevice", nil},
		{"missing code", "", "", "/login?error=state", nil},
		{"unknown code", "/oauth/resume", "code=nope", "/oauth/resume?error=server_error", nil},
		{"wrong nonce", "", "code=c2", "/login?error=nonce", func(q url.Values) {
			fake.Code("c2", fakeidp.Identity{Subject: "s", Email: "alice@example.com"}, "other-nonce", "")
		}},
		{"no roles", "/auth/reauth-complete", "code=c3", "/login?error=no_access&callbackUrl=%2Fauth%2Freauth-complete", func(q url.Values) {
			fake.Code("c3", fakeidp.Identity{Subject: "s-bob", Email: "bob@example.com"}, q.Get("nonce"), "")
		}},
	} {
		q := startLogin(t, b, tc.returnTo)
		if tc.register != nil {
			tc.register(q)
		}
		path := "/auth/oidc/callback?state=" + q.Get("state")
		if tc.query != "" {
			path += "&" + tc.query
		}
		resp, _ := b.noFollow(http.MethodGet, path)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != tc.want {
			t.Errorf("%s: %d %s, want %s", tc.name, resp.StatusCode, resp.Header.Get("Location"), tc.want)
		}
	}

	rows, _ := e.st.Pool.Query(ctx, `SELECT principal || '|' || resource || '|' || statement || '|' || outcome || '|' || decision || '|' || coalesce(detail, '') || '|' || channel
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
	_ = e.st.Pool.QueryRow(ctx, `SELECT min(id)::text FROM principal_session WHERE principal = 'alice@example.com'`).Scan(&first)
	want := []string{
		`alice@example.com|Session::"` + first + `"|OIDC login established session|SUCCESS|ALLOW||oidc`,
		"unknown|" + client + "|OIDC login failed|FAILURE|DENY|invalid_state|oidc",
		"unknown|" + client + "|OIDC login failed|FAILURE|DENY|idp_error=access_denied|oidc",
		"unknown|" + client + "|OIDC login failed|FAILURE|DENY|missing_code|oidc",
		"unknown|" + client + "|OIDC login failed|FAILURE|DENY|token_exchange_failed|oidc",
		"unknown|" + client + "|OIDC login failed|FAILURE|DENY|invalid_id_token|oidc",
		`bob@example.com|User::"bob@example.com"|OIDC login failed|FAILURE|DENY|no_effective_roles|oidc`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("auth audit:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	verifyChain(t, e)
}

func TestOIDCUnconfigured(t *testing.T) {
	e := setup(t)
	for _, path := range []string{"/auth/oidc/login", "/auth/oidc/callback"} {
		if status, body := e.do(t, http.MethodGet, path, "", nil); status != http.StatusNotImplemented || body != `{"code":"common.oidc_not_configured","params":{}}` {
			t.Fatalf("%s: %d %s", path, status, body)
		}
	}
}

func TestLivenessSweep(t *testing.T) {
	e, fake, crypto, provider := setupOIDC(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.st.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	newSession := func(principal, kind, refresh string) int64 {
		t.Helper()
		var id int64
		if err := e.st.Pool.QueryRow(ctx, `INSERT INTO principal_session (kind, principal, refresh_token_enc, idle_expires_at, absolute_expires_at)
			VALUES ($1, $2, $3, now() + interval '15 minutes', now() + interval '2 hours') RETURNING id`, kind, principal, crypto.Encrypt(refresh)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	state := func(id int64) string {
		var s string
		_ = e.st.Pool.QueryRow(ctx, `SELECT coalesce(ended_reason, '-') || '|' || liveness_status || '|' || (last_idp_check_at IS NOT NULL) FROM principal_session WHERE id = $1`, id).Scan(&s)
		return s
	}
	exec(`INSERT INTO app_user (principal) VALUES ('alice@example.com'), ('carol@example.com')`)
	exec(`INSERT INTO group_member (group_id, user_id) SELECT g.id, u.id FROM app_group g, app_user u WHERE g.name = 'eng'`)

	live := newSession("alice@example.com", "WEB", "rt-live")
	fake.OnRefresh("rt-live", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "alice@example.com", Groups: []string{"okta-eng"}}, Rotate: "rt-live-2", Nonce: "from-login"})
	rejected := newSession("alice@example.com", "WEB", "rt-gone")
	fake.OnRefresh("rt-gone", fakeidp.Refresh{Error: "invalid_grant"})
	daemon := newSession("alice@example.com", "DAEMON", "rt-gone")
	transient := newSession("alice@example.com", "WEB", "rt-flaky")
	fake.OnRefresh("rt-flaky", fakeidp.Refresh{Error: "invalid_client"})
	revoked := newSession("carol@example.com", "WEB", "rt-carol")
	fake.OnRefresh("rt-carol", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "carol@example.com"}})
	mismatch := newSession("dave@example.com", "WEB", "rt-dave")
	fake.OnRefresh("rt-dave", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "mallory@example.com"}})

	Liveness{Pool: e.st.Pool, Sessions: session.NewResolver(e.st.Pool, dbtest.Settings), Kotlin: &e.kotlin, Provider: provider, Crypto: crypto}.Sweep(ctx)

	for id, want := range map[int64]string{
		live: "-|ACTIVE|true", rejected: "IDP_REJECTED|INACTIVE|false", daemon: "-|INACTIVE|false",
		transient: "-|ACTIVE|false", revoked: "GROUP_REVOKED|INACTIVE|true", mismatch: "-|ACTIVE|false",
	} {
		if got := state(id); got != want {
			t.Errorf("session %d: %s, want %s", id, got, want)
		}
	}
	var enc []byte
	_ = e.st.Pool.QueryRow(ctx, `SELECT refresh_token_enc FROM principal_session WHERE id = $1`, live).Scan(&enc)
	if rotated, _ := crypto.Decrypt(enc); rotated != "rt-live-2" {
		t.Fatalf("rotated refresh %q", rotated)
	}
	if got := strings.Join(e.kotlin.sessionsEnded, ","); got != "alice@example.com,carol@example.com" {
		t.Fatalf("signalled %s", got)
	}
}
