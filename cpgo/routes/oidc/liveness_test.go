package oidc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/idp"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/fakeidp"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/device"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/oidc"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

type sweepEnv struct {
	t        *testing.T
	e        *routetest.Env
	fake     *fakeidp.IdP
	crypto   *idp.Crypto
	provider *idp.Provider
}

func newSweepEnv(t *testing.T) *sweepEnv {
	e, fake, crypto, provider := setupOIDC(t)
	return &sweepEnv{t, e, fake, crypto, provider}
}

func (s *sweepEnv) sweep(crypto *idp.Crypto) {
	oidc.Liveness{Pool: s.e.St.Pool, Sessions: session.NewResolver(s.e.St.Pool, dbtest.Settings), Kotlin: &s.e.Kotlin,
		Provider: s.provider, Crypto: crypto}.Sweep(context.Background())
}

// session inserts a live session; an empty refresh stores none, and a DAEMON row renews with "pmr_<id>".
func (s *sweepEnv) session(principal, kind, refresh string) int64 {
	s.t.Helper()
	var enc []byte
	if refresh != "" {
		enc = s.crypto.Encrypt(refresh)
	}
	var id int64
	if err := s.e.St.Pool.QueryRow(context.Background(), `INSERT INTO principal_session (kind, principal, refresh_token_enc, ttl_seconds,
		idle_expires_at, absolute_expires_at) VALUES ($1, $2, $3, CASE WHEN $1 = 'DAEMON' THEN 900 END,
		CASE WHEN $1 = 'WEB' THEN now() + interval '15 minutes' END, now() + interval '2 hours') RETURNING id`, kind, principal, enc).Scan(&id); err != nil {
		s.t.Fatal(err)
	}
	if kind == "DAEMON" {
		s.e.Exec(s.t, `UPDATE principal_session SET renewal_token_hash = $1 WHERE id = $2`, device.SHA256Hex("pmr_"+itoa(id)), id)
	}
	return id
}

func itoa(id int64) string { return strconv.FormatInt(id, 10) }

// state is ended_reason|liveness_status|stamped|window open.
func (s *sweepEnv) state(id int64) string {
	s.t.Helper()
	var out string
	if err := s.e.St.Pool.QueryRow(context.Background(), `SELECT coalesce(ended_reason, '-') || '|' || liveness_status || '|' ||
		(last_idp_check_at IS NOT NULL) || '|' || (absolute_expires_at > now()) FROM principal_session WHERE id = $1`, id).Scan(&out); err != nil {
		s.t.Fatal(err)
	}
	return out
}

func (s *sweepEnv) strings(sql string, args ...any) []string {
	s.t.Helper()
	rows, err := s.e.St.Pool.Query(context.Background(), sql, args...)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		out = append(out, v)
	}
	return out
}

func (s *sweepEnv) expiries(principal string) []string {
	return s.strings(`SELECT resource || '|' || coalesce(detail, '') || '|' || outcome || '|' || channel FROM audit_event
		WHERE kind = 'auth' AND action = 'auth.session.expire' AND principal = $1 ORDER BY id`, principal)
}

func (s *sweepEnv) groups(principal string) string {
	return strings.Join(s.strings(`SELECT g.name FROM group_member gm JOIN app_group g ON g.id = gm.group_id
		JOIN app_user u ON u.id = gm.user_id WHERE u.principal = $1 ORDER BY g.name`, principal), ",")
}

// credentials gives principal a SESSION wire token and an active grant, returning the token's id.
func (s *sweepEnv) credentials(principal string) int64 {
	s.t.Helper()
	var id int64
	if err := s.e.St.Pool.QueryRow(context.Background(), `INSERT INTO proxy_token (token_hash, principal, kind, expires_at)
		VALUES (md5($1), $1, 'SESSION', now() + interval '1 hour') RETURNING id`, principal).Scan(&id); err != nil {
		s.t.Fatal(err)
	}
	s.e.Exec(s.t, `INSERT INTO access_grant (principal, role_id, granted_by, expires_at)
		SELECT $1, id, 'approver@example.com', now() + interval '1 hour' FROM app_role WHERE name = 'analyst'`, principal)
	return id
}

func (s *sweepEnv) credentialsLive(principal string, token int64) bool {
	return s.e.Count(s.t, `SELECT count(*) FROM proxy_token WHERE id = $1 AND revoked_at IS NULL`, token) == 1 &&
		s.e.Count(s.t, `SELECT count(*) FROM access_grant WHERE principal = $1 AND revoked_at IS NULL`, principal) == 1
}

func TestLivenessSweepGroupChanges(t *testing.T) {
	s := newSweepEnv(t)
	s.e.Exec(t, `INSERT INTO app_group (name) VALUES ('unmapped');
		INSERT INTO app_user (principal) VALUES ('kept@example.com'), ('direct@example.com'), ('omitted@example.com');
		INSERT INTO group_member (group_id, user_id) SELECT g.id, u.id FROM app_group g, app_user u
		WHERE (u.principal = 'kept@example.com' AND g.name IN ('eng', 'unmapped')) OR (u.principal = 'direct@example.com' AND g.name = 'unmapped')
		   OR (u.principal = 'omitted@example.com' AND g.name = 'eng');
		INSERT INTO principal_role (principal, role_id) SELECT 'direct@example.com', id FROM app_role WHERE name = 'analyst'`)

	kept := s.session("kept@example.com", "WEB", "rt-kept")
	s.fake.OnRefresh("rt-kept", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "kept@example.com", Groups: []string{"unmapped"}}})
	direct := s.session("direct@example.com", "WEB", "rt-direct")
	s.fake.OnRefresh("rt-direct", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "direct@example.com", Groups: []string{}}})
	omitted := s.session("omitted@example.com", "WEB", "rt-omitted")
	s.fake.OnRefresh("rt-omitted", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "omitted@example.com"}})

	s.sweep(s.crypto)

	for _, tc := range []struct {
		principal     string
		id            int64
		groups, state string
		groupRevoked  bool
	}{
		{"kept@example.com", kept, "unmapped", "GROUP_REVOKED|INACTIVE|true|true", true},
		{"direct@example.com", direct, "", "-|ACTIVE|true|true", false},
		{"omitted@example.com", omitted, "", "GROUP_REVOKED|INACTIVE|true|true", true},
	} {
		if got := s.groups(tc.principal); got != tc.groups {
			t.Errorf("%s groups %q, want %q", tc.principal, got, tc.groups)
		}
		if got := s.state(tc.id); got != tc.state {
			t.Errorf("%s session %s, want %s", tc.principal, got, tc.state)
		}
		want := []string{}
		if tc.groupRevoked {
			want = []string{`User::"` + tc.principal + `"|group_revoked|SUCCESS|session`}
		}
		if got := s.expiries(tc.principal); !slices.Equal(got, want) {
			t.Errorf("%s expiry audit %v, want %v", tc.principal, got, want)
		}
	}
	slices.Sort(s.e.Kotlin.Ended)
	if got := strings.Join(s.e.Kotlin.Ended, ","); got != "kept@example.com,omitted@example.com" {
		t.Fatalf("signalled %s", got)
	}
}

func TestLivenessSweepIdpRejection(t *testing.T) {
	s := newSweepEnv(t)
	s.fake.OnRefresh("rt-gone", fakeidp.Refresh{Error: "invalid_grant"})
	s.fake.OnRefresh("rt-dana", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "dana@example.com", Groups: []string{"okta-eng"}}})

	danaToken := s.credentials("dana@example.com")
	rejected := s.session("dana@example.com", "DAEMON", "rt-gone")
	sibling := s.session("dana@example.com", "DAEMON", "rt-dana")

	erinToken := s.credentials("erin@example.com")
	erinA := s.session("erin@example.com", "DAEMON", "rt-gone")
	erinB := s.session("erin@example.com", "DAEMON", "rt-gone")
	erinWeb := s.session("erin@example.com", "WEB", "rt-gone")

	s.sweep(s.crypto)

	for id, want := range map[int64]string{
		rejected: "-|INACTIVE|false|false", sibling: "-|ACTIVE|true|true",
		erinA: "-|INACTIVE|false|false", erinB: "-|INACTIVE|false|false", erinWeb: "IDP_REJECTED|INACTIVE|false|true",
	} {
		if got := s.state(id); got != want {
			t.Errorf("session %d: %s, want %s", id, got, want)
		}
	}
	for principal, token := range map[string]int64{"dana@example.com": danaToken, "erin@example.com": erinToken} {
		if !s.credentialsLive(principal, token) {
			t.Errorf("an IdP rejection revoked %s's wire token or grant", principal)
		}
	}
	if got, want := s.expiries("dana@example.com"), []string{`Session::"` + itoa(rejected) + `"|idp_rejected|SUCCESS|session`}; !slices.Equal(got, want) {
		t.Errorf("dana expiry audit %v, want %v", got, want)
	}
	got := s.expiries("erin@example.com")
	slices.Sort(got)
	var want []string
	for _, id := range []int64{erinA, erinB, erinWeb} {
		want = append(want, `Session::"`+itoa(id)+`"|idp_rejected|SUCCESS|session`)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("erin expiry audit %v, want %v", got, want)
	}
}

func TestLivenessSweepTransientFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refresh fakeidp.Refresh
	}{
		{"invalid_client", fakeidp.Refresh{Error: "invalid_client", Status: http.StatusUnauthorized}},
		{"server error", fakeidp.Refresh{Error: "server_error", Status: http.StatusInternalServerError}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSweepEnv(t)
			s.fake.OnRefresh("rt-flaky", tc.refresh)
			token := s.credentials("flaky@example.com")
			daemon := s.session("flaky@example.com", "DAEMON", "rt-flaky")
			web := s.session("flaky@example.com", "WEB", "rt-flaky")
			before := len(s.fake.Forms)

			s.sweep(s.crypto)

			if len(s.fake.Forms) != before+2 {
				t.Fatalf("IdP calls %d, want 2", len(s.fake.Forms)-before)
			}
			for id, want := range map[int64]string{daemon: "-|ACTIVE|false|true", web: "-|ACTIVE|false|true"} {
				if got := s.state(id); got != want {
					t.Errorf("session %d: %s, want %s", id, got, want)
				}
			}
			if !s.credentialsLive("flaky@example.com", token) {
				t.Error("a transient IdP failure revoked the wire token or grant")
			}
			if got := s.expiries("flaky@example.com"); len(got) != 0 {
				t.Errorf("a transient IdP failure was audited as an expiry: %v", got)
			}
		})
	}
}

func TestLivenessSweepWithoutRefreshToken(t *testing.T) {
	s := newSweepEnv(t)
	daemon := s.session("none@example.com", "DAEMON", "")
	web := s.session("none@example.com", "WEB", "")
	s.sweep(s.crypto)
	for _, id := range []int64{daemon, web} {
		if got := s.state(id); got != "-|ACTIVE|false|true" {
			t.Errorf("session %d without a refresh token: %s", id, got)
		}
	}
	if len(s.fake.Forms) != 0 {
		t.Fatalf("a session without a refresh token reached the IdP %d times", len(s.fake.Forms))
	}

	stored := s.session("alice@example.com", "WEB", "rt-unread")
	s.fake.OnRefresh("rt-unread", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "alice@example.com", Groups: []string{"okta-eng"}}, Rotate: "rt-rotated"})
	var before, after []byte
	_ = s.e.St.Pool.QueryRow(context.Background(), `SELECT refresh_token_enc FROM principal_session WHERE id = $1`, stored).Scan(&before)
	s.sweep(nil)
	_ = s.e.St.Pool.QueryRow(context.Background(), `SELECT refresh_token_enc FROM principal_session WHERE id = $1`, stored).Scan(&after)
	if len(s.fake.Forms) != 0 || !bytes.Equal(before, after) || s.state(stored) != "-|ACTIVE|false|true" {
		t.Fatalf("a sweep without PM_RESULT_KEY touched the session: %d IdP calls, %s", len(s.fake.Forms), s.state(stored))
	}
}

func TestSessionRenewNeverReachesTheIdP(t *testing.T) {
	s := newSweepEnv(t)
	s.fake.OnRefresh("rt-renew", fakeidp.Refresh{Identity: &fakeidp.Identity{Subject: "s", Email: "alice@example.com", Groups: []string{"okta-eng"}}})
	daemon := s.session("alice@example.com", "DAEMON", "rt-renew")

	if resp, out := s.e.Browser(t).Bearer("/auth/session/renew", "pmr_"+itoa(daemon)); resp.StatusCode != http.StatusOK {
		t.Fatalf("renew: %d %s", resp.StatusCode, out)
	}
	if len(s.fake.Forms) != 0 {
		t.Fatalf("renew made %d IdP calls", len(s.fake.Forms))
	}
	s.sweep(s.crypto)
	if len(s.fake.Forms) == 0 || s.state(daemon) != "-|ACTIVE|true|true" {
		t.Fatalf("the sweep did not recheck the daemon session: %d IdP calls, %s", len(s.fake.Forms), s.state(daemon))
	}
}

func TestStaleSessions(t *testing.T) {
	s := newSweepEnv(t)
	staleDaemon := s.session("p@example.com", "DAEMON", "daemon-refresh")
	staleWeb := s.session("p@example.com", "WEB", "web-refresh")
	staleChecked := s.session("p@example.com", "DAEMON", "")
	freshDaemon := s.session("p@example.com", "DAEMON", "")
	freshWeb := s.session("p@example.com", "WEB", "")
	endedWeb := s.session("p@example.com", "WEB", "")
	idleWeb := s.session("p@example.com", "WEB", "")
	expiredWeb := s.session("p@example.com", "WEB", "")
	expiredDaemon := s.session("p@example.com", "DAEMON", "")
	s.e.Exec(t, `UPDATE principal_session SET last_idp_check_at = now() - interval '1 hour' WHERE id = $1`, staleChecked)
	s.e.Exec(t, `UPDATE principal_session SET last_idp_check_at = now() WHERE id = ANY($1)`, []int64{freshDaemon, freshWeb})
	s.e.Exec(t, `UPDATE principal_session SET ended_at = now(), ended_reason = 'SIGNED_OUT', liveness_status = 'INACTIVE' WHERE id = $1`, endedWeb)
	s.e.Exec(t, `UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = $1`, idleWeb)
	s.e.Exec(t, `UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = ANY($1)`, []int64{expiredWeb, expiredDaemon})

	rows, err := db.New(s.e.St.Pool).StaleSessions(context.Background(), 600)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		refresh := "-"
		if r.RefreshTokenEnc != nil {
			refresh, _ = s.crypto.Decrypt(r.RefreshTokenEnc)
		}
		got = append(got, itoa(r.ID)+"|"+r.Kind+"|"+r.Principal+"|"+refresh)
	}
	slices.Sort(got)
	want := []string{
		itoa(staleDaemon) + "|DAEMON|p@example.com|daemon-refresh", itoa(staleWeb) + "|WEB|p@example.com|web-refresh",
		itoa(staleChecked) + "|DAEMON|p@example.com|-",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("stale sessions %v, want %v", got, want)
	}
}

// loginEnv serves OIDC login with crypto (nil for no PM_RESULT_KEY) and the given scopes.
func loginEnv(t *testing.T, withCrypto bool, scopes string) (*routetest.Env, *fakeidp.IdP, *idp.Crypto) {
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
		Scopes: scopes, RecheckInterval: time.Minute, Groups: idp.ParseGroupMapping("idp-eng=eng", ""),
	})
	e := routetest.SetupWith(t, nil, oidc.Login{Provider: provider, Crypto: crypto})
	e.Exec(t, `INSERT INTO app_role (name) VALUES ('analyst'); INSERT INTO app_group (name) VALUES ('eng');
		INSERT INTO group_role (group_id, role_id) SELECT g.id, r.id FROM app_group g, app_role r WHERE g.name = 'eng' AND r.name = 'analyst'`)
	return e, fake, crypto
}

// oidcLogin signs b in as alice through the fake IdP, which hands back refresh ("" for none).
func oidcLogin(t *testing.T, e *routetest.Env, fake *fakeidp.IdP, b *routetest.Browser, code, refresh string) {
	t.Helper()
	q := startLogin(t, b, "")
	fake.Code(code, fakeidp.Identity{Subject: "s-alice", Email: "alice@example.com", Groups: []string{"idp-eng"}}, q.Get("nonce"), refresh)
	if resp, _ := b.NoFollow(http.MethodGet, "/auth/oidc/callback?code="+code+"&state="+q.Get("state")); resp.StatusCode != http.StatusFound {
		t.Fatalf("callback %d", resp.StatusCode)
	}
}

// pmonLogin approves a pmon login from b's web session and returns the minted daemon session's handle.
func pmonLogin(t *testing.T, e *routetest.Env, b *routetest.Browser) string {
	t.Helper()
	pmon := e.Browser(t)
	s := pmon.StartDevice(`{}`)
	b.Expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK, "")
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device/success" {
		t.Fatalf("authorize went to %s", loc)
	}
	pmon.Expect(http.MethodPost, "/auth/device/poll", `{"handle":"`+s.Handle+`"}`, http.StatusOK, "")
	return s.Handle
}

func TestOIDCLoginStoresTheRefreshTokenEncrypted(t *testing.T) {
	refreshOf := func(e *routetest.Env, kind string) []byte {
		var enc []byte
		if err := e.St.Pool.QueryRow(context.Background(), `SELECT refresh_token_enc FROM principal_session
			WHERE principal = 'alice@example.com' AND kind = $1 ORDER BY id DESC LIMIT 1`, kind).Scan(&enc); err != nil {
			t.Fatal(err)
		}
		return enc
	}

	e, fake, crypto := loginEnv(t, true, "openid email groups offline_access")
	b := e.Browser(t)
	oidcLogin(t, e, fake, b, "c1", "rt-plaintext-secret")
	pmonLogin(t, e, b)
	for _, kind := range []string{"WEB", "DAEMON"} {
		enc := refreshOf(e, kind)
		if plain, err := crypto.Decrypt(enc); err != nil || plain != "rt-plaintext-secret" || bytes.Contains(enc, []byte("rt-plaintext-secret")) {
			t.Fatalf("%s refresh token at rest: %q %v", kind, plain, err)
		}
	}

	b = e.Browser(t)
	oidcLogin(t, e, fake, b, "c2", "")
	pmonLogin(t, e, b)
	if refreshOf(e, "WEB") != nil || refreshOf(e, "DAEMON") != nil {
		t.Fatal("a login the IdP gave no refresh token stored one")
	}

	for _, tc := range []struct {
		name       string
		withCrypto bool
		scopes     string
	}{
		{"no PM_RESULT_KEY", false, "openid email groups offline_access"},
		{"no offline_access", true, "openid email groups"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, fake, _ := loginEnv(t, tc.withCrypto, tc.scopes)
			b := e.Browser(t)
			oidcLogin(t, e, fake, b, "c1", "rt-unkept")
			pmonLogin(t, e, b)
			if refreshOf(e, "WEB") != nil || refreshOf(e, "DAEMON") != nil {
				t.Fatal("the refresh token was stored")
			}
		})
	}
}
