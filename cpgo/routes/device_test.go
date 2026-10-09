package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type startResponse struct {
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	UserCode                string `json:"userCode"`
	Handle                  string `json:"handle"`
	Interval                int    `json:"interval"`
}

func (b *browser) startDevice(body string) startResponse {
	b.t.Helper()
	resp, out := b.do(http.MethodPost, "/auth/device/start", body)
	var s startResponse
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &s) != nil {
		b.t.Fatalf("start: %d %s", resp.StatusCode, out)
	}
	return s
}

func (b *browser) debugLogin(principal string) {
	b.t.Helper()
	b.expect(http.MethodPost, "/auth/debug", `{"principal":"`+principal+`"}`, http.StatusOK, "")
}

// authorizeDevice answers where /auth/device/authorize sent the browser.
func (b *browser) authorizeDevice(userCode string) string {
	b.t.Helper()
	resp, body := b.noFollow(http.MethodGet, "/auth/device/authorize?user_code="+url.QueryEscape(userCode))
	if resp.StatusCode != http.StatusFound || body != "" {
		b.t.Fatalf("authorize: %d %q", resp.StatusCode, body)
	}
	return resp.Header.Get("Location")
}

// pmonLogin runs a whole pmon login for principal and returns the poll's result.
func pmonLogin(t *testing.T, e *env, principal, startBody string) pollResult {
	t.Helper()
	pmon, b := e.browser(t), e.browser(t)
	s := pmon.startDevice(startBody)
	b.debugLogin(principal)
	b.expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK, "")
	if loc := b.authorizeDevice(s.UserCode); loc != "/device/success" {
		t.Fatalf("authorize went to %s", loc)
	}
	resp, out := pmon.do(http.MethodPost, "/auth/device/poll", `{"handle":"`+s.Handle+`"}`)
	var r pollResult
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &r) != nil {
		t.Fatalf("poll: %d %s", resp.StatusCode, out)
	}
	return r
}

func (e *env) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.st.Pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := e.st.Pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceLogin(t *testing.T) {
	e := setup(t)
	pmon, b := e.browser(t), e.browser(t)

	s := pmon.startDevice(`{}`)
	if s.VerificationURI != "http://127.0.0.1:8080/device" || s.VerificationURIComplete != s.VerificationURI+"?user_code="+s.UserCode ||
		len(s.UserCode) != 9 || s.UserCode[4] != '-' || !strings.HasPrefix(s.Handle, "dvc_") || s.Interval != 2 {
		t.Fatalf("start: %+v", s)
	}
	poll := `{"handle":"` + s.Handle + `"}`
	pmon.expect(http.MethodPost, "/auth/device/poll", poll, http.StatusAccepted, `{"status":"authorization_pending"}`)
	pmon.expect(http.MethodPost, "/auth/device/poll", `{"handle":"dvc_nope"}`, http.StatusBadRequest,
		`{"code":"device.unknown_or_expired_login","params":{}}`)
	pmon.expect(http.MethodPost, "/auth/device/poll", `{}`, http.StatusInternalServerError, `{"code":"common.fallback","params":{}}`)

	confirm := `{"userCode":"` + strings.ToLower(strings.ReplaceAll(s.UserCode, "-", " ")) + `"}`
	b.expect(http.MethodPost, "/auth/device/confirm", confirm, http.StatusUnauthorized, `{"code":"common.unauthenticated","params":{}}`)
	if loc := b.authorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode {
		t.Fatalf("authorize without a confirm went to %s", loc)
	}
	b.debugLogin("alice@example.com")
	b.expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"ZZZZ-ZZZZ"}`, http.StatusBadRequest,
		`{"code":"device.unknown_or_expired_login","params":{}}`)
	b.expect(http.MethodPost, "/auth/device/confirm", confirm, http.StatusOK, `{"ok":true,"scopes":["mcp:query","mcp:read"]}`)

	other := pmon.startDevice(`{}`)
	if loc := b.authorizeDevice(other.UserCode); loc != "/device?user_code="+other.UserCode {
		t.Fatalf("a confirm for one code authorized another: %s", loc)
	}
	e.exec(t, `UPDATE principal_session SET refresh_token_enc = '\x0102' WHERE kind = 'WEB' AND principal = 'alice@example.com'`)
	if loc := b.authorizeDevice(s.UserCode); loc != "/device/success" {
		t.Fatalf("authorize went to %s", loc)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.device.approve' AND principal = 'alice@example.com'
		AND resource = 'DeviceLogin::"' || (SELECT id FROM device_login WHERE handle = $1) || '"'`, s.Handle); n != 1 {
		t.Fatalf("approve audit rows %d", n)
	}
	if loc := b.authorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode {
		t.Fatalf("the verify cookie outlived its approval: %s", loc)
	}

	resp, out := pmon.do(http.MethodPost, "/auth/device/poll", poll)
	var r pollResult
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &r) != nil || !strings.HasPrefix(r.Token, "pmt_") ||
		!strings.HasPrefix(r.RenewalToken, "pmr_") || r.Principal != "alice@example.com" || strings.Join(r.Scopes, " ") != "mcp:query mcp:read" ||
		r.ElevatedUntil != nil || strings.Contains(out, "elevatedUntil") {
		t.Fatalf("poll: %d %s", resp.StatusCode, out)
	}
	pmon.expect(http.MethodPost, "/auth/device/poll", poll, http.StatusBadRequest, `{"code":"device.login_already_completed","params":{}}`)
	if n := e.count(t, `SELECT count(*) FROM principal_session ps JOIN proxy_token t ON t.principal_session_id = ps.id
		WHERE ps.handle = $1 AND ps.kind = 'DAEMON' AND t.kind = 'SESSION' AND ps.renewal_token_hash = $2 AND t.token_hash = $3
		  AND ps.refresh_token_enc = '\x0102' 
		  AND ps.absolute_expires_at > now() + interval '7100 seconds'`, s.Handle, sha256Hex(r.RenewalToken), sha256Hex(r.Token)); n != 1 {
		t.Fatalf("minted sessions %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.device.mint' AND principal = 'alice@example.com'`); n != 1 {
		t.Fatalf("mint audit rows %d", n)
	}
}

func TestDeviceConfirmIsBoundToItsSession(t *testing.T) {
	e := setup(t)
	pmon, b := e.browser(t), e.browser(t)
	s := pmon.startDevice(`{}`)
	b.debugLogin("alice@example.com")
	b.expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK, "")
	b.debugLogin("alice@example.com")
	if loc := b.authorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode {
		t.Fatalf("a replacement session inherited the confirmation: %s", loc)
	}
	if n := e.count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND status = 'PENDING'`, s.Handle); n != 1 {
		t.Fatal("approved without its confirming session")
	}
}

func TestDeviceScopes(t *testing.T) {
	e := setup(t)
	pmon, b := e.browser(t), e.browser(t)
	pmon.expect(http.MethodPost, "/auth/device/start", `{"scopes":[" ",""]}`, http.StatusBadRequest, `{"code":"device.no_scopes","params":{}}`)
	pmon.expect(http.MethodPost, "/auth/device/start", `{"scopes":["mcp:read","mcp:root"]}`, http.StatusBadRequest,
		`{"code":"device.unknown_scope","params":{"scope":"mcp:root"}}`)

	s := pmon.startDevice(`{"scopes":["mcp:read"," mcp:policies:write","mcp:read"],"ttlSeconds":5}`)
	if n := e.count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND scopes = 'mcp:policies:write mcp:read' AND ttl_seconds = 60`, s.Handle); n != 1 {
		t.Fatal("start did not store the canonical scopes and the clamped ttl")
	}
	b.debugLogin("alice@example.com")
	b.expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK,
		`{"ok":true,"scopes":["mcp:policies:write","mcp:read"],"elevatedTtlSeconds":3600}`)
	b.authorizeDevice(s.UserCode)
	if n := e.count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND elevated_until BETWEEN now() + interval '3590 seconds' AND now() + interval '3610 seconds'`, s.Handle); n != 1 {
		t.Fatal("the approval did not start the elevated window")
	}
}

func TestDevicePollRollsBackAFailedMint(t *testing.T) {
	e := setup(t)
	pmon, b := e.browser(t), e.browser(t)
	s := pmon.startDevice(`{}`)
	b.debugLogin("bob@example.com")
	b.expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK, "")
	b.authorizeDevice(s.UserCode)
	poll := `{"handle":"` + s.Handle + `"}`

	e.exec(t, `INSERT INTO app_user (principal, source, active) VALUES ('bob@example.com', 'LOCAL', false)`)
	pmon.expect(http.MethodPost, "/auth/device/poll", poll, http.StatusForbidden, `{"code":"auth.principal_deprovisioned","params":{}}`)
	e.exec(t, `UPDATE app_user SET active = true WHERE principal = 'bob@example.com'`)

	e.exec(t, `CREATE FUNCTION reject_mint() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'no'; END $$ LANGUAGE plpgsql;
		CREATE TRIGGER reject_mint BEFORE INSERT ON audit_event FOR EACH ROW WHEN (NEW.action = 'auth.device.mint') EXECUTE FUNCTION reject_mint()`)
	pmon.expect(http.MethodPost, "/auth/device/poll", poll, http.StatusInternalServerError, "")
	if n := e.count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND status = 'APPROVED'`, s.Handle) +
		e.count(t, `SELECT count(*) FROM principal_session WHERE handle = $1`, s.Handle); n != 1 {
		t.Fatal("a failed mint left the handle consumed or a session behind")
	}
	e.exec(t, `DROP TRIGGER reject_mint ON audit_event`)
	pmon.expect(http.MethodPost, "/auth/device/poll", poll, http.StatusOK, "")
}

func (b *browser) bearer(path, secret string) (*http.Response, string) {
	b.t.Helper()
	return b.do(http.MethodPost, path, "", "Authorization", "Bearer "+secret)
}

func TestSessionRenew(t *testing.T) {
	e := setup(t)
	r := pmonLogin(t, e, "alice@example.com", `{"ttlSeconds":600}`)
	pmon := e.browser(t)

	pmon.expect(http.MethodPost, "/auth/session/renew", `{"principal":"alice@example.com"}`, http.StatusUnauthorized,
		`{"code":"auth.missing_renewal_token","params":{}}`)
	if resp, out := pmon.bearer("/auth/session/renew", "pmr_wrong"); resp.StatusCode != http.StatusUnauthorized || out != `{"code":"common.unauthenticated","params":{}}` {
		t.Fatalf("wrong secret: %d %s", resp.StatusCode, out)
	}
	resp, out := pmon.bearer("/auth/session/renew", r.RenewalToken)
	var renewed struct{ Token, ExpiresAt string }
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &renewed) != nil || renewed.Token == r.Token ||
		e.count(t, `SELECT count(*) FROM proxy_token WHERE token_hash = $1 AND expires_at BETWEEN now() + interval '590 seconds' AND now() + interval '600 seconds'`, sha256Hex(renewed.Token)) != 1 {
		t.Fatalf("renew: %d %s", resp.StatusCode, out)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.session.renew' AND channel = 'pmon'`); n != 1 {
		t.Fatalf("renew audit rows %d", n)
	}

	expired := `{"code":"auth.session_window_expired","params":{}}`
	for _, tc := range []struct{ name, set, reset string }{
		{"deprovisioned", `INSERT INTO app_user (principal, source, active) VALUES ('alice@example.com', 'LOCAL', false)`, `DELETE FROM app_user`},
		{"inactive", `UPDATE principal_session SET liveness_status = 'INACTIVE' WHERE kind = 'DAEMON'`, `UPDATE principal_session SET liveness_status = 'ACTIVE'`},
		{"window closed", `UPDATE principal_session SET absolute_expires_at = now() WHERE kind = 'DAEMON'`, ``},
	} {
		e.exec(t, tc.set)
		if resp, out := pmon.bearer("/auth/session/renew", r.RenewalToken); resp.StatusCode != http.StatusUnauthorized || out != expired {
			t.Fatalf("%s: %d %s", tc.name, resp.StatusCode, out)
		}
		if tc.reset != "" {
			e.exec(t, tc.reset)
		}
	}
}

func TestPmonLogout(t *testing.T) {
	e := setup(t)
	pmon := e.browser(t)
	if resp, _ := pmon.bearer("/auth/session/logout", "pmr_unknown"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unknown bearer: %d", resp.StatusCode)
	}

	r := pmonLogin(t, e, "alice@example.com", `{}`)
	sibling := pmonLogin(t, e, "alice@example.com", `{}`)
	resp, out := pmon.bearer("/auth/session/mcp-token", r.RenewalToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mcp-token: %d %s", resp.StatusCode, out)
	}
	for range 2 {
		if resp, _ := pmon.bearer("/auth/session/logout", r.RenewalToken); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("logout: %d", resp.StatusCode)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM proxy_token WHERE revoked_at IS NULL AND token_hash <> $1`, sha256Hex(sibling.Token)) +
		e.count(t, `SELECT count(*) FROM oauth_consent WHERE revoked_at IS NULL`); n != 0 {
		t.Fatalf("%d tokens or consents survived the logout", n)
	}
	if resp, _ := pmon.bearer("/auth/session/renew", sibling.RenewalToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("logout ended another login of the same principal: %d", resp.StatusCode)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.logout' AND statement = 'pmon session signed out' AND channel = 'pmon'
		AND position($1 in coalesce(detail, '') || statement) = 0`, r.RenewalToken); n != 1 {
		t.Fatalf("logout audit rows %d", n)
	}
	if resp, out := pmon.bearer("/auth/session/renew", r.RenewalToken); resp.StatusCode != http.StatusUnauthorized || out != `{"code":"auth.session_window_expired","params":{}}` {
		t.Fatalf("renew after logout: %d %s", resp.StatusCode, out)
	}

	replaced := pmonLogin(t, e, "bob@example.com", `{}`)
	if resp, out := pmon.bearer("/auth/session/mcp-token", replaced.RenewalToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("mcp-token: %d %s", resp.StatusCode, out)
	}
	if resp, _ := pmon.do(http.MethodPost, "/auth/session/logout?replaced=true", "", "Authorization", "Bearer "+replaced.RenewalToken); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("replaced logout: %d", resp.StatusCode)
	}
	if n := e.count(t, `SELECT count(*) FROM proxy_token WHERE token_hash = $1 AND revoked_at IS NULL AND retired_at IS NOT NULL`, sha256Hex(replaced.Token)); n != 1 {
		t.Fatal("a replaced login's wire token must be retired, not revoked")
	}
	if n := e.count(t, `SELECT count(*) FROM proxy_token WHERE principal = 'bob@example.com' AND kind = 'MCP_ACCESS' AND revoked_at IS NULL`) +
		e.count(t, `SELECT count(*) FROM oauth_consent WHERE principal = 'bob@example.com' AND revoked_at IS NULL`); n != 0 {
		t.Fatal("a replaced login's MCP token and consent must be revoked")
	}
}

func TestPmonMCPToken(t *testing.T) {
	e := setup(t)
	pmon := e.browser(t)
	mint := func(secret string) (int, string, map[string]string) {
		resp, out := pmon.bearer("/auth/session/mcp-token", secret)
		var m map[string]string
		_ = json.Unmarshal([]byte(out), &m)
		return resp.StatusCode, out, m
	}

	r := pmonLogin(t, e, "alice@example.com", `{"scopes":["mcp:read","mcp:query","mcp:policies:write"]}`)
	status, out, m := mint(r.RenewalToken)
	if status != http.StatusOK || m["scope"] != "mcp:policies:write mcp:query mcp:read" || !strings.HasPrefix(m["accessToken"], "pma_") {
		t.Fatalf("elevated: %d %s", status, out)
	}
	if n := e.count(t, `SELECT count(*) FROM proxy_token t JOIN oauth_consent c ON c.id = t.consent_id
		WHERE t.token_hash = $1 AND t.kind = 'MCP_ACCESS' AND t.client_id = 'pmon' AND c.scope = t.scope
		  AND t.resource = 'http://127.0.0.1:8080/mcp' AND t.principal_session_id IS NOT NULL`, sha256Hex(m["accessToken"])); n != 1 {
		t.Fatal("the MCP token is not stored under its consent")
	}
	if n := e.count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.session.mcp_token' AND detail = 'scope=mcp:policies:write mcp:query mcp:read'`); n != 1 {
		t.Fatalf("mcp-token audit rows %d", n)
	}
	expires, _ := time.Parse(time.RFC3339Nano, m["expiresAt"])
	if d := time.Until(expires); d < 590*time.Second || d > 600*time.Second {
		t.Fatalf("expires in %v", d)
	}

	e.exec(t, `UPDATE principal_session SET elevated_until = now() + interval '100 seconds' WHERE kind = 'DAEMON'`)
	if status, out, m := mint(r.RenewalToken); status != http.StatusOK {
		t.Fatalf("near the window's end: %d %s", status, out)
	} else if expires, _ := time.Parse(time.RFC3339Nano, m["expiresAt"]); time.Until(expires) > 100*time.Second {
		t.Fatalf("an elevated MCP token outlived its window: %s", m["expiresAt"])
	}
	e.exec(t, `UPDATE principal_session SET elevated_until = now() - interval '1 second' WHERE kind = 'DAEMON'`)
	if status, out, m := mint(r.RenewalToken); status != http.StatusOK || m["scope"] != "mcp:query mcp:read" {
		t.Fatalf("after the window: %d %s", status, out)
	}

	only := pmonLogin(t, e, "bob@example.com", `{"scopes":["mcp:tokens"],"ttlSeconds":300}`)
	if status, out, m := mint(only.RenewalToken); status != http.StatusOK {
		t.Fatalf("elevated only: %d %s", status, out)
	} else if expires, _ := time.Parse(time.RFC3339Nano, m["expiresAt"]); time.Until(expires) > 300*time.Second {
		t.Fatalf("an MCP token outlived its login: %s", m["expiresAt"])
	}
	e.exec(t, `UPDATE principal_session SET elevated_until = now() WHERE principal = 'bob@example.com'`)
	if status, out, _ := mint(only.RenewalToken); status != http.StatusForbidden || out != `{"code":"auth.scopes_expired","params":{}}` {
		t.Fatalf("no scopes left: %d %s", status, out)
	}

	pmon.expect(http.MethodPost, "/auth/session/mcp-token", "", http.StatusUnauthorized, `{"code":"auth.missing_renewal_token","params":{}}`)
	e.exec(t, `INSERT INTO app_user (principal, source, active) VALUES ('alice@example.com', 'LOCAL', false)`)
	if status, out, _ := mint(r.RenewalToken); status != http.StatusUnauthorized || out != `{"code":"auth.session_window_expired","params":{}}` {
		t.Fatalf("deactivated: %d %s", status, out)
	}
	e.exec(t, `DELETE FROM app_user`)
	e.exec(t, `UPDATE principal_session SET created_at = now() - interval '13 hours' WHERE principal = 'alice@example.com' AND kind = 'DAEMON'`)
	if status, out, _ := mint(r.RenewalToken); status != http.StatusUnauthorized || out != `{"code":"auth.session_window_expired","params":{}}` {
		t.Fatalf("past the login: %d %s", status, out)
	}
}

func TestSessionRenewWaitsForTheTeardownLock(t *testing.T) {
	e := setup(t)
	r := pmonLogin(t, e, "alice@example.com", `{}`)
	ctx := context.Background()
	tx, err := e.st.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('alice@example.com'));
		UPDATE principal_session SET liveness_status = 'INACTIVE', absolute_expires_at = now() WHERE kind = 'DAEMON'`); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		resp, out := e.browser(t).bearer("/auth/session/renew", r.RenewalToken)
		done <- strconv.Itoa(resp.StatusCode) + " " + out
	}()
	select {
	case got := <-done:
		t.Fatalf("renew answered while a teardown held the lock: %s", got)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := <-done; got != `401 {"code":"auth.session_window_expired","params":{}}` {
		t.Fatalf("renew after the teardown committed: %s", got)
	}
}
