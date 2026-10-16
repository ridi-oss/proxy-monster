package device_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/device"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// pmonLogin runs a whole pmon login for principal and returns the poll's result.
func pmonLogin(t *testing.T, e *routetest.Env, principal, startBody string) device.PollResult {
	t.Helper()
	pmon, b := e.Browser(t), e.Browser(t)
	s := pmon.StartDevice(startBody)
	b.DebugLogin(principal)
	b.Expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK, "")
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device/success" {
		t.Fatalf("authorize went to %s", loc)
	}
	resp, out := pmon.Do(http.MethodPost, "/auth/device/poll", `{"handle":"`+s.Handle+`"}`)
	var r device.PollResult
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &r) != nil {
		t.Fatalf("poll: %d %s", resp.StatusCode, out)
	}
	return r
}

func TestDeviceLogin(t *testing.T) {
	e := routetest.Setup(t)
	pmon, b := e.Browser(t), e.Browser(t)

	s := pmon.StartDevice(`{}`)
	if s.VerificationURI != "http://127.0.0.1:8080/device" || s.VerificationURIComplete != s.VerificationURI+"?user_code="+s.UserCode ||
		!regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4}$`).MatchString(s.UserCode) || !strings.HasPrefix(s.Handle, "dvc_") || s.Interval != 2 {
		t.Fatalf("start: %+v", s)
	}
	poll := `{"handle":"` + s.Handle + `"}`
	pmon.Expect(http.MethodPost, "/auth/device/poll", poll, http.StatusAccepted, `{"status":"authorization_pending"}`)
	pmon.Expect(http.MethodPost, "/auth/device/poll", `{"handle":"dvc_nope"}`, http.StatusBadRequest,
		`{"code":"device.unknown_or_expired_login","params":{}}`)
	pmon.Expect(http.MethodPost, "/auth/device/poll", `{}`, http.StatusInternalServerError, `{"code":"common.fallback","params":{}}`)

	confirm := `{"userCode":"` + strings.ToLower(strings.ReplaceAll(s.UserCode, "-", " ")) + `"}`
	b.Expect(http.MethodPost, "/auth/device/confirm", confirm, http.StatusUnauthorized, `{"code":"common.unauthenticated","params":{}}`)
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode {
		t.Fatalf("authorize without a confirm went to %s", loc)
	}
	b.DebugLogin("alice@example.com")
	pending := func(handle string) bool {
		return e.Count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND status = 'PENDING' AND principal IS NULL`, handle) == 1
	}
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode || !pending(s.Handle) {
		t.Fatalf("a signed-in browser that never confirmed went to %s", loc)
	}
	b.Expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"ZZZZ-ZZZZ"}`, http.StatusBadRequest,
		`{"code":"device.unknown_or_expired_login","params":{}}`)
	b.Expect(http.MethodPost, "/auth/device/confirm", confirm, http.StatusOK, `{"ok":true,"scopes":["mcp:query","mcp:read"]}`)

	other := pmon.StartDevice(`{}`)
	if loc := b.AuthorizeDevice(other.UserCode); loc != "/device?user_code="+other.UserCode {
		t.Fatalf("a confirm for one code authorized another: %s", loc)
	}
	if !pending(other.Handle) {
		t.Fatal("a confirm for one code approved another")
	}
	e.Exec(t, `UPDATE principal_session SET refresh_token_enc = '\x0102' WHERE kind = 'WEB' AND principal = 'alice@example.com'`)
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device/success" {
		t.Fatalf("authorize went to %s", loc)
	}
	if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.device.approve' AND principal = 'alice@example.com'
		AND resource = 'DeviceLogin::"' || (SELECT id FROM device_login WHERE handle = $1) || '"'`, s.Handle); n != 1 {
		t.Fatalf("approve audit rows %d", n)
	}
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode {
		t.Fatalf("the verify cookie outlived its approval: %s", loc)
	}
	bob := e.Browser(t)
	bob.DebugLogin("bob@example.com")
	bob.Expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusBadRequest,
		`{"code":"device.unknown_or_expired_login","params":{}}`)
	if n := e.Count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND status = 'APPROVED' AND principal = 'alice@example.com'`, s.Handle); n != 1 {
		t.Fatal("the approval is not alice's")
	}

	resp, out := pmon.Do(http.MethodPost, "/auth/device/poll", poll)
	var r device.PollResult
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &r) != nil || !strings.HasPrefix(r.Token, "pmt_") ||
		!strings.HasPrefix(r.RenewalToken, "pmr_") || r.Principal != "alice@example.com" || strings.Join(r.Scopes, " ") != "mcp:query mcp:read" ||
		r.ElevatedUntil != nil || strings.Contains(out, "elevatedUntil") {
		t.Fatalf("poll: %d %s", resp.StatusCode, out)
	}
	pmon.Expect(http.MethodPost, "/auth/device/poll", poll, http.StatusBadRequest, `{"code":"device.login_already_completed","params":{}}`)
	if n := e.Count(t, `SELECT count(*) FROM principal_session ps JOIN proxy_token t ON t.principal_session_id = ps.id
		WHERE ps.handle = $1 AND ps.kind = 'DAEMON' AND t.kind = 'SESSION' AND ps.renewal_token_hash = $2 AND t.token_hash = $3
		  AND ps.refresh_token_enc = '\x0102' AND ps.ttl_seconds = 43200 AND ps.liveness_status = 'ACTIVE'
		  AND ps.scopes = 'mcp:query mcp:read' AND ps.elevated_until IS NULL
		  AND ps.absolute_expires_at > now() + interval '7100 seconds'`, s.Handle, device.SHA256Hex(r.RenewalToken), device.SHA256Hex(r.Token)); n != 1 {
		t.Fatalf("minted sessions %d", n)
	}
	if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.device.mint' AND principal = 'alice@example.com'
		AND resource = 'Token::"' || (SELECT id FROM proxy_token WHERE token_hash = $1) || '"'`, device.SHA256Hex(r.Token)); n != 1 {
		t.Fatalf("mint audit rows %d", n)
	}
	for _, secret := range []string{s.Handle, r.Token, r.RenewalToken, "pmr_"} {
		if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE position($1 in principal || coalesce(resource, '') || statement || coalesce(detail, '')) > 0`, secret); n != 0 {
			t.Fatalf("%s reached the audit trail", secret)
		}
	}
}

func TestDeviceConfirmIsBoundToItsSession(t *testing.T) {
	e := routetest.Setup(t)
	pmon, b := e.Browser(t), e.Browser(t)
	s := pmon.StartDevice(`{}`)
	b.DebugLogin("alice@example.com")
	b.Expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK, "")
	b.DebugLogin("alice@example.com")
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode {
		t.Fatalf("a replacement session inherited the confirmation: %s", loc)
	}
	if n := e.Count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND status = 'PENDING'`, s.Handle); n != 1 {
		t.Fatal("approved without its confirming session")
	}
}

func TestDeviceScopes(t *testing.T) {
	e := routetest.Setup(t)
	pmon, b := e.Browser(t), e.Browser(t)
	pmon.Expect(http.MethodPost, "/auth/device/start", `{"scopes":[" ",""]}`, http.StatusBadRequest, `{"code":"device.no_scopes","params":{}}`)
	pmon.Expect(http.MethodPost, "/auth/device/start", `{"scopes":["mcp:read","mcp:root"]}`, http.StatusBadRequest,
		`{"code":"device.unknown_scope","params":{"scope":"mcp:root"}}`)

	s := pmon.StartDevice(`{"scopes":["mcp:read"," mcp:policies:write","mcp:read"],"ttlSeconds":5}`)
	if n := e.Count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND scopes = 'mcp:policies:write mcp:read' AND ttl_seconds = 60`, s.Handle); n != 1 {
		t.Fatal("start did not store the canonical scopes and the clamped ttl")
	}
	b.DebugLogin("alice@example.com")
	b.Expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK,
		`{"ok":true,"scopes":["mcp:policies:write","mcp:read"],"elevatedTtlSeconds":3600}`)
	b.AuthorizeDevice(s.UserCode)
	if n := e.Count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND elevated_until BETWEEN now() + interval '3590 seconds' AND now() + interval '3610 seconds'`, s.Handle); n != 1 {
		t.Fatal("the approval did not start the elevated window")
	}
	resp, out := pmon.Do(http.MethodPost, "/auth/device/poll", `{"handle":"`+s.Handle+`"}`)
	var r device.PollResult
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &r) != nil || strings.Join(r.Scopes, " ") != "mcp:policies:write mcp:read" || r.ElevatedUntil == nil {
		t.Fatalf("poll: %d %s", resp.StatusCode, out)
	}
	until, err := time.Parse(time.RFC3339Nano, *r.ElevatedUntil)
	if err != nil {
		t.Fatal(err)
	}
	if n := e.Count(t, `SELECT count(*) FROM principal_session ps JOIN device_login d ON d.handle = ps.handle WHERE ps.handle = $1
		AND ps.scopes = 'mcp:policies:write mcp:read' AND ps.elevated_until = d.elevated_until AND d.elevated_until = $2`, s.Handle, until); n != 1 {
		t.Fatalf("the daemon session does not carry the approved scopes and window %s", *r.ElevatedUntil)
	}
}

func TestDevicePollRollsBackAFailedMint(t *testing.T) {
	e := routetest.Setup(t)
	pmon, b := e.Browser(t), e.Browser(t)
	s := pmon.StartDevice(`{}`)
	b.DebugLogin("bob@example.com")
	b.Expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK, "")
	b.AuthorizeDevice(s.UserCode)
	poll := `{"handle":"` + s.Handle + `"}`

	e.Exec(t, `INSERT INTO app_user (principal, source, active) VALUES ('bob@example.com', 'LOCAL', false)`)
	pmon.Expect(http.MethodPost, "/auth/device/poll", poll, http.StatusForbidden, `{"code":"auth.principal_deprovisioned","params":{}}`)
	e.Exec(t, `UPDATE app_user SET active = true WHERE principal = 'bob@example.com'`)

	e.Exec(t, `CREATE FUNCTION reject_mint() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'no'; END $$ LANGUAGE plpgsql;
		CREATE TRIGGER reject_mint BEFORE INSERT ON audit_event FOR EACH ROW WHEN (NEW.action = 'auth.device.mint') EXECUTE FUNCTION reject_mint()`)
	pmon.Expect(http.MethodPost, "/auth/device/poll", poll, http.StatusInternalServerError, "")
	if n := e.Count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND status = 'APPROVED'`, s.Handle) +
		e.Count(t, `SELECT count(*) FROM principal_session WHERE handle = $1`, s.Handle) +
		e.Count(t, `SELECT count(*) FROM proxy_token`); n != 1 {
		t.Fatal("a failed mint left the handle consumed or a session or token behind")
	}
	e.Exec(t, `DROP TRIGGER reject_mint ON audit_event`)
	resp, out := pmon.Do(http.MethodPost, "/auth/device/poll", poll)
	var r device.PollResult
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &r) != nil || r.Principal != "bob@example.com" {
		t.Fatalf("retried poll: %d %s", resp.StatusCode, out)
	}
}

func TestDeviceAuthorizeRefusesAnEndedSessionOrAnExpiredLogin(t *testing.T) {
	e := routetest.Setup(t)
	pmon, b := e.Browser(t), e.Browser(t)
	pending := func(handle string) bool {
		return e.Count(t, `SELECT count(*) FROM device_login WHERE handle = $1 AND status = 'PENDING'`, handle) == 1
	}

	s := pmon.StartDevice(`{}`)
	b.DebugLogin("alice@example.com")
	b.Expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK, "")
	e.Exec(t, `UPDATE principal_session SET ended_at = now(), ended_reason = 'SIGNED_OUT', liveness_status = 'INACTIVE' WHERE kind = 'WEB'`)
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode || !pending(s.Handle) {
		t.Fatalf("an ended session authorized: %s", loc)
	}
	b.DebugLogin("alice@example.com")
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode || !pending(s.Handle) {
		t.Fatalf("a new session authorized without confirming again: %s", loc)
	}

	b.Expect(http.MethodPost, "/auth/device/confirm", `{"userCode":"`+s.UserCode+`"}`, http.StatusOK, "")
	e.Exec(t, `UPDATE device_login SET expires_at = now() - interval '1 second' WHERE handle = $1`, s.Handle)
	if loc := b.AuthorizeDevice(s.UserCode); loc != "/device?user_code="+s.UserCode || !pending(s.Handle) {
		t.Fatalf("an expired login was approved: %s", loc)
	}
}

func TestSessionRenew(t *testing.T) {
	e := routetest.Setup(t)
	r := pmonLogin(t, e, "alice@example.com", `{"ttlSeconds":600}`)
	pmon := e.Browser(t)

	pmon.Expect(http.MethodPost, "/auth/session/renew", `{"principal":"alice@example.com"}`, http.StatusUnauthorized,
		`{"code":"auth.missing_renewal_token","params":{}}`)
	if resp, out := pmon.Bearer("/auth/session/renew", "pmr_wrong"); resp.StatusCode != http.StatusUnauthorized || out != `{"code":"common.unauthenticated","params":{}}` {
		t.Fatalf("wrong secret: %d %s", resp.StatusCode, out)
	}
	resp, out := pmon.Bearer("/auth/session/renew", r.RenewalToken)
	var renewed struct{ Token, ExpiresAt string }
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &renewed) != nil || renewed.Token == r.Token ||
		e.Count(t, `SELECT count(*) FROM proxy_token WHERE token_hash = $1 AND expires_at BETWEEN now() + interval '590 seconds' AND now() + interval '600 seconds'`, device.SHA256Hex(renewed.Token)) != 1 {
		t.Fatalf("renew: %d %s", resp.StatusCode, out)
	}
	if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.session.renew' AND channel = 'pmon' AND outcome = 'SUCCESS'
		AND principal = 'alice@example.com'`); n != 1 {
		t.Fatalf("renew audit rows %d", n)
	}

	expired := `{"code":"auth.session_window_expired","params":{}}`
	for _, tc := range []struct{ name, set, reset string }{
		{"deprovisioned", `INSERT INTO app_user (principal, source, active) VALUES ('alice@example.com', 'LOCAL', false)`, `DELETE FROM app_user`},
		{"inactive", `UPDATE principal_session SET liveness_status = 'INACTIVE' WHERE kind = 'DAEMON'`, `UPDATE principal_session SET liveness_status = 'ACTIVE'`},
		{"window closed", `UPDATE principal_session SET absolute_expires_at = now() WHERE kind = 'DAEMON'`, ``},
	} {
		e.Exec(t, tc.set)
		if resp, out := pmon.Bearer("/auth/session/renew", r.RenewalToken); resp.StatusCode != http.StatusUnauthorized || out != expired {
			t.Fatalf("%s: %d %s", tc.name, resp.StatusCode, out)
		}
		if tc.reset != "" {
			e.Exec(t, tc.reset)
		}
	}
}

func TestPmonLogout(t *testing.T) {
	e := routetest.Setup(t)
	pmon := e.Browser(t)
	if resp, _ := pmon.Bearer("/auth/session/logout", "pmr_unknown"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unknown bearer: %d", resp.StatusCode)
	}
	pmon.Expect(http.MethodPost, "/auth/session/logout", "", http.StatusUnauthorized, `{"code":"auth.missing_renewal_token","params":{}}`)
	accessToken := func(secret string) string {
		t.Helper()
		resp, out := pmon.Bearer("/auth/session/mcp-token", secret)
		var m struct{ AccessToken string }
		if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &m) != nil {
			t.Fatalf("mcp-token: %d %s", resp.StatusCode, out)
		}
		return m.AccessToken
	}
	live := func(tokens ...string) int {
		t.Helper()
		var hashes []string
		for _, tok := range tokens {
			hashes = append(hashes, device.SHA256Hex(tok))
		}
		return e.Count(t, `SELECT count(*) FROM proxy_token WHERE token_hash = ANY($1) AND revoked_at IS NULL`, hashes)
	}

	r := pmonLogin(t, e, "alice@example.com", `{}`)
	resp, out := pmon.Bearer("/auth/session/renew", r.RenewalToken)
	var renewed struct{ Token string }
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(out), &renewed) != nil {
		t.Fatalf("renew: %d %s", resp.StatusCode, out)
	}
	mcp := accessToken(r.RenewalToken)
	sibling := pmonLogin(t, e, "alice@example.com", `{}`)
	siblingMCP := accessToken(sibling.RenewalToken)
	for range 2 {
		if resp, _ := pmon.Bearer("/auth/session/logout", r.RenewalToken); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("logout: %d", resp.StatusCode)
		}
	}
	if n := live(r.Token, renewed.Token, mcp); n != 0 {
		t.Fatalf("%d of the login's tokens survived the logout", n)
	}
	if n := live(sibling.Token, siblingMCP) + e.Count(t, `SELECT count(*) FROM oauth_consent WHERE revoked_at IS NULL`); n != 3 {
		t.Fatal("logout revoked another login's tokens or the consent it still holds")
	}
	if resp, _ := pmon.Bearer("/auth/session/renew", sibling.RenewalToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("logout ended another login of the same principal: %d", resp.StatusCode)
	}
	accessToken(sibling.RenewalToken)
	if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.logout' AND statement = 'pmon session signed out' AND channel = 'pmon'
		AND principal = 'alice@example.com'`); n != 1 {
		t.Fatalf("logout audit rows %d", n)
	}
	for _, secret := range []string{r.RenewalToken, r.Token, renewed.Token, mcp} {
		if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE position($1 in coalesce(resource, '') || statement || coalesce(detail, '')) > 0`, secret); n != 0 {
			t.Fatalf("%s reached the audit trail", secret)
		}
	}
	expired := `{"code":"auth.session_window_expired","params":{}}`
	for _, path := range []string{"/auth/session/renew", "/auth/session/mcp-token"} {
		if resp, out := pmon.Bearer(path, r.RenewalToken); resp.StatusCode != http.StatusUnauthorized || out != expired {
			t.Fatalf("%s after logout: %d %s", path, resp.StatusCode, out)
		}
	}

	replaced := pmonLogin(t, e, "bob@example.com", `{}`)
	if resp, out := pmon.Bearer("/auth/session/mcp-token", replaced.RenewalToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("mcp-token: %d %s", resp.StatusCode, out)
	}
	if resp, _ := pmon.Do(http.MethodPost, "/auth/session/logout?replaced=true", "", "Authorization", "Bearer "+replaced.RenewalToken); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("replaced logout: %d", resp.StatusCode)
	}
	if n := e.Count(t, `SELECT count(*) FROM proxy_token WHERE token_hash = $1 AND revoked_at IS NULL AND retired_at IS NOT NULL`, device.SHA256Hex(replaced.Token)); n != 1 {
		t.Fatal("a replaced login's wire token must be retired, not revoked")
	}
	if n := e.Count(t, `SELECT count(*) FROM proxy_token WHERE principal = 'bob@example.com' AND kind = 'MCP_ACCESS' AND revoked_at IS NULL`) +
		e.Count(t, `SELECT count(*) FROM oauth_consent WHERE principal = 'bob@example.com' AND revoked_at IS NULL`); n != 0 {
		t.Fatal("a replaced login's MCP token and consent must be revoked")
	}
	if resp, out := pmon.Bearer("/auth/session/renew", replaced.RenewalToken); resp.StatusCode != http.StatusUnauthorized || out != expired {
		t.Fatalf("renew after a replaced logout: %d %s", resp.StatusCode, out)
	}
}

func TestPmonMCPToken(t *testing.T) {
	e := routetest.Setup(t)
	pmon := e.Browser(t)
	mint := func(secret string) (int, string, map[string]string) {
		resp, out := pmon.Bearer("/auth/session/mcp-token", secret)
		var m map[string]string
		_ = json.Unmarshal([]byte(out), &m)
		return resp.StatusCode, out, m
	}

	r := pmonLogin(t, e, "alice@example.com", `{"scopes":["mcp:read","mcp:query","mcp:policies:write"]}`)
	status, out, m := mint(r.RenewalToken)
	if status != http.StatusOK || m["scope"] != "mcp:policies:write mcp:query mcp:read" || !strings.HasPrefix(m["accessToken"], "pma_") {
		t.Fatalf("elevated: %d %s", status, out)
	}
	if n := e.Count(t, `SELECT count(*) FROM proxy_token t JOIN oauth_consent c ON c.id = t.consent_id
		WHERE t.token_hash = $1 AND t.kind = 'MCP_ACCESS' AND t.client_id = 'pmon' AND c.scope = t.scope
		  AND t.resource = 'http://127.0.0.1:8080/mcp' AND t.principal_session_id IS NOT NULL`, device.SHA256Hex(m["accessToken"])); n != 1 {
		t.Fatal("the MCP token is not stored under its consent")
	}
	if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.session.mcp_token' AND detail = 'scope=mcp:policies:write mcp:query mcp:read'`); n != 1 {
		t.Fatalf("mcp-token audit rows %d", n)
	}
	expires, _ := time.Parse(time.RFC3339Nano, m["expiresAt"])
	if d := time.Until(expires); d < 590*time.Second || d > 600*time.Second {
		t.Fatalf("expires in %v", d)
	}

	e.Exec(t, `UPDATE principal_session SET elevated_until = now() + interval '100 seconds' WHERE kind = 'DAEMON'`)
	if status, out, m := mint(r.RenewalToken); status != http.StatusOK || m["scope"] != "mcp:policies:write mcp:query mcp:read" {
		t.Fatalf("near the window's end: %d %s", status, out)
	} else if expires, err := time.Parse(time.RFC3339Nano, m["expiresAt"]); err != nil || e.Count(t, `SELECT count(*) FROM proxy_token t
		JOIN principal_session ps ON ps.id = t.principal_session_id WHERE t.token_hash = $1 AND t.expires_at = ps.elevated_until
		AND ps.elevated_until = $2`, device.SHA256Hex(m["accessToken"]), expires) != 1 {
		t.Fatalf("an elevated MCP token minted near the window's end does not expire with it: %s", m["expiresAt"])
	}
	e.Exec(t, `UPDATE principal_session SET elevated_until = now() - interval '1 second' WHERE kind = 'DAEMON'`)
	if status, out, m := mint(r.RenewalToken); status != http.StatusOK || m["scope"] != "mcp:query mcp:read" {
		t.Fatalf("after the window: %d %s", status, out)
	}

	only := pmonLogin(t, e, "bob@example.com", `{"scopes":["mcp:tokens"],"ttlSeconds":300}`)
	if status, out, m := mint(only.RenewalToken); status != http.StatusOK {
		t.Fatalf("elevated only: %d %s", status, out)
	} else if expires, _ := time.Parse(time.RFC3339Nano, m["expiresAt"]); time.Until(expires) > 300*time.Second {
		t.Fatalf("an MCP token outlived its login: %s", m["expiresAt"])
	}
	e.Exec(t, `UPDATE principal_session SET elevated_until = now() WHERE principal = 'bob@example.com'`)
	if status, out, _ := mint(only.RenewalToken); status != http.StatusForbidden || out != `{"code":"auth.scopes_expired","params":{}}` {
		t.Fatalf("no scopes left: %d %s", status, out)
	}

	pmon.Expect(http.MethodPost, "/auth/session/mcp-token", "", http.StatusUnauthorized, `{"code":"auth.missing_renewal_token","params":{}}`)
	if status, out, _ := mint("pmr_not-a-session"); status != http.StatusUnauthorized || out != `{"code":"common.unauthenticated","params":{}}` {
		t.Fatalf("unknown bearer: %d %s", status, out)
	}
	closed := pmonLogin(t, e, "carol@example.com", `{}`)
	e.Exec(t, `UPDATE principal_session SET liveness_status = 'INACTIVE', absolute_expires_at = now() WHERE principal = 'carol@example.com'`)
	if status, out, _ := mint(closed.RenewalToken); status != http.StatusUnauthorized || out != `{"code":"auth.session_window_expired","params":{}}` {
		t.Fatalf("closed window: %d %s", status, out)
	}
	if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.session.mcp_token' AND channel <> 'pmon'`) +
		e.Count(t, `SELECT count(*) FROM audit_event WHERE position('pma_' in coalesce(resource, '') || statement || coalesce(detail, '')) > 0
			OR position('pmr_' in coalesce(resource, '') || statement || coalesce(detail, '')) > 0`); n != 0 {
		t.Fatal("an MCP token mint was audited off the pmon channel or with a secret")
	}
	e.Exec(t, `INSERT INTO app_user (principal, source, active) VALUES ('alice@example.com', 'LOCAL', false)`)
	if status, out, _ := mint(r.RenewalToken); status != http.StatusUnauthorized || out != `{"code":"auth.session_window_expired","params":{}}` {
		t.Fatalf("deactivated: %d %s", status, out)
	}
	e.Exec(t, `DELETE FROM app_user`)
	e.Exec(t, `UPDATE principal_session SET created_at = now() - interval '13 hours' WHERE principal = 'alice@example.com' AND kind = 'DAEMON'`)
	if status, out, _ := mint(r.RenewalToken); status != http.StatusUnauthorized || out != `{"code":"auth.session_window_expired","params":{}}` {
		t.Fatalf("past the login: %d %s", status, out)
	}
}

func TestSessionRenewWaitsForTheTeardownLock(t *testing.T) {
	e := routetest.Setup(t)
	r := pmonLogin(t, e, "alice@example.com", `{}`)
	ctx := context.Background()
	tx, err := e.St.Pool.Begin(ctx)
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
		resp, out := e.Browser(t).Bearer("/auth/session/renew", r.RenewalToken)
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

func TestSessionRenewAfterDeactivation(t *testing.T) {
	e := routetest.Setup(t)
	admin := e.St.WebSession(t, "admin@example.com", "k-admin", "dev-admin")
	e.Authz.Allow = map[string]bool{"admin@example.com admin.identity System:": true}
	user := func(principal string) string {
		t.Helper()
		status, out := e.Do(t, http.MethodPost, "/api/users", `{"principal":"`+principal+`"}`, admin)
		var u struct{ ID int64 }
		if status != http.StatusCreated || json.Unmarshal([]byte(out), &u) != nil {
			t.Fatalf("create %s: %d %s", principal, status, out)
		}
		return "/api/users/" + strconv.FormatInt(u.ID, 10)
	}
	setActive := func(path, principal string, active bool) (int, string) {
		return e.Do(t, http.MethodPut, path, `{"principal":"`+principal+`","active":`+strconv.FormatBool(active)+`}`, admin)
	}
	renew := func(secret string) (int, string) {
		resp, out := e.Browser(t).Bearer("/auth/session/renew", secret)
		var r struct{ Token string }
		if resp.StatusCode == http.StatusOK && json.Unmarshal([]byte(out), &r) == nil {
			return resp.StatusCode, r.Token
		}
		return resp.StatusCode, out
	}
	expired := `{"code":"auth.session_window_expired","params":{}}`

	alice := user("alice@example.com")
	first := pmonLogin(t, e, "alice@example.com", `{}`)
	second := pmonLogin(t, e, "alice@example.com", `{}`)
	status, renewed := renew(second.RenewalToken)
	if status != http.StatusOK {
		t.Fatalf("renew: %d %s", status, renewed)
	}
	if status, out := setActive(alice, "alice@example.com", false); status != http.StatusOK {
		t.Fatalf("deactivate: %d %s", status, out)
	}
	if n := e.Count(t, `SELECT count(*) FROM proxy_token WHERE token_hash = $1 AND revoked_at IS NOT NULL`, device.SHA256Hex(renewed)); n != 1 {
		t.Fatal("deactivation left the renewed token live")
	}
	for _, secret := range []string{first.RenewalToken, second.RenewalToken} {
		if status, out := renew(secret); status != http.StatusUnauthorized || out != expired {
			t.Fatalf("renew while deactivated: %d %s", status, out)
		}
	}
	if status, out := setActive(alice, "alice@example.com", true); status != http.StatusOK {
		t.Fatalf("reactivate: %d %s", status, out)
	}
	if status, out := renew(second.RenewalToken); status != http.StatusUnauthorized || out != expired {
		t.Fatalf("reactivation resurrected the renewal secret: %d %s", status, out)
	}

	bob := user("bob@example.com")
	login := pmonLogin(t, e, "bob@example.com", `{}`)
	ctx := context.Background()
	tx, err := e.St.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('bob@example.com'))`); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		status, _ := setActive(bob, "bob@example.com", false)
		done <- status
	}()
	select {
	case status := <-done:
		t.Fatalf("deactivation answered %d while another holder had the principal's lock", status)
	case <-time.After(300 * time.Millisecond):
	}
	if n := e.Count(t, `SELECT count(*) FROM proxy_token WHERE token_hash = $1 AND revoked_at IS NULL`, device.SHA256Hex(login.Token)); n != 1 {
		t.Fatal("the token was revoked while the teardown waited for the lock")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if status := <-done; status != http.StatusOK {
		t.Fatalf("deactivate after the lock released: %d", status)
	}
	if n := e.Count(t, `SELECT count(*) FROM proxy_token WHERE token_hash = $1 AND revoked_at IS NOT NULL`, device.SHA256Hex(login.Token)); n != 1 {
		t.Fatal("the teardown did not revoke the token once it got the lock")
	}
}

func TestDaemonQueriesSkipWebRows(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	r := pmonLogin(t, e, "alice@example.com", `{}`)
	bystander := pmonLogin(t, e, "bob@example.com", `{}`)
	var web int64
	if err := e.St.Pool.QueryRow(ctx, `SELECT id FROM principal_session WHERE kind = 'WEB' AND principal = 'alice@example.com' AND ended_at IS NULL`).Scan(&web); err != nil {
		t.Fatal(err)
	}
	e.Exec(t, `UPDATE principal_session SET renewal_token_hash = $1, ttl_seconds = 900 WHERE id = $2`, device.SHA256Hex("pmr_web"), web)
	q := db.New(e.St.Pool)
	if _, err := q.DaemonSession(ctx, web); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("a WEB row resolved as a daemon session: %v", err)
	}
	if resp, out := e.Browser(t).Bearer("/auth/session/renew", "pmr_web"); resp.StatusCode != http.StatusUnauthorized || out != `{"code":"common.unauthenticated","params":{}}` {
		t.Fatalf("a WEB row renewed: %d %s", resp.StatusCode, out)
	}

	if err := q.DeactivateDaemonSessions(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if n := e.Count(t, `SELECT count(*) FROM principal_session WHERE renewal_token_hash = $1 AND liveness_status = 'INACTIVE' AND absolute_expires_at <= now()`,
		device.SHA256Hex(r.RenewalToken)); n != 1 {
		t.Fatal("the daemon session was not closed")
	}
	if n := e.Count(t, `SELECT count(*) FROM principal_session WHERE id = $1 AND ended_at IS NULL AND liveness_status = 'ACTIVE' AND absolute_expires_at > now()`, web) +
		e.Count(t, `SELECT count(*) FROM principal_session WHERE renewal_token_hash = $1 AND liveness_status = 'ACTIVE' AND absolute_expires_at > now()`,
			device.SHA256Hex(bystander.RenewalToken)); n != 2 {
		t.Fatal("closing a principal's daemon sessions touched a web session or another principal")
	}
}
