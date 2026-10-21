package websession_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

func TestSessionRoutes(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO app_role (name) VALUES ('analyst'), ('auditor')`); err != nil {
		t.Fatal(err)
	}
	reason := func(id string) string {
		var r *string
		_ = e.St.Pool.QueryRow(ctx, `SELECT ended_reason FROM principal_session WHERE id = $1::bigint`, id).Scan(&r)
		if r == nil {
			return ""
		}
		return *r
	}
	b := e.Browser(t)

	b.Expect(http.MethodGet, "/auth/config", "", http.StatusOK,
		`{"oidcEnabled":false,"authDebug":true,"session":{"heartbeatMs":90000,"idleWarnLeadMs":60000,"absoluteWarnLeadMs":300000,"absoluteCapAmount":2,"absoluteCapUnit":"hours"}}`)
	b.Expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, `{"reason":"none"}`)

	if resp := b.Expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","requesterIp":"10.0.0.01"}`, http.StatusBadRequest,
		`{"code":"auth.invalid_requester_ip","params":{}}`); len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("a refused login set cookies: %v", resp.Header.Values("Set-Cookie"))
	}
	b.Expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","roles":["nope"]}`, http.StatusNotFound,
		`{"code":"common.not_found","params":{"resource":"role 'nope'"}}`)
	resp := b.Expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","roles":[" auditor","analyst","auditor",""],"requesterIp":" 10.1.2.3 "}`,
		http.StatusOK, `{"principal":"alice@example.com","roles":["auditor","analyst"],"requesterIp":"10.1.2.3"}`)
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 2 ||
		!regexp.MustCompile(`^pm_did=[0-9a-f-]{36}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax; \$x-enc=URI_ENCODING$`).MatchString(cookies[0]) ||
		!regexp.MustCompile(`^pm_session=[0-9a-f]{64}%2F[0-9a-f]{64}; Max-Age=7200; Expires=[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT; Path=/; HttpOnly; SameSite=Lax; \$x-enc=URI_ENCODING$`).MatchString(cookies[1]) {
		t.Fatalf("cookies %q", cookies)
	}

	me := b.Expect(http.MethodGet, "/auth/me", "", http.StatusOK, `{"principal":"alice@example.com","roles":["analyst","auditor"],"requesterIp":"10.1.2.3"}`)
	if me.Header.Get("Cache-Control") != "no-store" || len(me.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("me headers %v", me.Header)
	}
	_, status := b.Do(http.MethodGet, "/auth/session/status", "")
	id := regexp.MustCompile(`"sessionId":(\d+)`).FindStringSubmatch(status)
	if id == nil || !regexp.MustCompile(`^\{"now":"[^"]+Z","idleExpiresAt":"[^"]+Z","absoluteExpiresAt":"[^"]+Z","principal":"alice@example.com","sessionId":\d+\}$`).MatchString(status) {
		t.Fatalf("status %s", status)
	}
	clocks := func() (idle, absolute string) {
		_ = e.St.Pool.QueryRow(ctx, `SELECT idle_expires_at::text, absolute_expires_at::text FROM principal_session WHERE id = $1::bigint`, id[1]).Scan(&idle, &absolute)
		return
	}
	idleBefore, absBefore := clocks()
	b.Expect(http.MethodPost, "/auth/session/heartbeat", "", http.StatusOK, "")
	idleAfter, absAfter := clocks()
	if idleAfter <= idleBefore || absAfter != absBefore {
		t.Fatalf("heartbeat: idle %s -> %s, absolute %s -> %s", idleBefore, idleAfter, absBefore, absAfter)
	}
	b.Expect(http.MethodPost, "/auth/session/heartbeat", "", http.StatusOK, "")
	if again, _ := clocks(); again != idleAfter {
		t.Fatalf("a heartbeat inside the slide interval moved idle: %s -> %s", idleAfter, again)
	}

	u, _ := url.Parse(e.Srv.URL)
	key := func(br *routetest.Browser) string {
		for _, c := range br.Jar.Cookies(u) {
			if c.Name == "pm_session" {
				return c.Value
			}
		}
		return ""
	}
	firstKey := key(b)
	webRows := `SELECT count(*) FROM principal_session WHERE principal = 'alice@example.com' AND kind = 'WEB'`
	before := e.Count(t, webRows)
	b.Expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","roles":["analyst","nope"]}`, http.StatusNotFound, "")
	if after := e.Count(t, webRows); after != before {
		t.Fatalf("a rejected login minted a session: %d -> %d", before, after)
	}
	b.Expect(http.MethodGet, "/auth/me", "", http.StatusOK, `{"principal":"alice@example.com","roles":["analyst","auditor"],"requesterIp":"10.1.2.3"}`)
	b.Expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","roles":["analyst"]}`, http.StatusOK, `{"principal":"alice@example.com","roles":["analyst"]}`)
	if key(b) != firstKey || reason(id[1]) != "DISPLACED" {
		t.Fatalf("a re-login must keep the tracker and displace the old row: %q %q %s", firstKey, key(b), reason(id[1]))
	}
	_, status = b.Do(http.MethodGet, "/auth/session/status", "")
	id = regexp.MustCompile(`"sessionId":(\d+)`).FindStringSubmatch(status)

	other := e.Browser(t)
	other.Expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com"}`, http.StatusOK, `{"principal":"alice@example.com","roles":[]}`)
	other.Expect(http.MethodGet, "/auth/me", "", http.StatusOK, `{"principal":"alice@example.com","roles":[]}`)
	b.Expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, `{"reason":"displaced"}`)
	if reason(id[1]) != "DISPLACED" || strings.Join(e.Authz.Ended, ",") != "alice@example.com,alice@example.com" {
		t.Fatalf("displacement: %s %v", reason(id[1]), e.Authz.Ended)
	}

	_, otherStatus := other.Do(http.MethodGet, "/auth/session/status", "")
	otherID := regexp.MustCompile(`"sessionId":(\d+)`).FindStringSubmatch(otherStatus)[1]
	other.Expect(http.MethodPost, "/auth/logout", `{"sessionId":1}`, http.StatusOK, `{"ended":false}`)
	other.Expect(http.MethodGet, "/auth/me", "", http.StatusOK, "")
	thief := e.Browser(t)
	thief.Jar.SetCookies(u, other.Jar.Cookies(u))
	thief.SetDevice("11111111-1111-4111-8111-111111111111")
	thief.Expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, `{"reason":"bind_mismatch"}`)
	other.Expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, `{"reason":"bind_mismatch"}`)

	third := e.Browser(t)
	third.Expect(http.MethodPost, "/auth/debug", `{"principal":"bob@example.com"}`, http.StatusOK, "")
	_, thirdStatus := third.Do(http.MethodGet, "/auth/session/status", "")
	thirdID := regexp.MustCompile(`"sessionId":(\d+)`).FindStringSubmatch(thirdStatus)[1]
	out := third.Expect(http.MethodPost, "/auth/logout", "", http.StatusOK, `{"ended":true}`)
	if c := out.Header.Get("Set-Cookie"); c != "pm_session=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; SameSite=Lax; $x-enc=URI_ENCODING" {
		t.Fatalf("logout cookie %q", c)
	}
	if reason(thirdID) != "SIGNED_OUT" || reason(otherID) != "DEVICE_BIND_MISMATCH" {
		t.Fatalf("reasons %s %s", reason(thirdID), reason(otherID))
	}
	if strings.Join(e.Authz.Ended, ",") != "alice@example.com,alice@example.com,alice@example.com,bob@example.com" {
		t.Fatalf("logout must tell Kotlin the session ended: %v", e.Authz.Ended)
	}

	want := []string{
		"admin|alice@example.com|admin.identity|User::\"alice@example.com\"|replace direct roles of 'alice@example.com' [auditor, analyst]|10.1.2.3|console",
		"admin|alice@example.com|admin.identity|User::\"alice@example.com\"|replace direct roles of 'alice@example.com' [analyst]|10.1.2.3|console",
		"admin|alice@example.com|admin.identity|User::\"alice@example.com\"|replace direct roles of 'alice@example.com' []|127.0.0.1|console",
		"admin|bob@example.com|admin.identity|User::\"bob@example.com\"|replace direct roles of 'bob@example.com' []|127.0.0.1|console",
		"auth|bob@example.com|auth.logout|Session::\"" + thirdID + "\"|Web session signed out|127.0.0.1|session",
	}
	if got := routetest.AuditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	routetest.VerifyChain(t, e)
}

func TestDebugLoginIsOffWithoutAuthDebug(t *testing.T) {
	e := routetest.SetupConfig(t, routetest.Config{AuthDebugOff: true})
	status, body := e.Do(t, http.MethodPost, "/auth/debug", `{"principal":"x"}`, nil)
	if status != http.StatusNotFound || body != `{"code":"common.not_found","params":{"resource":"endpoint"}}` {
		t.Fatalf("%d %s", status, body)
	}
}

func TestAuthConfigMixedUnitCap(t *testing.T) {
	settings := dbtest.Settings()
	settings.AbsoluteSeconds = 90 * 60
	e := routetest.SetupConfig(t, routetest.Config{Settings: &settings})
	if _, body := e.Browser(t).Do(http.MethodGet, "/auth/config", ""); !strings.Contains(body, `"absoluteCapAmount":90,"absoluteCapUnit":"minutes"}`) {
		t.Fatalf("config %s", body)
	}
}

func webSessionID(t *testing.T, e *routetest.Env, principal string) int64 {
	t.Helper()
	var id int64
	if err := e.St.Pool.QueryRow(context.Background(), `SELECT id FROM principal_session WHERE principal = $1 AND kind = 'WEB' ORDER BY id DESC LIMIT 1`, principal).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func endedReason(t *testing.T, e *routetest.Env, id int64) string {
	t.Helper()
	var r *string
	_ = e.St.Pool.QueryRow(context.Background(), `SELECT ended_reason FROM principal_session WHERE id = $1`, id).Scan(&r)
	if r == nil {
		return ""
	}
	return *r
}

func TestSessionLogout(t *testing.T) {
	e := routetest.Setup(t)
	u, _ := url.Parse(e.Srv.URL)
	logoutRows := func(id int64) int {
		return e.Count(t, `SELECT count(*) FROM audit_event WHERE kind = 'auth' AND action = 'auth.logout' AND resource = $1
			AND outcome = 'SUCCESS' AND decision = 'ALLOW' AND channel = 'session' AND client_addr = '127.0.0.1'`, fmt.Sprintf(`Session::"%d"`, id))
	}

	b := e.Browser(t)
	b.DebugLogin("empty-body@example.com")
	if resp, body := b.Do(http.MethodPost, "/auth/logout", "", "Content-Type", "application/json"); resp.StatusCode != http.StatusOK || body != `{"ended":true}` {
		t.Fatalf("an empty JSON logout: %d %s", resp.StatusCode, body)
	}

	b.DebugLogin("web@example.com")
	captured := b.Jar.Cookies(u)
	id := webSessionID(t, e, "web@example.com")
	b.Expect(http.MethodPost, "/auth/logout", "", http.StatusOK, `{"ended":true}`)
	if r := endedReason(t, e, id); r != session.EndedSignedOut || logoutRows(id) != 1 {
		t.Fatalf("logout: reason %s, rows %d", r, logoutRows(id))
	}
	b.Expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, "")
	if status, _ := e.Do(t, http.MethodGet, "/auth/me", "", captured); status != http.StatusUnauthorized {
		t.Fatalf("a replayed cookie after logout: %d", status)
	}

	b.DebugLogin("conditional@example.com")
	stale := webSessionID(t, e, "conditional@example.com")
	b.DebugLogin("conditional@example.com")
	current := webSessionID(t, e, "conditional@example.com")
	resp := b.Expect(http.MethodPost, "/auth/logout", fmt.Sprintf(`{"sessionId":%d}`, stale), http.StatusOK, `{"ended":false}`)
	if len(resp.Header.Values("Set-Cookie")) != 0 || logoutRows(current) != 0 {
		t.Fatalf("a stale conditional logout: %v, rows %d", resp.Header.Values("Set-Cookie"), logoutRows(current))
	}
	b.Expect(http.MethodGet, "/auth/session/status", "", http.StatusOK, "")
	resp = b.Expect(http.MethodPost, "/auth/logout", fmt.Sprintf(`{"sessionId":%d}`, current), http.StatusOK, `{"ended":true}`)
	if !strings.Contains(resp.Header.Get("Set-Cookie"), "Max-Age=0") || logoutRows(current) != 1 {
		t.Fatalf("a matching logout: %v", resp.Header.Values("Set-Cookie"))
	}
	b.Expect(http.MethodGet, "/auth/session/status", "", http.StatusUnauthorized, `{"reason":"none"}`)

	b.DebugLogin("idle-logout@example.com")
	idle := webSessionID(t, e, "idle-logout@example.com")
	e.Exec(t, `UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = $1`, idle)
	b.Expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, "")
	b.Expect(http.MethodPost, "/auth/logout", "", http.StatusOK, `{"ended":true}`)
	if r := endedReason(t, e, idle); r != session.EndedSignedOut || logoutRows(idle) != 1 ||
		e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.logout' AND principal = 'idle-logout@example.com'`) != 1 {
		t.Fatalf("an idle-expired logout: %s, rows %d", r, logoutRows(idle))
	}
}

func TestSessionReasons(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	u, _ := url.Parse(e.Srv.URL)
	expect := func(b *routetest.Browser, method, path string, status int, body string) {
		t.Helper()
		if resp := b.Expect(method, path, "", status, body); resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: Cache-Control %q", method, path, resp.Header.Get("Cache-Control"))
		}
	}
	sessionCookie := func(b *routetest.Browser) *http.Cookie {
		t.Helper()
		for _, c := range b.Jar.Cookies(u) {
			if c.Name == "pm_session" {
				return c
			}
		}
		t.Fatal("no pm_session")
		return nil
	}

	fresh := e.Browser(t)
	expect(fresh, http.MethodGet, "/auth/session/status", http.StatusUnauthorized, `{"reason":"none"}`)
	expect(fresh, http.MethodGet, "/auth/me", http.StatusUnauthorized, `{"reason":"none"}`)
	expect(fresh, http.MethodPost, "/auth/session/heartbeat", http.StatusUnauthorized, `{"reason":"none"}`)

	b := e.Browser(t)
	b.DebugLogin("status@example.com")
	id := webSessionID(t, e, "status@example.com")
	e.Exec(t, `UPDATE principal_session SET last_seen_at = now() - interval '3 minutes', idle_expires_at = idle_expires_at - interval '3 minutes' WHERE id = $1`, id)
	deadlines := func() (idle, absolute, now time.Time) {
		_ = e.St.Pool.QueryRow(ctx, `SELECT idle_expires_at, absolute_expires_at, clock_timestamp() FROM principal_session WHERE id = $1`, id).Scan(&idle, &absolute, &now)
		return
	}
	var st struct {
		Now, IdleExpiresAt, AbsoluteExpiresAt, Principal string
		SessionID                                        int64
	}
	call := func(method, path string) {
		t.Helper()
		resp, body := b.Do(method, path, "")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" || json.Unmarshal([]byte(body), &st) != nil {
			t.Fatalf("%s %s: %d %v %s", method, path, resp.StatusCode, resp.Header, body)
		}
	}
	at := func(s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	idleBefore, absolute, dbBefore := deadlines()
	call(http.MethodGet, "/auth/session/status")
	_, _, dbAfter := deadlines()
	if st.Principal != "status@example.com" || st.SessionID != id || !at(st.IdleExpiresAt).Equal(idleBefore) || !at(st.AbsoluteExpiresAt).Equal(absolute) ||
		at(st.Now).Before(dbBefore.Add(-2*time.Second)) || at(st.Now).After(dbAfter.Add(2*time.Second)) {
		t.Fatalf("status %+v against idle %v absolute %v db %v..%v", st, idleBefore, absolute, dbBefore, dbAfter)
	}
	expect(b, http.MethodGet, "/auth/me", http.StatusOK, "")
	if status, _ := e.Do(t, http.MethodGet, "/api/tokens", "", b.Jar.Cookies(u)); status != http.StatusForbidden {
		t.Fatalf("/api with a session: %d", status)
	}
	if idle, _, _ := deadlines(); !idle.Equal(idleBefore) {
		t.Fatalf("status, me or /api slid idle: %v -> %v", idleBefore, idle)
	}
	call(http.MethodPost, "/auth/session/heartbeat")
	if idle, _, _ := deadlines(); !idle.After(idleBefore) || !at(st.IdleExpiresAt).Equal(idle) || st.SessionID != id {
		t.Fatalf("heartbeat %+v, idle %v -> %v", st, idleBefore, idle)
	}
	e.Exec(t, `UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = $1`, id)
	expect(b, http.MethodGet, "/auth/session/status", http.StatusUnauthorized, `{"reason":"expired"}`)
	expect(b, http.MethodGet, "/auth/me", http.StatusUnauthorized, `{"reason":"expired"}`)
	expect(b, http.MethodPost, "/auth/session/heartbeat", http.StatusUnauthorized, `{"reason":"expired"}`)

	for _, tc := range []struct{ principal, sql string }{
		{"missing@example.com", `DELETE FROM principal_session WHERE principal = $1`},
		{"expired@example.com", `UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE principal = $1`},
	} {
		br := e.Browser(t)
		br.DebugLogin(tc.principal)
		e.Exec(t, tc.sql, tc.principal)
		br.Expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, "")
		if status, _ := e.Do(t, http.MethodGet, "/api/tokens", "", br.Jar.Cookies(u)); status != http.StatusUnauthorized {
			t.Fatalf("%s: /api %d", tc.principal, status)
		}
	}

	first, second := e.Browser(t), e.Browser(t)
	first.DebugLogin("reason-status@example.com")
	captured := sessionCookie(first)
	second.DebugLogin("reason-status@example.com")
	expect(first, http.MethodGet, "/auth/session/status", http.StatusUnauthorized, `{"reason":"displaced"}`)
	expect(first, http.MethodGet, "/auth/me", http.StatusUnauthorized, `{"reason":"displaced"}`)
	expect(first, http.MethodPost, "/auth/session/heartbeat", http.StatusUnauthorized, `{"reason":"displaced"}`)
	if status, body := e.Do(t, http.MethodGet, "/auth/session/status", "", []*http.Cookie{captured}); status != http.StatusUnauthorized || body != `{"reason":"displaced"}` {
		t.Fatalf("a replayed displaced cookie: %d %s", status, body)
	}

	wrongDevice := &http.Cookie{Name: "pm_did", Value: "00000000-0000-0000-0000-000000000000"}
	for _, tc := range []struct {
		principal, path string
		device          *http.Cookie
	}{
		{"bind-status@example.com", "/auth/session/status", wrongDevice},
		{"bind-me-first@example.com", "/auth/me", wrongDevice},
		{"bind-absent@example.com", "/auth/session/status", nil},
	} {
		second.DebugLogin(tc.principal)
		cookies := []*http.Cookie{sessionCookie(second)}
		if tc.device != nil {
			cookies = append(cookies, tc.device)
		}
		if status, body := e.Do(t, http.MethodGet, tc.path, "", cookies); status != http.StatusUnauthorized || body != `{"reason":"bind_mismatch"}` {
			t.Fatalf("%s: %d %s", tc.principal, status, body)
		}
		if r := endedReason(t, e, webSessionID(t, e, tc.principal)); r != session.EndedDeviceMismatch {
			t.Fatalf("%s: ended %s", tc.principal, r)
		}
	}
	if status, body := e.Do(t, http.MethodGet, "/auth/me", "", []*http.Cookie{sessionCookie(second), wrongDevice}); status != http.StatusUnauthorized || body != `{"reason":"bind_mismatch"}` {
		t.Fatalf("me after a bind mismatch: %d %s", status, body)
	}
}

func TestDebugLoginRequesterIP(t *testing.T) {
	e := routetest.Setup(t)
	b := e.Browser(t)
	for _, bad := range []string{
		"not-an-ip", "999.1.1.1", "100.100.1.10:5432", "100.100.1.0/24", "100.100.1.10\x00", "100.100.1.10\x0012",
		"100.100.1.10​", "fe80::1%lo0", "[::1]", "100.100.001.010", "010.1.1.1",
	} {
		in, _ := json.Marshal(map[string]any{"principal": "dev@example.com", "roles": []string{}, "requesterIp": bad})
		b.Expect(http.MethodPost, "/auth/debug", string(in), http.StatusBadRequest, `{"code":"auth.invalid_requester_ip","params":{}}`)
	}
	if n := e.Count(t, `SELECT count(*) FROM principal_session WHERE kind = 'WEB'`); n != 0 {
		t.Fatalf("a refused login minted %d sessions", n)
	}
	for _, good := range []string{"100.100.1.10", "  100.100.1.10  ", "::1", "2001:db8::1", "fe80::1"} {
		b.Expect(http.MethodPost, "/auth/debug", `{"principal":"dev@example.com","requesterIp":"`+good+`"}`, http.StatusOK, "")
		var stored string
		_ = e.St.Pool.QueryRow(context.Background(), `SELECT debug_requester_ip FROM principal_session WHERE kind = 'WEB' ORDER BY id DESC LIMIT 1`).Scan(&stored)
		if stored != strings.TrimSpace(good) {
			t.Errorf("%q stored as %q", good, stored)
		}
	}
}
