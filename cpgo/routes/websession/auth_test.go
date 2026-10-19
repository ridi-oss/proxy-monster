package websession_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
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
	b.Expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","roles":["nope"]}`, http.StatusNotFound, "")
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
