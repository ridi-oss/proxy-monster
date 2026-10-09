package routes

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

type browser struct {
	t   *testing.T
	e   *env
	jar *cookiejar.Jar
}

func (e *env) browser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t, e, jar}
}

func (b *browser) do(method, path, body string, header ...string) (*http.Response, string) {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.e.srv.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := (&http.Client{Jar: b.jar}).Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, string(out)
}

func (b *browser) expect(method, path, body string, status int, want string) *http.Response {
	b.t.Helper()
	resp, got := b.do(method, path, body)
	if resp.StatusCode != status || (want != "" && got != want) {
		b.t.Fatalf("%s %s: %d %s, want %d %s", method, path, resp.StatusCode, got, status, want)
	}
	return resp
}

func (b *browser) setDevice(device string) {
	u, _ := url.Parse(b.e.srv.URL)
	b.jar.SetCookies(u, []*http.Cookie{{Name: "pm_did", Value: device, Path: "/"}})
}

func TestSessionRoutes(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.st.Pool.Exec(ctx, `INSERT INTO app_role (name) VALUES ('analyst'), ('auditor')`); err != nil {
		t.Fatal(err)
	}
	reason := func(id string) string {
		var r *string
		_ = e.st.Pool.QueryRow(ctx, `SELECT ended_reason FROM principal_session WHERE id = $1::bigint`, id).Scan(&r)
		if r == nil {
			return ""
		}
		return *r
	}
	b := e.browser(t)

	b.expect(http.MethodGet, "/auth/config", "", http.StatusOK,
		`{"oidcEnabled":false,"authDebug":true,"session":{"heartbeatMs":90000,"idleWarnLeadMs":60000,"absoluteWarnLeadMs":300000,"absoluteCapAmount":2,"absoluteCapUnit":"hours"}}`)
	b.expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, `{"reason":"none"}`)

	if resp := b.expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","requesterIp":"10.0.0.01"}`, http.StatusBadRequest,
		`{"code":"auth.invalid_requester_ip","params":{}}`); len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("a refused login set cookies: %v", resp.Header.Values("Set-Cookie"))
	}
	b.expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","roles":["nope"]}`, http.StatusNotFound,
		`{"code":"common.not_found","params":{"resource":"role 'nope'"}}`)
	resp := b.expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","roles":[" auditor","analyst","auditor",""],"requesterIp":" 10.1.2.3 "}`,
		http.StatusOK, `{"principal":"alice@example.com","roles":["auditor","analyst"],"requesterIp":"10.1.2.3"}`)
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 2 ||
		!regexp.MustCompile(`^pm_did=[0-9a-f-]{36}; Max-Age=7776000; Path=/; HttpOnly; SameSite=Lax; \$x-enc=URI_ENCODING$`).MatchString(cookies[0]) ||
		!regexp.MustCompile(`^pm_session=[0-9a-f]{64}%2F[0-9a-f]{64}; Max-Age=7200; Expires=[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT; Path=/; HttpOnly; SameSite=Lax; \$x-enc=URI_ENCODING$`).MatchString(cookies[1]) {
		t.Fatalf("cookies %q", cookies)
	}

	me := b.expect(http.MethodGet, "/auth/me", "", http.StatusOK, `{"principal":"alice@example.com","roles":["analyst","auditor"],"requesterIp":"10.1.2.3"}`)
	if me.Header.Get("Cache-Control") != "no-store" || len(me.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("me headers %v", me.Header)
	}
	_, status := b.do(http.MethodGet, "/auth/session/status", "")
	id := regexp.MustCompile(`"sessionId":(\d+)`).FindStringSubmatch(status)
	if id == nil || !regexp.MustCompile(`^\{"now":"[^"]+Z","idleExpiresAt":"[^"]+Z","absoluteExpiresAt":"[^"]+Z","principal":"alice@example.com","sessionId":\d+\}$`).MatchString(status) {
		t.Fatalf("status %s", status)
	}
	clocks := func() (idle, absolute string) {
		_ = e.st.Pool.QueryRow(ctx, `SELECT idle_expires_at::text, absolute_expires_at::text FROM principal_session WHERE id = $1::bigint`, id[1]).Scan(&idle, &absolute)
		return
	}
	idleBefore, absBefore := clocks()
	b.expect(http.MethodPost, "/auth/session/heartbeat", "", http.StatusOK, "")
	idleAfter, absAfter := clocks()
	if idleAfter <= idleBefore || absAfter != absBefore {
		t.Fatalf("heartbeat: idle %s -> %s, absolute %s -> %s", idleBefore, idleAfter, absBefore, absAfter)
	}
	b.expect(http.MethodPost, "/auth/session/heartbeat", "", http.StatusOK, "")
	if again, _ := clocks(); again != idleAfter {
		t.Fatalf("a heartbeat inside the slide interval moved idle: %s -> %s", idleAfter, again)
	}

	u, _ := url.Parse(e.srv.URL)
	key := func(br *browser) string {
		for _, c := range br.jar.Cookies(u) {
			if c.Name == "pm_session" {
				return c.Value
			}
		}
		return ""
	}
	firstKey := key(b)
	b.expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","roles":["nope"]}`, http.StatusNotFound, "")
	b.expect(http.MethodGet, "/auth/me", "", http.StatusOK, `{"principal":"alice@example.com","roles":["analyst","auditor"],"requesterIp":"10.1.2.3"}`)
	b.expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com","roles":["analyst"]}`, http.StatusOK, `{"principal":"alice@example.com","roles":["analyst"]}`)
	if key(b) != firstKey || reason(id[1]) != "DISPLACED" {
		t.Fatalf("a re-login must keep the tracker and displace the old row: %q %q %s", firstKey, key(b), reason(id[1]))
	}
	_, status = b.do(http.MethodGet, "/auth/session/status", "")
	id = regexp.MustCompile(`"sessionId":(\d+)`).FindStringSubmatch(status)

	other := e.browser(t)
	other.expect(http.MethodPost, "/auth/debug", `{"principal":"alice@example.com"}`, http.StatusOK, `{"principal":"alice@example.com","roles":[]}`)
	other.expect(http.MethodGet, "/auth/me", "", http.StatusOK, `{"principal":"alice@example.com","roles":[]}`)
	b.expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, `{"reason":"displaced"}`)
	if reason(id[1]) != "DISPLACED" || strings.Join(e.kotlin.sessionsEnded, ",") != "alice@example.com,alice@example.com" {
		t.Fatalf("displacement: %s %v", reason(id[1]), e.kotlin.sessionsEnded)
	}

	_, otherStatus := other.do(http.MethodGet, "/auth/session/status", "")
	otherID := regexp.MustCompile(`"sessionId":(\d+)`).FindStringSubmatch(otherStatus)[1]
	other.expect(http.MethodPost, "/auth/logout", `{"sessionId":1}`, http.StatusOK, `{"ended":false}`)
	other.expect(http.MethodGet, "/auth/me", "", http.StatusOK, "")
	thief := e.browser(t)
	thief.jar.SetCookies(u, other.jar.Cookies(u))
	thief.setDevice("11111111-1111-4111-8111-111111111111")
	thief.expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, `{"reason":"bind_mismatch"}`)
	other.expect(http.MethodGet, "/auth/me", "", http.StatusUnauthorized, `{"reason":"bind_mismatch"}`)

	third := e.browser(t)
	third.expect(http.MethodPost, "/auth/debug", `{"principal":"bob@example.com"}`, http.StatusOK, "")
	_, thirdStatus := third.do(http.MethodGet, "/auth/session/status", "")
	thirdID := regexp.MustCompile(`"sessionId":(\d+)`).FindStringSubmatch(thirdStatus)[1]
	out := third.expect(http.MethodPost, "/auth/logout", "", http.StatusOK, `{"ended":true}`)
	if c := out.Header.Get("Set-Cookie"); c != "pm_session=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; SameSite=Lax; $x-enc=URI_ENCODING" {
		t.Fatalf("logout cookie %q", c)
	}
	if reason(thirdID) != "SIGNED_OUT" || reason(otherID) != "DEVICE_BIND_MISMATCH" {
		t.Fatalf("reasons %s %s", reason(thirdID), reason(otherID))
	}

	want := []string{
		"admin|alice@example.com|admin.identity|User::\"alice@example.com\"|replace direct roles of 'alice@example.com' [auditor, analyst]|10.1.2.3|console",
		"admin|alice@example.com|admin.identity|User::\"alice@example.com\"|replace direct roles of 'alice@example.com' [analyst]|10.1.2.3|console",
		"admin|alice@example.com|admin.identity|User::\"alice@example.com\"|replace direct roles of 'alice@example.com' []|127.0.0.1|console",
		"admin|bob@example.com|admin.identity|User::\"bob@example.com\"|replace direct roles of 'bob@example.com' []|127.0.0.1|console",
		"auth|bob@example.com|auth.logout|Session::\"" + thirdID + "\"|Web session signed out|127.0.0.1|session",
	}
	if got := auditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	verifyChain(t, e)
}

func TestDebugLoginIsOffWithoutAuthDebug(t *testing.T) {
	st := dbtest.Open(t)
	settings := dbtest.Settings
	settings.AuthDebug = false
	mux := http.NewServeMux()
	Register(mux, st.Pool, api.Gate{Sessions: session.NewResolver(st.Pool, settings), Kotlin: &fakeKotlin{}}, Login{})
	srv := httptest.NewServer(front.Route(mux, http.NotFoundHandler()))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/auth/debug", "application/json", strings.NewReader(`{"principal":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || string(body) != `{"code":"common.not_found","params":{"resource":"endpoint"}}` {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestStorableIP(t *testing.T) {
	for _, bad := range []string{
		"not-an-ip", "999.1.1.1", "100.100.1.10:5432", "100.100.1.0/24",
		"100.100.1.10\x00", "100.100.1.10\x0012", "100.100.1.10​",
		"fe80::1%lo0", "[::1]", "100.100.001.010", "010.1.1.1",
	} {
		if storableIP(strings.TrimSpace(bad)) {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, good := range []string{"100.100.1.10", "  100.100.1.10  ", "::1", "2001:db8::1", "fe80::1"} {
		if !storableIP(strings.TrimSpace(good)) {
			t.Errorf("refused %q", good)
		}
	}
}
