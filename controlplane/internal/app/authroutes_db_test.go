package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/config"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/core"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/instant"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ============================================================================================
// Port of `WebSessionRoutesDbTest.kt` — 598 LOC, 8 cases (04-auth-session-tokens.md §4.7).
//
// ORACLE: the Kotlin test source itself, read this session from the worktree's own tree at
// control-plane/src/test/kotlin/.../WebSessionRoutesDbTest.kt. There is no JVM here, so the frozen
// assertions in that file are the oracle — never a remembered or imagined Kotlin run. Every case
// below cites the Kotlin line range it comes from.
//
// 🔴 WHY THESE CANNOT BE THE CONTAINER-FREE SUITE'S CASES. Everything in authroutes_test.go fakes
// the two session seams, and that is right for the gate/challenge/shape questions it asks. These
// eight ask questions that ONLY a real database can answer, and each one has a mechanism that lives
// in SQL rather than in Go:
//
//   - INV-A1-6's atomicity: roles + mint in ONE transaction, so a rejected role name leaves NEITHER
//     the rewritten assignments NOR a session behind. A fake store cannot fail the way a real
//     ReplaceDirectRolesOn fails.
//   - INV-A4-21's slide throttle: the `last_seen_at < now() - slide` predicate is in TouchWeb's
//     WHERE clause, deliberately not in Go, so only a real UPDATE can be throttled.
//   - INV-A4-22: `absolute_expires_at` is absent from TouchWeb's SET list.
//   - INV-A4-19 / INV-A4-3: displacement and device-bind mismatch END rows and stamp `ended_reason`,
//     which is what the four-value challenge reads back.
//   - INV-A4-16/-27: `now` on /auth/session/status is the DATABASE clock, and the assertion is a
//     window taken from `clock_timestamp()` around the call.
//
// The whole surface is driven through [NewHTTPSurface] — the Go form of `application { module(config,
// core) }` — over a real [core.ControlPlaneCore]. Nothing is stubbed: the mux, the plugin stack, the
// gates, the cookie codec, the session store and the Cedar graph are the ones a booted process gets.
// ============================================================================================

// authServer is one running control plane's HTTP surface plus the handles a case needs.
type authServer struct {
	t       *testing.T
	cfg     config.Config
	core    *core.ControlPlaneCore
	db      *store.Db
	surface *HTTPSurface
	server  *httptest.Server
}

// newAuthServer is `application { module(config, ControlPlaneCore(dataSource)) }` over a FRESH
// migrated database, served on a real socket.
//
// A real socket rather than a bare handler because half of these cases assert on cookie MECHANICS —
// Max-Age, Path, HttpOnly, SameSite, and a jar that carries `pm_session` + `pm_did` across requests
// exactly as a browser does. httptest.ResponseRecorder gives the header but not the jar, and hand
// re-attaching two cookies per request is precisely the place a port stops testing what it thinks.
func newAuthServer(t *testing.T, env map[string]string) *authServer {
	t.Helper()

	if env == nil {
		env = map[string]string{}
	}
	// PM_AUTH_DEBUG defaults to TRUE and V5 permits that only in a non-production-looking context,
	// which is what every one of these cases is (`Config.fromEnv { null }` on the Kotlin side).
	if _, ok := env["PM_DEV"]; !ok {
		env["PM_DEV"] = "true"
	}
	cfg, err := config.FromEnv(config.EnvOf(env))
	if err != nil {
		t.Fatalf("config rejected: %v", err)
	}
	// `.copy(dbUrl = "", dbUser = "", dbPassword = "")` — the store is handed in already open, so the
	// connection fields are not the ones in play.
	cfg.DBURL, cfg.DBUser, cfg.DBPassword = "", "", ""

	db, _ := dbtest.MigratedStore(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New(db, core.Options{Log: log})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	surface := NewHTTPSurface(context.Background(), cfg, c, log)
	server := httptest.NewServer(surface.Router.Handler())
	t.Cleanup(server.Close)

	return &authServer{t: t, cfg: cfg, core: c, db: db, surface: surface, server: server}
}

// client is `createClient { install(HttpCookies) }` — one browser, one cookie jar.
//
// Redirects are NOT followed: `/auth/oidc/login`'s 302 is an assertion target, and a followed
// redirect would dial a real IdP.
func (s *authServer) client() *http.Client {
	s.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		s.t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// bare is a client with NO jar — the `createClient { }` the Kotlin uses to replay a captured cookie
// by hand, so a stale credential is presented without the jar having quietly dropped it.
func (s *authServer) bare() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (s *authServer) do(c *http.Client, method, path, body string, cookies ...*http.Cookie) *http.Response {
	s.t.Helper()
	var r *http.Request
	var err error
	if body == "" {
		r, err = http.NewRequest(method, s.server.URL+path, nil)
	} else {
		r, err = http.NewRequest(method, s.server.URL+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if err != nil {
		s.t.Fatalf("build request: %v", err)
	}
	return s.send(c, r, cookies...)
}

// doEmptyJSON is a POST with a Content-Type and NO body — 🔒 the console's own logout shape, and the
// one the `contentLength() == 0 || ContentType == null` guard exists for.
//
// It cannot go through [authServer.do], which omits the header for an empty body: the two together
// take the SAME branch (no read), so a case that used `do` would silently be asserting the
// no-Content-Type path instead of the console's. The distinction is the whole point of the guard —
// with the header present and the body empty, a handler that read unconditionally would hit EOF and
// answer 500 on every console logout.
func (s *authServer) doEmptyJSON(c *http.Client, method, path string) *http.Response {
	s.t.Helper()
	r, err := http.NewRequest(method, s.server.URL+path, strings.NewReader(""))
	if err != nil {
		s.t.Fatalf("build request: %v", err)
	}
	r.Header.Set("Content-Type", "application/json")
	return s.send(c, r)
}

func (s *authServer) send(c *http.Client, r *http.Request, cookies ...*http.Cookie) *http.Response {
	s.t.Helper()
	for _, ck := range cookies {
		r.AddCookie(ck)
	}
	resp, err := c.Do(r)
	if err != nil {
		s.t.Fatalf("%s %s: %v", r.Method, r.URL.Path, err)
	}
	s.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// debugLogin posts a `DebugLogin` body with a Content-Type, as the Kotlin does at every call site.
func (s *authServer) debugLogin(c *http.Client, principal string, roles ...string) *http.Response {
	s.t.Helper()
	body := map[string]any{"principal": principal}
	if roles != nil {
		body["roles"] = roles
	}
	raw, err := json.Marshal(body)
	if err != nil {
		s.t.Fatalf("marshal DebugLogin: %v", err)
	}
	return s.do(c, http.MethodPost, "/auth/debug", string(raw))
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(raw)
}

func decodeBody(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	raw := readBody(t, resp)
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, raw)
	}
}

// setCookie returns the first Set-Cookie header for name, complete with its attributes — the shape
// `login.headers.getAll(HttpHeaders.SetCookie).first { it.startsWith("$SESSION_COOKIE=") }` returns.
func setCookieHeader(resp *http.Response, name string) (string, bool) {
	for _, h := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(h, name+"=") {
			return h, true
		}
	}
	return "", false
}

// ---- direct SQL, the Kotlin's private helpers ------------------------------------------------

func (s *authServer) webSessionCount(principal string) int {
	s.t.Helper()
	var n int
	err := s.db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM principal_session WHERE principal = $1 AND kind = 'WEB'`, principal).Scan(&n)
	if err != nil {
		s.t.Fatalf("webSessionCount(%s): %v", principal, err)
	}
	return n
}

func (s *authServer) webSessionID(principal string) int64 {
	s.t.Helper()
	var id int64
	err := s.db.Pool.QueryRow(context.Background(),
		`SELECT id FROM principal_session WHERE principal = $1 AND kind = 'WEB' ORDER BY id DESC LIMIT 1`,
		principal).Scan(&id)
	if err != nil {
		s.t.Fatalf("webSessionId(%s): %v", principal, err)
	}
	return id
}

func (s *authServer) sessionDeadline(id int64, column string) time.Time {
	s.t.Helper()
	var ts time.Time
	// The column name is a test-local literal from the two call sites below, never request data.
	err := s.db.Pool.QueryRow(context.Background(),
		`SELECT `+column+` FROM principal_session WHERE id = $1`, id).Scan(&ts)
	if err != nil {
		s.t.Fatalf("%s(%d): %v", column, id, err)
	}
	return ts
}

func (s *authServer) idleExpiresAt(id int64) time.Time {
	return s.sessionDeadline(id, "idle_expires_at")
}

func (s *authServer) absoluteExpiresAt(id int64) time.Time {
	return s.sessionDeadline(id, "absolute_expires_at")
}

// databaseNow is `SELECT clock_timestamp()` — 🔒 INV-A4-16's clock domain. A window built from
// time.Now() would be comparing the test process's clock against the one that stamped the row.
func (s *authServer) databaseNow() time.Time {
	s.t.Helper()
	var ts time.Time
	if err := s.db.Pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&ts); err != nil {
		s.t.Fatalf("clock_timestamp: %v", err)
	}
	return ts
}

// backdateIdle moves the row three minutes into the past so the NEXT heartbeat is outside the
// 120-second slide floor and can therefore extend. Without it the first heartbeat is throttled and
// the case would assert nothing.
func (s *authServer) backdateIdle(id int64) {
	s.t.Helper()
	_, err := s.db.Pool.Exec(context.Background(),
		`UPDATE principal_session
		    SET last_seen_at = now() - interval '3 minutes',
		        idle_expires_at = idle_expires_at - interval '3 minutes'
		  WHERE id = $1`, id)
	if err != nil {
		s.t.Fatalf("backdateIdle(%d): %v", id, err)
	}
}

func (s *authServer) endedReason(id int64) *string {
	s.t.Helper()
	var reason *string
	if err := s.db.Pool.QueryRow(context.Background(),
		`SELECT ended_reason FROM principal_session WHERE id = $1`, id).Scan(&reason); err != nil {
		s.t.Fatalf("endedReason(%d): %v", id, err)
	}
	return reason
}

func (s *authServer) directRoles(principal string) []string {
	s.t.Helper()
	roles, err := s.core.RoleResolver.DirectRoles(context.Background(), principal)
	if err != nil {
		s.t.Fatalf("DirectRoles(%s): %v", principal, err)
	}
	return roles
}

// assertReason is the Kotlin's `assertReason(response, reason)` (WebSessionRoutesDbTest.kt:43-47):
// 401, `Cache-Control: no-store`, and the SessionStatusError body — all three, every time.
//
// The header is part of it because a cached 401 keeps a re-authenticated tab looking signed out, and
// a status-only assertion would not notice it going missing.
func assertReason(t *testing.T, resp *http.Response, reason string) {
	t.Helper()
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var got struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("challenge body is not JSON (%v): %s", err, body)
	}
	if got.Reason != reason {
		t.Errorf("reason = %q, want %q (body %s)", got.Reason, reason, body)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------------------------
// Case 1 + 2 — `auth config exposes default session UX timings` (WebSessionRoutesDbTest.kt:97-121)
// and `auth config normalizes a mixed-unit absolute cap to minutes` (:123-136)
// ---------------------------------------------------------------------------------------------

// TestAuthConfigThroughTheRealModule is those two cases AT THE COMPOSITION ROOT.
//
// The values themselves are already pinned container-free (TestAuthConfigExposesDefaultSessionUxTimings,
// TestAuthConfigNormalizesAMixedUnitAbsoluteCapToMinutes). What only the real module can answer is
// that the route is MOUNTED — that `NewHTTPSurface` actually registers `GET /auth/config` and that a
// login shell reaching a booted process gets 200 rather than 404. A container-free suite mounts the
// group itself and so can never notice its absence from the composition root.
func TestAuthConfigThroughTheRealModule(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		s := newAuthServer(t, nil)
		resp := s.do(s.client(), http.MethodGet, "/auth/config", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var got AuthConfigResponse
		decodeBody(t, resp, &got)
		want := AuthConfigResponse{
			OidcEnabled: false,
			AuthDebug:   true,
			Session: SessionUxConfig{
				HeartbeatMs:        90_000,
				IdleWarnLeadMs:     60_000,
				AbsoluteWarnLeadMs: 300_000,
				AbsoluteCapAmount:  2,
				AbsoluteCapUnit:    "hours",
			},
		}
		if got != want {
			t.Errorf("AuthConfigResponse = %+v, want %+v", got, want)
		}
	})

	t.Run("a mixed-unit absolute cap renders as minutes", func(t *testing.T) {
		s := newAuthServer(t, map[string]string{"PM_WEB_SESSION_ABSOLUTE": "1h30m"})
		var got AuthConfigResponse
		decodeBody(t, s.do(s.client(), http.MethodGet, "/auth/config", ""), &got)
		if got.Session.AbsoluteCapAmount != 90 || got.Session.AbsoluteCapUnit != "minutes" {
			t.Errorf("absoluteCap = %d %s, want 90 minutes",
				got.Session.AbsoluteCapAmount, got.Session.AbsoluteCapUnit)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// Case 3 — `debug login resolves through the database and logout ends the row` (:138-251)
// ---------------------------------------------------------------------------------------------

// TestDebugLoginResolvesThroughTheDatabaseAndLogoutEndsTheRow is the case that pins 🔒 INV-A1-6 —
// roles and the session mint in ONE transaction — from four directions, and then INV-A4-7's logout.
//
// It is deliberately ONE long case rather than six short ones, exactly as the Kotlin is: the
// replace-not-add assertions only mean anything against the state the previous login left, and
// splitting them would let each half pass against a fresh database.
//
// `PM_WEB_SESSION_ABSOLUTE=90s` is the Kotlin's, and it is load-bearing twice: it makes the
// `pm_session` Max-Age observable as a distinct number, and it is the config value the cookie's
// lifetime must come from rather than a constant.
func TestDebugLoginResolvesThroughTheDatabaseAndLogoutEndsTheRow(t *testing.T) {
	s := newAuthServer(t, map[string]string{"PM_WEB_SESSION_ABSOLUTE": "90s"})
	c := s.client()
	const principal = "web@example.com"

	// A claimed role must EXIST: the claim becomes real `principal_role` rows, so a name with no
	// `app_role` behind it is rejected rather than accepted and quietly ignored. `system:auditor` is
	// seeded by V8__seed.sql, so it resolves in this freshly-migrated database.
	login := s.debugLogin(c, principal, "system:auditor")
	loginBody := readBody(t, login)
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (body %s)", login.StatusCode, loginBody)
	}

	sessionCookie, ok := setCookieHeader(login, session.SessionCookie)
	if !ok {
		t.Fatalf("no %s Set-Cookie on the login response: %v", session.SessionCookie, login.Header.Values("Set-Cookie"))
	}
	deviceCookie, ok := setCookieHeader(login, session.DeviceCookie)
	if !ok {
		t.Fatalf("no %s Set-Cookie on the login response: %v", session.DeviceCookie, login.Header.Values("Set-Cookie"))
	}
	// 🔒 The session cookie's lifetime is `config.webSessionAbsoluteSeconds`, the ONE cookie whose
	// maxAge comes from config. A constant here would silently outlive or undercut the row.
	if !strings.Contains(sessionCookie, "Max-Age=90") {
		t.Errorf("%s = %q, want Max-Age=90 (PM_WEB_SESSION_ABSOLUTE)", session.SessionCookie, sessionCookie)
	}
	// `pm_did` is the SIXTH cookie, set by hand outside the signed block — 90 days, Path=/, HttpOnly,
	// SameSite=Lax. All four are asserted because the device correlator is what INV-A4-19's binding
	// is checked against, and a cookie that expires with the session would make every re-login look
	// like a new device.
	for _, want := range []string{"Max-Age=7776000", "Path=/", "HttpOnly", "SameSite=Lax"} {
		if !strings.Contains(deviceCookie, want) {
			t.Errorf("%s = %q, want it to contain %q", session.DeviceCookie, deviceCookie, want)
		}
	}

	var got session.UserSession
	if err := json.Unmarshal([]byte(loginBody), &got); err != nil {
		t.Fatalf("login body is not JSON (%v): %s", err, loginBody)
	}
	if got.Principal != principal || !equalStrings(got.Roles, []string{"system:auditor"}) || got.RequesterIP != nil {
		t.Errorf("login body = %+v, want {%s [system:auditor] <nil>}", got, principal)
	}

	// /auth/me RE-RESOLVES rather than echoing the session: the console reads this to show who it
	// thinks you are, so reporting an empty set for a principal that holds roles misdescribes every
	// later denial. 🔒 INV-A1-8.
	var me session.UserSession
	decodeBody(t, s.do(c, http.MethodGet, "/auth/me", ""), &me)
	if me.Principal != principal || !equalStrings(me.Roles, []string{"system:auditor"}) {
		t.Errorf("/auth/me = %+v, want {%s [system:auditor]}", me, principal)
	}

	// The claim is not cosmetic: it became a DIRECT ASSIGNMENT, so authorization — which reads the
	// database, never the session — actually sees it. Without this the route could echo any role back
	// and still resolve to none, which is the bug this behaviour replaced.
	if roles := s.directRoles(principal); !equalStrings(roles, []string{"system:auditor"}) {
		t.Errorf("directRoles = %v, want [system:auditor]", roles)
	}

	// 🔒 INV-A1-6, THE ATOMICITY HALF. An unknown name fails the WHOLE login rather than being
	// dropped, and it names which role was rejected. Then: the pre-existing assignment survives, and
	// so does the session table — one transaction, so a login that fails on any part leaves NEITHER
	// behind. No session authorized by roles that were never committed, and no role rewrite standing
	// under a login that did not succeed.
	sessionsBefore := s.webSessionCount(principal)
	bogus := s.debugLogin(c, principal, "system:auditor", "no-such-role")
	bogusBody := readBody(t, bogus)
	if bogus.StatusCode != http.StatusNotFound {
		t.Fatalf("bogus-role login status = %d, want 404 (body %s)", bogus.StatusCode, bogusBody)
	}
	if !strings.Contains(bogusBody, "no-such-role") {
		t.Errorf("404 body = %s, want it to NAME the offending role", bogusBody)
	}
	if roles := s.directRoles(principal); !equalStrings(roles, []string{"system:auditor"}) {
		t.Errorf("directRoles after a rejected claim = %v, want the pre-existing [system:auditor]", roles)
	}
	if after := s.webSessionCount(principal); after != sessionsBefore {
		t.Errorf("web session count %d → %d across a REJECTED login; roles and mint share one "+
			"transaction, so a failed claim must mint nothing", sessionsBefore, after)
	}

	// REPLACE, not add. Every assertion above would also pass an implementation that only ever
	// inserts, so claim a DIFFERENT single role and require the first to be GONE.
	s.debugLogin(c, principal, "system:development-viewer")
	if roles := s.directRoles(principal); !equalStrings(roles, []string{"system:development-viewer"}) {
		t.Errorf("directRoles = %v, want [system:development-viewer] — the claim REPLACES, it does not accumulate", roles)
	}

	// An EMPTY claim is a deliberate WIPE of the direct set, not a no-op: it is how you drop back to
	// whatever groups and JIT grants alone confer.
	s.debugLogin(c, principal)
	if roles := s.directRoles(principal); len(roles) != 0 {
		t.Errorf("directRoles after an empty claim = %v, want [] — an empty claim is a wipe", roles)
	}

	// Restore the role the rest of this case's session assertions run under.
	s.debugLogin(c, principal, "system:auditor")
	id := s.webSessionID(principal)
	signedCookie := strings.SplitN(sessionCookie, ";", 2)[0]

	// 🔒 INV-A4-7 — logout is BOTH halves. `sessions.clear` looks like it only drops a cookie; the
	// end-write happens inside the storage `invalidate` Ktor calls for it.
	logout := s.do(c, http.MethodPost, "/auth/logout", "")
	logoutBody := readBody(t, logout)
	if logout.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d, want 200 (body %s)", logout.StatusCode, logoutBody)
	}
	if logoutBody != `{"ended":true}` {
		t.Errorf("logout body = %s, want {\"ended\":true}", logoutBody)
	}
	if cleared, ok := setCookieHeader(logout, session.SessionCookie); !ok || !strings.Contains(cleared, "Max-Age=0") {
		t.Errorf("logout Set-Cookie = %q (present=%v), want a Max-Age=0 deletion", cleared, ok)
	}

	var endedAt *time.Time
	var reason *string
	if err := s.db.Pool.QueryRow(context.Background(),
		`SELECT ended_at, ended_reason FROM principal_session WHERE id = $1`, id).Scan(&endedAt, &reason); err != nil {
		t.Fatalf("read ended row: %v", err)
	}
	if endedAt == nil {
		t.Error("ended_at is NULL after logout — the cookie was cleared but the row was left resolvable")
	}
	if reason == nil || *reason != session.EndedSignedOut {
		t.Errorf("ended_reason = %v, want %q", reason, session.EndedSignedOut)
	}

	if resp := s.do(c, http.MethodGet, "/auth/me", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/auth/me after logout = %d, want 401", resp.StatusCode)
	}
	// 🔒 THE REPLAY. The jar dropped the cookie, so this presents the captured one by hand — the
	// thing an attacker who copied it before logout would send. It must not resolve.
	replay := s.do(s.bare(), http.MethodGet, "/auth/me", "",
		&http.Cookie{Name: session.SessionCookie, Value: strings.SplitN(signedCookie, "=", 2)[1]})
	if replay.StatusCode != http.StatusUnauthorized {
		t.Errorf("replayed post-logout cookie = %d, want 401 — the row must be ended, not merely un-cookied",
			replay.StatusCode)
	}
}

// 🔴 TestAFailedMintRollsBackTheRoleRewrite is 🔒 INV-A1-6's OTHER HALF, and it is a case the Kotlin
// suite does not have.
//
// WebSessionRoutesDbTest covers the direction where the FIRST step fails: a bogus role name, so
// `replaceDirectRoles` throws and nothing downstream runs. That direction passes just as happily
// against two SEPARATE transactions, because there is nothing committed yet to roll back — which
// means the Kotlin suite does not actually pin the atomicity it documents. The invariant's own words
// are about the other direction: "Committing separately would let a failed mint leave the roles
// rewritten under a login that never succeeded."
//
// So the mint is made to fail, with a BEFORE INSERT trigger scoped to one principal, and the
// assertion is that the ROLE REWRITE went with it. Two independent commits would leave the principal
// holding `system:development-viewer` — a role set no successful login ever established, on an
// account whose caller was told the login failed.
//
// The trigger is the only honest way to stage this: every other failure mode inside MintWeb is
// either unreachable (the validator rejects a bad requesterIp first) or would abort the role write
// too. It lives in the test's own fresh database and is scoped by principal, so nothing else in the
// suite can see it.
func TestAFailedMintRollsBackTheRoleRewrite(t *testing.T) {
	s := newAuthServer(t, nil)
	c := s.client()
	const principal = "atomic@example.com"

	if resp := s.debugLogin(c, principal, "system:auditor"); resp.StatusCode != http.StatusOK {
		t.Fatalf("seed login = %d", resp.StatusCode)
	}
	liveBefore := s.webSessionID(principal)
	sessionsBefore := s.webSessionCount(principal)

	ctx := context.Background()
	if _, err := s.db.Pool.Exec(ctx, `
		CREATE FUNCTION pm_test_block_mint() RETURNS trigger AS $$
		BEGIN
			IF NEW.principal = 'atomic@example.com' THEN
				RAISE EXCEPTION 'pm_test: mint blocked';
			END IF;
			RETURN NEW;
		END $$ LANGUAGE plpgsql;
		CREATE TRIGGER pm_test_block_mint BEFORE INSERT ON principal_session
			FOR EACH ROW EXECUTE FUNCTION pm_test_block_mint();`); err != nil {
		t.Fatalf("install mint-blocking trigger: %v", err)
	}

	resp := s.debugLogin(c, principal, "system:development-viewer")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — a mint failure is not a ManagementException, so it "+
			"propagates to StatusPages (body %s)", resp.StatusCode, body)
	}
	if body != `{"code":"common.fallback","params":{}}` {
		t.Errorf("body = %s, want the StatusPages fallback", body)
	}

	// 🔒 THE ASSERTION. The claim in the failed request was `system:development-viewer`; the
	// principal must still hold only what the last SUCCESSFUL login established.
	if roles := s.directRoles(principal); !equalStrings(roles, []string{"system:auditor"}) {
		t.Errorf("directRoles = %v, want [system:auditor] — the role rewrite committed under a login "+
			"that never succeeded, so replaceDirectRoles and mintWeb are NOT sharing one transaction", roles)
	}
	// MintWeb's newest-wins displacement is an UPDATE that runs before its INSERT, so it must have
	// rolled back too: the session the user is actually holding is still live and still un-displaced.
	if r := s.endedReason(liveBefore); r != nil {
		t.Errorf("the previously live session was ended %q by a login that failed; the displacement "+
			"UPDATE is inside the same transaction and must roll back with it", *r)
	}
	if after := s.webSessionCount(principal); after != sessionsBefore {
		t.Errorf("web session count %d → %d across a failed mint", sessionsBefore, after)
	}
}

// ---------------------------------------------------------------------------------------------
// Case 4 — `conditional logout ends only the session id observed by the client` (:253-303)
// ---------------------------------------------------------------------------------------------

// TestConditionalLogoutEndsOnlyTheSessionIDObservedByTheClient is 🔒 INV-A1-9 against real rows.
//
// The container-free suite already pins the CONDITION (stale id ⇒ ended:false, matching id ⇒
// ended:true). What needs a database is the consequence: after a stale conditional logout the
// CURRENT session must still be usable — `/auth/session/status` still 200s and still names the
// current row. That is the failure this invariant exists to prevent: an automatic logout for a
// session the user already replaced signing them out of the tab they are actually using.
func TestConditionalLogoutEndsOnlyTheSessionIDObservedByTheClient(t *testing.T) {
	s := newAuthServer(t, nil)
	c := s.client()

	// ⚠️ A Content-Type with an EMPTY body is the console's own shape and must not be a decode
	// failure; it is an UNCONDITIONAL logout. Sent over a REAL socket here, so the Content-Length: 0
	// the transport writes is the one the server's guard reads.
	s.debugLogin(c, "empty-body@example.com")
	emptyBody := s.doEmptyJSON(c, http.MethodPost, "/auth/logout")
	if got := readBody(t, emptyBody); emptyBody.StatusCode != http.StatusOK || got != `{"ended":true}` {
		t.Errorf("empty-body logout = %d %s, want 200 {\"ended\":true}", emptyBody.StatusCode, got)
	}

	const principal = "conditional@example.com"
	s.debugLogin(c, principal)
	staleID := s.webSessionID(principal)
	s.debugLogin(c, principal)
	currentID := s.webSessionID(principal)
	if currentID == staleID {
		t.Fatalf("the second login reused session id %d; newest-wins must mint a new row", currentID)
	}

	staleLogout := s.do(c, http.MethodPost, "/auth/logout", `{"sessionId":`+itoa64(staleID)+`}`)
	if got := readBody(t, staleLogout); staleLogout.StatusCode != http.StatusOK || got != `{"ended":false}` {
		t.Errorf("stale conditional logout = %d %s, want 200 {\"ended\":false}", staleLogout.StatusCode, got)
	}
	// 🔒 And it must not clear the cookie either — WebSessionRoutesDbTest.kt:294. A response that
	// answered ended:false but still dropped the cookie would sign the user out anyway.
	if h, ok := setCookieHeader(staleLogout, session.SessionCookie); ok {
		t.Errorf("a stale conditional logout wrote %q; it must not touch the cookie", h)
	}

	stillCurrent := s.do(c, http.MethodGet, "/auth/session/status", "")
	if stillCurrent.StatusCode != http.StatusOK {
		t.Fatalf("session status after a stale conditional logout = %d, want 200", stillCurrent.StatusCode)
	}
	var status SessionStatus
	decodeBody(t, stillCurrent, &status)
	if status.SessionID != currentID {
		t.Errorf("sessionId = %d, want the still-live %d", status.SessionID, currentID)
	}

	matching := s.do(c, http.MethodPost, "/auth/logout", `{"sessionId":`+itoa64(currentID)+`}`)
	if got := readBody(t, matching); matching.StatusCode != http.StatusOK || got != `{"ended":true}` {
		t.Errorf("matching conditional logout = %d %s, want 200 {\"ended\":true}", matching.StatusCode, got)
	}
	if h, ok := setCookieHeader(matching, session.SessionCookie); !ok || !strings.Contains(h, "Max-Age=0") {
		t.Errorf("matching conditional logout Set-Cookie = %q (present=%v), want a deletion", h, ok)
	}
	// The jar has dropped the cookie, so the next status names no session at all.
	assertReason(t, s.do(c, http.MethodGet, "/auth/session/status", ""), session.WireReasonNone)
}

// ---------------------------------------------------------------------------------------------
// Case 5 — `expired and ended web rows fail closed` (:305-350)
// ---------------------------------------------------------------------------------------------

// TestExpiredAndEndedWebRowsFailClosed drives the two ways a cookie outlives its row: the row is
// GONE, and the row is past its ABSOLUTE deadline.
//
// The `/test/protected` route the Kotlin adds is reproduced with the same trick it uses — a
// requireApi gate built from `config.copy(authDebug = false)` — so an ordinary API route is proved
// to fail closed even on a deployment whose own bypass is on. Without that copy the gate would
// short-circuit and the case would assert nothing.
func TestExpiredAndEndedWebRowsFailClosed(t *testing.T) {
	s := newAuthServer(t, nil)
	s.mountProtected(t)
	c := s.client()

	s.debugLogin(c, "missing@example.com")
	if _, err := s.db.Pool.Exec(context.Background(),
		`DELETE FROM principal_session WHERE principal = $1`, "missing@example.com"); err != nil {
		t.Fatalf("delete row: %v", err)
	}
	if resp := s.do(c, http.MethodGet, "/auth/me", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/auth/me with a DELETED row = %d, want 401", resp.StatusCode)
	}

	s.debugLogin(c, "expired@example.com")
	if _, err := s.db.Pool.Exec(context.Background(),
		`UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE principal = $1`,
		"expired@example.com"); err != nil {
		t.Fatalf("expire row: %v", err)
	}
	if resp := s.do(c, http.MethodGet, "/auth/me", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/auth/me past the ABSOLUTE deadline = %d, want 401", resp.StatusCode)
	}
	if resp := s.do(c, http.MethodGet, "/test/protected", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an ordinary requireApi route past the absolute deadline = %d, want 401", resp.StatusCode)
	}

	// `assertNull(PrincipalSessionStore(dataSource, null).resolveWeb(-1, null))` — a nonexistent id
	// resolves to nothing rather than erroring, which is what makes the 401 above a resolution
	// failure and not an exception that StatusPages turned into a 500.
	row, err := s.surface.SessionStore.ResolveWeb(context.Background(), -1, nil)
	if err != nil {
		t.Errorf("ResolveWeb(-1) errored (%v); it must simply resolve to nothing", err)
	}
	if row != nil {
		t.Errorf("ResolveWeb(-1) = %+v, want nil", row)
	}
}

// mountProtected adds the Kotlin's `/test/protected` — `requireApi(config.copy(authDebug = false))`.
//
// It is mounted on the SAME mux the surface built, through [httpapi.Router.Mux], which is the seam
// the Kotlin's extra `routing { }` block is. The gate is a real [httpapi.Gates] over a config whose
// bypass is off, so the route asks the real question even while the application's own bypass is on.
func (s *authServer) mountProtected(t *testing.T) {
	t.Helper()
	offCfg := s.cfg
	offCfg.AuthDebug = false
	gates := *s.surface.Gates
	gates.Config = offCfg
	s.surface.Router.Mux().HandleFunc("GET /test/protected", func(w http.ResponseWriter, r *http.Request) {
		if !gates.RequireAPI(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// ---------------------------------------------------------------------------------------------
// Case 6 — `session observation and ordinary authenticated routes never slide idle while heartbeat
// does` (:352-436)
// ---------------------------------------------------------------------------------------------

// TestObservationNeverSlidesIdleWhileHeartbeatDoes is 🔒 INV-A4-20 and 🔒 INV-A4-21 together, and it
// is the single most important case in the file: it is the only thing standing between "the idle
// window is a security control" and "the idle window is unreachable because looking at the session
// resets it".
//
// Five requests are made against a backdated row and the idle deadline is read from the DATABASE
// after each: status, /auth/me and an ordinary /api route must leave it EXACTLY where it was; only
// the heartbeat may move it; and a second heartbeat inside the slide floor must be throttled by
// TouchWeb's WHERE clause rather than by anything in Go.
func TestObservationNeverSlidesIdleWhileHeartbeatDoes(t *testing.T) {
	s := newAuthServer(t, nil)
	s.mountApiProtected(t)
	c := s.client()
	fresh := s.bare()

	// A client with no cookie at all: all three session routes challenge with `none`.
	assertReason(t, s.do(fresh, http.MethodGet, "/auth/session/status", ""), session.WireReasonNone)
	assertReason(t, s.do(fresh, http.MethodGet, "/auth/me", ""), session.WireReasonNone)
	assertReason(t, s.do(fresh, http.MethodPost, "/auth/session/heartbeat", ""), session.WireReasonNone)

	const principal = "status@example.com"
	s.debugLogin(c, principal)
	id := s.webSessionID(principal)
	s.backdateIdle(id)
	beforeObserve := s.idleExpiresAt(id)
	dbBefore := s.databaseNow()

	statusResp := s.do(c, http.MethodGet, "/auth/session/status", "")
	dbAfter := s.databaseNow()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", statusResp.StatusCode)
	}
	if got := statusResp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var status SessionStatus
	decodeBody(t, statusResp, &status)
	if status.Principal != principal || status.SessionID != id {
		t.Errorf("status identity = %q/%d, want %q/%d", status.Principal, status.SessionID, principal, id)
	}
	if status.IdleExpiresAt != instant.Format(beforeObserve) {
		t.Errorf("idleExpiresAt = %q, want the row's %q", status.IdleExpiresAt, instant.Format(beforeObserve))
	}
	if now := s.idleExpiresAt(id); !now.Equal(beforeObserve) {
		t.Errorf("status observation EXTENDED idle (%s → %s)", instant.Format(beforeObserve), instant.Format(now))
	}
	if status.AbsoluteExpiresAt != instant.Format(s.absoluteExpiresAt(id)) {
		t.Errorf("absoluteExpiresAt = %q, want the row's %q",
			status.AbsoluteExpiresAt, instant.Format(s.absoluteExpiresAt(id)))
	}
	// 🔒 INV-A4-16 — `now` is the DATABASE clock. The console computes its countdown as
	// `idleExpiresAt - now`, and the deadline it counts down to was stamped by the database, so a
	// process clock skewed from it would make the warning fire early or never.
	if status.Now < instant.Format(dbBefore.Add(-2*time.Second)) || status.Now > instant.Format(dbAfter.Add(2*time.Second)) {
		t.Errorf("now = %q, outside the database-clock window [%s, %s]",
			status.Now, instant.Format(dbBefore.Add(-2*time.Second)), instant.Format(dbAfter.Add(2*time.Second)))
	}

	okMe := s.do(c, http.MethodGet, "/auth/me", "")
	if okMe.StatusCode != http.StatusOK {
		t.Fatalf("/auth/me = %d, want 200", okMe.StatusCode)
	}
	if got := okMe.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("/auth/me Cache-Control = %q, want no-store", got)
	}
	if now := s.idleExpiresAt(id); !now.Equal(beforeObserve) {
		t.Error("/auth/me EXTENDED idle")
	}

	okAPI := s.do(c, http.MethodGet, "/api/test/protected", "")
	if okAPI.StatusCode != http.StatusOK {
		t.Fatalf("/api/test/protected = %d, want 200", okAPI.StatusCode)
	}
	if now := s.idleExpiresAt(id); !now.Equal(beforeObserve) {
		t.Error("ordinary /api traffic EXTENDED idle")
	}

	heartbeat := s.do(c, http.MethodPost, "/auth/session/heartbeat", "")
	if heartbeat.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat = %d, want 200", heartbeat.StatusCode)
	}
	if got := heartbeat.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("heartbeat Cache-Control = %q, want no-store", got)
	}
	var beat SessionStatus
	decodeBody(t, heartbeat, &beat)
	afterHeartbeat := s.idleExpiresAt(id)
	if !afterHeartbeat.After(beforeObserve) {
		t.Fatalf("heartbeat did NOT extend an eligible idle deadline (%s → %s)",
			instant.Format(beforeObserve), instant.Format(afterHeartbeat))
	}
	if beat.IdleExpiresAt != instant.Format(afterHeartbeat) {
		t.Errorf("heartbeat body idleExpiresAt = %q, want the written %q", beat.IdleExpiresAt, instant.Format(afterHeartbeat))
	}
	if beat.SessionID != id {
		t.Errorf("heartbeat sessionId = %d, want %d", beat.SessionID, id)
	}
	// 🔒 INV-A4-22 — the ABSOLUTE deadline is not in TouchWeb's SET list and nothing may put it
	// there. A heartbeat that moved it would make the security bound slide with the convenience one,
	// i.e. an indefinitely renewable session.
	if beat.AbsoluteExpiresAt != status.AbsoluteExpiresAt {
		t.Errorf("heartbeat MOVED absoluteExpiresAt (%q → %q); it is the security bound and TouchWeb "+
			"must never touch it", status.AbsoluteExpiresAt, beat.AbsoluteExpiresAt)
	}

	// 🔒 INV-A4-21 — the slide floor. A second heartbeat immediately after the first matches ZERO
	// rows in the UPDATE, and the resolve that follows still answers 200 with the UNMOVED deadline.
	throttled := s.do(c, http.MethodPost, "/auth/session/heartbeat", "")
	if throttled.StatusCode != http.StatusOK {
		t.Fatalf("throttled heartbeat = %d, want 200 — a throttled slide is still a success", throttled.StatusCode)
	}
	var throttledStatus SessionStatus
	decodeBody(t, throttled, &throttledStatus)
	if throttledStatus.IdleExpiresAt != instant.Format(afterHeartbeat) {
		t.Errorf("throttled heartbeat reported %q, want the unmoved %q",
			throttledStatus.IdleExpiresAt, instant.Format(afterHeartbeat))
	}
	if now := s.idleExpiresAt(id); !now.Equal(afterHeartbeat) {
		t.Error("a heartbeat inside the slide interval WROTE the row; the throttle is in TouchWeb's WHERE clause")
	}

	// Past the IDLE deadline all three challenge with `expired` — the `else` arm of the four-value
	// mapping, reached with a NULL ended_reason and a non-null session id.
	if _, err := s.db.Pool.Exec(context.Background(),
		`UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatalf("expire idle: %v", err)
	}
	assertReason(t, s.do(c, http.MethodGet, "/auth/session/status", ""), session.WireReasonExpired)
	assertReason(t, s.do(c, http.MethodGet, "/auth/me", ""), session.WireReasonExpired)
	assertReason(t, s.do(c, http.MethodPost, "/auth/session/heartbeat", ""), session.WireReasonExpired)
}

// 🔴 TestAHeartbeatThatLosesTheRaceStillReportsWhyIsTheONLYtestOfTheByHandFailedSessionMarker.
//
// FOUND BY MUTATION, and it is the one survivor of an eighteen-mutation sweep: deleting
// `httpapi.SetFailedWebSession(r, row.ID)` from [authRoutes.heartbeat]'s nil arm broke NOTHING.
//
// The reason is a coverage blind spot that reads as covered. Every other "heartbeat reports
// displaced/expired" assertion in this file — case 6's `expired`, case 7's `displaced` — is answered
// by the WEB_SESSION_AUTH GATE, not by the handler: the row is already dead when the gate resolves
// it, so [httpapi.Sessions.WebSession] sets the marker itself and the handler never runs. The
// handler's nil arm is reachable ONLY in the narrow window the marker exists for, which
// httpapi.SetFailedWebSession's own doc states: "the per-request resolution SUCCEEDED, so
// Sessions.WebSession set nothing, and then touchWeb returned null because the row was ended or the
// device binding failed BETWEEN the two."
//
// So the window is staged deterministically. A BEFORE UPDATE trigger, scoped to one principal, ends
// the row AS THE TOUCH WRITES IT: TouchWeb's UPDATE matches (the row is live and outside the slide
// floor), the trigger stamps `ended_at`/`ended_reason`, and the resolve TouchWeb runs immediately
// afterwards on the same connection therefore returns nil. That is exactly the real race — a
// displacement landing between two statements — with the timing made repeatable.
//
// Without the by-hand marker the user is told `"none"` — "you were never signed in" — on the one
// route most likely to observe a displacement first, and the console sends them to a login page
// instead of saying someone signed in elsewhere.
func TestAHeartbeatThatLosesTheRaceStillReportsWhy(t *testing.T) {
	s := newAuthServer(t, nil)
	c := s.client()
	const principal = "racy@example.com"

	if resp := s.debugLogin(c, principal); resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d", resp.StatusCode)
	}
	id := s.webSessionID(principal)
	// Outside the 120s slide floor, so TouchWeb's UPDATE actually matches a row — a throttled touch
	// writes nothing, the trigger never fires, and the case would silently assert the gate again.
	s.backdateIdle(id)

	if _, err := s.db.Pool.Exec(context.Background(), `
		CREATE FUNCTION pm_test_end_on_touch() RETURNS trigger AS $$
		BEGIN
			NEW.ended_at := now();
			NEW.ended_reason := 'DISPLACED';
			RETURN NEW;
		END $$ LANGUAGE plpgsql;
		CREATE TRIGGER pm_test_end_on_touch BEFORE UPDATE ON principal_session
			FOR EACH ROW WHEN (NEW.principal = 'racy@example.com' AND NEW.ended_at IS NULL)
			EXECUTE FUNCTION pm_test_end_on_touch();`); err != nil {
		t.Fatalf("install touch-racing trigger: %v", err)
	}

	// ⚠️ WHY `displaced` PROVES THE HANDLER RAN, rather than the gate having answered instead:
	// `DISPLACED` is written by NOTHING here except the trigger, the trigger fires only on an UPDATE
	// of this row, and the only UPDATE in this request is TouchWeb's — which the handler issues AFTER
	// the gate admitted. A gate that had refused would answer `none` (no marker) or `bind_mismatch`
	// (the binding branch), never `displaced`.
	assertReason(t, s.do(c, http.MethodPost, "/auth/session/heartbeat", ""), session.WireReasonDisplaced)

	// And the row really did end during the touch, so the reason came from a real transition rather
	// than from something the fixture wrote before the request.
	if r := s.endedReason(id); r == nil || *r != session.EndedDisplaced {
		t.Errorf("ended_reason = %v, want %q — the trigger must have fired inside TouchWeb's UPDATE",
			r, session.EndedDisplaced)
	}
}

// mountApiProtected is case 6's `/api/test/protected`, the "ordinary authenticated route" whose
// whole job is to prove that ordinary traffic does not slide idle.
func (s *authServer) mountApiProtected(t *testing.T) {
	t.Helper()
	offCfg := s.cfg
	offCfg.AuthDebug = false
	gates := *s.surface.Gates
	gates.Config = offCfg
	s.surface.Router.Mux().HandleFunc("GET /api/test/protected", func(w http.ResponseWriter, r *http.Request) {
		if !gates.RequireAPI(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// ---------------------------------------------------------------------------------------------
// Case 7 — `session status and me surface displacement and bind mismatch reasons` (:438-556)
// ---------------------------------------------------------------------------------------------

// TestSessionStatusAndMeSurfaceDisplacementAndBindMismatch is 🔒 INV-A4-3 + 🔒 INV-A4-19 end to end:
// the four-value challenge vocabulary carrying the two reasons the console must explain differently.
//
// Three device-binding shapes are driven, and the third is the one a port gets wrong:
//
//	wrong pm_did on a session already ended by a prior request  → bind_mismatch
//	wrong pm_did with /auth/me as the FIRST mismatching request → bind_mismatch (resolve-then-map)
//	NO pm_did at all                                            → bind_mismatch, NOT a wildcard match
//
// The middle one guards against reading the ended reason BEFORE resolving a still-active mismatch:
// on a fresh session nothing has ended the row yet, so /auth/me's own resolve has to end it
// DEVICE_BIND_MISMATCH and only then can the challenge map it.
func TestSessionStatusAndMeSurfaceDisplacementAndBindMismatch(t *testing.T) {
	s := newAuthServer(t, nil)
	first := s.client()
	second := s.client()

	const displaced = "reason-status@example.com"
	firstLogin := s.debugLogin(first, displaced)
	if firstLogin.StatusCode != http.StatusOK {
		t.Fatalf("first login = %d", firstLogin.StatusCode)
	}
	capturedSession := cookieValueFrom(t, firstLogin, session.SessionCookie)

	if secondLogin := s.debugLogin(second, displaced); secondLogin.StatusCode != http.StatusOK {
		t.Fatalf("second login = %d", secondLogin.StatusCode)
	}

	// Newest-wins: the second login DISPLACED the first, and all three session routes say so.
	assertReason(t, s.do(first, http.MethodGet, "/auth/session/status", ""), session.WireReasonDisplaced)
	assertReason(t, s.do(first, http.MethodGet, "/auth/me", ""), session.WireReasonDisplaced)
	assertReason(t, s.do(first, http.MethodPost, "/auth/session/heartbeat", ""), session.WireReasonDisplaced)

	// The same, replayed by hand from a jar-less client — a copied cookie learns the same reason.
	assertReason(t, s.do(s.bare(), http.MethodGet, "/auth/session/status", "",
		&http.Cookie{Name: session.SessionCookie, Value: capturedSession}), session.WireReasonDisplaced)

	// ---- a WRONG pm_did ----
	const bound = "bind-status@example.com"
	boundLogin := s.debugLogin(second, bound)
	boundSession := cookieValueFrom(t, boundLogin, session.SessionCookie)
	boundID := s.webSessionID(bound)
	wrongDevice := &http.Cookie{Name: session.DeviceCookie, Value: "00000000-0000-0000-0000-000000000000"}
	replay := s.bare()

	assertReason(t, s.do(replay, http.MethodGet, "/auth/session/status", "",
		&http.Cookie{Name: session.SessionCookie, Value: boundSession}, wrongDevice),
		session.WireReasonBindMismatch)
	if r := s.endedReason(boundID); r == nil || *r != session.EndedDeviceBindMismatch {
		t.Errorf("ended_reason = %v, want %q — the mismatch must END the row, not merely refuse it",
			r, session.EndedDeviceBindMismatch)
	}
	assertReason(t, s.do(replay, http.MethodGet, "/auth/me", "",
		&http.Cookie{Name: session.SessionCookie, Value: boundSession}, wrongDevice),
		session.WireReasonBindMismatch)

	// ---- /auth/me as the FIRST mismatching request on a fresh session ----
	const meFirst = "bind-me-first@example.com"
	meFirstLogin := s.debugLogin(second, meFirst)
	meFirstSession := cookieValueFrom(t, meFirstLogin, session.SessionCookie)
	meFirstID := s.webSessionID(meFirst)

	assertReason(t, s.do(replay, http.MethodGet, "/auth/me", "",
		&http.Cookie{Name: session.SessionCookie, Value: meFirstSession}, wrongDevice),
		session.WireReasonBindMismatch)
	if r := s.endedReason(meFirstID); r == nil || *r != session.EndedDeviceBindMismatch {
		t.Errorf("ended_reason after a first-request mismatch = %v, want %q — /auth/me must "+
			"resolve-then-map, not read the reason before resolving", r, session.EndedDeviceBindMismatch)
	}

	// ---- an ABSENT pm_did: a stolen pm_session replayed with no device cookie at all ----
	const absent = "bind-absent@example.com"
	absentLogin := s.debugLogin(second, absent)
	absentSession := cookieValueFrom(t, absentLogin, session.SessionCookie)
	absentID := s.webSessionID(absent)

	assertReason(t, s.do(replay, http.MethodGet, "/auth/session/status", "",
		&http.Cookie{Name: session.SessionCookie, Value: absentSession}), session.WireReasonBindMismatch)
	if r := s.endedReason(absentID); r == nil || *r != session.EndedDeviceBindMismatch {
		t.Errorf("ended_reason for an ABSENT pm_did = %v, want %q — absent must fail closed exactly "+
			"like wrong, never resolve as a wildcard (F35/F40: this reason lives only in test comments)",
			r, session.EndedDeviceBindMismatch)
	}
}

// cookieValueFrom pulls one cookie's VALUE off a response, for a replay that must not go through a jar.
func cookieValueFrom(t *testing.T, resp *http.Response, name string) string {
	t.Helper()
	for _, ck := range resp.Cookies() {
		if ck.Name == name {
			return ck.Value
		}
	}
	t.Fatalf("no %s cookie on the response: %v", name, resp.Header.Values("Set-Cookie"))
	return ""
}

// ---------------------------------------------------------------------------------------------
// Case 8 — `a pre-cutover principal-roles cookie fails closed to unauthenticated` (:558-597)
// ---------------------------------------------------------------------------------------------

// TestAPreCutoverPrincipalRolesCookieFailsClosed is INV-A4-10 failure mode (b), and the ONE case in
// this file whose mechanism the Go port had to re-derive rather than copy.
//
// The Kotlin forges the cookie with `SessionTransportTransformerMessageAuthentication`, Ktor's own
// MAC transform — a cookie that is HMAC-VALID under the current key but whose payload is a
// pre-cutover `{principal, roles}` UserSession rather than a storage tracker id. The port's cookie
// encoding is deliberately a different (clean HMAC) scheme, so the Kotlin's exact bytes cannot be
// reproduced; what IS reproduced is the SITUATION, which is the thing under test: a cookie whose MAC
// verifies and whose plaintext is not a tracker key.
//
// 🔒 It must be 401, never 500. This is the shape every browser holding an old cookie sends on the
// morning of cutover, and a 500 would take the login page down with it — the one moment nobody can
// afford an error page instead of a redirect to SSO.
func TestAPreCutoverPrincipalRolesCookieFailsClosed(t *testing.T) {
	s := newAuthServer(t, nil)

	legacy, err := types.MarshalWire(session.UserSession{Principal: "legacy@example.com"})
	if err != nil {
		t.Fatalf("marshal legacy payload: %v", err)
	}
	codec := session.NewCookieCodec(s.cfg.SessionSecret, s.cfg.MCPIssuer())
	forged := &http.Cookie{Name: session.SessionCookie, Value: codec.EncodeRaw(legacy)}

	// Premise check: the forged cookie really does authenticate. Without this the case would also
	// pass against a cookie the MAC simply rejected, which is a different (and already covered) path.
	if _, derr := codec.DecodeRaw(forged.Value); derr != nil {
		t.Fatalf("premise changed: the forged cookie no longer verifies (%v), so this case is not "+
			"testing a valid-HMAC-wrong-shape payload", derr)
	}

	resp := s.do(s.bare(), http.MethodGet, "/auth/me", "", forged)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — a valid HMAC over a wrong-shape payload must be treated as "+
			"unauthenticated, never a 500 (body %s)", resp.StatusCode, readBody(t, resp))
	}
}

// ---------------------------------------------------------------------------------------------
// 🔒 INV-A1-7 at the route — DebugRequesterIpDbTest.kt:155-195's rejection half
// ---------------------------------------------------------------------------------------------

// TestARefusedSimulatedAddressLeavesNothingBehind is the assertion DebugRequesterIpDbTest.kt:190
// makes and the container-free 400 case cannot: "Rejection must leave NOTHING behind. Every
// assertion above would also hold for a handler that minted the session, rewrote the principal's
// roles, and only then returned 400 — leaving the caller logged in under a request the server said
// it refused."
//
// The full sixteen-literal accept/reject corpus is pinned one layer down, on the arbiter itself
// (internal/httpapi/storableip_test.go, sourced from the same Kotlin file). What is asserted HERE is
// the ORDER: the check runs before ensureDeviceCookie and before the transaction.
func TestARefusedSimulatedAddressLeavesNothingBehind(t *testing.T) {
	s := newAuthServer(t, nil)
	c := s.client()
	const principal = "bad-ip@example.com"

	// Seed a real prior state, so "nothing was written" is a claim about a REWRITE as well as an
	// insert: the refused login must not have replaced these roles either.
	if resp := s.debugLogin(c, principal, "system:auditor"); resp.StatusCode != http.StatusOK {
		t.Fatalf("seed login = %d", resp.StatusCode)
	}
	sessionsBefore := s.webSessionCount(principal)

	resp := s.do(c, http.MethodPost, "/auth/debug", `{"principal":"`+principal+`","roles":["system:development-viewer"],"requesterIp":"100.100.1.0/24"}`)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, body)
	}
	// ⚠️ `"params":{}` IS PART OF THE SHAPE, not noise. Kotlin's `ApiError(code, params = emptyMap())`
	// is a defaulted NON-NULL map, and encodeDefaults=true therefore always emits it (INV-A1-4).
	// types.ApiError.MarshalJSON normalises a nil map to `{}` for exactly this reason. Asserting the
	// whole body rather than just the code is what keeps a future "drop the empty params" cleanup
	// from silently changing an error shape the console parses.
	if body != `{"code":"auth.invalid_requester_ip","params":{}}` {
		t.Errorf("body = %s, want {\"code\":\"auth.invalid_requester_ip\",\"params\":{}}", body)
	}
	if after := s.webSessionCount(principal); after != sessionsBefore {
		t.Errorf("web session count %d → %d across a REFUSED login; the check must precede the "+
			"transaction, not follow it", sessionsBefore, after)
	}
	if roles := s.directRoles(principal); !equalStrings(roles, []string{"system:auditor"}) {
		t.Errorf("directRoles = %v, want the untouched [system:auditor] — a refused login must not "+
			"rewrite roles", roles)
	}
}

// TestADebugLoginStoresAndReportsAValidSimulatedAddress is the positive control INV-A1-7's rejection
// half needs: the loop above must be rejecting `100.100.1.0/24` specifically, not rejecting
// everything. DebugRequesterIpDbTest.kt:192-195 makes the same point in the same file.
//
// It also covers 🔒 INV-A1-8's second half against a REAL row: the address is read back off
// `principal_session.debug_requester_ip` by a later /auth/me, not echoed from the login response the
// console's reload never sees.
func TestADebugLoginStoresAndReportsAValidSimulatedAddress(t *testing.T) {
	s := newAuthServer(t, nil)
	c := s.client()
	const principal = "good-ip@example.com"

	resp := s.do(c, http.MethodPost, "/auth/debug",
		`{"principal":"`+principal+`","roles":[],"requesterIp":"  100.100.1.10  "}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, readBody(t, resp))
	}

	// Stored AS TYPED, TRIMMED — the trim is the route's (`requesterIp?.trim()`), and dropping it
	// would push a leading space into the charset allowlist and turn a valid address into a 400.
	var stored *string
	if err := s.db.Pool.QueryRow(context.Background(),
		`SELECT debug_requester_ip FROM principal_session WHERE principal = $1 AND kind = 'WEB'`,
		principal).Scan(&stored); err != nil {
		t.Fatalf("read debug_requester_ip: %v", err)
	}
	if stored == nil || *stored != "100.100.1.10" {
		t.Fatalf("debug_requester_ip = %v, want %q (trimmed)", stored, "100.100.1.10")
	}

	var me session.UserSession
	decodeBody(t, s.do(c, http.MethodGet, "/auth/me", ""), &me)
	if me.RequesterIP == nil || *me.RequesterIP != "100.100.1.10" {
		t.Errorf("/auth/me requesterIp = %v, want %q read back off the session row",
			me.RequesterIP, "100.100.1.10")
	}
}

// ---------------------------------------------------------------------------------------------
// The OIDC routes at the composition root — 04-auth-session-tokens.md:281-282
// ---------------------------------------------------------------------------------------------

// TestOidcRoutesAnswer501WhenOidcIsUnconfigured pins the unconfigured posture of the two OIDC routes
// AS MOUNTED BY THE REAL MODULE.
//
// ⚠️ THIS CASE CHANGED THE PORT. `NewHTTPSurface` previously skipped the whole group when
// `config.oidc == null`, so an unconfigured deployment answered 404 where Ktor answers 501
// `common.oidc_not_configured` — a console that says "that page does not exist" instead of "SSO is
// not set up on this deployment". Ktor mounts `oidcRoutes` UNCONDITIONALLY and each handler runs the
// `config.oidc == null || discovery == null || validator == null` guard; internal/oidc reproduces
// that guard exactly, so the fix is to mount with nil Discovery/Validator and let the guard answer.
// OidcCallbackTest case 2 is the Kotlin assertion this restores at the app level.
func TestOidcRoutesAnswer501WhenOidcIsUnconfigured(t *testing.T) {
	s := newAuthServer(t, nil)
	for _, path := range []string{"/auth/oidc/login", "/auth/oidc/callback"} {
		resp := s.do(s.client(), http.MethodGet, path, "")
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s = %d, want 501 (body %s) — the group must mount unconditionally so the "+
				"handler's own guard answers", path, resp.StatusCode, body)
		}
		// `"params":{}` for the same INV-A1-4 reason as every other ApiError on the wire.
		if body != `{"code":"common.oidc_not_configured","params":{}}` {
			t.Errorf("%s body = %s, want {\"code\":\"common.oidc_not_configured\",\"params\":{}}", path, body)
		}
	}
}

// TestTheModuleMountsEveryA1Route is the boot-time inventory: a route table is only a contract if
// something notices a route falling out of it.
//
// It asserts REACHABILITY, not behaviour — each route is hit with no credentials and must answer
// anything other than 404. Behaviour is every other case in this file. A group silently unmounted
// (the `oidcRoutes` nil-return above is exactly that failure, and it shipped) is otherwise
// indistinguishable from a route that is merely gated.
func TestTheModuleMountsEveryA1Route(t *testing.T) {
	s := newAuthServer(t, nil)
	c := s.bare()
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/auth/config"},
		{http.MethodPost, "/auth/debug"},
		{http.MethodGet, "/auth/me"},
		{http.MethodGet, "/auth/session/status"},
		{http.MethodPost, "/auth/session/heartbeat"},
		{http.MethodPost, "/auth/logout"},
		{http.MethodGet, "/api/me/permissions"},
		{http.MethodGet, "/auth/oidc/login"},
		{http.MethodGet, "/auth/oidc/callback"},
	} {
		resp := s.do(c, tc.method, tc.path, "")
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("%s %s = 404; the composition root does not mount it", tc.method, tc.path)
		}
	}
}

// itoa64 keeps the conditional-logout bodies above readable at their call sites.
func itoa64(v int64) string { return strconv.FormatInt(v, 10) }
