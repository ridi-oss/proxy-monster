package queryhistory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/config"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `/api/query-history` — 07-tasks-approvals-results.md §9's two routes.
//
//	GET    /api/query-history   requireApi, `limit` default 50 coerced into [1, 200]
//	DELETE /api/query-history   requireApi, **204**
//
// Both fall back to `"debug-user"`, and both are PRINCIPAL-SCOPED FROM THE SESSION AND ONLY FROM THE
// SESSION — no `principal` query parameter, no admin view, no cross-principal read.
//
// 🔴 NEW, like everything else in this package (F17). The oracle is §9, cited per case.
//
// No Cedar anywhere: requireApi is the whole authorization, because the session determines WHAT the
// answer contains rather than merely whether one is given. The fixture therefore has no authorizer at
// all, and [httpapi.Gates.Authz] is left nil — which is itself an assertion: a route that reached
// Cedar would nil-panic and StatusPages would turn it into a visible 500.
// ---------------------------------------------------------------------------------------------

type routeFixture struct {
	*storeFixture
	handler  http.Handler
	sessions *httpapi.Sessions
	resolver *fakeResolver
	cfg      config.Config
}

func newRouteFixture(t *testing.T, authDebug bool) *routeFixture {
	t.Helper()
	sf := newStoreFixture(t)

	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = authDebug
	cfg.SecretToken = nil
	cfg.SessionSecret = "query-history-route-test-secret-32b"
	cfg.OIDC = nil
	cfg.ResultKey = nil
	cfg.ScimToken = nil
	cfg.TrustedProxies = map[string]struct{}{}

	resolver := newFakeResolver()
	sessions := &httpapi.Sessions{
		Codec:           session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		Storage:         newFakeStorage(),
		Resolver:        resolver,
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
	}
	// Authz is deliberately nil — see the file comment.
	gates := &httpapi.Gates{Config: cfg, Sessions: sessions}

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(NewRoutes(gates, sf.store, nil))

	return &routeFixture{storeFixture: sf, handler: router.Handler(), sessions: sessions, resolver: resolver, cfg: cfg}
}

func (f *routeFixture) login(principal string) *http.Cookie {
	f.t.Helper()
	const id int64 = 9
	now := time.Now().UTC()
	f.resolver.rows[id] = &session.WebRow{
		ID: id, Principal: principal, CreatedAt: now, Now: now,
		IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	}
	rec := httptest.NewRecorder()
	if err := f.sessions.SetWebSession(context.Background(), rec, id); err != nil {
		f.t.Fatalf("SetWebSession: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.SessionCookie {
			return c
		}
	}
	f.t.Fatalf("no %s cookie was written", session.SessionCookie)
	return nil
}

func (f *routeFixture) do(method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

// ---- The gate ---------------------------------------------------------------------------------

// requireApi on BOTH routes. The DELETE matters more than the GET: it takes no id and has no
// confirmation step, so it clears the caller's entire history — safe only because the table is
// explicitly convenience-only (V5__tasks.sql:104), and only for the caller's OWN rows.
func TestBothQueryHistoryRoutesRequireASession(t *testing.T) {
	f := newRouteFixture(t, false)

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			rec := f.do(method, "/api/query-history")

			assertStatus(t, rec, http.StatusUnauthorized, "no session")
			var body types.ApiError
			decodeJSON(t, rec, &body)
			if body.Code != "common.unauthenticated" {
				t.Errorf("code: got %q, want \"common.unauthenticated\"", body.Code)
			}
		})
	}
}

// ---- GET --------------------------------------------------------------------------------------

// 200 with the caller's deduplicated history, newest first.
func TestGetAnswers200WithTheCallersOwnDeduplicatedHistory(t *testing.T) {
	f := newRouteFixture(t, false)
	f.add(alice, nil, "select one")
	f.add(alice, nil, "select two")
	f.add(alice, nil, "select one")
	f.add(bob, nil, "select bobs")

	rec := f.do(http.MethodGet, "/api/query-history", f.login(alice))

	assertStatus(t, rec, http.StatusOK, "list")
	var got []Entry
	decodeJSON(t, rec, &got)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 distinct: %+v", len(got), got)
	}
	if got[0].SQL != "select one" || got[1].SQL != "select two" {
		t.Errorf("got %q, %q; want the deduplicated list newest-first", got[0].SQL, got[1].SQL)
	}
}

// ⚠️ PRINCIPAL-SCOPED FROM THE SESSION AND ONLY FROM THE SESSION. There is no `principal` query
// parameter to honour and [Store] exposes no unscoped read, so a caller cannot widen the scope even
// by guessing a parameter name. Both are probed here, because "the parameter does not exist" is only
// observable as "supplying it changes nothing".
func TestGetIgnoresAnyAttemptToNameAnotherPrincipal(t *testing.T) {
	f := newRouteFixture(t, false)
	f.add(alice, nil, "alice statement")
	f.add(bob, nil, "bob statement")
	cookie := f.login(alice)

	for _, target := range []string{
		"/api/query-history?principal=" + bob,
		"/api/query-history?user=" + bob,
		"/api/query-history?principal=" + bob + "&limit=50",
	} {
		t.Run(target, func(t *testing.T) {
			rec := f.do(http.MethodGet, target, cookie)
			assertStatus(t, rec, http.StatusOK, "scoped read")
			var got []Entry
			decodeJSON(t, rec, &got)
			for _, e := range got {
				if e.SQL == "bob statement" {
					t.Errorf("%s leaked another principal's history", target)
				}
			}
			if len(got) != 1 || got[0].SQL != "alice statement" {
				t.Errorf("got %+v, want only alice's own row", got)
			}
		})
	}
}

// The limit, from a URL. Default 50, coerced into [1, 200] — DIFFERENT numbers from audit's
// 100/[1,500], and the reason the two helpers are separate functions.
func TestTheLimitQueryParameterIsCoercedFromTheURL(t *testing.T) {
	f := newRouteFixture(t, false)
	f.add(alice, nil, "select a")
	f.add(alice, nil, "select b")
	f.add(alice, nil, "select c")
	cookie := f.login(alice)

	for _, c := range []struct {
		query string
		want  int
		why   string
	}{
		{"?limit=1", 1, "an in-range limit is honoured"},
		{"?limit=0", 1, "coerceIn's floor: 0 clamps UP to 1"},
		{"?limit=-1", 1, "the floor, from below"},
		{"?limit=abc", 3, "unparseable ⇒ the 50 default, which exceeds the fixture"},
		{"?limit=3000000000", 3, "🔒 32-bit: NOT A NUMBER to Kotlin ⇒ the default, not the 200 cap"},
		{"?limit=", 3, "present but empty is unparseable ⇒ the default"},
		{"", 3, "absent ⇒ the default"},
	} {
		t.Run(c.query+" "+c.why, func(t *testing.T) {
			rec := f.do(http.MethodGet, "/api/query-history"+c.query, cookie)
			assertStatus(t, rec, http.StatusOK, "limit")
			var got []Entry
			decodeJSON(t, rec, &got)
			if len(got) != c.want {
				t.Errorf("got %d entries, want %d — %s", len(got), c.want, c.why)
			}
		})
	}
}

// 🔒 INV-A1-4 — an empty history is `[]`, never `null`.
func TestAnEmptyHistoryIsAnEmptyArrayNotNull(t *testing.T) {
	f := newRouteFixture(t, false)

	rec := f.do(http.MethodGet, "/api/query-history", f.login("nobody@example.com"))

	assertStatus(t, rec, http.StatusOK, "empty")
	if got := rec.Body.String(); got != `[]` {
		t.Errorf("body: got %s, want []", got)
	}
}

// ---- DELETE -----------------------------------------------------------------------------------

// **204** with NO body, and it clears the caller's rows AND ONLY THE CALLER'S.
func TestDeleteAnswers204AndClearsOnlyTheCallersRows(t *testing.T) {
	f := newRouteFixture(t, false)
	f.add(alice, nil, "alice statement")
	f.add(bob, nil, "bob statement")

	rec := f.do(http.MethodDelete, "/api/query-history", f.login(alice))

	assertStatus(t, rec, http.StatusNoContent, "clear")
	if rec.Body.Len() != 0 {
		t.Errorf("204 must carry no body, got %q", rec.Body.String())
	}
	if n := f.rowCount(alice); n != 0 {
		t.Errorf("alice still has %d rows", n)
	}
	if n := f.rowCount(bob); n != 1 {
		t.Errorf("bob's history was disturbed: %d rows left, want 1", n)
	}
}

// ---- the "debug-user" fallback ------------------------------------------------------------------

// Both routes fall back to `"debug-user"` when PM_AUTH_DEBUG admitted a request with no session
// (07-tasks-approvals-results.md:631).
//
// ⚠️ Contrast internal/policy's `/api/policies` routes, which pass a NULL principal in the same
// situation. The difference is right: there the principal lands on an audit row whose whole purpose is
// attribution (INV-A2-22) and a fabricated identity would be worse than none; here it is a partition
// key for a convenience list, so a stable literal gives every debug session ONE SHARED history instead
// of dropping the feature.
func TestUnderAuthDebugWithNoSessionBothRoutesUseTheDebugUserPartition(t *testing.T) {
	f := newRouteFixture(t, true)
	f.add(DebugPrincipal, nil, "a debug-user statement")
	f.add(alice, nil, "alice statement")

	rec := f.do(http.MethodGet, "/api/query-history")
	assertStatus(t, rec, http.StatusOK, "debug list")
	var got []Entry
	decodeJSON(t, rec, &got)
	if len(got) != 1 || got[0].SQL != "a debug-user statement" {
		t.Errorf("got %+v, want only the debug-user partition", got)
	}

	rec = f.do(http.MethodDelete, "/api/query-history")
	assertStatus(t, rec, http.StatusNoContent, "debug clear")
	if n := f.rowCount(DebugPrincipal); n != 0 {
		t.Errorf("the debug partition still has %d rows", n)
	}
	if n := f.rowCount(alice); n != 1 {
		t.Errorf("a debug clear touched alice's rows: %d left, want 1", n)
	}
}

// 🔒 THE ORDER IS LOAD-BEARING: the session is READ FIRST and the literal is only the fallback, so a
// debug-mode request that DOES carry a session gets ITS OWN history rather than the shared debug one.
//
// Reversing it — branching on authDebug before looking — would make PM_AUTH_DEBUG silently merge every
// developer's history into one list, and the merge would be invisible until two people ran the local
// stack at once.
func TestUnderAuthDebugAliveSessionStillGetsItsOwnHistory(t *testing.T) {
	f := newRouteFixture(t, true)
	f.add(DebugPrincipal, nil, "a debug-user statement")
	f.add(alice, nil, "alice statement")

	rec := f.do(http.MethodGet, "/api/query-history", f.login(alice))

	assertStatus(t, rec, http.StatusOK, "debug list with a session")
	var got []Entry
	decodeJSON(t, rec, &got)
	if len(got) != 1 || got[0].SQL != "alice statement" {
		t.Errorf("got %+v, want alice's own history — the session is read BEFORE the fallback", got)
	}
}

// ---- routing --------------------------------------------------------------------------------------

// Same path, two methods. ServeMux answers 405 with an `Allow` header for anything else, which is
// what Ktor gives too (it answers 405 for a path that matches with no method handler).
//
// ⚠️ `HEAD` is in the Allow set because ServeMux registers it implicitly alongside every GET — the
// httpapi.Router divergence 3, recorded there and visible here. Ktor installs no AutoHeadResponse, so
// this WIDENS the accepted method set. Not an authorization hole (HEAD reaches the same handler and
// therefore the same gate), and pinned rather than silently accepted.
func TestAnUnsupportedMethodIs405WithAnAllowHeader(t *testing.T) {
	f := newRouteFixture(t, true)

	rec := f.do(http.MethodPost, "/api/query-history")

	assertStatus(t, rec, http.StatusMethodNotAllowed, "POST")
	allow := rec.Header().Get("Allow")
	if allow == "" {
		t.Fatal("405 must carry an Allow header")
	}
	for _, want := range []string{"GET", "DELETE"} {
		if !strings.Contains(allow, want) {
			t.Errorf("Allow = %q, must include %s", allow, want)
		}
	}
	if !strings.Contains(allow, "HEAD") {
		t.Errorf("Allow = %q — HEAD is expected here: ServeMux registers it implicitly alongside GET "+
			"(httpapi.Router divergence 3). If this ever stops being true, the divergence note is stale.",
			allow)
	}
}

// ---- fakes and helpers ------------------------------------------------------------------------------

type fakeStorage struct{ keys map[string]int64 }

func newFakeStorage() *fakeStorage { return &fakeStorage{keys: map[string]int64{}} }

func (f *fakeStorage) Write(_ context.Context, key string, ref session.WebSessionRef) error {
	f.keys[key] = ref.SessionID
	return nil
}

func (f *fakeStorage) Read(_ context.Context, key string) (session.WebSessionRef, error) {
	id, ok := f.keys[key]
	if !ok {
		return session.WebSessionRef{}, session.ErrUnknownWebSessionKey
	}
	return session.WebSessionRef{SessionID: id}, nil
}

func (f *fakeStorage) Invalidate(_ context.Context, key string) error {
	delete(f.keys, key)
	return nil
}

type fakeResolver struct{ rows map[int64]*session.WebRow }

func newFakeResolver() *fakeResolver { return &fakeResolver{rows: map[int64]*session.WebRow{}} }

func (f *fakeResolver) ResolveWeb(_ context.Context, id int64, _ *string) (*session.WebRow, error) {
	return f.rows[id], nil
}

func (f *fakeResolver) WebEndedReason(context.Context, int64) (*string, error) { return nil, nil }

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: got status %d, want %d (body: %s)", what, rec.Code, want, rec.Body.String())
	}
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body.String())
	}
}
