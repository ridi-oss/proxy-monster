package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// The Sessions plugin and the Authentication plugin — 01-bootstrap.md §2 ("Plugins, in order:
// … Sessions (5 cookies) → Authentication", and `respondSessionUnauthorized` at :312-313),
// 04-auth-session-tokens.md §3.1 (`webSession()` / `userSession()`) and §3.2
// (`PrincipalSessionStorage`).
//
// The seams are faked (see support_test.go). internal/session's own DB suites prove the SQL; what
// this file owns is the REQUEST-TIME plumbing over it — the resolution cache, the collapse of every
// cookie-read failure to "unauthenticated", the two halves of a logout, and the four-value challenge
// reason.

// liveSessions returns a Sessions over fresh fakes, with row 7 live and held by principal.
func liveSessions(t *testing.T) (*Sessions, *fakeStorage, *fakeResolver) {
	t.Helper()
	storage := newFakeStorage()
	resolver := newFakeResolver()
	resolver.rows[7] = &session.WebRow{ID: 7, Principal: "alice@example.com", Now: time.Now()}
	return testSessions(storage, resolver), storage, resolver
}

// ---------------------------------------------------------------------------------------------
// webSession() — Auth.kt:97-108
// ---------------------------------------------------------------------------------------------

func TestWebSessionResolvesALiveRowFromTheCookie(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))

	row, err := sessions.WebSession(r)
	if err != nil {
		t.Fatalf("WebSession: %v", err)
	}
	if row == nil || row.Principal != "alice@example.com" {
		t.Fatalf("row = %+v, want the live row for alice@example.com", row)
	}
}

// 🔒 INV-A4-11 — "resolution is cached exactly once per request." The cost of getting this wrong is
// not merely N round trips: session.Store.ResolveWeb ENDS a row on a device-binding mismatch, so a
// second resolution would evaluate a row the first one just killed. Observable as the resolver call
// count.
func TestWebSessionResolvesAtMostOncePerRequest(t *testing.T) {
	sessions, storage, resolver := liveSessions(t)
	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))

	for i := 0; i < 3; i++ {
		if _, err := sessions.WebSession(r); err != nil {
			t.Fatalf("WebSession #%d: %v", i, err)
		}
	}
	if resolver.resolveCalls != 1 {
		t.Errorf("resolveWeb was called %d times for one request, want exactly 1 (INV-A4-11)",
			resolver.resolveCalls)
	}
}

// The cached value must include a cached NOTHING — 04-auth-session-tokens.md §3.1 step 1, "including
// a cached null". That is what `resolvedIdentity.done` is for; a bare *WebRow in the context could
// not tell "resolved to nothing" from "not yet resolved" and would re-resolve on every read.
func TestWebSessionCachesTheNegativeAnswerToo(t *testing.T) {
	sessions, storage, resolver := liveSessions(t)
	delete(resolver.rows, 7) // the row is gone: expired, displaced, whatever.

	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))

	for i := 0; i < 3; i++ {
		row, err := sessions.WebSession(r)
		if err != nil || row != nil {
			t.Fatalf("WebSession #%d = (%+v, %v), want (nil, nil)", i, row, err)
		}
	}
	if resolver.resolveCalls != 1 {
		t.Errorf("resolveWeb was called %d times, want exactly 1 — a cached nil is still a cache hit",
			resolver.resolveCalls)
	}
}

// 🔒 INV-A4-10 — EVERY cookie-read failure mode collapses to "unauthenticated", never to a 500 and
// never to a partially-trusted identity. Losing this turns a stale browser cookie into a 500 on
// every request, which is a total outage for anyone whose browser still holds one.
//
// The Kotlin's three swallowed failures are (a) an unknown tracker id, (b) deserialization failing
// on a pre-cutover `{principal, roles}` payload that is HMAC-valid under the current key
// (WebSessionRoutesDbTest case 8), and (c) a missing store attribute.
//
// ⚠️ (b) reaches the SAME code path as (a) in this port, and deliberately so: `pm_session` carries a
// TRACKER ID rather than a JSON payload (99-library-decisions.md D7), so an authentic cookie holding
// the old `{principal, roles}` shape decodes to raw bytes that are simply not a known session key.
// The distinction the Kotlin makes is in WHERE the failure happens, not in what the caller sees, and
// what the caller sees is the invariant. The case is kept as its own row so a future port that DOES
// put a payload in the cookie inherits an assertion for it.
func TestWebSessionCollapsesEveryCookieReadFailureToUnauthenticated(t *testing.T) {
	authentic := func(t *testing.T, s *Sessions, payload string) *http.Cookie {
		t.Helper()
		return s.Codec.NewCookie(session.SessionSpec(7200), s.Codec.EncodeRaw([]byte(payload)))
	}

	t.Run("(a) an unknown tracker id", func(t *testing.T) {
		sessions, _, _ := liveSessions(t)
		r := requestWithIdentity(http.MethodGet, "/probe")
		r.AddCookie(authentic(t, sessions, "0123456789abcdef0123456789abcdef"))
		assertNoSession(t, sessions, r)
	})

	t.Run("(b) a valid HMAC over a wrong-shape payload", func(t *testing.T) {
		sessions, _, _ := liveSessions(t)
		r := requestWithIdentity(http.MethodGet, "/probe")
		r.AddCookie(authentic(t, sessions, `{"principal":"alice@example.com","roles":["admin"]}`))
		assertNoSession(t, sessions, r)
	})

	t.Run("(c) no storage wired at all", func(t *testing.T) {
		sessions, storage, _ := liveSessions(t)
		cookie := loginCookie(t, sessions, storage, 7)
		sessions.Storage = nil
		r := requestWithIdentity(http.MethodGet, "/probe")
		r.AddCookie(cookie)
		assertNoSession(t, sessions, r)
	})

	t.Run("no resolver wired at all", func(t *testing.T) {
		sessions, storage, _ := liveSessions(t)
		cookie := loginCookie(t, sessions, storage, 7)
		sessions.Resolver = nil
		r := requestWithIdentity(http.MethodGet, "/probe")
		r.AddCookie(cookie)
		assertNoSession(t, sessions, r)
	})

	t.Run("a forged cookie", func(t *testing.T) {
		sessions, storage, _ := liveSessions(t)
		cookie := loginCookie(t, sessions, storage, 7)
		cookie.Value = cookie.Value[:len(cookie.Value)-1] + "X" // one byte of the MAC flipped
		r := requestWithIdentity(http.MethodGet, "/probe")
		r.AddCookie(cookie)
		assertNoSession(t, sessions, r)
	})

	t.Run("a cookie signed with a different key", func(t *testing.T) {
		sessions, storage, _ := liveSessions(t)
		cookie := loginCookie(t, sessions, storage, 7)
		other := session.NewCookieCodec("a-completely-different-session-secret", "http://127.0.0.1:8080")
		cookie.Value = other.EncodeRaw([]byte("0123456789abcdef0123456789abcdef"))
		r := requestWithIdentity(http.MethodGet, "/probe")
		r.AddCookie(cookie)
		assertNoSession(t, sessions, r)
	})

	t.Run("a storage read that fails for some other reason", func(t *testing.T) {
		sessions, storage, _ := liveSessions(t)
		cookie := loginCookie(t, sessions, storage, 7)
		storage.readErr = errStoreDown
		r := requestWithIdentity(http.MethodGet, "/probe")
		r.AddCookie(cookie)
		assertNoSession(t, sessions, r)
	})

	t.Run("no cookie at all", func(t *testing.T) {
		sessions, _, _ := liveSessions(t)
		assertNoSession(t, sessions, requestWithIdentity(http.MethodGet, "/probe"))
	})
}

// assertNoSession is the INV-A4-10 assertion: nil row AND nil error. A non-nil error here would
// become a 500 at the gate, which is exactly the failure the invariant forbids.
func assertNoSession(t *testing.T, s *Sessions, r *http.Request) {
	t.Helper()
	row, err := s.WebSession(r)
	if err != nil {
		t.Fatalf("WebSession returned an error (%v); every cookie-read failure must collapse to "+
			"unauthenticated, never to a 500", err)
	}
	if row != nil {
		t.Fatalf("WebSession resolved %+v; want no session", row)
	}
}

// The error return is NOT one of INV-A4-10's three. It is the resolver failing — the database being
// down mid-resolution — which in the Kotlin is an exception reaching StatusPages. Distinguishing it
// is what lets a gate answer `common.fallback` instead of telling a caller they are signed out when
// the truth is "we could not tell".
func TestWebSessionSurfacesAResolverFailureAsAnError(t *testing.T) {
	sessions, storage, resolver := liveSessions(t)
	resolver.resolveErr = errStoreDown

	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))

	if _, err := sessions.WebSession(r); err == nil {
		t.Fatal("a resolver failure must be returned, not swallowed into 'no session'")
	}
}

// A request that never went through [Sessions.Install] still resolves — it just resolves EVERY time,
// because there is nowhere to cache. Worth pinning: it is the difference between a missing
// middleware being a performance bug and being a nil-pointer panic.
func TestWebSessionWorksWithoutTheInstallHolderButDoesNotCache(t *testing.T) {
	sessions, storage, resolver := liveSessions(t)
	r := httptest.NewRequest(http.MethodGet, "/probe", nil) // deliberately NOT requestWithIdentity
	r.AddCookie(loginCookie(t, sessions, storage, 7))

	for i := 0; i < 2; i++ {
		row, err := sessions.WebSession(r)
		if err != nil || row == nil {
			t.Fatalf("WebSession #%d = (%+v, %v), want the live row", i, row, err)
		}
	}
	if resolver.resolveCalls != 2 {
		t.Errorf("resolveCalls = %d, want 2 — with no holder there is nothing to cache into",
			resolver.resolveCalls)
	}
}

func TestInstallSeatsTheResolutionHolder(t *testing.T) {
	sessions, _, _ := liveSessions(t)
	var seen bool
	h := sessions.Install(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = identityOf(r) != nil
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe", nil))
	if !seen {
		t.Error("Install must seat the per-request resolution holder")
	}
}

// ---------------------------------------------------------------------------------------------
// userSession() — Auth.kt:111
// ---------------------------------------------------------------------------------------------

// 🔒 ROLES ARE DELIBERATELY EMPTY (04-auth-session-tokens.md §3.1). `Tokens.kt:268`'s `rolesOf(call)`
// therefore always returns an empty list for a real session, which is why minted tokens carry an
// empty role snapshot and effective roles are re-resolved at decide time. §6 Q4 asks whether that is
// intentional; PORT POLICY says reproduce it either way, so this test pins the reproduction and a
// later "fix" has to change it deliberately.
func TestUserSessionCarriesThePrincipalAndNoRoles(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))

	us, err := sessions.UserSession(r)
	if err != nil {
		t.Fatalf("UserSession: %v", err)
	}
	if us == nil {
		t.Fatal("UserSession = nil, want a session for alice@example.com")
	}
	if us.Principal != "alice@example.com" {
		t.Errorf("principal = %q, want alice@example.com", us.Principal)
	}
	if len(us.Roles) != 0 {
		t.Errorf("roles = %v, want empty — userSession() never carries roles", us.Roles)
	}
	// INV-A1-4: nil roles still marshal as `[]`, which is what emptyList() + encodeDefaults=true
	// produces. The console's `roles.map` throws on null.
	raw, err := types.MarshalWire(us)
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	if got, want := string(raw), `{"principal":"alice@example.com","roles":[]}`; got != want {
		t.Errorf("wire bytes = %s, want %s", got, want)
	}
}

func TestUserSessionIsNilWithoutASession(t *testing.T) {
	sessions, _, _ := liveSessions(t)
	us, err := sessions.UserSession(requestWithIdentity(http.MethodGet, "/probe"))
	if err != nil || us != nil {
		t.Fatalf("UserSession = (%+v, %v), want (nil, nil)", us, err)
	}
}

// ---------------------------------------------------------------------------------------------
// Cookie write / clear
// ---------------------------------------------------------------------------------------------

// The link is committed BEFORE the Set-Cookie is written. Reversed, a browser can hold a key the
// database does not know — a login that silently did not happen, visible only on the next request.
// (loginCookie asserts the ordering on every call; this case states it as its own claim.)
func TestSetWebSessionLinksTheKeyBeforeWritingTheCookie(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	rec := httptest.NewRecorder()

	if err := sessions.SetWebSession(context.Background(), rec, 7); err != nil {
		t.Fatalf("SetWebSession: %v", err)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want exactly one", len(cookies))
	}
	ck := cookies[0]
	if ck.Name != session.SessionCookie {
		t.Errorf("cookie name = %q, want %q", ck.Name, session.SessionCookie)
	}
	// 01-bootstrap.md §"Cookies": all five share path=/, httpOnly, SameSite=Lax; `pm_session` is the
	// one whose maxAge comes from config (`webSessionAbsoluteSeconds`).
	if ck.Path != "/" || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("attributes = {path:%q httpOnly:%v sameSite:%v}, want {/ true Lax}",
			ck.Path, ck.HttpOnly, ck.SameSite)
	}
	if ck.MaxAge != 7200 {
		t.Errorf("maxAge = %d, want 7200 (config.webSessionAbsoluteSeconds)", ck.MaxAge)
	}
	// The issuer in testSessions is http://, so secure is off. A https issuer flips it — pinned in
	// internal/session's cookie suite; asserted here only to catch an accidental hardcode.
	if ck.Secure {
		t.Error("secure = true for an http issuer; it must track mcpIssuer's scheme")
	}

	// The tracker id in the cookie is what the storage was keyed with.
	raw, err := sessions.Codec.DecodeRaw(ck.Value)
	if err != nil {
		t.Fatalf("the cookie this package wrote does not authenticate: %v", err)
	}
	if id, ok := storage.keys[string(raw)]; !ok || id != 7 {
		t.Errorf("storage holds %v, want the cookie's key -> 7", storage.keys)
	}
}

// 🔒 THE ORDERING IN ITS OBSERVABLE FORM. Asserting "the key is linked" after a SUCCESSFUL call
// cannot distinguish the two orders — both end with both done. What distinguishes them is the link
// FAILING: with the link first, SetWebSession returns before any Set-Cookie is written and the
// browser is left holding nothing. Reversed, the browser would hold a live-looking cookie pointing
// at a row the database never heard of, and the login would present as "signed in, then instantly
// signed out again" on the very next request.
func TestSetWebSessionWritesNoCookieWhenTheLinkFails(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	sessions.Storage = &failingWriteStorage{fakeStorage: storage}
	rec := httptest.NewRecorder()

	if err := sessions.SetWebSession(context.Background(), rec, 7); err == nil {
		t.Fatal("SetWebSession must return the link failure")
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("Set-Cookie = %+v, want none — the link must be committed BEFORE the cookie is "+
			"written", cookies)
	}
}

type failingWriteStorage struct{ *fakeStorage }

func (f *failingWriteStorage) Write(context.Context, string, session.WebSessionRef) error {
	return errStoreDown
}

// A tracker key is a bearer credential for a live session (it is the whole content of `pm_session`),
// so two logins must never collide.
func TestSetWebSessionMintsAFreshKeyEachTime(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	for i := 0; i < 4; i++ {
		if err := sessions.SetWebSession(context.Background(), httptest.NewRecorder(), int64(i)); err != nil {
			t.Fatalf("SetWebSession #%d: %v", i, err)
		}
	}
	if len(storage.keys) != 4 {
		t.Errorf("storage holds %d keys after 4 logins, want 4 distinct ones: %v",
			len(storage.keys), storage.keys)
	}
}

// 🔒 INV-A4-7 — BOTH HALVES. App.kt:781's `sessions.clear(SESSION_COOKIE)` looks like it only drops a
// cookie; the end-write happens inside PrincipalSessionStorage.invalidate, which Ktor calls for it.
// A Go port that writes the deletion by hand ends up with a "signed out" row that a replayed cookie
// still resolves.
func TestClearWebSessionInvalidatesTheRowAndDeletesTheCookie(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	cookie := loginCookie(t, sessions, storage, 7)
	r := requestWithIdentity(http.MethodPost, "/auth/logout")
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()

	if err := sessions.ClearWebSession(context.Background(), rec, r); err != nil {
		t.Fatalf("ClearWebSession: %v", err)
	}

	if len(storage.ended) != 1 {
		t.Fatalf("invalidate was called %d times, want exactly 1 — logout must END the row, not just "+
			"drop the cookie (INV-A4-7)", len(storage.ended))
	}
	raw, err := sessions.Codec.DecodeRaw(cookie.Value)
	if err != nil {
		t.Fatalf("DecodeRaw: %v", err)
	}
	if storage.ended[0] != string(raw) {
		t.Errorf("invalidate was called with %q, want the cookie's own tracker key", storage.ended[0])
	}

	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Fatalf("Set-Cookie = %+v, want one deletion (MaxAge < 0)", cleared)
	}
	// A browser matches a deletion on (name, domain, path): a delete written without path=/ silently
	// leaves the cookie in place.
	if cleared[0].Path != "/" {
		t.Errorf("deletion path = %q, want / — otherwise the browser keeps the cookie", cleared[0].Path)
	}
}

// Leaving the browser holding a live credential because the database was briefly unreachable is the
// worse of the two failures, so the cookie goes regardless and the error is returned for the caller.
func TestClearWebSessionDeletesTheCookieEvenWhenTheInvalidateFails(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	cookie := loginCookie(t, sessions, storage, 7)
	storage.readErr = errStoreDown // unused by Invalidate, but proves we are not reading first
	failing := &failingInvalidateStorage{fakeStorage: storage}
	sessions.Storage = failing

	r := requestWithIdentity(http.MethodPost, "/auth/logout")
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()

	if err := sessions.ClearWebSession(context.Background(), rec, r); err == nil {
		t.Error("the invalidate failure must be returned so the caller can log it")
	}
	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Fatalf("Set-Cookie = %+v, want the deletion to be written anyway", cleared)
	}
}

// A logout with no cookie at all is not an error and must not touch the storage.
func TestClearWebSessionWithNoCookieIsANoOp(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	rec := httptest.NewRecorder()

	if err := sessions.ClearWebSession(context.Background(), rec, requestWithIdentity(http.MethodPost, "/auth/logout")); err != nil {
		t.Fatalf("ClearWebSession with no cookie: %v", err)
	}
	if len(storage.ended) != 0 {
		t.Errorf("invalidate was called %d times for a request with no session cookie", len(storage.ended))
	}
}

type failingInvalidateStorage struct{ *fakeStorage }

func (f *failingInvalidateStorage) Invalidate(context.Context, string) error { return errStoreDown }

// ---------------------------------------------------------------------------------------------
// FAILED_WEB_SESSION
// ---------------------------------------------------------------------------------------------

// 🔒 INV-A4-12's payoff. `read` returns refs for ENDED and EXPIRED rows precisely so that this
// attribute gets set; a storage lookup that filtered them out would leave every terminated session
// reporting "none" instead of "displaced" / "bind_mismatch".
func TestFailedWebSessionRecordsTheIDACookieNamedButDidNotResolve(t *testing.T) {
	sessions, storage, resolver := liveSessions(t)
	delete(resolver.rows, 7)

	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))
	if _, err := sessions.WebSession(r); err != nil {
		t.Fatalf("WebSession: %v", err)
	}

	failed := FailedWebSession(r)
	if failed == nil || *failed != 7 {
		t.Fatalf("FailedWebSession = %v, want 7", failed)
	}
}

func TestFailedWebSessionIsUnsetWhenTheRequestNamedNoSession(t *testing.T) {
	sessions, _, _ := liveSessions(t)
	r := requestWithIdentity(http.MethodGet, "/probe")
	if _, err := sessions.WebSession(r); err != nil {
		t.Fatalf("WebSession: %v", err)
	}
	if failed := FailedWebSession(r); failed != nil {
		t.Errorf("FailedWebSession = %v, want nil for a request that carried no cookie", *failed)
	}
}

func TestFailedWebSessionIsUnsetForALiveRow(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))
	if _, err := sessions.WebSession(r); err != nil {
		t.Fatalf("WebSession: %v", err)
	}
	if failed := FailedWebSession(r); failed != nil {
		t.Errorf("FailedWebSession = %v, want nil for a session that resolved", *failed)
	}
}

// ---------------------------------------------------------------------------------------------
// The Authentication plugin — `authenticate(WEB_SESSION_AUTH)`, App.kt:536-542
// ---------------------------------------------------------------------------------------------

func TestRequireWebSessionAdmitsALiveRow(t *testing.T) {
	sessions, storage, _ := liveSessions(t)
	reached := false
	h := sessions.Install(sessions.RequireWebSession(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})))

	r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	r.AddCookie(loginCookie(t, sessions, storage, 7))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if !reached {
		t.Fatalf("the handler was not reached (status %d, body %s)", rec.Code, rec.Body.String())
	}
}

// It is a DIFFERENT gate from requireApi: this one answers a SessionStatusError (so the console can
// explain WHY the session went away), where requireApi answers an ApiError. Collapsing the two would
// leave the console unable to distinguish "someone signed in elsewhere" from "not signed in".
func TestRequireWebSessionChallengesWithASessionStatusErrorNotAnApiError(t *testing.T) {
	sessions, _, _ := liveSessions(t)
	h := sessions.Install(sessions.RequireWebSession(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the handler must not be reached without a session")
	})))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	assertStatus(t, rec, http.StatusUnauthorized, "no session")
	var body SessionStatusError
	decodeBody(t, rec, &body)
	if body.Reason != session.WireReasonNone {
		t.Errorf("reason = %q, want %q", body.Reason, session.WireReasonNone)
	}
	// Asserted on the RAW bytes rather than by decoding into types.ApiError, because ApiError's
	// UnmarshalJSON rejects a body with no `code` — which would turn "the right shape" into a test
	// failure.
	if strings.Contains(rec.Body.String(), `"code"`) {
		t.Errorf("the challenge body carries an ApiError code (%s); WEB_SESSION_AUTH answers a "+
			"SessionStatusError so the console can explain WHY the session went away",
			rec.Body.String())
	}
}

// A resolver failure is not a challenge: the caller is not being told "you are signed out" when the
// truth is "the database is down". Same body StatusPages would produce.
func TestRequireWebSessionAnswersTheFallbackWhenTheResolverFails(t *testing.T) {
	sessions, storage, resolver := liveSessions(t)
	cookie := loginCookie(t, sessions, storage, 7)
	resolver.resolveErr = errStoreDown

	h := sessions.Install(sessions.RequireWebSession(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the handler must not be reached when resolution failed")
	})))

	r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assertStatus(t, rec, http.StatusInternalServerError, "resolver down")
	var body types.ApiError
	decodeBody(t, rec, &body)
	if body.Code != "common.fallback" {
		t.Errorf("code = %q, want \"common.fallback\"", body.Code)
	}
}

// ---------------------------------------------------------------------------------------------
// respondSessionUnauthorized — App.kt:242-253
// ---------------------------------------------------------------------------------------------

// 🔒 THE PIN sessions.go's doc comment names. A row that merely ran past its deadline has
// `ended_reason IS NULL`, so WebEndedReason returns nil while the session id is very much present —
// and the Kotlin answers "expired", not "none". session.WireReason maps a nil ended-reason to
// "none", which is correct for ITS documented input and wrong here, so the sessionId check has to
// come first. Delegating the whole mapping to WireReason would turn the commonest failure of all —
// an idle timeout — into "you were never signed in", and the console would stop offering the
// "your session ran out, sign in again" path.
func TestChallengeReasonForLiveRowWithNoEndedReasonIsExpired(t *testing.T) {
	sessions, storage, resolver := liveSessions(t)
	delete(resolver.rows, 7) // past its deadline
	// endedReasons has no entry for 7, so WebEndedReason answers nil.

	r := requestWithIdentity(http.MethodGet, "/auth/me")
	r.AddCookie(loginCookie(t, sessions, storage, 7))
	if _, err := sessions.WebSession(r); err != nil {
		t.Fatalf("WebSession: %v", err)
	}

	rec := httptest.NewRecorder()
	sessions.RespondSessionUnauthorized(rec, r)

	var body SessionStatusError
	decodeBody(t, rec, &body)
	if body.Reason != session.WireReasonExpired {
		t.Errorf("reason = %q, want %q — a NULL ended_reason on a NAMED session is an expiry, not "+
			"'you were never signed in'", body.Reason, session.WireReasonExpired)
	}
}

func TestChallengeReasonIsNoneWhenTheRequestNamedNoSession(t *testing.T) {
	sessions, _, _ := liveSessions(t)
	r := requestWithIdentity(http.MethodGet, "/auth/me")
	if _, err := sessions.WebSession(r); err != nil {
		t.Fatalf("WebSession: %v", err)
	}

	rec := httptest.NewRecorder()
	sessions.RespondSessionUnauthorized(rec, r)

	var body SessionStatusError
	decodeBody(t, rec, &body)
	if body.Reason != session.WireReasonNone {
		t.Errorf("reason = %q, want %q", body.Reason, session.WireReasonNone)
	}
}

// 🔒 INV-A4-3 — the six stored ENDED_* reasons collapse to exactly four wire values, and the three
// surfaced ones are the three the console must explain differently. DEACTIVATED is deliberately NOT
// surfaced: an unauthenticated caller is never told that a specific account was deprovisioned. A
// port that leaked it would change the disclosure surface.
func TestChallengeCollapsesTheSixEndedReasonsToFour(t *testing.T) {
	for _, tc := range []struct {
		stored string
		want   string
	}{
		{session.EndedDisplaced, session.WireReasonDisplaced},
		{session.EndedDeviceBindMismatch, session.WireReasonBindMismatch},
		{session.EndedSignedOut, session.WireReasonExpired},
		{session.EndedDeactivated, session.WireReasonExpired},
		{session.EndedGroupRevoked, session.WireReasonExpired},
		{session.EndedIdpRejected, session.WireReasonExpired},
	} {
		t.Run(tc.stored, func(t *testing.T) {
			sessions, storage, resolver := liveSessions(t)
			delete(resolver.rows, 7)
			resolver.endedReasons[7] = tc.stored

			r := requestWithIdentity(http.MethodGet, "/auth/me")
			r.AddCookie(loginCookie(t, sessions, storage, 7))
			if _, err := sessions.WebSession(r); err != nil {
				t.Fatalf("WebSession: %v", err)
			}

			rec := httptest.NewRecorder()
			sessions.RespondSessionUnauthorized(rec, r)

			var body SessionStatusError
			decodeBody(t, rec, &body)
			if body.Reason != tc.want {
				t.Errorf("reason for %s = %q, want %q", tc.stored, body.Reason, tc.want)
			}
			if body.Reason == tc.stored {
				t.Errorf("the stored reason %q reached the wire verbatim; only the four-value "+
					"vocabulary may (INV-A4-3)", tc.stored)
			}
		})
	}
}

// A failed ended-reason LOOKUP must not upgrade the answer to "none" — the session id is still
// evidence that a session existed. "expired" is the fail-safe default the Kotlin's `else` arm gives.
func TestChallengeFallsBackToExpiredWhenTheEndedReasonLookupFails(t *testing.T) {
	sessions, storage, resolver := liveSessions(t)
	delete(resolver.rows, 7)

	r := requestWithIdentity(http.MethodGet, "/auth/me")
	r.AddCookie(loginCookie(t, sessions, storage, 7))
	if _, err := sessions.WebSession(r); err != nil {
		t.Fatalf("WebSession: %v", err)
	}
	sessions.Resolver = &erroringReasonResolver{fakeResolver: resolver}

	rec := httptest.NewRecorder()
	sessions.RespondSessionUnauthorized(rec, r)

	var body SessionStatusError
	decodeBody(t, rec, &body)
	if body.Reason != session.WireReasonExpired {
		t.Errorf("reason = %q, want %q", body.Reason, session.WireReasonExpired)
	}
}

type erroringReasonResolver struct{ *fakeResolver }

func (e *erroringReasonResolver) WebEndedReason(context.Context, int64) (*string, error) {
	return nil, errStoreDown
}

// A cached 401 would keep a re-authenticated tab looking signed out until the browser decided
// otherwise — which is indistinguishable, to the user, from the login being broken.
func TestChallengeIsAlwaysNoStore(t *testing.T) {
	sessions, _, _ := liveSessions(t)
	rec := httptest.NewRecorder()
	sessions.RespondSessionUnauthorized(rec, requestWithIdentity(http.MethodGet, "/auth/me"))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	assertStatus(t, rec, http.StatusUnauthorized, "challenge")
}
