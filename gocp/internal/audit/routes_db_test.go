package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `/api/audit` and `/api/audit/{id}` — 08-audit.md §3.
//
// ORACLE: 08-audit.md §3's two-row route table (:150-155) and §4's `AuditReadRoutesDbTest.kt`
// (7 cases, :175-186). read_db_test.go already ports the four cases that are about the VISIBILITY
// MODEL — it drives [Reader] directly, over a real Cedar engine and the shipped seed policies. What
// is left, and what this file owns, are the three cases that are only observable through HTTP:
//
//	case 1  🔒 unauthenticated non-debug list is rejected without authorization
//	case 3     non-numeric audit id is a bad id, NOT a lookup
//	case 4     the old decisions route is removed        ← a NEGATIVE route test
//
// plus the `limit` coercion bounds that 08-audit.md §4 lists as a COVERAGE GAP ("`limit` coercion
// bounds (`0`, `-1`, `501`, non-numeric) on `/api/audit`"), which are reachable only from a URL.
//
// The Cedar layer is the REAL one — dbtest's DBPolicyStore over the seeded `policy` table, exactly as
// read_db_test.go builds it. A stubbed decision would prove the handler called something; the point
// of INV-A8-6 and INV-A8-7 is WHICH SHIPPED POLICY answers.
// ---------------------------------------------------------------------------------------------

// routeFixture is readFixture plus the HTTP surface: the plugin stack, the two session seams, and
// the mounted route group.
type routeFixture struct {
	*readFixture
	handler  http.Handler
	sessions *httpapi.Sessions
	storage  *fakeStorage
	resolver *fakeResolver
	cfg      config.Config
}

// newRouteFixture wires [Routes] over the SAME reader read_db_test.go tests, at the requested
// AuthDebug setting.
//
// ⚠️ AuthDebug is passed to BOTH httpapi.Gates (through Config) and [Reader]. They are two fields and
// nothing enforces agreement — see TestTheGateAndTheReaderMustAgreeAboutAuthDebug for what a
// disagreement produces and why the app wiring must pass one value to both.
func newRouteFixture(t *testing.T, authDebug bool) *routeFixture {
	t.Helper()
	rf := newReadFixture(t)

	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = authDebug
	cfg.SecretToken = nil
	cfg.SessionSecret = "audit-route-test-session-secret-32b"
	cfg.OIDC = nil
	cfg.ResultKey = nil
	cfg.ScimToken = nil
	cfg.TrustedProxies = map[string]struct{}{}

	storage := newFakeStorage()
	resolver := newFakeResolver()
	sessions := &httpapi.Sessions{
		Codec:           session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		Storage:         storage,
		Resolver:        resolver,
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
	}
	gates := &httpapi.Gates{Config: cfg, Authz: rf.authz, Sessions: sessions}

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(NewRoutes(gates, rf.reader(authDebug), nil))

	return &routeFixture{
		readFixture: rf, handler: router.Handler(), sessions: sessions,
		storage: storage, resolver: resolver, cfg: cfg,
	}
}

func (f *routeFixture) login(principal string) *http.Cookie {
	f.t.Helper()
	const id int64 = 11
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

func (f *routeFixture) get(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

// ---- The gate --------------------------------------------------------------------------------

// 🔒 `AuditReadRoutesDbTest` case 1 — "unauthenticated non-debug list is rejected WITHOUT
// authorization".
//
// Both halves are asserted. The 401 is the easy one; the one that matters is that the ROLE SOURCE WAS
// NEVER CONSULTED — requireApi rejects before any principal exists, so nothing about the deployment's
// policy set can be probed by an unauthenticated caller. The Kotlin uses the same counting role
// source for exactly this.
//
// KT: AuditReadRoutesDbTest.kt#unauthenticated non-debug list is rejected without authorization
func TestUnauthenticatedAuditReadsAreRejectedWithoutAuthorization(t *testing.T) {
	f := newRouteFixture(t, false)
	f.roles.reset()

	for _, target := range []string{"/api/audit", "/api/audit/" + strconv.FormatInt(f.aliceIDs[0], 10)} {
		t.Run(target, func(t *testing.T) {
			f.roles.reset()
			rec := f.get(target)

			assertStatus(t, rec, http.StatusUnauthorized, "no session")
			var body types.ApiError
			decodeJSON(t, rec, &body)
			if body.Code != "common.unauthenticated" {
				t.Errorf("code: got %q, want \"common.unauthenticated\"", body.Code)
			}
			if got := f.roles.count(); got != 0 {
				t.Errorf("authorization was attempted %d times for an unauthenticated request", got)
			}
		})
	}
}

// 🔒 requireApi, NOT requireAdmin — 08-audit.md §3. An ordinary principal with no audit grant gets
// 200, not 403, because the two-tier visibility model happens INSIDE the handler.
//
// This is the route-level statement of INV-A8-7: "a denied collection read DEGRADES to own-rows, it
// does not 403." A port that gated the routes on `admin.*` would take away every ordinary user's view
// of what was decided about them.
func TestAnOrdinaryPrincipalGets200AndOnlyOwnRows(t *testing.T) {
	f := newRouteFixture(t, false)

	rec := f.get("/api/audit", f.login(readAlice))

	assertStatus(t, rec, http.StatusOK, "ordinary principal")
	var events []types.AuditEvent
	decodeJSON(t, rec, &events)
	if len(events) == 0 {
		t.Fatal("an ordinary principal must still see their OWN rows (INV-A8-7)")
	}
	for _, e := range events {
		if e.Principal != readAlice {
			t.Errorf("a denied collection read leaked %s's row to %s", e.Principal, readAlice)
		}
	}
}

// The other tier: the seeded `audit.read-admin` policy (V8 -5) gives system:admin the whole log, and
// the fixture assigns that role to readAuditor.
func TestAnAuditorGetsTheWholeLogThroughTheRoute(t *testing.T) {
	f := newRouteFixture(t, false)

	rec := f.get("/api/audit", f.login(readAuditor))

	assertStatus(t, rec, http.StatusOK, "auditor")
	var events []types.AuditEvent
	decodeJSON(t, rec, &events)
	if len(events) != len(f.allIDs()) {
		t.Errorf("auditor saw %d rows, want the whole log (%d)", len(events), len(f.allIDs()))
	}
}

// 🔒 INV-A8-8 — the debug bypass short-circuits BEFORE any session resolution, mirroring requireApi.
// A debug request with NO COOKIE AT ALL reads the whole log — and the same is true of the DETAIL route,
// which is a SEPARATE handler with its own RequireAPI call (routes.go:99 and :138). The Kotlin case
// asserts both halves with no login in the client; asserting only the collection would leave a port
// that gated `/api/audit/{id}` on a session passing.
//
// KT: AuditReadRoutesDbTest.kt#auth debug returns all rows and details without authorization or a session — route half: "without a session" is only assertable here
func TestAuthDebugReadsTheWholeLogWithNoSession(t *testing.T) {
	f := newRouteFixture(t, true)
	f.roles.reset()

	rec := f.get("/api/audit")

	assertStatus(t, rec, http.StatusOK, "authDebug, no session")
	var events []types.AuditEvent
	decodeJSON(t, rec, &events)
	// The exact ID SET, not just the count: a feed that returned the right NUMBER of rows from the
	// wrong scope would satisfy a count.
	assertIDSet(t, events, f.allIDs())
	// ...and the lifecycle row keeps its `kind` through the route's serialization, which is the field
	// the console branches on to render it as something other than a query decision.
	if got := findByID(t, events, f.e3ID).Kind; got != "approval_lifecycle" {
		t.Errorf("the debug feed rendered the lifecycle row's kind as %q, want approval_lifecycle", got)
	}
	if got := f.roles.count(); got != 0 {
		t.Errorf("the bypass must PREVENT Cedar from being reached, not skip it; %d role lookups", got)
	}

	// The DETAIL half, still with no cookie: bob's record is readable by a caller who has no identity
	// at all, and Cedar is not reached for it either.
	f.roles.reset()
	detail := f.get("/api/audit/" + strconv.FormatInt(f.bobIDs[0], 10))
	assertStatus(t, detail, http.StatusOK, "authDebug detail, no session")
	var event types.AuditEvent
	decodeJSON(t, detail, &event)
	if event.Principal != readBob {
		t.Errorf("the debug detail returned principal %q, want %q", event.Principal, readBob)
	}
	if event.ID == nil || *event.ID != f.bobIDs[0] {
		t.Errorf("the debug detail returned id %v, want %d", event.ID, f.bobIDs[0])
	}
	if got := f.roles.count(); got != 0 {
		t.Errorf("the debug DETAIL reached authorization %d times; the bypass must precede it", got)
	}
}

// ---- GET /api/audit/{id} ----------------------------------------------------------------------

// 🔒 `AuditReadRoutesDbTest` case 3 — "non-numeric audit id is a BAD ID, NOT A LOOKUP".
//
// Two claims, and the second is the interesting one: the 400 answers BEFORE the store is touched, so
// `/api/audit/abc` never costs a query and never reaches Cedar. Asserting only the status would pass
// for an implementation that looked the row up first and then noticed.
//
// KT: AuditReadRoutesDbTest.kt#non-numeric audit id is a bad id, not a lookup
func TestANonNumericAuditIdIsABadIdAndNeverALookup(t *testing.T) {
	f := newRouteFixture(t, false)
	f.roles.reset()

	rec := f.get("/api/audit/abc", f.login(readAlice))

	assertStatus(t, rec, http.StatusBadRequest, "non-numeric id")
	var body types.ApiError
	decodeJSON(t, rec, &body)
	if body.Code != "common.bad_id" {
		t.Errorf("code: got %q, want \"common.bad_id\"", body.Code)
	}
	if got := f.roles.count(); got != 0 {
		t.Errorf("a bad id must not reach authorization; %d role lookups", got)
	}
}

// 🔒 INV-A8-6 — DENIED AND MISSING ARE DELIBERATELY INDISTINGUISHABLE, and this asserts it at the
// level a caller actually sees: the STATUS AND THE RESPONSE BYTES ARE IDENTICAL.
//
// read_db_test.go proves the Reader returns (nil, nil) for both. What HTTP adds is the possibility of
// leaking the difference anyway — a different status, a different `resource` param, a header, a
// length. Comparing whole recorded responses is the only assertion that covers all of those at once.
//
// All four of the Kotlin case's claims are asserted here, at the HTTP layer, in its order:
//
//  1. the own-rows LIST — 200, exactly alice's ids (her two queries plus the lifecycle row she
//     authored), every row hers, and exactly ONE collection authorization;
//  2. her OWN detail — 200, her principal, one authorization;
//  3. bob's detail — 404 common.not_found{resource}, one authorization;
//  4. a nonexistent id — the SAME status and the SAME body bytes, and ZERO authorizations, i.e. a
//     missing row must not even reach Cedar.
//
// read_db_test.go's TestOrdinaryPrincipalSeesOnlyOwnRowsAndDeniedDetailLooksMissing makes the same
// four claims against [Reader]; this restates them through the route, where the byte-identity of the
// two 404s and the lookup counts of the real gate stack are observable.
//
// KT: AuditReadRoutesDbTest.kt#ordinary principal sees only own rows and denied detail is indistinguishable from missing — route half: the Kotlin compares the two 404 BODIES, which only the HTTP layer can do
func TestADeniedAuditRecordIsByteIdenticalToAMissingOne(t *testing.T) {
	f := newRouteFixture(t, false)
	cookie := f.login(readAlice)

	// (1) The denied COLLECTION read degrades to own rows — 200, not 403 (INV-A8-7) — and costs
	// exactly one authorization however many rows come back.
	f.roles.reset()
	list := f.get("/api/audit?limit=500", cookie)
	assertStatus(t, list, http.StatusOK, "own-rows list")
	var records []types.AuditEvent
	decodeJSON(t, list, &records)
	assertIDSet(t, records, append(append([]int64{}, f.aliceIDs...), f.e3ID))
	for _, rec := range records {
		if rec.Principal != readAlice {
			t.Errorf("the own-rows feed leaked a row owned by %s", rec.Principal)
		}
	}
	if got := f.roles.count(); got != 1 {
		t.Errorf("the list made %d authorizations, want exactly 1 collection authorization", got)
	}

	// (2) Her own DETAIL read is allowed by the shipped `audit.read-own` policy, in one authorization.
	f.roles.reset()
	own := f.get("/api/audit/"+strconv.FormatInt(f.aliceIDs[0], 10), cookie)
	assertStatus(t, own, http.StatusOK, "own detail")
	var ownEvent types.AuditEvent
	decodeJSON(t, own, &ownEvent)
	if ownEvent.Principal != readAlice {
		t.Errorf("own detail principal: got %q, want %q", ownEvent.Principal, readAlice)
	}
	if got := f.roles.count(); got != 1 {
		t.Errorf("the own-row detail made %d authorizations, want 1", got)
	}

	// (3) Bob's row exists and alice may not see it — one authorization, which is what makes it a DENY
	// rather than a lookup miss.
	f.roles.reset()
	denied := f.get("/api/audit/"+strconv.FormatInt(f.bobIDs[0], 10), cookie)
	deniedLookups := f.roles.count()

	// (4) This id has never existed.
	f.roles.reset()
	missing := f.get("/api/audit/987654", cookie)
	missingLookups := f.roles.count()

	assertStatus(t, denied, http.StatusNotFound, "denied")
	assertStatus(t, missing, http.StatusNotFound, "missing")
	if denied.Body.String() != missing.Body.String() {
		t.Errorf("denied and missing must be byte-identical (INV-A8-6):\n denied  %s\n missing %s",
			denied.Body.String(), missing.Body.String())
	}
	var body types.ApiError
	decodeJSON(t, denied, &body)
	if body.Code != "common.not_found" || body.Params["resource"] != NotFoundResource {
		t.Errorf("body: got %+v, want common.not_found{resource: %q}", body, NotFoundResource)
	}
	// Header-level leakage too: a different Content-Length would answer the question the body refuses
	// to. (Equal bodies imply equal length, so this is really a guard on the whole header set.)
	if denied.Header().Get("Content-Type") != missing.Header().Get("Content-Type") {
		t.Error("the two answers must not differ in their headers either")
	}
	if deniedLookups != 1 {
		t.Errorf("the denied detail made %d authorizations, want 1", deniedLookups)
	}
	// The bodies being equal does not make the WORK equal: a missing row is answered before Cedar is
	// reached, so a caller cannot distinguish the two by timing or by policy-evaluation side effects
	// either.
	if missingLookups != 0 {
		t.Errorf("a missing row reached Cedar (%d lookups) — it must not", missingLookups)
	}
}

// A principal's OWN record is readable, by the shipped `audit.read-own` policy (V8 -4) comparing
// `resource.principal == principal`. The contrast that makes the case above meaningful.
func TestAPrincipalCanReadTheirOwnAuditRecord(t *testing.T) {
	f := newRouteFixture(t, false)

	rec := f.get("/api/audit/"+strconv.FormatInt(f.aliceIDs[0], 10), f.login(readAlice))

	assertStatus(t, rec, http.StatusOK, "own record")
	var event types.AuditEvent
	decodeJSON(t, rec, &event)
	if event.Principal != readAlice {
		t.Errorf("principal: got %q, want %q", event.Principal, readAlice)
	}
}

// ---- limit coercion, from a URL ---------------------------------------------------------------

// 08-audit.md §4 lists these as a COVERAGE GAP: "`limit` coercion bounds (`0`, `-1`, `501`,
// non-numeric) on `/api/audit`". canon_test.go's TestCoerceLimit covers the function; this covers the
// URL, which is where the two failures that matter live — a route that forgot to call CoerceLimit at
// all, and a route that passed `Get()` without `Has()` and so could not tell absent from empty.
func TestTheLimitQueryParameterIsCoercedFromTheURL(t *testing.T) {
	f := newRouteFixture(t, true) // authDebug: the whole log, so the row count is the limit's alone.

	for _, c := range []struct {
		query string
		want  int
		why   string
	}{
		{"?limit=1", 1, "an in-range limit is honoured"},
		{"?limit=0", 1, "coerceIn's floor: 0 clamps UP to 1, it does not read zero rows"},
		{"?limit=-1", 1, "the floor again, from below"},
		{"?limit=abc", len(f.allIDs()), "unparseable falls back to the default (100), which exceeds the fixture"},
		{"?limit=3000000000", len(f.allIDs()), "🔒 32-bit: Kotlin's toIntOrNull says NOT A NUMBER, so this is the DEFAULT (100) and not the 500 cap"},
		{"?limit=", len(f.allIDs()), "present but empty is unparseable, so the default"},
		{"", len(f.allIDs()), "absent is the default"},
	} {
		t.Run(c.query+" "+c.why, func(t *testing.T) {
			rec := f.get("/api/audit" + c.query)
			assertStatus(t, rec, http.StatusOK, "limit")
			var events []types.AuditEvent
			decodeJSON(t, rec, &events)
			if len(events) != c.want {
				t.Errorf("got %d rows, want %d — %s", len(events), c.want, c.why)
			}
		})
	}
}

// ---- shape -------------------------------------------------------------------------------------

// 🔒 INV-A1-4 — an empty feed is `[]`, never `null`. The console renders `.length` on it.
//
// routes.go normalises explicitly rather than relying on the store, because a nil slice is what a Go
// query helper returns for no rows and `null` is a different shape from `[]` to every JSON consumer.
func TestAnEmptyAuditFeedIsAnEmptyArrayNotNull(t *testing.T) {
	f := newRouteFixture(t, false)

	// A principal with no rows of their own, denied the collection: own-rows, of which there are none.
	rec := f.get("/api/audit", f.login("nobody@example.com"))

	assertStatus(t, rec, http.StatusOK, "empty feed")
	if got := strings.TrimSpace(rec.Body.String()); got != `[]` {
		t.Errorf("body: got %s, want []", got)
	}
}

// ---- the negative route ------------------------------------------------------------------------

// `AuditReadRoutesDbTest` case 4 — "old decisions route is removed".
//
// ⚠️ THIS IS A NEGATIVE ROUTE TEST and routes.go:60-63 names it by exactly this name. It is easy to
// lose in a port precisely because nothing fails when a route is absent: the assertion has to be
// written on purpose, or the day someone re-adds `/api/decisions` as a convenience nobody notices
// that a retired surface came back.
// KT: AuditReadRoutesDbTest.kt#old decisions route is removed
func TestOldDecisionsRouteStaysRemoved(t *testing.T) {
	f := newRouteFixture(t, true) // authDebug, so a live route would answer 200 rather than 401.

	for _, target := range []string{"/api/decisions", "/api/decisions/1"} {
		t.Run(target, func(t *testing.T) {
			rec := f.get(target)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s answered %d; the retired decisions route must stay removed", target, rec.Code)
			}
		})
	}
}

// ---- the two AuthDebug fields --------------------------------------------------------------------

// ⚠️ FINDING, recorded rather than fixed: `AuthDebug` is carried TWICE on this surface — by
// httpapi.Gates (through Config) and by [Reader] — and NOTHING enforces that they agree.
//
// routes.go:46-48 claims the opposite: "The Reader carries AuthDebug itself (INV-A8-8), so this type
// never reads config: the two places that could disagree about whether the bypass is on are collapsed
// into one." That is true of `Routes` in isolation and NOT true of the wiring: `Routes` reads only the
// Reader's copy, but the GATE in front of it reads Config's.
//
// This test measures what a disagreement actually produces, so the hazard is a known quantity rather
// than a guess: gate ON + reader OFF admits a sessionless request that the reader then cannot serve,
// and the handler answers 500 common.fallback carrying the Kotlin's postcondition message. It is
// fail-closed (no data leaks) but it is a 500 on a live surface.
//
// The other direction — gate OFF + reader ON — is harmless: requireApi demands a session, and the
// reader then ignores the principal it was given.
//
// internal/app is where the two are set, and TestAuditRoutesGetOneAuthDebugValue there asserts the
// wiring passes one value to both.
func TestTheGateAndTheReaderMustAgreeAboutAuthDebug(t *testing.T) {
	rf := newReadFixture(t)

	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.SessionSecret = "audit-route-test-session-secret-32b"
	cfg.TrustedProxies = map[string]struct{}{}
	cfg.AuthDebug = true // the GATE bypasses…

	sessions := &httpapi.Sessions{
		Codec:           session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		Storage:         newFakeStorage(),
		Resolver:        newFakeResolver(),
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
	}
	gates := &httpapi.Gates{Config: cfg, Authz: rf.authz, Sessions: sessions}
	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(NewRoutes(gates, rf.reader(false), nil)) // …but the READER does not.

	rec := httptest.NewRecorder()
	router.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/audit", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("a disagreeing pair answers the StatusPages fallback; got %d (%s)", rec.Code, rec.Body.String())
	}
	var body types.ApiError
	decodeJSON(t, rec, &body)
	if body.Code != "common.fallback" {
		t.Errorf("code: got %q, want \"common.fallback\"", body.Code)
	}
	t.Log("RECORDED: AuthDebug is carried twice on this surface and nothing enforces agreement. " +
		"Fail-closed (no rows are served) but a 500. internal/app must pass one value to both.")
}

// ---- fakes and helpers ---------------------------------------------------------------------------

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
