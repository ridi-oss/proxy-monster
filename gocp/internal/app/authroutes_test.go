package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
)

// ============================================================================================
// A1's auth routes, CONTAINER-FREE half.
//
// Everything here is driven through the real [httpapi.Router] stack (CallLogging → StatusPages →
// Sessions.Install → mux), because the routes' contract includes things the stack owns: the
// per-request identity cache the WEB_SESSION_AUTH wrapper reads, and the fallback body a panicking
// handler produces. Calling a handler function directly would test a different thing.
//
// The two session seams are faked exactly as internal/httpapi's own suites fake them — the SQL
// behind them is proved by internal/session's DB suites, and faking here is what lets these cases
// drive the failure modes (an unknown tracker key, a store that is down) that are awkward to stage
// against a real row. The routes that CANNOT be faked — anything reaching mintWeb, touchWeb or
// replaceDirectRoles — are in authroutes_db_test.go against a real container.
// ============================================================================================

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

// authTestConfig is the Go form of `Config.fromEnv { null }` for the route suites: the shipped
// defaults, with the two fields every case must be explicit about.
//
// PM_AUTH_DEBUG DEFAULTS TO TRUE, so `authDebug` is named at every call site rather than inherited —
// a suite that silently ran under the bypass would assert nothing about the gates.
func authTestConfig(authDebug bool) config.Config {
	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL, cfg.DBUser, cfg.DBPassword = "", "", ""
	cfg.AuthDebug = authDebug
	cfg.DevMarker = true
	cfg.SessionSecret = "auth-route-test-session-secret-32ch"
	cfg.SessionWindowSeconds = 3600
	cfg.IdpRecheckIntervalSeconds = 600
	cfg.TrustedProxies = map[string]struct{}{}
	return cfg
}

// fakeStorage is the tracker-id ↔ row seam (httpapi.SessionStorage).
type fakeStorage struct {
	keys  map[string]int64
	ended []string
}

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
	f.ended = append(f.ended, key)
	return nil
}

// fakeResolver is the liveness + device-binding seam (httpapi.WebSessionResolver).
type fakeResolver struct {
	rows         map[int64]*session.WebRow
	endedReasons map[int64]string
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{rows: map[int64]*session.WebRow{}, endedReasons: map[int64]string{}}
}

func (f *fakeResolver) ResolveWeb(_ context.Context, id int64, _ *string) (*session.WebRow, error) {
	return f.rows[id], nil
}

func (f *fakeResolver) WebEndedReason(_ context.Context, id int64) (*string, error) {
	reason, ok := f.endedReasons[id]
	if !ok {
		return nil, nil
	}
	return &reason, nil
}

// recordingAuthorizer counts and captures what was asked of Cedar, so a test can assert on WHETHER
// it was asked at all — which is INV-A2-16's actual claim, and computeMePermissions' too.
type recordingAuthorizer struct {
	calls  []authz.AuthzAction
	ctxs   []authz.AuthzContext
	allow  map[authz.AuthzAction]bool
	reason string
}

func (a *recordingAuthorizer) Authorize(
	_ string, action authz.AuthzAction, _ authz.AuthzResource, ctx authz.AuthzContext,
) authz.AuthzDecision {
	a.calls = append(a.calls, action)
	a.ctxs = append(a.ctxs, ctx)
	if a.allow[action] {
		return authz.AuthzDecision{Allowed: true}
	}
	return authz.Deny(a.reason)
}

// unusedPolicyStore is `MePermissionsUnusedDataSource` (MePermissionsRouteTest.kt:223-235): a
// sentinel proving the inline-policy engine never consults a store. Any call is a bug in the fixture.
type unusedPolicyStore struct{ t *testing.T }

func (s unusedPolicyStore) EnabledSources() []authz.PolicySource {
	s.t.Fatal("the inline-policy engine must not query its Cedar policy store")
	return nil
}
func (s unusedPolicyStore) StateVersion() int64 { return 0 }

// authFixture is one wired route group plus the handles a case needs to drive it.
type authFixture struct {
	cfg      config.Config
	handler  http.Handler
	sessions *httpapi.Sessions
	storage  *fakeStorage
	resolver *fakeResolver
	gates    *httpapi.Gates
}

// newAuthFixture builds the routes over the fakes and the REAL plugin stack.
//
// `store` is deliberately left nil: every route that dereferences it (debug login's mint,
// heartbeat's touch) is a DB case and lives in the other file. A nil-pointer panic here would be
// this fixture being used for the wrong test, and StatusPages turns it into a visible 500 rather
// than a hang.
func newAuthFixture(t *testing.T, cfg config.Config, az httpapi.Authorizer) *authFixture {
	t.Helper()
	storage := newFakeStorage()
	resolver := newFakeResolver()
	sessions := &httpapi.Sessions{
		Codec:           session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		Storage:         storage,
		Resolver:        resolver,
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
	}
	gates := &httpapi.Gates{Config: cfg, Authz: az, Sessions: sessions}
	rt := &authRoutes{
		config:   cfg,
		gates:    gates,
		sessions: sessions,
		authz:    az,
		roles:    fakeRoles{},
		// 🔒 INV-A1-7's arbiter is the CEDAR ENGINE, not a regex, so the fixture wires the REAL
		// probe rather than a stub. A zero-value Authz is enough — EvaluatesInCedar touches no policy
		// store (internal/httpapi/storableip_test.go relies on the same fact). Stubbing it "true"
		// would make the 400 case below pass against a route that had lost the engine half entirely.
		evaluatesInCedar: (&authz.Authz{}).EvaluatesInCedar,
	}
	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(rt)
	return &authFixture{
		cfg: cfg, handler: router.Handler(), sessions: sessions,
		storage: storage, resolver: resolver, gates: gates,
	}
}

type fakeRoles struct{ byPrincipal map[string][]string }

func (f fakeRoles) Resolve(_ context.Context, principal string) ([]string, error) {
	return f.byPrincipal[principal], nil
}

// login seats a live row and returns the cookie a browser would send for it.
func (f *authFixture) login(t *testing.T, id int64, principal string) *http.Cookie {
	t.Helper()
	now := time.Now().UTC()
	f.resolver.rows[id] = &session.WebRow{
		ID: id, Principal: principal, CreatedAt: now, Now: now,
		IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	}
	rec := httptest.NewRecorder()
	if err := f.sessions.SetWebSession(context.Background(), rec, id); err != nil {
		t.Fatalf("SetWebSession: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.SessionCookie {
			return c
		}
	}
	t.Fatalf("no %s cookie was written", session.SessionCookie)
	return nil
}

// do runs one request through the full stack.
func (f *authFixture) do(method, target string, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------------------------
// normalizeDuration — App.kt:228-232
// ---------------------------------------------------------------------------------------------

// TestNormalizeDurationPicksTheLargestEXACTLY-dividing unit, and never falls back through units.
//
// The 5400 row is the REDUCED form of `auth config normalizes a mixed-unit absolute cap to minutes`
// (WebSessionRoutesDbTest.kt:124-136): 5400s must render as 90 MINUTES, not 1.5 hours and not "1 hour
// 30 minutes". It deliberately carries no coverage marker — the Kotlin case also asserts that
// `PM_WEB_SESSION_ABSOLUTE=1h30m` PARSES to 5400 and that /auth/config renders it, neither of which a
// pure-function table can see. The marker therefore lives on
// TestAuthConfigNormalizesAMixedUnitAbsoluteCapToMinutes, which drives env → config → route.
func TestNormalizeDurationPicksTheLargestExactlyDividingUnit(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		amount  int64
		unit    string
		why     string
	}{
		{7200, 2, "hours", "the default absolute window — WebSessionRoutesDbTest.kt:116"},
		{5400, 90, "minutes", "1h30m: 5400 % 3600 != 0, so the hours arm is SKIPPED ENTIRELY"},
		{3600, 1, "hours", "the boundary from below"},
		{900, 15, "minutes", "the default idle window"},
		{120, 2, "minutes", "the smallest multi-unit value that is still whole minutes"},
		{90, 90, "seconds", "the DEFAULT HEARTBEAT: 90 % 60 = 30, so it is SECONDS, not 1.5 minutes"},
		{91, 91, "seconds", "no exact unit"},
		{1, 1, "seconds", ""},
		{0, 0, "hours", "⚠️ 0 % 3600 == 0 takes the FIRST arm. Unreachable — parseDuration rejects it"},
	} {
		got := normalizeDuration(tc.seconds)
		if got.amount != tc.amount || got.unit != tc.unit {
			t.Errorf("normalizeDuration(%d) = {%d %s}, want {%d %s} (%s)",
				tc.seconds, got.amount, got.unit, tc.amount, tc.unit, tc.why)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// GET /auth/config — App.kt:581-596
// ---------------------------------------------------------------------------------------------

// TestAuthConfigExposesDefaultSessionUxTimings is `auth config exposes default session UX timings`
// (WebSessionRoutesDbTest.kt:97-121), the FULL struct equality it asserts.
//
// ⚠️ `authDebug: true` in the expected body is not incidental: the Kotlin builds this case from
// `Config.fromEnv { null }`, i.e. every default, and PM_AUTH_DEBUG's default is TRUE. The console
// renders its debug login form from this field.
// KT: WebSessionRoutesDbTest.kt#auth config exposes default session UX timings
func TestAuthConfigExposesDefaultSessionUxTimings(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)

	rec := f.do(http.MethodGet, "/auth/config", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got AuthConfigResponse
	decodeInto(t, rec, &got)

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
}

// TestAuthConfigNormalizesAMixedUnitAbsoluteCapToMinutes is WebSessionRoutesDbTest.kt:124-136 in full:
// the Kotlin builds its Config from an env reader answering `PM_WEB_SESSION_ABSOLUTE=1h30m`, boots the
// module, and asserts /auth/config reports `absoluteCapAmount = 90` and `absoluteCapUnit = "minutes"`.
// All three links are here — the env parse, the route, and the two rendered fields.
// KT: WebSessionRoutesDbTest.kt#auth config normalizes a mixed-unit absolute cap to minutes
func TestAuthConfigNormalizesAMixedUnitAbsoluteCapToMinutes(t *testing.T) {
	cfg, err := config.FromEnv(config.EnvOf(map[string]string{
		"PM_WEB_SESSION_ABSOLUTE": "1h30m",
		"PM_DEV":                  "true",
	}))
	if err != nil {
		t.Fatalf("config rejected: %v", err)
	}
	f := newAuthFixture(t, cfg, nil)

	var got AuthConfigResponse
	decodeInto(t, f.do(http.MethodGet, "/auth/config", ""), &got)
	if got.Session.AbsoluteCapAmount != 90 || got.Session.AbsoluteCapUnit != "minutes" {
		t.Errorf("absoluteCap = %d %s, want 90 minutes",
			got.Session.AbsoluteCapAmount, got.Session.AbsoluteCapUnit)
	}
}

// TestAuthConfigIsPublic pins that /auth/config calls NO gate — it is the one route the login shell
// reaches before it can authenticate anything, so a gate here is a deployment nobody can log into.
//
// Asserted with the bypass OFF and an Authorizer that fails the test if consulted, so "public" means
// "no session and no Cedar decision", not "authDebug let it through".
func TestAuthConfigIsPublic(t *testing.T) {
	az := &recordingAuthorizer{allow: map[authz.AuthzAction]bool{}}
	f := newAuthFixture(t, authTestConfig(false), az)

	rec := f.do(http.MethodGet, "/auth/config", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — /auth/config must be reachable with no session", rec.Code)
	}
	if len(az.calls) != 0 {
		t.Errorf("Cedar was consulted %v for a public route", az.calls)
	}
}

// ---------------------------------------------------------------------------------------------
// GET /api/me/permissions — MePermissionsRouteTest, 7 cases (01-bootstrap.md §4)
// ---------------------------------------------------------------------------------------------

// mePermissionsPolicies is MePermissionsRouteTest.kt:49-55's five inline Cedar policies, verbatim.
var mePermissionsPolicies = []authz.PolicySource{
	{ID: 1, Src: `permit(principal in Role::"datasource-admin", action == Action::"admin.datasources", resource);`},
	{ID: 2, Src: `permit(principal in Role::"policy-admin", action == Action::"admin.policies", resource);`},
	{ID: 3, Src: `permit(principal in Role::"identity-admin", action == Action::"admin.identity", resource);`},
	{ID: 4, Src: `permit(principal, action == Action::"audit.read", resource) when { resource is AuditRecord && resource.principal == principal };`},
	{ID: 5, Src: `permit(principal in Role::"auditor", action == Action::"audit.read", resource);`},
}

// mePermissionsRoles is MePermissionsRouteTest.kt:57-62's principal → roles map.
var mePermissionsRoles = map[string][]string{
	"datasource-only": {"datasource-admin"},
	"policy-only":     {"policy-admin"},
	"identity-only":   {"identity-admin"},
	"auditor-only":    {"auditor"},
}

// mePermissionsAuthz is `private fun authz(): Authz` — the REAL Cedar engine over those five
// policies. Container-free, unlike the Kotlin, which needed a database only for the CedarPolicyStore
// it then never queries; [unusedPolicyStore] is that sentinel here.
func mePermissionsAuthz(t *testing.T) *authz.Authz {
	t.Helper()
	engine, err := authz.NewCedarEngineFromSources(mePermissionsPolicies)
	if err != nil {
		t.Fatalf("NewCedarEngineFromSources: %v", err)
	}
	return authz.New(engine, unusedPolicyStore{t: t}, authz.RoleSourceFunc(func(p string) []string {
		return mePermissionsRoles[p]
	}))
}

// TestMePermissionsRequiresASessionWhenNotInDebug is MePermissionsRouteTest case 1.
//
// requireApi's 401, not the WEB_SESSION challenge: this route is behind requireApi, so the body is
// an ApiError (`common.unauthenticated`), NOT a SessionStatusError. The two 401s look identical in a
// status-only assertion and the console parses them differently.
// KT: MePermissionsRouteTest.kt#non-debug requests require a session
func TestMePermissionsRequiresASessionWhenNotInDebug(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(false), mePermissionsAuthz(t))

	rec := f.do(http.MethodGet, "/api/me/permissions", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Code   string            `json:"code"`
		Params map[string]string `json:"params"`
	}
	decodeInto(t, rec, &body)
	if body.Code != "common.unauthenticated" {
		t.Errorf("code = %q, want common.unauthenticated — this route is requireApi-gated, so the "+
			"401 body is an ApiError and not a SessionStatusError", body.Code)
	}
}

// TestMePermissionsUnderAuthDebugReturnsEverythingWithoutASession is MePermissionsRouteTest case 2.
//
// 🔒 The KEY SET is asserted, not just the values: `assertEquals(setOf("isAdmin","canReadAllAudit",
// "canApprove"), payload.keys)`. A fourth capability appearing on the wire has to be a deliberate
// edit to this test.
//
// 🔒 And Cedar must NOT be consulted — INV-A2-16's shape: the bypass prevents Cedar from being
// reached, it does not teach Cedar to allow.
// KT: MePermissionsRouteTest.kt#auth debug returns all capabilities without a session
func TestMePermissionsUnderAuthDebugReturnsEverythingWithoutASession(t *testing.T) {
	az := &recordingAuthorizer{allow: map[authz.AuthzAction]bool{}}
	f := newAuthFixture(t, authTestConfig(true), az)

	rec := f.do(http.MethodGet, "/api/me/permissions", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var keyed map[string]any
	decodeInto(t, rec, &keyed)
	if len(keyed) != 3 {
		t.Errorf("payload keys = %v, want exactly {isAdmin, canReadAllAudit, canApprove}", keyed)
	}
	for _, k := range []string{"isAdmin", "canReadAllAudit", "canApprove"} {
		if v, ok := keyed[k]; !ok || v != true {
			t.Errorf("%s = %v (present=%v), want true", k, v, ok)
		}
	}
	if len(az.calls) != 0 {
		t.Errorf("Cedar was consulted %v under PM_AUTH_DEBUG; the bypass must PREVENT it being "+
			"reached, not make it allow", az.calls)
	}
}

// TestEachIndependentAdminActionGrantsAdminAndApproval is MePermissionsRouteTest case 3 —
// 🔒 the three admin domains are deliberately INDEPENDENT: any ONE of them exposes the shared admin
// area, while audit collection access stays a separate capability.
// KT: MePermissionsRouteTest.kt#each independent admin action grants admin and approval but not audit collection access
func TestEachIndependentAdminActionGrantsAdminAndApproval(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(false), mePermissionsAuthz(t))

	for i, principal := range []string{"datasource-only", "policy-only", "identity-only"} {
		cookie := f.login(t, int64(100+i), principal)
		var got MePermissions
		rec := f.do(http.MethodGet, "/api/me/permissions", "", cookie)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 (body %s)", principal, rec.Code, rec.Body.String())
		}
		decodeInto(t, rec, &got)
		want := MePermissions{IsAdmin: true, CanReadAllAudit: false, CanApprove: true}
		if got != want {
			t.Errorf("%s: %+v, want %+v", principal, got, want)
		}
	}
}

// TestAuditorReadsTheAuditCollectionWithoutAdminOrApproval is MePermissionsRouteTest case 4 — the
// other half of the independence: audit.read on the AuditLog collection is NOT an admin capability.
// KT: MePermissionsRouteTest.kt#auditor can read the audit collection without admin or approval capabilities
func TestAuditorReadsTheAuditCollectionWithoutAdminOrApproval(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(false), mePermissionsAuthz(t))
	cookie := f.login(t, 200, "auditor-only")

	var got MePermissions
	rec := f.do(http.MethodGet, "/api/me/permissions", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	decodeInto(t, rec, &got)
	want := MePermissions{IsAdmin: false, CanReadAllAudit: true, CanApprove: false}
	if got != want {
		t.Errorf("%+v, want %+v", got, want)
	}
}

// TestOrdinaryPrincipalHasNoCoarseCapabilities is MePermissionsRouteTest case 7.
//
// ⚠️ Policy 4 (`audit.read` when `resource is AuditRecord && resource.principal == principal`) is in
// the fixture precisely so this case cannot pass by accident: a principal CAN read their OWN audit
// records, and `canReadAllAudit` must still be false because it asks about the AuditLog COLLECTION.
// An implementation that authorized against AuditRecord here would report true for everyone.
// KT: MePermissionsRouteTest.kt#ordinary principal has no coarse capabilities
func TestOrdinaryPrincipalHasNoCoarseCapabilities(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(false), mePermissionsAuthz(t))
	cookie := f.login(t, 300, "ordinary")

	var got MePermissions
	rec := f.do(http.MethodGet, "/api/me/permissions", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	decodeInto(t, rec, &got)
	if (got != MePermissions{}) {
		t.Errorf("%+v, want all false", got)
	}
}

// TestComputeMePermissionsAsksFourIndependentQuestions pins the SHAPE of the decision, which no
// outcome assertion can: four calls, in App.kt's order, and all three admin decisions made even when
// the first already allowed.
//
// 🔒 The last part is the one a Go port gets wrong for free. Kotlin assigns each decision to its own
// `val` and THEN ors them, so all three run; a Go `||` would short-circuit. Invisible today and a
// silent divergence the moment authorize gains an audit or metric side effect — which is exactly
// what an authorization decision tends to grow.
func TestComputeMePermissionsAsksFourIndependentQuestions(t *testing.T) {
	az := &recordingAuthorizer{allow: map[authz.AuthzAction]bool{
		// The FIRST admin domain allows, so a short-circuiting || would skip the other two.
		authz.ActionAdminDatasources: true,
	}}

	got := computeMePermissions("p", az, authz.AuthzContext{})

	want := []authz.AuthzAction{
		authz.ActionAdminDatasources, authz.ActionAdminPolicies,
		authz.ActionAdminIdentity, authz.ActionAuditRead,
	}
	if len(az.calls) != len(want) {
		t.Fatalf("Cedar was asked %v; want exactly %v — all three admin decisions are made even when "+
			"the first allows (App.kt:258-276 assigns each to its own val before OR-ing)", az.calls, want)
	}
	for i := range want {
		if az.calls[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, az.calls[i], want[i])
		}
	}
	if !got.IsAdmin || !got.CanApprove {
		t.Errorf("%+v: one permitted admin domain must grant isAdmin and canApprove", got)
	}
	if got.CanReadAllAudit {
		t.Error("canReadAllAudit must stay false — it is a separate, fourth decision")
	}
}

// TestCanApproveTracksIsAdminExactly pins the KNOWN APPROXIMATION as an approximation.
//
// ⚠️ `canApprove = isAdmin` is not a bug and must not be "fixed" into a task.approve decision: App.kt:287
// records that `task.approve` is REQUEST-SCOPED, so there is no honest coarse System check to make.
// The real gate is per-request in A7. If this ever diverges from isAdmin, someone has invented a
// coarse approval check — which is a behaviour change needing its own oracle.
func TestCanApproveTracksIsAdminExactly(t *testing.T) {
	for _, action := range []authz.AuthzAction{
		authz.ActionAdminDatasources, authz.ActionAdminPolicies, authz.ActionAdminIdentity,
	} {
		got := computeMePermissions("p", &recordingAuthorizer{
			allow: map[authz.AuthzAction]bool{action: true},
		}, authz.AuthzContext{})
		if got.CanApprove != got.IsAdmin {
			t.Errorf("%s: canApprove=%v isAdmin=%v — they must be the same value", action, got.CanApprove, got.IsAdmin)
		}
	}
	// And an audit-only principal approves nothing.
	got := computeMePermissions("p", &recordingAuthorizer{
		allow: map[authz.AuthzAction]bool{authz.ActionAuditRead: true},
	}, authz.AuthzContext{})
	if got.CanApprove || got.IsAdmin {
		t.Errorf("%+v: audit.read alone grants neither admin nor approval", got)
	}
}

// TestMePermissionsThreadsTheGatesAuthzContextIntoTheDecision is MePermissionsRouteTest case 5's
// PORTABLE HALF (A12 INV-A12-1).
//
// The Kotlin case drives it end to end: a trusted edge, an X-Forwarded-For, and an ip-gated
// `admin.datasources` permit that fires only for `203.0.113.0/24`. A12's httpRequesterIp is NOT
// PORTED, so the resolver half cannot be exercised yet — but the property the case exists to pin at
// THIS route is that `computeMePermissions`' context argument is load-bearing and comes from the
// SHARED gate seam. That half is portable now, and pinning it is what stops A12 landing a resolver
// the route then ignores.
//
//	TODO(A12): replace the stub Context with the real httpAuthzContext and restore the case's own
//	form — trustedProxies + X-Forwarded-For + the ip-gated permit — as an app-level DB test.
//
// KT-DEFER: MePermissionsRouteTest.kt#requester_ip from a trusted edge reaches the me-permissions admin decision — the
//
//	Kotlin case asserts an OBSERVABLE flip (isAdmin true for 203.0.113.10, false for 198.51.100.10) driven by
//	trustedProxies + X-Forwarded-For, and that needs A12's resolveHttpRequesterIp / httpRequesterIp /
//	httpAuthzContext, which are NOT ported (see the TODO(A12) in internal/httpapi/trustededge.go:19 — only
//	IsTrustedEdge landed, ahead of the SCIM TLS gate). With Gates.Context defaulting to an EMPTY context there is
//	no production path from a forwarded header to requester_ip to assert through. The PORTABLE half — that the
//	route passes the shared gate seam's context into all four decisions rather than an empty one — is what this
//	test pins, so A12 cannot land a resolver the route then ignores. Restore the case's own form when it does.
func TestMePermissionsThreadsTheGatesAuthzContextIntoTheDecision(t *testing.T) {
	az := &recordingAuthorizer{allow: map[authz.AuthzAction]bool{}}
	f := newAuthFixture(t, authTestConfig(false), az)
	// The A12 seam, stubbed: whatever it produces must reach every one of the four decisions.
	f.gates.Context = func(r *http.Request) authz.AuthzContext {
		return authz.AuthzContext{RequesterIP: strPtr(r.Header.Get("X-Test-Requester-Ip"))}
	}
	cookie := f.login(t, 400, "edge-admin")

	r := httptest.NewRequest(http.MethodGet, "/api/me/permissions", nil)
	r.Header.Set("X-Test-Requester-Ip", "203.0.113.10")
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if len(az.ctxs) != 4 {
		t.Fatalf("Cedar was asked %d times, want 4", len(az.ctxs))
	}
	for i, ctx := range az.ctxs {
		if ctx.RequesterIP == nil || *ctx.RequesterIP != "203.0.113.10" {
			t.Errorf("decision %d carried requester_ip %v, want 203.0.113.10 — the route must pass "+
				"Gates.AuthzContext, not an empty context", i, ctx.RequesterIP)
		}
	}
}

// ipGatedAdminPolicy is `MePermissionsRouteTest.ipGatedAdminAuthz`'s single policy
// (MePermissionsRouteTest.kt:92-93) verbatim: admin.datasources fires ONLY when requester_ip is inside
// the RFC 5737 documentation range 203.0.113.0/24. It is what makes `isAdmin` observably sensitive to
// the context argument, instead of a value that is false for every input.
const ipGatedAdminPolicy = `permit(
        principal in Role::"system:admin", action == Action::"admin.datasources", resource
    ) when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };`

// ipGatedAdminAuthz is `private fun ipGatedAdminAuthz(): Authz` (MePermissionsRouteTest.kt:89-98): the
// REAL Cedar engine over that one policy, with `edge-admin` holding system:admin and nobody else
// holding anything. [unusedPolicyStore] is the Kotlin's MePermissionsUnusedDataSource sentinel.
func ipGatedAdminAuthz(t *testing.T) *authz.Authz {
	t.Helper()
	engine, err := authz.NewCedarEngineFromSources([]authz.PolicySource{{ID: 1, Src: ipGatedAdminPolicy}})
	if err != nil {
		t.Fatalf("NewCedarEngineFromSources: %v", err)
	}
	return authz.New(engine, unusedPolicyStore{t: t}, authz.RoleSourceFunc(func(p string) []string {
		if p == "edge-admin" {
			return []string{"system:admin"}
		}
		return nil
	}))
}

// recordingDelegate records what was asked of Cedar AND forwards to a real [httpapi.Authorizer], so one
// case can assert both the route's verdict and the context every decision carried.
type recordingDelegate struct {
	inner httpapi.Authorizer
	ctxs  []authz.AuthzContext
}

func (a *recordingDelegate) Authorize(
	principal string, action authz.AuthzAction, resource authz.AuthzResource, ctx authz.AuthzContext,
) authz.AuthzDecision {
	a.ctxs = append(a.ctxs, ctx)
	return a.inner.Authorize(principal, action, resource, ctx)
}

// trustedEdgeContext is the A12 stand-in, copied in posture from internal/httpapi's own
// admincontext_authz_test.go: 12-request-context.md §2's rule and nothing more.
//
// 🔒 It REUSES the PRODUCTION [httpapi.IsTrustedEdge] / [httpapi.RequestPeer] / [httpapi.LastHeader]
// rather than reimplementing the peer test. RequesterIp.kt's own warning is that "a second hand-rolled
// copy of this test is how a header ends up honored from an untrusted peer", and a test fixture is not
// exempt — written this way the untrusted arm below is the production function's answer, so the fixture
// cannot be laxer than the real thing.
func trustedEdgeContext(trustedProxies map[string]struct{}) func(*http.Request) authz.AuthzContext {
	return func(r *http.Request) authz.AuthzContext {
		peer, present := httpapi.RequestPeer(r)
		if !httpapi.IsTrustedEdge(peer, present, trustedProxies) {
			return authz.AuthzContext{}
		}
		xff := httpapi.LastHeader(r, "X-Forwarded-For")
		if xff == nil || *xff == "" {
			return authz.AuthzContext{}
		}
		return authz.AuthzContext{RequesterIP: xff}
	}
}

// mePermissionsTestPeer is the socket peer httptest.NewRequest reports (Go sets RemoteAddr to
// 192.0.2.1:1234). It stands in for the literal "localhost" Ktor's test host reports and that the
// Kotlin's `trustedProxies = setOf("localhost")` trusts — same posture: the peer is trusted in one arm
// and not in the other, and nothing else moves.
const mePermissionsTestPeer = "192.0.2.1"

// TestAnUntrustedPeerCannotSpoofRequesterIPAtMePermissions is MePermissionsRouteTest case 6
// (A12 INV-A12-2).
//
// The Kotlin's assertion is `isAdmin == false` under a spoofed X-Forwarded-For, against an ip-gated
// `admin.datasources` permit that WOULD fire for 203.0.113.10 — so the negative arm only means
// something next to a reachable positive one. Both are here: the TRUSTED arm proves the ip-gated permit
// really does flip isAdmin to true when requester_ip arrives, and the UNTRUSTED arm — the case itself —
// proves the same header from a peer that is not a configured edge flips nothing.
//
// ⚠️ HONEST CAVEAT, unchanged: A12's httpRequesterIp / httpAuthzContext are NOT ported (the TODO at
// internal/httpapi/trustededge.go:20-22 — only IsTrustedEdge landed), so [httpapi.Gates.Context] is
// filled here by [trustedEdgeContext], a test-local stub over the production trusted-edge predicate.
// The stub stands in for A12; it does NOT stand in for the route, and the route is what is under test —
// that it threads Gates.Context into the decision instead of an empty one, and so cannot honor a
// forwarded header the shared seam refused to trust.
// KT: MePermissionsRouteTest.kt#an untrusted peer cannot spoof requester_ip via X-Forwarded-For at the me-permissions route
func TestAnUntrustedPeerCannotSpoofRequesterIPAtMePermissions(t *testing.T) {
	const spoofed = "203.0.113.10"

	// mePermissions fires one request carrying `spoofed` as X-Forwarded-For, with the given trusted-proxy
	// set in force, and returns the body plus every context Cedar was handed.
	mePermissions := func(t *testing.T, trusted ...string) (MePermissions, []authz.AuthzContext) {
		t.Helper()
		cfg := authTestConfig(false)
		for _, p := range trusted {
			cfg.TrustedProxies[p] = struct{}{}
		}
		az := &recordingDelegate{inner: ipGatedAdminAuthz(t)}
		f := newAuthFixture(t, cfg, az)
		f.gates.Context = trustedEdgeContext(cfg.TrustedProxies)
		cookie := f.login(t, 500, "edge-admin")

		r := httptest.NewRequest(http.MethodGet, "/api/me/permissions", nil)
		r.Header.Set("X-Forwarded-For", spoofed)
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		var got MePermissions
		decodeInto(t, rec, &got)
		return got, az.ctxs
	}

	// 🔒 THE NON-VACUITY CONTROL. With the peer configured as a trusted edge the forwarded address IS
	// requester_ip, the ip-gated permit fires, and isAdmin is TRUE. Without this arm the assertion below
	// would hold for a route that could never report an admin at all.
	t.Run("control: from a TRUSTED edge the forwarded address does reach the decision", func(t *testing.T) {
		got, ctxs := mePermissions(t, mePermissionsTestPeer)
		if !got.IsAdmin {
			t.Fatal("the ip-gated admin permit did not fire for a trusted edge forwarding 203.0.113.10 — " +
				"the untrusted arm below would then prove nothing")
		}
		if len(ctxs) != 4 {
			t.Fatalf("Cedar was asked %d times, want 4", len(ctxs))
		}
		for i, ctx := range ctxs {
			if ctx.RequesterIP == nil || *ctx.RequesterIP != spoofed {
				t.Errorf("decision %d carried requester_ip %v, want %q — the route must pass "+
					"Gates.AuthzContext, not an empty context", i, ctx.RequesterIP, spoofed)
			}
		}
	})

	// The case itself: the SAME header, the SAME policy, the SAME principal — only the peer is no longer
	// a configured edge.
	t.Run("an untrusted peer's X-Forwarded-For is not honored", func(t *testing.T) {
		got, ctxs := mePermissions(t)
		if got.IsAdmin {
			t.Error("a spoofed X-Forwarded-For made the caller an admin")
		}
		if got.CanApprove {
			t.Error("canApprove tracks isAdmin, so a spoofed header must not grant approval either")
		}
		if len(ctxs) != 4 {
			t.Fatalf("Cedar was asked %d times, want 4", len(ctxs))
		}
		for i, ctx := range ctxs {
			if ctx.RequesterIP != nil {
				t.Errorf("decision %d carried requester_ip %q from an untrusted peer's header",
					i, *ctx.RequesterIP)
			}
		}
	})
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ---------------------------------------------------------------------------------------------
// POST /auth/debug — the gate half (the DB half is in authroutes_db_test.go)
// ---------------------------------------------------------------------------------------------

// TestDebugLoginIs404WhenTheBypassIsOff pins 🔒 404, NOT 401 and NOT 403.
//
// With PM_AUTH_DEBUG off the endpoint DOES NOT EXIST. A 401 would advertise a dev login surface to
// an unauthenticated caller on a production deployment, and a 403 would confirm it is there and
// merely closed. The resource param is `endpoint`.
//
// This is also AuthAndIngestRoutesDbTest's second case verbatim — 404, `common.not_found`,
// `params.resource == "endpoint"` — which that suite reaches through the whole booted module. The
// gate-level version asserts the same three facts and reaches the same handler branch (App.kt:687-690
// / authroutes.go's debugLogin), so it is not re-driven through the module.
// KT: AuthAndIngestRoutesDbTest.kt#auth debug is a 404 endpoint when PM_AUTH_DEBUG is off
func TestDebugLoginIs404WhenTheBypassIsOff(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(false), nil)

	rec := f.do(http.MethodPost, "/auth/debug", `{"principal":"x@example.com"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Code   string            `json:"code"`
		Params map[string]string `json:"params"`
	}
	decodeInto(t, rec, &body)
	if body.Code != "common.not_found" || body.Params["resource"] != "endpoint" {
		t.Errorf(`body = %+v, want {common.not_found, resource:"endpoint"}`, body)
	}
}

// TestDebugLoginRejectsTheBypassBeforeReadingTheBody pins the ORDER of the first two steps: the
// authDebug check precedes `call.receive<DebugLogin>()`, so a malformed body on a
// bypass-off deployment is still a 404 and never a 500 that reveals the route parses anything.
func TestDebugLoginRejectsTheBypassBeforeReadingTheBody(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(false), nil)

	rec := f.do(http.MethodPost, "/auth/debug", `{ this is not json`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 — the bypass check must precede the body read", rec.Code)
	}
}

// TestAMalformedSimulatedAddressIs400AndWritesNoCookie is 🔒 INV-A1-7's step-ORDER half, and it is
// the half a database test cannot see.
//
// authroutes_db_test.go's TestARefusedSimulatedAddressLeavesNothingBehind proves the check precedes
// the TRANSACTION (no session minted, no roles rewritten). This proves it also precedes
// `ensureDeviceCookie`: a refused login must leave NOTHING behind, and `pm_did` is a 90-day cookie
// that a browser would keep long after the 400 is forgotten. The Kotlin's order is
// validate → ensureDeviceCookie → inTx (App.kt:700-720), so the assertion is that NO Set-Cookie of
// any kind appears on the 400.
//
// `100.100.1.0/24` is chosen deliberately: it is the ONE literal of DebugRequesterIpDbTest's sixteen
// where the two stages of the arbiter disagree — the Cedar engine ACCEPTS a CIDR (it is a legal
// `ip()` argument inside a policy) and only the charset allowlist rejects it. So this case fails if
// either stage is dropped, not merely if the check is missing.
func TestAMalformedSimulatedAddressIs400AndWritesNoCookie(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)

	rec := f.do(http.MethodPost, "/auth/debug",
		`{"principal":"x@example.com","roles":["r"],"requesterIp":"100.100.1.0/24"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	// `"params":{}` is part of the shape: Kotlin's ApiError carries a defaulted non-null map and
	// encodeDefaults=true always emits it (INV-A1-4).
	if got := rec.Body.String(); got != `{"code":"auth.invalid_requester_ip","params":{}}` {
		t.Errorf("body = %s, want {\"code\":\"auth.invalid_requester_ip\",\"params\":{}}", got)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("a REFUSED login wrote %d cookie(s) (%v); the validity check precedes "+
			"ensureDeviceCookie, so a 400 must leave no pm_did behind", len(cookies), cookies)
	}
}

// TestABlankSimulatedAddressIsAbsentRatherThanInvalid pins the `takeIf { it.isNotEmpty() }` that
// sits between the trim and the arbiter.
//
// "Blank/absent leaves the observed peer authoritative" (Auth.kt:48). A whitespace-only value is
// therefore NOT a 400 — it becomes an absent address, which is a different answer from both "valid"
// and "invalid". Collapsing it into the rejection arm would 400 a console that sent an empty input
// box, and collapsing it the other way would hand "" to the arbiter.
//
// It is asserted by what does NOT happen: no 400. The login then proceeds into the transaction,
// which this container-free fixture has no store for — so the assertion is deliberately narrow, and
// the accepted-and-stored half lives in authroutes_db_test.go
// (TestADebugLoginStoresAndReportsAValidSimulatedAddress).
func TestABlankSimulatedAddressIsAbsentRatherThanInvalid(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)

	for _, blank := range []string{`""`, `"   "`, `null`} {
		rec := f.do(http.MethodPost, "/auth/debug",
			`{"principal":"x@example.com","requesterIp":`+blank+`}`)
		if rec.Code == http.StatusBadRequest {
			t.Errorf("requesterIp %s was REFUSED; a blank address is ABSENT, not invalid (body %s)",
				blank, rec.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------------------------
// POST /auth/logout — App.kt:768-783
// ---------------------------------------------------------------------------------------------

// TestLogoutWithNoCookieAnswersEndedTrue pins the ⚠️ `currentRef != null` clause of INV-A1-9's
// condition, in the direction that looks like a bug and is not.
//
// A caller with NO cookie that names a session id falls through to the UNCONDITIONAL arm: it ends
// nothing and answers `{ended: true}`. Reproduced verbatim — the alternative reading (treat "no
// cookie" as "does not match, so refuse") would change what a logged-out tab's automatic logout is
// told, and there is no oracle for it.
func TestLogoutWithNoCookieAnswersEndedTrue(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)

	rec := f.do(http.MethodPost, "/auth/logout", `{"sessionId":77}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got LogoutResponse
	decodeInto(t, rec, &got)
	if !got.Ended {
		t.Error("ended = false; with NO cookie the conditional arm cannot fire, so the Kotlin " +
			"answers ended:true having ended nothing")
	}
	if len(f.storage.ended) != 0 {
		t.Errorf("invalidate was called %v with no cookie to resolve", f.storage.ended)
	}
}

// TestLogoutWithNoBodyIsUnconditional covers the console's own shape and the ⚠️ body-read guard: a
// POST with a Content-Type and an EMPTY body must not be a decode failure.
func TestLogoutWithNoBodyIsUnconditional(t *testing.T) {
	for _, tc := range []struct{ name, body, contentType string }{
		{"no body and no Content-Type at all", "", ""},
		{"a Content-Type with an empty body — the console's shape", "", "application/json"},
		{"an explicit empty object", `{}`, "application/json"},
		{"an explicit null sessionId", `{"sessionId":null}`, "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthFixture(t, authTestConfig(true), nil)
			cookie := f.login(t, 600, "logout@example.com")

			r := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(tc.body))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			r.AddCookie(cookie)
			rec := httptest.NewRecorder()
			f.handler.ServeHTTP(rec, r)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
			var got LogoutResponse
			decodeInto(t, rec, &got)
			if !got.Ended {
				t.Error("ended = false; an absent sessionId is an UNCONDITIONAL logout")
			}
			if len(f.storage.ended) != 1 {
				t.Errorf("invalidate called %d times, want 1 — 🔒 INV-A4-7: logout must END THE ROW, "+
					"not merely drop the cookie", len(f.storage.ended))
			}
		})
	}
}

// TestConditionalLogoutOnAStaleSessionEndsNothing is 🔒 INV-A1-9 at the unit level, including the
// assertion that is easiest to miss: NO Set-Cookie.
//
// WebSessionRoutesDbTest.kt:294 — "a stale conditional logout must not clear the cookie". Clearing
// it would sign the user out of the tab they are actually using, which is precisely the outcome the
// conditional exists to prevent; a status-and-body-only assertion would pass an implementation that
// cleared it anyway.
func TestConditionalLogoutOnAStaleSessionEndsNothing(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)
	cookie := f.login(t, 700, "conditional@example.com")

	rec := f.do(http.MethodPost, "/auth/logout", `{"sessionId":699}`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got LogoutResponse
	decodeInto(t, rec, &got)
	if got.Ended {
		t.Error("ended = true for a session id the cookie does not name")
	}
	if len(f.storage.ended) != 0 {
		t.Errorf("invalidate was called %v for a NON-matching session id", f.storage.ended)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("Set-Cookie = %+v; a stale conditional logout must not clear the cookie "+
			"(WebSessionRoutesDbTest.kt:294)", cookies)
	}
}

// TestConditionalLogoutOnTheCurrentSessionEndsIt is the other arm: the named id MATCHES, so the
// logout proceeds and both halves of INV-A4-7 run.
func TestConditionalLogoutOnTheCurrentSessionEndsIt(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)
	cookie := f.login(t, 800, "conditional@example.com")

	rec := f.do(http.MethodPost, "/auth/logout", `{"sessionId":800}`, cookie)
	var got LogoutResponse
	decodeInto(t, rec, &got)
	if !got.Ended {
		t.Error("ended = false for the session id the cookie names")
	}
	if len(f.storage.ended) != 1 {
		t.Errorf("invalidate called %d times, want 1", len(f.storage.ended))
	}
	if !clearsSessionCookie(rec) {
		t.Error("no Max-Age=0 pm_session cookie; the browser is still holding the credential")
	}
}

// TestLogoutComparesAgainstTheCOOKIENotAResolvedRow is the reason [httpapi.Sessions.WebSessionRef]
// exists as a separate accessor.
//
// The named session is ALREADY DEAD — the resolver has no row for it — which is the COMMON case,
// since an automatic logout fires precisely when something has gone wrong. The comparison must
// still see the cookie's id, so a stale conditional logout is still refused. Resolving instead
// would yield nil, fall through to the unconditional arm, and sign the user out of the tab they are
// using.
func TestLogoutComparesAgainstTheCookieNotAResolvedRow(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)
	cookie := f.login(t, 900, "dead@example.com")
	// Kill the row the cookie points at; the tracker link survives, exactly as INV-A4-12 requires.
	delete(f.resolver.rows, 900)

	rec := f.do(http.MethodPost, "/auth/logout", `{"sessionId":901}`, cookie)
	var got LogoutResponse
	decodeInto(t, rec, &got)
	if got.Ended {
		t.Error("ended = true: the comparison resolved the ref instead of reading it off the cookie, " +
			"so a stale conditional logout became an unconditional one")
	}
}

// TestLogoutIsUngated pins that signing out works with no session at all and with the bypass off —
// requiring a live session here would strand exactly the tabs that need to log out.
func TestLogoutIsUngated(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(false), &recordingAuthorizer{allow: map[authz.AuthzAction]bool{}})

	rec := f.do(http.MethodPost, "/auth/logout", "")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — /auth/logout has no gate (body %s)", rec.Code, rec.Body.String())
	}
}

// clearsSessionCookie reports whether the response deletes pm_session.
func clearsSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.SessionCookie && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// The WEB_SESSION_AUTH trio, unauthenticated
// ---------------------------------------------------------------------------------------------

// TestTheThreeSessionRoutesChallengeWithReasonNone is WebSessionRoutesDbTest.kt:377-379: a client
// with no cookie at all gets `401 {"reason":"none"}` and `Cache-Control: no-store` from all three.
//
// 🔒 The no-store header is on the CHALLENGE, not only on the success path. A cached 401 would keep
// a re-authenticated tab looking signed out until the cache entry aged out.
//
// The /auth/me leg is also the whole of AuthAndIngestRoutesDbTest's first case, which asserts exactly
// these three things about it — 401, `Cache-Control: no-store`, and a body of
// SessionStatusError("none") rather than an ApiError.
// KT: AuthAndIngestRoutesDbTest.kt#auth me without a session is unauthenticated — the /auth/me leg
func TestTheThreeSessionRoutesChallengeWithReasonNone(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/auth/session/status"},
		{http.MethodGet, "/auth/me"},
		{http.MethodPost, "/auth/session/heartbeat"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := f.do(tc.method, tc.path, "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
			var body httpapi.SessionStatusError
			decodeInto(t, rec, &body)
			if body.Reason != session.WireReasonNone {
				t.Errorf("reason = %q, want %q", body.Reason, session.WireReasonNone)
			}
		})
	}
}

// TestAuthMeUnderAuthDebugStillRequiresASession pins the difference between the two gates, which is
// the single easiest thing to get wrong in this area.
//
// 🔒 WEB_SESSION_AUTH has NO PM_AUTH_DEBUG BYPASS. requireApi does. So under the bypass
// /api/me/permissions answers 200 with no session while /auth/me answers 401 — and that asymmetry is
// what makes the console's "am I signed in" check meaningful in dev. A port that added the bypass
// here would make every dev session look authenticated and the debug login untestable.
func TestAuthMeUnderAuthDebugStillRequiresASession(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)

	if rec := f.do(http.MethodGet, "/api/me/permissions", ""); rec.Code != http.StatusOK {
		t.Fatalf("/api/me/permissions status = %d, want 200 — requireApi DOES bypass", rec.Code)
	}
	rec := f.do(http.MethodGet, "/auth/me", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("/auth/me status = %d, want 401 — WEB_SESSION_AUTH has no authDebug bypass", rec.Code)
	}
}

// TestSessionStatusRendersTheRowsThreeDatabaseTimestamps pins the DTO's shape and the ONE thing
// about it that is not obvious: `now` is the row's own `clock_timestamp()`, not the process clock.
//
// The DB suite asserts the clock DOMAIN (that `now` falls inside a database-clock window taken
// around the call); this asserts the PLUMBING — that all four values come off the same row and are
// rendered with Java's Instant.toString, not RFC3339Nano.
func TestSessionStatusRendersTheRowsThreeDatabaseTimestamps(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)
	cookie := f.login(t, 1000, "status@example.com")
	row := f.resolver.rows[1000]

	rec := f.do(http.MethodGet, "/auth/session/status", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	var got SessionStatus
	decodeInto(t, rec, &got)
	want := toSessionStatus(row)
	if got != want {
		t.Errorf("SessionStatus = %+v, want %+v", got, want)
	}
	if got.SessionID != 1000 || got.Principal != "status@example.com" {
		t.Errorf("identity fields = %d/%q, want 1000/status@example.com", got.SessionID, got.Principal)
	}
}

// TestAuthMeResolvesRolesPerRequestAndSortsThem is 🔒 INV-A1-8's first half at the unit level.
//
// The session carries NO roles (httpapi.Sessions.UserSession deliberately returns an empty set), so
// anything /auth/me reports had to come from a per-request resolve. The sort is asserted because the
// console renders the list verbatim and an unstable order is a UI that reshuffles between reads.
func TestAuthMeResolvesRolesPerRequestAndSortsThem(t *testing.T) {
	f := newAuthFixture(t, authTestConfig(true), nil)
	cookie := f.login(t, 1100, "roles@example.com")
	// Rebuild the route group with a role reader that answers out of order.
	f.rewireRoles(t, map[string][]string{"roles@example.com": {"zeta", "alpha", "mid"}})

	rec := f.do(http.MethodGet, "/auth/me", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got session.UserSession
	decodeInto(t, rec, &got)
	if got.Principal != "roles@example.com" {
		t.Errorf("principal = %q", got.Principal)
	}
	if len(got.Roles) != 3 || got.Roles[0] != "alpha" || got.Roles[1] != "mid" || got.Roles[2] != "zeta" {
		t.Errorf("roles = %v, want [alpha mid zeta] — resolved per request and .sorted()", got.Roles)
	}
}

// TestAuthMeReportsTheSimulatedAddressOnlyWhileTheBypassIsOn is 🔒 INV-A1-8's second half.
//
// "Reported only while the bypass that honors it is on, so the console never shows a simulated
// address the decision path is in fact ignoring" (App.kt:743-745). With the bypass off the field is
// ABSENT from the JSON, not null — INV-A1-4's explicitNulls=false — so the assertion is on the raw
// keys, not on a decoded pointer.
func TestAuthMeReportsTheSimulatedAddressOnlyWhileTheBypassIsOn(t *testing.T) {
	const ip = "100.100.1.10"

	t.Run("authDebug on — reported", func(t *testing.T) {
		f := newAuthFixture(t, authTestConfig(true), nil)
		cookie := f.login(t, 1200, "sim@example.com")
		f.resolver.rows[1200].DebugRequesterIP = strPtr(ip)

		rec := f.do(http.MethodGet, "/auth/me", "", cookie)
		var got session.UserSession
		decodeInto(t, rec, &got)
		if got.RequesterIP == nil || *got.RequesterIP != ip {
			t.Errorf("requesterIp = %v, want %q", got.RequesterIP, ip)
		}
	})

	t.Run("authDebug off — absent, not null", func(t *testing.T) {
		f := newAuthFixture(t, authTestConfig(false), nil)
		cookie := f.login(t, 1300, "sim@example.com")
		f.resolver.rows[1300].DebugRequesterIP = strPtr(ip)

		rec := f.do(http.MethodGet, "/auth/me", "", cookie)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), ip) {
			t.Errorf("body carries the simulated address with the bypass OFF: %s", rec.Body.String())
		}
		var keyed map[string]any
		decodeInto(t, rec, &keyed)
		if _, present := keyed["requesterIp"]; present {
			t.Errorf("requesterIp is PRESENT (as %v); explicitNulls=false omits it entirely", keyed["requesterIp"])
		}
	})
}

// rewireRoles rebuilds the mounted route group with a different role reader. The router is rebuilt
// rather than mutated because [httpapi.Router] deliberately exposes no way to replace a mounted
// group — a route table that could change after boot would defeat the conflicting-pattern panic that
// makes it a boot-time consistency check.
func (f *authFixture) rewireRoles(t *testing.T, roles map[string][]string) {
	t.Helper()
	rt := &authRoutes{
		config:   f.cfg,
		gates:    f.gates,
		sessions: f.sessions,
		roles:    fakeRoles{byPrincipal: roles},
	}
	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: f.sessions})
	router.Mount(rt)
	f.handler = router.Handler()
}
