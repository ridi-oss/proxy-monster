package datasource_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The A5 route fixture.
//
// 🔴 THIS FILE IS `package datasource_test`, NOT `package datasource`, AND THAT IS LOAD-BEARING.
// internal/management imports internal/datasource, so the production package cannot import the
// management service it serves — [datasource.Management] exists precisely to break that. An EXTERNAL
// test package has no such restriction: Go allows `foo_test` to import a package that imports `foo`.
// So these suites wire the REAL *management.DatasourceService, which is the only way to prove the
// interface is satisfiable and that the guards (INV-A11-28's reserved tag, INV-A11-29's schema, the
// 404s) really reach the wire through it. A fake management would test the handler's plumbing and
// none of the behaviour the route table is about.
//
// SPLIT OF FAKES AND REALITY, mirroring internal/policy/routes_support_test.go:
//   - STORES are real, over a migrated Postgres.
//   - The two SESSION seams are fakes; internal/session's own suites own the SQL.
//   - The ADMIN gate's Cedar is a counting fake, because what is unproven here is WHICH action each
//     route demands.
//   - The CONNECT decision is real Cedar wherever the claim is about authorization (wire-cert,
//     catalog, ?connectable=true) and a recording fake wherever the claim is about the route's
//     plumbing (that the two-pass call happens at all, with the datasource NAME and its tags).
// ---------------------------------------------------------------------------------------------

// ---- session seams ----------------------------------------------------------------------------

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

// ---- the admin gate's Cedar ---------------------------------------------------------------------

// recordingAuthorizer captures every (action, resource) a gate asked about. The A5 claim it proves is
// "these seven routes demand admin.datasources and the other six do not" — a fixture that only
// answered Allow/Deny would pass identically if a route asked for admin.policies.
type recordingAuthorizer struct {
	actions   []authz.AuthzAction
	resources []authz.AuthzResource
	allowed   bool
}

func (a *recordingAuthorizer) Authorize(
	_ string, action authz.AuthzAction, resource authz.AuthzResource, _ authz.AuthzContext,
) authz.AuthzDecision {
	a.actions = append(a.actions, action)
	a.resources = append(a.resources, resource)
	if a.allowed {
		return authz.Allow
	}
	return authz.Deny("no policy permits it")
}

func (a *recordingAuthorizer) reset() { a.actions, a.resources = nil, nil }

func (a *recordingAuthorizer) only(t *testing.T) authz.AuthzAction {
	t.Helper()
	if len(a.actions) != 1 {
		t.Fatalf("expected exactly one authorization, got %d: %v", len(a.actions), a.actions)
	}
	return a.actions[0]
}

// ---- the connect decision (recording fake) -------------------------------------------------------

// connectCall is one `mayConnect` invocation, recorded whole.
//
// 🔒 It captures the DATASOURCE NAME and the TAGS because INV-A2-2 (the Cedar resource is keyed off
// the name, never the id) and INV-A2-10 (one role snapshot threaded through both passes) are only
// observable from the arguments. A fake that returned a bool would let a route pass the numeric id
// and still be green.
type connectCall struct {
	principal   string
	roles       []string
	action      authz.AuthzAction
	datasource  string
	contextTags []string
	dsTags      []string
	pass        string // "tags" (pass 1) or "authorize" (pass 2)
}

type fakeConnect struct {
	calls []connectCall
	// derive is pass 1's answer — the context tags earned.
	derive []string
	// allow decides pass 2 per datasource name; a name absent from the map is denied.
	allow map[string]bool
}

func newFakeConnect() *fakeConnect { return &fakeConnect{allow: map[string]bool{}} }

func (f *fakeConnect) ResolveContextTags(
	principal string, roles []string, ds string, _ authz.AuthzContext, dsTags []string,
) []string {
	f.calls = append(f.calls, connectCall{
		principal: principal, roles: roles, datasource: ds, dsTags: dsTags, pass: "tags",
	})
	return f.derive
}

func (f *fakeConnect) AuthorizeDatasourceAction(
	principal string, roles []string, action authz.AuthzAction, ds string,
	ctx authz.AuthzContext, dsTags []string,
) authz.AuthzDecision {
	f.calls = append(f.calls, connectCall{
		principal: principal, roles: roles, action: action, datasource: ds,
		contextTags: ctx.Tags, dsTags: dsTags, pass: "authorize",
	})
	if f.allow[ds] {
		return authz.Allow
	}
	return authz.Deny("no datasource.connect grant")
}

func (f *fakeConnect) reset() { f.calls = nil }

// ---- the A10 seams ------------------------------------------------------------------------------

// fakeEvents is ProxyEventsHub reduced to the two methods A5 uses. `notified` is what
// `requestRefresh` reports, and a name absent from `attached` reports 0 — the honest zero.
type fakeEvents struct {
	attached  map[string]struct{}
	notified  map[string]int
	refreshed []string
}

func newFakeEvents() *fakeEvents {
	return &fakeEvents{attached: map[string]struct{}{}, notified: map[string]int{}}
}

func (f *fakeEvents) Attached() map[string]struct{} { return f.attached }

func (f *fakeEvents) RequestRefresh(name string) int {
	f.refreshed = append(f.refreshed, name)
	return f.notified[name]
}

// fakeTableDetails is TableDetailService. `detail` is the happy answer, `err` the failure; a nil
// detail with a nil error is the Kotlin's `null` return that becomes not_found{resource: table}.
type fakeTableDetails struct {
	detail *engine.TableDetail
	err    error
	calls  [][3]string
}

func (f *fakeTableDetails) Fetch(_ context.Context, name, schema, table string) (*engine.TableDetail, error) {
	f.calls = append(f.calls, [3]string{name, schema, table})
	return f.detail, f.err
}

// ---- the A3/A4 seams ------------------------------------------------------------------------------

type fakeTokens struct {
	// byToken maps the plaintext token to the identity it resolves to. An absent key is an
	// unresolvable token (revoked, expired or never issued) — A4's Resolve returns nil for all three.
	byToken map[string]*datasource.WireTokenIdentity
	err     error
}

func newFakeTokens() *fakeTokens {
	return &fakeTokens{byToken: map[string]*datasource.WireTokenIdentity{}}
}

func (f *fakeTokens) Resolve(_ context.Context, tok string) (*datasource.WireTokenIdentity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byToken[tok], nil
}

type fakeUsers struct {
	deactivated map[string]bool
	err         error
}

func newFakeUsers() *fakeUsers { return &fakeUsers{deactivated: map[string]bool{}} }

func (f *fakeUsers) IsDeactivated(_ context.Context, principal string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.deactivated[principal], nil
}

type fakeRoles struct {
	roles map[string][]string
	err   error
}

func newFakeRoles() *fakeRoles { return &fakeRoles{roles: map[string][]string{}} }

func (f *fakeRoles) Resolve(_ context.Context, principal string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.roles[principal], nil
}

// dbRoles is [fakeRoles]'s real-Cedar counterpart: server-side role resolution out of the control
// plane's own tables, so a case can grant a role by INSERT and have the decision see it.
type dbRoles struct{ src authz.RoleSource }

func (d dbRoles) Resolve(_ context.Context, principal string) ([]string, error) {
	return d.src.RolesOf(principal), nil
}

// ---- the fixture ---------------------------------------------------------------------------------

type fixture struct {
	t   *testing.T
	ctx context.Context

	db    *store.Db
	seed  *dbtest.Seed
	store *datasource.DatasourceStore
	mgmt  *management.DatasourceService

	handler  http.Handler
	sessions *httpapi.Sessions
	storage  *fakeStorage
	resolver *fakeResolver
	gates    *httpapi.Gates
	cfg      config.Config

	admin   *recordingAuthorizer
	connect *fakeConnect
	events  *fakeEvents
	details *fakeTableDetails
	tokens  *fakeTokens
	users   *fakeUsers
	roles   *fakeRoles

	// policies / cedar are non-nil only under [withRealCedar].
	policies *dbtest.DBPolicyStore

	// inspected records every chain handed to the trust-chain inspector, and inspectBad makes the
	// inspector report. INV-A5-22's claim is that reporting NEVER withholds the bytes.
	inspected  []string
	inspectBad bool
}

type fixtureOption func(*fixtureSetup)

type fixtureSetup struct {
	realCedar bool
	authDebug bool
}

// withRealCedar swaps the recording connect fake for the production Cedar path over the `policy`
// table — used by every case whose claim is about AUTHORIZATION rather than about the route calling
// the gate.
func withRealCedar() fixtureOption { return func(s *fixtureSetup) { s.realCedar = true } }

// withAuthDebug turns PM_AUTH_DEBUG on. Only two cases want it, and both are about the bypass itself.
func withAuthDebug() fixtureOption { return func(s *fixtureSetup) { s.authDebug = true } }

// routeConfig is the minimal valid Config, with the dev bypass OFF.
//
// 🔒 AuthDebug=false is the whole point, in WireCertRouteDbTest's own words: "with it on, every gate
// short-circuits and this test proves nothing."
func routeConfig() config.Config {
	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = false
	cfg.SecretToken = nil
	cfg.SessionSecret = "datasource-route-test-session-secret-32"
	cfg.OIDC = nil
	cfg.ResultKey = nil
	cfg.ScimToken = nil
	cfg.TrustedProxies = map[string]struct{}{}
	return cfg
}

func newFixture(t *testing.T, opts ...fixtureOption) *fixture {
	t.Helper()
	setup := &fixtureSetup{}
	for _, o := range opts {
		o(setup)
	}

	db, _ := dbtest.MigratedStore(t)
	cfg := routeConfig()
	cfg.AuthDebug = setup.authDebug

	storage := newFakeStorage()
	resolver := newFakeResolver()
	sessions := &httpapi.Sessions{
		Codec:           session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		Storage:         storage,
		Resolver:        resolver,
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
	}
	admin := &recordingAuthorizer{allowed: true}
	gates := &httpapi.Gates{Config: cfg, Authz: admin, Sessions: sessions}

	dsStore := datasource.NewDatasourceStore(db)
	events := newFakeEvents()
	details := &fakeTableDetails{}
	mgmt := management.NewDatasourceService(dsStore, events, details)

	f := &fixture{
		t: t, ctx: context.Background(), db: db, seed: dbtest.NewSeed(t, db),
		store: dsStore, mgmt: mgmt,
		sessions: sessions, storage: storage, resolver: resolver, gates: gates, cfg: cfg,
		admin: admin, connect: newFakeConnect(), events: events, details: details,
		tokens: newFakeTokens(), users: newFakeUsers(), roles: newFakeRoles(),
	}

	var (
		connectAuthz datasource.ConnectAuthorizer = f.connect
		roleResolver datasource.RoleResolver      = f.roles
	)
	if setup.realCedar {
		f.policies = dbtest.NewDBPolicyStore(t, db.Pool)
		src := dbtest.NewDBRoleSource(t, db.Pool)
		cedarEngine, err := authz.NewCedarEngine(f.policies)
		if err != nil {
			t.Fatalf("build the Cedar engine over the seeded policies: %v", err)
		}
		connectAuthz = authz.New(cedarEngine, f.policies, src)
		roleResolver = dbRoles{src: src}
	}

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(datasource.NewRoutes(datasource.RouteDeps{
		Gates:        gates,
		Authz:        connectAuthz,
		RoleResolver: roleResolver,
		Store:        dsStore,
		Events:       events,
		Tokens:       f.tokens,
		Users:        f.users,
		Management:   mgmt,
		// The one-line adapter internal/app must write. Reproduced here verbatim so the suite
		// exercises the real management call, re-lookup and all.
		Liveness: func(ctx context.Context, name string) (bool, error) {
			l, err := mgmt.GetDatasourceLiveness(ctx, name)
			return l.Attached, err
		},
		InspectTrustChain: func(pemChain string) (string, bool) {
			f.inspected = append(f.inspected, pemChain)
			if f.inspectBad {
				return "is not a parseable PEM certificate chain", true
			}
			return "", false
		},
	}))
	f.handler = router.Handler()
	return f
}

// ---- compile-time seam assertions -----------------------------------------------------------------
//
// 🔒 These are the reason this file is an EXTERNAL test package. [datasource.Management] and the
// three A11/A3/A4 seams are hand-written signature copies of types this package cannot import; a
// mismatch would otherwise only surface when internal/app is wired, in a different agent's change.
var (
	_ datasource.Management        = (*management.DatasourceService)(nil)
	_ management.ProxyAttachments  = (*fakeEvents)(nil)
	_ management.TableDetails      = (*fakeTableDetails)(nil)
	_ datasource.ConnectAuthorizer = (*authz.Authz)(nil)
)

// ---- driving the fixture ----------------------------------------------------------------------

// login seats a live web row and returns the cookie a browser would send for it.
func (f *fixture) login(principal string) *http.Cookie {
	f.t.Helper()
	id := int64(len(f.resolver.rows) + 1)
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

type request struct {
	method  string
	target  string
	body    string
	cookies []*http.Cookie
	headers map[string]string
}

func (f *fixture) send(req request) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if req.body == "" {
		r = httptest.NewRequest(req.method, req.target, nil)
	} else {
		r = httptest.NewRequest(req.method, req.target, strings.NewReader(req.body))
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range req.headers {
		r.Header.Set(k, v)
	}
	for _, c := range req.cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

// anon is a request with no session, no bearer and PM_AUTH_DEBUG off.
func (f *fixture) anon(method, target, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.send(request{method: method, target: target, body: body})
}

// as runs a request under a live web session for principal.
func (f *fixture) as(principal, method, target, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.send(request{method: method, target: target, body: body, cookies: []*http.Cookie{f.login(principal)}})
}

// asAdmin runs a request under a session Cedar allows, resetting the recorder first so `only` can
// assert exactly one authorization.
func (f *fixture) asAdmin(method, target, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	f.admin.allowed = true
	f.admin.reset()
	return f.as("admin@example.com", method, target, body)
}

// bearer runs a request whose only credential is an `Authorization` header.
func (f *fixture) bearer(header, method, target string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.send(request{method: method, target: target, headers: map[string]string{"Authorization": header}})
}

// ---- seeding -----------------------------------------------------------------------------------

// seedDatasource inserts a datasource row and returns it as the store serves it.
func (f *fixture) seedDatasource(name, eng, dbName string, tags ...string) datasource.Datasource {
	f.t.Helper()
	id := f.seed.Datasource(dbtest.DatasourceSpec{
		Name: name, Engine: eng, Host: "db", Port: 5432, DBName: dbName, Tags: tags,
	})
	return f.mustGet(id)
}

func (f *fixture) mustGet(id int64) datasource.Datasource {
	f.t.Helper()
	ds, found, err := f.store.Get(f.ctx, id)
	if err != nil || !found {
		f.t.Fatalf("read back datasource %d: found=%v err=%v", id, found, err)
	}
	return ds
}

// registerDatasource goes through DatasourceStore.Register — "the same path the proxy's gRPC Register
// drives, so the presence/clear semantics of the chain are exercised rather than bypassed by a direct
// INSERT" (WireCertRouteDbTest.kt:82-84).
func (f *fixture) registerDatasource(
	name string, eng datasource.Engine, dbName, advertiseAddr string, chain *string, wireTLS bool,
) datasource.Datasource {
	f.t.Helper()
	ds, err := f.store.Register(f.ctx, name, eng, "db", 3306, dbName, nil, advertiseAddr, chain, wireTLS)
	if err != nil {
		f.t.Fatalf("register %s: %v", name, err)
	}
	return ds
}

// addPolicy seeds a Cedar policy and bumps the engine's state version, which is what makes the new
// rule visible to the already-built engine (INV-A2-19).
func (f *fixture) addPolicy(name, src string) {
	f.t.Helper()
	if f.policies == nil {
		f.t.Fatal("addPolicy needs withRealCedar()")
	}
	f.seed.CedarPolicy(name, src)
	f.policies.Bump()
}

// ---- assertions ---------------------------------------------------------------------------------

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: got status %d, want %d (body: %s)", what, rec.Code, want, rec.Body.String())
	}
}

func assertAPIError(t *testing.T, rec *httptest.ResponseRecorder, wantCode, what string) types.ApiError {
	t.Helper()
	var body types.ApiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: body is not an ApiError (%v): %s", what, err, rec.Body.String())
	}
	if body.Code != wantCode {
		t.Errorf("%s: code %q, want %q (body: %s)", what, body.Code, wantCode, rec.Body.String())
	}
	return body
}

func assertParam(t *testing.T, body types.ApiError, key, want, what string) {
	t.Helper()
	if got := body.Params[key]; got != want {
		t.Errorf("%s: params[%q] = %q, want %q (params: %v)", what, key, got, want, body.Params)
	}
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body.String())
	}
}

func sortedStrings(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

// errSentinel is the stand-in for a JDBC failure on a seam that has no other way to fail.
var errSentinel = errors.New("seam exploded")
