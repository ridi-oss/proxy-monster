package access

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
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The route fixture for `accessRoutes` (06-query-decision.md §6).
//
// SPLIT OF FAKES AND REALITY, following internal/policy/routes_support_test.go's:
//
//   - the STORES are real, over a migrated Postgres. Every claim here is about a status, a body shape
//     or WHICH rows came back, and all three are downstream of what the SQL actually did. A faked
//     store would prove only that the handler called something — and INV-A6-28's whole point is that
//     the STORE returns rows the ROUTE then drops.
//   - the two SESSION seams are fakes. internal/session's own DB suites prove `principal_session`;
//     what a route test needs is "there is a session for P" or "there is none".
//   - Cedar is a COUNTING FAKE for the gate-map suites ([recordingAuthorizer]) and the REAL engine for
//     the two ported ElevationContextRouteAuthzDbTest cases ([cedarFixture]). The counting fake is
//     the only way to observe WHICH action and resource each route asks about — a fixture that merely
//     answered Allow/Deny would pass identically if `/reject` asked for `task.reject`.
// ---------------------------------------------------------------------------------------------

// fakeStorage is `SessionStorage`: the tracker-key ⇒ row-id map Ktor's session storage maintains.
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

// fakeResolver is `WebSessionResolver`: the live-row lookup.
type fakeResolver struct{ rows map[int64]*session.WebRow }

func newFakeResolver() *fakeResolver { return &fakeResolver{rows: map[int64]*session.WebRow{}} }

func (f *fakeResolver) ResolveWeb(_ context.Context, id int64, _ *string) (*session.WebRow, error) {
	return f.rows[id], nil
}

func (f *fakeResolver) WebEndedReason(context.Context, int64) (*string, error) { return nil, nil }

// askedFor is one recorded authorization: which entry point, which action, which resource.
//
// The ENTRY POINT is recorded alongside the action because accessRoutes uses three different ones and
// the choice is behaviour, not style: the list routes use plain `authorize` (EMPTY context), approve
// and reject use `authorizeWithContext` (request context + derived tags), and create uses
// `authorizeDatasourceAction` (a Datasource resource keyed by NAME, which the AuthzResource sum type
// cannot express). A test that only recorded the action could not tell them apart.
type askedFor struct {
	via            string
	action         authz.AuthzAction
	resource       authz.AuthzResource
	context        authz.AuthzContext
	roles          []string
	datasourceName *string
	datasourceTags []string
}

// recordingAuthorizer implements BOTH [Authorizer] (the four methods accessRoutes needs) and
// httpapi.Authorizer (the one the gates need), because the production wiring passes ONE *authz.Authz
// to both and the fixture must not accidentally prove that two graphs agree.
type recordingAuthorizer struct {
	asked   []askedFor
	allowed bool
	reason  string
	// tags is what ResolveContextTags returns — pass 1's answer, staged per case.
	tags []string
}

func (a *recordingAuthorizer) Authorize(
	_ string, action authz.AuthzAction, resource authz.AuthzResource, ctx authz.AuthzContext,
) authz.AuthzDecision {
	a.asked = append(a.asked, askedFor{via: "authorize", action: action, resource: resource, context: ctx})
	return a.decide()
}

func (a *recordingAuthorizer) ResolveContextTags(
	_ string, roles []string, datasourceName string, raw authz.AuthzContext, dsTags []string,
) []string {
	name := datasourceName
	a.asked = append(a.asked, askedFor{
		via: "resolveContextTags", context: raw, roles: roles,
		datasourceName: &name, datasourceTags: dsTags,
	})
	return a.tags
}

func (a *recordingAuthorizer) AuthorizeDatasourceAction(
	_ string, roles []string, action authz.AuthzAction, datasourceName string,
	ctx authz.AuthzContext, dsTags []string,
) authz.AuthzDecision {
	name := datasourceName
	a.asked = append(a.asked, askedFor{
		via: "authorizeDatasourceAction", action: action, context: ctx, roles: roles,
		datasourceName: &name, datasourceTags: dsTags,
	})
	return a.decide()
}

func (a *recordingAuthorizer) AuthorizeWithContext(
	_ string, action authz.AuthzAction, resource authz.AuthzResource,
	raw authz.AuthzContext, datasourceName *string, dsTags []string,
) authz.AuthzDecision {
	a.asked = append(a.asked, askedFor{
		via: "authorizeWithContext", action: action, resource: resource, context: raw,
		datasourceName: datasourceName, datasourceTags: dsTags,
	})
	return a.decide()
}

func (a *recordingAuthorizer) decide() authz.AuthzDecision {
	if a.allowed {
		return authz.Allow
	}
	return authz.Deny(a.reason)
}

func (a *recordingAuthorizer) reset() { a.asked = nil }

// only returns the single recorded authorization, failing when there was not exactly one. "Exactly
// once" is part of most claims here: a route that decided twice would still answer 200 and would
// double every Cedar evaluation on a list of 500 grants.
func (a *recordingAuthorizer) only(t *testing.T) askedFor {
	t.Helper()
	if len(a.asked) != 1 {
		t.Fatalf("expected exactly one authorization, got %d: %+v", len(a.asked), a.asked)
	}
	return a.asked[0]
}

func (a *recordingAuthorizer) actions() []authz.AuthzAction {
	out := make([]authz.AuthzAction, 0, len(a.asked))
	for _, ask := range a.asked {
		out = append(out, ask.action)
	}
	return out
}

// fakeRoleResolver is A3's RoleResolver, staged per case. The `POST /api/access-requests` gate
// resolves roles server-side and threads that ONE snapshot into both passes (INV-A2-10), so the
// fixture has to be able to observe which snapshot arrived.
type fakeRoleResolver struct {
	roles []string
	err   error
}

func (f *fakeRoleResolver) Resolve(context.Context, string) ([]string, error) {
	return f.roles, f.err
}

// routeFixture is the mounted group plus everything a case needs to drive it.
type routeFixture struct {
	t           *testing.T
	ctx         context.Context
	db          *store.Db
	handler     http.Handler
	sessions    *httpapi.Sessions
	storage     *fakeStorage
	resolver    *fakeResolver
	gates       *httpapi.Gates
	authz       *recordingAuthorizer
	store       *Store
	datasources *datasource.DatasourceStore
	roles       *fakeRoleResolver
	seed        *dbtest.Seed
	cfg         config.Config
}

// routeConfig is the minimal valid Config, with the dev bypass OFF.
//
// 🔒 AuthDebug defaults to FALSE. A suite that ran with it on would test the bypass and nothing else,
// and every "this route demands task.approve" claim would be vacuous — under authDebug none of the
// three conditional gates in this file is even reached.
func routeConfig() config.Config {
	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = false
	cfg.SecretToken = nil
	cfg.SessionSecret = "access-route-test-session-secret-32b"
	cfg.OIDC = nil
	cfg.ResultKey = nil
	cfg.ScimToken = nil
	cfg.TrustedProxies = map[string]struct{}{}
	return cfg
}

func newRouteFixture(t *testing.T) *routeFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)

	storage := newFakeStorage()
	resolver := newFakeResolver()
	cfg := routeConfig()
	sessions := &httpapi.Sessions{
		Codec:           session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		Storage:         storage,
		Resolver:        resolver,
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
	}
	az := &recordingAuthorizer{allowed: true, reason: "no policy permits it"}
	gates := &httpapi.Gates{Config: cfg, Authz: az, Sessions: sessions}

	accessStore := NewStore(db.Pool)
	dsStore := datasource.NewDatasourceStore(db)
	roles := &fakeRoleResolver{roles: []string{"analyst"}}

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(NewRoutes(gates, accessStore, az, dsStore, roles, nil))

	return &routeFixture{
		t: t, ctx: context.Background(), db: db,
		handler: router.Handler(), sessions: sessions, storage: storage, resolver: resolver,
		gates: gates, authz: az, store: accessStore, datasources: dsStore, roles: roles,
		seed: dbtest.NewSeed(t, db), cfg: cfg,
	}
}

// authDebug flips the dev bypass ON for the gates the handlers read through.
//
// 🔒 It sets exactly ONE field, `gates.Config.AuthDebug`, because the production code reads exactly
// one — see the comment on Routes.gates. If this needed two assignments to stay coherent, that would
// itself be the bug internal/audit measured.
func (f *routeFixture) authDebug(on bool) {
	f.gates.Config.AuthDebug = on
}

// loginAs seats a live web row and returns the cookie a browser would send for it.
//
// It is a free function rather than a method because BOTH fixtures need it — the counting-fake
// [routeFixture] and the real-Cedar [cedarFixture] — and two copies of the cookie dance is how the
// two would drift into signing differently.
func loginAs(t *testing.T, sessions *httpapi.Sessions, resolver *fakeResolver, principal string) *http.Cookie {
	t.Helper()
	id := int64(len(resolver.rows) + 1)
	now := time.Now().UTC()
	resolver.rows[id] = &session.WebRow{
		ID: id, Principal: principal, CreatedAt: now, Now: now,
		IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	}
	rec := httptest.NewRecorder()
	if err := sessions.SetWebSession(context.Background(), rec, id); err != nil {
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

// request is one call through the FULL plugin stack — CallLogging, StatusPages and the Sessions
// holder — rather than a direct handler invocation.
//
// 🔒 Several assertions are about the 500 `common.fallback` StatusPages produces (reject with a
// malformed body); calling the handler directly would surface those as a panic escaping the test.
//
// `peer` overrides r.RemoteAddr, which httptest sets to 192.0.2.1:1234. That is the SOCKET fact the
// trusted-edge rule tests, so a case about an untrusted forwarder has to be able to move it.
func request(
	t *testing.T, handler http.Handler, method, target, body, peer string,
	headers map[string]string, cookies ...*http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if peer != "" {
		r.RemoteAddr = peer
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	return rec
}

// login seats a live web row and returns the cookie a browser would send for it.
func (f *routeFixture) login(principal string) *http.Cookie {
	f.t.Helper()
	return loginAs(f.t, f.sessions, f.resolver, principal)
}

func (f *routeFixture) do(method, target, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return request(f.t, f.handler, method, target, body, "", nil, cookies...)
}

// as runs a request as an authenticated principal, with Cedar staged to allow.
func (f *routeFixture) as(principal, method, target, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	f.authz.allowed = true
	f.authz.reset()
	return f.do(method, target, body, f.login(principal))
}

// ---- seeding ----------------------------------------------------------------------------------

// seedRoleRequest opens a PENDING ROLE request through the PRODUCTION store.
func (f *routeFixture) seedRoleRequest(principal string, roleID int64, datasourceID *int64) AccessRequest {
	f.t.Helper()
	req, err := f.store.CreateRequest(f.ctx, principal, AccessRequestInput{
		RoleID: roleID, DatasourceID: datasourceID, Reason: types.Ptr("need it"),
	})
	if err != nil {
		f.t.Fatalf("CreateRequest(%s): %v", principal, err)
	}
	return *req
}

// seedQueryRequest opens a WORKFLOW QUERY task — the kind both decision routes must refuse with 400.
func (f *routeFixture) seedQueryRequest(principal string, datasourceID int64) AccessRequest {
	f.t.Helper()
	req, err := f.store.CreateQueryRequest(f.ctx, CreateQueryRequestInput{
		Principal: principal, DatasourceID: datasourceID, SQL: "select 1",
		DenyReason: types.Ptr("denied"), EvaluatedDecision: types.Ptr("DENY"),
	})
	if err != nil {
		f.t.Fatalf("CreateQueryRequest(%s): %v", principal, err)
	}
	return *req
}

// seedGrant mints a live grant by approving a fresh request — the only path that writes access_grant.
func (f *routeFixture) seedGrant(principal string, roleID int64) AccessGrant {
	f.t.Helper()
	req := f.seedRoleRequest(principal, roleID, nil)
	if _, err := f.store.Approve(f.ctx, req.ID, nil, "seeder@example.com"); err != nil {
		f.t.Fatalf("Approve(%d): %v", req.ID, err)
	}
	grants, err := f.store.ListGrants(f.ctx, &principal, false)
	if err != nil || len(grants) == 0 {
		f.t.Fatalf("ListGrants(%s): %v (%d rows)", principal, err, len(grants))
	}
	return grants[0]
}

// ---- assertions --------------------------------------------------------------------------------

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

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body.String())
	}
}
