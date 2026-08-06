package policy

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
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The route-level fixture shared by cedarroutes_db_test.go (A2 §8) and routes_db_test.go (A9 §3).
//
// SPLIT OF FAKES AND REALITY, and it is deliberate rather than convenient:
//
//   - the STORES are real, over a migrated Postgres. Every claim these suites make is about a
//     status, a body shape or a gate, and all three are downstream of what the store actually did —
//     a faked management layer would prove only that the handler called something.
//   - the two SESSION seams are fakes. internal/session's own DB suites already prove the SQL behind
//     `principal_session`; what a route test needs from identity is "there is a session for P" or
//     "there is none", and staging that through a real mint would add a table to every case that is
//     really about a 201.
//   - Cedar is a COUNTING FAKE ([recordingAuthorizer]). 02-authz.md §10's AdminGateTest already pins
//     which shipped policy answers `admin.policies`; what is unproven here is WHICH ACTION AND
//     RESOURCE each of the nineteen routes asks about, and that is only observable by recording the
//     call. INV-A2-16's claim is likewise about whether Cedar was reached AT ALL.
//
// The fakes mirror internal/app/authroutes_test.go's, which mirror internal/httpapi's. Three copies
// is two too many, and the eventual home is a small exported test-support package —
// 09-policies.md:95-100's disposition of the Kotlin's three JDBC-helper copies applies unchanged:
// duplication is not grounds for a refactor mid-port, and collapsing them is its own reviewable
// change.
// ---------------------------------------------------------------------------------------------

// fakeStorage is `SessionStorage`: the tracker-key ⇒ row-id map Ktor's session storage maintains.
type fakeStorage struct {
	keys map[string]int64
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
	delete(f.keys, key)
	return nil
}

// fakeResolver is `WebSessionResolver`: the live-row lookup.
type fakeResolver struct {
	rows map[int64]*session.WebRow
}

func newFakeResolver() *fakeResolver { return &fakeResolver{rows: map[int64]*session.WebRow{}} }

func (f *fakeResolver) ResolveWeb(_ context.Context, id int64, _ *string) (*session.WebRow, error) {
	return f.rows[id], nil
}

func (f *fakeResolver) WebEndedReason(context.Context, int64) (*string, error) { return nil, nil }

// recordingAuthorizer captures every (action, resource) pair a gate asked about.
//
// 🔒 It records rather than merely answering because the gate-map claims in 09-policies.md §3 and
// 02-authz.md §8 are claims about WHICH ACTION a route demands — `admin.policies` for roles and mask
// functions, `admin.identity` for assignments. A fixture that only returned Allow/Deny would pass
// identically if every route asked for the wrong one.
type recordingAuthorizer struct {
	actions   []authz.AuthzAction
	resources []authz.AuthzResource
	allowed   bool
	reason    string
}

func (a *recordingAuthorizer) Authorize(
	_ string, action authz.AuthzAction, resource authz.AuthzResource, _ authz.AuthzContext,
) authz.AuthzDecision {
	a.actions = append(a.actions, action)
	a.resources = append(a.resources, resource)
	if a.allowed {
		return authz.Allow
	}
	return authz.Deny(a.reason)
}

func (a *recordingAuthorizer) reset() {
	a.actions = nil
	a.resources = nil
}

// only returns the single action this authorizer was asked about, failing when it was asked a
// different number of times. "Exactly once" is part of every gate claim here: a route that ran its
// gate twice would still answer 200 and would double every Cedar evaluation on the admin surface.
func (a *recordingAuthorizer) only(t *testing.T) authz.AuthzAction {
	t.Helper()
	if len(a.actions) != 1 {
		t.Fatalf("expected exactly one authorization, got %d: %v", len(a.actions), a.actions)
	}
	return a.actions[0]
}

// routeFixture is one mounted route group plus everything a case needs to drive it.
type routeFixture struct {
	t          *testing.T
	ctx        context.Context
	db         *store.Db
	handler    http.Handler
	sessions   *httpapi.Sessions
	storage    *fakeStorage
	resolver   *fakeResolver
	gates      *httpapi.Gates
	authz      *recordingAuthorizer
	management *PolicyManagement
	policies   *CedarPolicyStore
	store      *PolicyStore
	cfg        config.Config
}

// routeConfig is the minimal valid Config a route suite needs, with the dev bypass OFF.
//
// 🔒 AuthDebug defaults to FALSE here, the opposite of internal/httpapi's testScimConfig. A gate
// suite that ran with the bypass on would test step 1 of requireAdmin and nothing else, and every
// "this route demands admin.policies" claim below would be vacuous.
func routeConfig() config.Config {
	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = false
	cfg.SecretToken = nil
	cfg.SessionSecret = "policy-route-test-session-secret-32b"
	cfg.OIDC = nil
	cfg.ResultKey = nil
	cfg.ScimToken = nil
	cfg.TrustedProxies = map[string]struct{}{}
	return cfg
}

// newRouteFixture migrates a database, builds the real stores over it, and mounts BOTH policy route
// groups on one router.
//
// Mounting both together is not laziness: `/api/policies` (A2) and `/api/roles` (A9) are two groups
// in one package that must coexist on one ServeMux, and Go 1.22 patterns PANIC at registration on a
// conflict. Registering them separately in two fixtures would never exercise that, and a conflict is
// exactly the failure a 120-route table produces when two areas claim overlapping paths.
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
	az := &recordingAuthorizer{allowed: true, reason: "no policy permits admin.policies"}
	gates := &httpapi.Gates{Config: cfg, Authz: az, Sessions: sessions}

	policies := NewCedarPolicyStore(db.Pool)
	polStore := NewPolicyStore(db.Pool)
	management := NewPolicyManagement(policies, polStore)

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(
		NewCedarPolicyRoutes(gates, management, nil),
		NewRoutes(gates, management, nil),
	)

	return &routeFixture{
		t: t, ctx: context.Background(), db: db,
		handler: router.Handler(), sessions: sessions, storage: storage, resolver: resolver,
		gates: gates, authz: az, management: management, policies: policies, store: polStore,
		cfg: cfg,
	}
}

// login seats a live web row and returns the cookie a browser would send for it.
func (f *routeFixture) login(principal string) *http.Cookie {
	f.t.Helper()
	const id int64 = 42
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

// do runs one request through the full plugin stack — CallLogging, StatusPages and the Sessions
// holder — rather than calling the handler directly.
//
// 🔒 That matters for more than realism: several assertions below are about the 500
// `common.fallback` StatusPages produces (a malformed body, a missing required field), and calling
// the handler directly would surface those as a panic escaping the test instead.
func (f *routeFixture) do(method, target, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
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

// admin runs a request as an authenticated principal Cedar allows.
func (f *routeFixture) admin(method, target, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	f.authz.allowed = true
	f.authz.reset()
	return f.do(method, target, body, f.login("admin@example.com"))
}

// assertStatus fails with the body attached — the difference between a five-second and a
// five-minute diagnosis.
func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: got status %d, want %d (body: %s)", what, rec.Code, want, rec.Body.String())
	}
}

// assertAPIError decodes an ApiError body and checks the code.
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

// decodeJSON unmarshals a recorded body, failing on malformed JSON.
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body.String())
	}
}

// seedUserPolicy writes one valid USER policy through the store and returns it.
func (f *routeFixture) seedUserPolicy(name, src string) CedarPolicy {
	f.t.Helper()
	created, err := f.policies.Create(f.ctx, NewCedarPolicyInput(name, src), types.Ptr("seed"))
	if err != nil {
		f.t.Fatalf("seed policy %s: %v", name, err)
	}
	return created
}

// validCedarSrc is a policy that type-checks against the bundled schema. Every case that needs "a
// policy" and does not care which uses this one.
const validCedarSrc = `permit(principal in Role::"tester", action == Action::"audit.read", resource);`

// invalidCedarSrc does not parse. Used for the validate-on-write and revalidate-on-enable paths.
const invalidCedarSrc = `permit(principal, action ==`
