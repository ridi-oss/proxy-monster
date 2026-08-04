package identity_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// 🔴 EVERY CASE IN THE TWO ROUTE SUITES IS NEW. 03-identity-scim.md coverage gap 6:
//
//	"No test drives a single SCIM route end to end. ScimAuthTest uses a stand-in /probe route; the Db
//	suites call the store directly. So every route-level branch in Scim.kt:320-594 — the 400
//	validations, the 409 mappings, the merge-vs-replace field semantics, the membership reconcilers,
//	the 201/204 statuses, the Resources envelope — is unasserted. This is the largest untested surface
//	in A3 and it is the wire contract web/-adjacent IdPs consume."
//
// The admin surface is no better off: Users.kt's fourteen routes have no route-level Kotlin test
// either. So these two files are written against the area doc's ROUTE TABLE, not migrated.
//
// # Why this file is `package identity_test`
//
// The admin routes bind to `identity.Management`, and the CONCRETE service is
// `*management.IdentityService` — in a package that IMPORTS internal/identity. An in-package test
// could not import it (a cycle), so the routes would have to be driven through a hand-written fake,
// which would prove the handler called something rather than what the guards did. An EXTERNAL test
// package can import both, so the service, the stores and the database are all real.
//
// # What is faked, and why only this
//
// The two SESSION seams and Cedar. internal/session's own DB suites prove `principal_session`, and
// 02-authz.md's AdminGateTest proves which shipped policy answers `admin.identity`; what is unproven
// HERE is which action each route demands and whether Cedar was reached at all, which is only
// observable by recording the call.
// ---------------------------------------------------------------------------------------------

// scimBearer is the standing PM_SCIM_TOKEN these suites configure.
const scimBearer = "a-standing-scim-secret"

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

// recordingAuthorizer captures every (action, resource) pair a gate asked about — because the claim
// "every identity route demands admin.identity" is a claim about WHICH action, and an authorizer that
// only answered Allow/Deny would pass identically if a route asked for admin.policies.
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

func (a *recordingAuthorizer) only(t *testing.T) authz.AuthzAction {
	t.Helper()
	if len(a.actions) != 1 {
		t.Fatalf("expected exactly one authorization, got %d: %v", len(a.actions), a.actions)
	}
	return a.actions[0]
}

type routeFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *store.Db
	handler  http.Handler
	sessions *httpapi.Sessions
	resolver *fakeResolver
	gates    *httpapi.Gates
	authz    *recordingAuthorizer
	seed     *dbtest.Seed

	store      *identity.UserGroupStore
	creds      *identity.Credentials
	management *management.IdentityService
	cfg        config.Config

	tokens        *token.Store
	grants        *access.Store
	sessionsStore *session.Store
}

// routeConfig is the minimal valid Config both suites need.
//
// 🔒 AuthDebug DEFAULTS TO FALSE, because requireAdmin short-circuits under it and every "this route
// demands admin.identity" claim would be vacuous with the bypass on.
//
// The SCIM suite flips it ON with [routeFixture.enableAuthDebug], and that is not a convenience: F33
// / INV-A3-38 says `requireScimAuth` has NO PM_AUTH_DEBUG bypass even though AGENTS.md and
// docs/authz-model.md:363 both claim it does, so running the SCIM gate cases with the bypass ON is
// what makes them a REGRESSION TEST for the doc's version — if anyone ever "fixes" the
// inconsistency, those cases start answering 200 and fail loudly.
func routeConfig() config.Config {
	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = false
	cfg.SecretToken = nil
	cfg.SessionSecret = "identity-route-test-session-secret-32b"
	cfg.OIDC = nil
	cfg.ResultKey = nil
	cfg.ScimToken = types.Ptr(scimBearer)
	cfg.TrustedProxies = map[string]struct{}{}
	return cfg
}

// newRouteFixture migrates a database, builds the REAL stores and the REAL management service over
// it, and mounts BOTH identity route groups on ONE router.
//
// Mounting them together is not laziness: `/api/users**`, `/api/groups**` and `/api/scim/v2/**` are
// three prefixes in one package that must coexist on one ServeMux, and Go 1.22 patterns PANIC at
// registration on a conflict. Registering them apart would never exercise that.
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
	az := &recordingAuthorizer{allowed: true, reason: "no policy permits admin.identity"}
	gates := &httpapi.Gates{Config: cfg, Authz: az, Sessions: sessions}

	users := identity.NewUserGroupStore(db.Pool)
	tokens := token.NewStore(db.Pool)
	grants := access.NewStore(db.Pool)
	sessionStore := session.NewStore(db.Pool, session.Options{})
	creds := identity.NewCredentials(db.Pool, tokens, grants, sessionStore)
	svc := management.NewIdentityService(db.Pool, users, policy.NewPolicyStore(db.Pool), creds)

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(
		identity.NewRoutes(gates, users, svc, nil),
		identity.NewScimRoutes(gates, users, creds, nil),
	)

	return &routeFixture{
		t: t, ctx: context.Background(), db: db,
		handler: router.Handler(), sessions: sessions, resolver: resolver,
		gates: gates, authz: az, seed: dbtest.NewSeed(t, db),
		store: users, creds: creds, management: svc, cfg: cfg,
		tokens: tokens, grants: grants, sessionsStore: sessionStore,
	}
}

// enableAuthDebug turns PM_AUTH_DEBUG on for every subsequent request. 🔒 The SCIM gate must be
// UNAFFECTED — see [routeConfig].
func (f *routeFixture) enableAuthDebug() {
	f.gates.Config.AuthDebug = true
}

// clearScimToken unconfigures SCIM, which must make the whole surface answer 501 rather than opening
// it (INV-A3-36).
func (f *routeFixture) clearScimToken() {
	f.gates.Config.ScimToken = nil
}

// ---- small helpers the two route suites share ------------------------------------------------

func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// systemGroups reads back the `source='SYSTEM'` rows — SEVEN of them on a fresh install
// (V8__seed.sql:48-58). 🔒 F36: every immutability case in these suites is parameterised over all
// seven rather than naming `system:admin`, because every guard is keyed on the COLUMN and a
// name-based port would leave six production-capability groups mutable.
func (f *routeFixture) systemGroups() []identity.AppGroup {
	f.t.Helper()
	groups, err := f.store.ListGroups(f.ctx)
	if err != nil {
		f.t.Fatalf("listGroups: %v", err)
	}
	var out []identity.AppGroup
	for _, g := range groups {
		if g.Source == identity.SystemSource {
			out = append(out, g)
		}
	}
	return out
}

// routeCredentials is what [routeFixture.seedCredentials] plants, so a case can assert on the rows.
type routeCredentials struct {
	tokenID  int64
	grantID  int64
	daemonID int64
	webID    int64
}

// seedCredentials mints one of every credential class for principal, through the REAL A4/A6 stores.
func (f *routeFixture) seedCredentials(principal, roleName string) routeCredentials {
	f.t.Helper()
	roleID := f.seed.Role(roleName)

	issued, err := f.tokens.Issue(f.ctx, f.db.Pool, token.KindSession, principal, []string{roleName}, nil, 3600)
	if err != nil {
		f.t.Fatalf("issue token: %v", err)
	}
	var grantID int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO access_grant (principal, role_id, granted_by, expires_at)
		 VALUES ($1, $2, 'approver@example.com', now() + interval '1 hour') RETURNING id`,
		principal, roleID).Scan(&grantID); err != nil {
		f.t.Fatalf("insert grant: %v", err)
	}
	daemon, err := f.sessionsStore.Create(f.ctx, nil, principal, nil, nil, 3600, 900)
	if err != nil {
		f.t.Fatalf("create daemon session: %v", err)
	}
	webID, err := f.sessionsStore.MintWeb(f.ctx, nil, session.MintWebInput{
		Principal: principal, AbsoluteSeconds: 7200, IdleSeconds: 900,
	})
	if err != nil {
		f.t.Fatalf("mint web session: %v", err)
	}
	return routeCredentials{tokenID: issued.ID, grantID: grantID, daemonID: daemon.Row.ID, webID: webID}
}

// assertRevoked is the four-class INV-A3-5 check, at route level.
func (f *routeFixture) assertRevoked(c routeCredentials, what string) {
	f.t.Helper()
	var tokenRevoked, grantRevoked, windowClosed bool
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at IS NOT NULL FROM proxy_token WHERE id = $1`, c.tokenID).Scan(&tokenRevoked); err != nil {
		f.t.Fatalf("%s: read token: %v", what, err)
	}
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT revoked_at IS NOT NULL FROM access_grant WHERE id = $1`, c.grantID).Scan(&grantRevoked); err != nil {
		f.t.Fatalf("%s: read grant: %v", what, err)
	}
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT liveness_status = 'INACTIVE' AND absolute_expires_at <= now()
		   FROM principal_session WHERE id = $1`, c.daemonID).Scan(&windowClosed); err != nil {
		f.t.Fatalf("%s: read daemon session: %v", what, err)
	}
	reason, err := f.sessionsStore.WebEndedReason(f.ctx, c.webID)
	if err != nil {
		f.t.Fatalf("%s: read web session: %v", what, err)
	}

	if !tokenRevoked {
		f.t.Errorf("%s: the wire token is still live", what)
	}
	if !grantRevoked {
		f.t.Errorf("%s: the JIT grant is still live", what)
	}
	if !windowClosed {
		f.t.Errorf("%s: the daemon renewal window is still open — a renewal secret survives", what)
	}
	if reason == nil {
		f.t.Errorf("%s: the web session is still live", what)
	} else if *reason != identity.EndedDeactivated {
		f.t.Errorf("%s: web ended_reason %q, want %q", what, *reason, identity.EndedDeactivated)
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

// do runs one request through the FULL plugin stack — CallLogging, StatusPages and the Sessions
// holder — rather than calling the handler directly. That matters beyond realism: several assertions
// are about the 500 `common.fallback` StatusPages produces, and a direct call would surface those as
// a panic escaping the test.
func (f *routeFixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// admin runs a request as an authenticated principal Cedar allows.
func (f *routeFixture) admin(method, target, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	f.authz.allowed = true
	f.authz.reset()
	req := newRequest(method, target, body)
	req.AddCookie(f.login("admin@example.com"))
	return f.do(req)
}

// scim runs a request over direct TLS with the correct standing bearer.
func (f *routeFixture) scim(method, target, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(f.scimRequest(method, target, body))
}

// scimRequest builds the TLS-and-bearer request the gate accepts, so a case that wants to break ONE
// of those two can start from a good one.
func (f *routeFixture) scimRequest(method, target, body string) *http.Request {
	req := newRequest(method, target, body)
	// 🔒 The scheme comes from the LISTENER's TLS state, never from a header — httpapi.RequestScheme.
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Authorization", "Bearer "+scimBearer)
	return req
}

func newRequest(method, target, body string) *http.Request {
	if body == "" {
		return httptest.NewRequest(method, target, nil)
	}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

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

// assertScimError decodes a SCIM error body and checks status, scimType and detail — all three,
// because scimType is what an IdP branches on and F26 turns on its ABSENCE on exactly one route.
func assertScimError(
	t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantType *string, wantDetail, what string,
) {
	t.Helper()
	assertStatus(t, rec, wantStatus, what)

	var body httpapi.ScimError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: body is not JSON (%v): %s", what, err, rec.Body.String())
	}
	// 🔒 INV-A3-2 — the SCIM envelope, not ApiError. A body carrying `code` is the A1 envelope leaking
	// onto a SCIM route.
	if len(body.Schemas) != 1 || body.Schemas[0] != httpapi.ScimErrorSchema {
		t.Errorf("%s: schemas %v, want [%s]", what, body.Schemas, httpapi.ScimErrorSchema)
	}
	if want := strconv.Itoa(wantStatus); body.Status != want {
		t.Errorf("%s: status %q, want %q (a STRING, per RFC 7644 §3.12)", what, body.Status, want)
	}
	switch {
	case wantType == nil && body.ScimType != nil:
		t.Errorf("%s: scimType %q, want it ABSENT", what, *body.ScimType)
	case wantType != nil && (body.ScimType == nil || *body.ScimType != *wantType):
		t.Errorf("%s: scimType %v, want %q", what, body.ScimType, *wantType)
	}
	if body.Detail == nil || *body.Detail != wantDetail {
		t.Errorf("%s: detail %v, want %q", what, body.Detail, wantDetail)
	}
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body.String())
	}
}
