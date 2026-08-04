package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/audit"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The shared DB + HTTP fixture for every route suite in this package.
//
// It is built on dbtest.NewEnforcementFixture, which means the CEDAR LAYER IS THE REAL ONE: the
// shipped V8 seed policies (task.assume-parties, task.cancel-parties, no-self-approval,
// task.editor-self-approve, the admin grant …) come from the migrations, and a real
// authz.CedarEngine answers over them. A stubbed authorizer would prove the handler called
// something; every 🔒 invariant in this area is about WHICH SHIPPED POLICY answers.
//
// 🔒 These suites FAIL rather than skip when Docker is absent. That is deliberate (the task brief and
// dbtest's doc both say so): a DB test that skips is a DB test that silently stops running.
// ---------------------------------------------------------------------------------------------

// httpFixture is the enforcement fixture plus the control-plane stores, the plugin stack and the
// three mounted route groups.
type httpFixture struct {
	t  *testing.T
	fx *dbtest.EnforcementFixture

	Access  *access.Store
	Audit   *audit.Store
	Results *result.Store

	RunExec *fakeRunExec
	Hub     *TaskCompletionHub
	Decider *Decider
	Gates   *httpapi.Gates

	handler  http.Handler
	sessions *httpapi.Sessions
	storage  *fakeStorage
	resolver *fakeResolver
	cfg      config.Config

	// pending collects the async bodies the routes launch, so a test can run them DETERMINISTICALLY
	// instead of sleeping. This is `appScope`, which the Kotlin also injects.
	mu      sync.Mutex
	pending []func()

	// auditFail, when set, makes every audit Insert fail — the only way to drive INV-A7-28's
	// "a failed audit insert propagates (500) so PII is never returned without a durable record".
	auditFail error
	// nextSessionID hands out distinct web-session ids so two logins in one test do not collide.
	nextSessionID int64
}

type fixtureOptions struct {
	AuthDebug bool
	// NoResultStore reproduces PM_RESULT_KEY being unset.
	NoResultStore bool
}

func newHTTPFixture(t *testing.T, opts fixtureOptions) *httpFixture {
	t.Helper()
	fx := dbtest.NewEnforcementFixture(t, dbtest.EnginePostgres)

	cfg := config.Defaults()
	cfg.HTTPPort = 0
	cfg.DBURL = "postgres://localhost/unused"
	cfg.DBUser = "unused"
	cfg.DBPassword = "unused"
	cfg.AuthDebug = opts.AuthDebug
	cfg.SecretToken = nil
	cfg.SessionSecret = "approval-route-test-session-secret-32b"
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
	gates := &httpapi.Gates{Config: cfg, Authz: fx.Authz, Sessions: sessions}

	f := &httpFixture{
		t: t, fx: fx,
		Access: access.NewStore(fx.Store.Pool),
		RunExec: &fakeRunExec{
			sessions: map[string]fakeSession{},
			response: query.QueryResponse{
				Decision: query.WireEnfAction(pb.EnfAction_ALLOW),
				Columns:  []string{"id"},
				Rows:     [][]*string{{strptr("1")}},
			},
		},
		Hub: NewTaskCompletionHub(), Gates: gates, sessions: sessions,
		storage: storage, resolver: resolver, cfg: cfg, nextSessionID: 100,
	}
	f.Audit = audit.New(fx.Store.Pool)

	if !opts.NoResultStore {
		// A fixed 32-byte key: the suite asserts on plaintext round-trips, never on the ciphertext.
		crypto, err := result.NewCrypto(bytes.Repeat([]byte{7}, result.KeyLen))
		if err != nil {
			t.Fatalf("result crypto: %v", err)
		}
		f.Results = result.NewStore(fx.Store.Pool, crypto)
	}

	f.Decider = &Decider{
		Datasources: fx.DatasourceStore,
		MaskFns:     fx.MaskFns,
		UserGroups:  fx.UserGroups,
		Roles:       fx.RoleResolver,
		Authz:       fx.Authz,
		// nil keeps system schemas deny-by-default, which is the fixture's posture everywhere else.
		SystemClassification: nil,
	}

	deps := Deps{
		Gates:   gates,
		Decider: f.Decider,
		Access:  f.Access,
		Audit:   &auditFailer{store: f.Audit, fixture: f},
		Results: f.resultStore(),
		RunExec: f.RunExec,
		Roles:   f.roleLister(),
		SelfApprove: SelfApproverFunc(func(principal string, ownRoles []string, ds datasource.Datasource,
			raw authz.AuthzContext, channel query.Channel) bool {
			// The REAL autoApproveTask body, inlined rather than importing internal/core (which would
			// drag the whole enforcement graph into this suite). It asks the same two Cedar questions
			// in the same order — INV-A7-17.
			taskCtx := raw
			value := channel.ContextValue()
			taskCtx.Channel = &value
			tags := fx.Authz.ResolveContextTags(principal, ownRoles, ds.Name, taskCtx, ds.Tags)
			if !fx.Authz.AuthorizeDatasourceAction(
				principal, ownRoles, authz.ActionTaskRequest, ds.Name, taskCtx.WithTags(tags), ds.Tags,
			).Allowed {
				return false
			}
			name := ds.Name
			return fx.Authz.AuthorizeWithContext(principal, authz.ActionTaskApprove,
				authz.ResourceApprovalRequest{Requester: principal, Approver: &principal, DatasourceName: &name},
				taskCtx, &name, ds.Tags).Allowed
		}),
		Hub:               f.Hub,
		Scope:             f.queueAsync,
		ExchangeTimeoutMs: 1000,
	}

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	router.Mount(
		NewRoutes(deps),
		NewEditorRoutes(deps),
		&TaskEventsRoute{
			Gates: gates, Hub: f.Hub, Access: f.Access, Datasources: fx.DatasourceStore,
			Authz: fx.Authz, Sessions: resolver,
			// Milliseconds, not 30 seconds: the timeout arm carries both the keepalive and the
			// liveness re-check, and a suite that waited the production interval could not test either.
			RecheckMs: 40, UnauthRetryMs: SSEUnauthRetryMs,
		},
	)
	f.handler = router.Handler()
	return f
}

// resultStore returns a typed-nil-free ResultStore: a (*result.Store)(nil) inside a non-nil interface
// would make every `rt.results == nil` check false and panic on the first call.
func (f *httpFixture) resultStore() ResultStore {
	if f.Results == nil {
		return nil
	}
	return f.Results
}

// roleLister reads app_role directly — the fixture's stand-in for policyStore.listRoles().
func (f *httpFixture) roleLister() RoleLister {
	return func(ctx context.Context) ([]Role, error) {
		rows, err := f.fx.Store.Pool.Query(ctx, `SELECT id, name FROM app_role ORDER BY id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []Role
		for rows.Next() {
			var r Role
			if err := rows.Scan(&r.ID, &r.Name); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rows.Err()
	}
}

// queueAsync is the injected appScope: it RECORDS the body instead of running it, so a test drives
// the async half with [httpFixture.runAsync] at a point of its choosing.
//
// 🔒 That determinism is what makes the execute suites meaningful. A `go f()` plus a sleep would make
// "the second execute is a 409" pass whether the first run had claimed the task or not.
func (f *httpFixture) queueAsync(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = append(f.pending, fn)
}

// runAsync drains and runs every queued async body, and reports how many ran.
func (f *httpFixture) runAsync() int {
	f.mu.Lock()
	queued := f.pending
	f.pending = nil
	f.mu.Unlock()
	for _, fn := range queued {
		fn()
	}
	return len(queued)
}

// pendingCount is how many async bodies are waiting — 0 proves a route "ran nothing".
func (f *httpFixture) pendingCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending)
}

// ---- sessions --------------------------------------------------------------------------------

func (f *httpFixture) login(principal string) *http.Cookie {
	f.t.Helper()
	f.nextSessionID++
	id := f.nextSessionID
	now := time.Now().UTC()
	f.resolver.set(id, &session.WebRow{
		ID: id, Principal: principal, CreatedAt: now, Now: now,
		IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	rec := httptest.NewRecorder()
	if err := f.sessions.SetWebSession(context.Background(), rec, id); err != nil {
		f.t.Fatalf("SetWebSession: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.SessionCookie {
			return c
		}
	}
	f.t.Fatal("no session cookie was written")
	return nil
}

// endSession is a newest-wins displacement / revocation: the row stops resolving.
func (f *httpFixture) endSession(principal string) {
	f.resolver.endAll(principal)
}

// ---- requests --------------------------------------------------------------------------------

func (f *httpFixture) do(method, target string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	f.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			f.t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, target, reader)
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		// A nil cookie is how an authDebug test says "no session at all" while still reusing the
		// cookie-taking helpers.
		if c != nil {
			r.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

func (f *httpFixture) get(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return f.do(http.MethodGet, target, nil, cookies...)
}

func (f *httpFixture) post(target string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, target, body, cookies...)
}

// ---- seeding ---------------------------------------------------------------------------------

// seedWorkflowTask creates a PENDING WORKFLOW approval for sql under role R, exactly as
// POST /api/approvals does.
func (f *httpFixture) seedWorkflowTask(principal, sql, roleName string) access.AccessRequest {
	f.t.Helper()
	roleID := f.roleID(roleName)
	reason := "because"
	evaluated := "DENY"
	req, err := f.Access.CreateQueryRequest(context.Background(), access.CreateQueryRequestInput{
		Principal: principal, DatasourceID: f.fx.DatasourceID, SQL: sql,
		Reason: &reason, EvaluatedDecision: &evaluated, RoleID: &roleID,
	})
	if err != nil {
		f.t.Fatalf("seed workflow task: %v", err)
	}
	return *req
}

// approveTask puts a seeded task into APPROVED with `decided_by = approver`.
func (f *httpFixture) approveTask(id int64, approver string) access.AccessRequest {
	f.t.Helper()
	req, err := f.Access.DecideQueryRequest(context.Background(), id, true, nil, approver)
	if err != nil || req == nil {
		f.t.Fatalf("approve task %d: req=%v err=%v", id, req, err)
	}
	return *req
}

func (f *httpFixture) roleID(name string) int64 {
	f.t.Helper()
	var id int64
	if err := f.fx.Store.Pool.QueryRow(context.Background(),
		`SELECT id FROM app_role WHERE name = $1`, name).Scan(&id); err != nil {
		f.t.Fatalf("role %q: %v", name, err)
	}
	return id
}

func (f *httpFixture) getRequest(id int64) *access.AccessRequest {
	f.t.Helper()
	req, err := f.Access.GetRequest(context.Background(), id)
	if err != nil {
		f.t.Fatalf("get request %d: %v", id, err)
	}
	return req
}

// storeResult drives an APPROVED task all the way to a DONE child holding the given rows, through
// the PRODUCTION store methods — claim, start, complete.
//
// 🔒 Going through the real methods (rather than an INSERT) is what makes a view test meaningful:
// the row it reads is byte-for-byte the row execution writes, encrypted by the real crypto.
func (f *httpFixture) storeResult(taskID int64, executor string, columns []string, rows [][]*string) {
	f.t.Helper()
	ctx := context.Background()
	claimed, err := f.Results.ClaimAndStartRun(ctx, taskID, executor, func(c context.Context, q store.Queryer) (bool, error) {
		return f.Access.ClaimExecutionOn(c, q, taskID)
	})
	if err != nil || claimed == nil {
		f.t.Fatalf("claim and start task %d: claimed=%v err=%v", taskID, claimed, err)
	}
	completed, err := f.Results.CompleteRun(ctx, taskID,
		result.DecryptedResult{Columns: columns, Rows: rows}, result.RetentionSec,
		func(c context.Context, q store.Queryer, _ result.QueryResultMeta) error {
			won, err := f.Access.MarkExecutedOn(c, q, taskID)
			if err != nil {
				return err
			}
			if !won {
				f.t.Fatalf("task %d left EXECUTING before completion", taskID)
			}
			return nil
		})
	if err != nil || completed == nil {
		f.t.Fatalf("complete task %d: completed=%v err=%v", taskID, completed, err)
	}
}

// overwriteStoredColumns rewrites the child's stored `columns` jsonb WITHOUT touching the
// ciphertext, so the decrypted payload and the metadata still agree while the LIVE decision's output
// columns will not. It is how the drift gates (5 and 6) are driven: catalog drift between execute and
// view is otherwise unreachable in a test.
func (f *httpFixture) overwriteChildSQL(taskID int64, sql string) {
	f.t.Helper()
	if _, err := f.fx.Store.Pool.Exec(context.Background(),
		`UPDATE query_result SET sql = $1 WHERE task_id = $2`, sql, taskID); err != nil {
		f.t.Fatalf("rewrite child sql for task %d: %v", taskID, err)
	}
}

// auditRows reads the approval_lifecycle rows for a task, newest first — the durable record
// INV-A7-28 and INV-A7-29 are about. It reads the RAW columns rather than going through the audit
// reader, so a bug in the reader cannot make a missing row look present.
func (f *httpFixture) auditRows(taskID int64) []string {
	f.t.Helper()
	rows, err := f.fx.Store.Pool.Query(context.Background(),
		`SELECT statement FROM audit_event WHERE kind = 'approval_lifecycle' AND statement LIKE $1 ORDER BY id`,
		"approval #"+strconv.FormatInt(taskID, 10)+" %")
	if err != nil {
		f.t.Fatalf("read lifecycle audit rows: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			f.t.Fatalf("read lifecycle audit rows: %v", err)
		}
		out = append(out, s)
	}
	return out
}

// ---- fakes -----------------------------------------------------------------------------------

// fakeSession is one open editor session in [fakeRunExec].
type fakeSession struct {
	principal      string
	datasourceName string
}

// fakeRunExec stands in for the unported RunExecService (07 §7). It records what it was asked to do
// so a suite can assert "and it ran NOTHING", which is half of INV-A7-26's claim.
type fakeRunExec struct {
	mu sync.Mutex

	// response / err are what Run and RunOnSession answer.
	response query.QueryResponse
	err      error

	// openErr is what OpenSession answers.
	openErr error
	nextID  int

	sessions map[string]fakeSession

	runs        []RunInput
	sessionRuns []SessionRunInput
	cancels     []int64
	closed      []string
}

func (f *fakeRunExec) Run(_ context.Context, in RunInput) (query.QueryResponse, error) {
	f.mu.Lock()
	f.runs = append(f.runs, in)
	err, response := f.err, f.response
	f.mu.Unlock()
	if in.Preflight != nil && !in.Preflight() {
		return query.QueryResponse{}, &ProxyRunError{Message: "preflight refused the run"}
	}
	if err != nil {
		return query.QueryResponse{}, err
	}
	return response, nil
}

func (f *fakeRunExec) OpenSession(_ context.Context, principal string, ds datasource.Datasource, _ *string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.openErr != nil {
		return "", f.openErr
	}
	f.nextID++
	id := "sess-" + strconv.Itoa(f.nextID)
	f.sessions[id] = fakeSession{principal: principal, datasourceName: ds.Name}
	return id, nil
}

func (f *fakeRunExec) RunOnSession(_ context.Context, in SessionRunInput) (query.QueryResponse, error) {
	f.mu.Lock()
	f.sessionRuns = append(f.sessionRuns, in)
	err, response := f.err, f.response
	f.mu.Unlock()
	if err != nil {
		return query.QueryResponse{}, err
	}
	return response, nil
}

func (f *fakeRunExec) SessionDatasourceName(sessionID, principal string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[sessionID]
	if !ok || s.principal != principal { // 🔒 owner-scoped, exactly as RunExec.kt:503
		return "", false
	}
	return s.datasourceName, true
}

func (f *fakeRunExec) CloseSessionOwnedBy(sessionID, principal string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[sessionID]
	if !ok || s.principal != principal {
		return false
	}
	delete(f.sessions, sessionID)
	f.closed = append(f.closed, sessionID)
	return true
}

func (f *fakeRunExec) CancelActiveRun(_ context.Context, taskID int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancels = append(f.cancels, taskID)
	return true
}

func (f *fakeRunExec) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

// auditFailer wraps the real audit store so a suite can make Insert fail on demand — the only way to
// exercise 🔒 INV-A7-28.
type auditFailer struct {
	store   *audit.Store
	fixture *httpFixture
}

func (a *auditFailer) Get(ctx context.Context, id int64) (*types.AuditEvent, error) {
	return a.store.Get(ctx, id)
}

func (a *auditFailer) Insert(ctx context.Context, rec types.AuditEvent) (int64, error) {
	if a.fixture.auditFail != nil {
		return 0, a.fixture.auditFail
	}
	return a.store.Insert(ctx, rec)
}

func (a *auditFailer) InsertOn(ctx context.Context, c store.Queryer, rec types.AuditEvent) (int64, error) {
	if a.fixture.auditFail != nil {
		return 0, a.fixture.auditFail
	}
	return a.store.InsertOn(ctx, c, rec)
}

// ---- session fakes ----------------------------------------------------------------------------

type fakeStorage struct {
	mu   sync.Mutex
	keys map[string]int64
}

func newFakeStorage() *fakeStorage { return &fakeStorage{keys: map[string]int64{}} }

func (f *fakeStorage) Write(_ context.Context, key string, ref session.WebSessionRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[key] = ref.SessionID
	return nil
}

func (f *fakeStorage) Read(_ context.Context, key string) (session.WebSessionRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.keys[key]
	if !ok {
		return session.WebSessionRef{}, session.ErrUnknownWebSessionKey
	}
	return session.WebSessionRef{SessionID: id}, nil
}

func (f *fakeStorage) Invalidate(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, key)
	return nil
}

type fakeResolver struct {
	mu   sync.Mutex
	rows map[int64]*session.WebRow
}

func newFakeResolver() *fakeResolver { return &fakeResolver{rows: map[int64]*session.WebRow{}} }

func (f *fakeResolver) set(id int64, row *session.WebRow) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[id] = row
}

func (f *fakeResolver) endAll(principal string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, row := range f.rows {
		if row != nil && row.Principal == principal {
			f.rows[id] = nil
		}
	}
}

func (f *fakeResolver) ResolveWeb(_ context.Context, id int64, _ *string) (*session.WebRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rows[id], nil
}

func (f *fakeResolver) WebEndedReason(context.Context, int64) (*string, error) { return nil, nil }

// ---- assertions --------------------------------------------------------------------------------

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: got status %d, want %d (body: %s)", what, rec.Code, want, rec.Body.String())
	}
}

func assertCode(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not an ApiError (%v): %s", err, rec.Body.String())
	}
	if body.Code != want {
		t.Errorf("code: got %q, want %q (body: %s)", body.Code, want, rec.Body.String())
	}
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body.String())
	}
}

func idPath(prefix string, id int64, suffix string) string {
	return prefix + strconv.FormatInt(id, 10) + suffix
}
