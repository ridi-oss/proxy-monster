package app_test

// The FAKE PROXY, over the real gRPC wire, against the real composition root.
//
// This is the Go counterpart of GrpcRunExecDbTest.kt:73-167's fixture, and the property that makes it
// worth the machinery is the one its Kotlin doc states: the SAME [core.ControlPlaneCore] is wired into
// both RunExecService and ControlPlaneGrpcService, so the fake proxy's Events / RunExec streams land on
// the exact `proxyEventsHub` and `runChannels` the service registers into. A fixture that constructed a
// second core would answer 503 `query.no_proxy_attached` on every case with a "proxy" right there —
// which is precisely the wiring mistake app/http.go's comment warns about, and this harness is what
// would catch it.
//
// Nothing here fakes the control plane. The token is minted by the real token store into real Postgres,
// the connection id comes from the real connection catalog, the audit rows are in the real hash chain,
// and the requester-IP registry is the one the gRPC Decide handler reads. Only the PROXY is fake, and
// only in the sense that it fabricates verdicts instead of talking to a database — which is exactly what
// lets a test drive DENY, a malformed row, or a watchdog timeout on demand.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/app"
	"github.com/ridi-oss/proxy-monster/gocp/internal/approval"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/queryhistory"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/runexec"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// runFixtureResultKey is a 32-byte AES key, base64. PM_RESULT_KEY must be set or A7 refuses every
// approver-exec and editor submit with 503 `approval.result_storage_not_configured` — which would make
// the route halves of this file assert the refusal instead of the run.
const runFixtureResultKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// runGate bounds every wait in this file. It is the Kotlin's `withTimeout(5_000)`.
const runGate = 15 * time.Second

// runFixture is one booted control plane plus a datasource and the fake-proxy machinery.
type runFixture struct {
	*bootedApp
	t  *testing.T
	ds datasource.Datasource
	// svc is the SAME service instance the routes hold — reached through App.Surface, which is why that
	// field exists. GrpcRunExecDbTest calls openSession/runOnSession/cancelActiveRun directly, and a
	// second instance would keep its own openSessions map.
	svc *runexec.Service
	// results / history are SECOND instances over the same pool, deliberately.
	//
	// ⚠️ Unlike `svc`, these two are pure stores with no in-memory state — every method is one SQL
	// statement — so a second instance reads exactly what the routes wrote. Constructing them here
	// rather than exposing them on HTTPSurface keeps a test-only read path out of the production
	// struct; `svc` is on there because A1's purge loop genuinely needs it.
	results *result.Store
	history *queryhistory.Store
}

// newRunFixture boots the app with result storage enabled and creates one postgres datasource.
func newRunFixture(t *testing.T) *runFixture {
	t.Helper()
	b := bootE2EWith(t, map[string]string{"PM_RESULT_KEY": runFixtureResultKey})
	ds, err := b.app.Core.DatasourceStore.Create(context.Background(), datasource.DatasourceInput{
		Name: "editor-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
	})
	if err != nil {
		t.Fatalf("create datasource: %v", err)
	}
	if b.app.Surface == nil || b.app.Surface.RunExec == nil {
		t.Fatal("the booted app exposes no RunExec service — the wiring in app/http.go is what this file drives")
	}
	crypto, err := result.NewCrypto(b.app.Config.ResultKey)
	if err != nil {
		t.Fatalf("result crypto from PM_RESULT_KEY: %v", err)
	}
	return &runFixture{
		bootedApp: b, t: t, ds: ds, svc: b.app.Surface.RunExec,
		results: result.NewStore(b.app.Db.Pool, crypto),
		history: queryhistory.New(b.app.Db.Pool),
	}
}

// awaitAttached / awaitDetached are `awaitUntil("Events stream attached") { name in attached() }`.
func (f *runFixture) awaitAttached() { f.awaitUntil("Events stream attached", f.isAttached) }
func (f *runFixture) awaitDetached() {
	f.awaitUntil("Events stream detached", func() bool { return !f.isAttached() })
}

// isAttached reads the hub's in-memory liveness view — "the open stream IS the liveness signal".
func (f *runFixture) isAttached() bool {
	_, ok := f.app.Core.ProxyEventsHub.Attached()[f.ds.Name]
	return ok
}

func (f *runFixture) awaitUntil(what string, predicate func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(runGate)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatalf("timed out awaiting: %s", what)
}

// events opens an Events stream — the proxy's own attach — and returns the OpenRunChannel messages the
// control plane pushes down it.
//
// 🔒 THE DIRECTION IS THE INVARIANT (INV-A10-35 / INV-A12-12): the control plane NEVER dials a proxy. It
// writes back down this stream, which the "proxy" opened. Everything in this file therefore starts here.
func (f *runFixture) events() (<-chan *pb.OpenRunChannel, func()) {
	f.t.Helper()
	ctx, cancel := context.WithCancel(f.authed)
	stream, err := f.client.Events(ctx, &pb.EventsRequest{DatasourceName: f.ds.Name})
	if err != nil {
		cancel()
		f.t.Fatalf("open Events: %v", err)
	}
	opens := make(chan *pb.OpenRunChannel, 8)
	go func() {
		defer close(opens)
		for {
			ev, err := stream.Recv()
			if err != nil {
				return
			}
			if open := ev.GetOpenRunChannel(); open != nil {
				opens <- open
			}
		}
	}()
	f.awaitAttached()
	return opens, cancel
}

// nextOpen takes the next OpenRunChannel push, or fails.
func (f *runFixture) nextOpen(opens <-chan *pb.OpenRunChannel) *pb.OpenRunChannel {
	f.t.Helper()
	select {
	case open, ok := <-opens:
		if !ok {
			f.t.Fatal("the Events stream closed before an OpenRunChannel arrived")
		}
		return open
	case <-time.After(runGate):
		f.t.Fatal("no OpenRunChannel push arrived — the run never asked a proxy to dial")
		return nil
	}
}

// proxyBehaviour is what a fake proxy does with one RunQuery. It writes onto `send`.
type proxyBehaviour func(send func(*pb.ProxyRunMsg), q *pb.RunQuery)

// fakeProxy is one claimed RunExec stream, driven by a behaviour.
type fakeProxy struct {
	t *testing.T
	// mu guards the three counters, which the test goroutine polls while the stream loop writes them.
	mu sync.Mutex
	// queries records every RunQuery the control plane dispatched, IN ORDER — the proof a persistent
	// session reuses ONE stream instead of dialing per statement.
	queries []string
	cancels int
	closes  int
	// closed is shut when the stream loop exits, which happens on the RunClose.
	closed chan struct{}
}

// dial claims `sessionID` with a Ready and then services control messages with `behave`.
//
// 🔒 The Ready is what CLAIMS the session (INV-A7-32), and it must be the FIRST message on the stream or
// the handler answers FAILED_PRECONDITION. Everything after it is relayed to the run's private inbound
// channel.
func (f *runFixture) dial(sessionID string, behave proxyBehaviour) *fakeProxy {
	f.t.Helper()
	ctx, cancel := context.WithCancel(f.authed)
	stream, err := f.client.RunExec(ctx)
	if err != nil {
		cancel()
		f.t.Fatalf("open RunExec: %v", err)
	}
	p := &fakeProxy{t: f.t, closed: make(chan struct{})}
	if err := stream.Send(&pb.ProxyRunMsg{
		Kind: &pb.ProxyRunMsg_SessionReady{SessionReady: &pb.RunReady{SessionId: sessionID}},
	}); err != nil {
		cancel()
		f.t.Fatalf("send RunReady: %v", err)
	}
	// send serialises the fake proxy's writes: a behaviour runs on its own goroutine (so a held query
	// does not stop the control-message loop), and grpc-go forbids concurrent Send on one stream.
	var sendMu sync.Mutex
	send := func(msg *pb.ProxyRunMsg) {
		sendMu.Lock()
		defer sendMu.Unlock()
		// A send failure after the stream is gone is expected on the teardown paths and is not a
		// failure of the case; the assertions are all on what the CONTROL PLANE did.
		_ = stream.Send(msg)
	}
	go func() {
		defer close(p.closed)
		for {
			control, err := stream.Recv()
			if err != nil {
				return
			}
			switch {
			case control.GetQuery() != nil:
				p.mu.Lock()
				p.queries = append(p.queries, control.GetQuery().GetSql())
				p.mu.Unlock()
				// A behaviour may block (holding a run in flight), so it runs on its own goroutine —
				// otherwise a held query would also stop this loop from seeing the RunCancel that
				// releases it.
				go behave(send, control.GetQuery())
			case control.GetCancel() != nil:
				p.mu.Lock()
				p.cancels++
				p.mu.Unlock()
			case control.GetClose() != nil:
				p.mu.Lock()
				p.closes++
				p.mu.Unlock()
				_ = stream.CloseSend()
				return
			default:
				p.t.Error("the control plane sent an empty run control message")
				return
			}
		}
	}()
	f.t.Cleanup(cancel)
	return p
}

// awaitClosed waits for the RunClose that ends the stream.
//
// 🔒 That close is INV-A7-36's payoff: without the cleanup's recovery dance the proxy would hold its
// backend connection forever, and this wait is what would hang.
func (p *fakeProxy) awaitClosed() {
	p.t.Helper()
	select {
	case <-p.closed:
	case <-time.After(runGate):
		p.t.Fatal("the run stream never received its RunClose — the proxy would hold its backend connection forever")
	}
}

func (p *fakeProxy) seenQueries() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.queries...)
}

func (p *fakeProxy) cancelCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cancels
}

// awaitCancel waits for a RunCancel to reach the stream.
func (p *fakeProxy) awaitCancel() {
	p.t.Helper()
	deadline := time.Now().Add(runGate)
	for time.Now().Before(deadline) {
		if p.cancelCount() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	p.t.Fatal("no RunCancel reached the stream")
}

// ---- fake-proxy behaviours ---------------------------------------------------------------------

// allowRows answers ALLOW, one chunk, then Done(-1).
func allowRows(columns []string, rows ...[]*string) proxyBehaviour {
	return func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW}))
		if columns != nil {
			send(rowsOf(columns, rows...))
		}
		send(doneOf(-1))
	}
}

// echoQuery answers ALLOW plus a single row echoing the statement — GrpcRunExecDbTest's persistent-
// session behaviour, which is how "all queries ran on the SAME held stream" becomes observable.
func echoQuery(send func(*pb.ProxyRunMsg), q *pb.RunQuery) {
	sql := q.GetSql()
	send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW}))
	send(rowsOf([]string{"echo"}, []*string{&sql}))
	send(doneOf(-1))
}

func decisionOf(d *pb.RunDecision) *pb.ProxyRunMsg {
	return &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Decision{Decision: d}}
}

func doneOf(rowsAffected int32) *pb.ProxyRunMsg {
	return &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Done{Done: &pb.RunDone{RowsAffected: rowsAffected}}}
}

func errorOf(message string) *pb.ProxyRunMsg {
	return &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_Error{Error: &pb.RunError{Message: message}}}
}

// rowsOf is GrpcRunExecDbTest's `rowsChunk(columns, rows)`.
func rowsOf(columns []string, rows ...[]*string) *pb.ProxyRunMsg {
	wire := make([]*pb.RunRow, 0, len(rows))
	for _, row := range rows {
		values := make([]*pb.RunValue, 0, len(row))
		for _, cell := range row {
			if cell == nil {
				values = append(values, &pb.RunValue{IsNull: true})
				continue
			}
			values = append(values, &pb.RunValue{Value: *cell})
		}
		wire = append(wire, &pb.RunRow{Values: values})
	}
	return &pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_ResultRows{ResultRows: &pb.RunResultRows{
		Columns: columns, Rows: wire,
	}}}
}

// ---- assertions over real state ---------------------------------------------------------------

// tokenResolves reports the principal on a live ephemeral token, or "" once it is revoked.
func (f *runFixture) tokenResolves(tok string) string {
	f.t.Helper()
	id, err := f.app.Core.TokenStore.Resolve(context.Background(), tok)
	if err != nil {
		f.t.Fatalf("resolve token: %v", err)
	}
	if id == nil {
		return ""
	}
	return id.Principal
}

// tokenIdentity is the full row `resolve` projects — principal, roles snapshot and kind.
func (f *runFixture) tokenIdentity(tok string) *token.Identity {
	f.t.Helper()
	id, err := f.app.Core.TokenStore.Resolve(context.Background(), tok)
	if err != nil {
		f.t.Fatalf("resolve token: %v", err)
	}
	return id
}

// carriedIP is `core.runRequesterIps.get(tokenHash(token))` — the decide-time carrier, keyed by the
// token's SHA-256 hash and never the raw token.
func (f *runFixture) carriedIP(tok string) *string {
	return f.app.Core.RunRequesterIPs.Get(token.Hash(tok))
}

// activeEphemeralTokens counts LIVE tokens of a kind for a principal, straight from the table — the
// Kotlin's `activeEditorTokens` helper.
func (f *runFixture) activeEphemeralTokens(principal string, kind token.Kind) int {
	f.t.Helper()
	var n int
	err := f.app.Db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM proxy_token
		     WHERE principal = $1 AND kind = $2 AND revoked_at IS NULL AND expires_at > now()`,
		principal, string(kind)).Scan(&n)
	if err != nil {
		f.t.Fatalf("count active tokens: %v", err)
	}
	return n
}

// insertAudit writes one audit row so `piiTouched` has something real to be read back from.
func (f *runFixture) insertAudit(decision string, piiTouched []string) int64 {
	f.t.Helper()
	event := types.NewAuditEvent("editor-user", f.ds.Name, "select test", types.Decision(decision))
	event.PIITouched = piiTouched
	id, err := f.app.Core.AuditStore.Insert(context.Background(), event)
	if err != nil {
		f.t.Fatalf("insert audit: %v", err)
	}
	return id
}

// ---- HTTP helpers -----------------------------------------------------------------------------

// post/get/del drive the REAL HTTP surface on the booted app.
func (f *runFixture) do(method, path, body string) (int, []byte) {
	f.t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", f.app.HTTPPort(), path)
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		f.t.Fatalf("build %s %s: %v", method, path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// decodeInto unmarshals a response body or fails with it attached.
func decodeInto(t *testing.T, raw []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("decode %T: %v (body: %s)", dst, err, raw)
	}
}

// bootE2EWith is [bootE2E] with extra env. It exists because A7's paths need PM_RESULT_KEY, which
// bootE2E deliberately leaves unset so its own cases exercise the no-crypto posture.
func bootE2EWith(t *testing.T, extra map[string]string) *bootedApp {
	t.Helper()
	backend := dbtest.Postgres(t)
	dbName := dbtest.FreshPostgresDatabase(t, "runexec")

	env := map[string]string{
		"PM_HTTP_PORT": "0",
		"PM_GRPC_PORT": "0",
		"PM_DB_URL":    backend.PostgresJDBCURL(dbName),
		"PM_DB_USER":   "proxymonster",
		"PM_DEV":       "true",
	}
	for k, v := range extra {
		env[k] = v
	}
	cfg, err := config.FromEnv(config.EnvOf(env))
	if err != nil {
		t.Fatalf("config rejected: %v", err)
	}
	cfg.DBUser, cfg.DBPassword = credsFromJDBC(t, backend.PostgresDSN(dbName))

	a, err := app.Boot(cfg, app.Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if err := a.StartHTTP(); err != nil {
		t.Fatalf("StartHTTP: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.Shutdown(ctx)
	})

	conn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", a.Grpc.BoundPort()),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial gRPC: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return &bootedApp{app: a, client: pb.NewControlPlaneClient(conn), authed: context.Background(), dbName: dbName}
}

// runInput is a shorthand for the one-shot path's parameter list.
func runInput(principal string, ds datasource.Datasource, sql string, maxRows int) query.RunInput {
	return query.RunInput{Principal: principal, Datasource: ds, SQL: sql, MaxRows: maxRows}
}

// ---- result-store and task reads --------------------------------------------------------------

// meta is `resultStore.meta(taskId)` — the child's metadata row.
func (f *runFixture) meta(taskID int64) *result.QueryResultMeta {
	f.t.Helper()
	m, err := f.results.Meta(context.Background(), taskID)
	if err != nil {
		f.t.Fatalf("read result meta for task %d: %v", taskID, err)
	}
	return m
}

// savedRows is `resultStore.accessFor(taskId)!!.decrypted!!.rows` — it FAILS if there is nothing
// readable, so a case that expects rows says so.
func (f *runFixture) savedRows(taskID int64) [][]*string {
	f.t.Helper()
	rows := f.savedRowsOrNil(taskID)
	if rows == nil {
		f.t.Fatalf("task %d has no readable stored result", taskID)
	}
	return rows
}

// savedRowsOrNil is the same read, tolerating absence — which is what a fail-closed case asserts.
//
// 🔒 It goes through [result.ResultAccess.Decrypted], the LAZY decrypt, so a case that expects no rows
// proves the payload is genuinely absent rather than merely unread.
func (f *runFixture) savedRowsOrNil(taskID int64) [][]*string {
	f.t.Helper()
	access, err := f.results.AccessFor(context.Background(), taskID)
	if err != nil {
		f.t.Fatalf("read result access for task %d: %v", taskID, err)
	}
	if access == nil {
		return nil
	}
	decrypted, err := access.Decrypted()
	if err != nil {
		f.t.Fatalf("decrypt result for task %d: %v", taskID, err)
	}
	if decrypted == nil {
		return nil
	}
	return decrypted.Rows
}

// editorChildID is `accessStore.editorChildId(taskId)`.
func (f *runFixture) editorChildID(taskID int64) int64 {
	f.t.Helper()
	id, err := f.app.Core.AccessStore.EditorChildID(context.Background(), taskID)
	if err != nil {
		f.t.Fatalf("read editor child id: %v", err)
	}
	if id == nil {
		return -1
	}
	return *id
}

// recentHistory is `historyStore.recent(principal, limit)`.
func (f *runFixture) recentHistory(principal string, limit int) []queryhistory.Entry {
	f.t.Helper()
	entries, err := f.history.Recent(context.Background(), principal, limit)
	if err != nil {
		f.t.Fatalf("read query history: %v", err)
	}
	return entries
}

// accessQueryRequestInput is ApprovalExecuteRouteDbTest's seed call, spelled out.
//
// `roleId` is what selects the execute-under-R branch at `/execute`: it populates `execute_as`, and
// without it the route answers 409 `approval.no_execute_role` (INV-A7-2) rather than running.
func accessQueryRequestInput(principal string, datasourceID int64, sql string, roleID int64) access.CreateQueryRequestInput {
	evaluated := "DENY"
	reason := "need it"
	return access.CreateQueryRequestInput{
		Principal:         principal,
		DatasourceID:      datasourceID,
		SQL:               sql,
		Reason:            &reason,
		EvaluatedDecision: &evaluated,
		RoleID:            &roleID,
	}
}

// taskEvents subscribes to the SSE stream `GET /api/tasks/events` and decodes the TaskEvent frames.
//
// It is the transport half of EditorSubmitRouteDbTest's `hub.subscribe(caller)`: the Kotlin reaches the
// hub object directly because it constructs it, while here the hub lives inside the booted app and the
// only way in is the route it feeds — which is the stronger observation anyway, since it also proves the
// event survives serialisation and the `task_read` push filter.
func (f *runFixture) taskEvents() (<-chan approval.TaskEvent, func()) {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d/api/tasks/events", f.app.HTTPPort()), nil)
	if err != nil {
		cancel()
		f.t.Fatalf("build the SSE request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		f.t.Fatalf("open the SSE stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		f.t.Fatalf("GET /api/tasks/events → %d, want 200", resp.StatusCode)
	}
	events := make(chan approval.TaskEvent, 8)
	go func() {
		defer close(events)
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			payload, ok := strings.CutPrefix(line, "data: ")
			if !ok {
				continue
			}
			var ev approval.TaskEvent
			if err := json.Unmarshal([]byte(payload), &ev); err != nil {
				continue
			}
			events <- ev
		}
	}()
	return events, cancel
}

// runexecQueryTimeoutMessage is runexec.QueryTimeoutMessage, named locally so the route test reads as a
// wire fixture rather than as a reference to the implementation it is checking.
const runexecQueryTimeoutMessage = runexec.QueryTimeoutMessage
