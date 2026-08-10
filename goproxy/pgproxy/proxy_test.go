package pgproxy_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/db"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/pgproxy"
	"github.com/ridi-oss/proxy-monster/goproxy/proxytls"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	primarySchema   = "it_pgproxy"
	secondarySchema = "it_pgproxy2"
	validToken      = "it-token-ok"
)

type fakeControlPlane struct {
	pb.UnimplementedControlPlaneServer

	mu           sync.Mutex
	validateErr  error
	validateFn   func(*pb.ValidateTokenRequest) (*pb.WireIdentity, error)
	onOpen       []*pb.ProxyCommand
	decideFn     func(*pb.DecisionRequest) (*pb.WireDecision, error)
	decideReqs   []*pb.DecisionRequest
	fragmentReqs []*pb.SchemaFragmentPush
	pushErr      error
	closeReqs    []*pb.CloseConnectionRequest
	completions  []*pb.CompletionReport
	events       []string
}

func (f *fakeControlPlane) ValidateToken(_ context.Context, req *pb.ValidateTokenRequest) (*pb.WireIdentity, error) {
	f.mu.Lock()
	validateErr := f.validateErr
	validateFn := f.validateFn
	onOpen := proto.Clone(&pb.WireIdentity{OnOpen: f.onOpen}).(*pb.WireIdentity).GetOnOpen()
	f.mu.Unlock()
	if validateErr != nil {
		return nil, validateErr
	}
	if req.GetToken() != validToken {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if validateFn != nil {
		return validateFn(proto.Clone(req).(*pb.ValidateTokenRequest))
	}
	return &pb.WireIdentity{
		Principal:    "pg-it@example.com",
		Roles:        []string{"analyst"},
		ConnectionId: []byte("0123456789abcdef"),
		OnOpen:       onOpen,
	}, nil
}

func (f *fakeControlPlane) Decide(_ context.Context, req *pb.DecisionRequest) (*pb.WireDecision, error) {
	cloned := proto.Clone(req).(*pb.DecisionRequest)
	f.mu.Lock()
	f.decideReqs = append(f.decideReqs, cloned)
	f.events = append(f.events, "decide:"+cloned.GetSql())
	decideFn := f.decideFn
	f.mu.Unlock()
	if decideFn != nil {
		return decideFn(cloned)
	}
	return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
}

func (f *fakeControlPlane) PushSchemaFragment(_ context.Context, req *pb.SchemaFragmentPush) (*pb.SchemaFragmentAck, error) {
	cloned := proto.Clone(req).(*pb.SchemaFragmentPush)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fragmentReqs = append(f.fragmentReqs, cloned)
	f.events = append(f.events, "push:"+cloned.GetSchema())
	if f.pushErr != nil {
		return nil, f.pushErr
	}
	return &pb.SchemaFragmentAck{Generation: uint64(len(f.fragmentReqs))}, nil
}

func (f *fakeControlPlane) CloseConnection(_ context.Context, req *pb.CloseConnectionRequest) (*pb.CloseConnectionResponse, error) {
	cloned := proto.Clone(req).(*pb.CloseConnectionRequest)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeReqs = append(f.closeReqs, cloned)
	return &pb.CloseConnectionResponse{}, nil
}

func (f *fakeControlPlane) ReportCompletion(_ context.Context, req *pb.CompletionReport) (*emptypb.Empty, error) {
	cloned := proto.Clone(req).(*pb.CompletionReport)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completions = append(f.completions, cloned)
	f.events = append(f.events, "completion")
	return &emptypb.Empty{}, nil
}

func (f *fakeControlPlane) completionReports() []*pb.CompletionReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*pb.CompletionReport, len(f.completions))
	for i, req := range f.completions {
		out[i] = proto.Clone(req).(*pb.CompletionReport)
	}
	return out
}

// waitCompletions polls until at least n completion reports have arrived (emission is fired asynchronously
// off the session's critical path) or fails after a generous deadline.
func (h *brokerHarness) waitCompletions(t *testing.T, n int) []*pb.CompletionReport {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := h.fake.completionReports()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("completion reports = %d, want >= %d", len(got), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func wireVerdict(verdict *pb.Verdict) *pb.WireDecision {
	return &pb.WireDecision{Outcome: &pb.WireDecision_Verdict{Verdict: verdict}}
}

func (f *fakeControlPlane) requests() []*pb.DecisionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	requests := make([]*pb.DecisionRequest, len(f.decideReqs))
	for i, request := range f.decideReqs {
		requests[i] = proto.Clone(request).(*pb.DecisionRequest)
	}
	return requests
}

func (f *fakeControlPlane) fragmentRequests() []*pb.SchemaFragmentPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	requests := make([]*pb.SchemaFragmentPush, len(f.fragmentReqs))
	for i, request := range f.fragmentReqs {
		requests[i] = proto.Clone(request).(*pb.SchemaFragmentPush)
	}
	return requests
}

func (f *fakeControlPlane) eventLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *fakeControlPlane) setPushError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushErr = err
}

func (f *fakeControlPlane) setOnOpen(commands ...*pb.ProxyCommand) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onOpen = proto.Clone(&pb.WireIdentity{OnOpen: commands}).(*pb.WireIdentity).GetOnOpen()
}

func (f *fakeControlPlane) setValidateFunc(validate func(*pb.ValidateTokenRequest) (*pb.WireIdentity, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validateFn = validate
}

func (f *fakeControlPlane) closeRequests() []*pb.CloseConnectionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	requests := make([]*pb.CloseConnectionRequest, len(f.closeReqs))
	for i, request := range f.closeReqs {
		requests[i] = proto.Clone(request).(*pb.CloseConnectionRequest)
	}
	return requests
}

func startFakeCP(t *testing.T) (*fakeControlPlane, *cp.Client) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake control plane: %v", err)
	}
	fake := &fakeControlPlane{}
	server := grpc.NewServer()
	pb.RegisterControlPlaneServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	client, err := cp.New(listener.Addr().String(), "secret-abc", "ds-it")
	if err != nil {
		t.Fatalf("cp.New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return fake, client
}

func seedTargetDb(t *testing.T) dbtest.TargetDb {
	t.Helper()
	targetDb := dbtest.Postgres(t)
	seed := dbtest.OpenPostgres(t, "")
	statements := []string{
		"CREATE SCHEMA IF NOT EXISTS " + primarySchema,
		"CREATE SCHEMA IF NOT EXISTS " + secondarySchema,
		"CREATE TABLE IF NOT EXISTS " + primarySchema + ".people (id int PRIMARY KEY, name text, ssn text)",
		"CREATE TABLE IF NOT EXISTS " + secondarySchema + ".people (id int PRIMARY KEY, name text, ssn text)",
		"CREATE TABLE IF NOT EXISTS " + primarySchema + ".prepared_notes (id int PRIMARY KEY, note text)",
		"DELETE FROM " + primarySchema + ".prepared_notes",
		"DELETE FROM " + primarySchema + ".people",
		"INSERT INTO " + primarySchema + ".people (id, name, ssn) VALUES (1, 'Alice', '987-65-4320'), (2, 'Bob', NULL)",
		"DELETE FROM " + secondarySchema + ".people",
		"INSERT INTO " + secondarySchema + ".people (id, name, ssn) VALUES (10, 'Secondary', 'secret-2')",
	}
	for _, statement := range statements {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("seed statement %q: %v", statement, err)
		}
	}
	return targetDb
}

type brokerHarness struct {
	fake   *fakeControlPlane
	addr   string
	server *pgproxy.Server
}

func startBroker(t *testing.T) *brokerHarness {
	t.Helper()
	targetDb := seedTargetDb(t)
	return startBrokerForDB(t, targetDb, "app")
}

// startBrokerForDB starts a broker whose service-account target points at a specific target database, so a
// test can exercise a session created under that database's stored GUC defaults (e.g. ALTER DATABASE ...
// SET standard_conforming_strings=off). The client's requested database is irrelevant — the proxy always
// dials its configured target.
func startBrokerForDB(t *testing.T, targetDb dbtest.TargetDb, database string) *brokerHarness {
	t.Helper()
	return startBrokerForDBSetup(t, targetDb, database, nil)
}

func startBrokerForDBSetup(t *testing.T, targetDb dbtest.TargetDb, database string, setup func(*fakeControlPlane)) *brokerHarness {
	t.Helper()
	fake, cpClient := startFakeCP(t)
	if setup != nil {
		setup(fake)
	}
	target := spi.TargetDb{
		Host:     targetDb.Host,
		Port:     targetDb.Port,
		Db:       database,
		User:     targetDb.User,
		Password: targetDb.Password,
	}
	server := pgproxy.New(0, target, cpClient, db.PgDb{}, nil)
	return startBrokerServer(t, fake, server)
}

func startBrokerTLS(t *testing.T) *brokerHarness {
	t.Helper()
	targetDb := seedTargetDb(t)
	fake, cpClient := startFakeCP(t)
	tlsProvider := proxytls.NewReloading("../proxytls/testdata/ec.crt", "../proxytls/testdata/ec-sec1.key")
	target := spi.TargetDb{
		Host:     targetDb.Host,
		Port:     targetDb.Port,
		Db:       "app",
		User:     targetDb.User,
		Password: targetDb.Password,
	}
	server := pgproxy.New(0, target, cpClient, db.PgDb{}, tlsProvider.Current)
	return startBrokerServer(t, fake, server)
}

func startBrokerServer(t *testing.T, fake *fakeControlPlane, server *pgproxy.Server) *brokerHarness {
	t.Helper()
	if err := server.Listen(); err != nil {
		t.Fatalf("pgproxy.Listen: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	t.Cleanup(func() {
		server.Shutdown()
		if err := <-serveDone; err != nil {
			t.Errorf("pgproxy.Serve: %v", err)
		}
	})
	return &brokerHarness{fake: fake, addr: server.Addr().String(), server: server}
}

func (h *brokerHarness) connect(t *testing.T, token string, simple bool) (*pgx.Conn, error) {
	t.Helper()
	config, err := pgx.ParseConfig(fmt.Sprintf("postgres://pm:%s@%s/app", token, h.addr))
	if err != nil {
		t.Fatalf("pgx.ParseConfig: %v", err)
	}
	if simple {
		config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	}
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err == nil {
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
	}
	return conn, err
}

func beforeDecide(commands ...*pb.ProxyCommand) *pb.WireDecision {
	return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{
		BeforeDecide: &pb.BeforeDecide{Commands: commands},
	}}
}

func refreshDecision(schema string) *pb.WireDecision {
	return wireVerdict(&pb.Verdict{
		Decision: pb.EnfAction_ALLOW,
		AfterStatement: []*pb.ProxyCommand{{
			Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: schema}},
		}},
	})
}

func fragmentHasColumn(fragment *pb.SchemaFragmentPush, schema, table, column string) bool {
	if fragment == nil {
		return false
	}
	for _, candidate := range fragment.GetColumns() {
		if candidate.GetSchema() == schema && candidate.GetTable() == table && candidate.GetColumn() == column {
			return true
		}
	}
	return false
}

func waitForFragmentRequests(t *testing.T, fake *fakeControlPlane, count int) []*pb.SchemaFragmentPush {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		requests := fake.fragmentRequests()
		if len(requests) >= count {
			return requests
		}
		if time.Now().After(deadline) {
			t.Fatalf("fragment pushes = %d, want at least %d", len(requests), count)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForCloseRequests(t *testing.T, fake *fakeControlPlane, count int) []*pb.CloseConnectionRequest {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		requests := fake.closeRequests()
		if len(requests) >= count {
			return requests
		}
		if time.Now().After(deadline) {
			t.Fatalf("close requests = %d, want at least %d", len(requests), count)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAllowRelaysRowsAndDecisionContext(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 1}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	const query = "SELECT id, name, ssn FROM it_pgproxy.people ORDER BY id"
	rows, err := conn.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()

	var got [][]any
	for rows.Next() {
		var id int
		var name string
		var ssn *string
		if err := rows.Scan(&id, &name, &ssn); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got = append(got, []any{id, name, ssn})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	ssn := "987-65-4320"
	want := [][]any{{1, "Alice", &ssn}, {2, "Bob", (*string)(nil)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %#v, want %#v", got, want)
	}

	requests := h.fake.requests()
	if len(requests) != 1 {
		t.Fatalf("Decide requests = %d, want 1", len(requests))
	}
	request := requests[0]
	if request.GetToken() != validToken || request.GetSql() != query || !reflect.DeepEqual(request.GetSearchPath(), []string{"pg_catalog", "public"}) {
		t.Fatalf("DecisionRequest = %+v, want token/query/default search path", request)
	}
	if !reflect.DeepEqual(request.GetConnectionId(), []byte("0123456789abcdef")) {
		t.Fatalf("DecisionRequest connection_id = %x, want minted id", request.GetConnectionId())
	}
}

func TestMaskRewritesRowsAndPreservesNull(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)}},
		}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	rows, err := conn.Query(context.Background(), "SELECT id, name, ssn FROM it_pgproxy.people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()

	var ids []int
	var names []string
	var ssns []*string
	for rows.Next() {
		var id int
		var name string
		var ssn *string
		if err := rows.Scan(&id, &name, &ssn); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		ids = append(ids, id)
		names = append(names, name)
		ssns = append(ssns, ssn)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	masked := "####"
	if !reflect.DeepEqual(ids, []int{1, 2}) || !reflect.DeepEqual(names, []string{"Alice", "Bob"}) || !reflect.DeepEqual(ssns, []*string{&masked, nil}) {
		t.Fatalf("masked rows: ids=%v names=%v ssns=%v", ids, names, ssns)
	}
}

func TestDenyLeaksNoRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "ssn is off-limits"}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	rows, err := conn.Query(context.Background(), "SELECT id, name, ssn FROM it_pgproxy.people ORDER BY id")
	if err != nil {
		assertPgError(t, err, "42501", "proxy-monster denied: ssn is off-limits")
		return
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	if count != 0 {
		t.Fatalf("scanned rows = %d, want 0", count)
	}
	assertPgError(t, rows.Err(), "42501", "proxy-monster denied: ssn is off-limits")
}

func TestUnbindableMaskLeaksNoRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(99)}},
		}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	rows, err := conn.Query(context.Background(), "SELECT id, name, ssn FROM it_pgproxy.people ORDER BY id")
	if err != nil {
		assertPgError(t, err, "0A000", "required mask could not be bound")
		return
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	if count != 0 {
		t.Fatalf("scanned rows = %d, want 0", count)
	}
	assertPgError(t, rows.Err(), "0A000", "required mask could not be bound")
}

// TestEmptyStringSsnRoundTripsDistinctFromNullThroughMask guards that the mask path preserves the
// value/NULL distinction for a zero-length string. An empty non-NULL ssn must round-trip as a length-0
// value (masked LAST_N of a 0-unit string is the 0-unit string), never collapsed into NULL, while an
// actual NULL ssn stays NULL. This exercises the wire NULL (length -1) vs empty (length 0) boundary
// through decode -> RowMasker.Apply -> encode.
func TestEmptyStringSsnRoundTripsDistinctFromNullThroughMask(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "LAST_N", Ordinal: proto.Int32(2)}},
		}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	// id 2 (Bob) has ssn NULL from the seed; add id 3 with a non-NULL empty-string ssn.
	if _, err := conn.Exec(ctx, "INSERT INTO "+primarySchema+".people (id, name, ssn) VALUES (3, 'Empty', '')"); err != nil {
		t.Fatalf("insert empty-ssn row: %v", err)
	}
	rows, err := conn.Query(ctx, "SELECT id, name, ssn FROM "+primarySchema+".people WHERE id IN (2, 3) ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()

	var ssns []*string
	for rows.Next() {
		var id int
		var name string
		var ssn *string
		if err := rows.Scan(&id, &name, &ssn); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		ssns = append(ssns, ssn)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	if len(ssns) != 2 {
		t.Fatalf("scanned %d rows, want 2", len(ssns))
	}
	if ssns[0] != nil {
		t.Fatalf("NULL ssn (id 2) round-tripped as %q, want nil", *ssns[0])
	}
	if ssns[1] == nil {
		t.Fatalf("empty-string ssn (id 3) round-tripped as NULL, want a length-0 value")
	}
	if *ssns[1] != "" {
		t.Fatalf("empty-string ssn (id 3) round-tripped as %q, want \"\"", *ssns[1])
	}
}

// TestCopyOutResponseFailsClosed guards the relay's COPY backstop: the broker does not support the COPY
// subprotocol, so a target DB CopyOutResponse must fail closed (0A000) rather than desynchronize the wire.
func TestCopyOutResponseFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err = conn.Exec(context.Background(), "COPY (SELECT id FROM "+primarySchema+".people) TO STDOUT")
	assertPgError(t, err, "0A000", "COPY is not supported")
}

func TestSearchPathChangeIsReprobedOnSameConnection(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := conn.Exec(context.Background(), "SET search_path TO it_pgproxy2"); err != nil {
		t.Fatalf("SET search_path: %v", err)
	}
	rows, err := conn.Query(context.Background(), "SELECT id, name FROM people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	if !reflect.DeepEqual(ids, []int{10}) {
		t.Fatalf("secondary rows = %v, want [10]", ids)
	}
	requests := h.fake.requests()
	if len(requests) != 2 {
		t.Fatalf("Decide requests = %d, want 2 (probes never call Decide)", len(requests))
	}
	if !reflect.DeepEqual(requests[0].GetSearchPath(), []string{"pg_catalog", "public"}) {
		t.Fatalf("SET SearchPath = %v", requests[0].GetSearchPath())
	}
	if !reflect.DeepEqual(requests[1].GetSearchPath(), []string{"pg_catalog", secondarySchema}) {
		t.Fatalf("post-SET SearchPath = %v, want [pg_catalog %s]", requests[1].GetSearchPath(), secondarySchema)
	}
}

// TestOpenTransactionStillReprobesNamespace guards probe-always across a transaction boundary. Entering
// a transaction must NOT freeze the namespace: after a statement that leaves the session in an open
// transaction (here BEGIN — a single-CommandComplete 'I'->'T' opener, the exact wire signature a prior
// "reuse the cache, skip the probe" optimization special-cased), a later bare read must still re-probe
// the effective search_path so it binds against the current namespace, not a stale cached one. The relay
// never infers "this opener changed nothing" from the wire signature — a top-level routine could carry
// the same signature while mutating search_path, so the probe is unconditional. `search_path` is not a
// GUC_REPORT parameter, so this re-probe is the ONLY thing that keeps the post-change bind correct.
func TestOpenTransactionStillReprobesNamespace(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	// Change the namespace while the transaction is open. Only a re-probe of the effective search_path
	// (search_path emits no GUC_REPORT ParameterStatus) lets the following bare read bind to it_pgproxy2.
	if _, err := conn.Exec(ctx, "SET search_path TO "+secondarySchema); err != nil {
		t.Fatalf("SET search_path in transaction: %v", err)
	}
	rows, err := conn.Query(ctx, "SELECT id, name FROM people ORDER BY id")
	if err != nil {
		t.Fatalf("Query inside transaction: %v", err)
	}
	var ids []int
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			t.Fatalf("Scan: %v", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	if !reflect.DeepEqual(ids, []int{10}) {
		t.Fatalf("post-open-transaction rows = %v, want [10] (bare read re-probed to %s)", ids, secondarySchema)
	}
	if _, err := conn.Exec(ctx, "COMMIT"); err != nil {
		t.Fatalf("COMMIT: %v", err)
	}

	requests := h.fake.requests()
	if len(requests) != 4 {
		t.Fatalf("Decide requests = %d, want 4 (BEGIN, SET, SELECT, COMMIT; probes never call Decide)", len(requests))
	}
	// The bare read (request index 2) must have been authorized against the re-probed namespace.
	if !reflect.DeepEqual(requests[2].GetSearchPath(), []string{"pg_catalog", secondarySchema}) {
		t.Fatalf("in-transaction read SearchPath = %v, want [pg_catalog %s] (namespace was not re-probed after entering the transaction)", requests[2].GetSearchPath(), secondarySchema)
	}
}

func TestCatalogRefreshAfterAutocommitDDLBeforeNextDecision(t *testing.T) {
	h := startBroker(t)
	const (
		tableName    = "refresh_autocommit"
		createSQL    = "CREATE TABLE " + primarySchema + "." + tableName + " (id int)"
		alterSQL     = "ALTER TABLE " + primarySchema + "." + tableName + " ADD COLUMN note text"
		followingSQL = "SELECT 1"
	)
	direct := dbtest.OpenPostgres(t, "")
	if _, err := direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName); err != nil {
		t.Fatalf("drop stale refresh table: %v", err)
	}
	t.Cleanup(func() { _, _ = direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName) })

	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		switch request.GetSql() {
		case createSQL, alterSQL:
			return refreshDecision(primarySchema), nil
		default:
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
		}
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, createSQL); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}
	requests := waitForFragmentRequests(t, h.fake, 1)
	if len(requests) != 1 || !fragmentHasColumn(requests[0], primarySchema, tableName, "id") {
		t.Fatalf("catalog pushes after CREATE = %#v, want one snapshot containing %s.%s.id", requests, primarySchema, tableName)
	}
	if _, err := conn.Exec(ctx, alterSQL); err != nil {
		t.Fatalf("ALTER TABLE: %v", err)
	}
	requests = waitForFragmentRequests(t, h.fake, 2)
	if len(requests) != 2 || !fragmentHasColumn(requests[1], primarySchema, tableName, "note") {
		t.Fatalf("catalog pushes after ALTER = %#v, want second snapshot containing %s.%s.note", requests, primarySchema, tableName)
	}
	if _, err := conn.Exec(ctx, followingSQL); err != nil {
		t.Fatalf("following SELECT: %v", err)
	}
	events := h.fake.eventLog()
	want := []string{"decide:" + createSQL, "push:" + primarySchema, "decide:" + alterSQL, "push:" + primarySchema, "decide:" + followingSQL}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("CP event order = %v, want %v", events, want)
	}
}

func TestCatalogRefreshRunsImmediatelyInsideTransaction(t *testing.T) {
	h := startBroker(t)
	const (
		tableName = "refresh_commit"
		ddlSQL    = "CREATE TABLE " + primarySchema + "." + tableName + " (id int)"
	)
	direct := dbtest.OpenPostgres(t, "")
	if _, err := direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName); err != nil {
		t.Fatalf("drop stale refresh table: %v", err)
	}
	t.Cleanup(func() { _, _ = direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName) })
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == ddlSQL {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	if _, err := conn.Exec(ctx, ddlSQL); err != nil {
		t.Fatalf("DDL in transaction: %v", err)
	}
	requests := waitForFragmentRequests(t, h.fake, 1)
	if len(requests) != 1 || !fragmentHasColumn(requests[0], primarySchema, tableName, "id") {
		t.Fatalf("fragment pushes while TxStatus T = %#v, want one in-transaction snapshot", requests)
	}
	if _, err := conn.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatalf("ROLLBACK: %v", err)
	}
}

func TestCatalogRefreshDoesNotArmOnFailedDDL(t *testing.T) {
	h := startBroker(t)
	const ddlSQL = "CREATE TABLE " + primarySchema + ".people (id int)"
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == ddlSQL {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := conn.Exec(context.Background(), ddlSQL); err == nil {
		t.Fatal("duplicate CREATE TABLE succeeded")
	}
	if got := len(h.fake.fragmentRequests()); got != 0 {
		t.Fatalf("catalog pushes after failed DDL = %d, want 0", got)
	}
}

func TestCatalogRefreshFailureClosesSessionAndRollsBack(t *testing.T) {
	h := startBroker(t)
	const (
		tableName = "refresh_failure"
		ddlSQL    = "CREATE TABLE " + primarySchema + "." + tableName + " (id int)"
	)
	direct := dbtest.OpenPostgres(t, "")
	if _, err := direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName); err != nil {
		t.Fatalf("drop stale refresh table: %v", err)
	}
	t.Cleanup(func() { _, _ = direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName) })
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == ddlSQL {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	h.fake.setPushError(status.Error(codes.Unavailable, "injected push failure"))
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	_, _ = conn.Exec(ctx, ddlSQL)
	if pushes := len(waitForFragmentRequests(t, h.fake, 1)); pushes != 1 {
		t.Fatalf("fragment pushes = %d, want one attempt", pushes)
	}
	var exists bool
	if err := direct.QueryRow("SELECT to_regclass($1) IS NOT NULL", primarySchema+"."+tableName).Scan(&exists); err != nil {
		t.Fatalf("verify rolled-back table: %v", err)
	}
	if exists {
		t.Fatalf("table %s.%s exists after failed push closed the transaction", primarySchema, tableName)
	}
}

func TestCommitAndChainRefetchesBeforeNextDecision(t *testing.T) {
	h := startBroker(t)
	const (
		commitSQL = "COMMIT AND CHAIN"
		nextSQL   = "SELECT 1"
	)
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == commitSQL {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := newRawPGClient(t, h)
	assertRawReadyForQuery(t, client.simpleQuery(t, "BEGIN"), 'T')
	commitFrames := client.simpleQuery(t, commitSQL)
	assertNoRawPGError(t, commitFrames)
	assertRawReadyForQuery(t, commitFrames, 'T')
	fragments := waitForFragmentRequests(t, h.fake, 1)
	if len(fragments) != 1 {
		t.Fatalf("fragment pushes after COMMIT AND CHAIN = %d, want 1", len(fragments))
	}
	nextFrames := client.simpleQuery(t, nextSQL)
	assertNoRawPGError(t, nextFrames)
	assertRawReadyForQuery(t, nextFrames, 'T')
	events := h.fake.eventLog()
	commitIndex := eventIndexPG(events, "decide:"+commitSQL, 0)
	pushIndex := eventIndexPG(events, "push:"+primarySchema, 0)
	nextIndex := eventIndexPG(events, "decide:"+nextSQL, 0)
	if commitIndex < 0 || pushIndex <= commitIndex || nextIndex <= pushIndex {
		t.Fatalf("event order = %v, want Decide(COMMIT AND CHAIN) -> push -> Decide(next)", events)
	}
	assertRawReadyForQuery(t, client.simpleQuery(t, "ROLLBACK"), 'I')
}

func TestRoutineDDLRefetchesBeforeNextDecision(t *testing.T) {
	h := startBroker(t)
	table := fmt.Sprintf("routine_created_%d", time.Now().UnixNano())
	procedure := fmt.Sprintf("routine_ddl_%d", time.Now().UnixNano())
	callSQL := "CALL " + primarySchema + "." + procedure + "()"
	nextSQL := "SELECT 1"
	direct := dbtest.OpenPostgres(t, "")
	if _, err := direct.Exec("CREATE OR REPLACE PROCEDURE " + primarySchema + "." + procedure + "() LANGUAGE plpgsql AS $$ BEGIN EXECUTE 'CREATE TABLE " + primarySchema + "." + table + " (id int)'; END $$"); err != nil {
		t.Fatalf("create DDL procedure: %v", err)
	}
	t.Cleanup(func() {
		_, _ = direct.Exec("DROP PROCEDURE IF EXISTS " + primarySchema + "." + procedure + "()")
		_, _ = direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + table)
	})
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == callSQL {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := conn.Exec(context.Background(), callSQL); err != nil {
		t.Fatalf("CALL routine DDL: %v", err)
	}
	fragments := waitForFragmentRequests(t, h.fake, 1)
	if len(fragments) != 1 || !fragmentHasColumn(fragments[0], primarySchema, table, "id") {
		t.Fatalf("routine fragment pushes = %#v, want snapshot containing %s.%s.id", fragments, primarySchema, table)
	}
	if _, err := conn.Exec(context.Background(), nextSQL); err != nil {
		t.Fatalf("next SELECT: %v", err)
	}
	if events := h.fake.eventLog(); eventIndexPG(events, "push:"+primarySchema, 0) >= eventIndexPG(events, "decide:"+nextSQL, 0) {
		t.Fatalf("event order = %v, want routine refresh before next Decide", events)
	}
}

func TestTransactionalCatalogRefreshPreventsStaleBareNameAllow(t *testing.T) {
	h := startBroker(t)
	const (
		frontSchema = "refresh_tx_front"
		backSchema  = "refresh_tx_back"
		tableName   = "shadowed"
		dropSQL     = "DROP TABLE " + frontSchema + "." + tableName
		readSQL     = "SELECT secret FROM " + tableName
	)
	direct := dbtest.OpenPostgres(t, "")
	for _, statement := range []string{
		"DROP SCHEMA IF EXISTS " + frontSchema + " CASCADE",
		"DROP SCHEMA IF EXISTS " + backSchema + " CASCADE",
		"CREATE SCHEMA " + frontSchema,
		"CREATE SCHEMA " + backSchema,
		"CREATE TABLE " + frontSchema + "." + tableName + " (secret text)",
		"CREATE TABLE " + backSchema + "." + tableName + " (secret text)",
		"INSERT INTO " + backSchema + "." + tableName + " VALUES ('shadow-row')",
	} {
		if _, err := direct.Exec(statement); err != nil {
			t.Fatalf("transactional stale-allow setup %q: %v", statement, err)
		}
	}
	t.Cleanup(func() {
		_, _ = direct.Exec("DROP SCHEMA IF EXISTS " + frontSchema + " CASCADE")
		_, _ = direct.Exec("DROP SCHEMA IF EXISTS " + backSchema + " CASCADE")
	})

	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == dropSQL {
			return refreshDecision(frontSchema), nil
		}
		if request.GetSql() == readSQL {
			h.fake.mu.Lock()
			var fragment *pb.SchemaFragmentPush
			if len(h.fake.fragmentReqs) > 0 {
				fragment = h.fake.fragmentReqs[len(h.fake.fragmentReqs)-1]
			}
			frontExists := fragmentHasColumn(fragment, frontSchema, tableName, "secret")
			h.fake.mu.Unlock()
			if frontExists {
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
			}
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "front table is absent from refreshed catalog"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "SET search_path TO "+frontSchema+", "+backSchema); err != nil {
		t.Fatalf("SET search_path: %v", err)
	}
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	if _, err := conn.Exec(ctx, dropSQL); err != nil {
		t.Fatalf("DROP front table in transaction: %v", err)
	}
	fragments := waitForFragmentRequests(t, h.fake, 1)
	if len(fragments) != 1 {
		t.Fatalf("fragment pushes before COMMIT = %d, want 1", len(fragments))
	}
	if fragmentHasColumn(fragments[0], frontSchema, tableName, "secret") {
		t.Fatalf("in-transaction fragment still contains dropped %s.%s.secret", frontSchema, tableName)
	}
	var secret string
	err = conn.QueryRow(ctx, readSQL).Scan(&secret)
	assertPgError(t, err, "42501", "front table is absent from refreshed catalog")
	if _, err := conn.Exec(ctx, "COMMIT"); err != nil {
		t.Fatalf("COMMIT: %v", err)
	}
	err = conn.QueryRow(ctx, readSQL).Scan(&secret)
	assertPgError(t, err, "42501", "front table is absent from refreshed catalog")
}

func TestCatalogRefreshPreventsStaleBareNameAllow(t *testing.T) {
	h := startBroker(t)
	const (
		frontSchema = "refresh_front"
		backSchema  = "refresh_back"
		tableName   = "shadowed"
		dropSQL     = "DROP TABLE " + frontSchema + "." + tableName
		readSQL     = "SELECT secret FROM " + tableName
	)
	direct := dbtest.OpenPostgres(t, "")
	for _, statement := range []string{
		"DROP SCHEMA IF EXISTS " + frontSchema + " CASCADE",
		"DROP SCHEMA IF EXISTS " + backSchema + " CASCADE",
		"CREATE SCHEMA " + frontSchema,
		"CREATE SCHEMA " + backSchema,
		"CREATE TABLE " + frontSchema + "." + tableName + " (secret text)",
		"CREATE TABLE " + backSchema + "." + tableName + " (secret text)",
		"INSERT INTO " + backSchema + "." + tableName + " VALUES ('shadow-row')",
	} {
		if _, err := direct.Exec(statement); err != nil {
			t.Fatalf("stale-allow setup %q: %v", statement, err)
		}
	}
	t.Cleanup(func() {
		_, _ = direct.Exec("DROP SCHEMA IF EXISTS " + frontSchema + " CASCADE")
		_, _ = direct.Exec("DROP SCHEMA IF EXISTS " + backSchema + " CASCADE")
	})

	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == dropSQL {
			return refreshDecision(frontSchema), nil
		}
		if request.GetSql() == readSQL {
			h.fake.mu.Lock()
			var fragment *pb.SchemaFragmentPush
			if len(h.fake.fragmentReqs) > 0 {
				fragment = h.fake.fragmentReqs[len(h.fake.fragmentReqs)-1]
			}
			frontExists := fragmentHasColumn(fragment, frontSchema, tableName, "secret")
			h.fake.mu.Unlock()
			if frontExists {
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
			}
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "front table is absent from refreshed catalog"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "SET search_path TO "+frontSchema+", "+backSchema); err != nil {
		t.Fatalf("SET search_path: %v", err)
	}
	if _, err := conn.Exec(ctx, dropSQL); err != nil {
		t.Fatalf("DROP front table: %v", err)
	}
	var secret string
	err = conn.QueryRow(ctx, readSQL).Scan(&secret)
	assertPgError(t, err, "42501", "front table is absent from refreshed catalog")
}

// TestStandardConformingStringsOffFailsClosed guards the CP admission-lexer invariant: the control plane
// tokenizes string literals assuming standard_conforming_strings=on. If a session turns it off, backslash
// escapes become active and the same bytes tokenize differently on the two sides, so a crafted
// multi-statement could slip past the CP's on-mode lexer. standard_conforming_strings is GUC_REPORT, so
// the change is observed before the next statement runs and the relay fails closed. The control plane
// ALLOWs the SET; the fail-closed is a relay-level backstop (parallel to client_encoding).
func TestStandardConformingStringsOffFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err = conn.Exec(context.Background(), "SET standard_conforming_strings=off")
	assertPgError(t, err, "0A000", "standard_conforming_strings must remain on")
	if requests := h.fake.requests(); len(requests) != 1 {
		t.Fatalf("Decide requests = %d, want 1 (the SET is authorized; the fail-closed is a relay backstop)", len(requests))
	}
}

// TestNonUTF8ClientEncodingFailsClosed guards the identifier-binding invariant: the engine/control plane
// read the client's SQL bytes as UTF-8, so a target-DB session that switches client_encoding away from UTF8
// would let the same bytes bind different objects on each side (a non-ASCII identifier could dodge its
// mask/deny). client_encoding is GUC_REPORT, so the change is observed before the next statement runs and
// the relay fails closed. The control plane ALLOWs the SET; the fail-closed is a relay-level backstop.
func TestNonUTF8ClientEncodingFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err = conn.Exec(context.Background(), "SET client_encoding TO 'LATIN1'")
	assertPgError(t, err, "0A000", "client_encoding must remain UTF8")
	if requests := h.fake.requests(); len(requests) != 1 {
		t.Fatalf("Decide requests = %d, want 1 (the SET is authorized; the fail-closed is a relay backstop)", len(requests))
	}
}

// TestUnsafeStartupStandardConformingStringsFailsClosed guards the STARTUP half of the lexer invariant.
// The on-change relay guard (TestStandardConformingStringsOffFailsClosed) only fires on a ParameterStatus
// that ARRIVES after connect; a database whose stored default is standard_conforming_strings=off
// (ALTER DATABASE ... SET) hands the session that divergent lexer from its very first statement, emitting
// no on-change frame. The shared target DB dial validates the startup ParameterStatus and fails closed at
// connect, so the broker never admits such a session. Isolated on a dedicated database because the
// suite-shared container persists across parallel test packages — mutating the "app" default would race
// them.
func TestUnsafeStartupStandardConformingStringsFailsClosed(t *testing.T) {
	targetDb := dbtest.Postgres(t)
	admin := dbtest.OpenPostgres(t, "")
	const unsafeDB = "pm_it_scs_off"
	if _, err := admin.Exec("DROP DATABASE IF EXISTS " + unsafeDB); err != nil {
		t.Fatalf("drop pre-existing unsafe db: %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE " + unsafeDB); err != nil {
		t.Fatalf("create unsafe db: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + unsafeDB) })
	if _, err := admin.Exec("ALTER DATABASE " + unsafeDB + " SET standard_conforming_strings = off"); err != nil {
		t.Fatalf("set unsafe startup default: %v", err)
	}

	h := startBrokerForDB(t, targetDb, unsafeDB)
	conn, err := h.connect(t, validToken, true)
	if err == nil {
		_ = conn.Close(context.Background())
		t.Fatal("connect to a standard_conforming_strings=off database succeeded, want fail-closed at connect")
	}
	// The dial fails closed inside the service-account handshake, which the broker reports to the client as
	// target-DB-unavailable (the specific cause is server-logged); no query is ever admitted.
	assertPgError(t, err, "08004", "target DB unavailable")
	if requests := h.fake.requests(); len(requests) != 0 {
		t.Fatalf("Decide requests = %d, want 0 (connection fails closed before any query)", len(requests))
	}
}

func TestDisconnectAfterDDLDoesNotAffectSiblingConnection(t *testing.T) {
	targetDb := seedTargetDb(t)
	connectionIDs := [][]byte{[]byte("session-one-0001"), []byte("session-two-0002")}
	var minted int
	h := startBrokerForDBSetup(t, targetDb, "app", func(fake *fakeControlPlane) {
		fake.setValidateFunc(func(*pb.ValidateTokenRequest) (*pb.WireIdentity, error) {
			if minted >= len(connectionIDs) {
				return nil, status.Error(codes.Internal, "too many sessions")
			}
			identity := &pb.WireIdentity{
				Principal:    "pg-it@example.com",
				Roles:        []string{"analyst"},
				ConnectionId: append([]byte(nil), connectionIDs[minted]...),
			}
			minted++
			return identity, nil
		})
	})
	table1 := fmt.Sprintf("disconnect_ddl_%d", time.Now().UnixNano())
	table2 := fmt.Sprintf("sibling_ddl_%d", time.Now().UnixNano())
	ddl1 := "CREATE TABLE " + primarySchema + "." + table1 + " (id int)"
	ddl2 := "CREATE TABLE " + primarySchema + "." + table2 + " (id int)"
	direct := dbtest.OpenPostgres(t, "")
	t.Cleanup(func() {
		_, _ = direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + table1)
		_, _ = direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + table2)
	})
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == ddl1 || request.GetSql() == ddl2 {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}

	session1 := newRawPGClient(t, h)
	session2 := newRawPGClient(t, h)
	assertNoRawPGError(t, session1.simpleQuery(t, ddl1))
	_ = session1.conn.Close()
	closes := waitForCloseRequests(t, h.fake, 1)
	assertNoRawPGError(t, session2.simpleQuery(t, ddl2))
	assertNoRawPGError(t, session2.simpleQuery(t, "SELECT 1"))

	if len(closes) != 1 || !reflect.DeepEqual(closes[0].GetConnectionId(), connectionIDs[0]) {
		t.Fatalf("CloseConnection requests = %#v, want exactly session 1 id %x", closes, connectionIDs[0])
	}
	requests := h.fake.requests()
	for _, req := range requests {
		switch req.GetSql() {
		case ddl1:
			if !reflect.DeepEqual(req.GetConnectionId(), connectionIDs[0]) {
				t.Fatalf("session 1 Decide connection_id = %x, want %x", req.GetConnectionId(), connectionIDs[0])
			}
		case ddl2, "SELECT 1":
			if !reflect.DeepEqual(req.GetConnectionId(), connectionIDs[1]) {
				t.Fatalf("session 2 Decide connection_id = %x, want %x", req.GetConnectionId(), connectionIDs[1])
			}
		}
	}
	fragments := h.fake.fragmentRequests()
	if len(fragments) != 2 {
		t.Fatalf("fragment pushes = %d, want one per session DDL", len(fragments))
	}
	if !reflect.DeepEqual(fragments[0].GetConnectionId(), connectionIDs[0]) || !reflect.DeepEqual(fragments[1].GetConnectionId(), connectionIDs[1]) {
		t.Fatalf("fragment connection_ids = [%x %x], want [%x %x]", fragments[0].GetConnectionId(), fragments[1].GetConnectionId(), connectionIDs[0], connectionIDs[1])
	}
}

func eventIndexPG(events []string, target string, occurrence int) int {
	for i, event := range events {
		if event != target {
			continue
		}
		if occurrence == 0 {
			return i
		}
		occurrence--
	}
	return -1
}

func TestOnOpenRunsBeforeFirstReadyAndCloseConnectionRunsOnce(t *testing.T) {
	targetDb := seedTargetDb(t)
	h := startBrokerForDBSetup(t, targetDb, "app", func(fake *fakeControlPlane) {
		fake.setOnOpen(&pb.ProxyCommand{
			Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: primarySchema}},
		})
	})

	client := newRawPGClient(t, h)
	fragments := waitForFragmentRequests(t, h.fake, 1)
	if len(fragments) != 1 || fragments[0].GetBackendGeneration() == 0 {
		t.Fatalf("on_open fragment = %#v, want nonzero backend_generation", fragments)
	}
	client.frontend.Send(&pgproto3.Terminate{})
	if err := client.frontend.Flush(); err != nil {
		t.Fatalf("send Terminate: %v", err)
	}
	_ = client.conn.Close()
	closes := waitForCloseRequests(t, h.fake, 1)
	if len(closes) != 1 || !reflect.DeepEqual(closes[0].GetConnectionId(), []byte("0123456789abcdef")) {
		t.Fatalf("CloseConnection requests = %#v, want minted id once", closes)
	}
}

func TestOnOpenPushFailureRefusesConnectionAndClosesControlPlaneState(t *testing.T) {
	targetDb := seedTargetDb(t)
	h := startBrokerForDBSetup(t, targetDb, "app", func(fake *fakeControlPlane) {
		fake.setOnOpen(&pb.ProxyCommand{
			Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: primarySchema}},
		})
		fake.setPushError(status.Error(codes.Unavailable, "injected on-open push failure"))
	})
	conn, err := h.connect(t, validToken, true)
	if conn != nil {
		_ = conn.Close(context.Background())
		t.Fatal("connection with failed on_open push succeeded")
	}
	assertPgError(t, err, "08004", "connection catalog unavailable")
	if got := len(waitForCloseRequests(t, h.fake, 1)); got != 1 {
		t.Fatalf("CloseConnection requests = %d, want 1 after open refusal", got)
	}
}

func TestBadTokenFailsClosed(t *testing.T) {
	h := startBroker(t)
	bad, err := h.connect(t, "it-token-bad", true)
	if bad != nil {
		_ = bad.Close(context.Background())
		t.Fatal("rejected-token connection succeeded")
	}
	assertPgError(t, err, "28000", "invalid or expired token")
}

func assertPgError(t *testing.T, err error, code, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want PostgreSQL %s containing %q", code, message)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("error = %T %v, want *pgconn.PgError", err, err)
	}
	if pgErr.Code != code || !strings.Contains(pgErr.Message, message) {
		t.Fatalf("PgError = code %q message %q, want %q containing %q", pgErr.Code, pgErr.Message, code, message)
	}
}
