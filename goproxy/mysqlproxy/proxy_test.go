package mysqlproxy_test

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/db"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/mysqlproxy"
	"github.com/ridi-oss/proxy-monster/goproxy/proxytls"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const (
	primarySchema   = "it_mysqlproxy"
	secondarySchema = "it_mysqlproxy2"
	serviceUser     = "it_proxy_svc"
	servicePassword = "it-svc-pw"
	validToken      = "it-token-ok"
)

func wireVerdict(verdict *pb.Verdict) *pb.WireDecision {
	return &pb.WireDecision{Outcome: &pb.WireDecision_Verdict{Verdict: verdict}}
}

type fakeControlPlane struct {
	pb.UnimplementedControlPlaneServer

	mu           sync.Mutex
	validateResp *pb.WireIdentity
	validateErr  error
	validateFn   func(*pb.ValidateTokenRequest) (*pb.WireIdentity, error)
	lastValidate *pb.ValidateTokenRequest
	decideFn     func(*pb.DecisionRequest) (*pb.WireDecision, error)
	decideReqs   []*pb.DecisionRequest
	fragmentReqs []*pb.SchemaFragmentPush
	pushErr      error
	pushAcks     []uint64
	closeReqs    []*pb.CloseConnectionRequest
	completions  []*pb.CompletionReport
	events       []string
}

func (f *fakeControlPlane) ValidateToken(_ context.Context, req *pb.ValidateTokenRequest) (*pb.WireIdentity, error) {
	f.mu.Lock()
	f.lastValidate = proto.Clone(req).(*pb.ValidateTokenRequest)
	validateErr := f.validateErr
	validateFn := f.validateFn
	var validateResp *pb.WireIdentity
	if f.validateResp != nil {
		validateResp = proto.Clone(f.validateResp).(*pb.WireIdentity)
	}
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
	if validateResp != nil {
		return validateResp, nil
	}
	return &pb.WireIdentity{Principal: "mysql-it@example.com", Roles: []string{"analyst"}}, nil
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
	generation := uint64(len(f.fragmentReqs))
	if len(f.pushAcks) > 0 {
		generation = f.pushAcks[0]
		f.pushAcks = f.pushAcks[1:]
	}
	return &pb.SchemaFragmentAck{Generation: generation}, nil
}

func (f *fakeControlPlane) CloseConnection(_ context.Context, req *pb.CloseConnectionRequest) (*pb.CloseConnectionResponse, error) {
	cloned := proto.Clone(req).(*pb.CloseConnectionRequest)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeReqs = append(f.closeReqs, cloned)
	f.events = append(f.events, "close")
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

func (f *fakeControlPlane) requests() []*pb.DecisionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*pb.DecisionRequest, len(f.decideReqs))
	for i, req := range f.decideReqs {
		out[i] = proto.Clone(req).(*pb.DecisionRequest)
	}
	return out
}

func (f *fakeControlPlane) fragmentRequests() []*pb.SchemaFragmentPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*pb.SchemaFragmentPush, len(f.fragmentReqs))
	for i, req := range f.fragmentReqs {
		out[i] = proto.Clone(req).(*pb.SchemaFragmentPush)
	}
	return out
}

func (f *fakeControlPlane) closeRequests() []*pb.CloseConnectionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*pb.CloseConnectionRequest, len(f.closeReqs))
	for i, req := range f.closeReqs {
		out[i] = proto.Clone(req).(*pb.CloseConnectionRequest)
	}
	return out
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

func (f *fakeControlPlane) setValidateResponse(resp *pb.WireIdentity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validateResp = proto.Clone(resp).(*pb.WireIdentity)
}

func (f *fakeControlPlane) setValidateFunc(validate func(*pb.ValidateTokenRequest) (*pb.WireIdentity, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validateFn = validate
}

func startFakeCP(t *testing.T) (*fakeControlPlane, *cp.Client) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake control plane: %v", err)
	}
	fake := &fakeControlPlane{
		validateResp: &pb.WireIdentity{
			Principal:    "mysql-it@example.com",
			Roles:        []string{"analyst"},
			ConnectionId: []byte("0123456789abcdef"),
		},
	}
	srv := grpc.NewServer()
	pb.RegisterControlPlaneServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})

	client, err := cp.New(lis.Addr().String(), "secret-abc", "ds-it")
	if err != nil {
		t.Fatalf("cp.New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return fake, client
}

func seedBackend(t *testing.T) dbtest.Backend {
	t.Helper()
	backend := dbtest.MySQL(t)
	seed := dbtest.OpenMySQL(t, "")
	statements := []string{
		"CREATE DATABASE IF NOT EXISTS " + primarySchema,
		"CREATE DATABASE IF NOT EXISTS " + secondarySchema,
		"CREATE TABLE IF NOT EXISTS " + primarySchema + ".people (id INT PRIMARY KEY, name VARCHAR(64), ssn VARCHAR(32))",
		"CREATE TABLE IF NOT EXISTS " + primarySchema + ".prepared_notes (id INT PRIMARY KEY, note VARCHAR(64))",
		"CREATE TABLE IF NOT EXISTS " + secondarySchema + ".people (id INT PRIMARY KEY, name VARCHAR(64), ssn VARCHAR(32))",
		"DELETE FROM " + primarySchema + ".people",
		"INSERT INTO " + primarySchema + ".people (id, name, ssn) VALUES (1, 'Alice', '900101-1234567'), (2, 'Bob', NULL)",
		"DELETE FROM " + primarySchema + ".prepared_notes",
		"DELETE FROM " + secondarySchema + ".people",
		"INSERT INTO " + secondarySchema + ".people (id, name, ssn) VALUES (10, 'Secondary', 'secret-2')",
		// caching_sha2_password is the mysql:8.0 / Aurora MySQL 3 default, so the broker's DB tests run
		// against it as the regression proof that the caching_sha2 backend handshake works end-to-end.
		// ALTER USER re-salts the stored credential every run, invalidating the server's fast-auth cache,
		// so the first backend dial each run is forced through the full-auth (RSA public-key) exchange.
		"CREATE USER IF NOT EXISTS '" + serviceUser + "'@'%' IDENTIFIED WITH caching_sha2_password BY '" + servicePassword + "'",
		"ALTER USER '" + serviceUser + "'@'%' IDENTIFIED WITH caching_sha2_password BY '" + servicePassword + "'",
		"GRANT ALL ON " + primarySchema + ".* TO '" + serviceUser + "'@'%'",
		"GRANT ALL ON " + secondarySchema + ".* TO '" + serviceUser + "'@'%'",
		"FLUSH PRIVILEGES",
	}
	for _, statement := range statements {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("seed statement %q: %v", statement, err)
		}
	}
	return backend
}

type brokerHarness struct {
	fake   *fakeControlPlane
	server *mysqlproxy.Server
	addr   string
}

func startBroker(t *testing.T) *brokerHarness {
	t.Helper()
	return startBrokerWithTLS(t, nil)
}

func startBrokerWithDb(t *testing.T, dbImpl engine.Db) *brokerHarness {
	t.Helper()
	return startBrokerConfigured(t, nil, dbImpl)
}

func startBrokerTLS(t *testing.T) *brokerHarness {
	t.Helper()
	reloading := proxytls.NewReloading("../proxytls/testdata/ec.crt", "../proxytls/testdata/ec-sec1.key")
	return startBrokerWithTLS(t, reloading.Current)
}

// startBrokerWithTLS boots a broker against the shared seeded backend. A nil tlsProvider keeps the frontend
// plaintext (every existing test); a non-nil one advertises CLIENT_SSL and requires TLS.
func startBrokerWithTLS(t *testing.T, tlsProvider func() (*tls.Config, error)) *brokerHarness {
	t.Helper()
	return startBrokerConfigured(t, tlsProvider, db.MySqlDb{})
}

func startBrokerConfigured(t *testing.T, tlsProvider func() (*tls.Config, error), dbImpl engine.Db) *brokerHarness {
	t.Helper()
	backend := seedBackend(t)
	fake, cpClient := startFakeCP(t)
	target := spi.BackendTarget{
		Host:     backend.Host,
		Port:     backend.Port,
		Db:       primarySchema,
		User:     serviceUser,
		Password: servicePassword,
	}
	server := mysqlproxy.New(0, target, cpClient, dbImpl, tlsProvider)
	if err := server.Listen(); err != nil {
		t.Fatalf("mysqlproxy.Listen: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	t.Cleanup(func() {
		server.Shutdown()
		if err := <-serveDone; err != nil {
			t.Errorf("mysqlproxy.Serve: %v", err)
		}
	})
	return &brokerHarness{fake: fake, server: server, addr: server.Addr().String()}
}

func (h *brokerHarness) openDB(t *testing.T, token string) *sql.DB {
	t.Helper()
	return h.openDBInDatabase(t, token, "")
}

func (h *brokerHarness) openDBInDatabase(t *testing.T, token, database string) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf("pm:%s@tcp(%s)/%s?allowCleartextPasswords=true&interpolateParams=false", token, h.addr, database)
	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// The proxy must forward the client's real socket address on ValidateToken so a rejected wire credential
// is audited with its source. A blank field re-opens the audited-without-source gap; the token in that
// field would leak the credential into the audit chain. (pgproxy plumbs the same value symmetrically.)
func TestValidateTokenCarriesClientAddr(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 1}), nil
	}
	conn := h.openDB(t, validToken)
	rows, err := conn.Query("SELECT id FROM people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	rows.Close()
	h.fake.mu.Lock()
	got := h.fake.lastValidate.GetClientAddr()
	h.fake.mu.Unlock()
	if got == "" || !strings.Contains(got, ":") || got == validToken {
		t.Fatalf("ValidateToken client_addr = %q; want the client socket address (host:port), not blank or the token", got)
	}
}

func refetchCommand(schema string, hash []byte) *pb.ProxyCommand {
	return &pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{
		Schema:        schema,
		IfHashDiffers: append([]byte(nil), hash...),
	}}}
}

func TestOnOpenRefetchCompletesBeforeHandshake(t *testing.T) {
	h := startBroker(t)
	h.fake.setValidateResponse(&pb.WireIdentity{
		Principal:    "mysql-it@example.com",
		Roles:        []string{"analyst"},
		ConnectionId: []byte("onopen-012345678"),
		OnOpen:       []*pb.ProxyCommand{refetchCommand(primarySchema, nil)},
	})

	client := openRawClient(t, h.addr, validToken)
	fragments := h.fake.fragmentRequests()
	if len(fragments) != 1 {
		t.Fatalf("on_open fragment pushes = %d, want 1", len(fragments))
	}
	fragment := fragments[0]
	if fragment.GetUnchanged() {
		t.Fatal("unconditional on_open push marked unchanged")
	}
	assertFragmentColumn(t, fragment, primarySchema, "people", "ssn")
	if fragment.GetBackendGeneration() == 0 {
		t.Fatal("on_open backend_generation = 0")
	}
	client.query(t, "SELECT 1")
	if events := h.fake.eventLog(); eventIndex(events, "push:"+primarySchema, 0) >= eventIndex(events, "decide:SELECT 1", 0) {
		t.Fatalf("event order = %v, want on_open push before first Decide", events)
	}
}

func TestOnOpenEqualHashPushesUnchangedWithoutColumns(t *testing.T) {
	h := startBroker(t)
	h.fake.setValidateResponse(&pb.WireIdentity{
		Principal:    "mysql-it@example.com",
		Roles:        []string{"analyst"},
		ConnectionId: []byte("samehash01234567"),
		OnOpen:       []*pb.ProxyCommand{refetchCommand(primarySchema, schemaHash(t, primarySchema))},
	})

	client := openRawClient(t, h.addr, validToken)
	fragment := h.fake.fragmentRequests()[0]
	if !fragment.GetUnchanged() {
		t.Fatal("equal-hash on_open push unchanged = false")
	}
	if len(fragment.GetColumns()) != 0 {
		t.Fatalf("equal-hash on_open columns = %d, want zero", len(fragment.GetColumns()))
	}
	client.query(t, "SELECT 1")
}

func TestOnOpenFailureRefusesConnectionAndClosesCPState(t *testing.T) {
	for _, test := range []struct {
		name   string
		dbImpl engine.Db
		setup  func(*fakeControlPlane)
	}{
		{"introspection", failingColumnsDb{MySqlDb: db.MySqlDb{}}, func(*fakeControlPlane) {}},
		{"push", db.MySqlDb{}, func(fake *fakeControlPlane) {
			fake.setPushError(status.Error(codes.Unavailable, "catalog unavailable"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := startBrokerWithDb(t, test.dbImpl)
			connectionID := []byte("openfail01234567")
			h.fake.setValidateResponse(&pb.WireIdentity{
				Principal:    "mysql-it@example.com",
				Roles:        []string{"analyst"},
				ConnectionId: connectionID,
				OnOpen:       []*pb.ProxyCommand{refetchCommand(primarySchema, nil)},
			})
			test.setup(h.fake)

			authResult := rawAuthenticate(t, h.addr, validToken)
			if len(authResult) == 0 || authResult[0] != 0xff || !strings.Contains(mysqlwire.ErrString(authResult), "catalog initialization failed") {
				t.Fatalf("auth result = %x (%q), want catalog initialization ERR", authResult, mysqlwire.ErrString(authResult))
			}
			waitFor(t, func() bool { return len(h.fake.closeRequests()) == 1 })
			if got := h.fake.closeRequests()[0].GetConnectionId(); !reflect.DeepEqual(got, connectionID) {
				t.Fatalf("CloseConnection id = %x, want %x", got, connectionID)
			}
		})
	}
}

// failingColumnsDb preserves the real MySQL hash probes but makes the mandatory full introspection fail.
type failingColumnsDb struct{ db.MySqlDb }

func (failingColumnsDb) SchemaColumnsSQL(string) string {
	return "SELECT * FROM pm_missing_schema_fragment_table"
}

func TestFlaggedDDLRefetchesBeforeNextStatement(t *testing.T) {
	h := startBroker(t)
	table := fmt.Sprintf("catalog_refresh_%d", time.Now().UnixNano())
	createSQL := "CREATE TABLE " + table + " (id INT PRIMARY KEY)"
	followupSQL := "SELECT 1"
	seed := dbtest.OpenMySQL(t, primarySchema)
	t.Cleanup(func() { _, _ = seed.Exec("DROP TABLE IF EXISTS " + table) })

	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
		if req.GetSql() == createSQL {
			verdict.AfterStatement = []*pb.ProxyCommand{refetchCommand(primarySchema, nil)}
		}
		return wireVerdict(verdict), nil
	}
	client := openRawClient(t, h.addr, validToken)

	client.query(t, createSQL)
	client.query(t, followupSQL)
	fragments := h.fake.fragmentRequests()
	if len(fragments) != 1 {
		t.Fatalf("PushSchemaFragment calls = %d, want 1 (decisions=%+v events=%v)", len(fragments), h.fake.requests(), h.fake.eventLog())
	}
	assertFragmentColumn(t, fragments[0], primarySchema, table, "id")
	if fragments[0].GetBackendGeneration() == 0 {
		t.Fatal("backend_generation = 0, want nonzero")
	}

	events := h.fake.eventLog()
	pushIndex := eventIndex(events, "push:"+primarySchema, 0)
	followupIndex := eventIndex(events, "decide:"+followupSQL, 0)
	if pushIndex < 0 || followupIndex < 0 || pushIndex >= followupIndex {
		t.Fatalf("event order = %v, want fragment push before follow-up Decide", events)
	}
}

func TestFlaggedTextDDLImplicitCommitRefetchesBeforeNextDecision(t *testing.T) {
	h := startBroker(t)
	table := fmt.Sprintf("catalog_implicit_text_%d", time.Now().UnixNano())
	probeID := time.Now().UnixNano()%1_000_000_000 + 100
	createSQL := "CREATE TABLE " + table + " (id INT PRIMARY KEY)"
	followupSQL := "SELECT 1"
	direct := dbtest.OpenMySQL(t, primarySchema)
	t.Cleanup(func() { _, _ = direct.Exec("DROP TABLE IF EXISTS " + table) })

	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
		if req.GetSql() == createSQL {
			verdict.AfterStatement = []*pb.ProxyCommand{refetchCommand(primarySchema, nil)}
		}
		return wireVerdict(verdict), nil
	}
	client := openRawClient(t, h.addr, validToken)
	client.query(t, "START TRANSACTION")
	client.query(t, fmt.Sprintf("INSERT INTO prepared_notes (id, note) VALUES (%d, 'implicit-text')", probeID))
	client.query(t, createSQL)

	waitFor(t, func() bool { return len(h.fake.fragmentRequests()) == 1 })
	fragments := h.fake.fragmentRequests()
	if len(fragments) != 1 {
		t.Fatalf("PushSchemaFragment calls after DDL = %d, want 1", len(fragments))
	}
	assertFragmentColumn(t, fragments[0], primarySchema, table, "id")
	var committed int
	if err := direct.QueryRow("SELECT COUNT(*) FROM prepared_notes WHERE id = ?", probeID).Scan(&committed); err != nil {
		t.Fatalf("verify implicit-commit probe row: %v", err)
	}
	if committed != 1 {
		t.Fatalf("implicit-commit probe row count = %d, want 1 visible from a sibling connection", committed)
	}

	client.query(t, followupSQL)
	events := h.fake.eventLog()
	ddlIndex := eventIndex(events, "decide:"+createSQL, 0)
	pushIndex := eventIndex(events, "push:"+primarySchema, 0)
	followupIndex := eventIndex(events, "decide:"+followupSQL, 0)
	if ddlIndex < 0 || pushIndex <= ddlIndex || followupIndex <= pushIndex {
		t.Fatalf("event order = %v, want Decide(DDL) -> push -> Decide(next)", events)
	}
}

func TestBeforeDecideRunsRefetchThenResendsEquivalentRequest(t *testing.T) {
	h := startBroker(t)
	var calls int
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		calls++
		if calls == 1 {
			return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{
				Commands: []*pb.ProxyCommand{refetchCommand(primarySchema, nil)},
			}}}, nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := openRawClient(t, h.addr, validToken)
	client.query(t, "SELECT 1")

	requests := h.fake.requests()
	if len(requests) != 2 {
		t.Fatalf("Decide requests = %d, want 2", len(requests))
	}
	if !proto.Equal(requests[0], requests[1]) {
		t.Fatalf("retried request differs:\nfirst=%v\nsecond=%v", requests[0], requests[1])
	}
	fragments := h.fake.fragmentRequests()
	if len(fragments) != 1 {
		t.Fatalf("before_decide fragment pushes = %d, want 1", len(fragments))
	}
	events := h.fake.eventLog()
	if !reflect.DeepEqual(events[:3], []string{"decide:SELECT 1", "push:" + primarySchema, "decide:SELECT 1"}) {
		t.Fatalf("event order = %v, want decide/push/decide", events)
	}
}

func TestBeforeDecideBoundClosesSession(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{
			Commands: []*pb.ProxyCommand{refetchCommand(primarySchema, nil)},
		}}}, nil
	}
	client := openRawClient(t, h.addr, validToken)
	response := client.firstQueryPacket(t, "SELECT 1")
	if len(response) == 0 || response[0] != 0xff || !strings.Contains(mysqlwire.ErrString(response), "demanded pre-decision commands 4 times") {
		t.Fatalf("response = %x (%q), want bounded before_decide failure", response, mysqlwire.ErrString(response))
	}
	if got := len(h.fake.requests()); got != 4 {
		t.Fatalf("Decide requests = %d, want 4", got)
	}
	if got := len(h.fake.fragmentRequests()); got != 3 {
		t.Fatalf("before_decide pushes = %d, want 3", got)
	}
}

func TestUnknownCommandFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{
			Commands: []*pb.ProxyCommand{{}},
		}}}, nil
	}
	client := openRawClient(t, h.addr, validToken)
	response := client.firstQueryPacket(t, "SELECT 1")
	if len(response) == 0 || response[0] != 0xff || !strings.Contains(mysqlwire.ErrString(response), "malformed before-decision commands") {
		t.Fatalf("response = %x (%q), want malformed-command denial", response, mysqlwire.ErrString(response))
	}
	if len(h.fake.fragmentRequests()) != 0 {
		t.Fatal("unknown command reached refetcher")
	}
}

func TestDDLWithoutAfterStatementDoesNotRefetch(t *testing.T) {
	h := startBroker(t)
	table := fmt.Sprintf("catalog_no_command_%d", time.Now().UnixNano())
	seed := dbtest.OpenMySQL(t, primarySchema)
	t.Cleanup(func() { _, _ = seed.Exec("DROP TABLE IF EXISTS " + table) })

	openRawClient(t, h.addr, validToken).query(t, "CREATE TABLE "+table+" (id INT PRIMARY KEY)")
	if got := len(h.fake.fragmentRequests()); got != 0 {
		t.Fatalf("PushSchemaFragment calls = %d, want zero without after_statement", got)
	}
}

func TestRejectedFlaggedDDLDoesNotRefetch(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = refreshSchemaDecision
	client := openRawClient(t, h.addr, validToken)
	missing := fmt.Sprintf("missing_catalog_table_%d", time.Now().UnixNano())

	response := client.firstQueryPacket(t, "ALTER TABLE "+missing+" ADD COLUMN impossible INT")
	if len(response) == 0 || response[0] != 0xff {
		t.Fatalf("rejected DDL response = %x, want backend ERR", response)
	}
	if got := len(h.fake.fragmentRequests()); got != 0 {
		t.Fatalf("PushSchemaFragment calls after rejected DDL = %d, want zero", got)
	}
}

func TestFlaggedDMLRefetchFailureClosesFrontendAndBackend(t *testing.T) {
	h := startBroker(t)
	const connectionIDQuery = "SELECT CONNECTION_ID()"
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
		if req.GetSql() != connectionIDQuery {
			verdict.AfterStatement = []*pb.ProxyCommand{refetchCommand(primarySchema, nil)}
		}
		return wireVerdict(verdict), nil
	}
	client := openRawClient(t, h.addr, validToken)
	rows := client.textRows(t, connectionIDQuery, 1)
	if len(rows) != 1 || rows[0][0] == nil {
		t.Fatalf("CONNECTION_ID rows = %v", rows)
	}
	var backendID uint64
	if _, err := fmt.Sscan(*rows[0][0], &backendID); err != nil {
		t.Fatalf("parse backend id %q: %v", *rows[0][0], err)
	}

	h.fake.setPushError(status.Error(codes.Unavailable, "catalog unavailable"))
	response := client.firstQueryPacket(t, "UPDATE people SET name = name WHERE id = 1")
	if len(response) == 0 || response[0] != 0x00 {
		t.Fatalf("DML response = %x, want backend OK before terminal refetch", response)
	}
	_ = client.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("frontend session remained open after fragment push failure")
	}

	direct := dbtest.OpenMySQL(t, "")
	waitFor(t, func() bool {
		var count int
		if err := direct.QueryRow("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID = ?", backendID).Scan(&count); err != nil {
			return false
		}
		return count == 0
	})
}

func TestPreparedDDLRefetchesOnlyAfterSuccessfulExecute(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		h := startBroker(t)
		table := fmt.Sprintf("catalog_prepared_%d", time.Now().UnixNano())
		createSQL := "CREATE TABLE " + table + " (id INT PRIMARY KEY)"
		var decideCount int
		h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
			decideCount++
			verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
			if req.GetSql() == createSQL && decideCount >= 2 {
				verdict.AfterStatement = []*pb.ProxyCommand{refetchCommand(primarySchema, nil)}
			}
			return wireVerdict(verdict), nil
		}
		seed := dbtest.OpenMySQL(t, primarySchema)
		t.Cleanup(func() { _, _ = seed.Exec("DROP TABLE IF EXISTS " + table) })
		client := openRawClient(t, h.addr, validToken)

		prepared := client.prepare(t, createSQL)
		if got := len(h.fake.fragmentRequests()); got != 0 {
			t.Fatalf("PushSchemaFragment calls after PREPARE = %d, want zero", got)
		}
		client.executeNoParams(t, prepared.StmtID)
		client.drainResult(t)
		deadline := time.Now().Add(2 * time.Second)
		for len(h.fake.fragmentRequests()) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		fragments := h.fake.fragmentRequests()
		if len(fragments) != 1 {
			t.Fatalf("PushSchemaFragment calls after EXECUTE = %d, want one", len(fragments))
		}
		assertFragmentColumn(t, fragments[0], primarySchema, table, "id")
	})

	t.Run("failure", func(t *testing.T) {
		h := startBroker(t)
		h.fake.decideFn = refreshSchemaDecision
		missing := fmt.Sprintf("missing_catalog_prepared_%d", time.Now().UnixNano())
		client := openRawClient(t, h.addr, validToken)

		prepared := client.prepare(t, "ALTER TABLE "+missing+" ADD COLUMN impossible INT")
		response := client.command(t, stmtExecuteNoParamsPayload(t, prepared.StmtID))
		if len(response) == 0 || response[0] != 0xff {
			t.Fatalf("failed EXECUTE response = %x, want backend ERR", response)
		}
		if got := len(h.fake.fragmentRequests()); got != 0 {
			t.Fatalf("PushSchemaFragment calls after failed EXECUTE = %d, want zero", got)
		}
	})
}

func TestPreparedDDLImplicitCommitRefetchesBeforeNextDecision(t *testing.T) {
	h := startBroker(t)
	table := fmt.Sprintf("catalog_implicit_prepared_%d", time.Now().UnixNano())
	probeID := time.Now().UnixNano()%1_000_000_000 + 100
	createSQL := "CREATE TABLE " + table + " (id INT PRIMARY KEY)"
	followupSQL := "SELECT 1"
	direct := dbtest.OpenMySQL(t, primarySchema)
	t.Cleanup(func() { _, _ = direct.Exec("DROP TABLE IF EXISTS " + table) })

	var createDecisions int
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
		if req.GetSql() == createSQL {
			createDecisions++
			if createDecisions == 2 {
				verdict.AfterStatement = []*pb.ProxyCommand{refetchCommand(primarySchema, nil)}
			}
		}
		return wireVerdict(verdict), nil
	}
	client := openRawClient(t, h.addr, validToken)
	client.query(t, "START TRANSACTION")
	client.query(t, fmt.Sprintf("INSERT INTO prepared_notes (id, note) VALUES (%d, 'implicit-prepared')", probeID))
	prepared := client.prepare(t, createSQL)
	if got := len(h.fake.fragmentRequests()); got != 0 {
		t.Fatalf("PushSchemaFragment calls after PREPARE = %d, want 0", got)
	}
	client.executeNoParams(t, prepared.StmtID)
	client.drainResult(t)

	waitFor(t, func() bool { return len(h.fake.fragmentRequests()) == 1 })
	fragments := h.fake.fragmentRequests()
	if len(fragments) != 1 {
		t.Fatalf("PushSchemaFragment calls after EXECUTE = %d, want 1", len(fragments))
	}
	assertFragmentColumn(t, fragments[0], primarySchema, table, "id")
	var committed int
	if err := direct.QueryRow("SELECT COUNT(*) FROM prepared_notes WHERE id = ?", probeID).Scan(&committed); err != nil {
		t.Fatalf("verify prepared implicit-commit probe row: %v", err)
	}
	if committed != 1 {
		t.Fatalf("prepared implicit-commit probe row count = %d, want 1 visible from a sibling connection", committed)
	}

	client.query(t, followupSQL)
	events := h.fake.eventLog()
	secondDDLDecide := eventIndex(events, "decide:"+createSQL, 1)
	pushIndex := eventIndex(events, "push:"+primarySchema, 0)
	followupIndex := eventIndex(events, "decide:"+followupSQL, 0)
	if secondDDLDecide < 0 || pushIndex <= secondDDLDecide || followupIndex <= pushIndex {
		t.Fatalf("event order = %v, want Decide(EXECUTE) -> push -> Decide(next)", events)
	}
}

func refreshSchemaDecision(*pb.DecisionRequest) (*pb.WireDecision, error) {
	return wireVerdict(&pb.Verdict{
		Decision:       pb.EnfAction_ALLOW,
		AfterStatement: []*pb.ProxyCommand{refetchCommand(primarySchema, nil)},
	}), nil
}

func assertFragmentColumn(t *testing.T, fragment *pb.SchemaFragmentPush, schema, table, column string) {
	t.Helper()
	for _, candidate := range fragment.GetColumns() {
		if candidate.GetSchema() == schema && candidate.GetTable() == table && candidate.GetColumn() == column {
			return
		}
	}
	t.Fatalf("fragment does not contain %s.%s.%s", schema, table, column)
}

func schemaHash(t *testing.T, schema string) []byte {
	t.Helper()
	backend := dbtest.OpenMySQL(t, primarySchema)
	dbImpl := db.MySqlDb{}
	query, _, err := dbImpl.SchemaHashSQL(schema, nil)
	if err != nil {
		t.Fatalf("SchemaHashSQL: %v", err)
	}
	var hash string
	var produced, count uint64
	if err := backend.QueryRow(query).Scan(&hash, &produced, &count); err != nil {
		t.Fatalf("schema hash query: %v", err)
	}
	rows := [][]*string{{&hash, stringPtr(fmt.Sprint(produced)), stringPtr(fmt.Sprint(count))}}
	decoded, trusted, err := dbImpl.SchemaHashFromRows(rows)
	if err != nil || !trusted {
		t.Fatalf("SchemaHashFromRows = (%x, %v, %v), want trusted", decoded, trusted, err)
	}
	return decoded
}

func stringPtr(value string) *string { return &value }

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition did not become true before timeout")
	}
}

func eventIndex(events []string, target string, occurrence int) int {
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

func TestCommitAndChainRefetchesBeforeNextDecision(t *testing.T) {
	h := startBroker(t)
	const (
		commitSQL = "COMMIT AND CHAIN"
		nextSQL   = "SELECT 1"
	)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
		if req.GetSql() == commitSQL {
			verdict.AfterStatement = []*pb.ProxyCommand{refetchCommand(primarySchema, nil)}
		}
		return wireVerdict(verdict), nil
	}
	client := openRawClient(t, h.addr, validToken)
	client.query(t, "START TRANSACTION")
	client.query(t, commitSQL)
	client.query(t, nextSQL)

	fragments := h.fake.fragmentRequests()
	if len(fragments) != 1 {
		t.Fatalf("PushSchemaFragment calls = %d, want 1", len(fragments))
	}
	events := h.fake.eventLog()
	commitIndex := eventIndex(events, "decide:"+commitSQL, 0)
	pushIndex := eventIndex(events, "push:"+primarySchema, 0)
	nextIndex := eventIndex(events, "decide:"+nextSQL, 0)
	if commitIndex < 0 || pushIndex <= commitIndex || nextIndex <= pushIndex {
		t.Fatalf("event order = %v, want Decide(COMMIT AND CHAIN) -> push -> Decide(next)", events)
	}
}

func TestRoutineDDLRefetchesBeforeNextDecision(t *testing.T) {
	h := startBroker(t)
	table := fmt.Sprintf("routine_created_%d", time.Now().UnixNano())
	procedure := fmt.Sprintf("routine_ddl_%d", time.Now().UnixNano())
	callSQL := "CALL " + procedure + "()"
	nextSQL := "SELECT 1"
	direct := dbtest.OpenMySQL(t, primarySchema)
	if _, err := direct.Exec("DROP PROCEDURE IF EXISTS " + procedure); err != nil {
		t.Fatalf("drop stale procedure: %v", err)
	}
	if _, err := direct.Exec("CREATE PROCEDURE " + procedure + "() CREATE TABLE " + table + " (id INT PRIMARY KEY)"); err != nil {
		t.Fatalf("create DDL procedure: %v", err)
	}
	t.Cleanup(func() {
		_, _ = direct.Exec("DROP PROCEDURE IF EXISTS " + procedure)
		_, _ = direct.Exec("DROP TABLE IF EXISTS " + table)
	})

	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
		if req.GetSql() == callSQL {
			verdict.AfterStatement = []*pb.ProxyCommand{refetchCommand(primarySchema, nil)}
		}
		return wireVerdict(verdict), nil
	}
	client := openRawClient(t, h.addr, validToken)
	client.query(t, callSQL)
	waitFor(t, func() bool { return len(h.fake.fragmentRequests()) == 1 })
	fragments := h.fake.fragmentRequests()
	if len(fragments) != 1 {
		t.Fatalf("PushSchemaFragment calls after CALL = %d, want 1", len(fragments))
	}
	assertFragmentColumn(t, fragments[0], primarySchema, table, "id")
	client.query(t, nextSQL)
	if events := h.fake.eventLog(); eventIndex(events, "push:"+primarySchema, 0) >= eventIndex(events, "decide:"+nextSQL, 0) {
		t.Fatalf("event order = %v, want routine refresh before next Decide", events)
	}
}

func TestDisconnectAfterDDLDoesNotAffectSiblingConnection(t *testing.T) {
	h := startBroker(t)
	connectionIDs := [][]byte{[]byte("session-one-0001"), []byte("session-two-0002")}
	var minted int
	h.fake.setValidateFunc(func(*pb.ValidateTokenRequest) (*pb.WireIdentity, error) {
		if minted >= len(connectionIDs) {
			return nil, status.Error(codes.Internal, "too many sessions")
		}
		identity := &pb.WireIdentity{
			Principal:    "mysql-it@example.com",
			Roles:        []string{"analyst"},
			ConnectionId: append([]byte(nil), connectionIDs[minted]...),
		}
		minted++
		return identity, nil
	})
	table1 := fmt.Sprintf("disconnect_ddl_%d", time.Now().UnixNano())
	table2 := fmt.Sprintf("sibling_ddl_%d", time.Now().UnixNano())
	ddl1 := "CREATE TABLE " + table1 + " (id INT PRIMARY KEY)"
	ddl2 := "CREATE TABLE " + table2 + " (id INT PRIMARY KEY)"
	direct := dbtest.OpenMySQL(t, primarySchema)
	t.Cleanup(func() {
		_, _ = direct.Exec("DROP TABLE IF EXISTS " + table1)
		_, _ = direct.Exec("DROP TABLE IF EXISTS " + table2)
	})
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
		if req.GetSql() == ddl1 || req.GetSql() == ddl2 {
			verdict.AfterStatement = []*pb.ProxyCommand{refetchCommand(primarySchema, nil)}
		}
		return wireVerdict(verdict), nil
	}

	session1 := openRawClient(t, h.addr, validToken)
	session2 := openRawClient(t, h.addr, validToken)
	session1.query(t, ddl1)
	if err := session1.conn.Close(); err != nil {
		t.Fatalf("abruptly close session 1: %v", err)
	}
	waitFor(t, func() bool { return len(h.fake.closeRequests()) == 1 })
	session2.query(t, ddl2)
	session2.query(t, "SELECT 1")

	closes := h.fake.closeRequests()
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

func TestCloseConnectionExactlyOnceOnQuitAndDisconnect(t *testing.T) {
	for _, test := range []struct {
		name string
		stop func(t *testing.T, client *rawClient)
	}{
		{"quit", func(t *testing.T, client *rawClient) {
			if err := mysqlwire.WritePacket(client.conn, 0, []byte{mysqlwire.ComQuit}); err != nil {
				t.Fatalf("write COM_QUIT: %v", err)
			}
		}},
		{"disconnect", func(t *testing.T, client *rawClient) {
			if err := client.conn.Close(); err != nil {
				t.Fatalf("close client: %v", err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := startBroker(t)
			client := openRawClient(t, h.addr, validToken)
			test.stop(t, client)
			waitFor(t, func() bool { return len(h.fake.closeRequests()) == 1 })
			time.Sleep(50 * time.Millisecond)
			closes := h.fake.closeRequests()
			if len(closes) != 1 {
				t.Fatalf("CloseConnection calls = %d, want exactly 1", len(closes))
			}
			if got := closes[0].GetConnectionId(); !reflect.DeepEqual(got, []byte("0123456789abcdef")) {
				t.Fatalf("CloseConnection id = %x", got)
			}
		})
	}
}

func TestAllowRelaysRowsAndDecisionContext(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 1}), nil
	}
	conn := h.openDB(t, validToken)
	const query = "SELECT id, name, ssn FROM people ORDER BY id"
	rows, err := conn.Query(query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()

	var got [][]any
	for rows.Next() {
		var id int
		var name string
		var ssn sql.NullString
		if err := rows.Scan(&id, &name, &ssn); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got = append(got, []any{id, name, ssn})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	want := [][]any{
		{1, "Alice", sql.NullString{String: "900101-1234567", Valid: true}},
		{2, "Bob", sql.NullString{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %#v, want %#v", got, want)
	}

	requests := h.fake.requests()
	if len(requests) != 1 {
		t.Fatalf("Decide requests = %d, want 1", len(requests))
	}
	req := requests[0]
	if req.GetToken() != validToken || req.GetSql() != query || !reflect.DeepEqual(req.GetSearchPath(), []string{primarySchema}) {
		t.Fatalf("DecisionRequest = %+v, want token/query/SearchPath [%s]", req, primarySchema)
	}
	if got := req.GetConnectionId(); !reflect.DeepEqual(got, []byte("0123456789abcdef")) {
		t.Fatalf("DecisionRequest connection_id = %x, want stable 16-byte id", got)
	}
}

func TestHandshakeDatabaseIsRelayedAndSelected(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn := h.openDBInDatabase(t, validToken, secondarySchema)
	rows, err := conn.Query("SELECT id FROM people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()

	var got []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got = append(got, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	if !reflect.DeepEqual(got, []int{10}) {
		t.Fatalf("secondary database rows = %v, want [10]", got)
	}

	// The handshake-selected database is relayed to the backend as COM_INIT_DB, not authorized as a
	// synthesized USE: only the query reaches the control plane, decided under the switched namespace.
	requests := h.fake.requests()
	if len(requests) != 1 {
		t.Fatalf("Decide requests = %d, want just the query (handshake db is relayed, not authorized)", len(requests))
	}
	if !reflect.DeepEqual(requests[0].GetSearchPath(), []string{secondarySchema}) {
		t.Fatalf("query SearchPath = %v, want re-probed [%s]", requests[0].GetSearchPath(), secondarySchema)
	}
}

func TestMaskRewritesRowsAndPreservesNull(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks: []*pb.ColumnMask{
				{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)},
			},
		}), nil
	}
	conn := h.openDB(t, validToken)
	rows, err := conn.Query("SELECT id, name, ssn FROM people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()

	var got []sql.NullString
	var ids []int
	var names []string
	for rows.Next() {
		var id int
		var name string
		var ssn sql.NullString
		if err := rows.Scan(&id, &name, &ssn); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		ids = append(ids, id)
		names = append(names, name)
		got = append(got, ssn)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	if !reflect.DeepEqual(ids, []int{1, 2}) || !reflect.DeepEqual(names, []string{"Alice", "Bob"}) {
		t.Fatalf("unmasked columns changed: ids=%v names=%v", ids, names)
	}
	want := []sql.NullString{{String: "####", Valid: true}, {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("masked ssn = %#v, want %#v", got, want)
	}
}

func TestDenyLeaksNoRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "ssn is off-limits"}), nil
	}
	conn := h.openDB(t, validToken)
	rows, err := conn.Query("SELECT id, name, ssn FROM people ORDER BY id")
	if err == nil {
		if rows != nil {
			_ = rows.Close()
		}
		t.Fatal("Query succeeded, want policy denial")
	}
	if rows != nil {
		t.Fatalf("rows = %v, want nil on deny (zero rows leaked)", rows)
	}
	if !strings.Contains(err.Error(), "Error 1142") || !strings.Contains(err.Error(), "proxy-monster denied: ssn is off-limits") {
		t.Fatalf("Query error = %q, want 1142 policy denial", err)
	}
}

func TestUnbindableMaskLeaksNoPacketsBeforeError(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks: []*pb.ColumnMask{
				{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(99)},
			},
		}), nil
	}
	client := openRawClient(t, h.addr, validToken)
	response := client.firstQueryPacket(t, "SELECT id, name, ssn FROM people ORDER BY id")
	if len(response) == 0 || response[0] != 0xff {
		t.Fatalf("first query packet = %x, want ERR before column count or rows", response)
	}
	if got := mysqlwire.ErrString(response); !strings.Contains(got, "required mask could not be bound") {
		t.Fatalf("query error = %q, want mask-binding failure", got)
	}
}

func TestComInitDBRelaysAndReprobesNamespace(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := openRawClient(t, h.addr, validToken)

	client.query(t, "SELECT id FROM people ORDER BY id")
	client.initDB(t, secondarySchema)
	client.query(t, "SELECT id FROM people ORDER BY id")

	// COM_INIT_DB is relayed mechanically and never reaches the control plane; the switch surfaces only as
	// the re-probed namespace of the following query.
	requests := h.fake.requests()
	if len(requests) != 2 {
		t.Fatalf("Decide requests = %d, want two queries (COM_INIT_DB is relayed, not authorized)", len(requests))
	}
	if got := requests[0].GetSearchPath(); !reflect.DeepEqual(got, []string{primarySchema}) {
		t.Fatalf("first SearchPath = %v, want [%s]", got, primarySchema)
	}
	if got := requests[1].GetSearchPath(); !reflect.DeepEqual(got, []string{secondarySchema}) {
		t.Fatalf("post-COM_INIT_DB SearchPath = %v, want re-probed [%s]", got, secondarySchema)
	}
}

// TestTextUseIsReprobedIntoNamespace proves a bare text USE moves the authorization namespace: after USE
// the next statement is decided under the new schema. The proxy re-probes the current database before
// every statement (probe-always), so this holds whether or not the backend emits a SESSION_TRACK_SCHEMA
// signal for the USE.
func TestTextUseIsReprobedIntoNamespace(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := openRawClient(t, h.addr, validToken)

	client.query(t, "USE "+secondarySchema)
	client.query(t, "SELECT id FROM people ORDER BY id")

	requests := h.fake.requests()
	if len(requests) != 2 {
		t.Fatalf("Decide requests = %d, want 2", len(requests))
	}
	if got := requests[0].GetSearchPath(); !reflect.DeepEqual(got, []string{primarySchema}) {
		t.Fatalf("USE SearchPath = %v, want pre-switch [%s]", got, primarySchema)
	}
	if got := requests[1].GetSearchPath(); !reflect.DeepEqual(got, []string{secondarySchema}) {
		t.Fatalf("post-USE SearchPath = %v, want re-probed [%s]", got, secondarySchema)
	}
}

// TestChainedSessionTrackBypassStillReprobesNamespace is the namespace half of the chained
// session-track bypass. A client that
// clears session_track_system_variables (silently defeating the sysvar tracker), then disables
// session_track_schema (now unreported), then issues a bare text USE, defeats every backend signal the
// proxy could observe the switch through — yet the current database really changed. Probe-always closes
// the hole: the proxy re-reads DATABASE() before the next statement, so that statement is authorized under
// the switched schema, never the stale one. The tracker-defeating SETs and the USE all succeed; the guard
// is that the following bare read is decided against the NEW namespace.
func TestChainedSessionTrackBypassStillReprobesNamespace(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := openRawClient(t, h.addr, validToken)

	client.query(t, "SET session_track_system_variables=''")
	client.query(t, "SET SESSION session_track_schema = OFF")
	client.query(t, "USE "+secondarySchema)
	client.query(t, "SELECT id FROM people ORDER BY id")

	requests := h.fake.requests()
	if len(requests) != 4 {
		t.Fatalf("Decide requests = %d, want 4 (two SETs, USE, SELECT)", len(requests))
	}
	if got := requests[3].GetSearchPath(); !reflect.DeepEqual(got, []string{secondarySchema}) {
		t.Fatalf("post-bypass SELECT SearchPath = %v, want re-probed [%s] (stale namespace not defeated)", got, secondarySchema)
	}
}

// TestUnsafeConnectionCharsetFailsClosed is the encoding half of the chained session-track bypass.
// The control plane resolves
// identifiers from the client's SQL bytes read as UTF-8; a connection charset that leaves utf8mb4/utf8
// rebinds the same bytes to different identifiers. A DIRECT `SET NAMES latin1` is caught immediately by
// the OK-packet sysvar tracker and drops the connection. When the tracker is first defeated (chained
// bypass), the change is unreported — but the per-statement charset re-probe still catches it and fails
// the next statement closed, so probe-always covers the encoding invariant the tracker no longer can.
func TestUnsafeConnectionCharsetFailsClosed(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		h := startBroker(t)
		h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
		}
		client := openRawClient(t, h.addr, validToken)
		response := client.firstQueryPacket(t, "SET NAMES latin1")
		if len(response) == 0 || response[0] != 0xff {
			t.Fatalf("SET NAMES latin1 response = %x, want fail-closed ERR", response)
		}
		if got := mysqlwire.ErrString(response); !strings.Contains(got, "character set must remain utf8mb4/utf8") {
			t.Fatalf("charset error = %q, want utf8mb4/utf8 fail-closed", got)
		}
	})

	t.Run("chained past a defeated tracker", func(t *testing.T) {
		h := startBroker(t)
		h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
		}
		client := openRawClient(t, h.addr, validToken)
		// Clear the tracker so the charset change is not reported in its OK, then switch charset (accepted
		// silently), then a bare read whose pre-statement re-probe observes the unsafe charset.
		client.query(t, "SET session_track_system_variables=''")
		client.query(t, "SET NAMES latin1")
		response := client.firstQueryPacket(t, "SELECT id FROM people ORDER BY id")
		if len(response) == 0 || response[0] != 0xff {
			t.Fatalf("post-bypass SELECT response = %x, want fail-closed ERR", response)
		}
		if got := mysqlwire.ErrString(response); !strings.Contains(got, "namespace probe failed") || !strings.Contains(got, "utf8mb4/utf8") {
			t.Fatalf("post-bypass charset error = %q, want probe-time utf8mb4/utf8 fail-closed", got)
		}
	})
}

func TestMultiPacketCommandsFailClosedBeforeForwarding(t *testing.T) {
	h := startBroker(t)
	commands := []struct {
		name string
		cmd  byte
	}{
		{name: "query", cmd: mysqlwire.ComQuery},
		{name: "init-db", cmd: mysqlwire.ComInitDB},
		{name: "field-list", cmd: mysqlwire.ComFieldList},
		{name: "ping", cmd: mysqlwire.ComPing},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			client := openRawClient(t, h.addr, validToken)
			// Send only the exact-max header and command byte. The proxy must reject from the header
			// without allocating or waiting for the remaining 16 MiB body.
			prefix := []byte{0xff, 0xff, 0xff, 0x00, command.cmd}
			if n, err := client.conn.Write(prefix); err != nil || n != len(prefix) {
				t.Fatalf("write max-size command prefix: n=%d err=%v", n, err)
			}
			_, response, err := mysqlwire.ReadPacket(client.conn)
			if err != nil {
				t.Fatalf("read multi-packet refusal: %v", err)
			}
			if len(response) == 0 || response[0] != 0xff {
				t.Fatalf("multi-packet response = %x, want ERR", response)
			}
			if got := mysqlwire.ErrString(response); !strings.Contains(got, "multi-packet commands not yet supported") {
				t.Fatalf("multi-packet error = %q, want unsupported message", got)
			}
		})
	}
	if requests := h.fake.requests(); len(requests) != 0 {
		t.Fatalf("multi-packet command reached authorization as %+v; no partial command may be decided", requests)
	}
}

func TestFieldListIsRejectedFailClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := openRawClient(t, h.addr, validToken)

	// COM_FIELD_LIST carries no SQL the control plane can decide on. The broker must refuse it locally
	// rather than synthesize an equivalent SHOW COLUMNS, so it never reaches the control plane.
	fieldList := append([]byte{mysqlwire.ComFieldList}, "people\x00%\x00"...)
	response := client.command(t, fieldList)
	if len(response) == 0 || response[0] != 0xff {
		t.Fatalf("COM_FIELD_LIST response = %x, want fail-closed ERR", response)
	}
	if got := mysqlwire.ErrString(response); !strings.Contains(got, "COM_FIELD_LIST is not supported") {
		t.Fatalf("COM_FIELD_LIST error = %q, want not-supported message", got)
	}
	if requests := h.fake.requests(); len(requests) != 0 {
		t.Fatalf("Decide requests = %d, want COM_FIELD_LIST refused without reaching the control plane", len(requests))
	}
}

func TestLegacyEOFRelayRewriteAndPing(t *testing.T) {
	h := startBroker(t)
	rewritten := "SELECT 'rewritten'"
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if req.GetSql() == "SELECT 'original'" {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, RewrittenSql: &rewritten}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}

	legacy := openRawClientWithEOF(t, h.addr, validToken, false)
	legacy.query(t, "SELECT id FROM people ORDER BY id")
	ping := legacy.command(t, []byte{mysqlwire.ComPing})
	if len(ping) == 0 || ping[0] != 0x00 {
		t.Fatalf("COM_PING response = %x, want OK", ping)
	}

	conn := h.openDB(t, validToken)
	var got string
	if err := conn.QueryRow("SELECT 'original'").Scan(&got); err != nil {
		t.Fatalf("rewritten query: %v", err)
	}
	if got != "rewritten" {
		t.Fatalf("rewritten query value = %q, want rewritten", got)
	}
}

func TestOversizedUnauthenticatedHandshakeIsRejectedWithoutBody(t *testing.T) {
	server := mysqlproxy.New(0, spi.BackendTarget{}, nil, nil, nil)
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	t.Cleanup(func() {
		server.Shutdown()
		if err := <-serveDone; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, _, err := mysqlwire.ReadPacket(conn); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if _, err := conn.Write([]byte{0xff, 0xff, 0xff, 0x01}); err != nil {
		t.Fatalf("write oversized header: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, _, err := mysqlwire.ReadPacket(conn); err == nil {
		t.Fatal("oversized unauthenticated packet was not rejected")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("proxy waited for oversized body instead of rejecting its header: %v", err)
	}
}

func TestBadTokenFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.mu.Lock()
	h.fake.validateErr = status.Error(codes.Unauthenticated, "rejected")
	h.fake.mu.Unlock()

	bad := h.openDB(t, "it-token-bad")
	if err := bad.Ping(); err == nil {
		t.Fatal("Ping with rejected token succeeded")
	} else if !strings.Contains(err.Error(), "invalid or expired token") {
		t.Fatalf("Ping error = %q, want invalid-token wire error", err)
	}
	_ = bad.Close()
}

func TestPreparedSelectAllowRelaysBinaryRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn := h.openDB(t, validToken)
	const query = "SELECT id, name, ssn FROM people WHERE id = ?"
	stmt, err := conn.Prepare(query)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	rows, err := stmt.Query(1)
	if err != nil {
		t.Fatalf("prepared Query: %v", err)
	}
	var id int
	var name, ssn string
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			t.Fatalf("prepared rows.Next: %v", err)
		}
		t.Fatal("prepared query returned no rows")
	}
	if err := rows.Scan(&id, &name, &ssn); err != nil {
		t.Fatalf("prepared Scan: %v", err)
	}
	if rows.Next() {
		t.Fatal("prepared query returned more than one row")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("prepared rows.Err: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("prepared rows.Close: %v", err)
	}
	if id != 1 || name != "Alice" || ssn != "900101-1234567" {
		t.Fatalf("prepared row = (%d, %q, %q), want (1, Alice, 900101-1234567)", id, name, ssn)
	}

	requests := h.fake.requests()
	if len(requests) != 2 {
		t.Fatalf("Decide requests after PREPARE+EXECUTE = %d, want exactly 2", len(requests))
	}
	if requests[0].GetSql() != query || !strings.Contains(requests[0].GetSql(), "?") {
		t.Fatalf("PREPARE DecisionRequest SQL = %q, want literal placeholder query %q", requests[0].GetSql(), query)
	}
	if got := requests[0].GetSearchPath(); !reflect.DeepEqual(got, []string{primarySchema}) {
		t.Fatalf("PREPARE SearchPath = %v, want [%s]", got, primarySchema)
	}
	if requests[1].GetSql() != query || !strings.Contains(requests[1].GetSql(), "?") {
		t.Fatalf("EXECUTE DecisionRequest SQL = %q, want as-prepared placeholder query %q", requests[1].GetSql(), query)
	}
	if got := requests[1].GetSearchPath(); !reflect.DeepEqual(got, []string{primarySchema}) {
		t.Fatalf("EXECUTE SearchPath = %v, want frozen [%s]", got, primarySchema)
	}

	if err := stmt.Close(); err != nil {
		t.Fatalf("prepared Close: %v", err)
	}
	var followup string
	if err := conn.QueryRow("SELECT name FROM people WHERE id = 2").Scan(&followup); err != nil {
		t.Fatalf("query after COM_STMT_CLOSE: %v", err)
	}
	if followup != "Bob" {
		t.Fatalf("query after COM_STMT_CLOSE = %q, want Bob", followup)
	}
	if got := len(h.fake.requests()); got != 3 {
		t.Fatalf("Decide requests after follow-up query = %d, want 3 (CLOSE adds none)", got)
	}
}

func TestPreparedDenyAtPrepareLeaksNothing(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "prepared ssn is off-limits"}), nil
	}
	conn := h.openDB(t, validToken)
	stmt, err := conn.Prepare("SELECT id, name, ssn FROM people WHERE id = ?")
	if err == nil {
		_ = stmt.Close()
		t.Fatal("Prepare succeeded, want policy denial")
	}
	if stmt != nil {
		t.Fatalf("Prepare statement = %v, want nil on denial", stmt)
	}
	if !strings.Contains(err.Error(), "Error 1142") || !strings.Contains(err.Error(), "proxy-monster denied: prepared ssn is off-limits") {
		t.Fatalf("Prepare error = %q, want 1142 policy denial", err)
	}
	if got := len(h.fake.requests()); got != 1 {
		t.Fatalf("Decide requests after denied PREPARE = %d, want 1", got)
	}

	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	var name string
	if err := conn.QueryRow("SELECT name FROM people WHERE id = 1").Scan(&name); err != nil {
		t.Fatalf("query after denied PREPARE: %v", err)
	}
	if name != "Alice" {
		t.Fatalf("query after denied PREPARE = %q, want Alice", name)
	}
}

func TestPreparedMaskWithoutPermitFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks: []*pb.ColumnMask{
				{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)},
			},
		}), nil
	}
	conn := h.openDB(t, validToken)
	stmt, err := conn.Prepare("SELECT id, name, ssn FROM people WHERE id = ?")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(1)
	if err == nil {
		if rows != nil {
			_ = rows.Close()
		}
		t.Fatal("prepared MASK query succeeded without sql.unmaskable permission")
	}
	if rows != nil {
		t.Fatalf("prepared MASK rows = %v, want nil (no binary row leaked)", rows)
	}
	if !strings.Contains(err.Error(), "cannot be masked on the binary protocol") {
		t.Fatalf("prepared MASK error = %q, want binary-protocol masking failure", err)
	}
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests after PREPARE+EXECUTE = %d, want 2", got)
	}

	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	var ssn string
	if err := conn.QueryRow("SELECT ssn FROM people WHERE id = 1").Scan(&ssn); err != nil {
		t.Fatalf("text query after refused prepared MASK execution: %v", err)
	}
	if ssn != "900101-1234567" {
		t.Fatalf("text query after refused prepared MASK execution = %q, want real ssn", ssn)
	}
}

func TestPreparedMaskWithPermitRelaysVerbatim(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks: []*pb.ColumnMask{
				{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)},
			},
			UnmaskablePermitted: true,
		}), nil
	}
	conn := h.openDB(t, validToken)
	stmt, err := conn.Prepare("SELECT id, name, ssn FROM people WHERE id = ?")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	var id int
	var name, ssn string
	if err := stmt.QueryRow(1).Scan(&id, &name, &ssn); err != nil {
		t.Fatalf("prepared QueryRow: %v", err)
	}
	if id != 1 || name != "Alice" || ssn != "900101-1234567" {
		t.Fatalf("prepared MASK-permitted row = (%d, %q, %q), want verbatim cleartext row", id, name, ssn)
	}
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests after PREPARE+EXECUTE = %d, want 2", got)
	}
}

func TestPreparedInsertAllowReportsAffectedRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn := h.openDB(t, validToken)
	stmt, err := conn.Prepare("INSERT INTO prepared_notes (id, note) VALUES (?, ?)")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(1, "hello")
	if err != nil {
		t.Fatalf("prepared Exec: %v", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected: %v", err)
	}
	if affected != 1 {
		t.Fatalf("RowsAffected = %d, want 1", affected)
	}
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests after PREPARE+EXECUTE = %d, want 2", got)
	}

	var note string
	if err := conn.QueryRow("SELECT note FROM prepared_notes WHERE id = 1").Scan(&note); err != nil {
		t.Fatalf("verify prepared INSERT: %v", err)
	}
	if note != "hello" {
		t.Fatalf("persisted prepared note = %q, want hello", note)
	}
}

func TestPreparedDeprecateEOFMetadataAndExecute(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := openRawClientWithEOF(t, h.addr, validToken, true)
	const query = "SELECT id, name FROM people ORDER BY id"
	prepared := client.prepare(t, query)
	if prepared.NumParams != 0 || prepared.NumColumns != 2 {
		t.Fatalf("PREPARE metadata = params:%d columns:%d, want params:0 columns:2", prepared.NumParams, prepared.NumColumns)
	}
	if got := len(h.fake.requests()); got != 1 {
		t.Fatalf("Decide requests after PREPARE = %d, want 1", got)
	}

	client.executeNoParams(t, prepared.StmtID)
	client.drainResult(t)
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests after EXECUTE = %d, want 2", got)
	}
}

func TestPreparedLifecycleUnknownCloseReset(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := openRawClient(t, h.addr, validToken)

	unknown := client.command(t, stmtExecuteNoParamsPayload(t, 0x7f7e7d7c))
	assertUnknownPreparedStatement(t, unknown)
	if got := len(h.fake.requests()); got != 0 {
		t.Fatalf("Decide requests after unknown EXECUTE = %d, want 0", got)
	}

	first := client.prepare(t, "SELECT id FROM people ORDER BY id")
	if got := len(h.fake.requests()); got != 1 {
		t.Fatalf("Decide requests after first PREPARE = %d, want 1", got)
	}
	closePayload := stmtCommandPayload(t, mysqlwire.ComStmtClose, first.StmtID)
	if err := mysqlwire.WritePacket(client.conn, 0, closePayload); err != nil {
		t.Fatalf("write COM_STMT_CLOSE: %v", err)
	}
	if got := len(h.fake.requests()); got != 1 {
		t.Fatalf("Decide requests after CLOSE = %d, want 1", got)
	}
	closed := client.command(t, stmtExecuteNoParamsPayload(t, first.StmtID))
	assertUnknownPreparedStatement(t, closed)
	if got := len(h.fake.requests()); got != 1 {
		t.Fatalf("Decide requests after CLOSE+closed EXECUTE = %d, want 1", got)
	}

	second := client.prepare(t, "SELECT id FROM people ORDER BY id")
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests after second PREPARE = %d, want 2", got)
	}
	reset := client.command(t, stmtCommandPayload(t, mysqlwire.ComStmtReset, second.StmtID))
	if len(reset) == 0 || reset[0] != 0x00 {
		t.Fatalf("COM_STMT_RESET response = %x, want OK", reset)
	}
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests after RESET = %d, want 2", got)
	}
	client.executeNoParams(t, second.StmtID)
	client.drainResult(t)
	if got := len(h.fake.requests()); got != 3 {
		t.Fatalf("Decide requests after RESET+EXECUTE = %d, want 3", got)
	}
}

func TestPreparedExecuteRevocationDeniesAndDoesNotExecute(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn := h.openDB(t, validToken)
	stmt, err := conn.Prepare("INSERT INTO prepared_notes (id, note) VALUES (?, ?)")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "grant revoked"}), nil
	}
	if _, err := stmt.Exec(11, "leak"); err == nil {
		t.Fatal("prepared Exec succeeded after grant revocation")
	} else if !strings.Contains(err.Error(), "Error 1142") || !strings.Contains(err.Error(), "proxy-monster denied: grant revoked") {
		t.Fatalf("prepared Exec error = %q, want 1142 revoked-grant denial", err)
	}

	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	var count int
	if err := conn.QueryRow("SELECT COUNT(*) FROM prepared_notes WHERE id = 11").Scan(&count); err != nil {
		t.Fatalf("verify revoked prepared INSERT side effect: %v", err)
	}
	if count != 0 {
		t.Fatalf("revoked prepared INSERT row count = %d, want 0", count)
	}
	if got := len(h.fake.requests()); got != 3 {
		t.Fatalf("Decide requests = %d, want 3 (PREPARE, denied EXECUTE, count query)", got)
	}
}

func TestPreparedUnmaskablePermitRevocationFailsClosed(t *testing.T) {
	h := startBroker(t)
	maskDecision := func(permitted bool) *pb.WireDecision {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks: []*pb.ColumnMask{
				{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)},
			},
			UnmaskablePermitted: permitted,
		})
	}
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return maskDecision(true), nil
	}
	conn := h.openDB(t, validToken)
	stmt, err := conn.Prepare("SELECT id, name, ssn FROM people WHERE id = ?")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return maskDecision(false), nil
	}
	rows, err := stmt.Query(1)
	if err == nil {
		if rows != nil {
			_ = rows.Close()
		}
		t.Fatal("prepared MASK query succeeded after sql.unmaskable revocation")
	}
	if rows != nil {
		t.Fatalf("prepared MASK rows = %v, want nil after permit revocation", rows)
	}
	if !strings.Contains(err.Error(), "cannot be masked on the binary protocol") {
		t.Fatalf("prepared MASK error = %q, want binary-protocol masking failure", err)
	}
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests after refused EXECUTE = %d, want 2", got)
	}

	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	var ssn string
	if err := conn.QueryRow("SELECT ssn FROM people WHERE id = 1").Scan(&ssn); err != nil {
		t.Fatalf("text query after unmaskable-permit revocation: %v", err)
	}
	if ssn != "900101-1234567" {
		t.Fatalf("text query after unmaskable-permit revocation = %q, want real ssn", ssn)
	}
	if got := len(h.fake.requests()); got != 3 {
		t.Fatalf("Decide requests after text query = %d, want 3", got)
	}
}

func TestPreparedExecuteUsesFrozenNamespace(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn := h.openDB(t, validToken)
	const preparedQuery = "SELECT ssn FROM people WHERE id = ?"
	stmt, err := conn.Prepare(preparedQuery)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	if _, err := conn.Exec("USE " + secondarySchema); err != nil {
		t.Fatalf("USE secondary database: %v", err)
	}
	var preparedSSN string
	if err := stmt.QueryRow(1).Scan(&preparedSSN); err != nil {
		t.Fatalf("prepared QueryRow after USE: %v", err)
	}
	if preparedSSN != "900101-1234567" {
		t.Fatalf("prepared QueryRow after USE = %q, want primary-schema ssn", preparedSSN)
	}
	var liveName string
	const liveQuery = "SELECT name FROM people WHERE id = 10"
	if err := conn.QueryRow(liveQuery).Scan(&liveName); err != nil {
		t.Fatalf("text QueryRow after USE: %v", err)
	}
	if liveName != "Secondary" {
		t.Fatalf("text QueryRow after USE = %q, want Secondary", liveName)
	}

	requests := h.fake.requests()
	if len(requests) != 4 {
		t.Fatalf("Decide requests = %d, want 4 (PREPARE, USE, EXECUTE, text query)", len(requests))
	}
	if requests[0].GetSql() != preparedQuery || !reflect.DeepEqual(requests[0].GetSearchPath(), []string{primarySchema}) {
		t.Fatalf("PREPARE request = %+v, want SQL %q under [%s]", requests[0], preparedQuery, primarySchema)
	}
	if requests[1].GetSql() != "USE "+secondarySchema {
		t.Fatalf("USE request SQL = %q, want %q", requests[1].GetSql(), "USE "+secondarySchema)
	}
	if requests[2].GetSql() != preparedQuery || !reflect.DeepEqual(requests[2].GetSearchPath(), []string{primarySchema}) {
		t.Fatalf("EXECUTE request = %+v, want as-prepared SQL under frozen [%s]", requests[2], primarySchema)
	}
	if requests[3].GetSql() != liveQuery || !reflect.DeepEqual(requests[3].GetSearchPath(), []string{secondarySchema}) {
		t.Fatalf("post-EXECUTE text request = %+v, want live namespace [%s]", requests[3], secondarySchema)
	}
}

func TestPreparedRewrittenSqlReDecidedAsPrepared(t *testing.T) {
	h := startBroker(t)
	const original = "SELECT id, name, ssn FROM people WHERE id = ?"
	const rewritten = "SELECT `id`, `name`, `ssn` FROM people WHERE id = ?"
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Contains(req.GetSql(), "?") {
			return wireVerdict(&pb.Verdict{
				Decision: pb.EnfAction_MASK,
				Masks: []*pb.ColumnMask{
					{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)},
				},
				RewrittenSql:        proto.String(rewritten),
				UnmaskablePermitted: true,
			}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn := h.openDB(t, validToken)
	stmt, err := conn.Prepare(original)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	var id int
	var name, ssn string
	if err := stmt.QueryRow(1).Scan(&id, &name, &ssn); err != nil {
		t.Fatalf("prepared rewritten QueryRow: %v", err)
	}
	if id != 1 || name != "Alice" || ssn != "900101-1234567" {
		t.Fatalf("prepared rewritten row = (%d, %q, %q), want (1, Alice, 900101-1234567)", id, name, ssn)
	}

	requests := h.fake.requests()
	if len(requests) != 2 {
		t.Fatalf("Decide requests = %d, want PREPARE and EXECUTE", len(requests))
	}
	if requests[0].GetSql() != original {
		t.Fatalf("PREPARE DecisionRequest SQL = %q, want original %q", requests[0].GetSql(), original)
	}
	if requests[1].GetSql() != rewritten {
		t.Fatalf("EXECUTE DecisionRequest SQL = %q, want backend-prepared rewrite %q", requests[1].GetSql(), rewritten)
	}
	for i, request := range requests {
		if got := request.GetSearchPath(); !reflect.DeepEqual(got, []string{primarySchema}) {
			t.Fatalf("DecisionRequest[%d] SearchPath = %v, want [%s]", i, got, primarySchema)
		}
	}
}

type rawClient struct {
	conn         net.Conn
	deprecateEOF bool
}

func openRawClient(t *testing.T, addr, token string) *rawClient {
	t.Helper()
	return openRawClientWithEOF(t, addr, token, true)
}

func rawAuthenticate(t *testing.T, addr, token string) []byte {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()
	greetingSeq, _, err := mysqlwire.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	caps := uint32(mysqlwire.CapProtocol41 | mysqlwire.CapSecureConn | mysqlwire.CapPluginAuth | mysqlwire.CapDeprecateEOF)
	if err := mysqlwire.WritePacket(conn, greetingSeq+1, mysqlwire.ClientHandshakeResponse(caps, "pm", nil)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	switchSeq, _, err := mysqlwire.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read auth switch: %v", err)
	}
	if err := mysqlwire.WritePacket(conn, switchSeq+1, append([]byte(token), 0)); err != nil {
		t.Fatalf("write token: %v", err)
	}
	_, authResult, err := mysqlwire.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	return authResult
}

func openRawClientWithEOF(t *testing.T, addr, token string, deprecateEOF bool) *rawClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	greetingSeq, _, err := mysqlwire.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read proxy greeting: %v", err)
	}
	caps := uint32(mysqlwire.CapProtocol41 | mysqlwire.CapSecureConn | mysqlwire.CapPluginAuth)
	if deprecateEOF {
		caps |= mysqlwire.CapDeprecateEOF
	}
	if err := mysqlwire.WritePacket(conn, greetingSeq+1, mysqlwire.ClientHandshakeResponse(caps, "pm", nil)); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	switchSeq, authSwitch, err := mysqlwire.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read auth switch: %v", err)
	}
	if len(authSwitch) == 0 || authSwitch[0] != 0xfe {
		t.Fatalf("auth switch = %x, want 0xfe mysql_clear_password", authSwitch)
	}
	if err := mysqlwire.WritePacket(conn, switchSeq+1, append([]byte(token), 0)); err != nil {
		t.Fatalf("write token: %v", err)
	}
	_, authResult, err := mysqlwire.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if len(authResult) == 0 || authResult[0] != 0x00 {
		t.Fatalf("auth result = %x, want OK", authResult)
	}
	return &rawClient{conn: conn, deprecateEOF: deprecateEOF}
}

func stmtCommandPayload(t *testing.T, command byte, stmtID uint32) []byte {
	t.Helper()
	payload := make([]byte, 5)
	payload[0] = command
	binary.LittleEndian.PutUint32(payload[1:], stmtID)
	parsedID, err := mysqlwire.StmtID(payload)
	if err != nil {
		t.Fatalf("parse generated COM_STMT command: %v", err)
	}
	if parsedID != stmtID {
		t.Fatalf("generated COM_STMT id = %d, want %d", parsedID, stmtID)
	}
	return payload
}

func stmtExecuteNoParamsPayload(t *testing.T, stmtID uint32) []byte {
	t.Helper()
	payload := stmtCommandPayload(t, mysqlwire.ComStmtExecute, stmtID)
	return append(payload, 0x00, 0x01, 0x00, 0x00, 0x00)
}

func assertUnknownPreparedStatement(t *testing.T, payload []byte) {
	t.Helper()
	if len(payload) < 3 || payload[0] != 0xff {
		t.Fatalf("unknown prepared statement response = %x, want ERR 1243", payload)
	}
	if code := binary.LittleEndian.Uint16(payload[1:3]); code != 1243 {
		t.Fatalf("unknown prepared statement error code = %d, want 1243 (payload %x)", code, payload)
	}
	if message := mysqlwire.ErrString(payload); !strings.Contains(message, "unknown prepared statement") {
		t.Fatalf("unknown prepared statement error = %q, want matching message", message)
	}
}

func (c *rawClient) prepare(t *testing.T, sql string) mysqlwire.StmtPrepareOK {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, 0, mysqlwire.ComStmtPreparePayload(sql)); err != nil {
		t.Fatalf("write COM_STMT_PREPARE: %v", err)
	}
	_, first, err := mysqlwire.ReadPacket(c.conn)
	if err != nil {
		t.Fatalf("read COM_STMT_PREPARE response: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("empty COM_STMT_PREPARE response")
	}
	if first[0] == 0xff {
		t.Fatalf("COM_STMT_PREPARE error: %s", mysqlwire.ErrString(first))
	}
	prepared, err := mysqlwire.ParseStmtPrepareOK(first)
	if err != nil {
		t.Fatalf("parse COM_STMT_PREPARE_OK: %v", err)
	}
	c.drainPrepareMetadata(t, "parameter", prepared.NumParams)
	c.drainPrepareMetadata(t, "column", prepared.NumColumns)
	return prepared
}

func (c *rawClient) drainPrepareMetadata(t *testing.T, kind string, count int) {
	t.Helper()
	for range count {
		if _, _, err := mysqlwire.ReadPacket(c.conn); err != nil {
			t.Fatalf("read prepared-statement %s definition: %v", kind, err)
		}
	}
	if count > 0 && !c.deprecateEOF {
		_, terminator, err := mysqlwire.ReadPacket(c.conn)
		if err != nil {
			t.Fatalf("read prepared-statement %s-definition EOF: %v", kind, err)
		}
		if !mysqlwire.IsResultTerminator(terminator) {
			t.Fatalf("prepared-statement %s-definition terminator = %x, want EOF", kind, terminator)
		}
	}
}

func (c *rawClient) executeNoParams(t *testing.T, stmtID uint32) {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, 0, stmtExecuteNoParamsPayload(t, stmtID)); err != nil {
		t.Fatalf("write COM_STMT_EXECUTE: %v", err)
	}
}

func (c *rawClient) query(t *testing.T, sql string) {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, 0, mysqlwire.ComQueryPayload(sql)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	c.drainResult(t)
}

func (c *rawClient) firstQueryPacket(t *testing.T, sql string) []byte {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, 0, mysqlwire.ComQueryPayload(sql)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	_, payload, err := mysqlwire.ReadPacket(c.conn)
	if err != nil {
		t.Fatalf("read first query packet: %v", err)
	}
	return payload
}

func (c *rawClient) command(t *testing.T, payload []byte) []byte {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, 0, payload); err != nil {
		t.Fatalf("write command: %v", err)
	}
	_, response, err := mysqlwire.ReadPacket(c.conn)
	if err != nil {
		t.Fatalf("read command response: %v", err)
	}
	return response
}

func (c *rawClient) initDB(t *testing.T, database string) {
	t.Helper()
	payload := append([]byte{mysqlwire.ComInitDB}, database...)
	if err := mysqlwire.WritePacket(c.conn, 0, payload); err != nil {
		t.Fatalf("write COM_INIT_DB: %v", err)
	}
	_, response, err := mysqlwire.ReadPacket(c.conn)
	if err != nil {
		t.Fatalf("read COM_INIT_DB response: %v", err)
	}
	if len(response) == 0 || response[0] != 0x00 {
		t.Fatalf("COM_INIT_DB response = %x, want OK", response)
	}
}

func (c *rawClient) textRows(t *testing.T, sql string, expectedColumns int) [][]*string {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, 0, mysqlwire.ComQueryPayload(sql)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	_, first, err := mysqlwire.ReadPacket(c.conn)
	if err != nil {
		t.Fatalf("read result first packet: %v", err)
	}
	count, err := mysqlwire.NewReader(first).Lenenc()
	if err != nil || int(count) != expectedColumns {
		t.Fatalf("result column count = %d (%v), want %d", count, err, expectedColumns)
	}
	for range count {
		if _, _, err := mysqlwire.ReadPacket(c.conn); err != nil {
			t.Fatalf("read column definition: %v", err)
		}
	}
	if !c.deprecateEOF {
		if _, _, err := mysqlwire.ReadPacket(c.conn); err != nil {
			t.Fatalf("read column-definition EOF: %v", err)
		}
	}
	var rows [][]*string
	for {
		_, payload, err := mysqlwire.ReadPacket(c.conn)
		if err != nil {
			t.Fatalf("read result row: %v", err)
		}
		if mysqlwire.IsResultTerminator(payload) {
			return rows
		}
		row, err := mysqlwire.ParseTextRow(payload, expectedColumns)
		if err != nil {
			t.Fatalf("parse text row: %v", err)
		}
		rows = append(rows, row)
	}
}

func (c *rawClient) drainResult(t *testing.T) {
	t.Helper()
	_, first, err := mysqlwire.ReadPacket(c.conn)
	if err != nil {
		t.Fatalf("read result first packet: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("empty first result packet")
	}
	if first[0] == 0xff {
		t.Fatalf("query error: %s", mysqlwire.ErrString(first))
	}
	if first[0] == 0x00 {
		return
	}
	count, err := mysqlwire.NewReader(first).Lenenc()
	if err != nil {
		t.Fatalf("parse result column count: %v", err)
	}
	for range count {
		if _, _, err := mysqlwire.ReadPacket(c.conn); err != nil {
			t.Fatalf("read column definition: %v", err)
		}
	}
	if !c.deprecateEOF {
		if _, _, err := mysqlwire.ReadPacket(c.conn); err != nil {
			t.Fatalf("read column-definition EOF: %v", err)
		}
	}
	for {
		_, payload, err := mysqlwire.ReadPacket(c.conn)
		if err != nil {
			t.Fatalf("read result row: %v", err)
		}
		if len(payload) > 0 && payload[0] == 0xff {
			t.Fatalf("query error: %s", mysqlwire.ErrString(payload))
		}
		if mysqlwire.IsResultTerminator(payload) {
			return
		}
	}
}
