package run_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/db"
	"github.com/ridi-oss/proxy-monster/goproxy/dialects"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/run"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	runSessionID       = "pm-run-session"
	runToken           = "pm-run-token"
	runConnectionID    = "0123456789abcdef"
	runMySQLSchema     = "pm_run_it"
	runMySQLService    = "pm_run_svc"
	runMySQLServicePwd = "pm-run-svc-pw"
	runPGSchema        = "pm_run_it"
)

func wireVerdict(verdict *pb.Verdict) *pb.WireDecision {
	return &pb.WireDecision{Outcome: &pb.WireDecision_Verdict{Verdict: verdict}}
}

type runFakeCP struct {
	pb.UnimplementedControlPlaneServer

	mu              sync.Mutex
	runDecide       func(*pb.DecisionRequest) *pb.WireDecision
	runRequests     []*pb.DecisionRequest
	fragmentPushes  []*pb.SchemaFragmentPush
	closeRequests   []*pb.CloseConnectionRequest
	events          []string
	fragmentPushErr error
	runCommands     chan *pb.ControlRunMsg
	runTranscript   chan *pb.ProxyRunMsg
	runReady        chan struct{}
	readyOnce       sync.Once
}

func runNewFakeCP() *runFakeCP {
	return &runFakeCP{
		runCommands:   make(chan *pb.ControlRunMsg),
		runTranscript: make(chan *pb.ProxyRunMsg, 32),
		runReady:      make(chan struct{}),
	}
}

func (f *runFakeCP) Decide(_ context.Context, req *pb.DecisionRequest) (*pb.WireDecision, error) {
	cloned := proto.Clone(req).(*pb.DecisionRequest)
	f.mu.Lock()
	f.runRequests = append(f.runRequests, cloned)
	f.events = append(f.events, "decide:"+cloned.GetSql())
	decide := f.runDecide
	f.mu.Unlock()
	if decide == nil {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	return proto.Clone(decide(cloned)).(*pb.WireDecision), nil
}

func (f *runFakeCP) PushSchemaFragment(_ context.Context, req *pb.SchemaFragmentPush) (*pb.SchemaFragmentAck, error) {
	cloned := proto.Clone(req).(*pb.SchemaFragmentPush)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fragmentPushes = append(f.fragmentPushes, cloned)
	f.events = append(f.events, "push:"+cloned.GetSchema())
	if f.fragmentPushErr != nil {
		return nil, f.fragmentPushErr
	}
	return &pb.SchemaFragmentAck{Generation: uint64(len(f.fragmentPushes))}, nil
}

func (f *runFakeCP) CloseConnection(_ context.Context, req *pb.CloseConnectionRequest) (*pb.CloseConnectionResponse, error) {
	cloned := proto.Clone(req).(*pb.CloseConnectionRequest)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeRequests = append(f.closeRequests, cloned)
	f.events = append(f.events, "close")
	return &pb.CloseConnectionResponse{}, nil
}

func (f *runFakeCP) RunExec(stream grpc.BidiStreamingServer[pb.ProxyRunMsg, pb.ControlRunMsg]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	f.runTranscript <- proto.Clone(first).(*pb.ProxyRunMsg)
	ready := first.GetSessionReady()
	if ready != nil {
		f.mu.Lock()
		f.events = append(f.events, "ready")
		f.mu.Unlock()
	}
	f.readyOnce.Do(func() { close(f.runReady) })
	if ready == nil {
		return nil
	}

	recvDone := make(chan error, 1)
	go func() {
		for {
			message, err := stream.Recv()
			if err != nil {
				recvDone <- err
				return
			}
			f.runTranscript <- proto.Clone(message).(*pb.ProxyRunMsg)
		}
	}()

	for {
		select {
		case command, ok := <-f.runCommands:
			if !ok {
				return nil
			}
			if err := stream.Send(proto.Clone(command).(*pb.ControlRunMsg)); err != nil {
				return err
			}
		case err := <-recvDone:
			return err
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (f *runFakeCP) runSetDecide(decide func(*pb.DecisionRequest) *pb.WireDecision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runDecide = decide
}

func (f *runFakeCP) runRecordedRequests() []*pb.DecisionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	requests := make([]*pb.DecisionRequest, len(f.runRequests))
	for i, request := range f.runRequests {
		requests[i] = proto.Clone(request).(*pb.DecisionRequest)
	}
	return requests
}

func (f *runFakeCP) runRecordedFragments() []*pb.SchemaFragmentPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	fragments := make([]*pb.SchemaFragmentPush, len(f.fragmentPushes))
	for i, fragment := range f.fragmentPushes {
		fragments[i] = proto.Clone(fragment).(*pb.SchemaFragmentPush)
	}
	return fragments
}

func (f *runFakeCP) runRecordedCloses() []*pb.CloseConnectionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	closes := make([]*pb.CloseConnectionRequest, len(f.closeRequests))
	for i, closeRequest := range f.closeRequests {
		closes[i] = proto.Clone(closeRequest).(*pb.CloseConnectionRequest)
	}
	return closes
}

func (f *runFakeCP) runRecordedEvents() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *runFakeCP) runSetFragmentPushError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fragmentPushErr = err
}

type runEngineFixture struct {
	runDB        engine.Db
	runProvider  spi.Provider
	runTarget    spi.BackendTarget
	runTable     string
	runNamespace []string
}

type runCapturingProvider struct {
	spi.Provider
	readTimeout chan time.Duration
}

func (p *runCapturingProvider) NewRunSession(target spi.BackendTarget, dbImpl engine.Db, client spi.SessionClient, token string, connectionID []byte, guard engine.ExecGuard, readTimeout time.Duration) (spi.BackendSession, error) {
	p.readTimeout <- readTimeout
	return p.Provider.NewRunSession(target, dbImpl, client, token, connectionID, guard, readTimeout)
}

func TestRunnerMySQL(t *testing.T) {
	runEngineContract(t, runSeedMySQL(t))
}

func TestRunnerPostgres(t *testing.T) {
	runEngineContract(t, runSeedPostgres(t))
}

func TestRunnerPostgresTempTablesAreSessionIsolated(t *testing.T) {
	fixture := runSeedPostgres(t)
	tempTable := runUniqueTable("pm_run_temp_isolation")
	createSQL := "CREATE TEMP TABLE " + tempTable + " (id int PRIMARY KEY, note text)"
	readSQL := "SELECT id FROM " + tempTable

	fake1, client1 := runStartFakeCP(t, runSessionID+"-temp-1")
	runLaunchOpen(t, fake1, client1, fixture, spi.RunOpen{
		SessionID:    runSessionID + "-temp-1",
		Token:        runToken,
		ConnectionID: []byte("temp-session-001"),
		OnOpen:       []*pb.Refetch{{Schema: runPGSchema}},
	})
	fake2, client2 := runStartFakeCP(t, runSessionID+"-temp-2")
	runLaunchOpen(t, fake2, client2, fixture, spi.RunOpen{
		SessionID:    runSessionID + "-temp-2",
		Token:        runToken,
		ConnectionID: []byte("temp-session-002"),
		OnOpen:       []*pb.Refetch{{Schema: runPGSchema}},
	})

	runSendQuery(fake1, createSQL, 20)
	runExpectSuccess(t, fake1, 0)
	runSendQuery(fake1, readSQL, 20)
	runExpectDecision(t, runRecv(t, fake1), pb.EnfAction_ALLOW, nil, "")
	runExpectRows(t, runRecv(t, fake1), []string{"id"})
	runExpectDone(t, runRecv(t, fake1), -1)
	requests1 := fake1.runRecordedRequests()
	last1 := requests1[len(requests1)-1]
	if !runRequestHasTempTable(last1, tempTable, "id") || !runRequestHasTempTable(last1, tempTable, "note") {
		t.Fatalf("session 1 temp_columns = %v, want %s.id and %s.note", last1.GetTempColumns(), tempTable, tempTable)
	}

	runSendQuery(fake2, "SELECT 1", 20)
	runExpectDecision(t, runRecv(t, fake2), pb.EnfAction_ALLOW, nil, "")
	runExpectRows(t, runRecv(t, fake2), []string{"?column?"})
	runExpectDone(t, runRecv(t, fake2), -1)
	for _, request := range fake2.runRecordedRequests() {
		if runRequestHasTempTable(request, tempTable, "") {
			t.Fatalf("session 2 DecisionRequest leaked session 1 temp rows: %v", request.GetTempColumns())
		}
	}

	runSendQuery(fake2, readSQL, 20)
	runExpectDecision(t, runRecv(t, fake2), pb.EnfAction_ALLOW, nil, "")
	if message := runRecv(t, fake2); message.GetError() == nil || !strings.Contains(message.GetError().GetMessage(), "does not exist") {
		t.Fatalf("session 2 bare temp read = %v, want backend relation-does-not-exist error", message)
	}
}

func runRequestHasTempTable(request *pb.DecisionRequest, table, column string) bool {
	for _, temp := range request.GetTempColumns() {
		if temp.GetTable() == table && (column == "" || temp.GetColumn() == column) {
			return true
		}
	}
	return false
}

func TestRunnerMalformedOpen(t *testing.T) {
	fixture := runSeedMySQL(t)
	tests := []struct {
		name string
		open spi.RunOpen
	}{
		{
			name: "mapping error closes valid connection",
			open: spi.RunOpen{
				SessionID:    runSessionID,
				Token:        runToken,
				ConnectionID: []byte(runConnectionID),
				MapErr:       errors.New("unsupported run open command"),
			},
		},
		{
			name: "bad connection id fails without close",
			open: spi.RunOpen{
				SessionID:    runSessionID + "-bad-id",
				Token:        runToken,
				ConnectionID: []byte("short"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake, client := runStartFakeCP(t, test.open.SessionID)
			done := make(chan struct{})
			go func() {
				run.NewRunner(client, fixture.runDB, fixture.runTarget, fixture.runProvider, 0).Run(test.open, nil)
				close(done)
			}()
			if message := runRecv(t, fake); message.GetError() == nil {
				t.Fatalf("malformed open message = %v, want RunError", message)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("runner did not terminate after malformed open")
			}
			if len(test.open.ConnectionID) == 16 {
				runExpectSingleClose(t, fake)
			} else if closes := fake.runRecordedCloses(); len(closes) != 0 {
				t.Fatalf("CloseConnection requests = %v, want none for malformed id", closes)
			}
		})
	}
}

func TestRunnerNormalCloseReleasesConnection(t *testing.T) {
	fixture := runSeedMySQL(t)
	fake, client := runStartFakeCP(t, runSessionID)
	waitDone := runLaunch(t, fake, client, fixture)
	fake.runCommands <- &pb.ControlRunMsg{Kind: &pb.ControlRunMsg_Close{Close: &pb.RunClose{}}}
	waitDone()
	runExpectSingleClose(t, fake)
}

func TestRunnerCatalogRefresh(t *testing.T) {
	fixtures := []struct {
		name    string
		fixture runEngineFixture
	}{
		{name: "mysql", fixture: runSeedMySQL(t)},
		{name: "postgres", fixture: runSeedPostgres(t)},
	}
	for _, test := range fixtures {
		t.Run(test.name, func(t *testing.T) {
			runCatalogRefreshContract(t, test.fixture)
		})
	}
}

func runEngineContract(t *testing.T, fixture runEngineFixture) {
	t.Helper()
	fake, client := runStartFakeCP(t, runSessionID)
	runnerDone := runLaunch(t, fake, client, fixture)

	allowSQL := fmt.Sprintf("SELECT id, secret FROM %s WHERE id <= 2 ORDER BY id", fixture.runTable)
	maskSQL := fmt.Sprintf("SELECT id, secret FROM %s WHERE id = 1", fixture.runTable)
	nullSQL := fmt.Sprintf("SELECT id, secret FROM %s WHERE id IN (3, 4) ORDER BY id", fixture.runTable)
	denySQL := fmt.Sprintf("SELECT secret FROM %s WHERE id = 1", fixture.runTable)
	badMaskSQL := fmt.Sprintf("SELECT id FROM %s WHERE id = 1", fixture.runTable)
	capsSQL := fmt.Sprintf("SELECT id FROM %s ORDER BY id", fixture.runTable)
	writeSQL := fmt.Sprintf("UPDATE %s SET note = 'updated' WHERE id IN (1, 2)", fixture.runTable)

	fake.runSetDecide(func(req *pb.DecisionRequest) *pb.WireDecision {
		switch req.GetSql() {
		case maskSQL:
			ordinal := int32(1)
			return wireVerdict(&pb.Verdict{
				Decision:       pb.EnfAction_MASK,
				DecisionId:     102,
				EffectiveRoles: []string{"analyst"},
				Masks:          []*pb.ColumnMask{{Column: "secret", Kind: "FIXED", Ordinal: &ordinal}},
			})
		case denySQL:
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DecisionId: 103, DenyReason: "not granted"})
		case badMaskSQL:
			ordinal := int32(99)
			return wireVerdict(&pb.Verdict{
				Decision:   pb.EnfAction_MASK,
				DecisionId: 104,
				Masks:      []*pb.ColumnMask{{Column: "missing", Kind: "FIXED", Ordinal: &ordinal}},
			})
		default:
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 101, EffectiveRoles: []string{"analyst"}})
		}
	})

	runSendQuery(fake, allowSQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	allowRows := runExpectRows(t, runRecv(t, fake), []string{"id", "secret"})
	runExpectValues(t, allowRows, [][]runExpectedValue{{{value: "1"}, {value: "clear-1"}}, {{value: "2"}, {value: "clear-2"}}})
	runExpectDone(t, runRecv(t, fake), -1)

	requests := fake.runRecordedRequests()
	if len(requests) == 0 {
		t.Fatal("no run Decide request recorded")
	}
	firstRequest := requests[0]
	if firstRequest.GetToken() != runToken || firstRequest.GetSql() != allowSQL || firstRequest.GetClientAddr() != "" || string(firstRequest.GetConnectionId()) != runConnectionID {
		t.Fatalf("first Decide request = %+v", firstRequest)
	}
	if !reflect.DeepEqual(firstRequest.GetSearchPath(), fixture.runNamespace) {
		t.Fatalf("first Decide namespace = %v, want %v", firstRequest.GetSearchPath(), fixture.runNamespace)
	}

	runSendQuery(fake, maskSQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_MASK, []string{"secret"}, "")
	maskRows := runExpectRows(t, runRecv(t, fake), []string{"id", "secret"})
	runExpectValues(t, maskRows, [][]runExpectedValue{{{value: "1"}, {value: "####"}}})
	runExpectDone(t, runRecv(t, fake), -1)

	runSendQuery(fake, nullSQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	nullRows := runExpectRows(t, runRecv(t, fake), []string{"id", "secret"})
	runExpectValues(t, nullRows, [][]runExpectedValue{{{value: "3"}, {isNull: true}}, {{value: "4"}, {value: ""}}})
	runExpectDone(t, runRecv(t, fake), -1)

	runSendQuery(fake, denySQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_DENY, nil, "not granted")
	runExpectSilence(t, fake, 200*time.Millisecond)

	runSendQuery(fake, allowSQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	runExpectRows(t, runRecv(t, fake), []string{"id", "secret"})
	runExpectDone(t, runRecv(t, fake), -1)

	runSendQuery(fake, capsSQL, 3)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if got := len(runExpectRows(t, runRecv(t, fake), []string{"id"})); got != 3 {
		t.Fatalf("maxRows=3 returned %d rows", got)
	}
	runExpectDone(t, runRecv(t, fake), -1)

	runSendQuery(fake, capsSQL, 0)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if got := len(runExpectRows(t, runRecv(t, fake), []string{"id"})); got != 500 {
		t.Fatalf("maxRows=0 returned %d rows", got)
	}
	runExpectDone(t, runRecv(t, fake), -1)

	runSendQuery(fake, capsSQL, 7000)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	firstChunk := runExpectRows(t, runRecv(t, fake), []string{"id"})
	secondChunk := runExpectRows(t, runRecv(t, fake), []string{"id"})
	if len(firstChunk) != 1000 || len(secondChunk) != 200 {
		t.Fatalf("maxRows=7000 chunks = %d + %d, want 1000 + 200", len(firstChunk), len(secondChunk))
	}
	runExpectDone(t, runRecv(t, fake), -1)

	runSendQuery(fake, capsSQL, -9)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if got := len(runExpectRows(t, runRecv(t, fake), []string{"id"})); got != 1 {
		t.Fatalf("negative maxRows returned %d rows", got)
	}
	runExpectDone(t, runRecv(t, fake), -1)

	runSendQuery(fake, writeSQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if got := len(runExpectRows(t, runRecv(t, fake), nil)); got != 0 {
		t.Fatalf("write emitted %d rows, want 0", got)
	}
	runExpectDone(t, runRecv(t, fake), 2)

	runSendQuery(fake, allowSQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	runExpectRows(t, runRecv(t, fake), []string{"id", "secret"})
	runExpectDone(t, runRecv(t, fake), -1)
	requests = fake.runRecordedRequests()
	if got := requests[len(requests)-1].GetSearchPath(); !reflect.DeepEqual(got, fixture.runNamespace) {
		t.Fatalf("post-write Decide namespace = %v, want %v", got, fixture.runNamespace)
	}

	runSendQuery(fake, badMaskSQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_MASK, []string{"missing"}, "")
	errorMessage := runRecv(t, fake).GetError()
	if errorMessage == nil || !strings.Contains(errorMessage.GetMessage(), "mask binding failed") {
		t.Fatalf("bad mask terminal message = %v", errorMessage)
	}
	runnerDone()
	runExpectSingleClose(t, fake)
	runExpectSilence(t, fake, 200*time.Millisecond)
}

func runCatalogRefreshContract(t *testing.T, fixture runEngineFixture) {
	t.Helper()

	t.Run("after_statement refetches before reply and next Decide", func(t *testing.T) {
		fake, client := runStartFakeCP(t, runSessionID)
		runLaunch(t, fake, client, fixture)
		initialPushes := len(fake.runRecordedFragments())
		table := runUniqueTable("pm_run_refresh")
		ddl := runCreateTableSQL(fixture, table)
		nextSQL := "BEGIN"
		fake.runSetDecide(runCatalogRefreshDecider(ddl, fixture.runNamespaceForTable()))

		runSendQuery(fake, ddl, 20)
		runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		runExpectRows(t, runRecv(t, fake), nil)
		runExpectDone(t, runRecv(t, fake), 0)
		fragments := fake.runRecordedFragments()
		if len(fragments) != initialPushes+1 {
			t.Fatalf("fragment pushes = %d, want %d", len(fragments), initialPushes+1)
		}
		if !runFragmentHasTable(fragments[len(fragments)-1], fixture.runNamespaceForTable(), table) {
			t.Fatalf("pushed fragment does not contain %s.%s", fixture.runNamespaceForTable(), table)
		}

		runSendQuery(fake, nextSQL, 20)
		runExpectSuccess(t, fake, 0)
		events := fake.runRecordedEvents()
		pushEvent := "push:" + fixture.runNamespaceForTable()
		if !runLastEventBefore(events, pushEvent, "decide:"+nextSQL) {
			t.Fatalf("events = %v, want after-statement push before next Decide", events)
		}
	})

	t.Run("capped statement does not cap after-statement refetch", func(t *testing.T) {
		fake, client := runStartFakeCP(t, runSessionID)
		runLaunch(t, fake, client, fixture)
		initialPushes := len(fake.runRecordedFragments())
		table := runUniqueTable("pm_run_capped_refresh")
		ddl := runCreateTableSQL(fixture, table)
		fake.runSetDecide(runCatalogRefreshDecider(ddl, fixture.runNamespaceForTable()))

		runSendQuery(fake, ddl, 1)
		runExpectSuccess(t, fake, 0)
		fragments := fake.runRecordedFragments()
		if len(fragments) != initialPushes+1 {
			t.Fatalf("fragment pushes = %d, want %d", len(fragments), initialPushes+1)
		}
		if got := len(fragments[len(fragments)-1].GetColumns()); got <= 2 {
			t.Fatalf("capped refetch returned %d catalog rows, want complete fragment with more than 2", got)
		}
		if !runFragmentHasTable(fragments[len(fragments)-1], fixture.runNamespaceForTable(), table) {
			t.Fatalf("pushed fragment does not contain %s.%s", fixture.runNamespaceForTable(), table)
		}
	})

	t.Run("routine DDL refetches before done", func(t *testing.T) {
		fake, client := runStartFakeCP(t, runSessionID)
		runLaunch(t, fake, client, fixture)
		initialPushes := len(fake.runRecordedFragments())
		table := runUniqueTable("pm_run_routine_refresh")
		var callSQL string
		directSchema := fixture.runNamespaceForTable()
		if fixture.runProvider.Dialect() == engine.MySQL {
			procedure := runUniqueTable("pm_run_routine")
			direct := dbtest.OpenMySQL(t, directSchema)
			if _, err := direct.Exec("CREATE PROCEDURE " + procedure + "() CREATE TABLE " + table + " (id INT PRIMARY KEY)"); err != nil {
				t.Fatalf("create MySQL DDL procedure: %v", err)
			}
			t.Cleanup(func() {
				_, _ = direct.Exec("DROP PROCEDURE IF EXISTS " + procedure)
				_, _ = direct.Exec("DROP TABLE IF EXISTS " + table)
			})
			callSQL = "CALL " + procedure + "()"
		} else {
			procedure := runUniqueTable("pm_run_routine")
			direct := dbtest.OpenPostgres(t, "")
			if _, err := direct.Exec("CREATE OR REPLACE PROCEDURE " + directSchema + "." + procedure + "() LANGUAGE plpgsql AS $$ BEGIN EXECUTE 'CREATE TABLE " + directSchema + "." + table + " (id int)'; END $$"); err != nil {
				t.Fatalf("create PostgreSQL DDL procedure: %v", err)
			}
			t.Cleanup(func() {
				_, _ = direct.Exec("DROP PROCEDURE IF EXISTS " + directSchema + "." + procedure + "()")
				_, _ = direct.Exec("DROP TABLE IF EXISTS " + directSchema + "." + table)
			})
			callSQL = "CALL " + directSchema + "." + procedure + "()"
		}
		fake.runSetDecide(runCatalogRefreshDecider(callSQL, directSchema))

		runSendQuery(fake, callSQL, 20)
		runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		runExpectRows(t, runRecv(t, fake), nil)
		waitForRunFragments(t, fake, initialPushes+1)
		fragments := fake.runRecordedFragments()
		if len(fragments) != initialPushes+1 {
			t.Fatalf("routine fragment pushes before Done = %d, want %d", len(fragments), initialPushes+1)
		}
		if !runFragmentHasTable(fragments[len(fragments)-1], directSchema, table) {
			t.Fatalf("routine fragment does not contain %s.%s", directSchema, table)
		}
		runExpectDone(t, runRecv(t, fake), 0)
	})

	t.Run("before_decide refetches and retries", func(t *testing.T) {
		fake, client := runStartFakeCP(t, runSessionID)
		runLaunch(t, fake, client, fixture)
		initialPushes := len(fake.runRecordedFragments())
		calls := 0
		fake.runSetDecide(func(*pb.DecisionRequest) *pb.WireDecision {
			calls++
			if calls == 1 {
				return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{
					Commands: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{
						Schema: fixture.runNamespaceForTable(),
					}}}},
				}}}
			}
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW})
		})

		runSendQuery(fake, "BEGIN", 20)
		runExpectSuccess(t, fake, 0)
		if calls != 2 {
			t.Fatalf("Decide calls = %d, want 2", calls)
		}
		if got := len(fake.runRecordedFragments()); got != initialPushes+1 {
			t.Fatalf("fragment pushes = %d, want %d after before_decide", got, initialPushes+1)
		}
		events := fake.runRecordedEvents()
		if !runContainsEventSequence(events, []string{
			"decide:BEGIN",
			"push:" + fixture.runNamespaceForTable(),
			"decide:BEGIN",
		}) {
			t.Fatalf("events = %v, want Decide -> refetch -> retry", events)
		}
	})

	t.Run("before_decide retry bound terminates and closes connection", func(t *testing.T) {
		fake, client := runStartFakeCP(t, runSessionID)
		waitDone := runLaunch(t, fake, client, fixture)
		initialPushes := len(fake.runRecordedFragments())
		fake.runSetDecide(func(*pb.DecisionRequest) *pb.WireDecision {
			return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{
				Commands: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{
					Schema: fixture.runNamespaceForTable(),
				}}}},
			}}}
		})

		runSendQuery(fake, "BEGIN", 20)
		if message := runRecv(t, fake); message.GetError() == nil {
			t.Fatalf("unbounded before_decide message = %v, want RunError", message)
		}
		waitDone()
		if got := len(fake.runRecordedRequests()); got != 4 {
			t.Fatalf("Decide calls = %d, want initial plus 3 retries", got)
		}
		if got := len(fake.runRecordedFragments()); got != initialPushes+3 {
			t.Fatalf("fragment pushes = %d, want %d bounded command rounds", got, initialPushes+3)
		}
		runExpectSingleClose(t, fake)
	})

	t.Run("command absent does not refetch", func(t *testing.T) {
		fake, client := runStartFakeCP(t, runSessionID)
		runLaunch(t, fake, client, fixture)
		initialPushes := len(fake.runRecordedFragments())
		ddl := runCreateTableSQL(fixture, runUniqueTable("pm_run_no_refresh"))

		runSendQuery(fake, ddl, 20)
		runExpectSuccess(t, fake, 0)
		if got := len(fake.runRecordedFragments()); got != initialPushes {
			t.Fatalf("fragment pushes = %d, want unchanged %d", got, initialPushes)
		}
	})

	t.Run("push failure terminates stream and closes connection", func(t *testing.T) {
		fake, client := runStartFakeCP(t, runSessionID)
		waitDone := runLaunch(t, fake, client, fixture)
		initialPushes := len(fake.runRecordedFragments())
		ddl := runCreateTableSQL(fixture, runUniqueTable("pm_run_push_failure"))
		fake.runSetDecide(runCatalogRefreshDecider(ddl, fixture.runNamespaceForTable()))
		fake.runSetFragmentPushError(errors.New("injected fragment push failure"))

		runSendQuery(fake, ddl, 20)
		runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		if message := runRecv(t, fake); message.GetError() == nil {
			t.Fatalf("push-failed DDL message = %v, want RunError", message)
		}
		waitDone()
		if got := len(fake.runRecordedFragments()); got != initialPushes+1 {
			t.Fatalf("fragment pushes = %d, want %d including failed attempt", got, initialPushes+1)
		}
		runExpectSingleClose(t, fake)
	})

	t.Run("backend-failed DDL does not refetch", func(t *testing.T) {
		fake, client := runStartFakeCP(t, runSessionID)
		waitDone := runLaunch(t, fake, client, fixture)
		initialPushes := len(fake.runRecordedFragments())
		ddl := fmt.Sprintf("CREATE TABLE %s (id INT PRIMARY KEY)", fixture.runTable)
		fake.runSetDecide(runCatalogRefreshDecider(ddl, fixture.runNamespaceForTable()))

		runSendQuery(fake, ddl, 20)
		runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		if message := runRecv(t, fake); message.GetError() == nil {
			t.Fatalf("backend-failed DDL message = %v, want RunError", message)
		}
		waitDone()
		if got := len(fake.runRecordedFragments()); got != initialPushes {
			t.Fatalf("fragment pushes = %d, want unchanged %d", got, initialPushes)
		}
		runExpectSingleClose(t, fake)
	})

	if fixture.runProvider.Dialect() == engine.Postgres {
		t.Run("transactional DDL refetches inside the open transaction", func(t *testing.T) {
			fake, client := runStartFakeCP(t, runSessionID)
			runLaunch(t, fake, client, fixture)
			initialPushes := len(fake.runRecordedFragments())
			table := runUniqueTable("pm_run_tx_refresh")
			ddl := runCreateTableSQL(fixture, table)
			fake.runSetDecide(runCatalogRefreshDecider(ddl, fixture.runNamespaceForTable()))

			runSendQuery(fake, "BEGIN", 20)
			runExpectSuccess(t, fake, 0)
			runSendQuery(fake, ddl, 20)
			runExpectSuccess(t, fake, 0)
			fragments := fake.runRecordedFragments()
			if len(fragments) != initialPushes+1 {
				t.Fatalf("fragment pushes before COMMIT = %d, want %d", len(fragments), initialPushes+1)
			}
			if !runFragmentHasTable(fragments[len(fragments)-1], fixture.runNamespaceForTable(), table) {
				t.Fatalf("in-transaction fragment does not contain %s.%s", fixture.runNamespaceForTable(), table)
			}
			runSendQuery(fake, "ROLLBACK", 20)
			runExpectSuccess(t, fake, 0)
		})
	}
}

func runCatalogRefreshDecider(flaggedSQL, schema string) func(*pb.DecisionRequest) *pb.WireDecision {
	return func(req *pb.DecisionRequest) *pb.WireDecision {
		verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
		if req.GetSql() == flaggedSQL {
			verdict.AfterStatement = []*pb.ProxyCommand{{
				Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: schema}},
			}}
		}
		return wireVerdict(verdict)
	}
}

func runUniqueTable(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func runCreateTableSQL(fixture runEngineFixture, table string) string {
	return fmt.Sprintf("CREATE TABLE %s.%s (id INT PRIMARY KEY)", fixture.runNamespaceForTable(), table)
}

func (f runEngineFixture) runNamespaceForTable() string {
	if f.runProvider.Dialect() == engine.MySQL {
		return runMySQLSchema
	}
	return runPGSchema
}

func runFragmentHasTable(fragment *pb.SchemaFragmentPush, schema, table string) bool {
	for _, column := range fragment.GetColumns() {
		if column.GetSchema() == schema && column.GetTable() == table {
			return true
		}
	}
	return false
}

func runLastEventBefore(events []string, first, second string) bool {
	firstIndex := -1
	secondIndex := -1
	for i, event := range events {
		if event == first {
			firstIndex = i
		}
		if event == second && secondIndex < 0 {
			secondIndex = i
		}
	}
	return firstIndex >= 0 && secondIndex >= 0 && firstIndex < secondIndex
}

func waitForRunFragments(t *testing.T, fake *runFakeCP, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(fake.runRecordedFragments()) < count && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(fake.runRecordedFragments()); got < count {
		t.Fatalf("fragment pushes = %d, want at least %d", got, count)
	}
}

func runContainsEventSequence(events, sequence []string) bool {
	matched := 0
	for _, event := range events {
		if matched < len(sequence) && event == sequence[matched] {
			matched++
		}
	}
	return matched == len(sequence)
}

func runExpectSingleClose(t *testing.T, fake *runFakeCP) {
	t.Helper()
	closes := fake.runRecordedCloses()
	if len(closes) != 1 || string(closes[0].GetConnectionId()) != runConnectionID {
		t.Fatalf("CloseConnection requests = %v, want one for %x", closes, []byte(runConnectionID))
	}
}

func runExpectSuccess(t *testing.T, fake *runFakeCP, rowsAffected int32) {
	t.Helper()
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	runExpectRows(t, runRecv(t, fake), nil)
	runExpectDone(t, runRecv(t, fake), rowsAffected)
}

// TestRunnerMySQLReprobesNamespaceAfterTrackerBypass is the run channel's namespace half of the
// chained session-track bypass. A
// client clears session_track_system_variables (silently defeating the sysvar tracker), then disables
// session_track_schema (now unreported), then switches databases with a bare USE — defeating every backend
// signal the proxy could observe the switch through. The current database really changed, so authorizing
// the next statement under the stale schema would let it escape its policy. Probe-always closes the hole:
// the engine re-reads DATABASE() before the next statement, so it is decided under the switched schema. The
// tracker-defeating SETs and the USE all succeed; the guard is the re-probed namespace of the bare read.
func TestRunnerMySQLReprobesNamespaceAfterTrackerBypass(t *testing.T) {
	fixture := runSeedMySQL(t)
	const runMySQLAltSchema = runMySQLSchema + "_alt"
	seed := dbtest.OpenMySQL(t, "")
	for _, statement := range []string{
		"CREATE DATABASE IF NOT EXISTS " + runMySQLAltSchema,
		"GRANT ALL ON " + runMySQLAltSchema + ".* TO '" + runMySQLService + "'@'%'",
		"FLUSH PRIVILEGES",
	} {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("bypass seed %q: %v", statement, err)
		}
	}

	fake, client := runStartFakeCP(t, runSessionID)
	runLaunch(t, fake, client, fixture)

	for _, bypassSQL := range []string{
		"SET session_track_system_variables=''",
		"SET SESSION session_track_schema = OFF",
		"USE " + runMySQLAltSchema,
	} {
		runSendQuery(fake, bypassSQL, 20)
		runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		runExpectRows(t, runRecv(t, fake), nil)
		runExpectDone(t, runRecv(t, fake), 0)
	}

	runSendQuery(fake, "SELECT 1", 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	runExpectRows(t, runRecv(t, fake), []string{"1"})
	runExpectDone(t, runRecv(t, fake), -1)

	requests := fake.runRecordedRequests()
	if got := requests[len(requests)-1].GetSearchPath(); !reflect.DeepEqual(got, []string{runMySQLAltSchema}) {
		t.Fatalf("post-bypass Decide namespace = %v, want re-probed %v (stale namespace not defeated)", got, []string{runMySQLAltSchema})
	}
}

// TestRunnerPostgresRejectsUnsafeGUC proves the persistent PostgreSQL session holds the UTF-8 and
// on-mode invariants the wire relay enforces (pgproxy/relay.go), so a session-scoped GUC change that
// would let the control plane and the backend bind different objects for the same bytes fails closed and
// terminates the session before any follow-up query can run.
func TestRunnerPostgresRejectsUnsafeGUC(t *testing.T) {
	fixture := runSeedPostgres(t)
	for _, unsafeSQL := range []string{
		"SET client_encoding TO 'LATIN1'",
		"SET standard_conforming_strings TO off",
	} {
		runAssertUnsafeGUCTerminates(t, fixture, unsafeSQL)
	}
}

func runAssertUnsafeGUCTerminates(t *testing.T, fixture runEngineFixture, unsafeSQL string) {
	t.Helper()
	fake, client := runStartFakeCP(t, runSessionID)
	waitDone := runLaunch(t, fake, client, fixture)

	runSendQuery(fake, unsafeSQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := runRecv(t, fake); message.GetError() == nil {
		t.Fatalf("[%s] expected RunError after unsafe GUC change, got %v", unsafeSQL, message)
	}
	waitDone()
	runExpectSilence(t, fake, 200*time.Millisecond)
}

// TestRunnerMySQLRejectsUnsafeSessionState proves the persistent MySQL session fails closed on the
// ways a control-plane-allowed SET can defeat authorization on a stateless relay. A DIRECT change to a
// tracked variable (schema tracking off, or a connection charset that leaves utf8mb4) is caught in the
// OK-packet sysvar tracker, so the offending statement is itself the terminal event — the failure is
// prompt, never a timeout. When the client first defeats the tracker (chained bypass), the later charset
// change is unreported; the per-statement charset re-probe then catches it and fails the next statement
// closed before it can run under a rebinding charset. Every case is deterministic and terminates promptly.
func TestRunnerMySQLRejectsUnsafeSessionState(t *testing.T) {
	fixture := runSeedMySQL(t)

	// Direct tampering: the tracker reports the change in the OK of the very statement that made it, so the
	// session fails closed on that statement.
	t.Run("direct schema-tracking disable", func(t *testing.T) {
		runAssertUnsafeMySQLStatementTerminates(t, fixture, "SET SESSION session_track_schema = OFF")
	})
	t.Run("direct charset change", func(t *testing.T) {
		runAssertUnsafeMySQLStatementTerminates(t, fixture, "SET NAMES latin1")
	})

	// Chained bypass: clearing session_track_system_variables first leaves the later charset change
	// unreported, so the tracker cannot catch it. The charset re-probe run before the following statement
	// does — that statement fails closed rather than binding identifiers under latin1.
	t.Run("charset past a defeated tracker", func(t *testing.T) {
		fake, client := runStartFakeCP(t, runSessionID)
		waitDone := runLaunch(t, fake, client, fixture)

		// Both SETs succeed silently: once the tracker list is empty the charset change is unreported.
		for _, silentSQL := range []string{"SET session_track_system_variables=''", "SET NAMES latin1"} {
			runSendQuery(fake, silentSQL, 20)
			runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
			runExpectRows(t, runRecv(t, fake), nil)
			runExpectDone(t, runRecv(t, fake), 0)
		}

		// The next statement's pre-authorization namespace/charset re-probe observes latin1 and fails closed
		// (a Fail verdict, so no Decision precedes the terminal error).
		runSendQuery(fake, "SELECT 1", 20)
		if message := runRecv(t, fake); message.GetError() == nil {
			t.Fatalf("expected RunError from the charset re-probe, got %v", message)
		}
		waitDone()
		runExpectSilence(t, fake, 200*time.Millisecond)
	})
}

func runAssertUnsafeMySQLStatementTerminates(t *testing.T, fixture runEngineFixture, unsafeSQL string) {
	t.Helper()
	fake, client := runStartFakeCP(t, runSessionID)
	waitDone := runLaunch(t, fake, client, fixture)

	runSendQuery(fake, unsafeSQL, 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := runRecv(t, fake); message.GetError() == nil {
		t.Fatalf("[%s] expected RunError after unsafe session-state change, got %v", unsafeSQL, message)
	}
	waitDone()
	runExpectSilence(t, fake, 200*time.Millisecond)
}

// TestRunnerMySQLCancelsSlowQuery proves the per-statement watchdog reaches the backend AND that a
// timed-out statement is reported as a timeout, never a success: with an injected short timeout the runner
// dials a side connection and issues KILL QUERY, interrupting SLEEP(30) fast. MySQL SLEEP returns a success
// row (1) when interrupted — but the watchdog's verdict overrides the backend, so the proxy sends the
// PM_QUERY_TIMEOUT sentinel error rather than a row + Done.
func TestRunnerMySQLCancelsSlowQuery(t *testing.T) {
	fixture := runSeedMySQL(t)
	fake, client := runStartFakeCP(t, runSessionID)
	runLaunchConfigured(t, fake, client, fixture, func(r *run.Runner) {
		r.SetQueryTimeoutForTest(750 * time.Millisecond)
	})

	start := time.Now()
	runSendQuery(fake, "SELECT SLEEP(30)", 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := runRecv(t, fake); message.GetError() == nil {
		t.Fatalf("expected a RunError after watchdog cancellation, got %v", message)
	} else if got := message.GetError().GetMessage(); got != run.QueryTimeoutMessage {
		t.Fatalf("expected the PM_QUERY_TIMEOUT sentinel, got %q", got)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("SLEEP(30) resolved in %s; the watchdog did not interrupt it", elapsed)
	}
}

// TestRunnerPostgresCancelsSlowQuery proves the watchdog's out-of-band CancelRequest reaches the
// backend: pg_sleep(30) is canceled fast, the backend replies with an ErrorResponse, and the session ends
// with a terminal error instead of blocking for the production timeout.
func TestRunnerPostgresCancelsSlowQuery(t *testing.T) {
	fixture := runSeedPostgres(t)
	fake, client := runStartFakeCP(t, runSessionID)
	waitDone := runLaunchConfigured(t, fake, client, fixture, func(r *run.Runner) {
		r.SetQueryTimeoutForTest(750 * time.Millisecond)
	})

	start := time.Now()
	runSendQuery(fake, "SELECT pg_sleep(30)", 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := runRecv(t, fake); message.GetError() == nil {
		t.Fatalf("expected RunError after watchdog cancellation, got %v", message)
	} else if got := message.GetError().GetMessage(); got != run.QueryTimeoutMessage {
		t.Fatalf("expected the PM_QUERY_TIMEOUT sentinel, got %q", got)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("pg_sleep(30) resolved in %s; the watchdog did not interrupt it", elapsed)
	}
	waitDone()
	runExpectSilence(t, fake, 200*time.Millisecond)
}

func TestRunnerMySQLCancelInFlightKeepsSessionUsable(t *testing.T) {
	fixture := runSeedMySQL(t)
	fake, client := runStartFakeCP(t, runSessionID)
	runLaunch(t, fake, client, fixture)

	start := time.Now()
	runSendQuery(fake, "SELECT SLEEP(30)", 20)
	runWaitForRequests(t, fake, 1)
	runWaitForMySQLSleep(t, fixture, "SELECT SLEEP(30)")
	runSendCancel(fake)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	rows := runExpectRows(t, runRecv(t, fake), []string{"SLEEP(30)"})
	runExpectValues(t, rows, [][]runExpectedValue{{{value: "1"}}})
	runExpectDone(t, runRecv(t, fake), -1)
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("SLEEP(30) resolved in %s; RunCancel did not interrupt it", elapsed)
	}

	runSendQuery(fake, "SELECT 42", 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	rows = runExpectRows(t, runRecv(t, fake), []string{"42"})
	runExpectValues(t, rows, [][]runExpectedValue{{{value: "42"}}})
	runExpectDone(t, runRecv(t, fake), -1)
}

func TestRunnerPostgresCancelInFlightTerminatesStream(t *testing.T) {
	fixture := runSeedPostgres(t)
	fake, client := runStartFakeCP(t, runSessionID)
	waitDone := runLaunch(t, fake, client, fixture)

	start := time.Now()
	runSendQuery(fake, "SELECT pg_sleep(30)", 20)
	runWaitForRequests(t, fake, 1)
	runWaitForPostgresSleep(t, fixture)
	runSendCancel(fake)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := runRecv(t, fake); message.GetError() == nil {
		t.Fatalf("expected RunError after RunCancel, got %v", message)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("pg_sleep(30) resolved in %s; RunCancel did not interrupt it", elapsed)
	}
	waitDone()
	runExpectSilence(t, fake, 200*time.Millisecond)
}

func TestRunnerCancelWhileIdleIsNoOp(t *testing.T) {
	fixture := runSeedMySQL(t)
	fake, client := runStartFakeCP(t, runSessionID)
	runLaunch(t, fake, client, fixture)

	runSendCancel(fake)
	runSendQuery(fake, "SELECT 7", 20)
	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	rows := runExpectRows(t, runRecv(t, fake), []string{"7"})
	runExpectValues(t, rows, [][]runExpectedValue{{{value: "7"}}})
	runExpectDone(t, runRecv(t, fake), -1)
}

func TestRunnerDrainReturnsWhenIdle(t *testing.T) {
	fixture := runSeedMySQL(t)
	fake, client := runStartFakeCP(t, runSessionID)
	draining := make(chan struct{})
	done := make(chan struct{})
	go func() {
		run.NewRunner(client, fixture.runDB, fixture.runTarget, fixture.runProvider, 0).Run(runOpen(fixture), draining)
		close(done)
	}()

	select {
	case <-fake.runReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the runner to start")
	}
	if first := runRecv(t, fake); first.GetSessionReady() == nil {
		t.Fatalf("expected SessionReady, got %v", first)
	}

	// The runner is idle between statements. A drain must return it without a Close from the control plane,
	// so the session ends and the editor re-homes to the replacement.
	close(draining)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not return on drain while idle")
	}
}

func TestRunnerDrainLetsInFlightStatementFinish(t *testing.T) {
	fixture := runSeedMySQL(t)
	fake, client := runStartFakeCP(t, runSessionID)
	draining := make(chan struct{})
	done := make(chan struct{})
	go func() {
		run.NewRunner(client, fixture.runDB, fixture.runTarget, fixture.runProvider, 0).Run(runOpen(fixture), draining)
		close(done)
	}()

	select {
	case <-fake.runReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the runner to start")
	}
	if first := runRecv(t, fake); first.GetSessionReady() == nil {
		t.Fatalf("expected SessionReady, got %v", first)
	}

	// Put a statement in flight, then drain mid-statement. The drain is observed only between statements, so
	// the running SLEEP must complete and return its row (0 == slept the full duration, not interrupted)
	// before the runner exits — draining must NOT cut it.
	runSendQuery(fake, "SELECT SLEEP(2)", 20)
	runWaitForRequests(t, fake, 1)
	runWaitForMySQLSleep(t, fixture, "SELECT SLEEP(2)")
	close(draining)

	runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	rows := runExpectRows(t, runRecv(t, fake), []string{"SLEEP(2)"})
	runExpectValues(t, rows, [][]runExpectedValue{{{value: "0"}}})
	runExpectDone(t, runRecv(t, fake), -1)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not exit after the in-flight statement finished")
	}
}

func TestRunnerDrainDoesNotStartAQueuedQuery(t *testing.T) {
	fixture := runSeedMySQL(t)
	fake, client := runStartFakeCP(t, runSessionID)
	draining := make(chan struct{})
	done := make(chan struct{})
	go func() {
		run.NewRunner(client, fixture.runDB, fixture.runTarget, fixture.runProvider, 0).Run(runOpen(fixture), draining)
		close(done)
	}()

	select {
	case <-fake.runReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the runner to start")
	}
	if first := runRecv(t, fake); first.GetSessionReady() == nil {
		t.Fatalf("expected SessionReady, got %v", first)
	}

	// Drain, then hand the runner a query. A query racing in with the drain must not start a new statement on
	// a departing proxy: the runner returns without a decision or rows, and the editor re-homes.
	close(draining)
	runSendQuery(fake, "SELECT 1", 20)

	runExpectSilence(t, fake, 500*time.Millisecond)
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("runner did not exit after draining with a queued query")
	}
}

func TestRunnerCloseInFlightCancelsBackend(t *testing.T) {
	fixture := runSeedMySQL(t)
	fake, client := runStartFakeCP(t, runSessionID)
	waitDone := runLaunch(t, fake, client, fixture)

	runSendQuery(fake, "SELECT SLEEP(30)", 20)
	runWaitForRequests(t, fake, 1)
	runWaitForMySQLSleep(t, fixture, "SELECT SLEEP(30)")
	start := time.Now()
	runSendClose(fake)
	waitDone()
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("runner closed in %s; RunClose did not interrupt the backend statement", elapsed)
	}
	runExpectSingleClose(t, fake)
	runExpectMySQLSleepStopped(t, fixture)
}

func TestRunnerPassesQueryTimeoutPlusGraceToRunSession(t *testing.T) {
	fixture := runSeedMySQL(t)
	capturing := &runCapturingProvider{Provider: fixture.runProvider, readTimeout: make(chan time.Duration, 1)}
	fixture.runProvider = capturing
	fake, client := runStartFakeCP(t, runSessionID)
	waitDone := runLaunchWithTimeout(t, fake, client, fixture, 17*time.Second)

	select {
	case got := <-capturing.readTimeout:
		if got != 47*time.Second {
			t.Fatalf("NewRunSession readTimeout = %s, want 47s", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for NewRunSession readTimeout")
	}
	runSendClose(fake)
	waitDone()
}

// runLaunch starts a runner against fixture over fake+client, completes its on-open refetch, then
// waits for and consumes SessionReady. It returns a function that blocks until the runner goroutine exits.
func runLaunch(t *testing.T, fake *runFakeCP, client *cp.Client, fixture runEngineFixture) func() {
	t.Helper()
	return runLaunchConfigured(t, fake, client, fixture, nil)
}

func runLaunchWithTimeout(t *testing.T, fake *runFakeCP, client *cp.Client, fixture runEngineFixture, queryTimeout time.Duration) func() {
	t.Helper()
	return runLaunchOpenConfigured(t, fake, client, fixture, runOpen(fixture), queryTimeout, nil)
}

// runLaunchConfigured is runLaunch with a hook to tweak the runner (e.g. inject a short watchdog
// timeout) before Run. It returns a function that blocks until the runner goroutine exits.
func runLaunchConfigured(t *testing.T, fake *runFakeCP, client *cp.Client, fixture runEngineFixture, configure func(*run.Runner)) func() {
	t.Helper()
	return runLaunchOpenConfigured(t, fake, client, fixture, runOpen(fixture), 0, configure)
}

func runLaunchOpen(t *testing.T, fake *runFakeCP, client *cp.Client, fixture runEngineFixture, open spi.RunOpen) func() {
	t.Helper()
	return runLaunchOpenConfigured(t, fake, client, fixture, open, 0, nil)
}

func runLaunchOpenConfigured(t *testing.T, fake *runFakeCP, client *cp.Client, fixture runEngineFixture, open spi.RunOpen, queryTimeout time.Duration, configure func(*run.Runner)) func() {
	t.Helper()
	runner := run.NewRunner(client, fixture.runDB, fixture.runTarget, fixture.runProvider, queryTimeout)
	if configure != nil {
		configure(runner)
	}
	done := make(chan struct{})
	go func() {
		runner.Run(open, nil)
		close(done)
	}()
	select {
	case <-fake.runReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for first run message")
	}
	first := runRecv(t, fake)
	if first.GetSessionReady() == nil {
		t.Fatalf("run initialization failed before SessionReady: %v", first)
	}
	ready := first.GetSessionReady()
	if ready.GetSessionId() != open.SessionID {
		t.Fatalf("SessionReady = %v, want session %q", ready, open.SessionID)
	}
	fragments := fake.runRecordedFragments()
	if len(fragments) != 1 || fragments[0].GetSchema() != fixture.runNamespaceForTable() {
		t.Fatalf("on-open fragments = %v, want schema %q before SessionReady", fragments, fixture.runNamespaceForTable())
	}
	if events := fake.runRecordedEvents(); !runLastEventBefore(events, "push:"+fixture.runNamespaceForTable(), "ready") {
		t.Fatalf("events = %v, want on-open push acknowledged before SessionReady", events)
	}
	return func() {
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("runner did not terminate")
		}
	}
}

func runOpen(fixture runEngineFixture) spi.RunOpen {
	return spi.RunOpen{
		SessionID:    runSessionID,
		Token:        runToken,
		ConnectionID: []byte(runConnectionID),
		OnOpen: []*pb.Refetch{{
			Schema: fixture.runNamespaceForTable(),
		}},
	}
}

func runStartFakeCP(t *testing.T, datasourceName string) (*runFakeCP, *cp.Client) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake run control plane: %v", err)
	}
	fake := runNewFakeCP()
	server := grpc.NewServer()
	pb.RegisterControlPlaneServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		close(fake.runCommands)
		server.Stop()
		_ = listener.Close()
	})

	client, err := cp.New(listener.Addr().String(), "run-secret", datasourceName)
	if err != nil {
		t.Fatalf("cp.New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return fake, client
}

func runSeedMySQL(t *testing.T) runEngineFixture {
	t.Helper()
	backend := dbtest.MySQL(t)
	seed := dbtest.OpenMySQL(t, "")
	statements := []string{
		"CREATE DATABASE IF NOT EXISTS " + runMySQLSchema,
		"CREATE TABLE IF NOT EXISTS " + runMySQLSchema + ".pm_run_rows (id INT PRIMARY KEY, secret VARCHAR(64) NULL, note VARCHAR(64) NOT NULL DEFAULT '')",
		"DELETE FROM " + runMySQLSchema + ".pm_run_rows",
		// caching_sha2_password (mysql:8.0 default) so the run channel's shared backend dial is exercised against
		// it too; the ALTER re-salts each run, forcing the plaintext full-auth (public-key) path on first dial.
		"CREATE USER IF NOT EXISTS '" + runMySQLService + "'@'%' IDENTIFIED WITH caching_sha2_password BY '" + runMySQLServicePwd + "'",
		"ALTER USER '" + runMySQLService + "'@'%' IDENTIFIED WITH caching_sha2_password BY '" + runMySQLServicePwd + "'",
		"GRANT ALL ON " + runMySQLSchema + ".* TO '" + runMySQLService + "'@'%'",
		"FLUSH PRIVILEGES",
	}
	for _, statement := range statements {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("MySQL seed statement %q: %v", statement, err)
		}
	}
	runSeedRows(t, seed, "INSERT INTO "+runMySQLSchema+".pm_run_rows (id, secret) VALUES ")
	return runEngineFixture{
		runDB:       db.MySqlDb{},
		runProvider: mustProvider(t, engine.MySQL),
		runTarget: spi.BackendTarget{
			Host: backend.Host, Port: backend.Port, Db: runMySQLSchema,
			User: runMySQLService, Password: runMySQLServicePwd,
		},
		runTable:     runMySQLSchema + ".pm_run_rows",
		runNamespace: []string{runMySQLSchema},
	}
}

func runSeedPostgres(t *testing.T) runEngineFixture {
	t.Helper()
	backend := dbtest.Postgres(t)
	seed := dbtest.OpenPostgres(t, "")
	statements := []string{
		"CREATE SCHEMA IF NOT EXISTS " + runPGSchema,
		"CREATE TABLE IF NOT EXISTS " + runPGSchema + ".pm_run_rows (id int PRIMARY KEY, secret text NULL, note text NOT NULL DEFAULT '')",
		"DELETE FROM " + runPGSchema + ".pm_run_rows",
	}
	for _, statement := range statements {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("Postgres seed statement %q: %v", statement, err)
		}
	}
	runSeedRows(t, seed, "INSERT INTO "+runPGSchema+".pm_run_rows (id, secret) VALUES ")
	return runEngineFixture{
		runDB:       db.PgDb{},
		runProvider: mustProvider(t, engine.Postgres),
		runTarget: spi.BackendTarget{
			Host: backend.Host, Port: backend.Port, Db: backend.DB,
			User: backend.User, Password: backend.Password,
		},
		runTable:     runPGSchema + ".pm_run_rows",
		runNamespace: []string{"pg_catalog", "public"},
	}
}

func mustProvider(t *testing.T, dialect engine.Dialect) spi.Provider {
	t.Helper()
	provider, err := dialects.For(dialect)
	if err != nil {
		t.Fatalf("dialects.For(%v): %v", dialect, err)
	}
	return provider
}

func runSeedRows(t *testing.T, seed *sql.DB, prefix string) {
	t.Helper()
	var statement strings.Builder
	statement.WriteString(prefix)
	for id := 1; id <= 1200; id++ {
		if id > 1 {
			statement.WriteByte(',')
		}
		statement.WriteString(fmt.Sprintf("(%d,", id))
		switch id {
		case 1:
			statement.WriteString("'clear-1'")
		case 2:
			statement.WriteString("'clear-2'")
		case 3:
			statement.WriteString("NULL")
		case 4:
			statement.WriteString("''")
		default:
			statement.WriteString("'bulk'")
		}
		statement.WriteByte(')')
	}
	if _, err := seed.Exec(statement.String()); err != nil {
		t.Fatalf("bulk seed run rows: %v", err)
	}
}

func runSendQuery(fake *runFakeCP, sql string, maxRows int32) {
	fake.runCommands <- &pb.ControlRunMsg{Kind: &pb.ControlRunMsg_Query{
		Query: &pb.RunQuery{Sql: sql, MaxRows: maxRows},
	}}
}

func runSendCancel(fake *runFakeCP) {
	fake.runCommands <- &pb.ControlRunMsg{Kind: &pb.ControlRunMsg_Cancel{Cancel: &pb.RunCancel{}}}
}

func runSendClose(fake *runFakeCP) {
	fake.runCommands <- &pb.ControlRunMsg{Kind: &pb.ControlRunMsg_Close{Close: &pb.RunClose{}}}
}

func runWaitForRequests(t *testing.T, fake *runFakeCP, count int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(fake.runRecordedRequests()) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d decision requests", count)
}

func runWaitForMySQLSleep(t *testing.T, fixture runEngineFixture, sleepSQL string) {
	t.Helper()
	direct := runOpenMySQLInspector(t, fixture)
	defer direct.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := direct.QueryRow(
			"SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE INFO LIKE ?", sleepSQL+"%",
		).Scan(&count); err != nil {
			t.Fatalf("inspect MySQL process list: %v", err)
		}
		if count > 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for MySQL %q to start", sleepSQL)
}

func runWaitForPostgresSleep(t *testing.T, fixture runEngineFixture) {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", fixture.runTarget.User, fixture.runTarget.Password, fixture.runTarget.Host, fixture.runTarget.Port, fixture.runTarget.Db)
	direct, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open Postgres activity inspector: %v", err)
	}
	defer direct.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := direct.QueryRow("SELECT COUNT(*) FROM pg_stat_activity WHERE query = 'SELECT pg_sleep(30)' AND state = 'active'").Scan(&count); err != nil {
			t.Fatalf("inspect Postgres activity: %v", err)
		}
		if count > 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for Postgres pg_sleep(30) to start")
}

func runOpenMySQLInspector(t *testing.T, fixture runEngineFixture) *sql.DB {
	t.Helper()
	direct, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", fixture.runTarget.User, fixture.runTarget.Password, fixture.runTarget.Host, fixture.runTarget.Port, fixture.runTarget.Db))
	if err != nil {
		t.Fatalf("open MySQL process inspector: %v", err)
	}
	return direct
}

func runExpectMySQLSleepStopped(t *testing.T, fixture runEngineFixture) {
	t.Helper()
	direct := runOpenMySQLInspector(t, fixture)
	defer direct.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		err := direct.QueryRow("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE INFO LIKE 'SELECT SLEEP(30)%'").Scan(&count)
		if err != nil {
			t.Fatalf("inspect MySQL process list: %v", err)
		}
		if count == 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("MySQL SLEEP(30) was still running after RunClose")
}

func runRecv(t *testing.T, fake *runFakeCP) *pb.ProxyRunMsg {
	t.Helper()
	select {
	case message := <-fake.runTranscript:
		return message
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for run transcript message")
		return nil
	}
}

func runExpectDecision(t *testing.T, message *pb.ProxyRunMsg, action pb.EnfAction, masked []string, deny string) {
	t.Helper()
	decision := message.GetDecision()
	if decision == nil || decision.GetDecision() != action || !reflect.DeepEqual(decision.GetMaskedColumns(), masked) || decision.GetDenyReason() != deny {
		t.Fatalf("run message = %v; decision = %v, want action=%s masked=%v deny=%q", message, decision, action, masked, deny)
	}
}

func runExpectRows(t *testing.T, message *pb.ProxyRunMsg, columns []string) []*pb.RunRow {
	t.Helper()
	result := message.GetResultRows()
	if result == nil || !reflect.DeepEqual(result.GetColumns(), columns) {
		t.Fatalf("RunResultRows = %v, want columns %v", result, columns)
	}
	return result.GetRows()
}

func runExpectDone(t *testing.T, message *pb.ProxyRunMsg, rowsAffected int32) {
	t.Helper()
	done := message.GetDone()
	if done == nil || done.GetRowsAffected() != rowsAffected {
		t.Fatalf("RunDone = %v, want rowsAffected=%d", done, rowsAffected)
	}
}

type runExpectedValue struct {
	value  string
	isNull bool
}

func runExpectValues(t *testing.T, rows []*pb.RunRow, expected [][]runExpectedValue) {
	t.Helper()
	if len(rows) != len(expected) {
		t.Fatalf("row count = %d, want %d", len(rows), len(expected))
	}
	for rowIndex, row := range rows {
		if len(row.GetValues()) != len(expected[rowIndex]) {
			t.Fatalf("row %d width = %d, want %d", rowIndex, len(row.GetValues()), len(expected[rowIndex]))
		}
		for columnIndex, value := range row.GetValues() {
			want := expected[rowIndex][columnIndex]
			if value.GetValue() != want.value || value.GetIsNull() != want.isNull {
				t.Fatalf("row %d column %d = %v, want value=%q null=%v", rowIndex, columnIndex, value, want.value, want.isNull)
			}
		}
	}
}

func runExpectSilence(t *testing.T, fake *runFakeCP, duration time.Duration) {
	t.Helper()
	select {
	case message := <-fake.runTranscript:
		t.Fatalf("unexpected run message during silence window: %v", message)
	case <-time.After(duration):
	}
}
