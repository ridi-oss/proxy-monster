package editor_test

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

	"github.com/ridi-oss/proxy-monster/goproxy/athena"
	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/postgres"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/editor"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	editorSessionID       = "pm-editor-session"
	editorToken           = "pm-editor-token"
	editorConnectionID    = "0123456789abcdef"
	editorMySQLSchema     = "pm_run_it"
	editorMySQLService    = "pm_run_svc"
	editorMySQLServicePwd = "pm-editor-svc-pw"
	editorPGSchema        = "pm_run_it"
)

func wireVerdict(verdict *pb.Verdict) *pb.WireDecision {
	return &pb.WireDecision{Outcome: &pb.WireDecision_Verdict{Verdict: verdict}}
}

type editorFakeCP struct {
	pb.UnimplementedControlPlaneServer

	mu               sync.Mutex
	editorDecide     func(*pb.DecisionRequest) *pb.WireDecision
	editorRequests   []*pb.DecisionRequest
	fragmentPushes   []*pb.SchemaFragmentPush
	closeRequests    []*pb.CloseConnectionRequest
	events           []string
	fragmentPushErr  error
	editorCommands   chan *pb.CpEditorMsg
	editorTranscript chan *pb.ProxyEditorMsg
	editorReady      chan struct{}
	readyOnce        sync.Once
	editorServing    chan struct{}
	servingOnce      sync.Once
	serving          *pb.EditorServing
	progressCount    int
}

func editorNewFakeCP() *editorFakeCP {
	return &editorFakeCP{
		editorCommands:   make(chan *pb.CpEditorMsg),
		editorTranscript: make(chan *pb.ProxyEditorMsg, 32),
		editorReady:      make(chan struct{}),
		editorServing:    make(chan struct{}),
	}
}

func (f *editorFakeCP) Decide(_ context.Context, req *pb.DecisionRequest) (*pb.WireDecision, error) {
	cloned := proto.Clone(req).(*pb.DecisionRequest)
	f.mu.Lock()
	f.editorRequests = append(f.editorRequests, cloned)
	f.events = append(f.events, "decide:"+cloned.GetSql())
	decide := f.editorDecide
	f.mu.Unlock()
	if decide == nil {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	return proto.Clone(decide(cloned)).(*pb.WireDecision), nil
}

func (f *editorFakeCP) PushSchemaFragment(_ context.Context, req *pb.SchemaFragmentPush) (*pb.SchemaFragmentAck, error) {
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

func (f *editorFakeCP) CloseConnection(_ context.Context, req *pb.CloseConnectionRequest) (*pb.CloseConnectionResponse, error) {
	cloned := proto.Clone(req).(*pb.CloseConnectionRequest)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeRequests = append(f.closeRequests, cloned)
	f.events = append(f.events, "close")
	return &pb.CloseConnectionResponse{}, nil
}

func (f *editorFakeCP) EditorExec(stream grpc.BidiStreamingServer[pb.ProxyEditorMsg, pb.CpEditorMsg]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	f.editorTranscript <- proto.Clone(first).(*pb.ProxyEditorMsg)
	ready := first.GetSessionReady()
	if ready != nil {
		f.mu.Lock()
		f.events = append(f.events, "ready")
		f.mu.Unlock()
	}
	f.readyOnce.Do(func() { close(f.editorReady) })
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
			switch {
			case message.GetProgress() != nil:
				// Target-DB-open liveness heartbeat — not part of the result transcript.
				f.mu.Lock()
				f.progressCount++
				f.mu.Unlock()
			case message.GetServing() != nil:
				f.mu.Lock()
				f.events = append(f.events, "serving")
				f.serving = proto.Clone(message.GetServing()).(*pb.EditorServing)
				f.mu.Unlock()
				f.servingOnce.Do(func() { close(f.editorServing) })
			default:
				f.editorTranscript <- proto.Clone(message).(*pb.ProxyEditorMsg)
			}
		}
	}()

	for {
		select {
		case command, ok := <-f.editorCommands:
			if !ok {
				return nil
			}
			if err := stream.Send(proto.Clone(command).(*pb.CpEditorMsg)); err != nil {
				return err
			}
		case err := <-recvDone:
			return err
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (f *editorFakeCP) editorSetDecide(decide func(*pb.DecisionRequest) *pb.WireDecision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.editorDecide = decide
}

func (f *editorFakeCP) editorRecordedRequests() []*pb.DecisionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	requests := make([]*pb.DecisionRequest, len(f.editorRequests))
	for i, request := range f.editorRequests {
		requests[i] = proto.Clone(request).(*pb.DecisionRequest)
	}
	return requests
}

func (f *editorFakeCP) editorRecordedFragments() []*pb.SchemaFragmentPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	fragments := make([]*pb.SchemaFragmentPush, len(f.fragmentPushes))
	for i, fragment := range f.fragmentPushes {
		fragments[i] = proto.Clone(fragment).(*pb.SchemaFragmentPush)
	}
	return fragments
}

func (f *editorFakeCP) editorRecordedCloses() []*pb.CloseConnectionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	closes := make([]*pb.CloseConnectionRequest, len(f.closeRequests))
	for i, closeRequest := range f.closeRequests {
		closes[i] = proto.Clone(closeRequest).(*pb.CloseConnectionRequest)
	}
	return closes
}

func (f *editorFakeCP) editorRecordedEvents() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *editorFakeCP) editorRecordedProgress() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.progressCount
}

func (f *editorFakeCP) editorSetFragmentPushError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fragmentPushErr = err
}

type editorEngineFixture struct {
	editorEngine    *engines.Engine
	editorTarget    spi.Target
	editorConfig    spi.TargetConfig
	editorTable     string
	editorNamespace []string
}

type editorCapturingDb struct {
	spi.Target
	readTimeout chan time.Duration
}

func (p *editorCapturingDb) OpenConnection(ctx context.Context, authz *spi.Authorizer, guard spi.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.Connection, error) {
	p.readTimeout <- readTimeout
	return p.Target.OpenConnection(ctx, authz, guard, readTimeout, defaultSchema)
}

// editorSlowOpenProvider blocks the target DB dial until release is closed, modeling a slow open against a large
// remote target DB. A test uses it to observe SessionReady landing before the open finishes and heartbeats
// being sent while it is in flight — without depending on wall-clock timing. It honors the target-DB open context:
// if that is cancelled (the control-plane closed the editor session, or the proxy drained, during the open) it returns
// at once, standing in for a real dialect whose dial/auth aborts on cancel. entered, when non-nil, is closed
// the first time the dial is reached so a test can wait until the open is genuinely in flight before cutting it.
type editorSlowOpenDb struct {
	spi.Target
	release   chan struct{}
	entered   chan struct{}
	enterOnce sync.Once
	// beforeDelegate, when non-nil, runs after release but before the real dial. A test uses it to close the
	// drain exactly as the open is about to complete, forcing the "open finished onto a draining proxy" race.
	beforeDelegate func()
}

func (p *editorSlowOpenDb) OpenConnection(ctx context.Context, authz *spi.Authorizer, guard spi.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.Connection, error) {
	if p.entered != nil {
		p.enterOnce.Do(func() { close(p.entered) })
	}
	select {
	case <-p.release:
		if p.beforeDelegate != nil {
			p.beforeDelegate()
		}
		return p.Target.OpenConnection(ctx, authz, guard, readTimeout, defaultSchema)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestServerMySQL(t *testing.T) {
	editorEngineContract(t, editorSeedMySQL(t))
}

func TestServerPostgres(t *testing.T) {
	editorEngineContract(t, editorSeedPostgres(t))
}

func TestServerPostgresTempTablesAreSessionIsolated(t *testing.T) {
	fixture := editorSeedPostgres(t)
	tempTable := editorUniqueTable("pm_run_temp_isolation")
	createSQL := "CREATE TEMP TABLE " + tempTable + " (id int PRIMARY KEY, note text)"
	readSQL := "SELECT id FROM " + tempTable

	fake1, client1 := editorStartFakeCP(t, editorSessionID+"-temp-1")
	editorLaunchOpen(t, fake1, client1, fixture, &pb.OpenEditorSession{
		SessionId:      editorSessionID + "-temp-1",
		EphemeralToken: editorToken,
		ConnectionId:   []byte("temp-session-001"),
		OnOpen:         []*pb.ProxyCommand{&pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Catalog: fixture.editorConfig.Db, Schema: editorPGSchema}}}},
	})
	fake2, client2 := editorStartFakeCP(t, editorSessionID+"-temp-2")
	editorLaunchOpen(t, fake2, client2, fixture, &pb.OpenEditorSession{
		SessionId:      editorSessionID + "-temp-2",
		EphemeralToken: editorToken,
		ConnectionId:   []byte("temp-session-002"),
		OnOpen:         []*pb.ProxyCommand{&pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Catalog: fixture.editorConfig.Db, Schema: editorPGSchema}}}},
	})

	editorSendQuery(fake1, createSQL, 20)
	editorExpectSuccess(t, fake1, 0)
	editorSendQuery(fake1, readSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake1), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake1), []string{"id"})
	editorExpectDone(t, editorRecv(t, fake1), -1)
	requests1 := fake1.editorRecordedRequests()
	last1 := requests1[len(requests1)-1]
	for _, column := range last1.GetTempColumns() {
		if column.GetCatalog() != fixture.editorConfig.Db {
			t.Fatalf("temp column catalog = %v, want %s", column.Catalog, fixture.editorConfig.Db)
		}
	}
	if !editorRequestHasTempTable(last1, tempTable, "id") || !editorRequestHasTempTable(last1, tempTable, "note") {
		t.Fatalf("session 1 temp_columns = %v, want %s.id and %s.note", last1.GetTempColumns(), tempTable, tempTable)
	}

	editorSendQuery(fake2, "SELECT 1", 20)
	editorExpectDecision(t, editorRecv(t, fake2), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake2), []string{"?column?"})
	editorExpectDone(t, editorRecv(t, fake2), -1)
	for _, request := range fake2.editorRecordedRequests() {
		if editorRequestHasTempTable(request, tempTable, "") {
			t.Fatalf("session 2 DecisionRequest leaked session 1 temp rows: %v", request.GetTempColumns())
		}
	}

	editorSendQuery(fake2, readSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake2), pb.EnfAction_ALLOW, nil, "")
	if message := editorRecv(t, fake2); message.GetError() == nil || !strings.Contains(message.GetError().GetRawMessage(), "does not exist") {
		t.Fatalf("session 2 bare temp read = %v, want target DB relation-does-not-exist error", message)
	}
}

func editorRequestHasTempTable(request *pb.DecisionRequest, table, column string) bool {
	for _, temp := range request.GetTempColumns() {
		if temp.GetTable() == table && (column == "" || temp.GetColumn() == column) {
			return true
		}
	}
	return false
}

func TestServerMalformedOpen(t *testing.T) {
	fixture := editorSeedMySQL(t)
	tests := []struct {
		name   string
		open   *pb.OpenEditorSession
		mapErr error
	}{
		{
			name: "mapping error closes valid connection",
			open: &pb.OpenEditorSession{
				SessionId:      editorSessionID,
				EphemeralToken: editorToken,
				ConnectionId:   []byte(editorConnectionID),
			},
			mapErr: errors.New("unsupported editor-session open command"),
		},
		{
			name: "bad connection id fails without close",
			open: &pb.OpenEditorSession{
				SessionId:      editorSessionID + "-bad-id",
				EphemeralToken: editorToken,
				ConnectionId:   []byte("short"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake, client := editorStartFakeCP(t, test.open.GetSessionId())
			done := make(chan struct{})
			go func() {
				editor.NewServer(client, fixture.editorTarget, 0).Serve(test.open, test.mapErr, nil)
				close(done)
			}()
			// The stream sends its session id (EditorReady) the instant it opens, before the open is validated, so even
			// a malformed open is attributable to its pending session; the EditorError follows.
			if first := editorRecv(t, fake); first.GetSessionReady() == nil {
				t.Fatalf("first frame = %v, want SessionReady before the malformed-open error", first)
			}
			if message := editorRecv(t, fake); message.GetError() == nil {
				t.Fatalf("malformed open message = %v, want EditorError after SessionReady", message)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("server did not terminate after malformed open")
			}
			if len(test.open.GetConnectionId()) == 16 {
				editorExpectSingleClose(t, fake)
			} else if closes := fake.editorRecordedCloses(); len(closes) != 0 {
				t.Fatalf("CloseConnection requests = %v, want none for malformed id", closes)
			}
		})
	}
}

func TestServerNormalCloseReleasesConnection(t *testing.T) {
	fixture := editorSeedMySQL(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	waitDone := editorLaunch(t, fake, client, fixture)
	fake.editorCommands <- &pb.CpEditorMsg{Kind: &pb.CpEditorMsg_Close{Close: &pb.EditorClose{}}}
	waitDone()
	editorExpectSingleClose(t, fake)
}

func TestServerCatalogRefresh(t *testing.T) {
	fixtures := []struct {
		name    string
		fixture editorEngineFixture
	}{
		{name: "mysql", fixture: editorSeedMySQL(t)},
		{name: "postgres", fixture: editorSeedPostgres(t)},
	}
	for _, test := range fixtures {
		t.Run(test.name, func(t *testing.T) {
			editorCatalogRefreshContract(t, test.fixture)
		})
	}
}

func editorEngineContract(t *testing.T, fixture editorEngineFixture) {
	t.Helper()
	fake, client := editorStartFakeCP(t, editorSessionID)
	runnerDone := editorLaunch(t, fake, client, fixture)

	allowSQL := fmt.Sprintf("SELECT id, secret FROM %s WHERE id <= 2 ORDER BY id", fixture.editorTable)
	maskSQL := fmt.Sprintf("SELECT id, secret FROM %s WHERE id = 1", fixture.editorTable)
	nullSQL := fmt.Sprintf("SELECT id, secret FROM %s WHERE id IN (3, 4) ORDER BY id", fixture.editorTable)
	denySQL := fmt.Sprintf("SELECT secret FROM %s WHERE id = 1", fixture.editorTable)
	badMaskSQL := fmt.Sprintf("SELECT id FROM %s WHERE id = 1", fixture.editorTable)
	capsSQL := fmt.Sprintf("SELECT id FROM %s ORDER BY id", fixture.editorTable)
	verdictCapSQL := fmt.Sprintf("SELECT id FROM %s WHERE id > 0 ORDER BY id", fixture.editorTable)
	writeSQL := fmt.Sprintf("UPDATE %s SET note = 'updated' WHERE id IN (1, 2)", fixture.editorTable)

	fake.editorSetDecide(func(req *pb.DecisionRequest) *pb.WireDecision {
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
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DecisionId: 103, DenyReason: "not granted", DenyCode: "rate_spent"})
		case badMaskSQL:
			ordinal := int32(99)
			return wireVerdict(&pb.Verdict{
				Decision:   pb.EnfAction_MASK,
				DecisionId: 104,
				Masks:      []*pb.ColumnMask{{Column: "missing", Kind: "FIXED", Ordinal: &ordinal}},
			})
		case verdictCapSQL:
			return wireVerdict(&pb.Verdict{
				Decision: pb.EnfAction_ALLOW, DecisionId: 105, EffectiveRoles: []string{"analyst"},
				MaxRows: 100, MaxBytes: 4000,
			})
		default:
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 101, EffectiveRoles: []string{"analyst"}})
		}
	})

	editorSendQuery(fake, allowSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	allowRows := editorExpectRows(t, editorRecv(t, fake), []string{"id", "secret"})
	editorExpectValues(t, allowRows, [][]editorExpectedValue{{{value: "1"}, {value: "clear-1"}}, {{value: "2"}, {value: "clear-2"}}})
	editorExpectDone(t, editorRecv(t, fake), -1)

	requests := fake.editorRecordedRequests()
	if len(requests) == 0 {
		t.Fatal("no editor session Decide request recorded")
	}
	firstRequest := requests[0]
	if firstRequest.GetToken() != editorToken || firstRequest.GetSql() != allowSQL || firstRequest.GetClientAddr() != "" || string(firstRequest.GetConnectionId()) != editorConnectionID {
		t.Fatalf("first Decide request = %+v", firstRequest)
	}
	if !reflect.DeepEqual(firstRequest.GetSearchPath(), fixture.editorNamespace) {
		t.Fatalf("first Decide namespace = %v, want %v", firstRequest.GetSearchPath(), fixture.editorNamespace)
	}

	editorSendQuery(fake, maskSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_MASK, []string{"secret"}, "")
	maskRows := editorExpectRows(t, editorRecv(t, fake), []string{"id", "secret"})
	editorExpectValues(t, maskRows, [][]editorExpectedValue{{{value: "1"}, {value: "####"}}})
	editorExpectDone(t, editorRecv(t, fake), -1)

	editorSendQuery(fake, nullSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	nullRows := editorExpectRows(t, editorRecv(t, fake), []string{"id", "secret"})
	editorExpectValues(t, nullRows, [][]editorExpectedValue{{{value: "3"}, {isNull: true}}, {{value: "4"}, {value: ""}}})
	editorExpectDone(t, editorRecv(t, fake), -1)

	editorSendQuery(fake, denySQL, 20)
	denied := editorRecv(t, fake)
	editorExpectDecision(t, denied, pb.EnfAction_DENY, nil, "not granted")
	if code := denied.GetDecision().GetDenyCode(); code != "rate_spent" {
		t.Fatalf("deny code = %q, want the verdict's rate_spent echoed", code)
	}
	editorExpectSilence(t, fake, 200*time.Millisecond)

	editorSendQuery(fake, allowSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), []string{"id", "secret"})
	editorExpectDone(t, editorRecv(t, fake), -1)

	editorSendQuery(fake, capsSQL, 3)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if got := len(editorExpectRows(t, editorRecv(t, fake), []string{"id"})); got != 3 {
		t.Fatalf("maxRows=3 returned %d rows", got)
	}
	editorExpectDone(t, editorRecv(t, fake), -1)

	editorSendQuery(fake, capsSQL, 0)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if got := len(editorExpectRows(t, editorRecv(t, fake), []string{"id"})); got != 500 {
		t.Fatalf("maxRows=0 returned %d rows", got)
	}
	editorExpectDone(t, editorRecv(t, fake), -1)

	editorSendQuery(fake, capsSQL, 7000)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	firstChunk := editorExpectRows(t, editorRecv(t, fake), []string{"id"})
	secondChunk := editorExpectRows(t, editorRecv(t, fake), []string{"id"})
	if len(firstChunk) != 1000 || len(secondChunk) != 200 {
		t.Fatalf("maxRows=7000 chunks = %d + %d, want 1000 + 200", len(firstChunk), len(secondChunk))
	}
	editorExpectDone(t, editorRecv(t, fake), -1)

	editorSendQuery(fake, capsSQL, -9)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if got := len(editorExpectRows(t, editorRecv(t, fake), []string{"id"})); got != 1 {
		t.Fatalf("negative maxRows returned %d rows", got)
	}
	editorExpectDone(t, editorRecv(t, fake), -1)

	// The verdict cap is below the client's page size, so it — not the page end — bounds the result.
	editorSendQuery(fake, verdictCapSQL, 500)
	capDecision := editorRecv(t, fake)
	editorExpectDecision(t, capDecision, pb.EnfAction_ALLOW, nil, "")
	if got := capDecision.GetDecision(); got.GetMaxRows() != 100 || got.GetMaxBytes() != 4000 {
		t.Fatalf("EditorDecision caps = %d/%d, want 100/4000", got.GetMaxRows(), got.GetMaxBytes())
	}
	if got := len(editorExpectRows(t, editorRecv(t, fake), []string{"id"})); got != 100 {
		t.Fatalf("verdict cap returned %d rows, want 100", got)
	}
	editorExpectTruncatedDone(t, editorRecv(t, fake), true)

	// The client asked for fewer rows than the cap allows, so this is a plain page end.
	editorSendQuery(fake, verdictCapSQL, 50)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if got := len(editorExpectRows(t, editorRecv(t, fake), []string{"id"})); got != 50 {
		t.Fatalf("client limit returned %d rows, want 50", got)
	}
	editorExpectTruncatedDone(t, editorRecv(t, fake), false)

	editorSendQuery(fake, writeSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if got := len(editorExpectRows(t, editorRecv(t, fake), nil)); got != 0 {
		t.Fatalf("write emitted %d rows, want 0", got)
	}
	editorExpectDone(t, editorRecv(t, fake), 2)

	editorSendQuery(fake, allowSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), []string{"id", "secret"})
	editorExpectDone(t, editorRecv(t, fake), -1)
	requests = fake.editorRecordedRequests()
	if got := requests[len(requests)-1].GetSearchPath(); !reflect.DeepEqual(got, fixture.editorNamespace) {
		t.Fatalf("post-write Decide namespace = %v, want %v", got, fixture.editorNamespace)
	}

	editorSendQuery(fake, badMaskSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_MASK, []string{"missing"}, "")
	errorMessage := editorRecv(t, fake).GetError()
	if errorMessage == nil || !strings.Contains(errorMessage.GetMessage(), "mask binding failed") {
		t.Fatalf("bad mask terminal message = %v", errorMessage)
	}
	runnerDone()
	editorExpectSingleClose(t, fake)
	editorExpectSilence(t, fake, 200*time.Millisecond)
}

func editorCatalogRefreshContract(t *testing.T, fixture editorEngineFixture) {
	t.Helper()

	t.Run("after_statement refetches before reply and next Decide", func(t *testing.T) {
		fake, client := editorStartFakeCP(t, editorSessionID)
		editorLaunch(t, fake, client, fixture)
		initialPushes := len(fake.editorRecordedFragments())
		table := editorUniqueTable("pm_run_refresh")
		ddl := editorCreateTableSQL(fixture, table)
		nextSQL := "BEGIN"
		fake.editorSetDecide(editorCatalogRefreshDecider(ddl, fixture.editorCatalog(), fixture.editorNamespaceForTable()))

		editorSendQuery(fake, ddl, 20)
		editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		editorExpectRows(t, editorRecv(t, fake), nil)
		editorExpectDone(t, editorRecv(t, fake), 0)
		fragments := fake.editorRecordedFragments()
		if len(fragments) != initialPushes+1 {
			t.Fatalf("fragment pushes = %d, want %d", len(fragments), initialPushes+1)
		}
		if !editorFragmentHasTable(fragments[len(fragments)-1], fixture.editorNamespaceForTable(), table) {
			t.Fatalf("pushed fragment does not contain %s.%s", fixture.editorNamespaceForTable(), table)
		}

		editorSendQuery(fake, nextSQL, 20)
		editorExpectSuccess(t, fake, 0)
		events := fake.editorRecordedEvents()
		pushEvent := "push:" + fixture.editorNamespaceForTable()
		if !editorLastEventBefore(events, pushEvent, "decide:"+nextSQL) {
			t.Fatalf("events = %v, want after-statement push before next Decide", events)
		}
	})

	t.Run("capped statement does not cap after-statement refetch", func(t *testing.T) {
		fake, client := editorStartFakeCP(t, editorSessionID)
		editorLaunch(t, fake, client, fixture)
		initialPushes := len(fake.editorRecordedFragments())
		table := editorUniqueTable("pm_run_capped_refresh")
		ddl := editorCreateTableSQL(fixture, table)
		fake.editorSetDecide(editorCatalogRefreshDecider(ddl, fixture.editorCatalog(), fixture.editorNamespaceForTable()))

		editorSendQuery(fake, ddl, 1)
		editorExpectSuccess(t, fake, 0)
		fragments := fake.editorRecordedFragments()
		if len(fragments) != initialPushes+1 {
			t.Fatalf("fragment pushes = %d, want %d", len(fragments), initialPushes+1)
		}
		if got := len(fragments[len(fragments)-1].GetColumns()); got <= 2 {
			t.Fatalf("capped refetch returned %d catalog rows, want complete fragment with more than 2", got)
		}
		if !editorFragmentHasTable(fragments[len(fragments)-1], fixture.editorNamespaceForTable(), table) {
			t.Fatalf("pushed fragment does not contain %s.%s", fixture.editorNamespaceForTable(), table)
		}
	})

	t.Run("routine DDL refetches before done", func(t *testing.T) {
		fake, client := editorStartFakeCP(t, editorSessionID)
		editorLaunch(t, fake, client, fixture)
		initialPushes := len(fake.editorRecordedFragments())
		table := editorUniqueTable("pm_run_routine_refresh")
		var callSQL string
		directSchema := fixture.editorNamespaceForTable()
		if fixture.editorEngine == engines.MySQL {
			procedure := editorUniqueTable("pm_run_routine")
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
			procedure := editorUniqueTable("pm_run_routine")
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
		fake.editorSetDecide(editorCatalogRefreshDecider(callSQL, fixture.editorCatalog(), directSchema))

		editorSendQuery(fake, callSQL, 20)
		editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		editorExpectRows(t, editorRecv(t, fake), nil)
		waitForEditorFragments(t, fake, initialPushes+1)
		fragments := fake.editorRecordedFragments()
		if len(fragments) != initialPushes+1 {
			t.Fatalf("routine fragment pushes before Done = %d, want %d", len(fragments), initialPushes+1)
		}
		if !editorFragmentHasTable(fragments[len(fragments)-1], directSchema, table) {
			t.Fatalf("routine fragment does not contain %s.%s", directSchema, table)
		}
		editorExpectDone(t, editorRecv(t, fake), 0)
	})

	t.Run("before_decide refetches and retries", func(t *testing.T) {
		fake, client := editorStartFakeCP(t, editorSessionID)
		editorLaunch(t, fake, client, fixture)
		initialPushes := len(fake.editorRecordedFragments())
		calls := 0
		fake.editorSetDecide(func(*pb.DecisionRequest) *pb.WireDecision {
			calls++
			if calls == 1 {
				return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{
					Commands: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{
						Schema: fixture.editorNamespaceForTable(), Catalog: fixture.editorCatalog(),
					}}}},
				}}}
			}
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW})
		})

		editorSendQuery(fake, "BEGIN", 20)
		editorExpectSuccess(t, fake, 0)
		if calls != 2 {
			t.Fatalf("Decide calls = %d, want 2", calls)
		}
		if got := len(fake.editorRecordedFragments()); got != initialPushes+1 {
			t.Fatalf("fragment pushes = %d, want %d after before_decide", got, initialPushes+1)
		}
		events := fake.editorRecordedEvents()
		if !editorContainsEventSequence(events, []string{
			"decide:BEGIN",
			"push:" + fixture.editorNamespaceForTable(),
			"decide:BEGIN",
		}) {
			t.Fatalf("events = %v, want Decide -> refetch -> retry", events)
		}
	})

	t.Run("before_decide retry bound terminates and closes connection", func(t *testing.T) {
		fake, client := editorStartFakeCP(t, editorSessionID)
		waitDone := editorLaunch(t, fake, client, fixture)
		initialPushes := len(fake.editorRecordedFragments())
		fake.editorSetDecide(func(*pb.DecisionRequest) *pb.WireDecision {
			return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{
				Commands: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{
					Schema: fixture.editorNamespaceForTable(), Catalog: fixture.editorCatalog(),
				}}}},
			}}}
		})

		editorSendQuery(fake, "BEGIN", 20)
		editorErr := editorRecv(t, fake).GetError()
		if editorErr == nil {
			t.Fatalf("unbounded before_decide: want EditorError")
		}
		// A decision-side (refetch retry-bound) failure is not the target DB's statement error; leave it untagged.
		if editorErr.GetTargetDbError() {
			t.Fatalf("before_decide retry-bound EditorError.target_db_error = true, want false")
		}
		waitDone()
		if got := len(fake.editorRecordedRequests()); got != 4 {
			t.Fatalf("Decide calls = %d, want initial plus 3 retries", got)
		}
		if got := len(fake.editorRecordedFragments()); got != initialPushes+3 {
			t.Fatalf("fragment pushes = %d, want %d bounded command rounds", got, initialPushes+3)
		}
		editorExpectSingleClose(t, fake)
	})

	t.Run("command absent does not refetch", func(t *testing.T) {
		fake, client := editorStartFakeCP(t, editorSessionID)
		editorLaunch(t, fake, client, fixture)
		initialPushes := len(fake.editorRecordedFragments())
		ddl := editorCreateTableSQL(fixture, editorUniqueTable("pm_run_no_refresh"))

		editorSendQuery(fake, ddl, 20)
		editorExpectSuccess(t, fake, 0)
		if got := len(fake.editorRecordedFragments()); got != initialPushes {
			t.Fatalf("fragment pushes = %d, want unchanged %d", got, initialPushes)
		}
	})

	t.Run("push failure terminates stream and closes connection", func(t *testing.T) {
		fake, client := editorStartFakeCP(t, editorSessionID)
		waitDone := editorLaunch(t, fake, client, fixture)
		initialPushes := len(fake.editorRecordedFragments())
		ddl := editorCreateTableSQL(fixture, editorUniqueTable("pm_run_push_failure"))
		fake.editorSetDecide(editorCatalogRefreshDecider(ddl, fixture.editorCatalog(), fixture.editorNamespaceForTable()))
		fake.editorSetFragmentPushError(errors.New("injected fragment push failure"))

		editorSendQuery(fake, ddl, 20)
		editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		editorErr := editorRecv(t, fake).GetError()
		if editorErr == nil {
			t.Fatalf("push-failed DDL: want EditorError")
		}
		// A proxy-internal fragment-push failure — not the target DB's statement error — must stay untagged.
		if editorErr.GetTargetDbError() {
			t.Fatalf("push-failure EditorError.target_db_error = true, want false")
		}
		waitDone()
		if got := len(fake.editorRecordedFragments()); got != initialPushes+1 {
			t.Fatalf("fragment pushes = %d, want %d including failed attempt", got, initialPushes+1)
		}
		editorExpectSingleClose(t, fake)
	})

	t.Run("target-DB-failed DDL does not refetch", func(t *testing.T) {
		fake, client := editorStartFakeCP(t, editorSessionID)
		waitDone := editorLaunch(t, fake, client, fixture)
		initialPushes := len(fake.editorRecordedFragments())
		ddl := fmt.Sprintf("CREATE TABLE %s (id INT PRIMARY KEY)", fixture.editorTable)
		fake.editorSetDecide(editorCatalogRefreshDecider(ddl, fixture.editorCatalog(), fixture.editorNamespaceForTable()))

		editorSendQuery(fake, ddl, 20)
		editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		editorErr := editorRecv(t, fake).GetError()
		if editorErr == nil {
			t.Fatalf("target-DB-failed DDL: want EditorError")
		}
		// The target DB's own ERR for the executed statement: tagged so the control-plane may surface it, with
		// the value-free redacted text in Message (no generic prefix) and the raw text in RawMessage.
		if !editorErr.GetTargetDbError() {
			t.Fatalf("target-DB-failed DDL EditorError.target_db_error = false, want true")
		}
		if editorErr.GetMessage() == "" || strings.HasPrefix(editorErr.GetMessage(), "query execution failed: ") {
			t.Fatalf("target-DB error message = %q, want the redacted text without the generic prefix", editorErr.GetMessage())
		}
		if editorErr.GetRawMessage() == "" {
			t.Fatalf("target-DB error RawMessage empty, want the raw text carried for a full-reader view")
		}
		waitDone()
		if got := len(fake.editorRecordedFragments()); got != initialPushes {
			t.Fatalf("fragment pushes = %d, want unchanged %d", got, initialPushes)
		}
		editorExpectSingleClose(t, fake)
	})

	if fixture.editorEngine == engines.Postgres {
		t.Run("transactional DDL refetches inside the open transaction", func(t *testing.T) {
			fake, client := editorStartFakeCP(t, editorSessionID)
			editorLaunch(t, fake, client, fixture)
			initialPushes := len(fake.editorRecordedFragments())
			table := editorUniqueTable("pm_run_tx_refresh")
			ddl := editorCreateTableSQL(fixture, table)
			fake.editorSetDecide(editorCatalogRefreshDecider(ddl, fixture.editorCatalog(), fixture.editorNamespaceForTable()))

			editorSendQuery(fake, "BEGIN", 20)
			editorExpectSuccess(t, fake, 0)
			editorSendQuery(fake, ddl, 20)
			editorExpectSuccess(t, fake, 0)
			fragments := fake.editorRecordedFragments()
			if len(fragments) != initialPushes+1 {
				t.Fatalf("fragment pushes before COMMIT = %d, want %d", len(fragments), initialPushes+1)
			}
			if !editorFragmentHasTable(fragments[len(fragments)-1], fixture.editorNamespaceForTable(), table) {
				t.Fatalf("in-transaction fragment does not contain %s.%s", fixture.editorNamespaceForTable(), table)
			}
			editorSendQuery(fake, "ROLLBACK", 20)
			editorExpectSuccess(t, fake, 0)
		})
	}
}

func editorCatalogRefreshDecider(flaggedSQL, catalog, schema string) func(*pb.DecisionRequest) *pb.WireDecision {
	return func(req *pb.DecisionRequest) *pb.WireDecision {
		verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW}
		if req.GetSql() == flaggedSQL {
			verdict.AfterStatement = []*pb.ProxyCommand{{
				Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Catalog: catalog, Schema: schema}},
			}}
		}
		return wireVerdict(verdict)
	}
}

func editorUniqueTable(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func editorCreateTableSQL(fixture editorEngineFixture, table string) string {
	return fmt.Sprintf("CREATE TABLE %s.%s (id INT PRIMARY KEY)", fixture.editorNamespaceForTable(), table)
}

func (f editorEngineFixture) editorCatalog() string {
	if f.editorEngine == engines.MySQL {
		return "def"
	}
	return f.editorConfig.Db
}

func (f editorEngineFixture) editorNamespaceForTable() string {
	if f.editorEngine == engines.MySQL {
		return editorMySQLSchema
	}
	return editorPGSchema
}

func editorFragmentHasTable(fragment *pb.SchemaFragmentPush, schema, table string) bool {
	for _, column := range fragment.GetColumns() {
		if column.GetSchema() == schema && column.GetTable() == table {
			return true
		}
	}
	return false
}

func editorLastEventBefore(events []string, first, second string) bool {
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

func waitForEditorFragments(t *testing.T, fake *editorFakeCP, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(fake.editorRecordedFragments()) < count && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(fake.editorRecordedFragments()); got < count {
		t.Fatalf("fragment pushes = %d, want at least %d", got, count)
	}
}

func editorContainsEventSequence(events, sequence []string) bool {
	matched := 0
	for _, event := range events {
		if matched < len(sequence) && event == sequence[matched] {
			matched++
		}
	}
	return matched == len(sequence)
}

func editorExpectSingleClose(t *testing.T, fake *editorFakeCP) {
	t.Helper()
	closes := fake.editorRecordedCloses()
	if len(closes) != 1 || string(closes[0].GetConnectionId()) != editorConnectionID {
		t.Fatalf("CloseConnection requests = %v, want one for %x", closes, []byte(editorConnectionID))
	}
}

func editorExpectSuccess(t *testing.T, fake *editorFakeCP, rowsAffected int32) {
	t.Helper()
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), nil)
	editorExpectDone(t, editorRecv(t, fake), rowsAffected)
}

// TestServerMySQLReprobesNamespaceAfterTrackerBypass is the editor session's namespace half of the
// chained session-track bypass. A
// client clears session_track_system_variables (silently defeating the sysvar tracker), then disables
// session_track_schema (now unreported), then switches databases with a bare USE — defeating every target DB
// signal the proxy could observe the switch through. The current database really changed, so authorizing
// the next statement under the stale schema would let it escape its policy. Probe-always closes the hole:
// the engine re-reads DATABASE() before the next statement, so it is decided under the switched schema. The
// tracker-defeating SETs and the USE all succeed; the guard is the re-probed namespace of the bare read.
func TestServerMySQLReprobesNamespaceAfterTrackerBypass(t *testing.T) {
	fixture := editorSeedMySQL(t)
	const editorMySQLAltSchema = editorMySQLSchema + "_alt"
	seed := dbtest.OpenMySQL(t, "")
	for _, statement := range []string{
		"CREATE DATABASE IF NOT EXISTS " + editorMySQLAltSchema,
		"GRANT ALL ON " + editorMySQLAltSchema + ".* TO '" + editorMySQLService + "'@'%'",
		"FLUSH PRIVILEGES",
	} {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("bypass seed %q: %v", statement, err)
		}
	}

	fake, client := editorStartFakeCP(t, editorSessionID)
	editorLaunch(t, fake, client, fixture)

	for _, bypassSQL := range []string{
		"SET session_track_system_variables=''",
		"SET SESSION session_track_schema = OFF",
		"USE " + editorMySQLAltSchema,
	} {
		editorSendQuery(fake, bypassSQL, 20)
		editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
		editorExpectRows(t, editorRecv(t, fake), nil)
		editorExpectDone(t, editorRecv(t, fake), 0)
	}

	editorSendQuery(fake, "SELECT 1", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), []string{"1"})
	editorExpectDone(t, editorRecv(t, fake), -1)

	requests := fake.editorRecordedRequests()
	if got := requests[len(requests)-1].GetSearchPath(); !reflect.DeepEqual(got, []string{editorMySQLAltSchema}) {
		t.Fatalf("post-bypass Decide namespace = %v, want re-probed %v (stale namespace not defeated)", got, []string{editorMySQLAltSchema})
	}
}

func TestServerMySQLReportsNamespaceAfterUse(t *testing.T) {
	fixture := editorSeedMySQL(t)
	const altSchema = editorMySQLSchema + "_ns"
	seed := dbtest.OpenMySQL(t, "")
	for _, statement := range []string{
		"CREATE DATABASE IF NOT EXISTS " + altSchema,
		"GRANT ALL ON " + altSchema + ".* TO '" + editorMySQLService + "'@'%'",
		"FLUSH PRIVILEGES",
	} {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("seed %q: %v", statement, err)
		}
	}
	fake, client := editorStartFakeCP(t, editorSessionID)
	editorLaunch(t, fake, client, fixture)
	editorExpectServingNamespace(t, fake, []string{editorMySQLSchema})

	editorSendQuery(fake, "USE "+altSchema, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), nil)
	afterUse := editorRecv(t, fake)
	editorExpectDoneNamespace(t, afterUse, []string{altSchema})
	if got := afterUse.GetDone().GetNamespace().GetCatalog(); got != "def" {
		t.Fatalf("EditorDone catalog = %q, want def", got)
	}

	before := len(fake.editorRecordedRequests())
	editorSendQuery(fake, "SELECT 1", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), []string{"1"})
	editorExpectDoneNamespace(t, editorRecv(t, fake), []string{altSchema})
	requests := fake.editorRecordedRequests()
	if len(requests) != before+1 || !reflect.DeepEqual(requests[len(requests)-1].GetSearchPath(), []string{altSchema}) {
		t.Fatalf("Decide after USE = %v, want one request with search_path %v", requests[before:], []string{altSchema})
	}
}

func TestServerMySQLOpensInDefaultSchema(t *testing.T) {
	fixture := editorSeedMySQL(t)
	const altSchema = editorMySQLSchema + "_default"
	seed := dbtest.OpenMySQL(t, "")
	for _, statement := range []string{
		"CREATE DATABASE IF NOT EXISTS " + altSchema,
		"GRANT ALL ON " + altSchema + ".* TO '" + editorMySQLService + "'@'%'",
		"FLUSH PRIVILEGES",
	} {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("seed %q: %v", statement, err)
		}
	}
	fake, client := editorStartFakeCP(t, editorSessionID)
	open := editorOpen(fixture)
	open.DefaultSchema = altSchema
	editorLaunchOpen(t, fake, client, fixture, open)
	editorExpectServingNamespace(t, fake, []string{altSchema})
}

func TestServerPostgresOpensInDefaultSchema(t *testing.T) {
	fixture := editorSeedPostgres(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	open := editorOpen(fixture)
	open.DefaultSchema = editorPGSchema
	editorLaunchOpen(t, fake, client, fixture, open)
	editorExpectServingNamespace(t, fake, []string{"pg_catalog", editorPGSchema})
}

func TestServerPostgresReportsNamespaceAfterSetSearchPath(t *testing.T) {
	fixture := editorSeedPostgres(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	editorLaunch(t, fake, client, fixture)
	initial := editorServingNamespace(t, fake)
	if len(initial) == 0 || initial[0] != "pg_catalog" {
		t.Fatalf("EditorServing namespace = %v, want the effective current_schemas(true) list", initial)
	}

	editorSendQuery(fake, "SET search_path TO "+editorPGSchema, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), nil)
	afterSet := editorRecv(t, fake)
	editorExpectDoneNamespace(t, afterSet, []string{"pg_catalog", editorPGSchema})
	if got := afterSet.GetDone().GetNamespace().GetCatalog(); got != fixture.editorConfig.Db {
		t.Fatalf("EditorDone catalog = %q, want %s", got, fixture.editorConfig.Db)
	}

	editorSendQuery(fake, "SELECT 1", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), []string{"?column?"})
	editorExpectDoneNamespace(t, editorRecv(t, fake), []string{"pg_catalog", editorPGSchema})
	requests := fake.editorRecordedRequests()
	if got := requests[len(requests)-1].GetSearchPath(); !reflect.DeepEqual(got, []string{"pg_catalog", editorPGSchema}) {
		t.Fatalf("Decide after SET search_path = %v, want %v", got, []string{"pg_catalog", editorPGSchema})
	}
}

// The reported namespace must not stand in for authorization's own probe: another connection can change
// what the session resolves between two statements.
func TestServerPostgresAuthorizesAgainstANamespaceChangedBetweenStatements(t *testing.T) {
	fixture := editorSeedPostgres(t)
	schema := editorUniqueTable("pm_run_ns_late")
	seed := dbtest.OpenPostgres(t, "")
	t.Cleanup(func() { _, _ = seed.Exec("DROP SCHEMA IF EXISTS " + schema) })
	fake, client := editorStartFakeCP(t, editorSessionID)
	editorLaunch(t, fake, client, fixture)

	editorSendQuery(fake, "SET search_path TO "+schema+", public", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), nil)
	editorExpectDoneNamespace(t, editorRecv(t, fake), []string{"pg_catalog", "public"})

	if _, err := seed.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	editorSendQuery(fake, "SELECT 1", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), []string{"?column?"})
	editorExpectDoneNamespace(t, editorRecv(t, fake), []string{"pg_catalog", schema, "public"})
	requests := fake.editorRecordedRequests()
	if got := requests[len(requests)-1].GetSearchPath(); !reflect.DeepEqual(got, []string{"pg_catalog", schema, "public"}) {
		t.Fatalf("Decide after another connection created %s = %v, want it probed fresh", schema, got)
	}
}

func editorServingNamespace(t *testing.T, fake *editorFakeCP) []string {
	t.Helper()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.serving.GetNamespace() == nil {
		t.Fatalf("EditorServing = %v, want a namespace", fake.serving)
	}
	return fake.serving.GetNamespace().GetSearchPath()
}

func editorExpectServingNamespace(t *testing.T, fake *editorFakeCP, want []string) {
	t.Helper()
	if got := editorServingNamespace(t, fake); !reflect.DeepEqual(got, want) {
		t.Fatalf("EditorServing namespace = %v, want %v", got, want)
	}
}

func editorExpectDoneNamespace(t *testing.T, message *pb.ProxyEditorMsg, want []string) {
	t.Helper()
	namespace := message.GetDone().GetNamespace()
	if namespace == nil || !reflect.DeepEqual(namespace.GetSearchPath(), want) {
		t.Fatalf("EditorDone = %v, want namespace %v", message, want)
	}
}

// TestServerPostgresRejectsUnsafeGUC proves the persistent PostgreSQL session holds the UTF-8 and
// on-mode invariants the wire relay enforces (postgres/relay.go), so a session-scoped GUC change that
// would let the control plane and the target DB bind different objects for the same bytes fails closed and
// terminates the session before any follow-up query can run.
func TestServerPostgresRejectsUnsafeGUC(t *testing.T) {
	fixture := editorSeedPostgres(t)
	for _, unsafeSQL := range []string{
		"SET client_encoding TO 'LATIN1'",
		"SET standard_conforming_strings TO off",
	} {
		editorAssertUnsafeGUCTerminates(t, fixture, unsafeSQL)
	}
}

func editorAssertUnsafeGUCTerminates(t *testing.T, fixture editorEngineFixture, unsafeSQL string) {
	t.Helper()
	fake, client := editorStartFakeCP(t, editorSessionID)
	waitDone := editorLaunch(t, fake, client, fixture)

	editorSendQuery(fake, unsafeSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := editorRecv(t, fake); message.GetError() == nil {
		t.Fatalf("[%s] expected EditorError after unsafe GUC change, got %v", unsafeSQL, message)
	}
	waitDone()
	editorExpectSilence(t, fake, 200*time.Millisecond)
}

// TestServerMySQLRejectsUnsafeSessionState proves the persistent MySQL session fails closed on the
// ways a control-plane-allowed SET can defeat authorization on a stateless relay. A DIRECT change to a
// tracked variable (schema tracking off, or a connection charset that leaves utf8mb4) is caught in the
// OK-packet sysvar tracker, so the offending statement is itself the terminal event — the failure is
// prompt, never a timeout. When the client first defeats the tracker (chained bypass), the later charset
// change is unreported; the per-statement charset re-probe then catches it and fails the next statement
// closed before it can run under a rebinding charset. Every case is deterministic and terminates promptly.
func TestServerMySQLRejectsUnsafeSessionState(t *testing.T) {
	fixture := editorSeedMySQL(t)

	// Direct tampering: the tracker reports the change in the OK of the very statement that made it, so the
	// session fails closed on that statement.
	t.Run("direct schema-tracking disable", func(t *testing.T) {
		editorAssertUnsafeMySQLStatementTerminates(t, fixture, "SET SESSION session_track_schema = OFF")
	})
	t.Run("direct charset change", func(t *testing.T) {
		editorAssertUnsafeMySQLStatementTerminates(t, fixture, "SET NAMES latin1")
	})

	// Chained bypass: clearing session_track_system_variables first leaves the later charset change
	// unreported, so the tracker cannot catch it. The charset re-probe run before the following statement
	// does — that statement fails closed rather than binding identifiers under latin1.
	t.Run("charset past a defeated tracker", func(t *testing.T) {
		fake, client := editorStartFakeCP(t, editorSessionID)
		waitDone := editorLaunch(t, fake, client, fixture)

		// Both SETs succeed silently: once the tracker list is empty the charset change is unreported.
		for _, silentSQL := range []string{"SET session_track_system_variables=''", "SET NAMES latin1"} {
			editorSendQuery(fake, silentSQL, 20)
			editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
			editorExpectRows(t, editorRecv(t, fake), nil)
			editorExpectDone(t, editorRecv(t, fake), 0)
		}

		// The next statement's pre-authorization namespace/charset re-probe observes latin1 and fails closed
		// (a Fail verdict, so no Decision precedes the terminal error).
		editorSendQuery(fake, "SELECT 1", 20)
		if message := editorRecv(t, fake); message.GetError() == nil {
			t.Fatalf("expected EditorError from the charset re-probe, got %v", message)
		}
		waitDone()
		editorExpectSilence(t, fake, 200*time.Millisecond)
	})
}

func editorAssertUnsafeMySQLStatementTerminates(t *testing.T, fixture editorEngineFixture, unsafeSQL string) {
	t.Helper()
	fake, client := editorStartFakeCP(t, editorSessionID)
	waitDone := editorLaunch(t, fake, client, fixture)

	editorSendQuery(fake, unsafeSQL, 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := editorRecv(t, fake); message.GetError() == nil {
		t.Fatalf("[%s] expected EditorError after unsafe session-state change, got %v", unsafeSQL, message)
	}
	waitDone()
	editorExpectSilence(t, fake, 200*time.Millisecond)
}

// TestServerMySQLCancelsSlowQuery proves the per-statement watchdog reaches the target DB AND that a
// timed-out statement is reported as a timeout, never a success: with an injected short timeout the server
// dials a side connection and issues KILL QUERY, interrupting SLEEP(30) fast. MySQL SLEEP returns a success
// row (1) when interrupted — but the watchdog's verdict overrides the target DB, so the proxy sends the
// PM_QUERY_TIMEOUT sentinel error rather than a row + Done.
func TestServerMySQLCancelsSlowQuery(t *testing.T) {
	fixture := editorSeedMySQL(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	editorLaunchConfigured(t, fake, client, fixture, func(s *editor.Server) {
		s.SetQueryTimeoutForTest(750 * time.Millisecond)
	})

	start := time.Now()
	editorSendQuery(fake, "SELECT SLEEP(30)", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := editorRecv(t, fake); message.GetError() == nil {
		t.Fatalf("expected an EditorError after watchdog cancellation, got %v", message)
	} else if got := message.GetError().GetMessage(); got != editor.QueryTimeoutMessage {
		t.Fatalf("expected the PM_QUERY_TIMEOUT sentinel, got %q", got)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("SLEEP(30) resolved in %s; the watchdog did not interrupt it", elapsed)
	}
}

// TestServerPostgresCancelsSlowQuery proves the watchdog's out-of-band CancelRequest reaches the
// target DB: pg_sleep(30) is canceled fast, the target DB replies with an ErrorResponse, and the session ends
// with a terminal error instead of blocking for the production timeout.
func TestServerPostgresCancelsSlowQuery(t *testing.T) {
	fixture := editorSeedPostgres(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	waitDone := editorLaunchConfigured(t, fake, client, fixture, func(s *editor.Server) {
		s.SetQueryTimeoutForTest(750 * time.Millisecond)
	})

	start := time.Now()
	editorSendQuery(fake, "SELECT pg_sleep(30)", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := editorRecv(t, fake); message.GetError() == nil {
		t.Fatalf("expected EditorError after watchdog cancellation, got %v", message)
	} else if got := message.GetError().GetMessage(); got != editor.QueryTimeoutMessage {
		t.Fatalf("expected the PM_QUERY_TIMEOUT sentinel, got %q", got)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("pg_sleep(30) resolved in %s; the watchdog did not interrupt it", elapsed)
	}
	waitDone()
	editorExpectSilence(t, fake, 200*time.Millisecond)
}

func TestServerMySQLCancelInFlightKeepsSessionUsable(t *testing.T) {
	fixture := editorSeedMySQL(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	editorLaunch(t, fake, client, fixture)

	start := time.Now()
	editorSendQuery(fake, "SELECT SLEEP(30)", 20)
	editorWaitForRequests(t, fake, 1)
	editorWaitForMySQLSleep(t, fixture, "SELECT SLEEP(30)")
	editorSendCancel(fake)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	rows := editorExpectRows(t, editorRecv(t, fake), []string{"SLEEP(30)"})
	editorExpectValues(t, rows, [][]editorExpectedValue{{{value: "1"}}})
	editorExpectDone(t, editorRecv(t, fake), -1)
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("SLEEP(30) resolved in %s; EditorCancel did not interrupt it", elapsed)
	}

	editorSendQuery(fake, "SELECT 42", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	rows = editorExpectRows(t, editorRecv(t, fake), []string{"42"})
	editorExpectValues(t, rows, [][]editorExpectedValue{{{value: "42"}}})
	editorExpectDone(t, editorRecv(t, fake), -1)
}

func TestServerPostgresCancelInFlightTerminatesStream(t *testing.T) {
	fixture := editorSeedPostgres(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	waitDone := editorLaunch(t, fake, client, fixture)

	start := time.Now()
	editorSendQuery(fake, "SELECT pg_sleep(30)", 20)
	editorWaitForRequests(t, fake, 1)
	editorWaitForPostgresSleep(t, fixture)
	editorSendCancel(fake)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	if message := editorRecv(t, fake); message.GetError() == nil {
		t.Fatalf("expected EditorError after EditorCancel, got %v", message)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("pg_sleep(30) resolved in %s; EditorCancel did not interrupt it", elapsed)
	}
	waitDone()
	editorExpectSilence(t, fake, 200*time.Millisecond)
}

func TestServerCancelWhileIdleIsNoOp(t *testing.T) {
	fixture := editorSeedMySQL(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	editorLaunch(t, fake, client, fixture)

	editorSendCancel(fake)
	editorSendQuery(fake, "SELECT 7", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	rows := editorExpectRows(t, editorRecv(t, fake), []string{"7"})
	editorExpectValues(t, rows, [][]editorExpectedValue{{{value: "7"}}})
	editorExpectDone(t, editorRecv(t, fake), -1)
}

func TestServerDrainReturnsWhenIdle(t *testing.T) {
	fixture := editorSeedMySQL(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	draining := make(chan struct{})
	done := make(chan struct{})
	go func() {
		editor.NewServer(client, fixture.editorTarget, 0).Serve(editorOpen(fixture), nil, draining)
		close(done)
	}()

	editorAwaitServing(t, fake)

	// The server is idle between statements. A drain must return it without a Close from the control plane,
	// so the session ends and the editor re-homes to the replacement.
	close(draining)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not return on drain while idle")
	}
}

func TestServerDrainLetsInFlightStatementFinish(t *testing.T) {
	fixture := editorSeedMySQL(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	draining := make(chan struct{})
	done := make(chan struct{})
	go func() {
		editor.NewServer(client, fixture.editorTarget, 0).Serve(editorOpen(fixture), nil, draining)
		close(done)
	}()

	editorAwaitServing(t, fake)

	// Put a statement in flight, then drain mid-statement. The drain is observed only between statements, so
	// the running SLEEP must complete and return its row (0 == slept the full duration, not interrupted)
	// before the server exits — draining must NOT cut it.
	editorSendQuery(fake, "SELECT SLEEP(2)", 20)
	editorWaitForRequests(t, fake, 1)
	editorWaitForMySQLSleep(t, fixture, "SELECT SLEEP(2)")
	close(draining)

	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	rows := editorExpectRows(t, editorRecv(t, fake), []string{"SLEEP(2)"})
	editorExpectValues(t, rows, [][]editorExpectedValue{{{value: "0"}}})
	editorExpectDone(t, editorRecv(t, fake), -1)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not exit after the in-flight statement finished")
	}
}

func TestServerDrainDoesNotStartAQueuedQuery(t *testing.T) {
	fixture := editorSeedMySQL(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	draining := make(chan struct{})
	done := make(chan struct{})
	go func() {
		editor.NewServer(client, fixture.editorTarget, 0).Serve(editorOpen(fixture), nil, draining)
		close(done)
	}()

	editorAwaitServing(t, fake)

	// Drain, then hand the server a query. A query racing in with the drain must not start a new statement on
	// a departing proxy: the server returns without a decision or rows, and the editor re-homes.
	close(draining)
	// The server may already have exited and ended the stream, leaving no one to take the query.
	select {
	case fake.editorCommands <- &pb.CpEditorMsg{Kind: &pb.CpEditorMsg_Query{Query: &pb.EditorQuery{Sql: "SELECT 1", MaxRows: 20}}}:
	case <-done:
	}

	editorExpectSilence(t, fake, 500*time.Millisecond)
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("server did not exit after draining with a queued query")
	}
}

// TestServerSendsEditorReadyBeforeTargetDbOpenAndHeartbeats proves the editor stream sends its id (EditorReady) up front
// and is kept alive through a slow open: SessionReady arrives before the (delayed) target DB dial finishes — so
// the CP can react to a stall or break during the open instead of waiting a blind budget — and EditorProgress
// heartbeats are emitted while the open runs, then EditorServing once it completes.
func TestServerSendsEditorReadyBeforeTargetDbOpenAndHeartbeats(t *testing.T) {
	fixture := editorSeedMySQL(t)
	release := make(chan struct{})
	fixture.editorTarget = &editorSlowOpenDb{Target: fixture.editorTarget, release: release}
	fake, client := editorStartFakeCP(t, editorSessionID)
	done := make(chan struct{})
	go func() {
		editor.NewServer(client, fixture.editorTarget, 0).Serve(editorOpen(fixture), nil, nil)
		close(done)
	}()

	// SessionReady must arrive while the target-DB open is still blocked — proving the session id is sent up front,
	// not deferred until the target DB is ready.
	select {
	case <-fake.editorReady:
	case <-time.After(5 * time.Second):
		t.Fatal("SessionReady did not arrive while the target-DB open was still blocked")
	}
	if first := editorRecv(t, fake); first.GetSessionReady() == nil {
		t.Fatalf("first frame = %v, want SessionReady", first)
	}

	// While the open is blocked, the proxy must heartbeat. Wait for at least one — deterministic, not a
	// wall-clock race: the open cannot finish until we release it below.
	deadline := time.Now().Add(15 * time.Second)
	for fake.editorRecordedProgress() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no EditorProgress heartbeat was sent while the target-DB open was blocked")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Release the open; it now completes with EditorServing and the session is usable.
	close(release)
	select {
	case <-fake.editorServing:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for EditorServing after releasing the target-DB open")
	}
	editorSendQuery(fake, "SELECT 1", 20)
	editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
	editorExpectRows(t, editorRecv(t, fake), []string{"1"})
	editorExpectDone(t, editorRecv(t, fake), -1)

	editorSendClose(fake)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not exit after EditorClose")
	}
}

// TestServerCloseDuringTargetDbOpenAbortsTargetDb proves the proxy reads the inbound during the target-DB open: a
// EditorClose the control-plane sends while the target-DB open is still in flight aborts the open at once and
// releases the reserved connection, instead of finishing a target-DB handshake for an editor session nobody is waiting for.
// The open is never released — the server can only return by cancelling it — so a return is the abort.
func TestServerCloseDuringTargetDbOpenAbortsTargetDb(t *testing.T) {
	fixture := editorSeedMySQL(t)
	entered := make(chan struct{})
	fixture.editorTarget = &editorSlowOpenDb{Target: fixture.editorTarget, release: make(chan struct{}), entered: entered}
	fake, client := editorStartFakeCP(t, editorSessionID)
	done := make(chan struct{})
	go func() {
		editor.NewServer(client, fixture.editorTarget, 0).Serve(editorOpen(fixture), nil, nil)
		close(done)
	}()

	editorAwaitTargetDbOpenInFlight(t, fake, entered)

	editorSendClose(fake)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not abort the target-DB open on EditorClose (still holding the target-DB handshake)")
	}
	editorWaitForCloses(t, fake, 1)
	editorExpectSingleClose(t, fake)
	editorExpectNoServing(t, fake)
}

// TestServerDrainDuringTargetDbOpenAbortsTargetDb is the redeploy analogue: a drain that lands while the target DB
// open is in flight aborts it and releases the connection, so the proxy does not keep dialing for an editor session that
// will re-home to the replacement.
func TestServerDrainDuringTargetDbOpenAbortsTargetDb(t *testing.T) {
	fixture := editorSeedMySQL(t)
	entered := make(chan struct{})
	fixture.editorTarget = &editorSlowOpenDb{Target: fixture.editorTarget, release: make(chan struct{}), entered: entered}
	fake, client := editorStartFakeCP(t, editorSessionID)
	draining := make(chan struct{})
	done := make(chan struct{})
	go func() {
		editor.NewServer(client, fixture.editorTarget, 0).Serve(editorOpen(fixture), nil, draining)
		close(done)
	}()

	editorAwaitTargetDbOpenInFlight(t, fake, entered)

	close(draining)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not abort the target-DB open on drain (still holding the target-DB handshake)")
	}
	editorWaitForCloses(t, fake, 1)
	editorExpectSingleClose(t, fake)
	editorExpectNoServing(t, fake)
}

// TestServerDrainAsTargetDbOpenCompletesInstallsNoSession is the open-then-instant-drain case end to end: the
// target-DB open runs to completion against the real target DB with the drain closing during it, and the server
// must NOT send EditorServing — no live editor session on a departing proxy — while still releasing the
// connection. It reaches the aborted outcome by whichever path the scheduler picks (the outer drain-abort or
// the post-completion re-check); the re-check branch itself is pinned deterministically by
// TestAbandonedDuringOpen in runner_internal_test.go, which no scheduler race can reach through this surface.
func TestServerDrainAsTargetDbOpenCompletesInstallsNoSession(t *testing.T) {
	fixture := editorSeedMySQL(t)
	release := make(chan struct{})
	draining := make(chan struct{})
	var drainOnce sync.Once
	fixture.editorTarget = &editorSlowOpenDb{
		Target:         fixture.editorTarget,
		release:        release,
		beforeDelegate: func() { drainOnce.Do(func() { close(draining) }) },
	}
	fake, client := editorStartFakeCP(t, editorSessionID)
	done := make(chan struct{})
	go func() {
		editor.NewServer(client, fixture.editorTarget, 0).Serve(editorOpen(fixture), nil, draining)
		close(done)
	}()

	select {
	case <-fake.editorReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the server to start")
	}
	if first := editorRecv(t, fake); first.GetSessionReady() == nil {
		t.Fatalf("first frame = %v, want SessionReady", first)
	}

	// Release the open; the provider closes the drain as it hands back the real session, so the completed open
	// is observed against a draining proxy. The server must fail the open rather than serve it.
	close(release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not return after a drain landed as the target-DB open completed")
	}
	editorWaitForCloses(t, fake, 1)
	editorExpectSingleClose(t, fake)
	editorExpectNoServing(t, fake)
}

// TestServerCloseDuringRealDialAbortsIt drives the abort end to end through the REAL MySQL dial: an EditorClose
// sent while the dial is mid-handshake against a target that accepts TCP but never sends its greeting must
// abort the dial and release the connection fast — exercising the real server, the real gRPC control stream,
// and the real provider.OpenConnection -> dialTargetDbAuthID (DialContext + AfterFunc), not a fake provider.
// The release is asserted well under the dial's handshake timeout: a dial that ignored the cancel would leak
// the connection until that timeout instead.
func TestServerCloseDuringRealDialAbortsIt(t *testing.T) {
	stall := editorStartStallingTarget(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	done := make(chan struct{})
	go func() {
		editor.NewServer(client, mustTarget(t, engines.MySQL, stall.config), 0).Serve(editorStallOpen(), nil, nil)
		close(done)
	}()

	editorAwaitRealDialInFlight(t, fake, stall)

	editorSendClose(fake)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not return on EditorClose while the real dial was in flight")
	}
	// The reserved connection must be released well before the dial's handshake timeout — proving the real
	// dial actually aborted on the cancel rather than running out its deadline.
	editorWaitForClosesWithin(t, fake, 1, 4*time.Second)
	editorExpectSingleClose(t, fake)
	editorExpectNoServing(t, fake)
}

// TestServerDrainDuringRealDialAbortsIt is the redeploy analogue of the above, driven through the real dial:
// a drain that lands while the real MySQL handshake is stalled aborts it and releases the connection fast.
func TestServerDrainDuringRealDialAbortsIt(t *testing.T) {
	stall := editorStartStallingTarget(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	draining := make(chan struct{})
	done := make(chan struct{})
	go func() {
		editor.NewServer(client, mustTarget(t, engines.MySQL, stall.config), 0).Serve(editorStallOpen(), nil, draining)
		close(done)
	}()

	editorAwaitRealDialInFlight(t, fake, stall)

	close(draining)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not return on drain while the real dial was in flight")
	}
	editorWaitForClosesWithin(t, fake, 1, 4*time.Second)
	editorExpectSingleClose(t, fake)
	editorExpectNoServing(t, fake)
}

func TestServerCloseInFlightCancelsTargetDb(t *testing.T) {
	fixture := editorSeedMySQL(t)
	fake, client := editorStartFakeCP(t, editorSessionID)
	waitDone := editorLaunch(t, fake, client, fixture)

	editorSendQuery(fake, "SELECT SLEEP(30)", 20)
	editorWaitForRequests(t, fake, 1)
	editorWaitForMySQLSleep(t, fixture, "SELECT SLEEP(30)")
	start := time.Now()
	editorSendClose(fake)
	waitDone()
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("server closed in %s; EditorClose did not interrupt the target-DB statement", elapsed)
	}
	editorExpectSingleClose(t, fake)
	editorExpectMySQLSleepStopped(t, fixture)
}

func TestServerPassesQueryTimeoutPlusGraceToConnection(t *testing.T) {
	fixture := editorSeedMySQL(t)
	capturing := &editorCapturingDb{Target: fixture.editorTarget, readTimeout: make(chan time.Duration, 1)}
	fixture.editorTarget = capturing
	fake, client := editorStartFakeCP(t, editorSessionID)
	waitDone := editorLaunchWithTimeout(t, fake, client, fixture, 17*time.Second)

	select {
	case got := <-capturing.readTimeout:
		if got != 47*time.Second {
			t.Fatalf("OpenConnection readTimeout = %s, want 47s", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OpenConnection readTimeout")
	}
	editorSendClose(fake)
	waitDone()
}

// editorLaunch starts a server against fixture over fake+client, completes its on-open refetch, then
// waits for and consumes SessionReady. It returns a function that blocks until the server goroutine exits.
func editorLaunch(t *testing.T, fake *editorFakeCP, client *cp.Client, fixture editorEngineFixture) func() {
	t.Helper()
	return editorLaunchConfigured(t, fake, client, fixture, nil)
}

func editorLaunchWithTimeout(t *testing.T, fake *editorFakeCP, client *cp.Client, fixture editorEngineFixture, queryTimeout time.Duration) func() {
	t.Helper()
	return editorLaunchOpenConfigured(t, fake, client, fixture, editorOpen(fixture), queryTimeout, nil)
}

// editorLaunchConfigured is editorLaunch with a hook to tweak the server (e.g. inject a short watchdog
// timeout) before Run. It returns a function that blocks until the server goroutine exits.
func editorLaunchConfigured(t *testing.T, fake *editorFakeCP, client *cp.Client, fixture editorEngineFixture, configure func(*editor.Server)) func() {
	t.Helper()
	return editorLaunchOpenConfigured(t, fake, client, fixture, editorOpen(fixture), 0, configure)
}

func editorLaunchOpen(t *testing.T, fake *editorFakeCP, client *cp.Client, fixture editorEngineFixture, open *pb.OpenEditorSession) func() {
	t.Helper()
	return editorLaunchOpenConfigured(t, fake, client, fixture, open, 0, nil)
}

func editorLaunchOpenConfigured(t *testing.T, fake *editorFakeCP, client *cp.Client, fixture editorEngineFixture, open *pb.OpenEditorSession, queryTimeout time.Duration, configure func(*editor.Server)) func() {
	t.Helper()
	server := editor.NewServer(client, fixture.editorTarget, queryTimeout)
	if configure != nil {
		configure(server)
	}
	done := make(chan struct{})
	go func() {
		server.Serve(open, nil, nil)
		close(done)
	}()
	select {
	case <-fake.editorReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for first editor session message")
	}
	first := editorRecv(t, fake)
	if first.GetSessionReady() == nil {
		t.Fatalf("editor session initialization failed before SessionReady: %v", first)
	}
	ready := first.GetSessionReady()
	if ready.GetSessionId() != open.GetSessionId() {
		t.Fatalf("SessionReady = %v, want session %q", ready, open.GetSessionId())
	}
	// SessionReady tells the CP which session the stream is for immediately; the target-DB open (and its on-open
	// catalog push) runs after it and completes at EditorServing. Wait for serving, then assert the push landed first.
	select {
	case <-fake.editorServing:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for EditorServing after the target-DB open")
	}
	fragments := fake.editorRecordedFragments()
	if len(fragments) != 1 || fragments[0].GetSchema() != fixture.editorNamespaceForTable() {
		t.Fatalf("on-open fragments = %v, want schema %q before EditorServing", fragments, fixture.editorNamespaceForTable())
	}
	if events := fake.editorRecordedEvents(); !editorLastEventBefore(events, "push:"+fixture.editorNamespaceForTable(), "serving") {
		t.Fatalf("events = %v, want on-open push acknowledged before EditorServing", events)
	}
	return func() {
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("server did not terminate")
		}
	}
}

func editorOpen(fixture editorEngineFixture) *pb.OpenEditorSession {
	return &pb.OpenEditorSession{
		SessionId:      editorSessionID,
		EphemeralToken: editorToken,
		ConnectionId:   []byte(editorConnectionID),
		OnOpen: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{
			Catalog: fixture.editorCatalog(),
			Schema:  fixture.editorNamespaceForTable(),
		}}}},
	}
}

func editorStartFakeCP(t *testing.T, datasourceName string) (*editorFakeCP, *cp.Client) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake editor session control plane: %v", err)
	}
	fake := editorNewFakeCP()
	server := grpc.NewServer()
	pb.RegisterControlPlaneServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		close(fake.editorCommands)
		server.Stop()
		_ = listener.Close()
	})

	client, err := cp.New(listener.Addr().String(), "editor-secret", datasourceName)
	if err != nil {
		t.Fatalf("cp.New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return fake, client
}

func editorSeedMySQL(t *testing.T) editorEngineFixture {
	t.Helper()
	targetConfig := dbtest.MySQL(t)
	seed := dbtest.OpenMySQL(t, "")
	statements := []string{
		"CREATE DATABASE IF NOT EXISTS " + editorMySQLSchema,
		"CREATE TABLE IF NOT EXISTS " + editorMySQLSchema + ".pm_run_rows (id INT PRIMARY KEY, secret VARCHAR(64) NULL, note VARCHAR(64) NOT NULL DEFAULT '')",
		"DELETE FROM " + editorMySQLSchema + ".pm_run_rows",
		// caching_sha2_password (mysql:8.0 default) so the editor session's shared target DB dial is exercised against
		// it too; the ALTER re-salts each run, forcing the plaintext full-auth (public-key) path on first dial.
		"CREATE USER IF NOT EXISTS '" + editorMySQLService + "'@'%' IDENTIFIED WITH caching_sha2_password BY '" + editorMySQLServicePwd + "'",
		"ALTER USER '" + editorMySQLService + "'@'%' IDENTIFIED WITH caching_sha2_password BY '" + editorMySQLServicePwd + "'",
		"GRANT ALL ON " + editorMySQLSchema + ".* TO '" + editorMySQLService + "'@'%'",
		"FLUSH PRIVILEGES",
	}
	for _, statement := range statements {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("MySQL seed statement %q: %v", statement, err)
		}
	}
	editorSeedRows(t, seed, "INSERT INTO "+editorMySQLSchema+".pm_run_rows (id, secret) VALUES ")
	config := spi.TargetConfig{
		Host: targetConfig.Host, Port: targetConfig.Port, Db: editorMySQLSchema,
		User: editorMySQLService, Password: editorMySQLServicePwd,
	}
	return editorEngineFixture{
		editorEngine:    engines.MySQL,
		editorTarget:    mustTarget(t, engines.MySQL, config),
		editorConfig:    config,
		editorTable:     editorMySQLSchema + ".pm_run_rows",
		editorNamespace: []string{editorMySQLSchema},
	}
}

func editorSeedPostgres(t *testing.T) editorEngineFixture {
	t.Helper()
	targetConfig := dbtest.Postgres(t)
	seed := dbtest.OpenPostgres(t, "")
	statements := []string{
		"CREATE SCHEMA IF NOT EXISTS " + editorPGSchema,
		"CREATE TABLE IF NOT EXISTS " + editorPGSchema + ".pm_run_rows (id int PRIMARY KEY, secret text NULL, note text NOT NULL DEFAULT '')",
		"DELETE FROM " + editorPGSchema + ".pm_run_rows",
	}
	for _, statement := range statements {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("Postgres seed statement %q: %v", statement, err)
		}
	}
	editorSeedRows(t, seed, "INSERT INTO "+editorPGSchema+".pm_run_rows (id, secret) VALUES ")
	config := spi.TargetConfig{
		Host: targetConfig.Host, Port: targetConfig.Port, Db: targetConfig.DB,
		User: targetConfig.User, Password: targetConfig.Password,
	}
	return editorEngineFixture{
		editorEngine:    engines.Postgres,
		editorTarget:    mustTarget(t, engines.Postgres, config),
		editorConfig:    config,
		editorTable:     editorPGSchema + ".pm_run_rows",
		editorNamespace: []string{"pg_catalog", "public"},
	}
}

func mustTarget(t *testing.T, e *engines.Engine, config spi.TargetConfig) spi.Target {
	t.Helper()
	provider, err := registry.For(e)
	if err != nil {
		t.Fatalf("registry.For(%s): %v", e.WireName, err)
	}
	target, err := provider.OpenTarget(config)
	if err != nil {
		t.Fatalf("OpenTarget(%s): %v", e.WireName, err)
	}
	t.Cleanup(func() { _ = target.Close() })
	return target
}

func editorSeedRows(t *testing.T, seed *sql.DB, prefix string) {
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

func editorSendQuery(fake *editorFakeCP, sql string, maxRows int32) {
	fake.editorCommands <- &pb.CpEditorMsg{Kind: &pb.CpEditorMsg_Query{
		Query: &pb.EditorQuery{Sql: sql, MaxRows: maxRows},
	}}
}

func editorSendCancel(fake *editorFakeCP) {
	fake.editorCommands <- &pb.CpEditorMsg{Kind: &pb.CpEditorMsg_Cancel{Cancel: &pb.EditorCancel{}}}
}

func editorSendClose(fake *editorFakeCP) {
	fake.editorCommands <- &pb.CpEditorMsg{Kind: &pb.CpEditorMsg_Close{Close: &pb.EditorClose{}}}
}

func editorWaitForRequests(t *testing.T, fake *editorFakeCP, count int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(fake.editorRecordedRequests()) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d decision requests", count)
}

// editorWaitForCloses waits until at least count CloseConnection requests have been recorded. An aborted
// target-DB open releases its connection off the hot path (see openTargetDb's abort), so a test cannot read the count
// synchronously right after the server returns.
func editorWaitForCloses(t *testing.T, fake *editorFakeCP, count int) {
	t.Helper()
	editorWaitForClosesWithin(t, fake, count, 10*time.Second)
}

func editorWaitForClosesWithin(t *testing.T, fake *editorFakeCP, count int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if len(fake.editorRecordedCloses()) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %d CloseConnection requests", within, count)
}

// editorStallingTarget is a TCP endpoint that accepts connections and holds them open without ever writing, so a
// target-DB handshake read against it stalls. accepted fires on the first accepted connection.
type editorStallingTarget struct {
	config   spi.TargetConfig
	accepted <-chan struct{}
}

// editorStartStallingTarget stands up an editorStallingTarget on a loopback port and closes every accepted connection
// (and the listener) on cleanup. It stands in for a target DB that is reachable but slow to answer, so a test
// can dial it for real and cut the editor session while the handshake is still blocked.
func editorStartStallingTarget(t *testing.T) editorStallingTarget {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stalling target: %v", err)
	}
	accepted := make(chan struct{}, 1)
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for _, conn := range held {
			_ = conn.Close()
		}
		mu.Unlock()
	})
	addr := listener.Addr().(*net.TCPAddr)
	return editorStallingTarget{
		config: spi.TargetConfig{
			Host: addr.IP.String(), Port: addr.Port, Db: editorMySQLSchema,
			User: editorMySQLService, Password: editorMySQLServicePwd,
		},
		accepted: accepted,
	}
}

// editorStallOpen is a valid editor-session open whose on-open catalog work is never reached (the dial to a stalling target
// blocks first), so any schema will do.
func editorStallOpen() *pb.OpenEditorSession {
	return &pb.OpenEditorSession{
		SessionId:      editorSessionID,
		EphemeralToken: editorToken,
		ConnectionId:   []byte(editorConnectionID),
		OnOpen:         []*pb.ProxyCommand{&pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Catalog: "def", Schema: editorMySQLSchema}}}},
	}
}

// editorAwaitRealDialInFlight consumes SessionReady and then blocks until the real dial has connected to the
// stalling target, so a test cuts the editor session while the handshake is genuinely stalled — not before the dial began.
func editorAwaitRealDialInFlight(t *testing.T, fake *editorFakeCP, stall editorStallingTarget) {
	t.Helper()
	select {
	case <-fake.editorReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the server to start")
	}
	if first := editorRecv(t, fake); first.GetSessionReady() == nil {
		t.Fatalf("first frame = %v, want SessionReady", first)
	}
	select {
	case <-stall.accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("the real dial did not connect to the stalling target")
	}
}

func editorWaitForMySQLSleep(t *testing.T, fixture editorEngineFixture, sleepSQL string) {
	t.Helper()
	direct := editorOpenMySQLInspector(t, fixture)
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

func editorWaitForPostgresSleep(t *testing.T, fixture editorEngineFixture) {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", fixture.editorConfig.User, fixture.editorConfig.Password, fixture.editorConfig.Host, fixture.editorConfig.Port, fixture.editorConfig.Db)
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

func editorOpenMySQLInspector(t *testing.T, fixture editorEngineFixture) *sql.DB {
	t.Helper()
	direct, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", fixture.editorConfig.User, fixture.editorConfig.Password, fixture.editorConfig.Host, fixture.editorConfig.Port, fixture.editorConfig.Db))
	if err != nil {
		t.Fatalf("open MySQL process inspector: %v", err)
	}
	return direct
}

func editorExpectMySQLSleepStopped(t *testing.T, fixture editorEngineFixture) {
	t.Helper()
	direct := editorOpenMySQLInspector(t, fixture)
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
	t.Fatal("MySQL SLEEP(30) was still running after EditorClose")
}

func editorRecv(t *testing.T, fake *editorFakeCP) *pb.ProxyEditorMsg {
	t.Helper()
	select {
	case message := <-fake.editorTranscript:
		return message
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for run transcript message")
		return nil
	}
}

func editorExpectDecision(t *testing.T, message *pb.ProxyEditorMsg, action pb.EnfAction, masked []string, deny string) {
	t.Helper()
	decision := message.GetDecision()
	if decision == nil || decision.GetDecision() != action || !reflect.DeepEqual(decision.GetMaskedColumns(), masked) || decision.GetDenyReason() != deny {
		t.Fatalf("editor session message = %v; decision = %v, want action=%s masked=%v deny=%q", message, decision, action, masked, deny)
	}
}

func editorExpectRows(t *testing.T, message *pb.ProxyEditorMsg, columns []string) []*pb.EditorRow {
	t.Helper()
	result := message.GetResultRows()
	if result == nil || !reflect.DeepEqual(result.GetColumns(), columns) {
		t.Fatalf("EditorResultRows = %v, want columns %v", result, columns)
	}
	return result.GetRows()
}

func editorExpectDone(t *testing.T, message *pb.ProxyEditorMsg, rowsAffected int32) {
	t.Helper()
	done := message.GetDone()
	if done == nil || done.GetRowsAffected() != rowsAffected {
		t.Fatalf("EditorDone = %v, want rowsAffected=%d", done, rowsAffected)
	}
}

func editorExpectTruncatedDone(t *testing.T, message *pb.ProxyEditorMsg, truncated bool) {
	t.Helper()
	editorExpectDone(t, message, -1)
	if got := message.GetDone().GetTruncatedByCap(); got != truncated {
		t.Fatalf("EditorDone truncated_by_cap = %v, want %v", got, truncated)
	}
}

type editorExpectedValue struct {
	value  string
	isNull bool
}

func editorExpectValues(t *testing.T, rows []*pb.EditorRow, expected [][]editorExpectedValue) {
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

func editorExpectSilence(t *testing.T, fake *editorFakeCP, duration time.Duration) {
	t.Helper()
	select {
	case message := <-fake.editorTranscript:
		t.Fatalf("unexpected editor session message during silence window: %v", message)
	case <-time.After(duration):
	}
}

// editorAwaitTargetDbOpenInFlight consumes SessionReady and then blocks until the target-DB open is genuinely in
// flight (the slow-open provider's entered signal), so a test can cut the editor session knowing the abort must unwind
// an open that is actually running, not race the server before it reaches the open.
func editorAwaitTargetDbOpenInFlight(t *testing.T, fake *editorFakeCP, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-fake.editorReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the server to start")
	}
	if first := editorRecv(t, fake); first.GetSessionReady() == nil {
		t.Fatalf("first frame = %v, want SessionReady", first)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the target-DB open to start")
	}
}

// editorAwaitServing waits until the server has completed its target-DB open and sent EditorServing, so a test that
// exercises a post-serving path (an idle drain, an in-flight statement, a queued query) starts from a ready
// session — matching the control-plane, which sends a query only after it observes EditorServing.
func editorAwaitServing(t *testing.T, fake *editorFakeCP) {
	t.Helper()
	select {
	case <-fake.editorReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the server to start")
	}
	if first := editorRecv(t, fake); first.GetSessionReady() == nil {
		t.Fatalf("expected SessionReady, got %v", first)
	}
	select {
	case <-fake.editorServing:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for EditorServing after the target-DB open")
	}
}

// editorExpectNoServing asserts the editor session never reached EditorServing — the open was aborted or failed, so the
// control-plane never installed a live editor session for it.
func editorExpectNoServing(t *testing.T, fake *editorFakeCP) {
	t.Helper()
	select {
	case <-fake.editorServing:
		t.Fatal("EditorServing was sent for an editor session that should have been aborted before it was ready to serve")
	default:
	}
}

var registry = spi.MustRegistry(athena.Provider{}, mysql.Provider{}, postgres.Provider{})
