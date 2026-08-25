package pgproxy_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

type rawPGClient struct {
	conn     net.Conn
	frontend *pgproto3.Frontend
}

var postgresEmptyQueryCases = []struct {
	name string
	sql  string
}{
	{name: "literal", sql: ""},
	{name: "whitespace", sql: " \t\r\n\f"},
	{name: "line comment", sql: "-- empty\n"},
	{name: "block comment", sql: "/* outer /* nested */ comment */"},
	{name: "semicolon", sql: ";"},
	{name: "combined", sql: " ; -- empty\n /* still empty */ ; "},
}

func newRawPGClient(t *testing.T, h *brokerHarness) *rawPGClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.addr, 30*time.Second)
	if err != nil {
		t.Fatalf("dial raw PostgreSQL client: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		_ = conn.Close()
		t.Fatalf("set raw PostgreSQL client deadline: %v", err)
	}
	client := &rawPGClient{conn: conn, frontend: pgproto3.NewFrontend(conn, conn)}
	t.Cleanup(func() {
		client.frontend.Send(&pgproto3.Terminate{})
		_ = client.frontend.Flush()
		_ = conn.Close()
	})

	client.frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":     "pm",
			"database": "app",
		},
	})
	if err := client.frontend.Flush(); err != nil {
		t.Fatalf("send raw PostgreSQL startup: %v", err)
	}
	message, err := client.frontend.Receive()
	if err != nil {
		t.Fatalf("receive raw PostgreSQL auth request: %v", err)
	}
	if _, ok := message.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("auth request = %T, want AuthenticationCleartextPassword", message)
	}
	client.frontend.Send(&pgproto3.PasswordMessage{Password: validToken})
	if err := client.frontend.Flush(); err != nil {
		t.Fatalf("send raw PostgreSQL password: %v", err)
	}
	for {
		message, err := client.frontend.Receive()
		if err != nil {
			t.Fatalf("receive raw PostgreSQL auth response: %v", err)
		}
		switch message := message.(type) {
		case *pgproto3.AuthenticationOk, *pgproto3.ParameterStatus, *pgproto3.BackendKeyData, *pgproto3.NoticeResponse:
		case *pgproto3.ReadyForQuery:
			return client
		case *pgproto3.ErrorResponse:
			t.Fatalf("raw PostgreSQL auth failed: %s (%s)", message.Message, message.Code)
		default:
			t.Fatalf("unexpected raw PostgreSQL auth response %T", message)
		}
	}
}

func (c *rawPGClient) simpleQuery(t *testing.T, sql string) []pgproto3.BackendMessage {
	t.Helper()
	c.frontend.Send(&pgproto3.Query{String: sql})
	if err := c.frontend.Flush(); err != nil {
		t.Fatalf("send raw simple query: %v", err)
	}
	return c.drainToRFQ(t)
}

func (c *rawPGClient) sendSync(t *testing.T, messages ...pgproto3.FrontendMessage) []pgproto3.BackendMessage {
	t.Helper()
	for _, message := range messages {
		c.frontend.Send(message)
	}
	c.frontend.Send(&pgproto3.Sync{})
	if err := c.frontend.Flush(); err != nil {
		t.Fatalf("send raw extended messages: %v", err)
	}
	return c.drainToRFQ(t)
}

func (c *rawPGClient) drainToRFQ(t *testing.T) []pgproto3.BackendMessage {
	t.Helper()
	var messages []pgproto3.BackendMessage
	for {
		message, err := c.frontend.Receive()
		if err != nil {
			t.Fatalf("receive raw PostgreSQL response: %v", err)
		}
		messages = append(messages, message)
		if _, ok := message.(*pgproto3.ReadyForQuery); ok {
			return messages
		}
	}
}

func TestEmptySimpleQueryDecidesAndRelays(t *testing.T) {
	h := startBroker(t)
	client := newRawPGClient(t, h)

	for _, tc := range postgresEmptyQueryCases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.fake.requests())
			frames := client.simpleQuery(t, tc.sql)
			if len(frames) != 2 {
				t.Fatalf("empty-query frames = %d, want EmptyQueryResponse + ReadyForQuery", len(frames))
			}
			if _, ok := frames[0].(*pgproto3.EmptyQueryResponse); !ok {
				t.Fatalf("empty-query frame[0] = %T, want EmptyQueryResponse", frames[0])
			}
			assertRawReadyForQuery(t, frames, 'I')
			// An empty statement is a first-class decision (audited, Cedar-visible), not a bypass.
			if got := len(h.fake.requests()); got != before+1 {
				t.Fatalf("Decide requests = %d, want %d", got, before+1)
			}
		})
	}
}

func TestEmptySimpleQueryDetectsDeadTarget(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := newRawPGClient(t, h)

	var backendPID int
	for _, frame := range client.simpleQuery(t, "SELECT pg_backend_pid()") {
		row, ok := frame.(*pgproto3.DataRow)
		if !ok || len(row.Values) != 1 {
			continue
		}
		var err error
		backendPID, err = strconv.Atoi(string(row.Values[0]))
		if err != nil {
			t.Fatalf("parse target DB process id: %v", err)
		}
	}
	if backendPID == 0 {
		t.Fatal("target DB process id was not returned")
	}
	admin := dbtest.OpenPostgres(t, "")
	var terminated bool
	if err := admin.QueryRow("SELECT pg_terminate_backend($1)", backendPID).Scan(&terminated); err != nil {
		t.Fatalf("terminate target DB session: %v", err)
	}
	if !terminated {
		t.Fatal("target DB session was not terminated")
	}

	if err := client.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set dead-target read deadline: %v", err)
	}
	// An empty statement takes the same decide-and-relay path as any other; against a dead target
	// it must surface an error (not hang, not succeed), exactly like a non-empty statement.
	client.frontend.Send(&pgproto3.Query{})
	if err := client.frontend.Flush(); err != nil {
		t.Fatalf("send empty query to dead target: %v", err)
	}
	sawError := false
	for {
		message, err := client.frontend.Receive()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatal("empty query against dead target timed out instead of surfacing an error")
			}
			if !sawError {
				t.Fatal("connection closed without an error response")
			}
			return
		}
		switch message.(type) {
		case *pgproto3.ErrorResponse:
			sawError = true
		case *pgproto3.EmptyQueryResponse, *pgproto3.CommandComplete:
			t.Fatalf("empty query against dead target succeeded: %T", message)
		case *pgproto3.ReadyForQuery:
			if !sawError {
				t.Fatal("empty query reported a dead target connection as ready without an error")
			}
			return
		}
	}
}

func TestEmptyExtendedQueryDecidesAndRelays(t *testing.T) {
	h := startBroker(t)
	client := newRawPGClient(t, h)

	for _, tc := range postgresEmptyQueryCases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.fake.requests())
			frames := client.sendSync(t,
				&pgproto3.Parse{Name: "", Query: tc.sql},
				&pgproto3.Bind{},
				&pgproto3.Describe{ObjectType: 'P'},
				&pgproto3.Execute{},
			)
			assertEmptyExtendedResponse(t, frames, 'I')
			// Parse authorizes and Execute re-decides — both gates must fire, on the original SQL.
			after := h.fake.requests()
			if len(after) != before+2 {
				t.Fatalf("Decide requests = %d, want %d (Parse + Execute both decide empty statements)", len(after), before+2)
			}
			for _, request := range after[before:] {
				if request.GetSql() != tc.sql {
					t.Fatalf("Decide saw %q, want the original %q", request.GetSql(), tc.sql)
				}
			}
		})
	}
}

func TestEmptyQueriesInAbortedTransaction(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	abort := func(t *testing.T, client *rawPGClient) {
		t.Helper()
		assertNoRawPGError(t, client.simpleQuery(t, "BEGIN"))
		frames := client.simpleQuery(t, "SELECT 1 / 0")
		if response, ok := frames[0].(*pgproto3.ErrorResponse); !ok || response.Code != "22012" {
			t.Fatalf("division-by-zero frame[0] = %#v, want ErrorResponse(22012)", frames[0])
		}
		assertRawReadyForQuery(t, frames, 'E')
	}

	t.Run("simple", func(t *testing.T) {
		client := newRawPGClient(t, h)
		abort(t, client)
		for _, tc := range postgresEmptyQueryCases {
			t.Run(tc.name, func(t *testing.T) {
				before := len(h.fake.requests())
				frames := client.simpleQuery(t, tc.sql)
				if _, ok := frames[0].(*pgproto3.EmptyQueryResponse); !ok {
					t.Fatalf("empty-query frame[0] = %T, want EmptyQueryResponse", frames[0])
				}
				assertRawReadyForQuery(t, frames, 'E')
				if got := len(h.fake.requests()); got != before+1 {
					t.Fatalf("Decide requests = %d after empty query, want %d", got, before+1)
				}
			})
		}
	})

	t.Run("extended", func(t *testing.T) {
		client := newRawPGClient(t, h)
		abort(t, client)
		for _, tc := range postgresEmptyQueryCases {
			t.Run(tc.name, func(t *testing.T) {
				before := len(h.fake.requests())
				frames := client.sendSync(t,
					&pgproto3.Parse{Name: "", Query: tc.sql},
					&pgproto3.Bind{},
					&pgproto3.Describe{ObjectType: 'P'},
					&pgproto3.Execute{},
				)
				if len(frames) != 3 {
					t.Fatalf("empty extended-query frames = %d, want ParseComplete + ErrorResponse + ReadyForQuery", len(frames))
				}
				if _, ok := frames[0].(*pgproto3.ParseComplete); !ok {
					t.Fatalf("empty extended-query frame[0] = %T, want ParseComplete", frames[0])
				}
				if response, ok := frames[1].(*pgproto3.ErrorResponse); !ok || response.Code != "25P02" {
					t.Fatalf("empty extended-query frame[1] = %#v, want ErrorResponse(25P02)", frames[1])
				}
				assertRawReadyForQuery(t, frames, 'E')
				if got := len(h.fake.requests()); got <= before {
					t.Fatalf("Decide requests = %d after empty query, want > %d", got, before)
				}
			})
		}
	})
}

func assertEmptyExtendedResponse(t *testing.T, frames []pgproto3.BackendMessage, txStatus byte) {
	t.Helper()
	if len(frames) != 5 {
		t.Fatalf("empty extended-query frames = %d, want ParseComplete + BindComplete + NoData + EmptyQueryResponse + ReadyForQuery", len(frames))
	}
	want := []any{
		(*pgproto3.ParseComplete)(nil),
		(*pgproto3.BindComplete)(nil),
		(*pgproto3.NoData)(nil),
		(*pgproto3.EmptyQueryResponse)(nil),
		(*pgproto3.ReadyForQuery)(nil),
	}
	for i, expected := range want {
		if reflect.TypeOf(frames[i]) != reflect.TypeOf(expected) {
			t.Fatalf("empty extended-query frame[%d] = %T, want %T", i, frames[i], expected)
		}
	}
	assertRawReadyForQuery(t, frames, txStatus)
}

func TestExtendedCatalogRefreshRunsAfterCommandCompleteBeforeSync(t *testing.T) {
	h := startBroker(t)
	const (
		tableName = "refresh_extended"
		ddlSQL    = "CREATE TABLE " + primarySchema + "." + tableName + " (id int)"
	)
	direct := dbtest.OpenPostgres(t, "")
	if _, err := direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName); err != nil {
		t.Fatalf("drop stale extended refresh table: %v", err)
	}
	t.Cleanup(func() { _, _ = direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName) })
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == ddlSQL {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := newRawPGClient(t, h)

	parseFrames := client.sendSync(t, &pgproto3.Parse{Name: "refresh_ddl", Query: ddlSQL})
	assertRawExtendedCompletion(t, parseFrames, "ParseComplete", 'I')
	if got := len(h.fake.fragmentRequests()); got != 0 {
		t.Fatalf("catalog pushes after Parse = %d, want 0", got)
	}

	client.frontend.Send(&pgproto3.Bind{DestinationPortal: "refresh_portal", PreparedStatement: "refresh_ddl"})
	client.frontend.Send(&pgproto3.Execute{Portal: "refresh_portal"})
	client.frontend.Send(&pgproto3.Flush{})
	if err := client.frontend.Flush(); err != nil {
		t.Fatalf("send Execute without Sync: %v", err)
	}
	for {
		message, err := client.frontend.Receive()
		if err != nil {
			t.Fatalf("receive Execute response: %v", err)
		}
		if response, ok := message.(*pgproto3.ErrorResponse); ok {
			t.Fatalf("Execute error = %s (%s)", response.Message, response.Code)
		}
		if _, ok := message.(*pgproto3.CommandComplete); ok {
			break
		}
		if _, leaked := message.(*pgproto3.ReadyForQuery); leaked {
			t.Fatal("internal extended refetch leaked an injected ReadyForQuery before client Sync")
		}
	}
	client.frontend.Send(&pgproto3.Sync{})
	if err := client.frontend.Flush(); err != nil {
		t.Fatalf("send Sync: %v", err)
	}
	requests := waitForFragmentRequests(t, h.fake, 1)
	if len(requests) != 1 || !fragmentHasColumn(requests[0], primarySchema, tableName, "id") {
		t.Fatalf("fragment pushes after Execute = %#v, want one snapshot containing %s.%s.id", requests, primarySchema, tableName)
	}
	assertRawReadyForQuery(t, client.drainToRFQ(t), 'I')
}

func TestExtendedCatalogRefreshPushFailureClosesInsteadOfWaitingForSync(t *testing.T) {
	h := startBroker(t)
	const (
		tableName = "refresh_extended_push_failure"
		ddlSQL    = "CREATE TABLE " + primarySchema + "." + tableName + " (id int)"
	)
	direct := dbtest.OpenPostgres(t, "")
	if _, err := direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName); err != nil {
		t.Fatalf("drop stale extended table: %v", err)
	}
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == ddlSQL {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	h.fake.setPushError(status.Error(codes.Unavailable, "injected push failure"))
	client := newRawPGClient(t, h)
	assertRawExtendedCompletion(t, client.sendSync(t, &pgproto3.Parse{Name: "push_fail", Query: ddlSQL}), "ParseComplete", 'I')

	client.frontend.Send(&pgproto3.Bind{DestinationPortal: "push_fail_portal", PreparedStatement: "push_fail"})
	client.frontend.Send(&pgproto3.Execute{Portal: "push_fail_portal"})
	client.frontend.Send(&pgproto3.Flush{})
	if err := client.frontend.Flush(); err != nil {
		t.Fatalf("send Execute: %v", err)
	}
	for {
		message, err := client.frontend.Receive()
		if err != nil {
			break
		}
		if _, ok := message.(*pgproto3.CommandComplete); ok {
			continue
		}
		if _, ready := message.(*pgproto3.ReadyForQuery); ready {
			t.Fatal("push failure entered skip-to-Sync recovery instead of closing")
		}
	}
	if got := len(waitForFragmentRequests(t, h.fake, 1)); got != 1 {
		t.Fatalf("fragment push attempts = %d, want 1", got)
	}
}

func TestExtendedCatalogRefreshDoesNotArmOnExecuteError(t *testing.T) {
	h := startBroker(t)
	const (
		tableName = "refresh_extended_error"
		ddlSQL    = "CREATE TABLE " + primarySchema + "." + tableName + " (id int CHECK (id > 0))"
	)
	direct := dbtest.OpenPostgres(t, "")
	if _, err := direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName); err != nil {
		t.Fatalf("drop stale extended error table: %v", err)
	}
	t.Cleanup(func() { _, _ = direct.Exec("DROP TABLE IF EXISTS " + primarySchema + "." + tableName) })
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == ddlSQL {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := newRawPGClient(t, h)

	// Parse succeeds, then a direct target-DB session creates the same table before Execute so PostgreSQL's
	// Execute path returns ErrorResponse. The command must not arm on that terminal failure.
	assertRawExtendedCompletion(t, client.sendSync(t, &pgproto3.Parse{Name: "refresh_ddl_error", Query: ddlSQL}), "ParseComplete", 'I')
	if _, err := direct.Exec(ddlSQL); err != nil {
		t.Fatalf("create conflicting table directly: %v", err)
	}
	frames := client.sendSync(t,
		&pgproto3.Bind{DestinationPortal: "refresh_error_portal", PreparedStatement: "refresh_ddl_error"},
		&pgproto3.Execute{Portal: "refresh_error_portal"},
	)
	var response *pgproto3.ErrorResponse
	for _, frame := range frames {
		if candidate, ok := frame.(*pgproto3.ErrorResponse); ok {
			response = candidate
			break
		}
	}
	if response == nil || response.Code != "42P07" {
		t.Fatalf("Execute frames = %#v, want 42P07 duplicate_table", frames)
	}
	assertRawReadyForQuery(t, frames, 'I')
	if got := len(h.fake.fragmentRequests()); got != 0 {
		t.Fatalf("catalog pushes after Execute ErrorResponse = %d, want 0", got)
	}
}

func TestExtendedBeforeDecideRefetchRetriesWithoutReadyForQueryLeak(t *testing.T) {
	h := startBroker(t)
	const query = "SELECT 1"
	attempts := 0
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() != query {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
		}
		attempts++
		if attempts == 1 {
			return beforeDecide(&pb.ProxyCommand{
				Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: primarySchema}},
			}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := newRawPGClient(t, h)
	frames := client.sendSync(t, &pgproto3.Parse{Name: "retry", Query: query})
	assertRawExtendedCompletion(t, frames, "ParseComplete", 'I')
	if attempts != 2 {
		t.Fatalf("Decide attempts = %d, want 2", attempts)
	}
	if got := len(waitForFragmentRequests(t, h.fake, 1)); got != 1 {
		t.Fatalf("fragment pushes = %d, want 1 before retry", got)
	}
}

func TestExtendedAllowRelaysParameterizedRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	const query = "SELECT id, name, ssn FROM it_pgproxy.people WHERE id = $1"
	rows, err := conn.Query(context.Background(), query, 1)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("rows.Next = false: %v", rows.Err())
	}
	var id int
	var name string
	var ssn *string
	if err := rows.Scan(&id, &name, &ssn); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if id != 1 || name != "Alice" || ssn == nil || *ssn != "987-65-4320" {
		t.Fatalf("row = (%d, %q, %v), want Alice row", id, name, ssn)
	}
	if rows.Next() {
		t.Fatal("query returned more than one row")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}

	requests := h.fake.requests()
	if len(requests) != 2 {
		t.Fatalf("Decide requests = %d, want 2 (Parse + Execute)", len(requests))
	}
	for i, request := range requests {
		if request.GetSql() != query || !reflect.DeepEqual(request.GetSearchPath(), []string{"pg_catalog", "public"}) {
			t.Fatalf("DecisionRequest[%d] = %+v, want placeholder SQL and default search path", i, request)
		}
	}
}

func TestExtendedDenyAtParseLeaksNothing(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "prepared ssn is off-limits"}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	const query = "SELECT ssn FROM it_pgproxy.people WHERE id = $1"
	if _, err := conn.Prepare(ctx, "stmt_deny", query); err == nil {
		t.Fatal("denied Prepare succeeded")
	} else {
		assertPgError(t, err, "42501", "proxy-monster denied")
	}
	if got := len(h.fake.requests()); got != 1 {
		t.Fatalf("Decide requests after denied Parse = %d, want 1", got)
	}

	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	if _, err := conn.Prepare(ctx, "stmt_deny", query); err != nil {
		t.Fatalf("re-Prepare same name after denial: %v", err)
	}
	var ssn string
	if err := conn.QueryRow(ctx, "stmt_deny", 1).Scan(&ssn); err != nil {
		t.Fatalf("query recovered statement: %v", err)
	}
	if ssn != "987-65-4320" {
		t.Fatalf("ssn = %q, want cleartext primary value", ssn)
	}
}

func TestExtendedTextMaskPreservesNull(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)}},
		}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	rows, err := conn.Query(context.Background(), "SELECT id, name, ssn FROM it_pgproxy.people ORDER BY id", pgx.QueryExecModeExec)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	defer rows.Close()
	var got []*string
	for rows.Next() {
		var id int
		var name string
		var ssn *string
		if err := rows.Scan(&id, &name, &ssn); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got = append(got, ssn)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	masked := "####"
	if !reflect.DeepEqual(got, []*string{&masked, nil}) {
		t.Fatalf("masked ssns = %#v, want [#### nil]", got)
	}
}

func TestExtendedTextUnbindableMaskLeaksNoRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(99)}},
		}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	rows, err := conn.Query(context.Background(), "SELECT id, name, ssn FROM it_pgproxy.people ORDER BY id", pgx.QueryExecModeExec)
	if err != nil {
		assertExtendedMaskError(t, err)
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
	assertExtendedMaskError(t, rows.Err())
}

func TestExtendedBinaryMaskWithoutPermitFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision: pb.EnfAction_MASK,
			Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)}},
		}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	const query = "SELECT id, name, ssn FROM it_pgproxy.people WHERE id = $1"
	if _, err := conn.Prepare(ctx, "stmt_bin", query); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	rows, err := conn.Query(ctx, "stmt_bin", pgx.QueryResultFormats{1, 1, 1}, 1)
	if err != nil {
		assertPgError(t, err, "0A000", "binary result format")
	} else {
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
		}
		if count != 0 {
			t.Fatalf("scanned rows = %d, want 0", count)
		}
		assertPgError(t, rows.Err(), "0A000", "binary result format")
	}
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests = %d, want 2", got)
	}
}

func TestExtendedBinaryMaskWithPermitRelaysVerbatim(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{
			Decision:            pb.EnfAction_MASK,
			Masks:               []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)}},
			UnmaskablePermitted: true,
		}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	const query = "SELECT id, name, ssn FROM it_pgproxy.people WHERE id = $1"
	if _, err := conn.Prepare(ctx, "stmt_bin_permit", query); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	var id int
	var name, ssn string
	if err := conn.QueryRow(ctx, "stmt_bin_permit", pgx.QueryResultFormats{1, 1, 1}, 1).Scan(&id, &name, &ssn); err != nil {
		t.Fatalf("binary QueryRow: %v", err)
	}
	if id != 1 || name != "Alice" || ssn != "987-65-4320" {
		t.Fatalf("row = (%d, %q, %q), want cleartext Alice row", id, name, ssn)
	}
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests = %d, want 2", got)
	}
}

func TestExtendedExecuteRevocationDeniesMutation(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	const query = "INSERT INTO it_pgproxy.prepared_notes (id, note) VALUES ($1, $2)"
	if _, err := conn.Prepare(ctx, "stmt_ins", query); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "grant revoked"}), nil
	}
	if _, err := conn.Exec(ctx, "stmt_ins", 11, "leak"); err == nil {
		t.Fatal("revoked prepared mutation succeeded")
	} else {
		assertPgError(t, err, "42501", "proxy-monster denied")
	}

	direct := dbtest.OpenPostgres(t, "")
	var count int
	if err := direct.QueryRow("SELECT COUNT(*) FROM " + primarySchema + ".prepared_notes WHERE id = 11").Scan(&count); err != nil {
		t.Fatalf("verify direct row count: %v", err)
	}
	if count != 0 {
		t.Fatalf("revoked mutation row count = %d, want 0", count)
	}
	if got := len(h.fake.requests()); got != 2 {
		t.Fatalf("Decide requests = %d, want 2", got)
	}
}

func TestExtendedExecuteAuthorizesUnderBindTimeNamespace(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "SET search_path TO "+primarySchema, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("SET primary search_path: %v", err)
	}
	const preparedQuery = "SELECT ssn FROM people WHERE id = $1"
	if _, err := conn.Prepare(ctx, "stmt_live", preparedQuery); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := conn.Exec(ctx, "SET search_path TO "+secondarySchema, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("SET secondary search_path: %v", err)
	}
	// PostgreSQL revalidates and resolves the named statement at Bind under the secondary path, so the
	// resulting portal returns the secondary row and its Execute decision must use that same bind-time path.
	var preparedSSN string
	if err := conn.QueryRow(ctx, "stmt_live", 10).Scan(&preparedSSN); err != nil {
		t.Fatalf("prepared QueryRow: %v", err)
	}
	if preparedSSN != "secret-2" {
		t.Fatalf("prepared ssn = %q, want secondary schema value", preparedSSN)
	}
	const liveQuery = "SELECT name FROM people WHERE id = 10"
	var liveName string
	if err := conn.QueryRow(ctx, liveQuery).Scan(&liveName); err != nil {
		t.Fatalf("live QueryRow: %v", err)
	}
	if liveName != "Secondary" {
		t.Fatalf("live name = %q, want Secondary", liveName)
	}

	requests := h.fake.requests()
	if len(requests) != 6 {
		t.Fatalf("Decide requests = %d, want 6 (SET, Parse, SET, Execute, Parse, Execute)", len(requests))
	}
	wantSQL := []string{
		"SET search_path TO " + primarySchema,
		preparedQuery,
		"SET search_path TO " + secondarySchema,
		preparedQuery,
		liveQuery,
		liveQuery,
	}
	wantPaths := [][]string{
		{"pg_catalog", "public"},
		{"pg_catalog", primarySchema},
		{"pg_catalog", primarySchema},
		{"pg_catalog", secondarySchema},
		{"pg_catalog", secondarySchema},
		{"pg_catalog", secondarySchema},
	}
	for i, request := range requests {
		if request.GetSql() != wantSQL[i] || !reflect.DeepEqual(request.GetSearchPath(), wantPaths[i]) {
			t.Fatalf("DecisionRequest[%d] = %+v, want SQL %q path %v", i, request, wantSQL[i], wantPaths[i])
		}
	}
}

func TestExtendedSearchPathSwapCannotBypassExecutePolicy(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		for _, schema := range request.GetSearchPath() {
			if schema == secondarySchema {
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "secondary schema forbidden"}), nil
			}
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "SET search_path TO "+primarySchema, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("SET primary search_path: %v", err)
	}
	const preparedQuery = "SELECT ssn FROM people WHERE id = $1"
	if _, err := conn.Prepare(ctx, "stmt_swap", preparedQuery); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := conn.Exec(ctx, "SET search_path TO "+secondarySchema, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("SET secondary search_path: %v", err)
	}

	rows, err := conn.Query(ctx, "stmt_swap", 10)
	if err != nil {
		assertPgError(t, err, "42501", "secondary schema forbidden")
	} else {
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
		}
		if count != 0 {
			t.Fatalf("scanned rows = %d, want 0", count)
		}
		assertPgError(t, rows.Err(), "42501", "secondary schema forbidden")
	}

	requests := h.fake.requests()
	if len(requests) != 4 {
		t.Fatalf("Decide requests = %d, want 4 (SET, Parse, SET, Execute)", len(requests))
	}
	// pgx binds immediately after the second SET, so request[3] must carry that bind-time context.
	executeRequest := requests[3]
	if executeRequest.GetSql() != preparedQuery || !reflect.DeepEqual(executeRequest.GetSearchPath(), []string{"pg_catalog", secondarySchema}) {
		t.Fatalf("Execute DecisionRequest = %+v, want SQL %q path [pg_catalog %s]", executeRequest, preparedQuery, secondarySchema)
	}
}

func TestExtendedExecuteDecidesUnderBindTimeContext(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := newRawPGClient(t, h)
	const victimSQL = "SELECT ssn FROM people WHERE id = $1"

	assertNoRawPGError(t, client.simpleQuery(t, "SET search_path TO "+primarySchema))
	assertNoRawPGError(t, client.simpleQuery(t, "BEGIN"))
	parseFrames := client.sendSync(t, &pgproto3.Parse{Name: "victim", Query: victimSQL})
	assertRawExtendedCompletion(t, parseFrames, "ParseComplete", 'T')
	assertNoRawPGError(t, client.simpleQuery(t, "SET search_path TO "+secondarySchema))
	bindFrames := client.sendSync(t, &pgproto3.Bind{
		DestinationPortal: "p_drift",
		PreparedStatement: "victim",
		Parameters:        [][]byte{[]byte("10")},
	})
	assertRawExtendedCompletion(t, bindFrames, "BindComplete", 'T')
	assertNoRawPGError(t, client.simpleQuery(t, "SET search_path TO "+primarySchema))

	executeFrames := client.sendSync(t, &pgproto3.Execute{Portal: "p_drift"})
	if len(executeFrames) != 3 {
		t.Fatalf("Execute frames = %d, want DataRow + CommandComplete + ReadyForQuery", len(executeFrames))
	}
	row, ok := executeFrames[0].(*pgproto3.DataRow)
	if !ok || !reflect.DeepEqual(row.Values, [][]byte{[]byte("secret-2")}) {
		t.Fatalf("Execute frame[0] = %#v, want one DataRow value secret-2", executeFrames[0])
	}
	if _, ok := executeFrames[1].(*pgproto3.CommandComplete); !ok {
		t.Fatalf("Execute frame[1] = %T, want CommandComplete", executeFrames[1])
	}
	assertRawReadyForQuery(t, executeFrames, 'T')

	requests := h.fake.requests()
	wantSQL := []string{
		"SET search_path TO " + primarySchema,
		"BEGIN",
		victimSQL,
		"SET search_path TO " + secondarySchema,
		"SET search_path TO " + primarySchema,
		victimSQL,
	}
	wantPaths := [][]string{
		{"pg_catalog", "public"},
		{"pg_catalog", primarySchema},
		{"pg_catalog", primarySchema},
		{"pg_catalog", primarySchema},
		{"pg_catalog", secondarySchema},
		{"pg_catalog", secondarySchema},
	}
	if len(requests) != len(wantSQL) {
		t.Fatalf("Decide requests = %d, want %d", len(requests), len(wantSQL))
	}
	for i, request := range requests {
		if request.GetSql() != wantSQL[i] || !reflect.DeepEqual(request.GetSearchPath(), wantPaths[i]) {
			t.Fatalf("DecisionRequest[%d] = %+v, want SQL %q path %v", i, request, wantSQL[i], wantPaths[i])
		}
	}
	assertNoRawPGError(t, client.simpleQuery(t, "ROLLBACK"))
}

func TestExtendedPostBindSearchPathDriftCannotBypassPolicy(t *testing.T) {
	h := startBroker(t)
	const victimSQL = "SELECT ssn FROM people WHERE id = $1"
	h.fake.decideFn = func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if request.GetSql() == victimSQL {
			for _, schema := range request.GetSearchPath() {
				if schema == secondarySchema {
					return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "secondary schema forbidden"}), nil
				}
			}
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := newRawPGClient(t, h)

	assertNoRawPGError(t, client.simpleQuery(t, "SET search_path TO "+primarySchema))
	assertNoRawPGError(t, client.simpleQuery(t, "BEGIN"))
	assertRawExtendedCompletion(t, client.sendSync(t, &pgproto3.Parse{Name: "victim", Query: victimSQL}), "ParseComplete", 'T')
	assertNoRawPGError(t, client.simpleQuery(t, "SET search_path TO "+secondarySchema))
	assertRawExtendedCompletion(t, client.sendSync(t, &pgproto3.Bind{
		DestinationPortal: "p_drift",
		PreparedStatement: "victim",
		Parameters:        [][]byte{[]byte("10")},
	}), "BindComplete", 'T')
	assertNoRawPGError(t, client.simpleQuery(t, "SET search_path TO "+primarySchema))

	executeFrames := client.sendSync(t, &pgproto3.Execute{Portal: "p_drift"})
	if len(executeFrames) != 2 {
		t.Fatalf("Execute frames = %d, want ErrorResponse + ReadyForQuery", len(executeFrames))
	}
	denial, ok := executeFrames[0].(*pgproto3.ErrorResponse)
	if !ok || denial.Code != "42501" || !strings.Contains(denial.Message, "proxy-monster denied") {
		t.Fatalf("Execute frame[0] = %#v, want 42501 proxy-monster denied", executeFrames[0])
	}
	assertRawReadyForQuery(t, executeFrames, 'T')

	requests := h.fake.requests()
	if len(requests) == 0 {
		t.Fatal("Decide requests = 0, want Execute decision")
	}
	last := requests[len(requests)-1]
	if last.GetSql() != victimSQL || !reflect.DeepEqual(last.GetSearchPath(), []string{"pg_catalog", secondarySchema}) {
		t.Fatalf("last DecisionRequest = %+v, want victim SQL at [pg_catalog %s]", last, secondarySchema)
	}
	assertNoRawPGError(t, client.simpleQuery(t, "ROLLBACK"))
}

// TestExtendedRejectedRebindAbortsTransactionNoLeak pins the real PostgreSQL 16 semantics of re-Binding
// an already-bound named portal. PostgreSQL does NOT drop the prior portal on a rejected re-Bind; instead
// the erroring Bind aborts the whole transaction (verified against PG16: 42P03 "cursor already exists",
// then any following command returns 25P02, never 34000). Because every Bind error aborts the transaction,
// no subsequent Execute can ever return rows, so a stale boundPortal snapshot cannot leak data. With an
// ALLOW-all policy the proxy re-decides the Execute (a harmless audit decision) and relays the target DB's
// own 25P02 verbatim: zero DataRow frames reach the client. That transaction abort — not a 34000, which
// real PostgreSQL never returns here — is what makes a rejected re-Bind safe.
func TestExtendedRejectedRebindAbortsTransactionNoLeak(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := newRawPGClient(t, h)
	const victimSQL = "SELECT ssn FROM people WHERE id = $1"

	assertNoRawPGError(t, client.simpleQuery(t, "SET search_path TO "+primarySchema))
	assertNoRawPGError(t, client.simpleQuery(t, "BEGIN"))
	assertRawExtendedCompletion(t, client.sendSync(t, &pgproto3.Parse{Name: "victim", Query: victimSQL}), "ParseComplete", 'T')
	assertRawExtendedCompletion(t, client.sendSync(t, &pgproto3.Bind{
		DestinationPortal: "p",
		PreparedStatement: "victim",
		Parameters:        [][]byte{[]byte("1")},
	}), "BindComplete", 'T')

	// Re-Bind the same named portal. PostgreSQL rejects it (42P03) and aborts the transaction.
	rebindFrames := client.sendSync(t, &pgproto3.Bind{
		DestinationPortal: "p",
		PreparedStatement: "victim",
		Parameters:        [][]byte{[]byte("1")},
	})
	rebindErr, ok := rebindFrames[0].(*pgproto3.ErrorResponse)
	if !ok || rebindErr.Code != "42P03" {
		t.Fatalf("re-Bind frame[0] = %#v, want 42P03 cursor-already-exists", rebindFrames[0])
	}
	assertRawReadyForQuery(t, rebindFrames, 'E')

	// Execute the still-mapped portal. The target DB's aborted-transaction error (25P02) is relayed and no
	// row ever flows; the proxy never fabricates a 34000, matching real PostgreSQL.
	executeFrames := client.sendSync(t, &pgproto3.Execute{Portal: "p"})
	for _, frame := range executeFrames {
		if _, isRow := frame.(*pgproto3.DataRow); isRow {
			t.Fatalf("Execute after rejected re-Bind leaked a DataRow: %#v", executeFrames)
		}
	}
	execErr, ok := executeFrames[0].(*pgproto3.ErrorResponse)
	if !ok || execErr.Code != "25P02" {
		t.Fatalf("Execute frame[0] = %#v, want target DB 25P02 aborted-transaction error", executeFrames[0])
	}
	assertRawReadyForQuery(t, executeFrames, 'E')
	// The transaction stays aborted; recovery from 'E' via ROLLBACK is covered by
	// TestExtendedAbortedTransactionRecoversViaRollback (both the simple- and extended-protocol paths).
}

// TestExtendedAbortedTransactionRecoversViaRollback pins that a connection wedged in the aborted-transaction
// state ('E') recovers via ROLLBACK over BOTH protocols. Before the 'E'-state namespace-reuse guard, the
// injected namespace probe hit the target DB's 25P02 and the proxy refused ROLLBACK with 58000, leaving the
// only escape a disconnect — an availability regression on routine traffic (any error inside an explicit
// transaction), and a divergence from vanilla PostgreSQL, which accepts ROLLBACK in the aborted state.
func TestExtendedAbortedTransactionRecoversViaRollback(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	const victimSQL = "SELECT ssn FROM people WHERE id = $1"

	// abortInTx opens a transaction and aborts it with a rejected re-Bind (42P03), leaving TxStatus 'E'.
	abortInTx := func(t *testing.T, client *rawPGClient) {
		t.Helper()
		assertNoRawPGError(t, client.simpleQuery(t, "SET search_path TO "+primarySchema))
		assertNoRawPGError(t, client.simpleQuery(t, "BEGIN"))
		assertRawExtendedCompletion(t, client.sendSync(t, &pgproto3.Parse{Name: "victim", Query: victimSQL}), "ParseComplete", 'T')
		assertRawExtendedCompletion(t, client.sendSync(t, &pgproto3.Bind{
			DestinationPortal: "p", PreparedStatement: "victim", Parameters: [][]byte{[]byte("1")},
		}), "BindComplete", 'T')
		rebind := client.sendSync(t, &pgproto3.Bind{
			DestinationPortal: "p", PreparedStatement: "victim", Parameters: [][]byte{[]byte("1")},
		})
		assertRawReadyForQuery(t, rebind, 'E')
	}

	t.Run("simple-query ROLLBACK", func(t *testing.T) {
		client := newRawPGClient(t, h)
		abortInTx(t, client)
		rollback := client.simpleQuery(t, "ROLLBACK")
		assertNoRawPGError(t, rollback)
		assertRawReadyForQuery(t, rollback, 'I')
		// The recovered connection is fully reusable for a fresh extended statement.
		assertRawExtendedCompletion(t, client.sendSync(t, &pgproto3.Parse{Name: "after", Query: victimSQL}), "ParseComplete", 'I')
	})

	t.Run("extended-protocol ROLLBACK", func(t *testing.T) {
		client := newRawPGClient(t, h)
		abortInTx(t, client)
		// JDBC-style ROLLBACK: Parse/Bind/Execute. Every injected probe on this path (handleParse's namespace
		// probe and handleBind's probeBindContext) must reuse the overlay rather than hit the aborted target DB.
		rollback := client.sendSync(t,
			&pgproto3.Parse{Name: "rb", Query: "ROLLBACK"},
			&pgproto3.Bind{DestinationPortal: "rbp", PreparedStatement: "rb"},
			&pgproto3.Execute{Portal: "rbp"},
		)
		assertNoRawPGError(t, rollback)
		assertRawReadyForQuery(t, rollback, 'I')
	})
}

// TestExtendedBindCoercionSetConfigLeaksAcrossSchema is a CHARACTERIZATION test for a known, out-of-scope
// limitation (KNOWN_LIMITATIONS.md, backlog): a domain CHECK that calls set_config('search_path', …) moves
// the path DURING Bind parameter coercion — after the proxy's pre-Bind probe but before PostgreSQL resolves
// the portal's table names — so Execute is authorized under the stale probed snapshot while the target DB binds
// the portal under the mutated path. The bare `people` reads id=10, which exists ONLY in the secondary
// schema, so a real leak surfaces the secondary row ('secret-2') even though the policy DENIES the secondary
// path. The proxy tracks search_path by SQL classification and cannot observe a set_config fired from inside
// coercion, so this is out of scope. If this test ever STOPS leaking, the limitation was closed — update the docs.
func TestExtendedBindCoercionSetConfigLeaksAcrossSchema(t *testing.T) {
	h := startBroker(t)
	var decidedPaths [][]string
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		path := req.GetSearchPath()
		decidedPaths = append(decidedPaths, path)
		for _, schema := range path {
			if schema == secondarySchema {
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "secondary schema is denied"}), nil
			}
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}

	// Create the evil domain directly on the target DB (bypassing the proxy) and look up its OID so Parse can
	// declare $1 as that domain — forcing PostgreSQL to run its CHECK during Bind parameter coercion.
	admin := dbtest.OpenPostgres(t, "")
	for _, stmt := range []string{
		"DROP DOMAIN IF EXISTS " + primarySchema + ".side_domain CASCADE",
		"CREATE DOMAIN " + primarySchema + ".side_domain AS text CHECK (set_config('search_path', VALUE, false) IS NOT NULL)",
	} {
		if _, err := admin.Exec(stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP DOMAIN IF EXISTS " + primarySchema + ".side_domain CASCADE") })
	var domainOID uint32
	if err := admin.QueryRow("SELECT oid FROM pg_type WHERE typname = 'side_domain'").Scan(&domainOID); err != nil {
		t.Fatalf("look up side_domain OID: %v", err)
	}

	client := newRawPGClient(t, h)
	assertNoRawPGError(t, client.simpleQuery(t, "SET search_path TO "+primarySchema))

	const victimSQL = "SELECT ssn FROM people WHERE id = 10 AND $1 IS NOT NULL"
	frames := client.sendSync(t,
		&pgproto3.Parse{Name: "v", Query: victimSQL, ParameterOIDs: []uint32{domainOID}},
		&pgproto3.Bind{DestinationPortal: "vp", PreparedStatement: "v", Parameters: [][]byte{[]byte(secondarySchema)}},
		&pgproto3.Execute{Portal: "vp"},
	)

	leaked := false
	for _, f := range frames {
		switch m := f.(type) {
		case *pgproto3.DataRow:
			for _, v := range m.Values {
				if v != nil && string(v) == "secret-2" {
					leaked = true
				}
			}
			t.Logf("DataRow: %q", m.Values)
		case *pgproto3.ErrorResponse:
			t.Logf("ErrorResponse: %s (%s)", m.Message, m.Code)
		default:
			t.Logf("frame: %T", f)
		}
	}
	t.Logf("decision search_paths seen: %v", decidedPaths)
	t.Logf("LEAKED (secondary secret disclosed under a primary-authorized decision): %v", leaked)
	if !leaked {
		t.Fatalf("expected the documented Bind-coercion set_config leak to reproduce (secondary row 'secret-2'); it did not — the leak may no longer reproduce, so revisit KNOWN_LIMITATIONS.md")
	}
	// The leak is only meaningful if the proxy authorized under the STALE primary path (not the secondary
	// one the target DB actually bound). Assert no decision was ever made under the secondary schema.
	for _, path := range decidedPaths {
		for _, schema := range path {
			if schema == secondarySchema {
				t.Fatalf("a decision was made under the secondary path %v — not the stale-snapshot leak this test documents", path)
			}
		}
	}
}

func assertNoRawPGError(t *testing.T, frames []pgproto3.BackendMessage) {
	t.Helper()
	for _, frame := range frames {
		if response, ok := frame.(*pgproto3.ErrorResponse); ok {
			t.Fatalf("raw PostgreSQL error = %s (%s)", response.Message, response.Code)
		}
	}
}

func assertRawExtendedCompletion(t *testing.T, frames []pgproto3.BackendMessage, want string, txStatus byte) {
	t.Helper()
	assertNoRawPGError(t, frames)
	if len(frames) != 2 {
		t.Fatalf("raw extended frames = %d, want %s + ReadyForQuery", len(frames), want)
	}
	complete := false
	switch want {
	case "ParseComplete":
		_, complete = frames[0].(*pgproto3.ParseComplete)
	case "BindComplete":
		_, complete = frames[0].(*pgproto3.BindComplete)
	default:
		t.Fatalf("unknown completion type %q", want)
	}
	if !complete {
		t.Fatalf("raw extended frame[0] = %T, want %s", frames[0], want)
	}
	assertRawReadyForQuery(t, frames, txStatus)
}

func assertRawReadyForQuery(t *testing.T, frames []pgproto3.BackendMessage, txStatus byte) {
	t.Helper()
	if len(frames) == 0 {
		t.Fatal("raw PostgreSQL response is empty")
	}
	ready, ok := frames[len(frames)-1].(*pgproto3.ReadyForQuery)
	if !ok || ready.TxStatus != txStatus {
		t.Fatalf("last raw PostgreSQL frame = %#v, want ReadyForQuery(%q)", frames[len(frames)-1], txStatus)
	}
}

func TestExtendedGucGuardOnExtendedPath(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err = conn.Exec(context.Background(), "SET client_encoding TO 'LATIN1'", pgx.QueryExecModeExec)
	assertPgError(t, err, "0A000", "client_encoding must remain UTF8")
}

func TestExtendedTargetDbRejectedParseLeavesNoStaleStatement(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.Prepare(ctx, "stmt_rejected", "SELECT missing_column FROM "+primarySchema+".people WHERE id = $1"); err == nil {
		t.Fatal("invalid Prepare succeeded")
	} else {
		assertPgError(t, err, "42703", "does not exist")
	}
	const validQuery = "SELECT name FROM it_pgproxy.people WHERE id = $1"
	if _, err := conn.Prepare(ctx, "stmt_rejected", validQuery); err != nil {
		t.Fatalf("valid re-Prepare same name: %v", err)
	}
	var name string
	if err := conn.QueryRow(ctx, "stmt_rejected", 1).Scan(&name); err != nil {
		t.Fatalf("execute valid replacement: %v", err)
	}
	if name != "Alice" {
		t.Fatalf("name = %q, want Alice", name)
	}
}

func TestExtendedRepeatedExecuteRedecides(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	const query = "SELECT name FROM it_pgproxy.people WHERE id = $1"
	if _, err := conn.Prepare(ctx, "stmt_repeat", query); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for _, id := range []int{1, 2} {
		var name string
		if err := conn.QueryRow(ctx, "stmt_repeat", id).Scan(&name); err != nil {
			t.Fatalf("QueryRow(%d): %v", id, err)
		}
	}
	if got := len(h.fake.requests()); got != 3 {
		t.Fatalf("Decide requests = %d, want 3 (Parse + two Executes)", got)
	}
}

func assertExtendedMaskError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want unbindable-mask failure")
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code != "0A000" || !strings.Contains(pgErr.Message, "required mask could not be bound") {
			t.Fatalf("PgError = code %q message %q, want 0A000 unbindable-mask error", pgErr.Code, pgErr.Message)
		}
		return
	}
	if !strings.Contains(err.Error(), "required mask could not be bound") && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("error = %T %v, want unbindable-mask or broken-connection error", err, err)
	}
}
