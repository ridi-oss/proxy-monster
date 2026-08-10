package pgproxy

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func ptr(s string) *string { return &s }

// encodePG serializes target-DB frames into the wire bytes a scripted target DB would send.
func encodePG(t *testing.T, msgs ...pgproto3.BackendMessage) []byte {
	t.Helper()
	var buf []byte
	for _, m := range msgs {
		var err error
		buf, err = m.Encode(buf)
		if err != nil {
			t.Fatalf("encode %T: %v", m, err)
		}
	}
	return buf
}

// scriptedRunSession returns an RunSession wired to a scripted target DB that, for each Execute call,
// consumes the client's Query and replies with the next response in order. Driving several statements over
// one persistent session lets a test pin the persistent-session contracts (drain-through-ReadyForQuery so
// the connection is reusable without statement/result skew; error-to-poison). Each response should end at
// the frame on which that Execute is expected to return, so the pipe write drains cleanly.
func (s *RunSession) execute(sql string, maxRows int) ([]string, [][]*string, int, error) {
	if s.poisoned {
		return nil, nil, 0, errors.New("run session is unusable after a prior protocol error")
	}
	executeMax, err := executeMaxRows(maxRows)
	if err != nil {
		return nil, nil, 0, err
	}
	s.targetDb.Send(&pgproto3.Parse{Name: "", Query: sql})
	s.targetDb.Send(&pgproto3.Bind{DestinationPortal: "", PreparedStatement: ""})
	s.targetDb.Send(&pgproto3.Describe{ObjectType: 'P', Name: ""})
	s.targetDb.Send(&pgproto3.Execute{Portal: "", MaxRows: executeMax})
	s.targetDb.Send(&pgproto3.Close{ObjectType: 'P', Name: ""})
	s.targetDb.Send(&pgproto3.Sync{})
	if err := s.targetDb.Flush(); err != nil {
		return nil, nil, 0, err
	}
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collector := rowsCollector{maxRows: maxRows, result: &result}
	targetDbErr, streamErr := s.streamResult(nil, streamOpts{extended: true}, collector.emit)
	err = firstErr(targetDbErr, streamErr, collector.failed)
	if streamErr != nil || collector.failed != nil {
		s.poisoned = true
	}
	return result.Columns, result.Rows, result.RowsAffected, err
}

func scriptedRunSession(t *testing.T, responses ...[]byte) (*RunSession, <-chan []pgproto3.FrontendMessage) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))

	be := &RunSession{conn: client, sessionCore: sessionCore{targetDb: pgproto3.NewFrontend(client, client)}}
	requests := make(chan []pgproto3.FrontendMessage, len(responses))
	go func() {
		defer close(requests)
		targetDb := pgproto3.NewBackend(server, server)
		for _, response := range responses {
			messages := make([]pgproto3.FrontendMessage, 0, 6)
			for range 6 {
				message, err := targetDb.Receive()
				if err != nil {
					return
				}
				messages = append(messages, message)
			}
			requests <- messages
			if _, err := server.Write(response); err != nil {
				return
			}
		}
	}()
	return be, requests
}

// runSessionExecute drives one RunSession.Execute against a scripted single-statement response.
func runSessionExecute(t *testing.T, sql string, maxRows int, response []byte) ([]string, [][]*string, int, error) {
	t.Helper()
	session, _ := scriptedRunSession(t, response)
	return session.execute(sql, maxRows)
}

func rowDesc(names ...string) *pgproto3.RowDescription {
	fields := make([]pgproto3.FieldDescription, len(names))
	for i, n := range names {
		fields[i] = pgproto3.FieldDescription{Name: []byte(n)}
	}
	return &pgproto3.RowDescription{Fields: fields}
}

func dataRow(values ...[]byte) *pgproto3.DataRow { return &pgproto3.DataRow{Values: values} }

func assertRows(t *testing.T, got, want [][]*string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("row count = %d, want %d (%v)", len(got), len(want), got)
	}
	for r := range want {
		if len(got[r]) != len(want[r]) {
			t.Fatalf("row %d width = %d, want %d", r, len(got[r]), len(want[r]))
		}
		for c := range want[r] {
			switch {
			case want[r][c] == nil && got[r][c] == nil:
			case want[r][c] == nil || got[r][c] == nil:
				t.Fatalf("row %d col %d = %v, want %v (NULL mismatch)", r, c, got[r][c], want[r][c])
			case *got[r][c] != *want[r][c]:
				t.Fatalf("row %d col %d = %q, want %q", r, c, *got[r][c], *want[r][c])
			}
		}
	}
}

func scriptedStreamCore(t *testing.T, responses ...[]byte) (*sessionCore, func()) {
	t.Helper()
	client, server := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	go func() {
		for _, response := range responses {
			if _, err := server.Write(response); err != nil {
				return
			}
		}
	}()
	return &sessionCore{targetDb: pgproto3.NewFrontend(client, client)}, func() { _ = client.Close(); _ = server.Close() }
}

func TestStreamResultSimpleRejectsExtendedAck(t *testing.T) {
	core, closeCore := scriptedStreamCore(t, encodePG(t, &pgproto3.ParseComplete{}))
	defer closeCore()
	_, err := core.streamResult(nil, streamOpts{}, nil)
	if !errors.Is(err, errUnexpectedFrame) {
		t.Fatalf("err = %v, want unexpected-frame rejection", err)
	}
}

func TestStreamResultMaskUnboundEmitsNoDataRow(t *testing.T) {
	core, closeCore := scriptedStreamCore(t, encodePG(t, rowDesc("secret"), dataRow([]byte("cleartext"))))
	defer closeCore()
	ordinal := int32(99)
	dataRows := 0
	_, err := core.streamResult([]*pb.ColumnMask{{Ordinal: &ordinal}}, streamOpts{}, func(message pgproto3.BackendMessage) error {
		if _, ok := message.(*pgproto3.DataRow); ok {
			dataRows++
		}
		return nil
	})
	if !errors.Is(err, engine.ErrMaskUnbound) || dataRows != 0 {
		t.Fatalf("err = %v dataRows = %d, want mask-unbound before any DataRow", err, dataRows)
	}
}

func TestSoftProbeWidthMismatchDrainsForNextStatement(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	core := &sessionCore{targetDb: pgproto3.NewFrontend(client, client)}
	go func() {
		targetDb := pgproto3.NewBackend(server, server)
		for _, response := range [][]byte{
			encodePG(t, rowDesc("a", "b"), dataRow([]byte("one")), &pgproto3.ReadyForQuery{TxStatus: 'I'}),
			encodePG(t, rowDesc("ok"), dataRow([]byte("next")), &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'}),
		} {
			if _, err := targetDb.Receive(); err != nil {
				return
			}
			if _, err := server.Write(response); err != nil {
				return
			}
		}
	}()
	if _, err := core.runProbe("first", 2, true); err == nil || !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("first err = %v, want width mismatch", err)
	}
	rows, err := core.runProbe("second", 1, true)
	if err != nil {
		t.Fatalf("second probe: %v", err)
	}
	assertRows(t, rows, [][]*string{{ptr("next")}})
}

func TestRunStatementPGExecuteCap(t *testing.T) {
	response := encodePG(t, &pgproto3.PortalSuspended{}, &pgproto3.CloseComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	session, requests := scriptedRunSession(t, response)
	if _, _, _, err := session.execute("SELECT 1", 2); err != nil {
		t.Fatal(err)
	}
	messages := <-requests
	execute, ok := messages[3].(*pgproto3.Execute)
	if !ok || execute.MaxRows != 3 {
		t.Fatalf("execute = %#v, want MaxRows=3", messages[3])
	}
	closePortal, ok := messages[4].(*pgproto3.Close)
	if !ok || closePortal.ObjectType != 'P' {
		t.Fatalf("close = %#v, want portal close", messages[4])
	}
}

func TestRunStatementPGUncappedExecute(t *testing.T) {
	response := encodePG(t, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 0")}, &pgproto3.CloseComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	session, requests := scriptedRunSession(t, response)
	if _, _, _, err := session.execute("SELECT 1", 0); err != nil {
		t.Fatal(err)
	}
	if execute := (<-requests)[3].(*pgproto3.Execute); execute.MaxRows != 0 {
		t.Fatalf("MaxRows = %d, want 0", execute.MaxRows)
	}
}

func TestRunSessionExecutePGMultiRowSelect(t *testing.T) {
	response := encodePG(t,
		rowDesc("id", "name"),
		dataRow([]byte("1"), []byte("alice")),
		dataRow([]byte("2"), nil),
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	cols, rows, ra, err := runSessionExecute(t, "SELECT id, name FROM t", 0, response)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Join(cols, ",") != "id,name" {
		t.Fatalf("columns = %v, want [id name]", cols)
	}
	assertRows(t, rows, [][]*string{{ptr("1"), ptr("alice")}, {ptr("2"), nil}})
	if ra != -1 {
		t.Fatalf("rowsAffected = %d, want -1 for a result set", ra)
	}
}

func TestRunSessionExecutePGMaxRowsCap(t *testing.T) {
	response := encodePG(t,
		rowDesc("n"),
		dataRow([]byte("1")),
		dataRow([]byte("2")),
		dataRow([]byte("3")),
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 3")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	_, rows, _, err := runSessionExecute(t, "SELECT n FROM t", 2, response)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assertRows(t, rows, [][]*string{{ptr("1")}, {ptr("2")}})
}

func TestRunSessionExecutePGNullVersusEmpty(t *testing.T) {
	response := encodePG(t,
		rowDesc("a", "b"),
		dataRow(nil, []byte("")),
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	_, rows, _, err := runSessionExecute(t, "SELECT a, b FROM t", 0, response)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assertRows(t, rows, [][]*string{{nil, ptr("")}})
}

func TestRunSessionExecutePGRowsAffectedOnWrite(t *testing.T) {
	response := encodePG(t,
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 5")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	cols, rows, ra, err := runSessionExecute(t, "INSERT INTO t VALUES (...)", 0, response)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(cols) != 0 || len(rows) != 0 {
		t.Fatalf("write returned %d cols, %d rows, want 0/0", len(cols), len(rows))
	}
	if ra != 5 {
		t.Fatalf("rowsAffected = %d, want 5", ra)
	}
}

func TestRunSessionExecutePGTargetDbError(t *testing.T) {
	response := encodePG(t,
		&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42P01", Message: "relation \"nope\" does not exist"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	_, _, _, err := runSessionExecute(t, "SELECT * FROM nope", 0, response)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v, want target-DB error surfaced", err)
	}
}

func TestRunSessionExecutePGRejectsCopy(t *testing.T) {
	response := encodePG(t, &pgproto3.CopyOutResponse{})
	_, _, _, err := runSessionExecute(t, "COPY t TO STDOUT", 0, response)
	if err == nil || !strings.Contains(err.Error(), "COPY") {
		t.Fatalf("err = %v, want COPY rejection", err)
	}
}

func TestRunSessionExecutePGGuardsClientEncoding(t *testing.T) {
	response := encodePG(t, &pgproto3.ParameterStatus{Name: "client_encoding", Value: "LATIN1"})
	_, _, _, err := runSessionExecute(t, "SET client_encoding = 'LATIN1'", 0, response)
	if err == nil || !strings.Contains(err.Error(), "UTF8") {
		t.Fatalf("err = %v, want client_encoding guard", err)
	}
}

func TestRunSessionExecutePGGuardsStandardConformingStrings(t *testing.T) {
	response := encodePG(t, &pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "off"})
	_, _, _, err := runSessionExecute(t, "SET standard_conforming_strings = off", 0, response)
	if err == nil || !strings.Contains(err.Error(), "standard_conforming_strings") {
		t.Fatalf("err = %v, want standard_conforming_strings guard", err)
	}
}

func TestRunSessionExecutePGAllowsUTF8ParameterStatus(t *testing.T) {
	response := encodePG(t,
		&pgproto3.ParameterStatus{Name: "client_encoding", Value: "utf8"}, // case-insensitive
		rowDesc("n"),
		dataRow([]byte("1")),
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	_, rows, _, err := runSessionExecute(t, "SELECT 1", 0, response)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assertRows(t, rows, [][]*string{{ptr("1")}})
}

func TestRunSessionExecutePGRejectsUnexpectedFrame(t *testing.T) {
	response := encodePG(t, &pgproto3.BackendKeyData{ProcessID: 1, SecretKey: 2})
	_, _, _, err := runSessionExecute(t, "SELECT 1", 0, response)
	if err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("err = %v, want unexpected-frame rejection", err)
	}
}

func TestRunSessionExecutePGPoisonedSessionFailsClosed(t *testing.T) {
	be := &RunSession{poisoned: true}
	_, _, _, err := be.execute("SELECT 1", 0)
	if err == nil || !strings.Contains(err.Error(), "unusable") {
		t.Fatalf("err = %v, want poisoned-session rejection", err)
	}
}

func TestRunSessionExecutePGRejectsColumnCountMismatch(t *testing.T) {
	response := encodePG(t,
		rowDesc("a", "b"),
		dataRow([]byte("only-one-value")), // 1 value for a 2-column result
	)
	_, _, _, err := runSessionExecute(t, "SELECT a, b FROM t", 0, response)
	if err == nil || !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("err = %v, want column-count mismatch", err)
	}
}

// A capped first statement must still drain through ReadyForQuery so the persistent session is reusable:
// the second statement must see only its OWN columns and rows, never leftover frames from the first.
func TestRunSessionExecutePGSequentialQueriesDoNotSkew(t *testing.T) {
	first := encodePG(t,
		rowDesc("n"),
		dataRow([]byte("1")), dataRow([]byte("2")), dataRow([]byte("3")),
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 3")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	second := encodePG(t,
		rowDesc("label"),
		dataRow([]byte("second")),
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	be, _ := scriptedRunSession(t, first, second)

	if _, rows, _, err := be.execute("SELECT n FROM t", 2); err != nil || len(rows) != 2 {
		t.Fatalf("first Execute: rows=%d err=%v (want 2 rows, no error)", len(rows), err)
	}
	cols, rows, _, err := be.execute("SELECT label FROM u", 0)
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if strings.Join(cols, ",") != "label" {
		t.Fatalf("second columns = %v, want [label] (statement/result skew)", cols)
	}
	assertRows(t, rows, [][]*string{{ptr("second")}})
}

// A protocol error must poison the session: the NEXT Execute fails closed with "unusable" without writing a
// second Query to the target DB (so a swallowed best-effort probe error cannot let a later statement read the
// failed statement's stale frames).
func TestRunSessionExecutePGErrorPoisonsSession(t *testing.T) {
	malformed := encodePG(t, &pgproto3.BackendKeyData{ProcessID: 1, SecretKey: 2})
	be, _ := scriptedRunSession(t, malformed) // only the first statement is ever served

	if _, _, _, err := be.execute("SELECT 1", 0); err == nil {
		t.Fatal("first Execute should fail on a malformed frame")
	}
	_, _, _, err := be.execute("SELECT 2", 0)
	if err == nil || !strings.Contains(err.Error(), "unusable") {
		t.Fatalf("second Execute err = %v, want poisoned-session rejection", err)
	}
}
