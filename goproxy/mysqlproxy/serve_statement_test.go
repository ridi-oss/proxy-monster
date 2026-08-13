package mysqlproxy

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/db"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

type runTestDecider struct{}

func (runTestDecider) Decide(engine.DecideRequest) engine.DecisionOutcome {
	return engine.DecisionOutcome{Decision: &engine.Decision{Action: "ALLOW"}}
}

func scriptedMySQLRun(t *testing.T, maxRows int, response []byte) (*RunSession, <-chan string) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	qe := engine.NewQueryEngine(db.MySqlDb{}, runTestDecider{})
	qe.SetNamespace([]string{"test"})
	s := &RunSession{conn: client, qe: qe, ref: &engine.Refetcher{}}
	writes := make(chan string, 3)
	go func() {
		defer close(writes)
		if maxRows > 0 {
			_, payload, err := mysqlwire.ReadPacket(server)
			if err != nil {
				return
			}
			writes <- string(payload[1:])
			_ = mysqlwire.WritePacket(server, 1, mysqlwire.OKPacket())
		}
		_, payload, err := mysqlwire.ReadPacket(server)
		if err != nil {
			return
		}
		writes <- string(payload[1:])
		_, _ = server.Write(response)
		if maxRows > 0 {
			_, payload, err = mysqlwire.ReadPacket(server)
			if err != nil {
				return
			}
			writes <- string(payload[1:])
			_ = mysqlwire.WritePacket(server, 1, mysqlwire.OKPacket())
		}
	}()
	return s, writes
}

func runMySQLStatement(t *testing.T, maxRows int, response []byte) (engine.StatementResult, error, []string) {
	t.Helper()
	s, writes := scriptedMySQLRun(t, maxRows, response)
	result, err := s.ServeStatement("SELECT 1", maxRows)
	var got []string
	for write := range writes {
		got = append(got, write)
	}
	return result, err, got
}

func mysqlPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = mysqlwire.WritePacket(server, 1, payload)
		_ = server.Close()
	}()
	buf := make([]byte, 4+len(payload))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

func TestRunStatementMySQLBracketOrder(t *testing.T) {
	_, err, writes := runMySQLStatement(t, 2, mysqlPacket(t, mysqlwire.OKPacket()))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"SET SQL_SELECT_LIMIT = 3", "SELECT 1", "SET SQL_SELECT_LIMIT = DEFAULT"}
	if strings.Join(writes, "|") != strings.Join(want, "|") {
		t.Fatalf("writes = %v, want %v", writes, want)
	}
}

func TestRunStatementMySQLUncappedHasNoBracket(t *testing.T) {
	_, err, writes := runMySQLStatement(t, 0, mysqlPacket(t, mysqlwire.OKPacket()))
	if err != nil {
		t.Fatal(err)
	}
	if len(writes) != 1 || writes[0] != "SELECT 1" {
		t.Fatalf("writes = %v, want user query only", writes)
	}
}

func TestRunStatementMySQLResetsAfterTargetDbError(t *testing.T) {
	response := mysqlPacket(t, mysqlwire.ErrPacketState(1146, "42S02", "missing"))
	_, err, writes := runMySQLStatement(t, 2, response)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("err = %v, want target-DB error", err)
	}
	if len(writes) != 3 || writes[2] != "SET SQL_SELECT_LIMIT = DEFAULT" {
		t.Fatalf("writes = %v, want reset after ERR", writes)
	}
}

func TestTextResultCollectorRejectsMalformedRowWidth(t *testing.T) {
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collect := textResultCollector{maxRows: 1, result: &result}
	if err := collect.onColumns(2); err != nil {
		t.Fatal(err)
	}
	payload := mysqlwire.TextRowPayload([]*string{ptrMySQL("only-one")})
	if _, err := collect.onRow(payload); err == nil {
		t.Fatal("malformed row width was accepted")
	}
}

func ptrMySQL(value string) *string { return &value }

func TestTextResultCollectorMaskUnboundBeforeRows(t *testing.T) {
	ordinal := int32(3)
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collect := textResultCollector{maxRows: 1, result: &result, masks: []*pb.ColumnMask{{Ordinal: &ordinal}}}
	err := collect.onColumns(1)
	if !errors.Is(err, engine.ErrMaskUnbound) || len(result.Rows) != 0 {
		t.Fatalf("err=%v rows=%v, want unbound before rows", err, result.Rows)
	}
}
