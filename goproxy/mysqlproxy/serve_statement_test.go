package mysqlproxy

import (
	"encoding/binary"
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

func TestTextResultCollectorDisplaysBinaryValuesAsHex(t *testing.T) {
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collect := textResultCollector{maxRows: 1, result: &result}
	if err := collect.onColumns(2); err != nil {
		t.Fatal(err)
	}
	if err := collect.onColumnDef(mysqlColumnDef("uuid", mysqlwire.CharsetBinary, mysqlwire.ColumnTypeString)); err != nil {
		t.Fatal(err)
	}
	if err := collect.onColumnDef(mysqlColumnDef("name", 45, mysqlwire.ColumnTypeVarString)); err != nil {
		t.Fatal(err)
	}
	raw := string([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef})
	if _, err := collect.onRow(mysqlwire.TextRowPayload([]*string{&raw, ptrMySQL("Alice")})); err != nil {
		t.Fatal(err)
	}
	got := derefMySQL(result.Rows[0][0])
	if got != "0x1234567890abcdef1234567890abcdef" {
		t.Fatalf("binary value = %q, want visible hex", got)
	}
	if got := derefMySQL(result.Rows[0][1]); got != "Alice" {
		t.Fatalf("text value = %q, want Alice", got)
	}
}

func TestTextResultCollectorHexesBitAndGeometry(t *testing.T) {
	// BIT (0x10) and GEOMETRY (0xff) carry a binary charset; their bytes must always render as hex like every
	// other binary column, even when a value happens to be valid UTF-8 (e.g. BIT(1) = 0x01) — otherwise it
	// would reach the UI as an invisible control character.
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collect := textResultCollector{maxRows: 1, result: &result}
	if err := collect.onColumns(2); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []byte{0x10, 0xff} {
		if err := collect.onColumnDef(mysqlColumnDef("c", mysqlwire.CharsetBinary, typ)); err != nil {
			t.Fatal(err)
		}
	}
	bit := string([]byte{0x01})                                      // BIT(1) = b'1' — valid UTF-8, still binary
	geom := string([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00}) // WKB-ish, all valid UTF-8
	if _, err := collect.onRow(mysqlwire.TextRowPayload([]*string{&bit, &geom})); err != nil {
		t.Fatal(err)
	}
	if got := derefMySQL(result.Rows[0][0]); got != "0x01" {
		t.Fatalf("BIT value = %q, want 0x01", got)
	}
	if got := derefMySQL(result.Rows[0][1]); got != "0x00000000010100" {
		t.Fatalf("GEOMETRY value = %q, want hex", got)
	}
}

func TestTextResultCollectorHexesNonUTF8Fallback(t *testing.T) {
	// A cell whose bytes are not valid UTF-8 must be hexed even when its column is not classified binary, so
	// an unnamed or future binary type cannot revive the proto3-string marshal failure.
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collect := textResultCollector{maxRows: 1, result: &result}
	if err := collect.onColumns(1); err != nil {
		t.Fatal(err)
	}
	// charset 45 (utf8mb4) is not binary, so only the invalid-UTF-8 fallback can hex this value.
	if err := collect.onColumnDef(mysqlColumnDef("c", 45, mysqlwire.ColumnTypeVarString)); err != nil {
		t.Fatal(err)
	}
	raw := string([]byte{0xff, 0xfe})
	if _, err := collect.onRow(mysqlwire.TextRowPayload([]*string{&raw})); err != nil {
		t.Fatal(err)
	}
	if got := derefMySQL(result.Rows[0][0]); got != "0xfffe" {
		t.Fatalf("non-utf8 value = %q, want 0xfffe", got)
	}
}

func TestTextResultCollectorLeavesMaskedBinaryValuesMasked(t *testing.T) {
	ordinal := int32(0)
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collect := textResultCollector{
		maxRows: 1,
		result:  &result,
		masks:   []*pb.ColumnMask{{Kind: "FIXED", Ordinal: &ordinal}},
	}
	if err := collect.onColumns(1); err != nil {
		t.Fatal(err)
	}
	if err := collect.onColumnDef(mysqlColumnDef("uuid", mysqlwire.CharsetBinary, mysqlwire.ColumnTypeString)); err != nil {
		t.Fatal(err)
	}
	raw := string([]byte{0x12, 0x34, 0x56, 0x78})
	if _, err := collect.onRow(mysqlwire.TextRowPayload([]*string{&raw})); err != nil {
		t.Fatal(err)
	}
	if got := derefMySQL(result.Rows[0][0]); got != "####" {
		t.Fatalf("masked binary value = %q, want mask", got)
	}
}

func ptrMySQL(value string) *string { return &value }

func derefMySQL(value *string) string {
	if value == nil {
		return "<nil>"
	}
	return *value
}

func mysqlColumnDef(name string, charset uint16, typ byte) []byte {
	var payload []byte
	for _, value := range []string{"def", "app", "people", "people", name, name} {
		payload = mysqlwire.AppendLenencStr(payload, value)
	}
	payload = mysqlwire.AppendLenenc(payload, 0x0c)
	payload = binary.LittleEndian.AppendUint16(payload, charset)
	payload = binary.LittleEndian.AppendUint32(payload, 16)
	payload = append(payload, typ)
	payload = binary.LittleEndian.AppendUint16(payload, 0)
	payload = append(payload, 0, 0, 0)
	return payload
}

func TestTextResultCollectorMaskUnboundBeforeRows(t *testing.T) {
	ordinal := int32(3)
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collect := textResultCollector{maxRows: 1, result: &result, masks: []*pb.ColumnMask{{Ordinal: &ordinal}}}
	err := collect.onColumns(1)
	if !errors.Is(err, engine.ErrMaskUnbound) || len(result.Rows) != 0 {
		t.Fatalf("err=%v rows=%v, want unbound before rows", err, result.Rows)
	}
}
