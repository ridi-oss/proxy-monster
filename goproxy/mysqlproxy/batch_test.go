package mysqlproxy_test

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const batchTable = "batch_rows"

func (h *brokerHarness) openMultiStatementConn(t *testing.T) *sql.Conn {
	t.Helper()
	dsn := fmt.Sprintf("pm:%s@tcp(%s)/?allowCleartextPasswords=true&interpolateParams=false&multiStatements=true", validToken, h.addr)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func startMySQLBatchBroker(t *testing.T) (*brokerHarness, *sql.Conn) {
	t.Helper()
	h := startBroker(t)
	conn := h.openMultiStatementConn(t)
	if _, err := conn.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+batchTable); err != nil {
		t.Fatalf("drop: %v", err)
	}
	h.fake.mu.Lock()
	h.fake.decideReqs = nil
	h.fake.mu.Unlock()
	return h, conn
}

func mysqlDecidedSQL(h *brokerHarness) []string {
	var out []string
	for _, req := range h.fake.requests() {
		out = append(out, req.GetSql())
	}
	return out
}

func readResultSets(t *testing.T, rows *sql.Rows) [][]string {
	t.Helper()
	var sets [][]string
	for {
		var set []string
		for rows.Next() {
			var value sql.NullString
			if err := rows.Scan(&value); err != nil {
				t.Fatalf("scan: %v", err)
			}
			set = append(set, value.String)
		}
		sets = append(sets, set)
		if !rows.NextResultSet() {
			break
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return sets
}

func TestMySQLBatchDecidesEachStatementAgainstItsPredecessors(t *testing.T) {
	h, conn := startMySQLBatchBroker(t)
	statements := []string{
		"CREATE TABLE " + batchTable + " (id INT)",
		"INSERT INTO " + batchTable + " VALUES (1), (2)",
		"SELECT COUNT(*) FROM " + batchTable,
	}
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.HasPrefix(req.GetSql(), "CREATE") {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, AfterStatement: []*pb.ProxyCommand{refetchCommand(primarySchema, nil)}}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	rows, err := conn.QueryContext(context.Background(), strings.Join(statements, ";\n"))
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	defer rows.Close()
	sets := readResultSets(t, rows)
	if last := sets[len(sets)-1]; !reflect.DeepEqual(last, []string{"2"}) {
		t.Fatalf("result sets = %v, want the count 2 last", sets)
	}
	if got := mysqlDecidedSQL(h); !reflect.DeepEqual(got, statements) {
		t.Fatalf("decided = %q, want each statement once, in order", got)
	}
	events := strings.Join(h.fake.eventLog(), "|")
	if !strings.Contains(events, "decide:"+statements[0]+"|push:"+primarySchema+"|decide:"+statements[1]) {
		t.Fatalf("events = %s: the INSERT must be decided after the CREATE's catalog push", events)
	}
}

func TestMySQLBatchMasksEachStatementByItsOwnDecision(t *testing.T) {
	h, conn := startMySQLBatchBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Contains(req.GetSql(), "ssn") {
			return wireVerdict(&pb.Verdict{
				Decision: pb.EnfAction_MASK,
				Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(0)}},
			}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	rows, err := conn.QueryContext(context.Background(), "SELECT name FROM people WHERE id = 1; SELECT ssn FROM people WHERE id = 1")
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	defer rows.Close()
	if sets := readResultSets(t, rows); !reflect.DeepEqual(sets, [][]string{{"Alice"}, {"####"}}) {
		t.Fatalf("result sets = %v, want Alice unmasked and ssn masked", sets)
	}
}

func TestMySQLBatchStopsAtADenyKeepingWhatRan(t *testing.T) {
	h, conn := startMySQLBatchBroker(t)
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, "CREATE TABLE "+batchTable+" (id INT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Contains(req.GetSql(), "ssn") {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	before := len(mysqlDecidedSQL(h))
	_, err := conn.ExecContext(ctx, "INSERT INTO "+batchTable+" VALUES (1); SELECT ssn FROM people; INSERT INTO "+batchTable+" VALUES (2)")
	if err == nil || !strings.Contains(err.Error(), "Error 1142") {
		t.Fatalf("batch error = %v, want the 1142 deny", err)
	}
	if got := len(mysqlDecidedSQL(h)) - before; got != 2 {
		t.Fatalf("decided %d statements, want 2: nothing after the deny", got)
	}
	var ids []int
	rows, err := conn.QueryContext(ctx, "SELECT id FROM "+batchTable)
	if err != nil {
		t.Fatalf("connection unusable after a denied batch: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	if !reflect.DeepEqual(ids, []int{1}) {
		t.Fatalf("ids = %v, want [1]: MySQL keeps the statements before the failure", ids)
	}
}

func TestMySQLBatchWithoutMultiStatementsIsOneStatement(t *testing.T) {
	h := startBroker(t)
	conn := h.openDB(t, validToken)
	if _, err := conn.Exec("SELECT 1; SELECT 2"); err == nil {
		t.Fatal("a batch from a client that did not enable multi-statements ran")
	}
	if got := mysqlDecidedSQL(h); len(got) != 1 || got[0] != "SELECT 1; SELECT 2" {
		t.Fatalf("decided = %q, want the whole text once", got)
	}
}

func TestMySQLBatchStopsAtATargetErrorKeepingWhatRan(t *testing.T) {
	h, conn := startMySQLBatchBroker(t)
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, "CREATE TABLE "+batchTable+" (id INT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	before := len(mysqlDecidedSQL(h))
	_, err := conn.ExecContext(ctx, "INSERT INTO "+batchTable+" VALUES (1); SELECT * FROM no_such_table; INSERT INTO "+batchTable+" VALUES (2)")
	if err == nil || !strings.Contains(err.Error(), "Error 1146") {
		t.Fatalf("batch error = %v, want 1146", err)
	}
	if got := len(mysqlDecidedSQL(h)) - before; got != 2 {
		t.Fatalf("decided %d statements, want 2", got)
	}
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+batchTable).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count = %d, err = %v: want the first INSERT kept and the connection usable", count, err)
	}
}

func TestMySQLBatchWithAnEmptyStatementRunsNothing(t *testing.T) {
	h, conn := startMySQLBatchBroker(t)
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, "CREATE TABLE "+batchTable+" (id INT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Count(req.GetSql(), "INSERT") > 1 {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "expected 1 statement, got 2"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO "+batchTable+" VALUES (1); ; INSERT INTO "+batchTable+" VALUES (2)"); err == nil {
		t.Fatal("a batch with an empty statement ran")
	}
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+batchTable).Scan(&count); err != nil || count != 0 {
		t.Fatalf("count = %d, err = %v: want nothing inserted", count, err)
	}
}

// setOption sends COM_SET_OPTION and reads its EOF (or OK under CLIENT_DEPRECATE_EOF) reply.
func (c *rawClient) setOption(t *testing.T, option byte) {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, 0, []byte{mysqlwire.ComSetOption, option, 0}); err != nil {
		t.Fatalf("write COM_SET_OPTION: %v", err)
	}
	seq, payload, err := mysqlwire.ReadPacket(c.conn)
	if err != nil || seq != 1 || len(payload) == 0 || payload[0] != 0xfe {
		t.Fatalf("COM_SET_OPTION response seq=%d payload=%x err=%v, want an EOF/OK at seq 1", seq, payload, err)
	}
}

// batchMoreFlags runs sql and returns SERVER_MORE_RESULTS_EXISTS from each result's final packet, checking
// that sequence ids run on across results.
func (c *rawClient) batchMoreFlags(t *testing.T, sql string) []bool {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, 0, mysqlwire.ComQueryPayload(sql)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	var more []bool
	want := byte(1)
	eofs := 0
	for {
		seq, payload, err := mysqlwire.ReadPacket(c.conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if seq != want {
			t.Fatalf("seq = %d, want %d", seq, want)
		}
		want++
		if payload[0] == 0xff {
			t.Fatalf("batch failed: %s", mysqlwire.ErrString(payload))
		}
		if payload[0] != 0xfe || len(payload) >= 0xffffff {
			continue
		}
		var status []byte
		if c.deprecateEOF {
			r := mysqlwire.NewReader(payload[1:])
			_, _ = r.Lenenc()
			_, _ = r.Lenenc()
			status, _ = r.Bytes(2)
		} else {
			// Each result set has an EOF after its column definitions and another after its rows.
			if eofs++; eofs%2 == 1 {
				continue
			}
			status = payload[3:5]
		}
		hasMore := binary.LittleEndian.Uint16(status)&0x0008 != 0
		more = append(more, hasMore)
		if !hasMore {
			return more
		}
	}
}

func TestMySQLSetOptionEnablesBatches(t *testing.T) {
	for _, deprecateEOF := range []bool{true, false} {
		t.Run(fmt.Sprintf("deprecateEOF=%v", deprecateEOF), func(t *testing.T) {
			h := startBroker(t)
			client := openRawClientWithEOF(t, h.addr, validToken, deprecateEOF)
			client.setOption(t, mysqlwire.OptionMultiStatementsOn)
			if more := client.batchMoreFlags(t, "SELECT 1; SELECT 2"); !reflect.DeepEqual(more, []bool{true, false}) {
				t.Fatalf("more-results flags = %v, want [true false]", more)
			}
			client.setOption(t, mysqlwire.OptionMultiStatementsOff)
			before := len(mysqlDecidedSQL(h))
			if err := mysqlwire.WritePacket(client.conn, 0, mysqlwire.ComQueryPayload("SELECT 1; SELECT 2")); err != nil {
				t.Fatalf("write query: %v", err)
			}
			if _, payload, err := mysqlwire.ReadPacket(client.conn); err != nil || payload[0] != 0xff {
				t.Fatalf("response = %x, err = %v: want the target's ERR for the unsplit batch", payload, err)
			}
			if got := mysqlDecidedSQL(h)[before:]; !reflect.DeepEqual(got, []string{"SELECT 1; SELECT 2"}) {
				t.Fatalf("decided = %q: with multi-statements off the batch is one statement", got)
			}
		})
	}
}
