package pgproxy_test

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

const batchTable = primarySchema + ".batch_rows"

func startBatchBroker(t *testing.T) (*brokerHarness, *pgconn.PgConn, *sql.DB) {
	t.Helper()
	h := startBroker(t)
	seed := dbtest.OpenPostgres(t, "")
	if _, err := seed.Exec("DROP TABLE IF EXISTS " + batchTable); err != nil {
		t.Fatalf("drop: %v", err)
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return h, conn.PgConn(), seed
}

func decidedSQL(h *brokerHarness) []string {
	var out []string
	for _, req := range h.fake.requests() {
		out = append(out, req.GetSql())
	}
	return out
}

func tableExists(t *testing.T, seed *sql.DB, table string) bool {
	t.Helper()
	var name sql.NullString
	if err := seed.QueryRow("SELECT to_regclass($1)::text", table).Scan(&name); err != nil {
		t.Fatalf("to_regclass: %v", err)
	}
	return name.Valid
}

func batchError(t *testing.T, err error) *pgconn.PgError {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("batch error = %v, want a PostgreSQL error", err)
	}
	return pgErr
}

func TestBatchDecidesEachStatementAgainstItsPredecessors(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	statements := []string{
		"CREATE TABLE " + batchTable + " (id int)",
		"INSERT INTO " + batchTable + " VALUES (1), (2)",
		"SELECT count(*) FROM " + batchTable,
	}
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.HasPrefix(req.GetSql(), "CREATE") {
			return refreshDecision(primarySchema), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	results, err := conn.Exec(context.Background(), strings.Join(statements, ";\n")+";").ReadAll()
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if len(results) != 3 || string(results[2].Rows[0][0]) != "2" {
		t.Fatalf("results = %d, last rows = %v", len(results), results[len(results)-1].Rows)
	}
	want := append(append([]string{"BEGIN"}, statements...), "COMMIT")
	if got := decidedSQL(h); !reflect.DeepEqual(got, want) {
		t.Fatalf("decided = %q, want %q", got, want)
	}
	events := strings.Join(h.fake.eventLog(), "|")
	if !strings.Contains(events, "decide:"+statements[0]+"|push:"+primarySchema+"|decide:"+statements[1]) {
		t.Fatalf("events = %s: the INSERT must be decided after the CREATE's catalog push", events)
	}
	if conn.TxStatus() != 'I' {
		t.Fatalf("tx status = %c, want I", conn.TxStatus())
	}
	if !tableExists(t, seed, batchTable) {
		t.Fatal("the committed batch's table is missing")
	}
}

func TestBatchDenyRollsBackEarlierStatements(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Contains(req.GetSql(), "ssn") {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	_, err := conn.Exec(context.Background(), "CREATE TABLE "+batchTable+" (id int); SELECT ssn FROM it_pgproxy.people; INSERT INTO "+batchTable+" VALUES (1)").ReadAll()
	if pgErr := batchError(t, err); pgErr.Code != "42501" {
		t.Fatalf("code = %s, want 42501", pgErr.Code)
	}
	if got := decidedSQL(h); len(got) != 4 || got[3] != "ROLLBACK" {
		t.Fatalf("decided = %q, want BEGIN, CREATE, the denied SELECT, ROLLBACK", got)
	}
	if conn.TxStatus() != 'I' || tableExists(t, seed, batchTable) {
		t.Fatalf("tx status = %c, table kept = %v: the denied batch must leave nothing", conn.TxStatus(), tableExists(t, seed, batchTable))
	}
	if _, err := conn.Exec(context.Background(), "SELECT 1").ReadAll(); err != nil {
		t.Fatalf("connection unusable after a denied batch: %v", err)
	}
}

func TestBatchTargetErrorRollsBackAndStops(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	_, err := conn.Exec(context.Background(), "CREATE TABLE "+batchTable+" (id int); SELECT 1/0; INSERT INTO "+batchTable+" VALUES (1)").ReadAll()
	if pgErr := batchError(t, err); pgErr.Code != "22012" {
		t.Fatalf("code = %s, want 22012", pgErr.Code)
	}
	if got := decidedSQL(h); len(got) != 4 || got[3] != "ROLLBACK" {
		t.Fatalf("decided = %q, want BEGIN, CREATE, SELECT 1/0, ROLLBACK", got)
	}
	if conn.TxStatus() != 'I' || tableExists(t, seed, batchTable) {
		t.Fatalf("tx status = %c: the failed batch must roll back", conn.TxStatus())
	}
}

func TestBatchInsideClientTransactionLeavesItToTheClient(t *testing.T) {
	_, conn, seed := startBatchBroker(t)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "BEGIN").ReadAll(); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	if _, err := conn.Exec(ctx, "CREATE TABLE "+batchTable+" (id int); INSERT INTO "+batchTable+" VALUES (1)").ReadAll(); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if conn.TxStatus() != 'T' || tableExists(t, seed, batchTable) {
		t.Fatalf("tx status = %c: the client's transaction must stay open and uncommitted", conn.TxStatus())
	}
	if _, err := conn.Exec(ctx, "SELECT 1/0; SELECT 2").ReadAll(); err == nil {
		t.Fatal("division by zero succeeded")
	}
	if conn.TxStatus() != 'E' {
		t.Fatalf("tx status = %c, want E: an error aborts the client's transaction", conn.TxStatus())
	}
	if _, err := conn.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
		t.Fatalf("ROLLBACK: %v", err)
	}
}

func TestBatchWithTransactionControlIsRefused(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	_, err := conn.Exec(context.Background(), "BEGIN ISOLATION LEVEL SERIALIZABLE; CREATE TABLE "+batchTable+" (id int)").ReadAll()
	if pgErr := batchError(t, err); pgErr.Code != "0A000" {
		t.Fatalf("code = %s, want 0A000", pgErr.Code)
	}
	if got := decidedSQL(h); len(got) != 0 || conn.TxStatus() != 'I' || tableExists(t, seed, batchTable) {
		t.Fatalf("decided = %q, tx status = %c: a refused batch runs nothing", got, conn.TxStatus())
	}
}

func TestBatchWithAnUnparsedTransactionStatementIsRefused(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	_, err := conn.Exec(context.Background(), "CREATE TABLE "+batchTable+" (id int); ABORT AND CHAIN; CREATE TABLE "+batchTable+"_after (id int)").ReadAll()
	if pgErr := batchError(t, err); pgErr.Code != "0A000" {
		t.Fatalf("code = %s, want 0A000", pgErr.Code)
	}
	if len(decidedSQL(h)) != 0 || tableExists(t, seed, batchTable) || tableExists(t, seed, batchTable+"_after") {
		t.Fatal("a refused batch runs nothing")
	}
}

func TestBatchDeniedRollbackClosesTheConnection(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Contains(req.GetSql(), "ssn") || req.GetSql() == "ROLLBACK" {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	_, _ = conn.Exec(context.Background(), "CREATE TABLE "+batchTable+" (id int); SELECT ssn FROM it_pgproxy.people").ReadAll()
	if _, err := conn.Exec(context.Background(), "COMMIT").ReadAll(); err == nil {
		t.Fatal("COMMIT succeeded on the connection the denied ROLLBACK left open")
	}
	if tableExists(t, seed, batchTable) {
		t.Fatal("the denied batch's table was committed")
	}
}

func TestBatchDeniedBeginRunsNothing(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if req.GetSql() == "BEGIN" {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no session"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	_, err := conn.Exec(context.Background(), "CREATE TABLE "+batchTable+" (id int); SELECT 1").ReadAll()
	if pgErr := batchError(t, err); pgErr.Code != "42501" {
		t.Fatalf("code = %s, want 42501", pgErr.Code)
	}
	if got := decidedSQL(h); !reflect.DeepEqual(got, []string{"BEGIN"}) || tableExists(t, seed, batchTable) {
		t.Fatalf("decided = %q: nothing may run after a denied BEGIN", got)
	}
}

func TestBatchRollbackReprobesTheNamespace(t *testing.T) {
	h, conn, _ := startBatchBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Contains(req.GetSql(), "ssn") {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "SET search_path = "+secondarySchema+", public; SELECT ssn FROM people").ReadAll(); err == nil {
		t.Fatal("the batch was not denied")
	}
	if _, err := conn.Exec(ctx, "SELECT 1").ReadAll(); err != nil {
		t.Fatalf("query: %v", err)
	}
	requests := h.fake.requests()
	if got := requests[2].GetSearchPath(); !reflect.DeepEqual(got, []string{"pg_catalog", secondarySchema, "public"}) {
		t.Fatalf("denied statement's search path = %v: it must be decided under the batch's SET", got)
	}
	if got := requests[len(requests)-1].GetSearchPath(); !reflect.DeepEqual(got, []string{"pg_catalog", "public"}) {
		t.Fatalf("search path = %v: the rolled-back SET must not outlive the batch", got)
	}
}

func TestBatchMasksEachStatementByItsOwnDecision(t *testing.T) {
	h, conn, _ := startBatchBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Contains(req.GetSql(), "ssn") {
			return wireVerdict(&pb.Verdict{
				Decision: pb.EnfAction_MASK,
				Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(0)}},
			}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	results, err := conn.Exec(context.Background(), "SELECT name FROM it_pgproxy.people WHERE id = 1; SELECT ssn FROM it_pgproxy.people WHERE id = 1").ReadAll()
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if name, ssn := string(results[0].Rows[0][0]), string(results[1].Rows[0][0]); name != "Alice" || ssn != "####" {
		t.Fatalf("name = %q, ssn = %q: want Alice unmasked and ssn masked", name, ssn)
	}
}

func TestSingleStatementWithTrailingSemicolonIsNotABatch(t *testing.T) {
	h, conn, _ := startBatchBroker(t)
	if _, err := conn.Exec(context.Background(), "SELECT 'a;b';  ").ReadAll(); err != nil {
		t.Fatalf("query: %v", err)
	}
	if got := decidedSQL(h); !reflect.DeepEqual(got, []string{"SELECT 'a;b';  "}) {
		t.Fatalf("decided = %q, want the original text once", got)
	}
}

func TestBatchWithItsOwnTransactionRunsAsIs(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	statements := []string{
		"BEGIN ISOLATION LEVEL SERIALIZABLE",
		"CREATE TABLE " + batchTable + " (id int)",
		"SHOW transaction_isolation",
		"COMMIT",
	}
	results, err := conn.Exec(context.Background(), strings.Join(statements, "; ")).ReadAll()
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if got := string(results[2].Rows[0][0]); got != "serializable" {
		t.Fatalf("isolation = %q, want serializable", got)
	}
	if got := decidedSQL(h); !reflect.DeepEqual(got, statements) {
		t.Fatalf("decided = %q, want the batch's own statements and no proxy BEGIN/COMMIT", got)
	}
	if conn.TxStatus() != 'I' || !tableExists(t, seed, batchTable) {
		t.Fatalf("tx status = %c: the batch's COMMIT must commit", conn.TxStatus())
	}
}

func TestBatchWithItsOwnTransactionStopsAtADeny(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Contains(req.GetSql(), "ssn") {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	ctx := context.Background()
	_, err := conn.Exec(ctx, "BEGIN; CREATE TABLE "+batchTable+" (id int); SELECT ssn FROM it_pgproxy.people; COMMIT").ReadAll()
	if pgErr := batchError(t, err); pgErr.Code != "42501" || conn.TxStatus() != 'E' {
		t.Fatalf("code = %s, tx status = %c, want 42501 and E", pgErr.Code, conn.TxStatus())
	}
	if got := decidedSQL(h); len(got) != 3 {
		t.Fatalf("decided = %q: the COMMIT after the deny must not run", got)
	}
	if _, err := conn.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
		t.Fatalf("ROLLBACK: %v", err)
	}
	if tableExists(t, seed, batchTable) {
		t.Fatal("the denied batch's table was committed")
	}
}

func TestBatchEndingItsTransactionMidwayIsRefused(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	_, err := conn.Exec(context.Background(), "BEGIN; CREATE TABLE "+batchTable+" (id int); COMMIT; CREATE TABLE "+batchTable+"_after (id int); COMMIT").ReadAll()
	if pgErr := batchError(t, err); pgErr.Code != "0A000" {
		t.Fatalf("code = %s, want 0A000", pgErr.Code)
	}
	if len(decidedSQL(h)) != 0 || tableExists(t, seed, batchTable) {
		t.Fatal("a refused batch runs nothing")
	}
}
