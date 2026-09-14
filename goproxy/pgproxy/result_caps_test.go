package pgproxy_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/protobuf/proto"
)

func seedCapRows(t *testing.T) {
	t.Helper()
	db := dbtest.OpenPostgres(t, "app")
	for _, query := range []string{
		"DROP TABLE IF EXISTS it_pgproxy.cap_rows",
		"CREATE TABLE it_pgproxy.cap_rows AS SELECT n AS id, repeat('x', 10) AS value FROM generate_series(1,10000) n",
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
}

func countCapRows(t *testing.T, rows pgx.Rows, queryErr error, want int, message string) {
	t.Helper()
	if queryErr != nil {
		t.Fatal(queryErr)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	if count != want {
		t.Fatalf("delivered rows = %d, want %d (error %v)", count, want, rows.Err())
	}
	if message == "" {
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return
	}
	var pgErr *pgconn.PgError
	if !errors.As(rows.Err(), &pgErr) || pgErr.Code != "57014" || pgErr.Severity != "ERROR" || pgErr.Message != message || pgErr.Hint == "" {
		t.Fatalf("rows error = %v, want 57014 %q with hint", rows.Err(), message)
	}
}

func TestResultCaps(t *testing.T) {
	for _, simple := range []bool{true, false} {
		for _, tc := range []struct {
			name              string
			maxRows, maxBytes int64
			want              int
			message           string
		}{
			{name: "rows", maxRows: 500, want: 500, message: "proxy-monster: result exceeds the row cap (500 rows); request unbounded access"},
			{name: "bytes", maxBytes: 50, want: 5, message: "proxy-monster: result exceeds the byte cap (50 bytes); request unbounded access"},
			{name: "unbounded", want: 10000},
		} {
			t.Run(fmt.Sprintf("simple=%v/%s", simple, tc.name), func(t *testing.T) {
				h := startBroker(t)
				seedCapRows(t)
				h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
					return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, MaxRows: tc.maxRows, MaxBytes: tc.maxBytes}), nil
				}
				conn, err := h.connect(t, validToken, simple)
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				pid := conn.PgConn().PID()
				rows, err := conn.Query(ctx, "SELECT value FROM it_pgproxy.cap_rows")
				countCapRows(t, rows, err, tc.want, tc.message)
				report := h.waitCompletions(t, 1)[0]
				status := "ok"
				if tc.message != "" {
					status = "error"
				}
				if report.GetRowsReturned() != int64(tc.want) || report.GetBytesReturned() != int64(tc.want*10) || report.GetStatus() != status {
					t.Fatalf("completion = %v", report)
				}
				var value int
				if err := conn.QueryRow(ctx, "SELECT 42").Scan(&value); err != nil || value != 42 || conn.PgConn().PID() != pid {
					t.Fatalf("same connection SELECT 42 = %d, %v", value, err)
				}
			})
		}
	}
}

// A byte cap charges the TARGET-DB row, so a masked result is capped where the target's volume crosses it
// and not where the (shorter) masked row does — identically on both wire protocols.
func TestResultCapCountsTargetDbBytesUnderMasking(t *testing.T) {
	for _, simple := range []bool{true, false} {
		t.Run(fmt.Sprintf("simple=%v", simple), func(t *testing.T) {
			h := startBroker(t)
			seedCapRows(t)
			h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
				return wireVerdict(&pb.Verdict{
					Decision: pb.EnfAction_MASK, DecisionId: completionDecisionID, MaxBytes: 50,
					Masks: []*pb.ColumnMask{{Column: "value", Kind: "FIXED", Ordinal: proto.Int32(0)}},
				}), nil
			}
			conn, err := h.connect(t, validToken, simple)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := conn.Query(context.Background(), "SELECT value FROM it_pgproxy.cap_rows")
			countCapRows(t, rows, err, 5, "proxy-monster: result exceeds the byte cap (50 bytes); request unbounded access")
			if report := h.waitCompletions(t, 1)[0]; report.GetRowsReturned() != 5 || report.GetBytesReturned() != 50 {
				t.Fatalf("completion = %v, want 5 rows / 50 target-DB bytes", report)
			}
		})
	}
}

func TestResultCapTransactionRollback(t *testing.T) {
	for _, simple := range []bool{true, false} {
		t.Run(fmt.Sprintf("simple=%v", simple), func(t *testing.T) {
			h := startBroker(t)
			seedCapRows(t)
			h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, MaxRows: 500}), nil
			}
			conn, err := h.connect(t, validToken, simple)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, "CREATE TEMP TABLE cap_pending AS SELECT 1 AS id"); err != nil {
				t.Fatal(err)
			}
			rows, err := tx.Query(ctx, "SELECT value, pg_sleep(0.0001) FROM it_pgproxy.cap_rows")
			countCapRows(t, rows, err, 500, "proxy-monster: result exceeds the row cap (500 rows); request unbounded access")
			if status := conn.PgConn().TxStatus(); status != 'E' {
				t.Fatalf("transaction status = %c", status)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			var value int
			if err := conn.QueryRow(ctx, "SELECT 42").Scan(&value); err != nil || value != 42 || conn.PgConn().TxStatus() != 'I' {
				t.Fatalf("post-rollback SELECT 42 = %d, %v, tx=%c", value, err, conn.PgConn().TxStatus())
			}
		})
	}
}

// A suspended portal resumed by further Executes must not restart the cap tally: the cap bounds the
// portal's whole output, not each page a row-limited Execute delivers.
func TestResultCapAcrossPortalPages(t *testing.T) {
	h := startBroker(t)
	seedCapRows(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, MaxRows: 250}), nil
	}
	client := newRawPGClient(t, h)
	// A portal lives only until its transaction ends, so the pages resume inside an explicit one.
	client.simpleQuery(t, "BEGIN")
	client.sendSync(t,
		&pgproto3.Parse{Name: "cap_stmt", Query: "SELECT value FROM it_pgproxy.cap_rows"},
		&pgproto3.Bind{PreparedStatement: "cap_stmt", DestinationPortal: "cap_portal"},
	)

	delivered := 0
	capError := ""
	for page := 0; page < 10 && capError == ""; page++ {
		for _, message := range client.sendSync(t, &pgproto3.Execute{Portal: "cap_portal", MaxRows: 100}) {
			switch message := message.(type) {
			case *pgproto3.DataRow:
				delivered++
			case *pgproto3.ErrorResponse:
				if message.Code != "57014" {
					t.Fatalf("page %d error = %s (%s), want 57014", page, message.Message, message.Code)
				}
				capError = message.Message
			}
		}
	}
	if delivered != 250 || capError == "" {
		t.Fatalf("delivered %d rows with error %q, want 250 and a 57014 (cap restarted per page)", delivered, capError)
	}
}

// The session and its transaction survive a cap; whether the transaction can still COMMIT follows the
// target's own state: a CancelRequest that lands mid-query aborts it (COMMIT then rolls back), one that
// arrives after the query finished leaves it open (COMMIT commits the earlier work).
func TestResultCapThenCommit(t *testing.T) {
	for _, simple := range []bool{true, false} {
		t.Run(fmt.Sprintf("simple=%v", simple), func(t *testing.T) {
			h := startBroker(t)
			seedCapRows(t)
			h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, MaxRows: 500}), nil
			}
			conn, err := h.connect(t, validToken, simple)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Exec(ctx, "INSERT INTO it_pgproxy.cap_rows VALUES (10001, 'pending')"); err != nil {
				t.Fatal(err)
			}
			rows, err := conn.Query(ctx, "SELECT value FROM it_pgproxy.cap_rows")
			countCapRows(t, rows, err, 500, "proxy-monster: result exceeds the row cap (500 rows); request unbounded access")
			status := conn.PgConn().TxStatus()
			if status != 'T' && status != 'E' {
				t.Fatalf("transaction status after a cap = %c, want the transaction still open", status)
			}
			tag, err := conn.Exec(ctx, "COMMIT")
			if err != nil || conn.PgConn().TxStatus() != 'I' {
				t.Fatalf("COMMIT after a cap: %v (tx=%c)", err, conn.PgConn().TxStatus())
			}
			wantTag, wantCount := "COMMIT", 1
			if status == 'E' {
				wantTag, wantCount = "ROLLBACK", 0
			}
			if tag.String() != wantTag {
				t.Fatalf("COMMIT tag = %q after tx status %c, want %q", tag.String(), status, wantTag)
			}
			other, err := h.connect(t, validToken, simple)
			if err != nil {
				t.Fatal(err)
			}
			var count int
			if err := other.QueryRow(ctx, "SELECT count(*) FROM it_pgproxy.cap_rows WHERE id = 10001").Scan(&count); err != nil || count != wantCount {
				t.Fatalf("rows from the capped transaction visible = %d, %v, want %d", count, err, wantCount)
			}
		})
	}
}

// A named prepared statement outlives the cap that cut one of its executions.
func TestResultCapPreparedReexecute(t *testing.T) {
	h := startBroker(t)
	seedCapRows(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, MaxRows: 500}), nil
	}
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := conn.Prepare(ctx, "cap_reuse", "SELECT value FROM it_pgproxy.cap_rows WHERE id >= $1"); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.Query(ctx, "cap_reuse", 0)
	countCapRows(t, rows, err, 500, "proxy-monster: result exceeds the row cap (500 rows); request unbounded access")
	rows, err = conn.Query(ctx, "cap_reuse", 9991)
	countCapRows(t, rows, err, 10, "")
	rows, err = conn.Query(ctx, "cap_reuse", 0)
	countCapRows(t, rows, err, 500, "proxy-monster: result exceeds the row cap (500 rows); request unbounded access")
	if reports := h.waitCompletions(t, 3); reports[1].GetRowsReturned() != 10 || reports[1].GetStatus() != "ok" {
		t.Fatalf("middle completion = %v", reports[1])
	}
}

// A spent rate is an ordinary policy denial on the wire; the session survives it and the next allowed
// statement runs.
func TestRateSpentDenyKeepsSession(t *testing.T) {
	for _, simple := range []bool{true, false} {
		t.Run(fmt.Sprintf("simple=%v", simple), func(t *testing.T) {
			h := startBroker(t)
			seedCapRows(t)
			h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "rate 100MB/1h spent"}), nil
			}
			conn, err := h.connect(t, validToken, simple)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			rows, err := conn.Query(ctx, "SELECT value FROM it_pgproxy.cap_rows")
			if err == nil {
				for rows.Next() {
				}
				err = rows.Err()
				rows.Close()
			}
			assertPgError(t, err, "42501", "proxy-monster denied: rate 100MB/1h spent")
			h.fake.mu.Lock()
			h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID}), nil
			}
			h.fake.mu.Unlock()
			var count int
			if err := conn.QueryRow(ctx, "SELECT count(*) FROM it_pgproxy.cap_rows").Scan(&count); err != nil || count != 10000 {
				t.Fatalf("post-reset count(*) = %d, %v", count, err)
			}
		})
	}
}

// After a portal is capped mid-page the aborted transaction rolls back and the same session runs a fresh
// BEGIN / SELECT / COMMIT.
func TestResultCapPortalThenFreshTransaction(t *testing.T) {
	h := startBroker(t)
	seedCapRows(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, MaxRows: 250}), nil
	}
	client := newRawPGClient(t, h)
	client.simpleQuery(t, "BEGIN")
	client.sendSync(t,
		&pgproto3.Parse{Name: "cap_stmt", Query: "SELECT value FROM it_pgproxy.cap_rows"},
		&pgproto3.Bind{PreparedStatement: "cap_stmt", DestinationPortal: "cap_portal"},
	)
	delivered := 0
	capped := false
	for page := 0; page < 10 && !capped; page++ {
		for _, message := range client.sendSync(t, &pgproto3.Execute{Portal: "cap_portal", MaxRows: 100}) {
			switch message := message.(type) {
			case *pgproto3.DataRow:
				delivered++
			case *pgproto3.ErrorResponse:
				if message.Code != "57014" {
					t.Fatalf("page %d error = %s (%s)", page, message.Message, message.Code)
				}
				capped = true
			}
		}
	}
	if delivered != 250 || !capped {
		t.Fatalf("delivered %d rows, capped=%v", delivered, capped)
	}
	last := func(messages []pgproto3.BackendMessage) *pgproto3.ReadyForQuery {
		return messages[len(messages)-1].(*pgproto3.ReadyForQuery)
	}
	if rfq := last(client.simpleQuery(t, "COMMIT")); rfq.TxStatus != 'I' {
		t.Fatalf("tx status after COMMIT of an aborted transaction = %c", rfq.TxStatus)
	}
	if rfq := last(client.simpleQuery(t, "BEGIN")); rfq.TxStatus != 'T' {
		t.Fatalf("tx status after BEGIN = %c", rfq.TxStatus)
	}
	rowsSeen := 0
	for _, message := range client.simpleQuery(t, "SELECT value FROM it_pgproxy.cap_rows WHERE id <= 5") {
		if _, ok := message.(*pgproto3.DataRow); ok {
			rowsSeen++
		}
	}
	if rowsSeen != 5 {
		t.Fatalf("fresh transaction SELECT delivered %d rows, want 5", rowsSeen)
	}
	if rfq := last(client.simpleQuery(t, "COMMIT")); rfq.TxStatus != 'I' {
		t.Fatalf("tx status after COMMIT = %c", rfq.TxStatus)
	}
}
