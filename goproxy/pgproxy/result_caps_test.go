package pgproxy_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
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
			name      string
			tags      []string
			unbounded bool
			want      int
			message   string
		}{
			{name: "rows", tags: []string{"cap-rows-500"}, want: 500, message: "proxy-monster: result exceeds the row cap (500 rows); request unbounded access"},
			{name: "bytes", tags: []string{"cap-bytes-50"}, want: 5, message: "proxy-monster: result exceeds the byte cap (50 bytes); request unbounded access"},
			{name: "unbounded", tags: []string{"cap-rows-500"}, unbounded: true, want: 10000},
		} {
			t.Run(fmt.Sprintf("simple=%v/%s", simple, tc.name), func(t *testing.T) {
				h := startBroker(t)
				seedCapRows(t)
				h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
					return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, UnmaskedTags: tc.tags, Unbounded: tc.unbounded}), nil
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

func TestResultCapTransactionRollback(t *testing.T) {
	for _, simple := range []bool{true, false} {
		t.Run(fmt.Sprintf("simple=%v", simple), func(t *testing.T) {
			h := startBroker(t)
			seedCapRows(t)
			h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, UnmaskedTags: []string{"cap-rows-500"}}), nil
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
