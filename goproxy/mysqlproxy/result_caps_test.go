package mysqlproxy_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func seedCapRows(t *testing.T) {
	t.Helper()
	db := dbtest.OpenMySQL(t, primarySchema)
	for _, query := range []string{
		"DROP TABLE IF EXISTS cap_rows",
		"CREATE TABLE cap_rows (id INT PRIMARY KEY, value VARCHAR(10) NOT NULL)",
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	values := make([]string, 10000)
	for i := range values {
		values[i] = fmt.Sprintf("(%d, 'xxxxxxxxxx')", i)
	}
	if _, err := db.Exec("INSERT INTO cap_rows VALUES " + strings.Join(values, ",")); err != nil {
		t.Fatal(err)
	}
}

func countCapRows(t *testing.T, rows *sql.Rows, queryErr error, want int, message string) {
	t.Helper()
	if queryErr != nil {
		t.Fatalf("query: %v", queryErr)
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
	var mysqlErr *mysql.MySQLError
	if !errors.As(rows.Err(), &mysqlErr) || mysqlErr.Number != 1317 || string(mysqlErr.SQLState[:]) != "70100" || mysqlErr.Message != message {
		t.Fatalf("rows error = %v, want 1317/70100 %q", rows.Err(), message)
	}
}

func TestResultCaps(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		tags                 []string
		unbounded            bool
		prepared, unmaskable bool
		want                 int
		message              string
	}{
		{name: "rows", tags: []string{"cap-rows-500"}, want: 500, message: "proxy-monster: result exceeds the row cap (500 rows); request unbounded access"},
		{name: "bytes", tags: []string{"cap-bytes-55"}, want: 5, message: "proxy-monster: result exceeds the byte cap (55 bytes); request unbounded access"},
		{name: "prepared", tags: []string{"cap-rows-500"}, prepared: true, want: 500, message: "proxy-monster: result exceeds the row cap (500 rows); request unbounded access"},
		{name: "unmaskable", tags: []string{"cap-rows-500"}, prepared: true, unmaskable: true, want: 500, message: "proxy-monster: result exceeds the row cap (500 rows); request unbounded access"},
		{name: "unbounded", tags: []string{"cap-rows-500"}, unbounded: true, want: 10000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startBroker(t)
			seedCapRows(t)
			h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
				verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, UnmaskedTags: tc.tags, Unbounded: tc.unbounded}
				if tc.unmaskable {
					verdict.Decision = pb.EnfAction_MASK
					verdict.UnmaskablePermitted = true
				}
				return wireVerdict(verdict), nil
			}
			ctx := context.Background()
			conn, err := h.openDB(t, validToken).Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var rows *sql.Rows
			if tc.prepared {
				stmt, prepErr := conn.PrepareContext(ctx, "SELECT value FROM cap_rows WHERE id >= ?")
				if prepErr != nil {
					t.Fatal(prepErr)
				}
				defer stmt.Close()
				rows, err = stmt.QueryContext(ctx, 0)
			} else {
				rows, err = conn.QueryContext(ctx, "SELECT value FROM cap_rows")
			}
			countCapRows(t, rows, err, tc.want, tc.message)
			report := h.waitCompletions(t, 1)[0]
			status := "ok"
			if tc.message != "" {
				status = "error"
			}
			if report.GetRowsReturned() != int64(tc.want) || report.GetStatus() != status || report.GetDecisionId() != completionDecisionID {
				t.Fatalf("completion = %v", report)
			}
			if tc.name == "bytes" && report.GetBytesReturned() != 55 {
				t.Fatalf("completion bytes = %d, want 55", report.GetBytesReturned())
			}
			var value int
			if err := conn.QueryRowContext(ctx, "SELECT 42").Scan(&value); err != nil || value != 42 {
				t.Fatalf("same connection SELECT 42 = %d, %v", value, err)
			}
		})
	}
}

func TestResultCapPreservesTransaction(t *testing.T) {
	h := startBroker(t)
	seedCapRows(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: completionDecisionID, UnmaskedTags: []string{"cap-rows-500"}}), nil
	}
	ctx := context.Background()
	conn, err := h.openDB(t, validToken).Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO cap_rows VALUES (10000, 'pending')"); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query("SELECT value FROM cap_rows")
	countCapRows(t, rows, err, 500, "proxy-monster: result exceeds the row cap (500 rows); request unbounded access")
	var value string
	if err := tx.QueryRow("SELECT value FROM cap_rows WHERE id = 10000").Scan(&value); err != nil || value != "pending" {
		t.Fatalf("uncommitted row = %q, %v", value, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM cap_rows WHERE id = 10000").Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled back row count = %d, %v", count, err)
	}
}
