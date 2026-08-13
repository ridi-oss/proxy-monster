package pgproxy_test

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// completionDecisionID is the audit decision id the fake control plane stamps on a verdict so the proxy
// correlates and emits a post-relay completion report for it (a 0 id would suppress emission).
const completionDecisionID = int64(4242)

func allowWithDecisionID(id int64) func(*pb.DecisionRequest) (*pb.WireDecision, error) {
	return func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: id}), nil
	}
}

// A simple-protocol SELECT reports one completion carrying the relayed row count and the decision id.
func TestCompletionReportSimpleSelectCountsRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = allowWithDecisionID(completionDecisionID)
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	rows, err := conn.Query(context.Background(), "SELECT id, name, ssn FROM it_pgproxy.people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	rows.Close()

	report := h.waitCompletions(t, 1)[0]
	if report.GetDecisionId() != completionDecisionID {
		t.Fatalf("completion decision_id = %d, want %d", report.GetDecisionId(), completionDecisionID)
	}
	// The seeded people table holds exactly two rows (Alice, Bob).
	if report.GetRowsReturned() != 2 {
		t.Fatalf("completion rows_returned = %d, want 2", report.GetRowsReturned())
	}
	if report.GetBytesReturned() <= 0 {
		t.Fatalf("completion bytes_returned = %d, want > 0", report.GetBytesReturned())
	}
	if report.GetStatus() != "ok" {
		t.Fatalf("completion status = %q, want ok", report.GetStatus())
	}
}

// An extended-protocol SELECT relays its rows through the Execute path and reports the same volume.
func TestCompletionReportExtendedSelectCountsRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = allowWithDecisionID(completionDecisionID)
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	rows, err := conn.Query(context.Background(), "SELECT id, name, ssn FROM it_pgproxy.people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	rows.Close()

	reports := h.waitCompletions(t, 1)
	report := reports[len(reports)-1]
	if report.GetDecisionId() != completionDecisionID {
		t.Fatalf("completion decision_id = %d, want %d", report.GetDecisionId(), completionDecisionID)
	}
	if report.GetRowsReturned() != 2 {
		t.Fatalf("completion rows_returned = %d, want 2", report.GetRowsReturned())
	}
	if report.GetStatus() != "ok" {
		t.Fatalf("completion status = %q, want ok", report.GetStatus())
	}
}

// A statement whose target-DB result is an error still reports a completion, tagged status=error.
func TestCompletionReportErroredStatement(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = allowWithDecisionID(completionDecisionID)
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// An allowed statement the target DB rejects (unknown table) relays an error, not a result set.
	rows, queryErr := conn.Query(context.Background(), "SELECT id FROM it_pgproxy.no_such_table_here")
	if queryErr == nil {
		for rows.Next() {
		}
		queryErr = rows.Err()
		rows.Close()
	}
	if queryErr == nil {
		t.Fatal("Query on a missing table succeeded, want a target-DB error")
	}

	report := h.waitCompletions(t, 1)[0]
	if report.GetDecisionId() != completionDecisionID {
		t.Fatalf("completion decision_id = %d, want %d", report.GetDecisionId(), completionDecisionID)
	}
	if report.GetStatus() != "error" {
		t.Fatalf("completion status = %q, want error", report.GetStatus())
	}
	if report.GetRowsReturned() != 0 {
		t.Fatalf("errored completion rows_returned = %d, want 0", report.GetRowsReturned())
	}
}

// A DENY relays nothing to the client, so it emits no completion — even when the denied decision carries
// an audit id.
func TestCompletionReportDenyEmitsNothing(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DecisionId: completionDecisionID, DenyReason: "off-limits"}), nil
	}
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := conn.Exec(context.Background(), "SELECT ssn FROM it_pgproxy.people"); err == nil || !strings.Contains(err.Error(), "proxy-monster denied") {
		t.Fatalf("Exec error = %v, want a policy denial", err)
	}
	// A DENY never reaches the emission path, so nothing is fired; a brief grace guards against a stray goroutine.
	time.Sleep(200 * time.Millisecond)
	if got := h.fake.completionReports(); len(got) != 0 {
		t.Fatalf("completion reports after DENY = %d, want 0", len(got))
	}
}
