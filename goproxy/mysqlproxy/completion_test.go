package mysqlproxy_test

import (
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
	conn := h.openDB(t, validToken)

	rows, err := conn.Query("SELECT id, name, ssn FROM people ORDER BY id")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	_ = rows.Close()

	got := h.waitCompletions(t, 1)
	report := got[len(got)-1]
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

// An extended-protocol (prepared) SELECT reports the completion for the EXECUTE relay only — PREPARE
// relays no rows, so exactly one completion lands, counting the executed statement's rows.
func TestCompletionReportPreparedSelectCountsRows(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = allowWithDecisionID(completionDecisionID)
	conn := h.openDB(t, validToken)

	stmt, err := conn.Prepare("SELECT id, name, ssn FROM people WHERE id = ?")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()
	rows, err := stmt.Query(1)
	if err != nil {
		t.Fatalf("prepared Query: %v", err)
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("prepared rows.Err: %v", err)
	}
	_ = rows.Close()

	got := h.waitCompletions(t, 1)
	report := got[len(got)-1]
	if report.GetDecisionId() != completionDecisionID {
		t.Fatalf("completion decision_id = %d, want %d", report.GetDecisionId(), completionDecisionID)
	}
	// Exactly the one matching row (id = 1).
	if report.GetRowsReturned() != 1 {
		t.Fatalf("completion rows_returned = %d, want 1", report.GetRowsReturned())
	}
	if report.GetStatus() != "ok" {
		t.Fatalf("completion status = %q, want ok", report.GetStatus())
	}
}

// A statement whose target-DB result is an error still reports a completion, tagged status=error.
func TestCompletionReportErroredStatement(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = allowWithDecisionID(completionDecisionID)
	conn := h.openDB(t, validToken)

	// An allowed statement the target DB rejects (unknown table) relays an ERR, not a result set.
	if _, err := conn.Query("SELECT id FROM no_such_table_here"); err == nil {
		t.Fatal("Query on a missing table succeeded, want a target-DB error")
	}

	got := h.waitCompletions(t, 1)
	report := got[len(got)-1]
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
	conn := h.openDB(t, validToken)

	if _, err := conn.Query("SELECT ssn FROM people"); err == nil || !strings.Contains(err.Error(), "proxy-monster denied") {
		t.Fatalf("Query error = %v, want a policy denial", err)
	}
	// A DENY never reaches the emission path, so nothing is fired; a brief grace guards against a stray goroutine.
	time.Sleep(200 * time.Millisecond)
	if got := h.fake.completionReports(); len(got) != 0 {
		t.Fatalf("completion reports after DENY = %d, want 0", len(got))
	}
}
