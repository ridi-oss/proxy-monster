package mysqlproxy_test

import (
	"strings"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func denyCheckingTargetSyntax(*pb.DecisionRequest) (*pb.WireDecision, error) {
	return wireVerdict(&pb.Verdict{
		Decision:          pb.EnfAction_DENY,
		DecisionId:        completionDecisionID,
		DenyReason:        "fail-closed: could not analyze (parse)",
		CheckTargetSyntax: true,
	}), nil
}

func TestTargetSyntaxCheckForwardsTheTargetParseError(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = denyCheckingTargetSyntax
	conn := h.openDB(t, validToken)

	_, err := conn.Query("SELEC 1")
	if err == nil || !strings.Contains(err.Error(), "Error 1064") || strings.Contains(err.Error(), "proxy-monster") {
		t.Fatalf("Query error = %v, want the target's own 1064", err)
	}
	got := h.waitCompletions(t, 1)
	if got[0].GetDecisionId() != completionDecisionID || got[0].GetStatus() != "rejected" {
		t.Fatalf("completion = %v, want status rejected for decision %d", got[0], completionDecisionID)
	}

	h.fake.decideFn = allowWithDecisionID(0)
	var name string
	if err := conn.QueryRow("SELECT name FROM people WHERE id = 1").Scan(&name); err != nil || name != "Alice" {
		t.Fatalf("query after the forwarded error = %q, %v; want Alice", name, err)
	}
}

func TestTargetSyntaxCheckDeniesAStatementTheTargetParses(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = denyCheckingTargetSyntax
	conn := h.openDB(t, validToken)

	for _, statement := range []string{"SELECT name FROM people", "SELECT no_such_column FROM people"} {
		_, err := conn.Query(statement)
		if err == nil || !strings.Contains(err.Error(), "Error 1142") || !strings.Contains(err.Error(), "proxy-monster denied: fail-closed") {
			t.Fatalf("Query(%q) error = %v, want the 1142 deny", statement, err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.fake.completionReports(); len(got) != 0 {
		t.Fatalf("completion reports after denies = %d, want 0", len(got))
	}

	h.fake.decideFn = allowWithDecisionID(0)
	var name string
	if err := conn.QueryRow("SELECT name FROM people WHERE id = 1").Scan(&name); err != nil || name != "Alice" {
		t.Fatalf("query after the denies = %q, %v; want Alice", name, err)
	}
}

func TestTargetSyntaxCheckIsSkippedWithoutTheFlag(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "off-limits"}), nil
	}
	conn := h.openDB(t, validToken)

	_, err := conn.Query("SELEC 1")
	if err == nil || !strings.Contains(err.Error(), "Error 1142") {
		t.Fatalf("Query error = %v, want the 1142 deny", err)
	}
}

func TestPreparedTargetSyntaxCheckForwardsTheTargetParseError(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = denyCheckingTargetSyntax
	conn := h.openDB(t, validToken)

	stmt, err := conn.Prepare("SELEC ?")
	if err == nil {
		_ = stmt.Close()
		t.Fatal("Prepare succeeded, want the target's 1064")
	}
	if !strings.Contains(err.Error(), "Error 1064") {
		t.Fatalf("Prepare error = %v, want the target's own 1064", err)
	}
	if _, err := conn.Prepare("SELECT name FROM people WHERE id = ?"); err == nil || !strings.Contains(err.Error(), "Error 1142") {
		t.Fatalf("Prepare error = %v, want the 1142 deny", err)
	}
}
