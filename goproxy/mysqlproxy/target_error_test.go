package mysqlproxy_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// checkingTargetError plays the control plane's unanalyzable floor: ask for a target error check, then
// forward the target's error, or deny a statement that prepared. It records each reported error code.
func checkingTargetError(codes *[]string) func(*pb.DecisionRequest) (*pb.WireDecision, error) {
	var mu sync.Mutex
	return func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		check := request.GetTargetCheck()
		if check == nil {
			return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{
				Commands: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_CheckTargetError{CheckTargetError: &pb.CheckTargetError{}}}},
			}}}, nil
		}
		mu.Lock()
		*codes = append(*codes, check.GetErrorCode())
		mu.Unlock()
		if check.GetErrorCode() != "" {
			return wireVerdict(&pb.Verdict{
				Decision:            pb.EnfAction_ALLOW,
				DecisionId:          completionDecisionID,
				ForwardTargetError:  true,
				SanitizeDiagnostics: true,
			}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "fail-closed: could not analyze (parse)"}), nil
	}
}

func TestTargetErrorIsForwarded(t *testing.T) {
	h := startBroker(t)
	var codes []string
	h.fake.decideFn = checkingTargetError(&codes)
	conn := h.openDB(t, validToken)

	_, err := conn.Query("SELEC 1")
	if err == nil || !strings.Contains(err.Error(), "Error 1064 (42000): You have an error in your SQL syntax") || !strings.Contains(err.Error(), "near 'SELEC 1'") {
		t.Fatalf("Query error = %v, want the target's own 1064 message", err)
	}
	_, err = conn.Query("SELECT no_such_column FROM people")
	if err == nil || !strings.Contains(err.Error(), "Error 1054 (42S22): Unknown column 'no_such_column' in 'field list'") {
		t.Fatalf("Query error = %v, want the target's 1054", err)
	}
	got := h.waitCompletions(t, 2)
	for _, c := range got {
		if c.GetDecisionId() != completionDecisionID || c.GetStatus() != "error" {
			t.Fatalf("completion = %v, want status error for decision %d", c, completionDecisionID)
		}
	}
	if strings.Join(codes, ",") != "1064,1054" {
		t.Fatalf("reported target error codes = %v, want [1064 1054]", codes)
	}

	h.fake.decideFn = allowWithDecisionID(0)
	var name string
	if err := conn.QueryRow("SELECT name FROM people WHERE id = 1").Scan(&name); err != nil || name != "Alice" {
		t.Fatalf("query after the forwarded errors = %q, %v; want Alice", name, err)
	}
}

func TestTargetErrorCheckDeniesAStatementTheTargetPrepares(t *testing.T) {
	h := startBroker(t)
	var codes []string
	h.fake.decideFn = checkingTargetError(&codes)
	conn := h.openDB(t, validToken)

	// A CREATE PROCEDURE runs but cannot be prepared (1295), which says nothing about the statement.
	for _, statement := range []string{"SELECT name FROM people", "CREATE PROCEDURE never_created() SELECT 1"} {
		_, err := conn.Query(statement)
		if err == nil || !strings.Contains(err.Error(), "Error 1142") || !strings.Contains(err.Error(), "proxy-monster denied: fail-closed") {
			t.Fatalf("Query(%q) error = %v, want the 1142 deny", statement, err)
		}
	}
	if strings.Join(codes, ",") != "," {
		t.Fatalf("reported target error codes = %q, want two clean checks", codes)
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.fake.completionReports(); len(got) != 0 {
		t.Fatalf("completion reports after a deny = %d, want 0", len(got))
	}

	h.fake.decideFn = allowWithDecisionID(0)
	var name string
	if err := conn.QueryRow("SELECT name FROM people WHERE id = 1").Scan(&name); err != nil || name != "Alice" {
		t.Fatalf("query after the deny = %q, %v; want Alice", name, err)
	}
}

func TestForwardWithoutAnObservedTargetErrorFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, ForwardTargetError: true}), nil
	}
	conn := h.openDB(t, validToken)

	if _, err := conn.Query("SELECT name FROM people"); err == nil || !strings.Contains(err.Error(), "did not observe") {
		t.Fatalf("Query error = %v, want a mechanical failure", err)
	}
}

func TestPreparedStatementTargetErrorIsForwarded(t *testing.T) {
	h := startBroker(t)
	var codes []string
	h.fake.decideFn = checkingTargetError(&codes)
	conn := h.openDB(t, validToken)

	stmt, err := conn.Prepare("SELEC ?")
	if err == nil {
		_ = stmt.Close()
		t.Fatal("Prepare succeeded, want the target's 1064")
	}
	if !strings.Contains(err.Error(), "Error 1064") {
		t.Fatalf("Prepare error = %v, want the target's 1064", err)
	}
	if _, err := conn.Prepare("SELECT name FROM people WHERE id = ?"); err == nil || !strings.Contains(err.Error(), "Error 1142") {
		t.Fatalf("Prepare error = %v, want the 1142 deny", err)
	}
}
