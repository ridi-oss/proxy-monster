package pgproxy_test

import (
	"context"
	"slices"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func denyCheckingTargetSyntaxExcept(allowed ...string) func(*pb.DecisionRequest) (*pb.WireDecision, error) {
	return func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if slices.Contains(allowed, request.GetSql()) {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
		}
		return wireVerdict(&pb.Verdict{
			Decision:          pb.EnfAction_DENY,
			DecisionId:        completionDecisionID,
			DenyReason:        "fail-closed: could not analyze (parse)",
			CheckTargetSyntax: true,
		}), nil
	}
}

func TestTargetSyntaxCheckForwardsTheTargetSyntaxError(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = denyCheckingTargetSyntaxExcept("SELECT 1")
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()

	_, err = conn.Exec(ctx, "SELEC 1")
	assertPgError(t, err, "42601", "syntax error")
	got := h.waitCompletions(t, 1)
	if got[0].GetDecisionId() != completionDecisionID || got[0].GetStatus() != "rejected" {
		t.Fatalf("completion = %v, want status rejected for decision %d", got[0], completionDecisionID)
	}
	if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("query after the forwarded error: %v", err)
	}
}

func TestTargetSyntaxCheckDeniesAStatementTheTargetParses(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = denyCheckingTargetSyntaxExcept("SELECT 1")
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()

	for _, statement := range []string{"SELECT name FROM it_pgproxy.people", "SELECT no_such_column FROM it_pgproxy.people"} {
		_, err := conn.Exec(ctx, statement)
		assertPgError(t, err, "42501", "proxy-monster denied: fail-closed")
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.fake.completionReports(); len(got) != 0 {
		t.Fatalf("completion reports after denies = %d, want 0", len(got))
	}
	if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("query after the denies: %v", err)
	}
}

func TestTargetSyntaxErrorAbortsTheOpenTransaction(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = denyCheckingTargetSyntaxExcept("BEGIN", "SELECT 1", "ROLLBACK")
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()

	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	_, err = conn.Exec(ctx, "SELEC 1")
	assertPgError(t, err, "42601", "syntax error")
	_, err = conn.Exec(ctx, "SELECT 1")
	assertPgError(t, err, "25P02", "")
	if _, err := conn.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatalf("ROLLBACK: %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("query after ROLLBACK: %v", err)
	}
}

func TestExtendedTargetSyntaxCheckForwardsTheTargetSyntaxError(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = denyCheckingTargetSyntaxExcept()
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()

	_, err = conn.Prepare(ctx, "stmt_syntax", "SELEC $1")
	assertPgError(t, err, "42601", "syntax error")
	_, err = conn.Prepare(ctx, "stmt_denied", "SELECT name FROM it_pgproxy.people WHERE id = $1")
	assertPgError(t, err, "42501", "proxy-monster denied: fail-closed")

	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	var name string
	if err := conn.QueryRow(ctx, "SELECT name FROM it_pgproxy.people WHERE id = $1", 1).Scan(&name); err != nil {
		t.Fatalf("query after the forwarded error: %v", err)
	}
}
