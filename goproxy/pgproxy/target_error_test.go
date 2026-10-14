package pgproxy_test

import (
	"context"
	"slices"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// checkingTargetErrorExcept plays the control plane's unanalyzable floor for every statement not in
// allowed: ask for a target error check, then forward the target's error, or deny a statement that prepared.
func checkingTargetErrorExcept(allowed ...string) func(*pb.DecisionRequest) (*pb.WireDecision, error) {
	return func(request *pb.DecisionRequest) (*pb.WireDecision, error) {
		if slices.Contains(allowed, request.GetSql()) {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
		}
		check := request.GetTargetCheck()
		if check == nil {
			return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{
				Commands: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_CheckTargetError{CheckTargetError: &pb.CheckTargetError{}}}},
			}}}, nil
		}
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

func TestTargetErrorIsForwardedRedacted(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = checkingTargetErrorExcept("SELECT 1")
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()

	_, err = conn.Exec(ctx, "SELEC 1")
	assertPgError(t, err, "42601", "syntax_error")
	_, err = conn.Exec(ctx, "SELECT no_such_column FROM it_pgproxy.people")
	assertPgError(t, err, "42703", `column "no_such_column" does not exist`)
	got := h.waitCompletions(t, 2)
	for _, c := range got {
		if c.GetDecisionId() != completionDecisionID || c.GetStatus() != "error" {
			t.Fatalf("completion = %v, want status error for decision %d", c, completionDecisionID)
		}
	}
	if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("query after the forwarded errors: %v", err)
	}
}

func TestTargetErrorCheckDeniesAStatementTheTargetPrepares(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = checkingTargetErrorExcept("SELECT 1")
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()

	_, err = conn.Exec(ctx, "SELECT name FROM it_pgproxy.people")
	assertPgError(t, err, "42501", "proxy-monster denied: fail-closed")
	time.Sleep(200 * time.Millisecond)
	if got := h.fake.completionReports(); len(got) != 0 {
		t.Fatalf("completion reports after a deny = %d, want 0", len(got))
	}
	if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("query after the deny: %v", err)
	}
}

func TestTargetErrorAbortsTheOpenTransaction(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = checkingTargetErrorExcept("BEGIN", "SELECT 1", "ROLLBACK")
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()

	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	_, err = conn.Exec(ctx, "SELEC 1")
	assertPgError(t, err, "42601", "syntax_error")
	_, err = conn.Exec(ctx, "SELECT 1")
	assertPgError(t, err, "25P02", "")
	if _, err := conn.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatalf("ROLLBACK: %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("query after ROLLBACK: %v", err)
	}
}

func TestExtendedTargetErrorIsForwarded(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = checkingTargetErrorExcept()
	conn, err := h.connect(t, validToken, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()

	_, err = conn.Prepare(ctx, "stmt_syntax", "SELEC $1")
	assertPgError(t, err, "42601", "syntax_error")
	_, err = conn.Prepare(ctx, "stmt_denied", "SELECT name FROM it_pgproxy.people WHERE id = $1")
	assertPgError(t, err, "42501", "proxy-monster denied: fail-closed")
	// Untyped, $1 IS NULL cannot be inferred (42P18); the check keeps the client's text OID.
	_, err = conn.PgConn().Prepare(ctx, "stmt_typed", "VALUES ($1 IS NULL)", []uint32{25})
	assertPgError(t, err, "42501", "proxy-monster denied: fail-closed")

	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	var name string
	if err := conn.QueryRow(ctx, "SELECT name FROM it_pgproxy.people WHERE id = $1", 1).Scan(&name); err != nil {
		t.Fatalf("query after the forwarded error: %v", err)
	}
}
