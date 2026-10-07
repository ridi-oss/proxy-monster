package pgproxy_test

import (
	"context"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// A refusal inside an open transaction fails it as a target-DB error would, so COMMIT rolls back.
func TestDenyInsideTransactionAbortsIt(t *testing.T) {
	for _, extended := range []bool{false, true} {
		name := "simple"
		if extended {
			name = "extended"
		}
		t.Run(name, func(t *testing.T) {
			h, conn, seed := startBatchBroker(t)
			h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
				if strings.Contains(req.GetSql(), "ssn") {
					return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no"}), nil
				}
				return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
			}
			ctx := context.Background()
			if _, err := conn.Exec(ctx, "BEGIN; CREATE TABLE "+batchTable+" (id int)").ReadAll(); err == nil {
				t.Fatal("transaction control in a batch was not refused")
			}
			for _, statement := range []string{"BEGIN", "CREATE TABLE " + batchTable + " (id int)"} {
				if _, err := conn.Exec(ctx, statement).ReadAll(); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			}
			var err error
			if extended {
				err = conn.ExecParams(ctx, "SELECT ssn FROM it_pgproxy.people", nil, nil, nil, nil).Read().Err
			} else {
				_, err = conn.Exec(ctx, "SELECT ssn FROM it_pgproxy.people").ReadAll()
			}
			if pgErr := batchError(t, err); pgErr.Code != "42501" {
				t.Fatalf("code = %s, want 42501", pgErr.Code)
			}
			if conn.TxStatus() != 'E' {
				t.Fatalf("tx status = %c, want E", conn.TxStatus())
			}
			if _, err := conn.Exec(ctx, "COMMIT").ReadAll(); err != nil {
				t.Fatalf("COMMIT: %v", err)
			}
			if conn.TxStatus() != 'I' || tableExists(t, seed, batchTable) {
				t.Fatalf("tx status = %c: COMMIT of the failed transaction must roll it back", conn.TxStatus())
			}
		})
	}
}

func TestBatchDenyInsideClientTransactionAbortsIt(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if strings.Contains(req.GetSql(), "ssn") {
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no"}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "BEGIN").ReadAll(); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	_, err := conn.Exec(ctx, "CREATE TABLE "+batchTable+" (id int); SELECT ssn FROM it_pgproxy.people").ReadAll()
	if pgErr := batchError(t, err); pgErr.Code != "42501" || conn.TxStatus() != 'E' {
		t.Fatalf("code = %s, tx status = %c, want 42501 and E", pgErr.Code, conn.TxStatus())
	}
	if _, err := conn.Exec(ctx, "COMMIT").ReadAll(); err != nil {
		t.Fatalf("COMMIT: %v", err)
	}
	if tableExists(t, seed, batchTable) {
		t.Fatal("COMMIT kept the statement before the deny")
	}
}

func TestResultCapInsideTransactionAbortsIt(t *testing.T) {
	h, conn, seed := startBatchBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, MaxRows: 1}), nil
	}
	ctx := context.Background()
	for _, statement := range []string{"BEGIN", "CREATE TABLE " + batchTable + " (id int)"} {
		if _, err := conn.Exec(ctx, statement).ReadAll(); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	_, err := conn.Exec(ctx, "SELECT generate_series(1, 10)").ReadAll()
	if pgErr := batchError(t, err); pgErr.Code != "57014" || conn.TxStatus() != 'E' {
		t.Fatalf("code = %s, tx status = %c, want 57014 and E", pgErr.Code, conn.TxStatus())
	}
	if _, err := conn.Exec(ctx, "COMMIT").ReadAll(); err != nil {
		t.Fatalf("COMMIT: %v", err)
	}
	if tableExists(t, seed, batchTable) {
		t.Fatal("COMMIT kept the work before the capped statement")
	}
}
