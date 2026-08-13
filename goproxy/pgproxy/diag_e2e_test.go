package pgproxy_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// End-to-end proof, through the real proxy against a real PostgreSQL target DB, that a
// diagnostic-redacted connection (Verdict.sanitize_diagnostics) never relays a stored value in a target DB
// error's fields — the whole-row `DETAIL: Failing row contains (…)` leak from the design — while a
// non-redacted connection does (so the test exercises a genuine leak the redaction closes). Complements the
// unit-level field-strip tests. See docs/diagnostic-redaction.md.

const diagSentinel = "010-1234-5678"

// seedDiagLeakTable creates a row whose `secret` column holds the sentinel and a CHECK the next UPDATE will
// violate. The failing UPDATE names only `amount`, but PostgreSQL's `Failing row contains (…)` DETAIL dumps
// the whole stored row — including `secret` the statement never referenced.
func seedDiagLeakTable(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	for _, sql := range []string{
		"DROP TABLE IF EXISTS it_pgproxy.diag_leak",
		"CREATE TABLE it_pgproxy.diag_leak (id int PRIMARY KEY, secret text, amount int CHECK (amount >= 0))",
		"INSERT INTO it_pgproxy.diag_leak VALUES (1, '" + diagSentinel + "', 100)",
	} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
}

func TestDiagnosticRedactionStripsWholeRowDetailEndToEnd(t *testing.T) {
	h := startBroker(t)
	var sanitize atomic.Bool
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: sanitize.Load()}), nil
	}
	ctx := context.Background()
	const failingUpdate = "UPDATE it_pgproxy.diag_leak SET amount = -1 WHERE id = 1"

	// Redacted connection: the CHECK violation must reach the client as code + severity only.
	sanitize.Store(true)
	redacted, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect (redacted): %v", err)
	}
	seedDiagLeakTable(t, redacted)

	_, err = redacted.Exec(ctx, failingUpdate)
	var pgErr *pgconn.PgError
	if err == nil || !errors.As(err, &pgErr) {
		t.Fatalf("UPDATE error = %T %v, want *pgconn.PgError", err, err)
	}
	if pgErr.Code != "23514" {
		t.Errorf("SQLSTATE = %q, want 23514 preserved for a usable error", pgErr.Code)
	}
	if pgErr.Severity == "" {
		t.Error("severity was dropped; the client needs it to classify the error")
	}
	if pgErr.Detail != "" {
		t.Errorf("Detail survived redaction: %q", pgErr.Detail)
	}
	// The sentinel must not appear in ANY field the client received.
	if blob := pgErr.Message + pgErr.Detail + pgErr.Hint + pgErr.Where + pgErr.InternalQuery +
		pgErr.SchemaName + pgErr.TableName + pgErr.ColumnName + pgErr.ConstraintName; strings.Contains(blob, diagSentinel) {
		t.Errorf("stored value leaked through a redacted error field: %q", blob)
	}

	// Control: a non-redacted connection genuinely leaks the stored value in DETAIL, proving the redaction
	// above is what closes a real leak (not an artifact of the test).
	sanitize.Store(false)
	plain, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect (control): %v", err)
	}
	_, err = plain.Exec(ctx, failingUpdate)
	if err == nil || !errors.As(err, &pgErr) {
		t.Fatalf("control UPDATE error = %T %v, want *pgconn.PgError", err, err)
	}
	if !strings.Contains(pgErr.Detail, diagSentinel) {
		t.Fatalf("control connection did not leak the stored value in DETAIL (%q) — the test is not exercising a real leak", pgErr.Detail)
	}
}

func TestDiagnosticRedactionForwardsNoticeEvenWhenRedacted(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: true}), nil
	}
	ctx := context.Background()

	var notices []string
	config, err := pgx.ParseConfig(fmt.Sprintf("postgres://pm:%s@%s/app", validToken, h.addr))
	if err != nil {
		t.Fatalf("pgx.ParseConfig: %v", err)
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	config.RuntimeParams["client_min_messages"] = "notice"
	config.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { notices = append(notices, n.Message) }
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect with notice sink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })

	// A benign server NOTICE ("table ... does not exist, skipping") carries no row value, so it is forwarded
	// even on a redacted connection: notices are advisory and the only value-bearing notice is RAISE NOTICE,
	// which needs PL/pgSQL and is denied at the control plane (a DO block classifies as OTHER → deny) — the
	// closure is enforcement, not dropping notices here.
	if _, err := conn.Exec(ctx, "DROP TABLE IF EXISTS it_pgproxy.diag_no_such_table"); err != nil {
		t.Fatalf("DROP TABLE IF EXISTS: %v", err)
	}
	if len(notices) == 0 {
		t.Error("expected the skip-notice to be forwarded on a redacted connection, got none")
	}
}
