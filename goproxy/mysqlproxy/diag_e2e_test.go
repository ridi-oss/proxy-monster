package mysqlproxy_test

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-sql-driver/mysql"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// End-to-end proof through the real proxy that a diagnostic-redacted connection strips a
// backend ERR packet to essno + SQLSTATE + the generic message, and relays it verbatim otherwise. MySQL's
// stored-value diagnostic leak is chiefly the SHOW WARNINGS buffer, denied at the control plane;
// this validates the ERR-packet message strip that closes the inline-error surface. A recognizable
// token embedded in a nonexistent table name stands in for the echoed content the message must not carry.
// See docs/diagnostic-redaction.md.
func TestDiagnosticRedactionStripsMysqlErrPacketEndToEnd(t *testing.T) {
	h := startBroker(t)
	var sanitize atomic.Bool
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: sanitize.Load()}), nil
	}
	const token = "diag_010_1234_5678"
	query := "SELECT * FROM " + primarySchema + "." + token

	// Redacted: the 1146 ERR reaches the client as essno + generic message only.
	sanitize.Store(true)
	redacted := h.openDB(t, validToken)
	_, err := redacted.Exec(query)
	var myErr *mysql.MySQLError
	if err == nil || !errors.As(err, &myErr) {
		t.Fatalf("error = %T %v, want *mysql.MySQLError", err, err)
	}
	if myErr.Number != 1146 {
		t.Errorf("essno = %d, want 1146 preserved for a usable error", myErr.Number)
	}
	if myErr.Message != "ER_NO_SUCH_TABLE" {
		t.Errorf("message = %q, want the essno symbol", myErr.Message)
	}
	if strings.Contains(myErr.Message, token) {
		t.Errorf("the token leaked through the redacted message: %q", myErr.Message)
	}

	// Control: without redaction the backend message is relayed verbatim (token present), proving the
	// redaction above is what strips it.
	sanitize.Store(false)
	plain := h.openDB(t, validToken)
	_, err = plain.Exec(query)
	if err == nil || !errors.As(err, &myErr) {
		t.Fatalf("control error = %T %v, want *mysql.MySQLError", err, err)
	}
	if !strings.Contains(myErr.Message, token) {
		t.Fatalf("control message did not echo the token (%q) — the test is not exercising a real strip", myErr.Message)
	}
}

// The error-based extraction attack confirmed in the field — `extractvalue(1, concat(0x7e,
// (SELECT <masked col> …)))` puts the stored value directly into a 1105 XPATH error message, returned on the
// query itself with no SHOW WARNINGS / GET DIAGNOSTICS read-back. This is defense-in-depth behind the CP's
// own lineage enforcement (a masked column in a non-output position is denied before the statement runs);
// this test isolates the redaction layer with an allow-all fake CP to prove the ERR-packet strip still
// removes the value if the statement ever reaches the backend.
func TestDiagnosticRedactionStripsErrorBasedExtractionEndToEnd(t *testing.T) {
	h := startBroker(t)
	var sanitize atomic.Bool
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: sanitize.Load()}), nil
	}
	const sentinel = "010-1234-5678"

	sanitize.Store(true)
	redacted := h.openDB(t, validToken)
	for _, ddl := range []string{
		"DROP TABLE IF EXISTS " + primarySchema + ".diag_xxe",
		"CREATE TABLE " + primarySchema + ".diag_xxe (secret VARCHAR(64))",
		"INSERT INTO " + primarySchema + ".diag_xxe VALUES ('" + sentinel + "')",
	} {
		if _, err := redacted.Exec(ddl); err != nil {
			t.Fatalf("seed %q: %v", ddl, err)
		}
	}
	xxe := "SELECT extractvalue(1, concat(0x7e, (SELECT secret FROM " + primarySchema + ".diag_xxe LIMIT 1)))"

	// Redacted: the 1105 XPATH error must reach the client stripped of the extracted value.
	_, err := redacted.Exec(xxe)
	var myErr *mysql.MySQLError
	if err == nil || !errors.As(err, &myErr) {
		t.Fatalf("error = %T %v, want *mysql.MySQLError", err, err)
	}
	if myErr.Message != "ER_UNKNOWN_ERROR" {
		t.Errorf("message = %q, want the essno symbol (ER_UNKNOWN_ERROR is the extractvalue catch-all)", myErr.Message)
	}
	if strings.Contains(myErr.Message, sentinel) {
		t.Errorf("error-based extraction leaked the stored value through the redacted message: %q", myErr.Message)
	}

	// Control: without redaction the 1105 error echoes the stored value, proving the attack is genuine.
	sanitize.Store(false)
	plain := h.openDB(t, validToken)
	_, err = plain.Exec(xxe)
	if err == nil || !errors.As(err, &myErr) {
		t.Fatalf("control error = %T %v, want *mysql.MySQLError", err, err)
	}
	if !strings.Contains(myErr.Message, sentinel) {
		t.Fatalf("control did not leak the stored value (%q) — not exercising the real attack", myErr.Message)
	}
}
