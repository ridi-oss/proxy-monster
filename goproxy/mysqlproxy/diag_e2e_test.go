package mysqlproxy_test

import (
	"database/sql"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-sql-driver/mysql"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// End-to-end through the real proxy and target DB: on a diagnostic-redacted connection an error whose
// message names only schema objects reaches the client exactly as the target DB sent it, and an error that
// echoes a stored value or a statement fragment carries only its essno symbol. The control connection
// (no redaction) proves each value case genuinely leaks. Run against every MySQL series in db-support.json
// via PM_TEST_MYSQL_IMAGE. See docs/diagnostic-redaction.md.
func TestDiagnosticRedactionMysqlErrPacketEndToEnd(t *testing.T) {
	h := startBroker(t)
	var sanitize atomic.Bool
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: sanitize.Load()}), nil
	}
	const sentinel = "010-1234-5678"
	s := primarySchema

	db := h.openDB(t, validToken)
	for _, ddl := range []string{
		"DROP TABLE IF EXISTS " + s + ".diag_items",
		"DROP TABLE IF EXISTS " + s + ".diag_orders",
		"CREATE TABLE " + s + ".diag_orders (id INT PRIMARY KEY, amount INT, email VARCHAR(64) UNIQUE, " +
			"status VARCHAR(16) NOT NULL, created INT NOT NULL, CONSTRAINT diag_amount_positive CHECK (amount > 0))",
		"CREATE TABLE " + s + ".diag_items (id INT, order_id INT, " +
			"CONSTRAINT diag_items_order_fk FOREIGN KEY (order_id) REFERENCES " + s + ".diag_orders (id))",
		"INSERT INTO " + s + ".diag_orders VALUES (1, 10, '" + sentinel + "', 'paid', 1)",
		"INSERT INTO " + s + ".diag_items VALUES (1, 1)",
	} {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("seed %q: %v", ddl, err)
		}
	}
	run := func(redact bool, query string) *mysql.MySQLError {
		t.Helper()
		sanitize.Store(redact)
		return mysqlError(t, db, query)
	}

	kept := []struct {
		essno uint16
		query string
	}{
		{1146, "SELECT * FROM " + s + ".diag_no_such_table"},
		{1054, "SELECT shipped_at FROM " + s + ".diag_orders"},
		{1050, "CREATE TABLE " + s + ".diag_orders (a INT)"},
		{1052, "SELECT id FROM " + s + ".diag_orders, " + s + ".diag_items"},
		{1048, "INSERT INTO " + s + ".diag_orders VALUES (2, 10, 'b', NULL, 1)"},
		{1364, "INSERT INTO " + s + ".diag_orders (id, amount, email, status) VALUES (3, 10, 'c', 'new')"},
		{3819, "INSERT INTO " + s + ".diag_orders VALUES (4, -1, 'd', 'new', 1)"},
		{1452, "INSERT INTO " + s + ".diag_items VALUES (2, 99)"},
		{1451, "DELETE FROM " + s + ".diag_orders WHERE id = 1"},
		{1091, "ALTER TABLE " + s + ".diag_orders DROP INDEX diag_no_such_index"},
		{1305, "SELECT " + s + ".diag_no_such_function()"},
		{1055, "SELECT status, count(*) FROM " + s + ".diag_orders GROUP BY email"},
	}
	for _, c := range kept {
		raw := run(false, c.query)
		got := run(true, c.query)
		if raw.Number != c.essno || got.Number != c.essno {
			t.Errorf("%s: essno raw=%d redacted=%d, want %d", c.query, raw.Number, got.Number, c.essno)
			continue
		}
		if got.Message != raw.Message {
			t.Errorf("%s: redacted message = %q, want the target DB message %q", c.query, got.Message, raw.Message)
		}
	}

	stripped := []struct {
		essno  uint16
		symbol string
		query  string
	}{
		{1062, "ER_DUP_ENTRY", "INSERT INTO " + s + ".diag_orders VALUES (5, 10, '" + sentinel + "', 'new', 1)"},
		{1366, "ER_TRUNCATED_WRONG_VALUE_FOR_FIELD", "INSERT INTO " + s + ".diag_orders VALUES (6, 'x" + sentinel + "', 'f', 'new', 1)"},
		{1064, "ER_PARSE_ERROR", "SELECT * FROM " + s + ".diag_orders WHERE email = = '" + sentinel + "'"},
	}
	for _, c := range stripped {
		raw := run(false, c.query)
		if !strings.Contains(raw.Message, sentinel) {
			t.Errorf("%s: control message %q does not echo the value; the case is not exercising a leak", c.query, raw.Message)
		}
		got := run(true, c.query)
		if got.Number != c.essno || got.Message != c.symbol {
			t.Errorf("%s: redacted = %d %q, want %d %q", c.query, got.Number, got.Message, c.essno, c.symbol)
		}
	}
}

func mysqlError(t *testing.T, db *sql.DB, query string) *mysql.MySQLError {
	t.Helper()
	_, err := db.Exec(query)
	var myErr *mysql.MySQLError
	if err == nil || !errors.As(err, &myErr) {
		t.Fatalf("%s: error = %T %v, want *mysql.MySQLError", query, err, err)
	}
	return myErr
}

// The error-based extraction attack confirmed in the field — `extractvalue(1, concat(0x7e,
// (SELECT <masked col> …)))` puts the stored value directly into a 1105 XPATH error message, returned on the
// query itself with no SHOW WARNINGS / GET DIAGNOSTICS read-back. This is defense-in-depth behind the CP's
// own lineage enforcement (a masked column in a non-output position is denied before the statement runs);
// this test isolates the redaction layer with an allow-all fake CP to prove the ERR-packet strip still
// removes the value if the statement ever reaches the target DB.
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
