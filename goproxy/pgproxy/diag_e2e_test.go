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
	"github.com/ridi-oss/proxy-monster/goproxy/pgproxy"
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

// pgKeptCase raises one allowlisted template with ordinary SQL; setup and cleanup run on the same session
// around each attempt.
type pgKeptCase struct {
	code, template, sql string
	setup, cleanup      []string
}

var (
	asNoPerm  = []string{"SET ROLE diag_noperm"}
	resetRole = []string{"RESET ROLE"}
)

// pgKeptCases covers every template in pgSchemaMessages except pgUnitOnlyTemplates.
var pgKeptCases = []pgKeptCase{
	{"42P01", `missing FROM-clause entry for table "%s"`, "SELECT x.id FROM it_pgproxy.diag_orders o", nil, nil},
	{"42P01", `table "%s" does not exist`, "DROP TABLE it_pgproxy.diag_nosuch", nil, nil},
	{"42P01", `view "%s" does not exist`, "DROP VIEW it_pgproxy.diag_nosuch", nil, nil},
	{"42P01", `sequence "%s" does not exist`, "DROP SEQUENCE it_pgproxy.diag_nosuch", nil, nil},
	{"42P01", `materialized view "%s" does not exist`, "DROP MATERIALIZED VIEW it_pgproxy.diag_nosuch", nil, nil},
	{"42P07", `relation "%s" already exists`, "CREATE TABLE it_pgproxy.diag_orders (a int)", nil, nil},
	{"42703", `column "%s" does not exist`, "SELECT shipped_at FROM it_pgproxy.diag_orders", nil, nil},
	{"42703", `column %i.%i does not exist`, "SELECT o.shipped_at FROM it_pgproxy.diag_orders o", nil, nil},
	{"42703", `column "%s" referenced in foreign key constraint does not exist`,
		"CREATE TABLE it_pgproxy.diag_new (a int, FOREIGN KEY (z) REFERENCES it_pgproxy.diag_orders (id))", nil, nil},
	{"42701", `column "%s" specified more than once`, "INSERT INTO it_pgproxy.diag_orders (id, id) VALUES (1, 1)", nil, nil},
	{"42701", `column "%s" of relation "%s" already exists`, "ALTER TABLE it_pgproxy.diag_orders ADD COLUMN email text", nil, nil},
	{"42702", `column reference "%s" is ambiguous`, "SELECT id FROM it_pgproxy.diag_orders, it_pgproxy.diag_items", nil, nil},
	{"42704", `index "%s" does not exist`, "DROP INDEX it_pgproxy.diag_nosuch", nil, nil},
	{"42704", `constraint "%s" of relation "%s" does not exist`, "ALTER TABLE it_pgproxy.diag_orders DROP CONSTRAINT diag_nosuch", nil, nil},
	{"42P06", `schema "%s" already exists`, "CREATE SCHEMA it_pgproxy", nil, nil},
	{"42710", `constraint "%s" for relation "%s" already exists`,
		"ALTER TABLE it_pgproxy.diag_orders ADD CONSTRAINT diag_orders_amount_check CHECK (amount > 1)", nil, nil},
	{"42710", `trigger "%s" for relation "%s" already exists`,
		"CREATE TRIGGER diag_trg BEFORE INSERT ON it_pgproxy.diag_items FOR EACH ROW EXECUTE FUNCTION it_pgproxy.diag_trgfn()", nil, nil},
	{"42710", `type "%s" already exists`, "CREATE TYPE it_pgproxy.diag_type AS (a int)", nil, nil},
	{"42723", `function "%s" already exists with same argument types`,
		"CREATE FUNCTION it_pgproxy.diag_fn(int) RETURNS int LANGUAGE sql AS 'SELECT $1'", nil, nil},
	{"42804", `column "%s" is of type %t but expression is of type %t`, "UPDATE it_pgproxy.diag_orders SET amount = 'x'::text", nil, nil},
	{"42501", `permission denied for table %i`, "SELECT * FROM it_pgproxy.diag_orders", asNoPerm, resetRole},
	{"42501", `permission denied for view %i`, "SELECT * FROM it_pgproxy.diag_v", asNoPerm, resetRole},
	{"42501", `permission denied for materialized view %i`, "SELECT * FROM it_pgproxy.diag_mv", asNoPerm, resetRole},
	{"42501", `permission denied for sequence %i`, "SELECT nextval('it_pgproxy.diag_seq')", asNoPerm, resetRole},
	{"42501", `permission denied for schema %i`, "SELECT * FROM it_diag_private.t", asNoPerm, resetRole},
	{"42501", `permission denied for function %i`, "SELECT it_pgproxy.diag_fn(1)", asNoPerm, resetRole},
	{"42501", `permission denied for procedure %i`, "CALL it_pgproxy.diag_proc()", asNoPerm, resetRole},
	{"23502", `null value in column "%s" of relation "%s" violates not-null constraint`,
		"INSERT INTO it_pgproxy.diag_orders VALUES (2, 10, 'b', NULL)", nil, nil},
	{"23505", `duplicate key value violates unique constraint "%s"`,
		"INSERT INTO it_pgproxy.diag_orders VALUES (3, 10, '" + diagSentinel + "', 'new')", nil, nil},
	{"23503", `insert or update on table "%s" violates foreign key constraint "%s"`, "INSERT INTO it_pgproxy.diag_items VALUES (2, 99)", nil, nil},
	{"23503", `update or delete on table "%s" violates foreign key constraint "%s" on table "%s"`,
		"DELETE FROM it_pgproxy.diag_orders WHERE id = 1", nil, nil},
	{"23514", `new row for relation "%s" violates check constraint "%s"`, "UPDATE it_pgproxy.diag_orders SET amount = -1 WHERE id = 1", nil, nil},
	{"23514", `check constraint "%s" of relation "%s" is violated by some row`,
		"ALTER TABLE it_pgproxy.diag_neg ADD CONSTRAINT diag_neg_pos CHECK (a > 0)", nil, nil},
	{"23P01", `conflicting key value violates exclusion constraint "%s"`, "INSERT INTO it_pgproxy.diag_circles VALUES ('<(0,0),1>')", nil, nil},
}

// pgUnitOnlyTemplates are allowlisted templates ordinary SQL on a test server cannot raise.
var pgUnitOnlyTemplates = []struct{ code, template, reason string }{}

// On a redacted connection every allowlisted PostgreSQL template a test server can raise keeps its primary
// message exactly as the target DB sent it, while Detail is still dropped and a value-carrying message is
// replaced by its condition name.
func TestDiagnosticRedactionKeepsSchemaOnlyMessageEndToEnd(t *testing.T) {
	h := startBroker(t)
	var sanitize atomic.Bool
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: sanitize.Load()}), nil
	}
	ctx := context.Background()
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	for _, sql := range []string{
		"DROP TABLE IF EXISTS it_pgproxy.diag_items, it_pgproxy.diag_orders, it_pgproxy.diag_neg, it_pgproxy.diag_circles CASCADE",
		"DROP SEQUENCE IF EXISTS it_pgproxy.diag_seq",
		"DROP TYPE IF EXISTS it_pgproxy.diag_type",
		"DROP FUNCTION IF EXISTS it_pgproxy.diag_fn(int), it_pgproxy.diag_trgfn()",
		"DROP PROCEDURE IF EXISTS it_pgproxy.diag_proc()",
		"DROP SCHEMA IF EXISTS it_diag_private CASCADE",
		"DO $$ BEGIN CREATE ROLE diag_noperm NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$",
		"GRANT USAGE ON SCHEMA it_pgproxy TO diag_noperm",
		"CREATE TABLE it_pgproxy.diag_orders (id int PRIMARY KEY, amount int CHECK (amount > 0), " +
			"email text UNIQUE, status text NOT NULL)",
		"CREATE TABLE it_pgproxy.diag_items (id int, order_id int REFERENCES it_pgproxy.diag_orders (id))",
		"INSERT INTO it_pgproxy.diag_orders VALUES (1, 10, '" + diagSentinel + "', 'paid')",
		"INSERT INTO it_pgproxy.diag_items VALUES (1, 1)",
		"CREATE VIEW it_pgproxy.diag_v AS SELECT id FROM it_pgproxy.diag_orders",
		"CREATE MATERIALIZED VIEW it_pgproxy.diag_mv AS SELECT id FROM it_pgproxy.diag_orders",
		"CREATE SEQUENCE it_pgproxy.diag_seq",
		"CREATE FUNCTION it_pgproxy.diag_fn(int) RETURNS int LANGUAGE sql AS 'SELECT $1'",
		"REVOKE EXECUTE ON FUNCTION it_pgproxy.diag_fn(int) FROM PUBLIC",
		"CREATE PROCEDURE it_pgproxy.diag_proc() LANGUAGE sql AS 'SELECT 1'",
		"REVOKE EXECUTE ON PROCEDURE it_pgproxy.diag_proc() FROM PUBLIC",
		"CREATE FUNCTION it_pgproxy.diag_trgfn() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'",
		"CREATE TRIGGER diag_trg BEFORE INSERT ON it_pgproxy.diag_items FOR EACH ROW EXECUTE FUNCTION it_pgproxy.diag_trgfn()",
		"CREATE TYPE it_pgproxy.diag_type AS (a int)",
		"CREATE TABLE it_pgproxy.diag_neg (a int)",
		"INSERT INTO it_pgproxy.diag_neg VALUES (-1)",
		"CREATE TABLE it_pgproxy.diag_circles (c circle, EXCLUDE USING gist (c WITH &&))",
		"INSERT INTO it_pgproxy.diag_circles VALUES ('<(0,0),1>')",
		"CREATE SCHEMA it_diag_private",
	} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec := func(redact bool, sql string, setup, cleanup []string) *pgconn.PgError {
		t.Helper()
		sanitize.Store(redact)
		for _, q := range setup {
			if _, err := conn.Exec(ctx, q); err != nil {
				t.Fatalf("%s: setup %q: %v", sql, q, err)
			}
		}
		_, err := conn.Exec(ctx, sql)
		for _, q := range cleanup {
			if _, cerr := conn.Exec(ctx, q); cerr != nil {
				t.Fatalf("%s: cleanup %q: %v", sql, q, cerr)
			}
		}
		var pgErr *pgconn.PgError
		if err == nil || !errors.As(err, &pgErr) {
			t.Fatalf("%s: error = %T %v, want *pgconn.PgError", sql, err, err)
		}
		return pgErr
	}
	run := func(redact bool, sql string) *pgconn.PgError {
		t.Helper()
		return exec(redact, sql, nil, nil)
	}

	for _, c := range pgKeptCases {
		raw := exec(false, c.sql, c.setup, c.cleanup)
		got := exec(true, c.sql, c.setup, c.cleanup)
		if raw.Code != c.code || got.Code != c.code {
			t.Errorf("%s: SQLSTATE raw=%s %q redacted=%s, want %s", c.sql, raw.Code, raw.Message, got.Code, c.code)
			continue
		}
		if !pgproxy.MatchesSchemaTemplate(c.code, c.template, raw.Message) {
			t.Errorf("%s: target DB message %q does not match template %q", c.sql, raw.Message, c.template)
		}
		if got.Message != raw.Message {
			t.Errorf("%s: redacted message = %q, want the target DB message %q", c.sql, got.Message, raw.Message)
		}
		if got.Detail != "" {
			t.Errorf("%s: Detail survived redaction: %q", c.sql, got.Detail)
		}
	}

	// These messages carry only a name here, but a resolver can turn a run-time value into that name
	// (::regclass, ::regtype, ::regnamespace, ::regoper, has_column_privilege, pg_get_object_address — see
	// TestDiagnosticRedactionDropsValueToNameTemplatesEndToEnd), so the template is not allowlisted and even a
	// statement-text name strips to the condition name.
	strippedSchemaCode := []struct{ code, condition, sql string }{
		{"42P01", "undefined_table", "SELECT * FROM it_pgproxy.diag_no_such_table"},
		{"42704", "undefined_object", "SELECT 1::diag_no_such_type"},
		{"42883", "undefined_function", "SELECT 1 + 'a'::text"},
		{"42883", "undefined_function", "SELECT diag_no_such_function(1, 'x')"},
		{"42703", "undefined_column", "UPDATE it_pgproxy.diag_orders SET shipped_at = 1"},
		{"3F000", "invalid_schema_name", "CREATE TABLE diag_no_such_schema.t (a int)"},
	}
	for _, c := range strippedSchemaCode {
		if got := run(true, c.sql); got.Code != c.code || got.Message != c.condition {
			t.Errorf("%s: redacted = %s %q, want %s %q (template not allowlisted)", c.sql, got.Code, got.Message, c.code, c.condition)
		}
	}

	const conversion = "UPDATE it_pgproxy.diag_orders SET amount = email::int WHERE id = 1"
	if raw := run(false, conversion); !strings.Contains(raw.Message, diagSentinel) {
		t.Fatalf("control message %q does not echo the stored value; the case is not exercising a leak", raw.Message)
	}
	if got := run(true, conversion); got.Code != "22P02" || got.Message != "invalid_text_representation" {
		t.Errorf("redacted conversion error = %s %q, want 22P02 invalid_text_representation", got.Code, got.Message)
	}
}

// Every allowlisted template is either raised end to end above or consciously listed as unit-only.
func TestPgSchemaMessagesCoveredEndToEnd(t *testing.T) {
	covered := map[[2]string]bool{}
	for _, c := range pgKeptCases {
		covered[[2]string{c.code, c.template}] = true
	}
	for _, u := range pgUnitOnlyTemplates {
		key := [2]string{u.code, u.template}
		if covered[key] {
			t.Errorf("%s %q is both raised end to end and listed unit-only", u.code, u.template)
		}
		covered[key] = true
	}
	allowlisted := map[[2]string]bool{}
	for code, templates := range pgproxy.SchemaMessageTemplates() {
		for _, template := range templates {
			key := [2]string{code, template}
			allowlisted[key] = true
			if !covered[key] {
				t.Errorf("allowlisted %s %q has no end-to-end case and is not listed unit-only", code, template)
			}
		}
	}
	for key := range covered {
		if !allowlisted[key] {
			t.Errorf("%s %q is covered but not allowlisted", key[0], key[1])
		}
	}
}

// A PostgreSQL object-name resolver that takes a string argument reports the string back in its error, so a
// masked column fed to one would launder a stored value into a diagnostic that an allowlisted schema-name
// template would relay. Enforcement denies a masked column as such an argument; this isolates the redaction
// layer (allow-all fake CP, sanitize on) and proves no stored value reaches the client even if the statement
// executes — i.e. the leaking templates are not allowlisted, and the Where/InternalQuery fields that echo
// run-time text are dropped. The control connection proves each vector genuinely carries the value.
func TestDiagnosticRedactionDropsValueToNameTemplatesEndToEnd(t *testing.T) {
	h := startBroker(t)
	var sanitize atomic.Bool
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: sanitize.Load()}), nil
	}
	ctx := context.Background()
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Two stored values: a bare word reaches the type/collation resolvers (a value with punctuation
	// syntax-errors before it names an object), and the realistic dash-bearing form a column actually holds.
	const word = "topsecretword"
	for _, sql := range []string{
		"DROP TABLE IF EXISTS it_pgproxy.diag_names",
		"CREATE TABLE it_pgproxy.diag_names (id int, secret text)",
		"INSERT INTO it_pgproxy.diag_names VALUES (1, '" + word + "'), (2, '" + diagSentinel + "')",
	} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}

	// Each vector puts the stored `secret` into an error field, mostly as an object name. id=1 holds the bare word (it reaches the
	// type/collation resolvers, which syntax-error on a value with punctuation before it names an object);
	// id=2 holds the dash-bearing sentinel a column realistically carries.
	vectors := []string{
		"SELECT secret::regclass FROM it_pgproxy.diag_names WHERE id = 1",
		"SELECT secret::regtype FROM it_pgproxy.diag_names WHERE id = 1",
		"SELECT secret::regnamespace FROM it_pgproxy.diag_names WHERE id = 1",
		"SELECT secret::regoper FROM it_pgproxy.diag_names WHERE id = 1",
		"SELECT secret::regcollation FROM it_pgproxy.diag_names WHERE id = 1",
		"SELECT secret::regclass FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT nextval(secret) FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT currval(secret) FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT has_table_privilege(secret, 'select') FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT has_column_privilege(secret, 'x', 'select') FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT has_schema_privilege(secret, 'usage') FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT has_sequence_privilege(secret, 'usage') FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT pg_relation_size(secret) FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT pg_table_size(secret) FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT pg_total_relation_size(secret) FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT pg_get_serial_sequence(secret, 'x') FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT has_column_privilege('it_pgproxy.diag_names', secret, 'select') FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT pg_get_serial_sequence('it_pgproxy.diag_names', secret) FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT pg_get_object_address('function', ARRAY[secret], '{}') FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT pg_get_object_address('procedure', ARRAY[secret], '{}') FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT pg_get_object_address('trigger', ARRAY['it_pgproxy', 'diag_names', secret], '{}') " +
			"FROM it_pgproxy.diag_names WHERE id = 2",
		// Run-time SQL text: any template can carry the value, and InternalQuery echoes it.
		"SELECT query_to_xml('SELECT ' || secret, true, false, '') FROM it_pgproxy.diag_names WHERE id = 1",
		"SELECT query_to_xml('SELECT x.' || secret || ' FROM it_pgproxy.diag_names x', true, false, '') " +
			"FROM it_pgproxy.diag_names WHERE id = 1",
		"SELECT query_to_xml('SELECT 1/0 WHERE ''' || secret || ''' <> ''''', true, false, '') " +
			"FROM it_pgproxy.diag_names WHERE id = 2",
		"SELECT * FROM ts_stat((SELECT 'SELECT ' || secret FROM it_pgproxy.diag_names WHERE id = 1))",
		// An input function reports the text it failed on in Where.
		`SELECT ('{"value":"' || secret || '"')::json FROM it_pgproxy.diag_names WHERE id = 2`,
		"SELECT * FROM it_pgproxy.diag_names WHERE secret::regclass IS NOT NULL",
		"SELECT (SELECT secret FROM it_pgproxy.diag_names WHERE id = 2 LIMIT 1)::regclass",
	}
	stored := []string{word, diagSentinel}
	for _, vsql := range vectors {
		// Control: the vector genuinely carries a stored value into the target DB's error.
		sanitize.Store(false)
		_, err := conn.Exec(ctx, vsql)
		var pgErr *pgconn.PgError
		if err == nil || !errors.As(err, &pgErr) {
			t.Errorf("%s: control error = %T %v, want *pgconn.PgError", vsql, err, err)
			continue
		}
		if control := pgErrorFields(pgErr); !strings.Contains(control, word) && !strings.Contains(control, diagSentinel) {
			t.Errorf("%s: control error %q carries no stored value; vector is not exercising a leak", vsql, control)
			continue
		}
		// Redacted: no stored value may appear in any client-visible field.
		sanitize.Store(true)
		_, err = conn.Exec(ctx, vsql)
		if err == nil || !errors.As(err, &pgErr) {
			t.Errorf("%s: redacted error = %T %v, want *pgconn.PgError", vsql, err, err)
			continue
		}
		blob := pgErrorFields(pgErr)
		for _, s := range stored {
			if strings.Contains(blob, s) {
				t.Errorf("%s: stored value %q leaked through the redacted error: %q", vsql, s, blob)
			}
		}
	}
}

func pgErrorFields(e *pgconn.PgError) string {
	return strings.Join([]string{e.Message, e.Detail, e.Hint, e.Where, e.InternalQuery, e.SchemaName, e.TableName,
		e.ColumnName, e.DataTypeName, e.ConstraintName}, "|")
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
