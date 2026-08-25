package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

func TestStatementFactsResultReadsAreDeterministic(t *testing.T) {
	// Reference (predicate/order/join) columns come from a Go map, so without a stable sort the DENY grants
	// shuffle between runs. The control-plane freezes result_reads as a stored result's fingerprint and
	// compares them for proto equality at view, so a nondeterministic order would falsely deny an unchanged
	// query. Use a query whose unprojected refs span multiple clauses (WHERE + ORDER BY).
	sql := "SELECT id FROM users WHERE email = 'x' ORDER BY ssn"
	first := postgresFacts(t, sql)
	if !first.GetResolved() {
		t.Fatalf("expected resolved facts: %s", first.GetDetail())
	}
	for i := 0; i < 50; i++ {
		if !proto.Equal(first, postgresFacts(t, sql)) {
			t.Fatalf("result_reads order is nondeterministic across analyzer runs (run %d differs)", i)
		}
	}
}

func postgresFacts(t *testing.T, sql string) *pb.StatementFacts {
	t.Helper()
	return analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          sql,
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("acme", "public", "users", "id", "BIGINT"),
			columnSpec("acme", "public", "users", "ssn", "VARCHAR"),
			columnSpec("acme", "public", "users", "email", "VARCHAR"),
			columnSpec("acme", "public", "sink", "id", "BIGINT"),
			columnSpec("acme", "public", "sink", "value", "VARCHAR"),
		},
	})
}

func mysqlFacts(t *testing.T, sql string) *pb.StatementFacts { return mysqlFactsMode(t, sql, false) }

func mysqlFactsMode(t *testing.T, sql string, ansiQuotes bool) *pb.StatementFacts {
	t.Helper()
	cfg := &pb.EngineConfig{
		Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0),
	}
	if ansiQuotes {
		cfg.MysqlAnsiQuotes = proto.Bool(true)
	}
	return analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          sql,
		EngineConfig: cfg,
		Namespace:    &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("def", "acme", "users", "id", "BIGINT"),
			columnSpec("def", "acme", "users", "ssn", "VARCHAR"),
			columnSpec("def", "acme", "users", "email", "VARCHAR"),
			columnSpec("def", "acme", "sink", "id", "BIGINT"),
			columnSpec("def", "acme", "sink", "value", "VARCHAR"),
		},
	})
}

func TestStatementFactsMysqlAnsiQuotesMasksQuotedColumn(t *testing.T) {
	// Under MySQL sql_mode=ANSI_QUOTES the server reads `"ssn"` as the column ssn, not a string. With the
	// mysql_ansi_quotes EngineConfig flag the analyzer parses it the same way, so a masked column quoted
	// with `"` is SEEN (and gated/masked) instead of read as an inert string literal — the wire proxy can
	// forward the ANSI_QUOTES session instead of failing it closed. Without the flag (default mode) `"ssn"`
	// is a string, so it emits no column requirement.
	hasSSNColumnGrant := func(f *pb.StatementFacts) bool {
		for _, g := range f.GetResultReads() {
			if c := g.GetColumn(); c != nil && c.GetIdentity().GetColumn() == "ssn" {
				return true
			}
		}
		return false
	}
	if f := mysqlFactsMode(t, `SELECT "ssn" FROM users`, true); !f.GetResolved() || !hasSSNColumnGrant(f) {
		t.Fatalf("ANSI_QUOTES: `\"ssn\"` must be seen as the masked column ssn: %+v", f)
	}
	if f := mysqlFactsMode(t, `SELECT "ssn" FROM users`, false); hasSSNColumnGrant(f) {
		t.Fatalf("default mode: `\"ssn\"` is a string literal, not a column read: %+v", f)
	}
}

func TestStatementFactsColumnDispositions(t *testing.T) {
	facts := postgresFacts(t, "SELECT ssn, upper(email) AS redacted FROM users WHERE id > 0")
	if !facts.GetResolved() {
		t.Fatalf("expected resolved facts: %s", facts.GetDetail())
	}
	want := map[pb.MaskedDisposition]bool{
		pb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT:        false,
		pb.MaskedDisposition_MASKED_DISPOSITION_REDACT_OUTPUT_NULL: false,
		pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT:     false,
	}
	for _, grant := range facts.GetResultReads() {
		if grant.GetColumn() != nil {
			want[grant.GetMaskedDisposition()] = true
		}
	}
	for disposition, found := range want {
		if !found {
			t.Fatalf("missing column disposition %s in %+v", disposition, facts.GetResultReads())
		}
	}
	if got := facts.GetOutputColumns(); len(got) != 2 || got[0] != "ssn" || got[1] != "redacted" {
		t.Fatalf("unexpected output columns: %v", got)
	}
}

func TestStatementFactsWriteReadSetAlwaysDeniesMasking(t *testing.T) {
	facts := postgresFacts(t, "INSERT INTO sink (value) SELECT ssn FROM users")
	if !facts.GetResolved() {
		t.Fatalf("expected resolved write facts: %+v", facts)
	}
	foundInsert := facts.GetStatementExec().GetStatementKind() == pb.StatementKind_STATEMENT_KIND_INSERT_SELECT
	foundWriteRead := false
	for _, grant := range facts.GetResultReads() {
		if c := grant.GetColumn(); c != nil && c.GetIdentity().GetColumn() == "ssn" &&
			grant.GetMaskedDisposition() == pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT {
			foundWriteRead = true
		}
	}
	if !foundInsert || !foundWriteRead {
		t.Fatalf("missing insert or write-read grant: %+v", facts)
	}
}

func TestStatementFactsInadmissibleCases(t *testing.T) {
	cases := []struct {
		name  string
		facts func(*testing.T, string) *pb.StatementFacts
		sql   string
	}{
		{"batch", postgresFacts, "SELECT 1; SELECT 2"},
		{"reset-master", mysqlFacts, "RESET MASTER"},
		// SET ROLE, a SET/SHOW with a data-reading RHS, and a user-type cast resolve carrying a
		// system:critical Utility grant (SET_ROLE / SET_SUBQUERY / SHOW_SUBQUERY / USER_TYPE_CAST) rather
		// than failing closed. See TestGucAliasPrivilegeSetIsSystemCritical + the parity corpus.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := tc.facts(t, tc.sql)
			if facts.GetResolved() || facts.GetFailureClass() != pb.FailureClass_FAILURE_CLASS_INADMISSIBLE {
				t.Fatalf("expected INADMISSIBLE: %+v", facts)
			}
		})
	}
}

func TestStatementFactsMetadataAndUtilityClassification(t *testing.T) {
	showWarnings := mysqlFacts(t, "SHOW WARNINGS")
	if !showWarnings.GetResolved() || factsKind(showWarnings) != pb.StatementKind_STATEMENT_KIND_SHOW_WARNINGS {
		t.Fatalf("unexpected SHOW facts: %+v", showWarnings)
	}
	if ng := nonExecuteGrants(showWarnings); len(ng) != 1 || ng[0].GetUtility().GetCommand() != "SHOW_WARNINGS" {
		t.Fatalf("SHOW WARNINGS missing utility grant: %+v", showWarnings.GetResultReads())
	}

	describe := mysqlFacts(t, "DESCRIBE users ssn")
	if !describe.GetResolved() || factsKind(describe) != pb.StatementKind_STATEMENT_KIND_DESCRIBE || len(nonExecuteGrants(describe)) != 0 {
		t.Fatalf("unexpected DESCRIBE metadata facts: %+v", describe)
	}
}

func TestStatementFactsExplainAnalyzesInnerQuery(t *testing.T) {
	facts := mysqlFacts(t, "EXPLAIN TABLE users")
	// An EXPLAIN's output is the plan, not the query's columns: no output_columns, and no rewritten SQL.
	if !facts.GetResolved() || len(facts.GetOutputColumns()) != 0 || facts.GetRewrittenSql() != "" {
		t.Fatalf("unexpected EXPLAIN TABLE facts: %+v", facts)
	}
	foundSSN := false
	for _, grant := range facts.GetResultReads() {
		if c := grant.GetColumn(); c != nil && c.GetIdentity().GetColumn() == "ssn" {
			foundSSN = true
		}
	}
	if !foundSSN {
		t.Fatalf("EXPLAIN TABLE did not analyze SELECT * inner query: %+v", facts.GetResultReads())
	}

	descAnalyze := postgresFacts(t, "DESC ANALYZE SELECT ssn FROM users")
	if !descAnalyze.GetResolved() || len(descAnalyze.GetOutputColumns()) != 0 {
		t.Fatalf("DESC ANALYZE did not analyze inner query: %+v", descAnalyze)
	}
}

func TestStatementFactsAnalyzeTableGatesTableRead(t *testing.T) {
	// A table-targeted ANALYZE must carry the same result-read grant SELECT * FROM the table would, so the
	// result-read gate governs it and it is not an existence oracle. Both MySQL `ANALYZE TABLE t` and
	// PostgreSQL `ANALYZE t` target one table to read. The read grants must name THAT table (a second target,
	// `sink`, pins that they follow the target rather than a hardcoded one). Like an EXPLAIN, ANALYZE's output
	// is not the table's rows, so it emits no output_columns and no SELECT rewritten_sql leaks onto the wire.
	for _, tc := range []struct {
		name  string
		facts *pb.StatementFacts
		table string
	}{
		{"mysql ANALYZE TABLE users", mysqlFacts(t, "ANALYZE TABLE users"), "users"},
		{"mysql ANALYZE TABLE sink", mysqlFacts(t, "ANALYZE TABLE sink"), "sink"},
		{"postgres ANALYZE users", postgresFacts(t, "ANALYZE users"), "users"},
		{"postgres ANALYZE sink", postgresFacts(t, "ANALYZE sink"), "sink"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.facts.GetResolved() || factsKind(tc.facts) != pb.StatementKind_STATEMENT_KIND_ANALYZE_TABLE {
				t.Fatalf("expected resolved ANALYZE_TABLE: %+v", tc.facts)
			}
			if len(tc.facts.GetOutputColumns()) != 0 || tc.facts.GetRewrittenSql() != "" {
				t.Fatalf("ANALYZE must not rewrite onto the wire or output the table's columns: %+v", tc.facts)
			}
			// Every emitted column read grant must name the ANALYZE target, and there must be at least one —
			// a grant on a different table would mean the read gate governs the wrong resource.
			gated := false
			for _, grant := range tc.facts.GetResultReads() {
				c := grant.GetColumn()
				if c == nil {
					continue
				}
				if c.GetIdentity().GetTable() != tc.table {
					t.Fatalf("ANALYZE %s emitted a read grant on %q, not the target: %+v", tc.table, c.GetIdentity().GetTable(), grant)
				}
				gated = true
			}
			if !gated {
				t.Fatalf("ANALYZE %s did not gate the table read: %+v", tc.table, tc.facts.GetResultReads())
			}
		})
	}
}

func TestStatementFactsAnalyzeAdversarialFormsFailClosed(t *testing.T) {
	// The two ANALYZE forms that resolve to a table node but must NOT read-gate as a plain table both rely on
	// sqlglot-go's parse/lineage to fail closed: MySQL multi-table `ANALYZE TABLE t1, t2` degrades to a
	// Command (the list tail is unconsumed), and PostgreSQL's column-list `ANALYZE t (col)` parses the target
	// as an anonymous table-valued source that star-expansion refuses. If a future sqlglot-go bump widened
	// either, the synthetic SELECT * could resolve with no grants — connect-only, the oracle reopened. Pin
	// them unresolved so that regression fails here rather than silently.
	if f := mysqlFacts(t, "ANALYZE TABLE users, sink"); f.GetResolved() {
		t.Fatalf("multi-table ANALYZE must fail closed (unresolved), got: %+v", f)
	}
	if f := postgresFacts(t, "ANALYZE users (ssn)"); f.GetResolved() {
		t.Fatalf("column-list ANALYZE must fail closed (unresolved), got: %+v", f)
	}
}

// A plan-only EXPLAIN of a READ is stmt.kind.explain — MySQL EXPLAIN and EXPLAIN ANALYZE, PostgreSQL
// EXPLAIN, and PostgreSQL EXPLAIN ANALYZE of a read all land there (ANALYZE of a read returns a plan, not
// rows). An EXPLAIN of a WRITE keeps the write's own kind, so it authorizes/denies as that write. An
// EXPLAIN's output is the plan, not the query's columns, so `explain` here also means empty output_columns.
func TestStatementFactsExplainKind(t *testing.T) {
	cases := []struct {
		name    string
		facts   *pb.StatementFacts
		explain bool // an EXPLAIN form → output is the plan, so output_columns is empty
		kind    pb.StatementKind
	}{
		{"mysql read plan-only", mysqlFacts(t, "EXPLAIN SELECT ssn FROM users"), true, pb.StatementKind_STATEMENT_KIND_EXPLAIN},
		{"mysql read analyze", mysqlFacts(t, "EXPLAIN ANALYZE SELECT ssn FROM users"), true, pb.StatementKind_STATEMENT_KIND_EXPLAIN},
		{"mysql read desc analyze", mysqlFacts(t, "DESC ANALYZE SELECT ssn FROM users"), true, pb.StatementKind_STATEMENT_KIND_EXPLAIN},
		// A parenthesized target wraps the query in a Subquery; it must still classify, not fall unresolved.
		{"mysql read parenthesized", mysqlFacts(t, "EXPLAIN (SELECT ssn FROM users)"), true, pb.StatementKind_STATEMENT_KIND_EXPLAIN},
		{"mysql read analyze parenthesized", mysqlFacts(t, "EXPLAIN ANALYZE (SELECT ssn FROM users)"), true, pb.StatementKind_STATEMENT_KIND_EXPLAIN},
		{"mysql explain table", mysqlFacts(t, "EXPLAIN TABLE users"), true, pb.StatementKind_STATEMENT_KIND_DESCRIBE},
		// A write keeps its own kind, plan-only or ANALYZE, so it gates + denies as the write. The
		// MATERIALIZING forms are the security boundary — an EXPLAIN ANALYZE that copies masked PII into a
		// new/other table must NOT classify as the read-shaped EXPLAIN kind (which would run unmasked). Each
		// must keep its write kind.
		{"mysql write keeps kind", mysqlFacts(t, "EXPLAIN INSERT INTO users VALUES (1)"), true, pb.StatementKind_STATEMENT_KIND_INSERT},
		{"mysql analyze insert-select materializes", mysqlFacts(t, "EXPLAIN ANALYZE INSERT INTO users (ssn) SELECT ssn FROM users"), true, pb.StatementKind_STATEMENT_KIND_INSERT_SELECT},
		{"mysql analyze select-into-outfile materializes", mysqlFacts(t, "EXPLAIN ANALYZE SELECT ssn INTO OUTFILE '/tmp/x' FROM users"), true, pb.StatementKind_STATEMENT_KIND_SELECT_INTO_OUTFILE},
		{"mysql plain select", mysqlFacts(t, "SELECT ssn FROM users"), false, pb.StatementKind_STATEMENT_KIND_SELECT},
		{"pg read plan-only", postgresFacts(t, "EXPLAIN SELECT ssn FROM users"), true, pb.StatementKind_STATEMENT_KIND_EXPLAIN},
		{"pg read analyze", postgresFacts(t, "EXPLAIN ANALYZE SELECT ssn FROM users"), true, pb.StatementKind_STATEMENT_KIND_EXPLAIN},
		{"pg read analyze wrapped", postgresFacts(t, "EXPLAIN (ANALYZE, FORMAT JSON) SELECT ssn FROM users"), true, pb.StatementKind_STATEMENT_KIND_EXPLAIN},
		{"pg write analyze keeps kind", postgresFacts(t, "EXPLAIN ANALYZE DELETE FROM users WHERE id = 1"), true, pb.StatementKind_STATEMENT_KIND_DELETE},
		{"pg analyze ctas materializes", postgresFacts(t, "EXPLAIN ANALYZE CREATE TABLE leak AS SELECT ssn FROM users"), true, pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
	}
	// The materializing forms must also emit ssn as a write-payload DENY_STATEMENT grant, so a masked reader
	// is denied even where the inner write kind itself is authorized.
	for _, sql := range []string{
		"EXPLAIN ANALYZE INSERT INTO users (ssn) SELECT ssn FROM users",
		"EXPLAIN ANALYZE CREATE TABLE leak AS SELECT ssn FROM users",
	} {
		f := postgresFacts(t, sql)
		denied := false
		for _, g := range f.GetResultReads() {
			if c := g.GetColumn(); c != nil && c.GetIdentity().GetColumn() == "ssn" &&
				g.GetMaskedDisposition() == pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT {
				denied = true
			}
		}
		if !denied {
			t.Errorf("%q: ssn must carry a DENY_STATEMENT write-payload grant: %+v", sql, f.GetResultReads())
		}
	}
	for _, c := range cases {
		if got := len(c.facts.GetOutputColumns()) == 0; got != c.explain {
			t.Errorf("%s: output_columns empty = %v, want %v (an EXPLAIN outputs the plan, not the query's columns)", c.name, got, c.explain)
		}
		if got := factsKind(c.facts); got != c.kind {
			t.Errorf("%s: kind = %v, want %v", c.name, got, c.kind)
		}
	}
}

// The security invariant behind EXPLAIN classification: a statement that would MATERIALIZE data must never
// resolve as the read-shaped STATEMENT_KIND_EXPLAIN, which drops projection masks and can be unmasked by a
// `context.stmt_kind == "explain"` policy. describeKind's classifier (explainInnerIsPlanOnlyRead) is a
// separate signal from the probe's IsWrite; this locks them so a drift (e.g. a modifying CTE, or a new write shape)
// cannot silently reclassify a materializing form as plan-only. Each form must keep a non-EXPLAIN kind OR
// fail closed as unresolved.
func TestExplainNeverResolvesAMaterializingWriteAsPlanOnly(t *testing.T) {
	materializing := []string{
		"EXPLAIN ANALYZE INSERT INTO users (ssn) SELECT ssn FROM users",
		"EXPLAIN ANALYZE CREATE TABLE leak AS SELECT ssn FROM users",
		"EXPLAIN ANALYZE SELECT ssn INTO OUTFILE '/tmp/x' FROM users",
		"EXPLAIN ANALYZE DELETE FROM users WHERE id = 1",
		"EXPLAIN ANALYZE UPDATE users SET ssn = 'x' WHERE id = 1",
		"EXPLAIN WITH w AS (INSERT INTO users (ssn) VALUES ('x')) SELECT ssn FROM users",
		"EXPLAIN ANALYZE MERGE INTO users u USING users s ON u.id = s.id WHEN MATCHED THEN UPDATE SET ssn = s.ssn",
	}
	check := func(engine string, f *pb.StatementFacts, sql string) {
		if f.GetResolved() && factsKind(f) == pb.StatementKind_STATEMENT_KIND_EXPLAIN {
			t.Errorf("[%s] %q: a materializing statement resolved as plan-only EXPLAIN — its masks would drop", engine, sql)
		}
	}
	for _, sql := range materializing {
		check("mysql", mysqlFacts(t, sql), sql)
		check("postgres", postgresFacts(t, sql), sql)
	}
}

// The emission invariant that makes a plan-only EXPLAIN safe: an EXPLAIN's output is the plan, so it clears
// output_columns and every column grant must bind an EMPTY output ordinal. A stray ordinal against the empty
// output_columns fails the control-plane's mask-binding contract (a hard structural deny), which for a write
// EXPLAIN (CTAS, INSERT…SELECT — Origins carry ordinals off the read path) would mask the real write-payload
// deny path and block a legitimate writer. This locks that no EXPLAIN — read- OR write-shaped — emits one.
func TestExplainEmitsNoOutputOrdinal(t *testing.T) {
	explains := []string{
		"EXPLAIN SELECT id, ssn FROM users",
		"EXPLAIN ANALYZE SELECT id, ssn FROM users",
		"EXPLAIN SELECT id FROM users WHERE ssn = 'x'",
		"EXPLAIN TABLE users",
		"EXPLAIN ANALYZE INSERT INTO users (ssn) SELECT ssn FROM users",
		"EXPLAIN ANALYZE CREATE TABLE leak AS SELECT ssn FROM users",
		"EXPLAIN ANALYZE UPDATE users SET ssn = 'x' WHERE id = 1",
		"EXPLAIN ANALYZE DELETE FROM users WHERE id = 1",
	}
	check := func(engine string, f *pb.StatementFacts, sql string) {
		if !f.GetResolved() {
			return
		}
		if cols := f.GetOutputColumns(); len(cols) != 0 {
			t.Errorf("[%s] %q: an EXPLAIN must clear output_columns, got %v", engine, sql, cols)
		}
		for _, g := range f.GetResultReads() {
			if ords := g.GetOutputOrdinals(); len(ords) != 0 {
				t.Errorf("[%s] %q: an EXPLAIN grant on %s bound output ordinal %v against empty output_columns",
					engine, sql, g.GetColumn().GetIdentity().GetColumn(), ords)
			}
		}
	}
	for _, sql := range explains {
		check("mysql", mysqlFacts(t, sql), sql)
		check("postgres", postgresFacts(t, sql), sql)
	}
}

func TestStatementFactsNoFromUnknownFunctionGrant(t *testing.T) {
	facts := postgresFacts(t, "SELECT my_udf()")
	if !facts.GetResolved() {
		t.Fatalf("expected analyzable no-FROM statement: %+v", facts)
	}
	for _, grant := range facts.GetResultReads() {
		if grant.GetFunction().GetName() == "my_udf" {
			return
		}
	}
	t.Fatalf("unknown UDF did not emit Function grant: %+v", facts.GetResultReads())
}

func TestStatementFactsUserTypeCastGated(t *testing.T) {
	// A cast or typed literal to a user (non-built-in) type runs that type's coercion / DOMAIN CHECK — a
	// user function — on the shared target-DB session: code execution + an error-channel leak. It resolves
	// carrying a USER_TYPE_CAST Utility grant (system:critical), gated in every position: no-FROM CAST/::,
	// a qualified target, and a with-FROM read (the domain code runs regardless of the FROM).
	for _, sql := range []string{
		"SELECT CAST('x' AS public.pm_leak_domain)",
		"SELECT 'x'::public.pm_leak_domain",
		"SELECT 'x'::pm_leak_domain",
		"SELECT 1::public.evil_domain FROM users",
		"SELECT CAST('x' AS pm_leak.text)",
		// Typed-literal `type 'literal'` forms (schema-qualified or quoted leaf) are unambiguously a typed
		// literal and run the type's coercion / DOMAIN code — gated, not a relayable column read.
		"SELECT public.pm_leak_domain 'x'",
		`SELECT "pm_leak_domain" 'x'`,
		"SELECT public.pm_leak_domain 'x' FROM users",
		// A USER-SCHEMA quoted-leaf typed literal is still a user type (the quoted leaf is a real relation-
		// level name, not a pg_catalog builtin), so it stays gated.
		`SELECT pm_leak."text" 'x'`,
	} {
		parityUtility(t, sql, "postgres", "USER_TYPE_CAST")
	}
	// Built-in casts, an explicit pg_catalog reference to a built-in in BOTH the `::`/CAST and the typed-
	// literal spelling (sqlglot-go v0.17 resolves `pg_catalog.text 'x'` to the built-in node just like
	// `'x'::pg_catalog.text`), and — critically — a legitimate schema-qualified column with a QUOTED alias
	// (`col AS "x"`, the AST twin of a typed literal, but aliased by an IDENTIFIER token not a STRING) must
	// NOT be flagged as a typed literal.
	for _, sql := range []string{
		"SELECT 1::int", "SELECT '1'::integer", "SELECT 'x'::text",
		"SELECT '{1,2}'::int[]", "SELECT 'x'::pg_catalog.text", "SELECT 1::pg_catalog.int4",
		"SELECT pg_catalog.text 'x'",
		"SELECT int '5'", "SELECT bytea 'deadbeef'",
		`SELECT users.email AS "display" FROM users`, "SELECT id AS x FROM users",
	} {
		facts := postgresFacts(t, sql)
		if !facts.GetResolved() {
			t.Fatalf("built-in cast / legit alias must analyze: %q -> %+v", sql, facts)
		}
	}
}

func TestStatementFactsSchemaQualifiedFunctionGrant(t *testing.T) {
	// sqlglot drops a call's schema qualifier from the function node's own Name(), so `public.version()`
	// would fold onto the safe metadata version() and pass. A non-pg_catalog qualifier is user code: it
	// must emit a Function grant under its fully-qualified name so the control-plane never classifies it
	// as a trusted function (a user function shadowing a safe name is an exfil vector).
	for _, tc := range []struct{ sql, want string }{
		{"SELECT public.version()", "public.version"},
		{"SELECT public.version(), id FROM users", "public.version"},
		{"SELECT pm_leak.upper('x')", "pm_leak.upper"},
	} {
		facts := postgresFacts(t, tc.sql)
		found := false
		for _, grant := range facts.GetResultReads() {
			if grant.GetFunction().GetName() == tc.want {
				found = true
			}
		}
		if !found {
			t.Fatalf("qualified user function %q did not emit %q grant: %+v", tc.sql, tc.want, facts.GetResultReads())
		}
	}
	// A pg_catalog-qualified safe builtin is the trusted system function of that name — no grant.
	if facts := postgresFacts(t, "SELECT pg_catalog.abs(-1)"); len(nonExecuteGrants(facts)) != 0 {
		t.Fatalf("pg_catalog.abs must be safe: %+v", facts.GetResultReads())
	}
	// A bare builtin with a physical source stays on the manifest path; it is not a user-qualified call.
	if facts := postgresFacts(t, "SELECT age(now()), id FROM users"); hasFunctionGrant(facts, "age") {
		t.Fatalf("bare age() must not become an unclassified Function grant: %+v", facts.GetResultReads())
	}
}

func TestStatementFactsPgCatalogQualifierFoldedQuoteAware(t *testing.T) {
	// pg_catalog trust is decided on the qualifier folded through the dialect's quote-aware
	// NormalizeIdentifier, NOT a raw case-insensitive match. An UNQUOTED PG_CATALOG folds to pg_catalog
	// (the system catalog → trusted, no grant); a QUOTED "PG_CATALOG" stays case-sensitive and is a DISTINCT
	// user schema PostgreSQL's case-sensitive pg_ reservation allows to exist, so its function is user code
	// and must be gated. A raw EqualFold would wrongly trust "PG_CATALOG".fn() and let a shadowing user
	// function run as a system builtin.
	for _, sql := range []string{
		"SELECT pg_catalog.version()", "SELECT PG_CATALOG.version()", `SELECT "pg_catalog".version()`,
	} {
		if facts := postgresFacts(t, sql); len(nonExecuteGrants(facts)) != 0 {
			t.Fatalf("qualifier folding to the system catalog must be trusted (no grant): %q -> %+v", sql, facts.GetResultReads())
		}
	}
	// Quoted "PG_CATALOG" (a distinct user schema) is gated under its case-preserved qualified name, and
	// must never smuggle the bare trusted name `version`.
	facts := postgresFacts(t, `SELECT "PG_CATALOG".version()`)
	if !hasFunctionGrant(facts, "PG_CATALOG.version") {
		t.Fatalf(`quoted "PG_CATALOG".version() must emit a case-preserved Function grant: %+v`, facts.GetResultReads())
	}
	if hasFunctionGrant(facts, "version") {
		t.Fatalf(`quoted "PG_CATALOG" smuggled the bare trusted name: %+v`, facts.GetResultReads())
	}
	// Engine-gated: pg_catalog is a PostgreSQL schema. On MySQL a database literally named pg_catalog is
	// ordinary user code, so its function is gated — never trusted as a system builtin.
	if my := mysqlFacts(t, "SELECT pg_catalog.leak()"); !hasFunctionGrant(my, "pg_catalog.leak") {
		t.Fatalf("MySQL pg_catalog.leak() must be gated (pg_catalog is not a MySQL system schema): %+v", my.GetResultReads())
	}
}

func hasFunctionGrant(facts *pb.StatementFacts, name string) bool {
	for _, g := range facts.GetResultReads() {
		if g.GetFunction().GetName() == name {
			return true
		}
	}
	return false
}

// TestStatementFactsStructuredSessionForms locks the sqlglot-go v0.16 structured session/privilege
// shapes the analyzer now reads directly instead of scanning a Command tail: SET PASSWORD (kind=PASSWORD,
// including TO RANDOM and a FOR-user), SHOW CREATE USER (Show{this:"CREATE USER"}), and the RESET node.
func TestStatementFactsStructuredSessionForms(t *testing.T) {
	hasUtility := func(f *pb.StatementFacts, cmd string) bool {
		for _, g := range f.GetResultReads() {
			if g.GetUtility().GetCommand() == cmd {
				return true
			}
		}
		return false
	}
	// SET PASSWORD in every spelling → SET_PASSWORD (system:critical account-credential mutation).
	for _, sql := range []string{"SET PASSWORD = 'x'", "SET PASSWORD FOR 'u'@'h' = 'x'", "SET PASSWORD FOR u TO RANDOM"} {
		if f := mysqlFacts(t, sql); !hasUtility(f, "SET_PASSWORD") {
			t.Fatalf("%q must emit SET_PASSWORD: %+v", sql, f.GetResultReads())
		}
	}
	// SHOW CREATE USER (structured Show node) → SHOW_CREATE_USER (exposes a stored password hash).
	if f := mysqlFacts(t, "SHOW CREATE USER u"); !hasUtility(f, "SHOW_CREATE_USER") {
		t.Fatalf("SHOW CREATE USER must emit SHOW_CREATE_USER: %+v", f.GetResultReads())
	}
	// PostgreSQL RESET (dedicated Reset node) only restores defaults — a benign session passthrough.
	for _, sql := range []string{"RESET role", "RESET ALL", "RESET search_path"} {
		if f := postgresFacts(t, sql); !f.GetResolved() || factsKind(f) != pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR || len(nonExecuteGrants(f)) != 0 {
			t.Fatalf("RESET must be a benign session passthrough: %q -> %+v", sql, f)
		}
	}
}

func TestStatementFactsLexerModeAssignmentGated(t *testing.T) {
	// A lexer-mode GUC must only be assigned a value the analyzer can read at parse time. MySQL evaluates
	// the RHS, so a session variable, CONCAT, or DEFAULT can resolve to ANSI_QUOTES while the rendered
	// text carries no such token — the analyzer would keep parsing the old dialect while the target DB
	// flipped the lexer, so a later `SELECT "ssn" FROM users` returns the protected identifier's value.
	// A value that flips the lexer, or one the analyzer cannot read at parse time, resolves carrying a
	// system:critical Utility grant (the control-plane floor forbids it) — not a hard admission deny.
	for _, sql := range []string{
		"SET sql_mode = CONCAT('AN','SI_QUOTES')",
		"SET sql_mode = @m",
		"SET SESSION sql_mode = @m",
		"SET sql_mode = DEFAULT",
		"SET sql_mode = 1",
	} {
		parityUtility(t, sql, "mysql", "SET_SQL_MODE")
	}
	parityUtility(t, "SET standard_conforming_strings = @x", "postgres", "SET_STANDARD_CONFORMING_STRINGS")
	// A benign user-variable set and a literal, lexer-safe sql_mode stay session passthrough.
	for _, sql := range []string{"SET @m = 'ANSI_QUOTES'", "SET autocommit = 0", "SET sql_mode = 'TRADITIONAL'"} {
		facts := mysqlFacts(t, sql)
		if !facts.GetResolved() || factsKind(facts) != pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR {
			t.Fatalf("benign SET must be session passthrough: %q -> %+v", sql, facts)
		}
	}
}

func TestStatementFactsQualifiedFunctionInSetGated(t *testing.T) {
	// `SET @x = acme.version()` calls a user function that merely SPELLS the safe builtin `version`. If SET
	// admission only inspects the leaf name it looks safe and relays as a zero-grant SESSION passthrough,
	// so a later `SELECT @x` returns whatever the user function read. A qualified non-pg_catalog call is
	// user code and makes the SET inadmissible, e.g. `SET @x = acme.leak_ssn()`.
	for _, sql := range []string{
		"SET @x = acme.version()",
		"SET @x = acme.abs(1)",
		"SET @x = pm_leak.leak_ssn()",
		"SET @x = (SELECT ssn FROM users)",
	} {
		parityUtility(t, sql, "mysql", "SET_SUBQUERY")
	}
	// A pg_catalog-qualified safe builtin and a bare safe builtin stay benign SESSION passthrough.
	for _, sql := range []string{"SET @x = pg_catalog.abs(1)", "SET @x = abs(1)", "SET @x = 5"} {
		facts := mysqlFacts(t, sql)
		if !facts.GetResolved() || factsKind(facts) != pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR {
			t.Fatalf("safe SET must stay session passthrough: %q -> %+v", sql, facts)
		}
	}
}

func TestStatementFactsMultiPartQualifierFunctionGrant(t *testing.T) {
	// A multi-part / computed qualifier whose leaf merely spells `pg_catalog` must NOT enter the trusted
	// branch — its call is user code and must emit a fully-qualified (unclassified) Function grant, never
	// be skipped as a safe system builtin.
	for _, sql := range []string{
		"SELECT foo.pg_catalog.version()",
		"SELECT current_database().public.version()",
	} {
		facts := postgresFacts(t, sql)
		grants := facts.GetResultReads()
		if len(grants) == 0 {
			t.Fatalf("multi-part qualified call must emit a Function grant: %q -> %+v", sql, facts)
		}
		for _, grant := range grants {
			if name := grant.GetFunction().GetName(); name == "version" {
				t.Fatalf("multi-part qualifier smuggled a bare safe name %q: %q", name, sql)
			}
		}
	}
}

func TestStatementFactsPrivilegedSetScopeUtility(t *testing.T) {
	// A privileged scope (GLOBAL / PERSIST / PERSIST_ONLY / PASSWORD) mutates shared server state and must
	// emit its utility grant regardless of the item's POSITION in a multi-assignment SET. sqlglot renders
	// the scope keyword inline, so a `SET GLOBAL` prefix scan misses a privileged item after the first.
	for _, tc := range []struct{ sql, want string }{
		{"SET @a=1, GLOBAL max_connections=1", "SET_GLOBAL"},
		{"SET @a=1, PERSIST max_connections=5000", "SET_PERSIST"},
		{"SET @a=1, PERSIST_ONLY max_connections=5000", "SET_PERSIST_ONLY"},
		{"SET PASSWORD = 'x'", "SET_PASSWORD"},
		{"SET @@GLOBAL.max_connections=1", "SET_GLOBAL"},
		{"SET GLOBAL max_connections=1", "SET_GLOBAL"},
	} {
		facts := mysqlFacts(t, tc.sql)
		found := false
		for _, grant := range facts.GetResultReads() {
			if grant.GetUtility().GetCommand() == tc.want {
				found = true
			}
		}
		if !found {
			t.Fatalf("privileged SET %q did not emit %q utility grant: %+v", tc.sql, tc.want, facts.GetResultReads())
		}
	}
	// A standalone `SET PASSWORD` structures (kind=PASSWORD → SET_PASSWORD utility, above), but a multi-item
	// SET that buries PASSWORD after another item (`SET @a=1, PASSWORD='x'`) degrades to Command on MySQL
	// (sqlglot-go structuring gap — escalated). It carries a credential mutation, so it must not be
	// admin-relaxable: MySQL fails a Command-SET closed UNCONDITIONALLY.
	if facts := mysqlFacts(t, "SET @a=1, PASSWORD='x'"); facts.GetResolved() ||
		facts.GetFailureClass() != pb.FailureClass_FAILURE_CLASS_INADMISSIBLE {
		t.Fatalf("multi-item SET with PASSWORD must fail closed unconditionally: %+v", facts)
	}
	// A benign multi-assignment SET emits no utility grant.
	if facts := mysqlFacts(t, "SET @a=1, autocommit=0"); len(nonExecuteGrants(facts)) != 0 {
		t.Fatalf("benign multi-SET must have no utility grant: %+v", facts.GetResultReads())
	}
}

func TestStatementFactsSetPasswordCommandUtility(t *testing.T) {
	// `SET PASSWORD FOR 'u'@'h' = 'x'` degrades to a Command, not a structured Set — it must still emit the
	// SET_PASSWORD utility grant so it is gated and never relayed verbatim under exception.unanalyzable on dev.
	facts := mysqlFacts(t, "SET PASSWORD FOR 'u'@'h' = 'x'")
	found := false
	for _, grant := range facts.GetResultReads() {
		if grant.GetUtility().GetCommand() == "SET_PASSWORD" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SET PASSWORD FOR must emit SET_PASSWORD utility grant: %+v", facts)
	}
}

func TestStatementFactsTemporaryDDLDoesNotChangeCatalog(t *testing.T) {
	// Temporary-object DDL is session-local — it must NOT set catalog_changing (which schedules a
	// datasource-global catalog refetch). Persistent DDL still does.
	temp := []struct {
		sql string
		my  bool
	}{
		{"DROP TEMPORARY TABLE x", true},
		{"CREATE TEMPORARY TABLE t (id INT)", true},
		{"DROP TABLE pg_temp.x", false},
		// Unquoted PG_TEMP folds to pg_temp (PostgreSQL lowercases unquoted identifiers), and the
		// numbered per-backend form pg_temp_<n> is temp too — both session-local, not catalog-changing.
		{"DROP TABLE PG_TEMP.x", false},
		{"DROP TABLE pg_temp_2.x", false},
	}
	for _, tc := range temp {
		facts := postgresFacts(t, tc.sql)
		if tc.my {
			facts = mysqlFacts(t, tc.sql)
		}
		if facts.GetCatalogChanging() {
			t.Fatalf("temporary DDL must not be catalog-changing: %q -> %+v", tc.sql, facts)
		}
	}
	for _, sql := range []string{"DROP TABLE users", "ALTER TABLE users ADD COLUMN c INT"} {
		if facts := postgresFacts(t, sql); !facts.GetCatalogChanging() {
			t.Fatalf("persistent DDL must be catalog-changing: %q -> %+v", sql, facts)
		}
	}
	// A QUOTED "PG_TEMP" is a distinct, case-sensitive user schema — PostgreSQL protects quoted
	// identifiers from folding, and its pg_ reservation check is a case-sensitive lowercase compare, so
	// "PG_TEMP" can be a real persistent schema. Temp detection must fold through the dialect
	// (NormalizeIdentifier), NOT a raw lowercase that would conflate it with pg_temp and wrongly skip
	// the catalog refresh.
	if facts := postgresFacts(t, `DROP TABLE "PG_TEMP".x`); !facts.GetCatalogChanging() {
		t.Fatalf("quoted \"PG_TEMP\" is a distinct persistent schema — DROP must be catalog-changing: %+v", facts)
	}
	// pg_temp is a PostgreSQL-only temp-schema convention — MySQL has no such notion, so a MySQL DDL
	// targeting a schema literally named pg_temp is ordinary, catalog-changing DDL. The temp-schema signal
	// is delegated to the engine (engine.IsTempSchema), not hardcoded, so it never fires cross-dialect.
	if facts := mysqlFacts(t, "DROP TABLE pg_temp.x"); !facts.GetCatalogChanging() {
		t.Fatalf("MySQL pg_temp is an ordinary schema (not temp) — DROP must be catalog-changing: %+v", facts)
	}
}

func TestStatementFactsInsertOnConflictDoNothing(t *testing.T) {
	// `ON CONFLICT ... DO NOTHING` cannot update an existing row, so it classifies as a plain INSERT — never
	// INSERT_ON_DUP, whose kind authorizes the update an insert-only principal must be denied. `DO UPDATE` /
	// MySQL upsert keep the INSERT_ON_DUP kind.
	nothing := "INSERT INTO sink (id) VALUES (1) ON CONFLICT (id) DO NOTHING"
	if got := factsKind(postgresFacts(t, nothing)); got != pb.StatementKind_STATEMENT_KIND_INSERT {
		t.Fatalf("DO NOTHING kind = %v, want INSERT (not the upsert kind)", got)
	}
	doUpdate := "INSERT INTO sink (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET value='y'"
	if got := factsKind(postgresFacts(t, doUpdate)); got != pb.StatementKind_STATEMENT_KIND_INSERT_ON_DUP {
		t.Fatalf("DO UPDATE kind = %v, want INSERT_ON_DUP", got)
	}
}

func TestStatementFactsUnicodeEscapedSetConfigEmitsFunctionGrant(t *testing.T) {
	facts := postgresFacts(t, `SELECT U&"set_confi\0067"('search_path','x',false)`)
	if !facts.GetResolved() {
		t.Fatalf("decoded U& identifier should analyze: %+v", facts)
	}
	for _, grant := range facts.GetResultReads() {
		if grant.GetFunction().GetName() == "set_config" {
			return
		}
	}
	t.Fatalf("decoded set_config did not emit a Function grant: %+v", facts.GetResultReads())
}

func TestStatementFactsSchemaCandidatesAndTemporaryDDL(t *testing.T) {
	facts := postgresFacts(t, "SELECT public.users.ssn FROM public.users")
	found := false
	for _, candidate := range facts.GetSchemaQualifierCandidates() {
		if candidate == "public" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing public schema candidate: %v", facts.GetSchemaQualifierCandidates())
	}

	temporary := postgresFacts(t, "CREATE TEMP TABLE copied AS SELECT ssn FROM users")
	if !temporary.GetResolved() || temporary.GetCatalogChanging() {
		t.Fatalf("temporary DDL must not mark catalog changing: %+v", temporary)
	}
	permanent := postgresFacts(t, "CREATE TABLE copied AS SELECT ssn FROM users")
	if !permanent.GetResolved() || !permanent.GetCatalogChanging() {
		t.Fatalf("permanent DDL must mark catalog changing: %+v", permanent)
	}
}

func TestStatementFactsExecutableCommentAndOptimizerHint(t *testing.T) {
	executable := mysqlFacts(t, "SELECT 1 /*!50700 , ssn */ FROM users")
	if !executable.GetResolved() {
		t.Fatalf("executable comment should be analyzed: %+v", executable)
	}
	found := false
	for _, grant := range executable.GetResultReads() {
		if grant.GetColumn().GetIdentity().GetColumn() == "ssn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("executable comment ssn was not emitted: %+v", executable.GetResultReads())
	}
	if hinted := mysqlFacts(t, "SELECT /*+ MAX_EXECUTION_TIME(1000) */ id FROM users"); !hinted.GetResolved() {
		t.Fatalf("optimizer hint should remain inert: %+v", hinted)
	}
}

// A statement with no statements — "" / ";" / comment-only — classifies as an EMPTY session
// passthrough (authorized under stmt.cat.session, no grants) and relays so the target answers
// natively (PostgreSQL EmptyQueryResponse; MySQL ER_EMPTY_QUERY for blank, OK for comment-only).
// Anything that tokenizes to real content stays on the ordinary path.
func TestEmptyStatementClassifiesAsPassthrough(t *testing.T) {
	empties := map[string][]func(*testing.T, string) *pb.StatementFacts{
		"":                                   {postgresFacts, mysqlFacts},
		" \t\r\n\f":                          {postgresFacts, mysqlFacts},
		"-- empty\n":                         {postgresFacts, mysqlFacts},
		"# empty\n":                          {mysqlFacts},
		";":                                  {postgresFacts, mysqlFacts},
		" ; -- empty\n /* still empty */ ; ": {postgresFacts, mysqlFacts},
		// Comment nesting is engine-specific: PostgreSQL nests, MySQL ends at the first */ leaving
		// real tokens — so the same text is EMPTY on one engine and live SQL on the other.
		"/* outer /* nested */ comment */": {postgresFacts},
	}
	for sql, engines := range empties {
		for _, facts := range engines {
			f := facts(t, sql)
			if !f.GetResolved() {
				t.Fatalf("%q: empty statement must resolve, got %q", sql, f.GetDetail())
			}
			if kind := f.GetStatementExec().GetStatementKind(); kind != pb.StatementKind_STATEMENT_KIND_EMPTY {
				t.Fatalf("%q: kind = %v, want STATEMENT_KIND_EMPTY", sql, kind)
			}
			if len(f.GetResultReads()) != 0 || f.GetRewrittenSql() != "" {
				t.Fatalf("%q: empty statement must carry no grants or rewrite", sql)
			}
		}
	}
	for _, sql := range []string{
		"SELECT 1",
		"-- c\nSELECT 1",
		"';'",
	} {
		f := postgresFacts(t, sql)
		if f.GetStatementExec().GetStatementKind() == pb.StatementKind_STATEMENT_KIND_EMPTY {
			t.Fatalf("%q must not classify EMPTY", sql)
		}
	}
	// A tokenizer error must fall through to the ordinary parse path and fail closed there.
	if f := postgresFacts(t, "/* unterminated"); f.GetResolved() ||
		f.GetStatementExec().GetStatementKind() == pb.StatementKind_STATEMENT_KIND_EMPTY {
		t.Fatalf("unterminated comment must fail closed, not resolve: %+v", f)
	}
	// A trailing empty statement doesn't make the real one EMPTY: the SELECT is what's authorized.
	if f := postgresFacts(t, "SELECT 1; ;"); !f.GetResolved() ||
		f.GetStatementExec().GetStatementKind() != pb.StatementKind_STATEMENT_KIND_SELECT {
		t.Fatalf("SELECT with trailing empty must classify SELECT: %+v", f)
	}
	// A whole-statement executable comment is live SQL on MySQL, never EMPTY.
	for _, sql := range []string{"/*!50100 SELECT 1 */", "/*! DROP TABLE users */"} {
		f := mysqlFacts(t, sql)
		if f.GetStatementExec().GetStatementKind() == pb.StatementKind_STATEMENT_KIND_EMPTY {
			t.Fatalf("%q must not classify EMPTY", sql)
		}
	}
}
