package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// readsColumn reports whether the facts carry a column grant for the named column — i.e. the read is
// tracked and can be masked/denied, rather than silently copied out.
func readsColumn(f *pb.StatementFacts, column string) bool {
	for _, g := range f.GetResultReads() {
		if c := g.GetColumn(); c != nil && c.Identity.Column == column {
			return true
		}
	}
	return false
}

func surfacesFunction(f *pb.StatementFacts, name string) bool {
	for _, fn := range f.Functions {
		if fn == name {
			return true
		}
	}
	return false
}

// isDdlKind reports whether a statement kind is schema/catalog DDL (the kinds that carried sql.ddl before
// the single execute-grant migration). A privilege/account/replication statement degrades to STMT_UNKNOWN
// and is excluded, so a DDL grant is never handed to a non-schema statement.
func isDdlKind(k pb.StatementKind) bool {
	switch k {
	case pb.StatementKind_STATEMENT_KIND_CREATE_TABLE,
		pb.StatementKind_STATEMENT_KIND_CREATE_INDEX,
		pb.StatementKind_STATEMENT_KIND_CREATE_VIEW,
		pb.StatementKind_STATEMENT_KIND_CREATE_DATABASE,
		pb.StatementKind_STATEMENT_KIND_CREATE_FUNCTION,
		pb.StatementKind_STATEMENT_KIND_ALTER_TABLE,
		pb.StatementKind_STATEMENT_KIND_ALTER_VIEW,
		pb.StatementKind_STATEMENT_KIND_DROP_TABLE,
		pb.StatementKind_STATEMENT_KIND_DROP_INDEX,
		pb.StatementKind_STATEMENT_KIND_DROP_VIEW,
		pb.StatementKind_STATEMENT_KIND_DROP_DATABASE,
		pb.StatementKind_STATEMENT_KIND_DROP_TRIGGER,
		pb.StatementKind_STATEMENT_KIND_DROP_PROCEDURE,
		pb.StatementKind_STATEMENT_KIND_DROP_FUNCTION,
		pb.StatementKind_STATEMENT_KIND_TRUNCATE_TABLE:
		return true
	}
	return false
}

// valueFreeDdl reports whether the facts are a resolved statement authorized by a lone DDL execute grant
// with nothing else — the shape schema-only DDL takes. A statement that READS (a column grant, a hidden
// function) must not land here, or its read/function gate is silently dropped.
func valueFreeDdl(f *pb.StatementFacts) bool {
	return f.Resolved && f.GetStatementExec() != nil &&
		isDdlKind(f.GetStatementExec().GetStatementKind()) && len(f.GetResultReads()) == 0
}

// A catalog-changing statement resolves and carries exactly one sql.ddl datasource grant.
//
// The failure this guards is silent: reporting such a statement UNRESOLVED routes it through the
// exception.unanalyzable gate, whose grant relays statements unmasked and ships scoped to
// system:development — so on a production datasource every role is denied, including the
// system:production-architect that the sql.ddl policy names, and approval role discovery (which
// previews each candidate alone and drops the DENYs) offers no role at all.
//
// Emitting the grant is not enough on its own: an unresolved statement routes to the exception.unanalyzable
// gate regardless of its grants, so resolution and the grant are asserted together here.
func TestCatalogChangingDdlResolves(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"alter drop index", "ALTER TABLE users DROP INDEX idx_u_idx"},
		// The index name collides with the users.id column; it must still emit no column grant (the assertions
		// below reject any column/table resource), i.e. the index identifier is not read as a value.
		{"alter drop index named like a column", "ALTER TABLE users DROP INDEX id"},
		{"alter drop index qualified", "ALTER TABLE acme.users DROP INDEX idx_u_idx"},
		{"alter drop index backticked", "ALTER TABLE `acme`.`users` DROP INDEX `idx_u_idx`"},
		{"alter drop key spelling", "ALTER TABLE users DROP KEY idx_u_idx"},
		{"alter add index", "ALTER TABLE users ADD INDEX idx_email (email)"},
		{"alter add column", "ALTER TABLE users ADD c INT"},
		{"alter drop column", "ALTER TABLE users DROP COLUMN ssn"},
		{"alter rename", "ALTER TABLE users RENAME TO users2"},
		{"drop table", "DROP TABLE users"},
		{"drop index on table", "DROP INDEX idx_email ON users"},
		{"truncate", "TRUNCATE TABLE users"},
		{"create table", "CREATE TABLE t (id int)"},
		{"create index", "CREATE INDEX idx_email ON users (email)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := mysqlFacts(t, tc.sql)

			if !f.Resolved {
				t.Fatalf("resolved=false (class=%v detail=%q) — routes through exception.unanalyzable, which no "+
					"production role holds", f.FailureClass, f.Detail)
			}
			// A recognized statement authorized off its single execute grant, carrying a real kind (not the
			// STMT_UNKNOWN deny-by-default) — the same path INSERT takes, never a new DDL-only class.
			if factsKind(f) == pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN {
				t.Errorf("statement kind = STMT_UNKNOWN, want a resolved DDL kind")
			}
			if f.FailureClass != pb.FailureClass_FAILURE_CLASS_UNSPECIFIED {
				t.Errorf("failure_class = %v, want UNSPECIFIED on a resolved statement", f.FailureClass)
			}

			if f.GetStatementExec() == nil {
				t.Fatalf("no execute grant on a resolved statement")
			}
			if !isDdlKind(f.GetStatementExec().GetStatementKind()) {
				t.Errorf("execute grant kind:%v, want a DDL kind", f.GetStatementExec().GetStatementKind())
			}
			// No column/table read grant: an index or schema change reads no values, so there is nothing to
			// mask and nothing for catalog coverage to miss.
			if len(f.GetResultReads()) != 0 {
				t.Errorf("unexpected result-read grants on a schema-only DDL statement: %+v", f.GetResultReads())
			}
			// is_write is off the contract; the security-equivalent for schema DDL is that the emitted kind is
			// itself a write/DDL kind — a connection must treat it as mutating the catalog, not a benign read.
			if !isDdlKind(factsKind(f)) {
				t.Errorf("kind %v is not a write/DDL kind, want a schema-mutating kind", factsKind(f))
			}
			if !f.CatalogChanging {
				t.Errorf("catalog_changing = false, want true — a connection must re-measure rather than " +
					"keep serving the pre-change schema")
			}
		})
	}
}

// A CREATE with a query body keeps its lineage analysis: it reads columns, so it must still emit the
// per-column grants that masking binds to, not be swept into the value-free DDL path.
func TestCreateWithQueryBodyKeepsLineage(t *testing.T) {
	f := mysqlFacts(t, "CREATE VIEW v AS SELECT id, email FROM users")

	if !f.Resolved {
		t.Fatalf("resolved=false: class=%v detail=%q", f.FailureClass, f.Detail)
	}
	if factsKind(f) != pb.StatementKind_STATEMENT_KIND_CREATE_VIEW {
		t.Errorf("statement kind = %v, want CREATE_VIEW — it has a query body to trace", factsKind(f))
	}
	var columns int
	for _, g := range f.GetResultReads() {
		if g.GetColumn() != nil {
			columns++
		}
	}
	if columns == 0 {
		t.Errorf("no column grants — lineage was lost for a statement that reads columns")
	}
}

// The statement exactly as production submits it, against a catalog covering the table.
func TestAlterTableDropIndexProductionShape(t *testing.T) {
	f := analyzeProto(t, &pb.AnalyzeRequest{
		Sql: "ALTER TABLE bom.tb_set_book_sell_history DROP INDEX idx_u_idx",
		EngineConfig: &pb.EngineConfig{
			Engine: pb.Engine_MYSQL, EngineVersion: "8.0.44", MysqlLowerCaseTableNames: proto.Int32(0),
		},
		Namespace: &pb.Namespace{Catalog: "def", SearchPath: []string{"bom"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("def", "bom", "tb_set_book_sell_history", "id", "BIGINT"),
			columnSpec("def", "bom", "tb_set_book_sell_history", "u_idx", "BIGINT"),
			columnSpec("def", "bom", "tb_set_book_sell_history", "set_b_id", "VARCHAR"),
		},
	})

	if !f.Resolved {
		t.Fatalf("resolved=false: class=%v detail=%q", f.FailureClass, f.Detail)
	}
	if !valueFreeDdl(f) {
		t.Errorf("not resolved value-free DDL: kind=%v reads=%v", factsKind(f), f.GetResultReads())
	}
}

// A temp-scoped target is session-local: it changes no shared catalog, so other connections must not
// be forced to re-measure.
func TestTemporaryDdlIsNotCatalogChanging(t *testing.T) {
	f := mysqlFacts(t, "DROP TEMPORARY TABLE tmp_users")

	if !f.Resolved {
		t.Fatalf("resolved=false: class=%v detail=%q", f.FailureClass, f.Detail)
	}
	if f.CatalogChanging {
		t.Errorf("catalog_changing = true for a TEMPORARY target, want false")
	}
}

// Account-object DDL (CREATE/ALTER/DROP USER|ROLE) changes accounts/roles, not the column catalog the
// proxy re-measures — so it must resolve non-catalog-changing and relay as a no-column passthrough. If it
// were catalog-changing it would fall out of the passthrough, and a result-bearing form (CREATE USER …
// IDENTIFIED BY RANDOM PASSWORD returns the generated password) would be dropped for a column mismatch on
// view.
func TestAccountObjectDdlIsNotCatalogChanging(t *testing.T) {
	for _, sql := range []string{
		"CREATE USER 'u'@'h'",
		"CREATE USER 'u'@'h' IDENTIFIED BY RANDOM PASSWORD",
		"ALTER USER 'u'@'h' IDENTIFIED BY 'p'",
		"DROP USER 'u'@'h'",
		"CREATE ROLE 'r'",
		"DROP ROLE 'r'",
	} {
		f := mysqlFacts(t, sql)
		if !f.Resolved {
			t.Fatalf("%q resolved=false: class=%v detail=%q", sql, f.FailureClass, f.Detail)
		}
		if f.CatalogChanging {
			t.Errorf("%q catalog_changing=true — account DDL changes no column catalog, want false", sql)
		}
	}
}

// Classification comes from what sqlglot structurally resolved, never from matching the SQL text.
//
// A Command node IS sqlglot reporting "I did not model this statement": the verb survives as a string
// and the rest is unparsed text. Classifying off that verb would hand an authorization off a prefix —
// `RENAME USER`, which is account management, not a schema change. Some genuine table DDL degrades to
// Command too (`RENAME TABLE a TO b`) and is denied along with it; over-denying an unmodeled statement
// is the correct side to fail on, and the fix is for sqlglot to model the form, not for this layer to
// guess from a prefix.
func TestUnmodeledCommandStatementsStayDenied(t *testing.T) {
	for _, sql := range []string{
		"RENAME USER 'a'@'%' TO 'b'@'%'",
		// Table DDL that also degrades to Command — denied, deliberately.
		"RENAME TABLE users TO users2",
	} {
		f := mysqlFacts(t, sql)
		if f.Resolved {
			t.Errorf("%q resolved — a Command node is unmodeled SQL and must not be classified from its verb", sql)
		}
		if se := f.GetStatementExec(); se != nil && isDdlKind(se.GetStatementKind()) {
			t.Errorf("%q was handed a DDL execute grant off an unmodeled Command node", sql)
		}
	}
}

// A parenthesized query body must enforce identically to the bare one. Parentheses are real syntax, so
// sqlglot wraps the body in a Subquery; testing the immediate child read `AS (SELECT …)` as body-less
// and emitted zero column grants, which let a sql.ddl holder copy masked columns into a new
// unclassified table — the exfiltration path authz-model.md requires to fail closed.
func TestParenthesizedQueryBodyKeepsLineage(t *testing.T) {
	bare := "CREATE TABLE copied AS SELECT ssn FROM users"
	for _, sql := range []string{
		"CREATE TABLE copied AS (SELECT ssn FROM users)",
		"CREATE TABLE copied AS ((SELECT ssn FROM users))",
		"CREATE VIEW copied AS (SELECT ssn FROM users)",
		"CREATE TABLE copied AS (SELECT ssn FROM users UNION SELECT ssn FROM users)",
	} {
		f := mysqlFacts(t, sql)
		// It reads columns, so it takes the lineage path and resolves as a CREATE DDL kind (never swept
		// into value-free DDL); the DENY_STATEMENT assertion below proves the read is gated.
		if !f.Resolved || !isDdlKind(factsKind(f)) {
			t.Errorf("%q kind = %v (resolved=%v), want a resolved CREATE DDL kind — it reads columns", sql, factsKind(f), f.Resolved)
		}
		// The write-payload rule is what denies the copy, and it needs a DENY_STATEMENT disposition on
		// the protected column. Its absence is the whole bug, so assert it rather than a grant count.
		var denies int
		for _, g := range f.GetResultReads() {
			if c := g.GetColumn(); c != nil && c.Identity.Column == "ssn" &&
				g.MaskedDisposition == pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT {
				denies++
			}
		}
		if denies == 0 {
			t.Errorf("%q emitted no DENY_STATEMENT grant on users.ssn — a sql.ddl holder could copy it out", sql)
		}
	}

	// And the bare spelling still behaves the same way, so the two cannot drift apart.
	f := mysqlFacts(t, bare)
	if !f.Resolved || factsKind(f) != pb.StatementKind_STATEMENT_KIND_CREATE_TABLE {
		t.Errorf("%q kind = %v (resolved=%v), want CREATE_TABLE", bare, factsKind(f), f.Resolved)
	}
}

// PostgreSQL hides a query inside a Values body: `AS VALUES ((SELECT …))` reads columns while its
// immediate child is a Values, not a Select. It must not become value-free DDL (a lone sql.ddl grant,
// no columns) — that is the same copy-into-a-new-table path as the parenthesized CTAS.
//
// It lands unresolved rather than fully analyzed (lineage does not model this shape), which routes it to
// the exception.unanalyzable gate and denies it on the production floor. An over-deny, not a leak; the invariant
// asserted here is only that it never becomes value-free DDL.
func TestValuesBodyWithSubqueryIsNotValueFreeDdl(t *testing.T) {
	f := postgresFacts(t, "CREATE TABLE leaked AS VALUES ((SELECT ssn FROM users))")
	// The security invariant, stated so a regression cannot pass it: this must never be a statement
	// decideQuery would ALLOW off a lone sql.ddl grant. So it either stays unresolved (routing to the
	// exception.unanalyzable gate, denied on the production floor) or carries the users.ssn column grant that
	// protects the read.
	if valueFreeDdl(f) {
		t.Error("classified as value-free DDL — it reads users.ssn, so its read gate would be dropped")
	}
	if f.Resolved && !readsColumn(f, "ssn") {
		t.Errorf("resolved but emits no users.ssn column grant — decideQuery would ALLOW, leaking the copied column")
	}

	// A literal-only VALUES body reads nothing and stays ordinary DDL, so the guard above is not just
	// "anything with VALUES is denied".
	lit := postgresFacts(t, "CREATE TABLE fine AS VALUES (1), (2)")
	if !valueFreeDdl(lit) {
		t.Errorf("literal VALUES = resolved:%v reads:%v, want resolved value-free DDL", lit.Resolved, lit.GetResultReads())
	}
}

// PostgreSQL's `CREATE TABLE t AS TABLE src` copies every column of src — a body that carries no Select
// node at all — so it is a third spelling of the copy-into-a-new-table path alongside the parenthesized
// CTAS and the VALUES-with-subquery form. sqlglot-go v0.22.0 leaves `AS TABLE` unmodeled (a Command →
// unresolved → denied on the production floor), an over-deny. The invariant guarded here is that it never
// becomes value-free DDL with a bare sql.ddl grant, whatever a future parser does with it.
func TestCreateAsTableIsNotValueFreeDdl(t *testing.T) {
	f := postgresFacts(t, "CREATE TABLE copied AS TABLE users")
	if valueFreeDdl(f) {
		t.Error("classified as value-free DDL — AS TABLE copies every source column, so its read gate would be dropped")
	}
	if f.Resolved && !readsColumn(f, "ssn") {
		t.Error("resolved but emits no users.ssn column grant — a sql.ddl holder could copy the table out")
	}
}

// A VALUES body can carry a function call with no Select node — `AS VALUES (query_to_xml('SELECT ssn
// …'))` runs arbitrary SQL server-side via a system:data-leak function. The value-free DDL path emits no
// function grant, so a Select-only body check let a sql.ddl holder invoke it while the function gate the
// `AS SELECT query_to_xml(…)` spelling triggers was dropped. It must route to lineage (unresolved →
// denied on the production floor) and keep the function visible so the gate can act on it.
func TestCreateValuesWithFunctionIsNotValueFreeDdl(t *testing.T) {
	f := postgresFacts(t, "CREATE TABLE copied AS VALUES (query_to_xml('SELECT ssn FROM users', true, true, ''))")
	if valueFreeDdl(f) {
		t.Error("classified as value-free DDL — a VALUES body invoking a function drops the function gate")
	}
	if !surfacesFunction(f, "query_to_xml") {
		t.Error("query_to_xml not surfaced in facts.functions — the data-leak function gate cannot act on it")
	}
}
