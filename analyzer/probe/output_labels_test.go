package probe

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// A client may reference a derived table's implicit native label — valid on the real DB:
// PostgreSQL names unaliased projections per FigureColname, MySQL by verbatim source text.
// Pre-Qualify stamping makes those references resolve; a DUPLICATED label stays unresolvable,
// matching the target DB's own ambiguity/duplicate error.
func TestNativeLabelReferencesResolve(t *testing.T) {
	pg := func(sql string) *pb.StatementFacts {
		return analyzeProto(t, &pb.AnalyzeRequest{
			Sql:          sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"pg_catalog", "public"}},
			Catalog:      []*pb.ColumnSpec{columnSpec("acme", "public", "users", "id", "BIGINT")},
		})
	}
	my := func(sql string) *pb.StatementFacts {
		return analyzeProto(t, &pb.AnalyzeRequest{
			Sql:          sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.42", MysqlLowerCaseTableNames: proto.Int32(0)},
			Namespace:    &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}},
			Catalog:      []*pb.ColumnSpec{columnSpec("def", "acme", "users", "id", "BIGINT")},
		})
	}

	if f := pg(`SELECT c."current_database" FROM (SELECT current_database()) c`); !f.GetResolved() {
		t.Fatalf("PG native-label reference must resolve: %q", f.GetDetail())
	}
	if f := pg(`SELECT c."?column?" FROM (SELECT 1+1) c`); !f.GetResolved() {
		t.Fatalf("PG ?column? reference must resolve when unique: %q", f.GetDetail())
	}
	// Real PG: `column reference "?column?" is ambiguous`.
	if f := pg(`SELECT c."?column?" FROM (SELECT 1+1, 2+2) c`); f.GetResolved() {
		t.Fatal("PG duplicated ?column? reference must stay unresolvable")
	}
	if f := my("SELECT c.`1+1` FROM (SELECT 1+1) c"); !f.GetResolved() {
		t.Fatalf("MySQL verbatim-label reference must resolve: %q", f.GetDetail())
	}
	// Real MySQL: ER_DUP_FIELDNAME on the derived table.
	if f := my("SELECT c.`1+1` FROM (SELECT 1+1, 1+1) c"); f.GetResolved() {
		t.Fatal("MySQL duplicated label reference must stay unresolvable")
	}
}

// MySQL's label is the projection's verbatim source spelling — the relayed rewrite must carry it.
func TestMySQLRewriteKeepsVerbatimLabels(t *testing.T) {
	f := analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          "SELECT * FROM (SELECT database( ), u.id FROM users u) c",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.42", MysqlLowerCaseTableNames: proto.Int32(0)},
		Namespace:    &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}},
		Catalog:      []*pb.ColumnSpec{columnSpec("def", "acme", "users", "id", "BIGINT")},
	})
	if !f.GetResolved() {
		t.Fatalf("must resolve: %q", f.GetDetail())
	}
	if rewrite := f.GetRewrittenSql(); !strings.Contains(rewrite, "`database( )`") {
		t.Fatalf("rewrite lost MySQL's verbatim label: %s", rewrite)
	}
}

// A client alias spelled `_col_N` disables stamping entirely — synthetic and client labels are
// then indistinguishable.
func TestClientSyntheticAliasDisablesStamping(t *testing.T) {
	f := analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          `SELECT * FROM (SELECT current_database() AS _col_99, oid FROM pg_catalog.pg_namespace) c`,
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"pg_catalog", "public"}},
		Catalog:      []*pb.ColumnSpec{columnSpec("acme", "pg_catalog", "pg_namespace", "oid", "OID")},
	})
	if !f.GetResolved() {
		t.Fatalf("must resolve: %q", f.GetDetail())
	}
	if !strings.Contains(f.GetRewrittenSql(), "_col_99") {
		t.Fatalf("client _col_99 alias destroyed: %s", f.GetRewrittenSql())
	}
}

// PostgreSQL labels a call by its WRITTEN name — canonicalized AST names are the wrong label and
// would rebind a client's ORDER-BY-label to a different column than the target DB uses.
func TestPostgresWrittenFunctionLabels(t *testing.T) {
	// char_length/position/CEILING regenerate under different spellings; such rewrites are
	// already denied fail-closed (postgresFunctionChangedByRegeneration), so no wrong label can
	// relay for them. These cases regenerate faithfully and must carry the written name.
	cases := []struct{ sql, label string }{
		{`SELECT * FROM (SELECT md5(nspname), oid FROM pg_catalog.pg_namespace) c`, "md5"},
		{`SELECT * FROM (SELECT ROUND(oid + 0.5), nspname FROM pg_catalog.pg_namespace) c`, "round"},
		{`SELECT * FROM (SELECT now() at time zone 'UTC', nspname FROM pg_catalog.pg_namespace) c`, "timezone"},
		{`SELECT * FROM (SELECT (array[1,2])[1], nspname FROM pg_catalog.pg_namespace) c`, "array"},
	}
	for _, tc := range cases {
		f := analyzeProto(t, &pb.AnalyzeRequest{
			Sql:          tc.sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"pg_catalog", "public"}},
			Catalog: []*pb.ColumnSpec{
				columnSpec("acme", "pg_catalog", "pg_namespace", "oid", "OID"),
				columnSpec("acme", "pg_catalog", "pg_namespace", "nspname", "NAME"),
			},
		})
		if !f.GetResolved() {
			t.Fatalf("%s: did not resolve: %q", tc.sql, f.GetDetail())
		}
		if rewrite := f.GetRewrittenSql(); !strings.Contains(rewrite, `"`+tc.label+`"`) {
			t.Fatalf("%s: rewrite lost written label %q: %s", tc.sql, tc.label, rewrite)
		}
	}
}

// Real MySQL rejects a derived table with duplicated labels (ER_DUP_FIELDNAME, case-insensitive);
// the analyzer must fail the statement, never sanitize it into unique synthetic names.
func TestMySQLDuplicateDerivedLabelsFailClosed(t *testing.T) {
	my := func(sql string) *pb.StatementFacts {
		return analyzeProto(t, &pb.AnalyzeRequest{
			Sql:          sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.42", MysqlLowerCaseTableNames: proto.Int32(0)},
			Namespace:    &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}},
			Catalog:      []*pb.ColumnSpec{columnSpec("def", "acme", "users", "id", "BIGINT")},
		})
	}
	for _, sql := range []string{
		"SELECT * FROM (SELECT 1+1, 1+1) c",
		"WITH c AS (SELECT 1+1, 1+1) SELECT * FROM c",
		"SELECT * FROM (SELECT 1 AS `A`, 2 AS `a`) c", // case-insensitive duplicate
	} {
		if f := my(sql); f.GetResolved() {
			t.Fatalf("%s: must fail like MySQL ER_DUP_FIELDNAME, got resolved", sql)
		}
	}
	// Top-level duplicates are legal output on MySQL — only derived/CTE bodies reject.
	if f := my("SELECT 1+1, 1+1"); !f.GetResolved() {
		t.Fatalf("top-level duplicate labels are valid MySQL: %q", f.GetDetail())
	}
}

// A referenced duplicated PostgreSQL label is ambiguous on the real DB — including a duplicate
// the client made with explicit aliases.
func TestPostgresReferencedDuplicateStaysAmbiguous(t *testing.T) {
	pg := func(sql string) *pb.StatementFacts {
		return analyzeProto(t, &pb.AnalyzeRequest{
			Sql:          sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"pg_catalog", "public"}},
			Catalog:      []*pb.ColumnSpec{columnSpec("acme", "public", "users", "id", "BIGINT")},
		})
	}
	for _, sql := range []string{
		`SELECT c."?column?" FROM (SELECT 1+1, 2+2) c`,
		`SELECT c."?column?" FROM (SELECT 1 AS "?column?", 2+2) c`,
	} {
		if f := pg(sql); f.GetResolved() {
			t.Fatalf("%s: reference to duplicated label must stay unresolvable", sql)
		}
	}
	// Unreferenced duplicates are legal output on PG.
	if f := pg(`SELECT * FROM (SELECT 1+1, 2+2) c`); !f.GetResolved() {
		t.Fatalf("unreferenced PG duplicates are valid: %q", f.GetDetail())
	}
}

// The window and aggregate-filter parity cases are deferred (native labels vs the oracle's
// _col_0), which also removed their lineage coverage from the golden harness — keep it here.
func TestDeferredParityCasesKeepLineage(t *testing.T) {
	window := Probe("SELECT row_number() OVER (PARTITION BY region ORDER BY ssn) FROM users",
		parityEngineConfig(t, "postgres"), qualifyParitySchema(defaultProbeSchema(), "postgres"), parityNamespace("postgres"))
	if !window.Resolved {
		t.Fatalf("window: %q", window.Detail)
	}
	if got := window.References["ORDER_BY"]; len(got) != 1 || got[0] != "acme.public.users.ssn" {
		t.Fatalf("window ORDER_BY refs = %v, want [acme.public.users.ssn]", got)
	}
	if got := window.References["PREDICATE"]; len(got) != 1 || got[0] != "acme.public.users.region" {
		t.Fatalf("window PREDICATE refs = %v, want [acme.public.users.region]", got)
	}

	filter := Probe("SELECT count(*) FILTER (WHERE ssn IS NOT NULL) FROM users",
		parityEngineConfig(t, "postgres"), qualifyParitySchema(defaultProbeSchema(), "postgres"), parityNamespace("postgres"))
	if !filter.Resolved {
		t.Fatalf("filter: %q", filter.Detail)
	}
	if got := filter.References["AGGREGATE"]; len(got) != 1 || got[0] != "acme.public.users.ssn" {
		t.Fatalf("filter AGGREGATE refs = %v, want [acme.public.users.ssn]", got)
	}
}
