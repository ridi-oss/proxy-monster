package probe

import (
	"sort"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// TestCalledFunctions locks the called-function emission (docs/facts-emission.md): the probe emits the DISTINCT
// bare names of every Anonymous function call, so the control-plane can classify each against the
// datasource's system manifests and DENY a dangerous builtin by policy. sqlglot drops a function's schema
// qualifier at parse time, so only the bare name is emitted; standard-SQL builtins with dedicated node
// kinds (count/cast/substring) are NOT emitted (they are safe and carry unreliable names). The `functions`
// fact must be present ONLY for names actually called, deduped, and lowercased.
func TestCalledFunctions(t *testing.T) {
	pgCatalog := []*pb.ColumnSpec{
		columnSpec("acme", "public", "t", "id", "BIGINT"),
		columnSpec("acme", "public", "t", "c", "VARCHAR"),
	}
	pgNs := &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}}

	cases := []struct {
		name    string
		dialect string
		catalog []*pb.ColumnSpec
		ns      *pb.Namespace
		sql     string
		want    []string
	}{
		// Dangerous builtins reach the success path and MUST be emitted so the Cedar forbid can act.
		{"pg_terminate_backend", "postgres", pgCatalog, pgNs, "SELECT pg_terminate_backend(1)", []string{"pg_terminate_backend"}},
		{"set_config", "postgres", pgCatalog, pgNs, "SELECT set_config('search_path', 'x', false)", []string{"set_config"}},
		{"pageinspect nested calls both emitted", "postgres", pgCatalog, pgNs, "SELECT heap_page_items(get_raw_page('t', 0))", []string{"get_raw_page", "heap_page_items"}},
		{"dblink_get_result (not in backstop)", "postgres", pgCatalog, pgNs, "SELECT dblink_get_result('c')", []string{"dblink_get_result"}},
		// Safe Anonymous builtin is emitted (harmless — classifier returns null → not marshalled); a
		// dedicated-kind builtin (count) is NOT emitted; a bare user function IS emitted (classifier returns
		// null → treated as a safe/unclassified call on this phase).
		{"safe now() emitted, count() not, user fn emitted", "postgres", pgCatalog, pgNs, "SELECT now(), count(*), my_udf(c) FROM t", []string{"my_udf", "now"}},
		{"no functions", "postgres", pgCatalog, pgNs, "SELECT id FROM t", []string{}},
		{"dedup: same fn called twice → once", "postgres", pgCatalog, pgNs, "SELECT set_config('a','b',false), set_config('c','d',true)", []string{"set_config"}},
		// MySQL: rds_kill is Aurora-management (mysql.rds_ family); the bare name must be emitted so the
		// resolver classifies it. keyring_ is a __builtin__ family.
		{"mysql rds_kill", "mysql",
			[]*pb.ColumnSpec{columnSpec("def", "app", "t", "id", "BIGINT")},
			&pb.Namespace{Catalog: "def", SearchPath: []string{"app"}},
			"SELECT rds_kill(1)", []string{"rds_kill"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, resolved := probeFunctions(t, tc.sql, tc.dialect, tc.catalog, tc.ns)
			if !resolved {
				t.Fatalf("expected resolved=true (a resolved statement carries functions); sql=%s", tc.sql)
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("functions mismatch\n  sql:  %s\n  got:  %v\n  want: %v", tc.sql, got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("functions mismatch\n  sql:  %s\n  got:  %v\n  want: %v", tc.sql, got, want)
				}
			}
		})
	}
}

// TestFormerDangerousFuncsResolveAndEmit: every dangerous builtin analyzes resolved=TRUE and emits its
// bare name as a function fact (docs/facts-emission.md) — so the verdict is the control-plane function
// gate (per-version manifest OR the version-independent baseline floor), a stronger position than a
// datasource-agnostic resolved=false relay. A FROM clause mirrors the real gated shape
// (`SELECT pg_read_file('/x') FROM t`); the no-FROM form is gated separately by noFromFunctionGrants
// (facts.go).
func TestFormerDangerousFuncsResolveAndEmit(t *testing.T) {
	pgCatalog := []*pb.ColumnSpec{
		columnSpec("acme", "public", "t", "id", "BIGINT"),
		columnSpec("acme", "public", "t", "c", "VARCHAR"),
	}
	pgNs := &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}}
	myCatalog := []*pb.ColumnSpec{columnSpec("def", "app", "t", "id", "BIGINT")}
	myNs := &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}

	cases := []struct {
		name    string
		dialect string
		catalog []*pb.ColumnSpec
		ns      *pb.Namespace
		sql     string
		want    string
	}{
		{"dblink", "postgres", pgCatalog, pgNs, "SELECT dblink('c', 'SELECT 1') FROM t", "dblink"},
		{"dblink_exec", "postgres", pgCatalog, pgNs, "SELECT dblink_exec('c', 'SELECT 1') FROM t", "dblink_exec"},
		{"dblink_open", "postgres", pgCatalog, pgNs, "SELECT dblink_open('c') FROM t", "dblink_open"},
		{"dblink_fetch", "postgres", pgCatalog, pgNs, "SELECT dblink_fetch('c') FROM t", "dblink_fetch"},
		{"dblink_send_query", "postgres", pgCatalog, pgNs, "SELECT dblink_send_query('c', 'SELECT 1') FROM t", "dblink_send_query"},
		{"pg_read_file", "postgres", pgCatalog, pgNs, "SELECT pg_read_file('/etc/passwd') FROM t", "pg_read_file"},
		{"pg_read_binary_file", "postgres", pgCatalog, pgNs, "SELECT pg_read_binary_file('/etc/passwd') FROM t", "pg_read_binary_file"},
		{"pg_ls_dir", "postgres", pgCatalog, pgNs, "SELECT pg_ls_dir('/') FROM t", "pg_ls_dir"},
		{"pg_stat_file", "postgres", pgCatalog, pgNs, "SELECT pg_stat_file('/etc/passwd') FROM t", "pg_stat_file"},
		{"lo_import", "postgres", pgCatalog, pgNs, "SELECT lo_import('/etc/passwd') FROM t", "lo_import"},
		{"lo_export", "postgres", pgCatalog, pgNs, "SELECT lo_export(16384, '/tmp/x') FROM t", "lo_export"},
		{"query_to_xml", "postgres", pgCatalog, pgNs, "SELECT query_to_xml('SELECT 1', true, false, '') FROM t", "query_to_xml"},
		{"query_to_xml_and_xmlschema", "postgres", pgCatalog, pgNs, "SELECT query_to_xml_and_xmlschema('SELECT 1', true, false, '') FROM t", "query_to_xml_and_xmlschema"},
		{"xpath_table", "postgres", pgCatalog, pgNs, "SELECT xpath_table('a', 'b', 'c', 'd', 'e') FROM t", "xpath_table"},
		// MySQL server-side file read.
		{"load_file", "mysql", myCatalog, myNs, "SELECT load_file('/etc/passwd') FROM t", "load_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, resolved := probeFunctions(t, tc.sql, tc.dialect, tc.catalog, tc.ns)
			if !resolved {
				t.Fatalf("expected resolved=true; sql=%s", tc.sql)
			}
			found := false
			for _, g := range got {
				if g == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("function fact %q not emitted\n  sql: %s\n  got: %v", tc.want, tc.sql, got)
			}
		})
	}
}

// deniedColumns returns the set of column names emitted as DENY_STATEMENT result-read grants.
func deniedColumns(f *pb.StatementFacts) map[string]bool {
	out := map[string]bool{}
	for _, g := range f.GetResultReads() {
		if c := g.GetColumn(); c != nil && g.GetMaskedDisposition() == pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT {
			out[c.GetIdentity().GetColumn()] = true
		}
	}
	return out
}

// TestOdkuValuesIsNotAFunctionGrant locks two things about MySQL's `INSERT … ON DUPLICATE KEY UPDATE
// col = VALUES(col)`. First, `VALUES()` there is not a callable function — it names the value that would
// have been inserted — so the upsert must resolve and must NOT emit the deny-by-default Function grant that
// noFromFunctionGrants gives an unclassified no-FROM call (a regression there re-denies every plain upsert
// with "dangerous system function is not allowed: 'values'"). Second — and separately — making the
// pseudo-function safe must NOT weaken write-side gating: every column VALUES() names is still a
// DENY_STATEMENT grant, so a masked column cannot slip through the write payload unauthorized.
func TestOdkuValuesIsNotAFunctionGrant(t *testing.T) {
	sql := "INSERT INTO users (id, email, ssn) VALUES (1, 'x', 'y') ON DUPLICATE KEY UPDATE email = VALUES(email), ssn = VALUES(ssn)"
	f := mysqlFacts(t, sql)
	if !f.Resolved {
		t.Fatalf("upsert did not resolve: detail=%q", f.GetDetail())
	}
	for _, g := range f.GetResultReads() {
		if fn := g.GetFunction(); fn != nil && fn.GetName() == "values" {
			t.Fatalf("VALUES() emitted a Function grant (control-plane hard-denies it): %q", sql)
		}
	}
	denied := deniedColumns(f)
	for _, col := range []string{"email", "ssn"} {
		if !denied[col] {
			t.Fatalf("VALUES(%s) column is not gated DENY_STATEMENT — masking could be bypassed: reads=%v", col, f.GetResultReads())
		}
	}
}

// TestOdkuInsertSelectRetainsSourceLineage locks that the source of an INSERT … SELECT upsert stays gated
// even with a `VALUES(col)` in the update clause: a protected source column read by the SELECT must still be
// a DENY_STATEMENT grant, so the safe pseudo-function never masks the read side of a write-from-select.
func TestOdkuInsertSelectRetainsSourceLineage(t *testing.T) {
	sql := "INSERT INTO sink (id, value) SELECT id, ssn FROM users ON DUPLICATE KEY UPDATE value = VALUES(value)"
	f := mysqlFacts(t, sql)
	if !f.Resolved {
		t.Fatalf("insert-select upsert did not resolve: detail=%q", f.GetDetail())
	}
	if !deniedColumns(f)["ssn"] {
		t.Fatalf("protected source column users.ssn is not gated DENY_STATEMENT: reads=%v", f.GetResultReads())
	}
}

// TestPostgresQuotedValuesStaysGated locks that `values` is safe ONLY on MySQL. PostgreSQL has no `values`
// builtin, so a quoted `"values"()` is a user function and must still emit a no-FROM Function grant the
// control-plane denies — the MySQL ODKU allowance must not leak into PostgreSQL.
func TestPostgresQuotedValuesStaysGated(t *testing.T) {
	f := postgresFacts(t, `SELECT "values"()`)
	if !f.Resolved {
		t.Fatalf(`SELECT "values"() did not resolve: detail=%q`, f.GetDetail())
	}
	gated := false
	for _, g := range f.GetResultReads() {
		if fn := g.GetFunction(); fn != nil && fn.GetName() == "values" {
			gated = true
		}
	}
	if !gated {
		t.Fatalf(`PostgreSQL "values"() must emit a Function grant (a user function is gated): reads=%v`, f.GetResultReads())
	}
}

func probeFunctions(t *testing.T, sql, dialect string, cols []*pb.ColumnSpec, ns *pb.Namespace) ([]string, bool) {
	t.Helper()
	engineConfig := &pb.EngineConfig{Engine: pb.Engine_POSTGRES}
	if dialect == "mysql" {
		engineConfig = &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}
	}
	res := analyzeProbe(t, &pb.AnalyzeRequest{Sql: sql, EngineConfig: engineConfig, Namespace: ns, Catalog: cols})
	return res.Functions, res.Resolved
}

func TestPostgresInformationSchemaHelpersTrusted(t *testing.T) {
	for _, sql := range []string{
		"SELECT (information_schema._pg_expandarray(ARRAY[1,2])).n",
		"SELECT x.n FROM information_schema._pg_expandarray(ARRAY[1,2]) AS x(x,n)",
	} {
		f := postgresFacts(t, sql)
		if !f.GetResolved() {
			t.Fatalf("%s did not resolve: detail=%q", sql, f.GetDetail())
		}
		for _, g := range f.GetResultReads() {
			if fn := g.GetFunction(); fn != nil {
				t.Fatalf("%s: qualified information_schema helper must not emit a Function grant, got %q", sql, fn.GetName())
			}
		}
	}

	// The unqualified spelling could be a same-named user function: it stays gated.
	f := postgresFacts(t, "SELECT (_pg_expandarray(ARRAY[1,2])).n")
	gated := false
	for _, g := range f.GetResultReads() {
		if fn := g.GetFunction(); fn != nil && fn.GetName() == "_pg_expandarray" {
			gated = true
		}
	}
	if f.GetResolved() && !gated {
		t.Fatalf("unqualified _pg_expandarray must stay gated: reads=%v", f.GetResultReads())
	}

	// A helper outside the fixed set is user code even under the information_schema qualifier.
	f = postgresFacts(t, "SELECT information_schema.leak(1)")
	gated = false
	for _, g := range f.GetResultReads() {
		if fn := g.GetFunction(); fn != nil {
			gated = true
		}
	}
	if f.GetResolved() && !gated {
		t.Fatal("information_schema.<non-helper> must stay gated")
	}
}
