package probe

import (
	"sort"
	"strings"
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

func TestPostgresSafeFunctionsPinToPgCatalog(t *testing.T) {
	analyze := func(sql string) *pb.StatementFacts {
		t.Helper()
		return analyzeProto(t, &pb.AnalyzeRequest{
			Sql:          sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace: &pb.Namespace{
				Catalog:    "acme",
				SearchPath: []string{"user_schema", "pg_catalog"},
			},
			Catalog: []*pb.ColumnSpec{
				columnSpec("acme", "public", "users", "id", "BIGINT"),
			},
		})
	}
	eng, err := newPostgresEngine(&pb.EngineConfig{Engine: pb.Engine_POSTGRES})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		sql       string
		wantCalls []string
	}{
		{"SELECT version()", []string{"pg_catalog.version"}},
		{`SELECT "version"()`, []string{"pg_catalog.version"}},
		{"SELECT current_setting('search_path')", []string{"pg_catalog.current_setting"}},
		{"SELECT version(), current_setting('search_path')", []string{"pg_catalog.version", "pg_catalog.current_setting"}},
		{"SELECT quote_literal(version())", []string{"pg_catalog.quote_literal", "pg_catalog.version"}},
		{"SELECT quote_literal(md5(version()))", []string{"pg_catalog.quote_literal", "pg_catalog.md5", "pg_catalog.version"}},
		{"SELECT abs(1)", []string{"pg_catalog.abs"}},
		{"SELECT substring('abc', 1, 1)", []string{"pg_catalog.substring"}},
		{"SELECT substring('from', 1, 1)", []string{"pg_catalog.substring"}},
		{"SELECT position('in', 'abc')", []string{"pg_catalog.position"}},
		{"SELECT overlay('placing', 'X', 2, 1)", []string{"pg_catalog.overlay"}},
		{"SELECT version(), id FROM public.users", []string{"pg_catalog.version"}},
		{"SELECT value FROM version() AS v(value)", []string{"pg_catalog.version"}},
	} {
		facts := analyze(tc.sql)
		rewrite := strings.ReplaceAll(strings.ToLower(facts.GetRewrittenSql()), `"`, "")
		if !facts.GetResolved() {
			t.Errorf("safe function query did not resolve: %q -> %+v", tc.sql, facts)
			continue
		}
		for _, call := range tc.wantCalls {
			if !strings.Contains(rewrite, call) {
				t.Errorf("safe function was not pinned: %q -> %q", tc.sql, facts.GetRewrittenSql())
			}
		}
	}

	nested := analyze("SELECT quote_literal(md5(version()))")
	if got, want := nested.GetRewrittenSql(), "SELECT pg_catalog.quote_literal(pg_catalog.md5(pg_catalog.version()))"; got != want {
		t.Errorf("nested safe functions rewrite = %q, want %q", got, want)
	}
	abs := analyze("SELECT abs(1)")
	if got, want := abs.GetRewrittenSql(), "SELECT pg_catalog.abs(1)"; got != want {
		t.Errorf("dedicated safe function rewrite = %q, want %q", got, want)
	}

	for _, tc := range []struct {
		sql  string
		name string
	}{
		{"SELECT pg_catalog.version()", "version"},
		{"SELECT pg_catalog.abs(1)", "abs"},
		{"SELECT value FROM pg_catalog.version() AS v(value)", "version"},
	} {
		explicit := analyze(tc.sql)
		if !explicit.GetResolved() || explicit.RewrittenSql != nil || hasFunctionGrant(explicit, tc.name) {
			t.Errorf("explicit pg_catalog function was unnecessarily gated or rewritten: %q -> %+v", tc.sql, explicit)
		}
	}

	grammar := analyze("SELECT substring('abc' FROM 1 FOR 1), position('b' IN 'abc'), overlay('abc' PLACING 'X' FROM 2 FOR 1), coalesce(NULL, 1)")
	if !grammar.GetResolved() || grammar.RewrittenSql != nil {
		t.Errorf("PostgreSQL grammar functions were unnecessarily qualified: %+v", grammar)
	}

	stableComposition := analyze("SELECT users.*, upper('x') FROM public.users")
	stableRewrite := strings.ReplaceAll(strings.ToLower(stableComposition.GetRewrittenSql()), `"`, "")
	if !stableComposition.GetResolved() || strings.Contains(stableRewrite, "*") ||
		!strings.Contains(stableRewrite, "pg_catalog.upper") {
		t.Errorf("stable function did not compose with star expansion: %+v", stableComposition)
	}
	for _, call := range []string{
		"ceiling(1.2)",
		"char(65)",
		"char_length('x')",
		"character_length('x')",
		"current_date()",
		"date_part('year', current_timestamp)",
		"extract('year', current_timestamp)",
		"dateadd('day', 1, current_date)",
		"if(true, 1, 2)",
		"ifnull(NULL, 1)",
		"lcase('X')",
		"nvl(NULL, 1)",
		"overlay('abc', 'X', 2, 1)",
		"position('b', 'abc')",
		"pow(2, 3)",
		"substr('abc', 1, 1)",
		"substring('abc', 1, 1)",
		"truncate(1.2)",
		"ucase('x')",
	} {
		facts := analyze("SELECT users.*, " + call + " FROM public.users")
		if facts.GetResolved() || facts.RewrittenSql != nil || stageString(facts.FailedStage) != "VALIDATE" {
			t.Errorf("function changed by star regeneration was not rejected: %s -> %+v", call, facts)
		}
	}

	for _, sql := range []string{
		"CREATE TABLE version (id int)",
		"CREATE VIEW version(id) AS SELECT 1",
		"WITH version(id) AS (SELECT 1) SELECT id FROM version",
		"CREATE FUNCTION lower(text) RETURNS text LANGUAGE SQL AS 'SELECT $1'",
		"DROP FUNCTION lower(text)",
		"CREATE PROCEDURE lower() LANGUAGE SQL AS 'SELECT 1'",
		"CREATE TRIGGER tr BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION lower()",
	} {
		rewritten, changed, err := eng.pinSafeFunctionSQL(sql)
		if err != nil || changed || rewritten != sql {
			t.Errorf("non-call identifier was rewritten: %q -> %q, changed=%v err=%v", sql, rewritten, changed, err)
		}
	}

	defaultCall := "CREATE FUNCTION user_fn(text DEFAULT lower('X')) RETURNS text LANGUAGE SQL AS 'SELECT $1'"
	defaultRewrite, changed, err := eng.pinSafeFunctionSQL(defaultCall)
	if want := "CREATE FUNCTION user_fn(text DEFAULT pg_catalog.lower('X')) RETURNS text LANGUAGE SQL AS 'SELECT $1'"; err != nil || !changed || defaultRewrite != want {
		t.Errorf("executable declaration expression was not pinned: got %q, changed=%v err=%v, want %q", defaultRewrite, changed, err, want)
	}

	ambiguous := "WITH version(id) AS (SELECT 1) SELECT version(id) FROM version"
	if _, _, err := eng.pinSafeFunctionSQL(ambiguous); err == nil {
		t.Errorf("ambiguous source-to-AST function match did not fail closed: %q", ambiguous)
	}

	quotedDedicated := analyze(`SELECT "ABS"(-1)`)
	if quotedDedicated.GetResolved() || quotedDedicated.RewrittenSql != nil ||
		stageString(quotedDedicated.FailedStage) != "VALIDATE" {
		t.Errorf("quoted dedicated user function was treated as pg_catalog.abs: %+v", quotedDedicated)
	}

	userAbs := analyze("SELECT user_schema.abs(1)")
	if !userAbs.GetResolved() || userAbs.RewrittenSql != nil || !hasFunctionGrant(userAbs, "user_schema.abs") {
		t.Errorf("user-qualified dedicated function did not retain its Function grant: %+v", userAbs)
	}

	userFunction := analyze("SELECT user_schema.version()")
	if !userFunction.GetResolved() || userFunction.RewrittenSql != nil ||
		!hasFunctionGrant(userFunction, "user_schema.version") {
		t.Errorf("user-qualified function did not retain its Function grant: %+v", userFunction)
	}

	userTableFunction := analyze("SELECT value FROM user_schema.version() AS v(value)")
	if userTableFunction.GetResolved() || userTableFunction.RewrittenSql != nil ||
		stageString(userTableFunction.FailedStage) != "VALIDATE" {
		t.Errorf("user-qualified table function was treated as a safe builtin: %+v", userTableFunction)
	}

	for _, sql := range []string{`SELECT "VERSION"()`, `SELECT pg_catalog."VERSION"()`} {
		facts := analyze(sql)
		gated := false
		for _, grant := range facts.GetResultReads() {
			if grant.GetFunction() != nil {
				gated = true
			}
		}
		if !facts.GetResolved() || facts.RewrittenSql != nil || !gated {
			t.Errorf("quoted user function was treated as a safe builtin: %q -> %+v", sql, facts)
		}
	}
}

// TestFormerDangerousFuncsResolveAndEmit: every dangerous builtin analyzes resolved=TRUE and emits its
// bare name as a function fact (docs/facts-emission.md) — so the verdict is the control-plane function
// gate (per-version manifest OR the version-independent baseline floor), a stronger position than a
// datasource-agnostic resolved=false relay. A FROM clause mirrors the real gated shape
// (`SELECT pg_read_file('/x') FROM t`); qualifier-aware Function grants provide the fail-closed floor.
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
// functionCallGrants gives an unclassified call a fail-closed Function grant (a regression there re-denies every plain upsert
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
