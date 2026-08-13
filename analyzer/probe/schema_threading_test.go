package probe

import (
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"google.golang.org/protobuf/proto"
)

var canonicalPostgresCatalog = []*pb.ColumnSpec{
	columnSpec("acme", "pg_catalog", "pg_class", "oid", "BIGINT"),
	columnSpec("acme", "pg_catalog", "pg_class", "relname", "VARCHAR"),
	columnSpec("acme", "public", "users", "id", "BIGINT"),
	columnSpec("acme", "public", "users", "ssn", "VARCHAR"),
	columnSpec("acme", "public", "users", "name", "VARCHAR"),
	columnSpec("acme", "public", "users", "Name", "VARCHAR"),
	columnSpec("acme", "public", "Users", "ID", "BIGINT"),
	columnSpec("acme", "public", "Users", "Label", "VARCHAR"),
	columnSpec("acme", "public", "sink", "id", "BIGINT"),
	columnSpec("acme", "public", "sink", "data", "VARCHAR"),
	columnSpec("acme", "public", "orders", "id", "BIGINT"),
	columnSpec("acme", "public", "orders", "user_id", "BIGINT"),
	columnSpec("acme", "analytics", "users", "id", "BIGINT"),
	columnSpec("acme", "analytics", "users", "score", "BIGINT"),
}

var canonicalPostgresNamespace = &pb.Namespace{
	Catalog:    "acme",
	SearchPath: []string{"pg_catalog", "public"},
}

const canonicalUsersSSNKey = "acme.public.users.ssn"

// decodeProbeResult runs sql through the wire boundary for dialect ("mysql" | "postgres"). MySQL
// calls need mysqlLowerCaseTableNames (0/1/2); pass nil to test the fail-closed missing-mode path.
// Postgres calls always pass nil — it has no such setting.
func decodeProbeResult(t *testing.T, sql, dialect string, cols []*pb.ColumnSpec, ns *pb.Namespace, mysqlLowerCaseTableNames ...int32) *ProbeResult {
	t.Helper()
	engineConfig := &pb.EngineConfig{Engine: pb.Engine_POSTGRES}
	if dialect == "mysql" {
		engineConfig = &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46"}
		if len(mysqlLowerCaseTableNames) == 1 {
			engineConfig.MysqlLowerCaseTableNames = proto.Int32(mysqlLowerCaseTableNames[0])
		}
	}
	return analyzeProbe(t, &pb.AnalyzeRequest{Sql: sql, EngineConfig: engineConfig, Namespace: ns, Catalog: cols})
}

func allLineageKeys(result *ProbeResult) map[string]bool {
	keys := map[string]bool{}
	for _, origin := range result.Origins {
		for _, key := range origin.Origins {
			keys[key] = true
		}
	}
	for _, references := range result.References {
		for _, key := range references {
			keys[key] = true
		}
	}
	return keys
}

func requireResolvedKeys(t *testing.T, result *ProbeResult, expected ...string) {
	t.Helper()
	if !result.Resolved {
		t.Fatalf("probe unexpectedly unresolved at %v: %s", stageString(result.FailedStage), result.Detail)
	}
	keys := allLineageKeys(result)
	for _, expectedKey := range expected {
		if !keys[expectedKey] {
			t.Errorf("missing lineage key %q in %v", expectedKey, keys)
		}
	}
	for key := range keys {
		if strings.Count(key, ".") != 3 {
			t.Errorf("lineage key is not catalog.schema.table.column: %q", key)
		}
	}
}

// PostgreSQL quoted and unquoted cases are part of the byte-identity oracle: the emitted
// catalog.schema.table.column spelling must match the target DB's identifier identity exactly.
func TestSchemaThreadingPostgresResolution(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		keys []string
	}{
		{"bare default", "SELECT ssn FROM users", []string{canonicalUsersSSNKey}},
		{"implicit pg_catalog first", "SELECT relname FROM pg_class", []string{"acme.pg_catalog.pg_class.relname"}},
		{"explicit cross schema", "SELECT score FROM analytics.users", []string{"acme.analytics.users.score"}},
		{
			"same table name across schemas",
			"SELECT u.ssn, a.score FROM public.users u JOIN analytics.users a ON u.id = a.id",
			[]string{canonicalUsersSSNKey, "acme.analytics.users.score", "acme.public.users.id", "acme.analytics.users.id"},
		},
		{"unquoted identifiers fold", "SELECT NAME FROM USERS", []string{"acme.public.users.name"}},
		{"quoted identifiers preserve spelling", `SELECT "ID" FROM "Users"`, []string{"acme.public.Users.ID"}},
		{"quoted column preserves spelling", `SELECT "Name" FROM users`, []string{"acme.public.users.Name"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := decodeProbeResult(t, tc.sql, "postgres", canonicalPostgresCatalog, canonicalPostgresNamespace)
			requireResolvedKeys(t, result, tc.keys...)
		})
	}

	for _, sql := range []string{
		"SELECT ssn FROM other.public.users",
		"SELECT ssn FROM missing.users",
		"SELECT id FROM missing_table",
	} {
		result := decodeProbeResult(t, sql, "postgres", canonicalPostgresCatalog, canonicalPostgresNamespace)
		if result.Resolved || result.FailedStage == nil || *result.FailedStage != "VALIDATE" {
			t.Errorf("expected VALIDATE denial for %q, got %+v", sql, result)
		}
	}
}

func TestSchemaThreadingOrderedSearchPath(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("acme", "first", "shared", "marker", "BIGINT"),
		columnSpec("acme", "second", "shared", "marker", "BIGINT"),
	}
	cases := []struct {
		name       string
		searchPath []string
		expected   string
		forbidden  string
	}{
		{"first schema wins", []string{"first", "second"}, "acme.first.shared.marker", "acme.second.shared.marker"},
		{"reversed order changes winner", []string{"second", "first"}, "acme.second.shared.marker", "acme.first.shared.marker"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns := &pb.Namespace{Catalog: "acme", SearchPath: tc.searchPath}
			result := decodeProbeResult(t, "SELECT marker FROM shared", "postgres", cols, ns)
			requireResolvedKeys(t, result, tc.expected)
			if allLineageKeys(result)[tc.forbidden] {
				t.Fatalf("ordered search path also resolved later candidate %q: %+v", tc.forbidden, result)
			}
		})
	}

	noHit := decodeProbeResult(
		t,
		"SELECT marker FROM shared",
		"postgres",
		cols,
		&pb.Namespace{Catalog: "acme", SearchPath: []string{"missing"}},
	)
	if noHit.Resolved || noHit.FailedStage == nil || *noHit.FailedStage != "VALIDATE" {
		t.Fatalf("search path with no matching table must fail at VALIDATE, got %+v", noHit)
	}
}

// Together with the PostgreSQL quoted-identifier cases above, these case-mode assertions form the
// Byte-identity oracle: emitted catalog.schema.table.column keys must match target DB folding exactly.
func TestSchemaThreadingMySQLCaseModes(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("def", "App", "Users", "ID", "BIGINT"),
		columnSpec("def", "App", "Users", "SSN", "VARCHAR"),
		columnSpec("def", "Reporting", "Users", "ID", "BIGINT"),
		columnSpec("def", "Reporting", "Users", "Score", "BIGINT"),
	}
	cases := []struct {
		name     string
		mode     int
		search   string
		sql      string
		expected string
	}{
		{"mode 0 preserves schema and table", 0, "App", "SELECT id FROM App.Users", "def.App.Users.id"},
		{"mode 0 bare current database", 0, "App", "SELECT SSN FROM Users", "def.App.Users.ssn"},
		{"mode 1 compares schema and table lowercase", 1, "APP", "SELECT ID FROM APP.USERS", "def.app.users.id"},
		{"mode 2 compares schema and table lowercase", 2, "APP", "SELECT ID FROM APP.USERS", "def.app.users.id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns := &pb.Namespace{Catalog: "def", SearchPath: []string{tc.search}}
			result := decodeProbeResult(t, tc.sql, "mysql", cols, ns, int32(tc.mode))
			requireResolvedKeys(t, result, tc.expected)
		})
	}

	foreignCatalog := decodeProbeResult(
		t,
		"SELECT ID FROM DEF.App.Users",
		"mysql",
		cols,
		&pb.Namespace{Catalog: "def", SearchPath: []string{"App"}},
		0,
	)
	if foreignCatalog.Resolved {
		t.Fatalf("catalog spelling must be preserved; foreign catalog unexpectedly resolved: %+v", foreignCatalog)
	}

	missingMode := decodeProbeResult(t, "SELECT ID FROM Users", "mysql", cols, &pb.Namespace{Catalog: "def", SearchPath: []string{"App"}})
	if missingMode.Resolved {
		t.Fatalf("missing mysqlLowerCaseTableNames must fail closed")
	}

	duplicateCols := []*pb.ColumnSpec{
		columnSpec("def", "App", "Users", "ID", "BIGINT"),
		columnSpec("def", "App", "users", "ID", "BIGINT"),
	}
	duplicate := decodeProbeResult(
		t,
		"SELECT ID FROM users",
		"mysql",
		duplicateCols,
		&pb.Namespace{Catalog: "def", SearchPath: []string{"App"}},
		1,
	)
	if duplicate.Resolved || !strings.Contains(duplicate.Detail, "duplicate normalized table") {
		t.Fatalf("normalized duplicate table must fail closed, got %+v", duplicate)
	}
}

func TestSchemaThreadingRewrittenSQLDropsAnalyzerCatalog(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("def", "App", "Users", "ID", "BIGINT"),
		columnSpec("def", "App", "Users", "SSN", "VARCHAR"),
	}
	result := decodeProbeResult(
		t,
		"SELECT u.* FROM App.Users AS u",
		"mysql",
		cols,
		&pb.Namespace{Catalog: "def", SearchPath: []string{"App"}},
		0,
	)
	requireResolvedKeys(t, result, "def.App.Users.id", "def.App.Users.ssn")
	if result.RewrittenSQL == nil {
		t.Fatal("qualified star must produce rewritten SQL")
	}
	expressions, err := sqlglot.Parse(*result.RewrittenSQL, "mysql")
	if err != nil || len(expressions) != 1 {
		t.Fatalf("rewritten SQL is not parseable: %v; %q", err, *result.RewrittenSQL)
	}
	tables := expressions[0].FindAll(exp.KindTable)
	if len(tables) != 1 {
		t.Fatalf("expected one rewritten table, got %d: %q", len(tables), *result.RewrittenSQL)
	}
	if tables[0].CatalogName() != "" || tables[0].SchemaName() != "App" {
		t.Fatalf("rewritten SQL must keep schema but drop analyzer catalog: %q", *result.RewrittenSQL)
	}
}

func TestSchemaThreadingCteVisibility(t *testing.T) {
	cases := []struct {
		name      string
		sql       string
		expected  string
		forbidden string
	}{
		{
			"top-level CTE shadows physical table",
			"WITH users AS (SELECT score AS id FROM analytics.users) SELECT id FROM users",
			"acme.analytics.users.score",
			"acme.public.users.id",
		},
		{
			"dead CTE does not shadow explicit physical table",
			"WITH users AS (SELECT score AS id FROM analytics.users) SELECT id FROM public.users",
			"acme.public.users.id",
			"acme.analytics.users.score",
		},
		{
			"nested CTE name is not visible outside its scope",
			"WITH x AS (WITH users AS (SELECT score AS id FROM analytics.users) SELECT id FROM users) SELECT id FROM users",
			"acme.public.users.id",
			"acme.analytics.users.score",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := decodeProbeResult(t, tc.sql, "postgres", canonicalPostgresCatalog, canonicalPostgresNamespace)
			requireResolvedKeys(t, result, tc.expected)
			if allLineageKeys(result)[tc.forbidden] {
				t.Errorf("out-of-scope/dead source leaked into lineage: %q", tc.forbidden)
			}
		})
	}
}

func TestSchemaThreadingWholeRowsAndWrites(t *testing.T) {
	wholeRows := []string{
		"SELECT u.* FROM users u",
		"SELECT row_to_json(u) FROM users u",
		"SELECT (u).ssn FROM users u",
	}
	for _, sql := range wholeRows {
		result := decodeProbeResult(t, sql, "postgres", canonicalPostgresCatalog, canonicalPostgresNamespace)
		requireResolvedKeys(t, result, canonicalUsersSSNKey)
	}

	writes := []struct {
		sql  string
		keys []string
	}{
		{
			"UPDATE users SET name = ssn WHERE id = 1 RETURNING ssn",
			[]string{canonicalUsersSSNKey, "acme.public.users.id"},
		},
		{
			"DELETE FROM users WHERE ssn = 'x' RETURNING id",
			[]string{canonicalUsersSSNKey, "acme.public.users.id"},
		},
		{
			"INSERT INTO sink (id, data) VALUES (1, (SELECT ssn FROM users LIMIT 1)) RETURNING id",
			[]string{canonicalUsersSSNKey, "acme.public.sink.id"},
		},
		{
			"WITH protected(x) AS (SELECT ssn FROM users) INSERT INTO sink (data) VALUES ((SELECT x FROM protected LIMIT 1))",
			[]string{canonicalUsersSSNKey},
		},
		{
			"MERGE INTO users u USING analytics.users a ON u.id = a.id WHEN MATCHED THEN UPDATE SET name = a.score",
			[]string{"acme.public.users.id", "acme.analytics.users.id", "acme.analytics.users.score"},
		},
	}
	for _, tc := range writes {
		result := decodeProbeResult(t, tc.sql, "postgres", canonicalPostgresCatalog, canonicalPostgresNamespace)
		requireResolvedKeys(t, result, tc.keys...)
		if !result.IsWrite {
			t.Errorf("expected write result for %q", tc.sql)
		}
	}
}

func TestSchemaThreadingUnknownDMLRootColumnFailsClosed(t *testing.T) {
	result := decodeProbeResult(
		t,
		"DELETE FROM users WHERE totally_made_up = 1",
		"postgres",
		canonicalPostgresCatalog,
		canonicalPostgresNamespace,
	)
	if result.Resolved || result.FailedStage == nil || *result.FailedStage != "VALIDATE" {
		t.Fatalf("unknown native-DML-root column must fail at VALIDATE, got %+v", result)
	}
	if !strings.Contains(result.Detail, "unresolved column 'totally_made_up'") {
		t.Fatalf("unknown native-DML-root denial lost its reason: %+v", result)
	}
}

func TestSchemaThreadingWriteSourceResolution(t *testing.T) {
	cases := []struct {
		sql       string
		expected  []string
		forbidden string
	}{
		{
			"UPDATE sink SET data = name FROM users WHERE users.id = sink.id",
			[]string{"acme.public.users.name", "acme.public.users.id", "acme.public.sink.id"},
			canonicalUsersSSNKey,
		},
		{
			"UPDATE sink SET data = to_jsonb(user_id)::text FROM users user_id, orders o WHERE sink.id = user_id.id AND o.id = sink.id",
			[]string{"acme.public.orders.user_id", "acme.public.users.id", "acme.public.orders.id", "acme.public.sink.id"},
			canonicalUsersSSNKey,
		},
	}
	for _, tc := range cases {
		result := decodeProbeResult(t, tc.sql, "postgres", canonicalPostgresCatalog, canonicalPostgresNamespace)
		requireResolvedKeys(t, result, tc.expected...)
		if allLineageKeys(result)[tc.forbidden] {
			t.Fatalf("write source resolution introduced protected lineage %q: %+v", tc.forbidden, result)
		}
	}
}

// A mixed-case CTE in a write binds case-insensitively on PostgreSQL
// (the target-DB folds `Orders` ≡ `orders`), so its masked source column MUST reach the write's lineage.
// public.orders deliberately HAS an `amount` column, so a CTE ref misclassified as the physical
// public.orders would RESOLVE to the unmasked public.orders.amount and silently ALLOW — the exact
// fail-open. Before folding identifiers ahead of write-scope classification, that is what happened.
func TestSchemaThreadingWriteCTECaseFold(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("acme", "public", "users", "id", "BIGINT"),
		columnSpec("acme", "public", "users", "ssn", "VARCHAR"),
		columnSpec("acme", "public", "orders", "id", "BIGINT"),
		columnSpec("acme", "public", "orders", "amount", "VARCHAR"),
		columnSpec("acme", "public", "sink", "id", "BIGINT"),
		columnSpec("acme", "public", "sink", "data", "VARCHAR"),
	}
	ns := &pb.Namespace{Catalog: "acme", SearchPath: []string{"pg_catalog", "public"}}
	sql := "WITH Orders AS (SELECT id, ssn AS amount FROM users) " +
		"UPDATE sink SET data = orders.amount FROM orders WHERE sink.id = orders.id"
	result := decodeProbeResult(t, sql, "postgres", cols, ns)
	if !result.Resolved {
		t.Fatalf("probe unresolved: %s", result.Detail)
	}
	if !result.IsWrite {
		t.Fatalf("expected a write result")
	}
	keys := allLineageKeys(result)
	if !keys["acme.public.users.ssn"] {
		t.Errorf("mixed-case write CTE dropped masked acme.public.users.ssn from lineage %v "+
			"(misclassified as the unmasked physical public.orders) — fail-open", keys)
	}
	if keys["acme.public.orders.amount"] {
		t.Errorf("write CTE resolved the same-named physical decoy acme.public.orders.amount: %v", keys)
	}
}

// PG folds UNQUOTED identifiers ASCII-only (`CAFÉ` → `cafÉ`,
// the É preserved), not full-Unicode. A distinct column `café` (e.g. quoted-created, ordinary) can
// coexist with `cafÉ` (PII). An unquoted `CAFÉ` MUST resolve to `cafÉ` — matching the target DB — not
// over-fold to `café` and pick up the wrong column's policy. Requires sqlglot-go >= v0.2.0 (which folds
// PG identifiers ASCII-only instead of strings.ToLower).
func TestSchemaThreadingPostgresAsciiOnlyFold(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("acme", "public", "t", "cafÉ", "INT"),
		columnSpec("acme", "public", "t", "café", "INT"),
		columnSpec("acme", "public", "t", "id", "INT"),
	}
	ns := &pb.Namespace{Catalog: "acme", SearchPath: []string{"pg_catalog", "public"}}
	result := decodeProbeResult(t, "SELECT CAFÉ FROM t", "postgres", cols, ns)
	if !result.Resolved {
		t.Fatalf("probe unresolved: %s", result.Detail)
	}
	keys := allLineageKeys(result)
	if !keys["acme.public.t.cafÉ"] {
		t.Errorf("unquoted CAFÉ must resolve to cafÉ (PG ASCII-only fold); got %v", keys)
	}
	if keys["acme.public.t.café"] {
		t.Errorf("unquoted CAFÉ over-folded to café (full-Unicode) — wrong column, potential leak: %v", keys)
	}
}

// Non-ASCII MySQL identifiers resolve via sqlglot-go's exact utf8mb3_general_ci fold (MySQLLower) — so
// the ASCII restriction is lifted. The É≡é CTE-shadow that once forced a fail-closed deny now binds
// the CTE correctly: MySQL
// folds `éOrders` ≡ `ÉOrders`, so the reference reads the CTE source (users.ssn), NOT the unmasked
// physical decoy `éorders.amount`. general_ci is accent-PRESERVING (café ≠ cafe), so distinct
// accented columns stay distinct.
func TestSchemaThreadingMysqlNonAsciiIdentifiersFoldExactly(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("def", "app", "users", "ssn", "VARCHAR"),
		columnSpec("def", "app", "users", "id", "INT"),
		columnSpec("def", "app", "éorders", "amount", "VARCHAR"),
		columnSpec("def", "app", "éorders", "id", "INT"),
	}
	ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}
	// The CTE `ÉOrders` shadows the physical `éorders` (general_ci: É≡é). MySQL binds the reference
	// `éOrders` to the CTE → reads users.ssn. The analyzer must trace the CTE source, not the decoy.
	cte := "WITH `ÉOrders` AS (SELECT ssn AS amount FROM users) SELECT amount FROM `éOrders`"
	res := decodeProbeResult(t, cte, "mysql", cols, ns, 1)
	if !res.Resolved {
		t.Fatalf("non-ASCII CTE-shadow must resolve via the exact fold: %s", res.Detail)
	}
	keys := allLineageKeys(res)
	if !keys["def.app.users.ssn"] {
		t.Errorf("CTE-shadow must trace the CTE source def.app.users.ssn; got %v", keys)
	}
	if keys["def.app.éorders.amount"] {
		t.Errorf("CTE-shadow wrongly resolved the physical decoy def.app.éorders.amount: %v", keys)
	}
	// a plain non-ASCII reference resolves to its (folded) catalog column — no over-deny
	if r := decodeProbeResult(t, "SELECT amount FROM `Éorders`", "mysql", cols, ns, 1); !r.Resolved {
		t.Errorf("non-ASCII reference must resolve (Éorders ≡ éorders): %s", r.Detail)
	}
	// an ASCII query against the same catalog still resolves normally
	if r := decodeProbeResult(t, "SELECT ssn FROM users", "mysql", cols, ns, 1); !r.Resolved {
		t.Errorf("ASCII MySQL query must still resolve: %s", r.Detail)
	}
}

// Under MySQL lower_case_table_names=0 the server is STILL case-insensitive for columns and column
// aliases (lctn governs only table/db names), so a CTE's explicit output-column name must bind its
// consumer regardless of case. If it did not, `WITH cte (Secret) … SELECT secret` would leave
// `Secret` (definition) ≠ `secret` (reference): the payload output resolves to NO base column, and
// because a write disables the column validator the INSERT would ship with EMPTY lineage —
// users.ssn copied into the unmasked sink and ALLOWed (fail-open). sqlglot-go's role-aware
// mysql_case_sensitive_table_names strategy folds the output-column list like any other column, so
// definition ↔ reference match and the write's lineage carries users.ssn. Covers both lctn modes and
// read/write (the read must not over-deny; the write must not leak).
func TestSchemaThreadingMysqlCTEOutputColumnFold(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("def", "app", "users", "ssn", "VARCHAR"),
		columnSpec("def", "app", "users", "id", "INT"),
		columnSpec("def", "app", "sink", "data", "VARCHAR"),
		columnSpec("def", "app", "sink", "id", "INT"),
	}
	cases := []struct {
		name  string
		mode  int
		sql   string
		write bool
	}{
		{"mode0 write", 0, "INSERT INTO sink (data) WITH cte (Secret) AS (SELECT ssn FROM users) SELECT secret FROM cte", true},
		{"mode0 read", 0, "WITH cte (Secret) AS (SELECT ssn FROM users) SELECT secret FROM cte", false},
		{"mode0 same case", 0, "WITH cte (Secret) AS (SELECT ssn FROM users) SELECT Secret FROM cte", false},
		{"mode1 write", 1, "INSERT INTO sink (data) WITH cte (Secret) AS (SELECT ssn FROM users) SELECT secret FROM cte", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}
			result := decodeProbeResult(t, tc.sql, "mysql", cols, ns, int32(tc.mode))
			if !result.Resolved {
				t.Fatalf("probe unresolved: %s", result.Detail)
			}
			if result.IsWrite != tc.write {
				t.Fatalf("IsWrite=%v, want %v", result.IsWrite, tc.write)
			}
			if !allLineageKeys(result)["def.app.users.ssn"] {
				t.Errorf("CTE output-column case mismatch dropped def.app.users.ssn from lineage %v — fail-open",
					allLineageKeys(result))
			}
		})
	}
}

// Under MySQL lower_case_table_names=0, relation-level names — table
// names, column QUALIFIERS, and CTE names — are case-sensitive, while column names fold. The analyzer's
// fold (sqlglot-go's mysql_case_sensitive_table_names strategy) must PRESERVE the relation-level ones;
// folding a qualifier or CTE name resolves the wrong relation and, for a write (qualify-validation
// off), silently drops lineage → wrong ALLOW. Live-verified on MySQL 8.4 lctn=0: `SELECT users.ssn FROM
// Users` → ERROR 1054 (qualifier case-sensitive); a mixed-case CTE binds by exact case.
func TestSchemaThreadingMysqlLctn0RelationCaseSensitivity(t *testing.T) {
	ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}
	// #1: a qualified column against an unaliased mixed-case physical table keeps its lineage. Before
	// the fix the qualifier folded to `users` while the table stayed `Users` → empty write lineage.
	t.Run("qualified column, unaliased mixed-case table", func(t *testing.T) {
		cols := []*pb.ColumnSpec{
			columnSpec("def", "app", "Users", "ssn", "VARCHAR"),
			columnSpec("def", "app", "Users", "id", "INT"),
			columnSpec("def", "app", "sink", "data", "VARCHAR"),
			columnSpec("def", "app", "sink", "id", "INT"),
		}
		result := decodeProbeResult(t, "INSERT INTO sink (data) SELECT Users.ssn FROM Users", "mysql", cols, ns, 0)
		requireResolvedKeys(t, result, "def.app.Users.ssn")
		if !result.IsWrite {
			t.Fatalf("expected a write result")
		}
	})
	// #2: a mixed-case CTE shadowing a same-spelled physical table binds the CTE (its source), not the
	// physical decoy. Before the fix the CTE definition name folded but the reference did not → the
	// reference resolved the physical decoy Users.ssn instead of the CTE source other.ssn.
	t.Run("mixed-case CTE shadows physical table", func(t *testing.T) {
		cols := []*pb.ColumnSpec{
			columnSpec("def", "app", "Users", "ssn", "VARCHAR"),
			columnSpec("def", "app", "Users", "id", "INT"),
			columnSpec("def", "app", "other", "ssn", "VARCHAR"),
			columnSpec("def", "app", "other", "id", "INT"),
			columnSpec("def", "app", "sink", "data", "VARCHAR"),
			columnSpec("def", "app", "sink", "id", "INT"),
		}
		result := decodeProbeResult(t, "INSERT INTO sink (data) WITH Users AS (SELECT ssn FROM other) SELECT ssn FROM Users", "mysql", cols, ns, 0)
		if !result.Resolved {
			t.Fatalf("probe unresolved: %s", result.Detail)
		}
		keys := allLineageKeys(result)
		if !keys["def.app.other.ssn"] {
			t.Errorf("CTE reference must bind the CTE source def.app.other.ssn; got %v", keys)
		}
		if keys["def.app.Users.ssn"] {
			t.Errorf("CTE reference wrongly resolved the physical decoy def.app.Users.ssn: %v", keys)
		}
	})
}

// Byte-identity must also be injective: two structured identities that render to the same
// dotted key must fail closed instead of sharing policy accidentally.
func TestSchemaThreadingRejectsRenderedKeyCollision(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("a.b", "c", "d", "e", "INT"),
		columnSpec("a", "b.c", "d", "e", "INT"),
	}
	result := decodeProbeResult(t, "SELECT 1", "postgres", cols, &pb.Namespace{Catalog: "a.b", SearchPath: []string{"c"}})
	if result.Resolved || !strings.Contains(result.Detail, "both render") {
		t.Fatalf("rendered identity collision must fail closed, got %+v", result)
	}
}
