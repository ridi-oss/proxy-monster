package engines

import (
	"slices"
	"sort"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// nameTarget is one datasource as the analyzer sees it. rows, the search path and udfs' schemas are spelled
// as the target's own catalog returns them; the analyzer receives them in canonical spelling.
type nameTarget struct {
	engine     pb.Engine
	lctn       int32
	catalog    string
	searchPath []string
	rows       []*pb.Column
	// udfs is user functions by schema; nil puts testUDFs in the current schema.
	udfs map[string][]string
}

func mysqlNames(lctn int32, current string, rows ...*pb.Column) nameTarget {
	return nameTarget{engine: pb.Engine_MYSQL, lctn: lctn, catalog: "def", searchPath: []string{current}, rows: rows}
}

func postgresNames(searchPath []string, rows ...*pb.Column) nameTarget {
	return nameTarget{engine: pb.Engine_POSTGRES, catalog: "acme", searchPath: searchPath, rows: rows}
}

func athenaNames(rows ...*pb.Column) nameTarget {
	return nameTarget{engine: pb.Engine_ATHENA, catalog: "awsdatacatalog", searchPath: []string{"sample"}, rows: rows}
}

func (n nameTarget) targetSettings() *pb.TargetSettings {
	if n.engine != pb.Engine_MYSQL {
		return nil
	}
	return &pb.TargetSettings{EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(n.lctn)}
}

func (n nameTarget) datasource(t *testing.T) *Session {
	t.Helper()
	eng, _ := ByProto(n.engine)
	session, err := eng.NewSession(n.targetSettings())
	if err != nil {
		t.Fatalf("datasource: %v", err)
	}
	return session
}

func (n nameTarget) schema(t *testing.T, raw string) string {
	t.Helper()
	return n.datasource(t).CatalogSchemaName(&pb.Column{Schema: raw, Table: "_", Column: "_"}).String()
}

func (n nameTarget) canonicalRows(t *testing.T) []*pb.Column {
	t.Helper()
	out := make([]*pb.Column, len(n.rows))
	for i, c := range n.datasource(t).CatalogColumnNames(n.rows) {
		catalog := c.Catalog().String()
		if catalog == "" {
			catalog = n.catalog
		}
		out[i] = &pb.Column{Catalog: catalog, Schema: c.Schema().String(), Table: c.Table(), Column: c.Column(), DataType: n.rows[i].GetDataType()}
	}
	return out
}

// key is the canonical key the catalog push gives one introspected row.
func (n nameTarget) key(t *testing.T, row *pb.Column) string {
	t.Helper()
	single := n
	single.rows = []*pb.Column{row}
	c := single.canonicalRows(t)[0]
	return refKey(&pb.ObjectRef{Catalog: c.GetCatalog(), Schema: c.GetSchema(), Table: c.GetTable(), Column: c.GetColumn()})
}

func (n nameTarget) functions(t *testing.T) *pb.FunctionCatalog {
	t.Helper()
	if n.engine == pb.Engine_ATHENA {
		return &pb.FunctionCatalog{BuiltinFunctions: []string{"upper", "lower", "concat", "count"}}
	}
	udfs := n.udfs
	if udfs == nil {
		udfs = map[string][]string{n.searchPath[0]: testUDFs}
	}
	catalog := &pb.FunctionCatalog{BuiltinFunctions: testBuiltins}
	for schema, names := range udfs {
		catalog.UdfSchemas = append(catalog.UdfSchemas, &pb.SchemaFunctions{Schema: n.schema(t, schema), Names: names})
	}
	if n.engine == pb.Engine_POSTGRES {
		catalog.SystemFunctionSchemas = []*pb.SchemaFunctions{{Schema: "pg_catalog", Names: testBuiltins}}
	}
	return catalog
}

func (n nameTarget) facts(t *testing.T, sql string) *pb.StatementFacts {
	t.Helper()
	cfg := &pb.EngineConfig{Engine: n.engine, Target: n.targetSettings()}
	if n.engine == pb.Engine_ATHENA {
		cfg.Session = &pb.SessionObservation{Engine: &pb.SessionObservation_Athena{Athena: &pb.AthenaSqlContext{Workgroup: "sample"}}}
	}
	path := make([]string, len(n.searchPath))
	for i, s := range n.searchPath {
		path[i] = n.schema(t, s)
	}
	return analyzeProto(t, &pb.AnalyzeRequest{
		Sql: sql, EngineConfig: cfg, Namespace: &pb.Namespace{Catalog: n.catalog, SearchPath: path},
		Catalog: snapshotWith(n.canonicalRows(t), n.functions(t)),
	})
}

func refKey(ref *pb.ObjectRef) string {
	return ref.GetCatalog() + "." + ref.GetSchema() + "." + ref.GetTable() + "." + ref.GetColumn()
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func resultReadKeys(facts *pb.StatementFacts) []string {
	set := map[string]bool{}
	for _, g := range facts.GetResultReads() {
		if c := g.GetColumn(); c != nil {
			set[refKey(c)] = true
		}
	}
	return sortedKeys(set)
}

func returnedKeys(facts *pb.StatementFacts) []string {
	set := map[string]bool{}
	for _, r := range facts.GetReturnedColumns() {
		if c := r.GetColumn(); c != nil {
			set[refKey(c)] = true
		}
	}
	return sortedKeys(set)
}

func nameReadKeys(facts *pb.StatementFacts) []string {
	set := map[string]bool{}
	for _, k := range append(resultReadKeys(facts), returnedKeys(facts)...) {
		set[k] = true
	}
	return sortedKeys(set)
}

func nameFunctions(facts *pb.StatementFacts) []string {
	var out []string
	for _, g := range facts.GetResultReads() {
		if f := g.GetFunction(); f != nil {
			out = append(out, f.GetName())
		}
	}
	sort.Strings(out)
	return out
}

// requireReads asserts the statement resolved and names exactly want among its column keys.
func requireReads(t *testing.T, n nameTarget, sql string, want ...string) {
	t.Helper()
	facts := n.facts(t, sql)
	if !facts.GetResolved() {
		t.Errorf("%q unresolved at %s: %s", sql, stageString(facts.FailedStage), facts.GetDetail())
		return
	}
	want = append([]string(nil), want...)
	sort.Strings(want)
	if got := resultReadKeys(facts); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%q result-read keys = %v, want %v", sql, got, want)
	}
	for _, k := range returnedKeys(facts) {
		if !slices.Contains(want, k) {
			t.Errorf("%q returned column %s, want one of %v", sql, k, want)
		}
	}
}

func requireClosed(t *testing.T, n nameTarget, sql string) {
	t.Helper()
	if facts := n.facts(t, sql); facts.GetResolved() {
		t.Errorf("%q resolved with keys %v, want fail closed", sql, nameReadKeys(facts))
	}
}

func TestNameMySQLTableAliasCase(t *testing.T) {
	ssn, id, x := pbColumn("App", "Users", "SSN", "VARCHAR"), pbColumn("App", "Users", "ID", "BIGINT"), pbColumn("App", "u", "x", "BIGINT")
	n := mysqlNames(0, "App", ssn, id, x)
	requireClosed(t, n, "SELECT U.ssn FROM Users u")
	requireReads(t, n, "SELECT u.SSN FROM Users u", n.key(t, ssn))
	requireReads(t, n, "SELECT U.SSN FROM Users U", n.key(t, ssn))
	requireReads(t, n, "SELECT u.x FROM Users U, u", n.key(t, x))
	for _, lctn := range []int32{1, 2} {
		n := mysqlNames(lctn, "App", ssn, id, x)
		requireReads(t, n, "SELECT U.ssn FROM Users u", n.key(t, ssn))
		requireReads(t, n, "SELECT u.SSN FROM Users u", n.key(t, ssn))
		requireClosed(t, n, "SELECT u.x FROM Users U, u")
	}

	upper, lower := pbColumn("App", "Users", "SSN", "VARCHAR"), pbColumn("App", "users", "ssn", "VARCHAR")
	twins := mysqlNames(0, "App", upper, lower)
	if twins.key(t, upper) == twins.key(t, lower) {
		t.Fatalf("lctn 0 twins share key %q", twins.key(t, upper))
	}
	requireReads(t, twins, "SELECT users.ssn FROM Users AS users", twins.key(t, upper))
	requireReads(t, twins, "SELECT Users.ssn FROM users AS Users", twins.key(t, lower))
	requireReads(t, twins, "SELECT ssn FROM Users", twins.key(t, upper))
	requireReads(t, twins, "SELECT ssn FROM users", twins.key(t, lower))
}

func TestNameAthenaSQLPathMatchesCatalogKey(t *testing.T) {
	ssn := catalogColumn("AwsDataCatalog", "Sample", "Users", "SSN", "VARCHAR")
	id := catalogColumn("AwsDataCatalog", "Sample", "Users", "ID", "BIGINT")
	dotted := catalogColumn("AwsDataCatalog", "Sample", "İnfo", "İd", "VARCHAR")
	sharp := catalogColumn("AwsDataCatalog", "Sample", "Straße", "ẞ", "VARCHAR")
	n := athenaNames(ssn, id, dotted, sharp)
	for _, row := range n.rows {
		want := strings.Join([]string{athenaName(row.GetCatalog()), athenaName(row.GetSchema()), athenaName(row.GetTable()), athenaName(row.GetColumn())}, ".")
		if got := n.key(t, row); got != want {
			t.Errorf("catalog key %q, want athenaName spelling %q", got, want)
		}
	}
	for _, sql := range []string{`SELECT "SSN" FROM "USERS"`, `SELECT Ssn FROM Users`, `SELECT ssn FROM users`, `SELECT "ssn" FROM AwsDataCatalog."SAMPLE".Users`} {
		requireReads(t, n, sql, n.key(t, ssn))
	}
	requireReads(t, n, `SELECT * FROM "Users"`, n.key(t, ssn), n.key(t, id))
	for _, sql := range []string{`SELECT "İd" FROM "İnfo"`, `SELECT İd FROM İnfo`, `SELECT İD FROM İNFO`} {
		requireReads(t, n, sql, n.key(t, dotted))
	}
	for _, sql := range []string{`SELECT ẞ FROM Straße`, `SELECT ß FROM STRAßE`, `SELECT "ẞ" FROM "Straße"`} {
		requireReads(t, n, sql, n.key(t, sharp))
	}
	requireClosed(t, n, `SELECT ß FROM STRASSE`)
	requireClosed(t, n, `SELECT ss FROM Straße`)
}

func TestNamePostgresQuotedTwinsNeverSwap(t *testing.T) {
	lowerLower, lowerUpper := pbColumn("public", "users", "ssn", "VARCHAR"), pbColumn("public", "users", "SSN", "VARCHAR")
	upperLower, upperUpper := pbColumn("public", "Users", "ssn", "VARCHAR"), pbColumn("public", "Users", "SSN", "VARCHAR")
	n := postgresNames([]string{"public"}, lowerLower, lowerUpper, upperLower, upperUpper)
	distinct := map[string]bool{}
	for _, row := range []*pb.Column{lowerLower, lowerUpper, upperLower, upperUpper} {
		distinct[n.key(t, row)] = true
	}
	if len(distinct) != 4 {
		t.Fatalf("quoted twins share keys: %v", distinct)
	}
	cases := []struct {
		sql  string
		want []*pb.Column
	}{
		{`SELECT ssn FROM users`, []*pb.Column{lowerLower}},
		{`SELECT SSN FROM USERS`, []*pb.Column{lowerLower}},
		{`SELECT "SSN" FROM users`, []*pb.Column{lowerUpper}},
		{`SELECT ssn FROM "Users"`, []*pb.Column{upperLower}},
		{`SELECT "SSN" FROM "Users"`, []*pb.Column{upperUpper}},
		{`SELECT * FROM users`, []*pb.Column{lowerLower, lowerUpper}},
		{`SELECT * FROM "Users"`, []*pb.Column{upperLower, upperUpper}},
		{`SELECT u.ssn FROM "Users" u WHERE u."SSN" = 'x'`, []*pb.Column{upperLower, upperUpper}},
		{`SELECT a."SSN", b.ssn FROM users a JOIN "Users" b ON a.ssn = b."SSN"`, []*pb.Column{lowerLower, lowerUpper, upperLower, upperUpper}},
	}
	for _, tc := range cases {
		want := make([]string, len(tc.want))
		for i, row := range tc.want {
			want[i] = n.key(t, row)
		}
		requireReads(t, n, tc.sql, want...)
	}
	requireClosed(t, n, `SELECT "Ssn" FROM users`)
	requireClosed(t, n, `SELECT ssn FROM "USERS"`)
}

func TestNameMySQLSystemSchemasBySQL(t *testing.T) {
	processlist := pbColumn("information_schema", "PROCESSLIST", "INFO", "VARCHAR")
	tables := pbColumn("information_schema", "TABLES", "TABLE_NAME", "VARCHAR")
	mysqlUser := pbColumn("mysql", "user", "authentication_string", "VARCHAR")
	sysList := pbColumn("sys", "processlist", "current_statement", "VARCHAR")
	userMySQL := pbColumn("MYSQL", "USER", "pw", "VARCHAR")
	userSys := pbColumn("SYS", "x", "secret", "VARCHAR")

	zero := mysqlNames(0, "App", processlist, tables, mysqlUser, sysList, userMySQL, userSys)
	if got := zero.key(t, processlist); got != "def.information_schema.processlist.info" {
		t.Errorf("information_schema key under lctn 0 = %q", got)
	}
	requireReads(t, zero, `SELECT INFO FROM INFORMATION_SCHEMA.PROCESSLIST`, zero.key(t, processlist))
	requireReads(t, zero, `SELECT info FROM Information_Schema.ProcessList`, zero.key(t, processlist))
	requireReads(t, zero, `SELECT table_name FROM information_schema.Tables`, zero.key(t, tables))
	requireReads(t, zero, `SELECT pw FROM MYSQL.USER`, zero.key(t, userMySQL))
	requireReads(t, zero, `SELECT authentication_string FROM mysql.user`, zero.key(t, mysqlUser))
	requireClosed(t, zero, `SELECT authentication_string FROM MYSQL.USER`)
	requireReads(t, zero, `SELECT secret FROM SYS.x`, zero.key(t, userSys))
	requireClosed(t, zero, `SELECT current_statement FROM SYS.PROCESSLIST`)
	requireClosed(t, zero, `SELECT secret FROM sys.x`)

	for _, lctn := range []int32{1, 2} {
		n := mysqlNames(lctn, "App", processlist, tables, mysqlUser, sysList)
		requireReads(t, n, `SELECT INFO FROM INFORMATION_SCHEMA.PROCESSLIST`, n.key(t, processlist))
		requireReads(t, n, `SELECT table_name FROM information_schema.Tables`, n.key(t, tables))
		requireReads(t, n, `SELECT authentication_string FROM MYSQL.USER`, n.key(t, mysqlUser))
		requireReads(t, n, `SELECT current_statement FROM SYS.PROCESSLIST`, n.key(t, sysList))
		if got := n.key(t, userMySQL); got != "def.mysql.user.pw" {
			t.Errorf("lctn %d: MYSQL.USER key %q does not fold to the system schema", lctn, got)
		}
	}
}

func TestNamePostgresSearchPathCase(t *testing.T) {
	quoted, folded := pbColumn("App", "t", "ssn", "VARCHAR"), pbColumn("app", "t", "ssn", "VARCHAR")
	cases := []struct {
		name    string
		path    []string
		want    *pb.Column
		pending string
	}{
		{"lowercase entry", []string{"app"}, folded, ""},
		{"mixed-case entry as current_schemas reports it", []string{"App"}, quoted, "search_path entries are folded as unquoted identifiers"},
		{"mixed-case entry ahead of lowercase", []string{"App", "app"}, quoted, "search_path entries are folded as unquoted identifiers"},
		{"lowercase entry ahead of mixed-case", []string{"app", "App"}, folded, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pending != "" {
				t.Skip("pending-name-fix: " + tc.pending)
			}
			n := postgresNames(tc.path, quoted, folded)
			requireReads(t, n, `SELECT ssn FROM t`, n.key(t, tc.want))
		})
	}
	t.Run("entry naming no schema", func(t *testing.T) {
		t.Skip("pending-name-fix: search_path entry APP folds onto schema app")
		requireClosed(t, postgresNames([]string{"APP"}, quoted, folded), `SELECT ssn FROM t`)
	})
}

func TestNamePostgresExcludedCase(t *testing.T) {
	lower, upper := pbColumn("public", "users", "ssn", "VARCHAR"), pbColumn("public", "users", "SSN", "VARCHAR")
	source := pbColumn("public", "Users", "ssn", "VARCHAR")
	n := postgresNames([]string{"public"}, lower, upper, source)
	for _, alias := range []string{"excluded", "EXCLUDED", "Excluded", `"excluded"`} {
		requireReads(t, n, `INSERT INTO users (ssn) VALUES ('a') ON CONFLICT (ssn) DO UPDATE SET ssn = `+alias+`.ssn`, n.key(t, lower))
		requireReads(t, n, `INSERT INTO users ("SSN") VALUES ('a') ON CONFLICT ("SSN") DO UPDATE SET "SSN" = `+alias+`."SSN"`, n.key(t, upper))
		requireReads(t, n, `INSERT INTO users ("SSN") SELECT ssn FROM "Users" ON CONFLICT ("SSN") DO UPDATE SET "SSN" = `+alias+`."SSN"`, n.key(t, upper), n.key(t, source))
	}
	t.Run("quoted EXCLUDED names no relation", func(t *testing.T) {
		t.Skip(`pending-name-fix: "EXCLUDED" resolves as the excluded pseudo-relation`)
		requireClosed(t, n, `INSERT INTO users (ssn) SELECT ssn FROM "Users" ON CONFLICT (ssn) DO UPDATE SET ssn = "EXCLUDED".ssn`)
	})
	t.Run("excluded column naming no target column", func(t *testing.T) {
		t.Skip("pending-name-fix: EXCLUDED column names are not checked against the target table")
		requireClosed(t, n, `INSERT INTO users (ssn) VALUES ('a') ON CONFLICT (ssn) DO UPDATE SET ssn = excluded."Ssn"`)
	})
}

func TestNameFunctionQualifierCase(t *testing.T) {
	ssn := pbColumn("App", "Users", "SSN", "VARCHAR")
	zero := mysqlNames(0, "App", ssn)
	requireReads(t, zero, `SELECT App.MY_UDF(ssn) FROM Users`, zero.key(t, ssn))
	if got := nameFunctions(zero.facts(t, `SELECT App.MY_UDF(ssn) FROM Users`)); strings.Join(got, ",") != "App.my_udf" {
		t.Errorf("lctn 0 function grant = %v, want App.my_udf", got)
	}
	requireClosed(t, zero, `SELECT APP.my_udf(ssn) FROM Users`)
	requireClosed(t, zero, `SELECT app.my_udf(ssn) FROM Users`)
	for _, lctn := range []int32{1, 2} {
		n := mysqlNames(lctn, "App", ssn)
		for _, sql := range []string{`SELECT App.my_udf(ssn) FROM Users`, `SELECT APP.MY_UDF(ssn) FROM Users`, "SELECT `app`.My_Udf(ssn) FROM Users", `SELECT MY_UDF(ssn) FROM Users`} {
			if got := nameFunctions(n.facts(t, sql)); strings.Join(got, ",") != "app.my_udf" {
				t.Errorf("lctn %d %q function grant = %v, want app.my_udf", lctn, sql, got)
			}
		}
	}

	pg := postgresNames([]string{"public"}, pbColumn("public", "users", "ssn", "VARCHAR"))
	pg.udfs = map[string][]string{"public": {"Leak", "leak2"}, "App": {"f"}, "app": {"g"}}
	cases := []struct{ sql, want string }{
		{`SELECT "Leak"(ssn) FROM users`, "public.Leak"},
		{`SELECT LEAK2(ssn) FROM users`, "public.leak2"},
		{`SELECT "App".f() FROM users`, "App.f"},
		{`SELECT APP.g() FROM users`, "app.g"},
		{`SELECT "lower"(ssn) FROM users`, ""},
		{`SELECT LOWER(ssn) FROM users`, ""},
		{`SELECT PG_CATALOG.lower(ssn) FROM users`, ""},
	}
	for _, tc := range cases {
		facts := pg.facts(t, tc.sql)
		if !facts.GetResolved() {
			t.Errorf("%q unresolved: %s", tc.sql, facts.GetDetail())
			continue
		}
		var udfs []string
		for _, g := range facts.GetResultReads() {
			if f := g.GetFunction(); f != nil && !f.GetBuiltin() {
				udfs = append(udfs, f.GetName())
			}
		}
		if strings.Join(udfs, ",") != tc.want {
			t.Errorf("%q user function grants = %v, want %q", tc.sql, udfs, tc.want)
		}
	}
	for _, sql := range []string{`SELECT Leak(ssn) FROM users`, `SELECT "LEAK2"(ssn) FROM users`, `SELECT App.f() FROM users`, `SELECT "APP".g() FROM users`, `SELECT "Lower"(ssn) FROM users`, `SELECT "PG_CATALOG".lower(ssn) FROM users`} {
		requireClosed(t, pg, sql)
	}

}

func TestNameMySQLCTEAndDerivedCase(t *testing.T) {
	ssn, id, base := pbColumn("App", "Users", "SSN", "VARCHAR"), pbColumn("App", "Users", "ID", "BIGINT"), pbColumn("App", "c", "ssn", "VARCHAR")
	zero := mysqlNames(0, "App", ssn, id, base)
	requireReads(t, zero, `WITH C AS (SELECT id AS ssn FROM Users) SELECT ssn FROM C`, zero.key(t, id))
	requireReads(t, zero, `WITH C AS (SELECT id AS ssn FROM Users) SELECT ssn FROM c`, zero.key(t, base))
	requireReads(t, zero, `WITH C AS (SELECT ssn FROM Users) SELECT x.SSN FROM C x`, zero.key(t, ssn))
	requireClosed(t, zero, `SELECT X.ssn FROM (SELECT ssn FROM Users) x`)
	requireReads(t, zero, `SELECT x.SSN FROM (SELECT ssn FROM Users) x`, zero.key(t, ssn))
	requireReads(t, zero, `SELECT App.Users.ssn FROM App.Users`, zero.key(t, ssn))
	requireClosed(t, zero, `SELECT APP.USERS.ssn FROM App.Users`)
	requireClosed(t, zero, `SELECT ssn FROM app.users`)
	for _, lctn := range []int32{1, 2} {
		n := mysqlNames(lctn, "App", ssn, id, base)
		requireReads(t, n, `WITH C AS (SELECT id AS ssn FROM Users) SELECT ssn FROM C`, n.key(t, id))
		requireReads(t, n, `WITH C AS (SELECT id AS ssn FROM Users) SELECT ssn FROM c`, n.key(t, id))
		requireReads(t, n, `WITH C AS (SELECT ssn FROM Users) SELECT X.SSN FROM c x`, n.key(t, ssn))
		requireReads(t, n, `SELECT X.ssn FROM (SELECT ssn FROM Users) x`, n.key(t, ssn))
		requireReads(t, n, `SELECT APP.USERS.ssn FROM App.Users`, n.key(t, ssn))
		requireReads(t, n, `SELECT ssn FROM app.users`, n.key(t, ssn))
		requireReads(t, n, "SELECT `App`.`USERS`.`Ssn` FROM `APP`.`users`", n.key(t, ssn))
		requireClosed(t, n, `WITH c AS (SELECT 1 AS ssn) SELECT ssn FROM c JOIN C ON true`)
	}
}

func TestNameNonASCIIFolds(t *testing.T) {
	type spelling struct{ table, column string }
	targets := []struct {
		name  string
		n     nameTarget
		row   *pb.Column
		same  []spelling
		other []spelling
	}{
		{"mysql lctn 0", mysqlNames(0, "App"), pbColumn("App", "İnfo", "ß", "VARCHAR"),
			[]spelling{{"İnfo", "ß"}, {"`İnfo`", "`ß`"}}, []spelling{{"İNFO", "ß"}, {"i̇nfo", "ß"}, {"İnfo", "ss"}}},
		{"mysql lctn 1", mysqlNames(1, "App"), pbColumn("App", "İnfo", "ß", "VARCHAR"),
			[]spelling{{"İnfo", "ß"}, {"İNFO", "ß"}, {"`İNFO`", "`ß`"}}, []spelling{{"i̇nfo", "ß"}, {"İnfo", "ss"}}},
		{"mysql kelvin sign folds to k", mysqlNames(1, "App"), pbColumn("App", "Info", "\u212a", "VARCHAR"),
			[]spelling{{"Info", "k"}, {"Info", "K"}, {"Info", "`\u212a`"}}, []spelling{{"Info", "kk"}}},
		{"mysql accent kept", mysqlNames(1, "App"), pbColumn("App", "Info", "CAFÉ", "VARCHAR"),
			[]spelling{{"Info", "café"}, {"Info", "CAFÉ"}, {"Info", "`café`"}}, []spelling{{"Info", "cafe"}, {"Info", "CAFE"}}},
		{"postgres", postgresNames([]string{"public"}), pbColumn("public", "İnfo", "ß", "VARCHAR"),
			[]spelling{{"İnfo", "ß"}, {"İNFO", "ß"}, {`"İnfo"`, `"ß"`}}, []spelling{{`"İNFO"`, "ß"}, {"i̇nfo", "ß"}, {"İnfo", "ss"}}},
		{"postgres non-ASCII stays", postgresNames([]string{"public"}), pbColumn("public", "cafÉ", "x", "VARCHAR"),
			[]spelling{{"CAFÉ", "x"}, {"cafÉ", "X"}, {`"cafÉ"`, `"x"`}}, []spelling{{"café", "x"}, {`"CAFÉ"`, "x"}}},
		{"athena", athenaNames(), catalogColumn("AwsDataCatalog", "Sample", "İnfo", "ẞ", "VARCHAR"),
			[]spelling{{"İnfo", "ẞ"}, {"İNFO", "ß"}, {`"İnfo"`, `"ẞ"`}}, []spelling{{"İnfo", "ss"}}},
	}
	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			n := tc.n
			n.rows = []*pb.Column{tc.row}
			key := n.key(t, tc.row)
			session := n.datasource(t)
			for _, s := range tc.same {
				requireReads(t, n, "SELECT "+s.column+" FROM "+s.table, key)
				parsed, err := session.ParseColumn(n.catalog, n.searchPath[0], s.table, s.column)
				if err != nil {
					t.Errorf("ParseColumn(%s, %s): %v", s.table, s.column, err)
					continue
				}
				got := refKey(&pb.ObjectRef{Catalog: parsed.Catalog().String(), Schema: n.schema(t, parsed.Schema().String()), Table: parsed.Table(), Column: parsed.Column()})
				if got != key {
					t.Errorf("ParseColumn(%s, %s) = %q, SQL and catalog key %q", s.table, s.column, got, key)
				}
			}
			for _, s := range tc.other {
				requireClosed(t, n, "SELECT "+s.column+" FROM "+s.table)
			}
		})
	}
}

// For each engine and MySQL mode, every case and quote variant of schema, table, column and table alias either
// resolves to the catalog key of the one row it denotes or fails closed when it denotes none.
func TestNameVariantsMeetCatalogKey(t *testing.T) {
	type target struct {
		name  string
		n     nameTarget
		quote string
		// denotes reports whether identifier text, quoted or not, names raw; relation is a schema, table or alias.
		denotes func(text string, quoted, relation bool, raw string) bool
	}
	ascii := func(text string, _, _ bool, raw string) bool { return strings.EqualFold(text, raw) }
	mysqlDenotes := func(lctn int32) func(string, bool, bool, string) bool {
		return func(text string, _, relation bool, raw string) bool {
			if relation && lctn == 0 {
				return text == raw
			}
			return strings.EqualFold(text, raw)
		}
	}
	postgresDenotes := func(text string, quoted, _ bool, raw string) bool {
		if quoted {
			return text == raw
		}
		return strings.ToLower(text) == raw
	}
	mixed := []*pb.Column{pbColumn("Sch", "Tab", "Col", "VARCHAR"), pbColumn("Sch", "Tab", "Id", "BIGINT")}
	targets := []target{
		{"mysql lctn 0", mysqlNames(0, "Sch", append(mixed, pbColumn("sch", "tab", "col", "VARCHAR"), pbColumn("Sch", "tab", "other", "VARCHAR"))...), "`", mysqlDenotes(0)},
		{"mysql lctn 1", mysqlNames(1, "Sch", mixed...), "`", mysqlDenotes(1)},
		{"mysql lctn 2", mysqlNames(2, "Sch", mixed...), "`", mysqlDenotes(2)},
		{"postgres", postgresNames([]string{"sch"}, append(mixed, pbColumn("sch", "tab", "col", "VARCHAR"), pbColumn("sch", "Tab", "COL", "VARCHAR"))...), `"`, postgresDenotes},
		{"athena", athenaNames(catalogColumn("awsdatacatalog", "Sch", "Tab", "Col", "VARCHAR")), `"`, ascii},
	}
	variants := func(base string) []string {
		return []string{strings.ToLower(base), strings.ToUpper(base), base}
	}
	type ident struct {
		text   string
		quoted bool
	}
	spell := func(base, quote string) []ident {
		var out []ident
		for _, v := range variants(base) {
			out = append(out, ident{v, false}, ident{v, true})
		}
		return append(out, ident{base + "z", false})
	}
	sql := func(quote string, id ident) string {
		if id.quoted {
			return quote + id.text + quote
		}
		return id.text
	}
	for _, tg := range targets {
		t.Run(tg.name, func(t *testing.T) {
			n := tg.n
			if n.engine == pb.Engine_ATHENA {
				n.searchPath = []string{"Sch"}
			}
			denoted := func(schema, table, column ident) *pb.Column {
				var hit *pb.Column
				for _, row := range n.rows {
					if tg.denotes(schema.text, schema.quoted, true, row.GetSchema()) && tg.denotes(table.text, table.quoted, true, row.GetTable()) &&
						tg.denotes(column.text, column.quoted, false, row.GetColumn()) {
						if hit != nil {
							t.Fatalf("fixture: %v and %v both match", hit, row)
						}
						hit = row
					}
				}
				return hit
			}
			resolved, closed := 0, 0
			check := func(query string, row *pb.Column) {
				t.Helper()
				if row == nil {
					closed++
					requireClosed(t, n, query)
					return
				}
				resolved++
				requireReads(t, n, query, n.key(t, row))
			}
			query := func(s, tb, c ident) {
				check("SELECT "+sql(tg.quote, c)+" FROM "+sql(tg.quote, s)+"."+sql(tg.quote, tb), denoted(s, tb, c))
			}
			for _, s := range spell("Sch", tg.quote) {
				for _, tb := range spell("Tab", tg.quote) {
					query(s, tb, ident{"Col", true})
					query(s, tb, ident{"COL", false})
				}
			}
			for _, c := range spell("Col", tg.quote) {
				query(ident{"Sch", true}, ident{"Tab", true}, c)
				query(ident{"sch", false}, ident{"TAB", false}, c)
			}
			alias := ident{"Al", false}
			for _, ref := range spell("Al", tg.quote) {
				var row *pb.Column
				if tg.denotes(ref.text, ref.quoted, true, n.canonicalAlias(alias.text)) {
					row = denoted(ident{"Sch", true}, ident{"Tab", true}, ident{"Col", true})
				}
				check("SELECT "+sql(tg.quote, ref)+"."+sql(tg.quote, ident{"Col", true})+" FROM "+sql(tg.quote, ident{"Sch", true})+"."+sql(tg.quote, ident{"Tab", true})+" "+alias.text, row)
			}
			if resolved+closed != 7*7*2+7*2+7 || resolved == 0 || closed == 0 {
				t.Fatalf("checked %d resolving and %d closed spellings", resolved, closed)
			}
		})
	}
}

// canonicalAlias is how an unquoted alias declaration is spelled for later references.
func (n nameTarget) canonicalAlias(text string) string {
	if n.engine == pb.Engine_MYSQL && n.lctn == 0 {
		return text
	}
	return strings.ToLower(text)
}
