package db

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/introspect"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func quoteMySQL(identifier string) string {
	return "`" + strings.ReplaceAll(identifier, "`", "``") + "`"
}

func introspectTarget(t *testing.T, open func(spi.TargetDb) (*sql.DB, error), adapter engine.Db, probe introspect.NamespaceProbe, target dbtest.TargetDb, database string) *pb.CatalogRequest {
	t.Helper()
	pool, err := open(spi.TargetDb{Host: target.Host, Port: target.Port, Db: database, User: target.User, Password: target.Password})
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	defer pool.Close()
	catalog, err := introspect.Run(context.Background(), pool, adapter, probe, database)
	if err != nil {
		t.Fatalf("introspect.Run(%q): %v", database, err)
	}
	return catalog
}

func pinConn(t *testing.T, database *sql.DB) *sql.Conn {
	t.Helper()
	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("pin connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type relationKey struct{ schema, table, column string }

func relationKeys(columns []*analyzerpb.Column, schema string) []relationKey {
	var keys []relationKey
	for _, c := range columns {
		if c.GetSchema() == schema {
			keys = append(keys, relationKey{c.GetSchema(), c.GetTable(), c.GetColumn()})
		}
	}
	slices.SortFunc(keys, func(a, b relationKey) int {
		return cmp.Or(cmp.Compare(a.table, b.table), cmp.Compare(a.column, b.column))
	})
	return keys
}

func schemaColumns(columns []*analyzerpb.Column, schema string) []*analyzerpb.Column {
	var out []*analyzerpb.Column
	for _, c := range columns {
		if c.GetSchema() == schema {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b *analyzerpb.Column) int {
		return cmp.Or(cmp.Compare(a.GetTable(), b.GetTable()), cmp.Compare(a.GetOrdinal(), b.GetOrdinal()), cmp.Compare(a.GetColumn(), b.GetColumn()))
	})
	return out
}

// assertFragmentMatchesBulk requires a refetch of schema to equal the bulk catalog, and its hash to be stable.
func assertFragmentMatchesBulk(t *testing.T, adapter engine.Db, conn *sql.Conn, catalog string, bulk *pb.CatalogRequest, schema string) {
	t.Helper()
	want := schemaColumns(bulk.GetCatalog().GetColumns(), schema)
	if len(want) == 0 {
		t.Fatalf("bulk catalog has no columns under schema %q", schema)
	}
	push := runRefetchIntegration(t, adapter, conn, catalog, schema, nil)
	if got := schemaColumns(push.GetColumns(), schema); !equalColumns(got, want) || len(push.GetColumns()) != len(want) {
		t.Fatalf("refetch %q columns = %+v\nwant bulk %+v", schema, push.GetColumns(), want)
	}
	again := runRefetchIntegration(t, adapter, conn, catalog, schema, push.GetContentHash())
	if !again.GetUnchanged() || !bytes.Equal(again.GetContentHash(), push.GetContentHash()) {
		t.Fatalf("refetch %q with its own hash = %+v, want unchanged", schema, again)
	}
}

func TestMySQLLowerCase0KeepsSchemaAndTableCase(t *testing.T) {
	target := dbtest.MySQL(t)
	admin := dbtest.OpenMySQL(t, "")
	conn := pinConn(t, admin)
	if mode := mysqlMode(t, conn); mode != 0 {
		t.Fatalf("default MySQL container lower_case_table_names = %d, want 0", mode)
	}
	upper := uniqueFixtureName("PmNamesApp")
	lower := strings.ToLower(upper)
	for _, schema := range []string{upper, lower} {
		execRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quoteMySQL(schema))
		execRefetchSQL(t, conn, "CREATE DATABASE "+quoteMySQL(schema))
		t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + quoteMySQL(schema)) })
	}
	execRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(upper)+".`Users` (Id INT NOT NULL, EMail VARCHAR(64) NULL)")
	execRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(upper)+".`users` (id INT NOT NULL, Note VARCHAR(64) NULL)")
	execRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(lower)+".`users` (id INT NOT NULL, email VARCHAR(64) NULL)")

	bulk := introspectTarget(t, introspect.OpenMySQLTarget, MySqlDb{}, introspect.ProbeMySQLNamespace, target, upper)
	if got := bulk.GetDefaultSchemas(); !slices.Equal(got, []string{upper}) {
		t.Fatalf("DefaultSchemas = %v, want [%s]", got, upper)
	}
	if bulk.GetMysqlLowerCaseTableNames() != 0 {
		t.Fatalf("pushed lower_case_table_names = %d, want 0", bulk.GetMysqlLowerCaseTableNames())
	}
	cols := bulk.GetCatalog().GetColumns()
	if got, want := relationKeys(cols, upper), []relationKey{
		{upper, "Users", "email"}, {upper, "Users", "id"}, {upper, "users", "id"}, {upper, "users", "note"},
	}; !slices.Equal(got, want) {
		t.Errorf("pushed %s columns = %v, want %v", upper, got, want)
	}
	if got, want := relationKeys(cols, lower), []relationKey{{lower, "users", "email"}, {lower, "users", "id"}}; !slices.Equal(got, want) {
		t.Errorf("pushed %s columns = %v, want %v", lower, got, want)
	}

	assertFragmentMatchesBulk(t, MySqlDb{}, conn, "def", bulk, upper)
	assertFragmentMatchesBulk(t, MySqlDb{}, conn, "def", bulk, lower)
	if bytes.Equal(trustedRefetchHash(t, MySqlDb{}, conn, upper), trustedRefetchHash(t, MySqlDb{}, conn, lower)) {
		t.Fatalf("schemas %q and %q hash identically", upper, lower)
	}
	if !bytes.Equal(trustedRefetchHash(t, MySqlDb{}, conn, upper), trustedRefetchHash(t, MySqlDb{}, conn, upper)) {
		t.Fatalf("schema %q hash is not stable", upper)
	}
}

func TestMySQLLowerCase1FoldsSchemaAndTable(t *testing.T) {
	target := dbtest.MySQLLowerCase1(t)
	admin := dbtest.OpenMySQLLowerCase1(t, "")
	conn := pinConn(t, admin)
	if mode := mysqlMode(t, conn); mode != 1 {
		t.Fatalf("lower_case_table_names = %d, want 1", mode)
	}
	mixed := uniqueFixtureName("PmNamesApp")
	canonical := strings.ToLower(mixed)
	execRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quoteMySQL(mixed))
	execRefetchSQL(t, conn, "CREATE DATABASE "+quoteMySQL(mixed))
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + quoteMySQL(mixed)) })
	execRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(mixed)+".`Users` (Id INT NOT NULL, EMail VARCHAR(64) NULL)")
	execRefetchSQL(t, conn, "CREATE FUNCTION "+quoteMySQL(mixed)+".`AddTax` (amount INT) RETURNS INT DETERMINISTIC RETURN amount")

	bulk := introspectTarget(t, introspect.OpenMySQLTarget, MySqlDb{}, introspect.ProbeMySQLNamespace, target, mixed)
	if got := bulk.GetDefaultSchemas(); !slices.Equal(got, []string{canonical}) {
		t.Fatalf("DefaultSchemas = %v, want [%s]", got, canonical)
	}
	if bulk.GetMysqlLowerCaseTableNames() != 1 {
		t.Fatalf("pushed lower_case_table_names = %d, want 1", bulk.GetMysqlLowerCaseTableNames())
	}
	cols := bulk.GetCatalog().GetColumns()
	if got, want := relationKeys(cols, canonical), []relationKey{{canonical, "users", "email"}, {canonical, "users", "id"}}; !slices.Equal(got, want) {
		t.Errorf("pushed %s columns = %v, want %v", canonical, got, want)
	}
	for _, c := range cols {
		if c.GetSchema() != strings.ToLower(c.GetSchema()) || c.GetTable() != strings.ToLower(c.GetTable()) || c.GetColumn() != strings.ToLower(c.GetColumn()) {
			t.Errorf("pushed column %s.%s.%s is not canonical lowercase", c.GetSchema(), c.GetTable(), c.GetColumn())
		}
	}
	for _, system := range []string{"information_schema", "mysql", "performance_schema", "sys"} {
		if len(relationKeys(cols, system)) == 0 {
			t.Errorf("system schema %q missing from the pushed catalog", system)
		}
	}
	var routines []string
	for _, group := range bulk.GetCatalog().GetRoutines() {
		if group.GetSchema() == canonical {
			routines = group.GetNames()
		}
	}
	if !slices.Equal(routines, []string{"addtax"}) {
		t.Errorf("pushed %s routines = %v, want [addtax]", canonical, routines)
	}

	assertFragmentMatchesBulk(t, MySqlDb{}, conn, "def", bulk, canonical)
	assertFragmentMatchesBulk(t, MySqlDb{}, conn, "def", bulk, "information_schema")
}

func mysqlMode(t *testing.T, conn *sql.Conn) int {
	t.Helper()
	var mode int
	if err := conn.QueryRowContext(context.Background(), "SELECT @@lower_case_table_names").Scan(&mode); err != nil {
		t.Fatalf("read lower_case_table_names: %v", err)
	}
	return mode
}

// lowerCase2Db evaluates MySqlDb's SQL as mode 2 on a case-preserving mode-0 server; Linux cannot run mode 2.
type lowerCase2Db struct{ MySqlDb }

func asMode2(sqlText string) string {
	return strings.ReplaceAll(sqlText, "@@lower_case_table_names", "2")
}

func (d lowerCase2Db) Datasource(query func(string) (*string, error)) (engines.Datasource, error) {
	return d.MySqlDb.Datasource(func(string) (*string, error) { return query("SELECT 2") })
}
func (d lowerCase2Db) SchemaColumnsSQL(schema string) string {
	return asMode2(d.MySqlDb.SchemaColumnsSQL(schema))
}
func (d lowerCase2Db) SchemaRoutinesSQL(schema string) string {
	return asMode2(d.MySqlDb.SchemaRoutinesSQL(schema))
}
func (d lowerCase2Db) SchemaHashSQL(schema string, setup [][]*string) (string, int, error) {
	sqlText, columns, err := d.MySqlDb.SchemaHashSQL(schema, setup)
	return asMode2(sqlText), columns, err
}

func probeAsMode2(ctx context.Context, conn *sql.Conn, targetDb string) (*pb.CatalogRequest, error) {
	catalog, err := introspect.ProbeMySQLNamespace(ctx, conn, targetDb)
	if err != nil {
		return nil, err
	}
	two := int32(2)
	catalog.MysqlLowerCaseTableNames = &two
	return catalog, nil
}

func TestMySQLLowerCase2FoldsStoredCase(t *testing.T) {
	target := dbtest.MySQL(t)
	admin := dbtest.OpenMySQL(t, "")
	conn := pinConn(t, admin)
	mixed := uniqueFixtureName("PmNamesMode2")
	canonical := strings.ToLower(mixed)
	execRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quoteMySQL(mixed))
	execRefetchSQL(t, conn, "CREATE DATABASE "+quoteMySQL(mixed))
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + quoteMySQL(mixed)) })
	execRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(mixed)+".`Users` (Id INT NOT NULL, EMail VARCHAR(64) NULL)")

	bulk := introspectTarget(t, introspect.OpenMySQLTarget, MySqlDb{}, probeAsMode2, target, mixed)
	if got := bulk.GetDefaultSchemas(); !slices.Equal(got, []string{canonical}) {
		t.Fatalf("DefaultSchemas = %v, want [%s]", got, canonical)
	}
	if got, want := relationKeys(bulk.GetCatalog().GetColumns(), canonical), []relationKey{{canonical, "users", "email"}, {canonical, "users", "id"}}; !slices.Equal(got, want) {
		t.Fatalf("pushed %s columns = %v, want %v", canonical, got, want)
	}
	if got := relationKeys(bulk.GetCatalog().GetColumns(), mixed); len(got) != 0 {
		t.Fatalf("pushed raw-case schema %s columns %v", mixed, got)
	}

	t.Run("refetch and hash find the stored case by its canonical name", func(t *testing.T) {
		adapter := lowerCase2Db{}
		assertFragmentMatchesBulk(t, adapter, conn, "def", bulk, canonical)
		if !bytes.Equal(trustedRefetchHash(t, adapter, conn, canonical), trustedRefetchHash(t, MySqlDb{}, conn, mixed)) {
			t.Fatalf("mode-2 hash of %q differs from the stored-case hash of %q", canonical, mixed)
		}
	})
}

func TestMySQLFragmentRowsUnderEachMode(t *testing.T) {
	row := func(schema, table, column string) [][]*string {
		return [][]*string{{ptr(schema), ptr(table), ptr(column), ptr("int"), ptr("1"), ptr("NO"), ptr("def")}}
	}
	for _, tc := range []struct {
		name                 string
		mode                 int32
		requested            string
		schema, table, colmn string
		want                 *relationKey
	}{
		{"mode 0 keeps case", 0, "App", "App", "Users", "EMail", &relationKey{"App", "Users", "email"}},
		{"mode 0 refuses a case-differing row", 0, "app", "App", "Users", "EMail", nil},
		{"mode 1 folds", 1, "app", "app", "users", "EMail", &relationKey{"app", "users", "email"}},
		{"mode 2 folds the stored case", 2, "app", "App", "Users", "EMail", &relationKey{"app", "users", "email"}},
		{"mode 2 refuses another schema", 2, "app", "Other", "Users", "EMail", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.FragmentColumnsFromRows(MySqlDb{}, mysqlDatasource(t, tc.mode), tc.requested, row(tc.schema, tc.table, tc.colmn))
			if tc.want == nil {
				if err == nil {
					t.Fatalf("FragmentColumnsFromRows = %+v, want refused", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("FragmentColumnsFromRows: %v", err)
			}
			if len(got) != 1 || (relationKey{got[0].GetSchema(), got[0].GetTable(), got[0].GetColumn()}) != *tc.want {
				t.Fatalf("FragmentColumnsFromRows = %+v, want %v", got, *tc.want)
			}
		})
	}
}

func TestMySQLNormalizeSystemSchemasByMode(t *testing.T) {
	for _, tc := range []struct {
		mode   int32
		schema string
		want   string
	}{
		{0, "INFORMATION_SCHEMA", "information_schema"},
		{0, "Information_Schema", "information_schema"},
		{0, "SYS", "SYS"},
		{0, "MySQL", "MySQL"},
		{0, "PERFORMANCE_SCHEMA", "PERFORMANCE_SCHEMA"},
		{1, "INFORMATION_SCHEMA", "information_schema"},
		{1, "SYS", "sys"},
		{1, "MySQL", "mysql"},
		{1, "PERFORMANCE_SCHEMA", "performance_schema"},
		{2, "INFORMATION_SCHEMA", "information_schema"},
		{2, "SYS", "sys"},
		{2, "MySQL", "mysql"},
		{2, "PERFORMANCE_SCHEMA", "performance_schema"},
	} {
		got := (MySqlDb{}).NormalizeColumns(mysqlDatasource(t, tc.mode), []*analyzerpb.Column{{Schema: tc.schema, Table: "T", Column: "C"}})[0]
		if got.GetSchema() != tc.want || got.GetColumn() != "c" {
			t.Errorf("mode %d NormalizeColumns(%s.T.C) = %s.%s.%s, want schema %s, column c", tc.mode, tc.schema, got.GetSchema(), got.GetTable(), got.GetColumn(), tc.want)
		}
	}
}

func TestMySQLRefetchRefusesUnknownLowerCaseTableNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rows  [][]*string
		probe error
	}{
		{"probe error", nil, sql.ErrConnDone},
		{"no row", [][]*string{}, nil},
		{"NULL", [][]*string{{nil}}, nil},
		{"out of range", [][]*string{{ptr("3")}}, nil},
		{"negative", [][]*string{{ptr("-1")}}, nil},
		{"not a number", [][]*string{{ptr("on")}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pushed := false
			refetcher := engine.Refetcher{
				Catalog: "def",
				Db:      MySqlDb{},
				Probe: func(statement string, _ int) ([][]*string, error) {
					switch statement {
					case lowerCaseTableNamesSQL:
						return tc.rows, tc.probe
					case (MySqlDb{}).SchemaColumnsSQL("App"):
						return [][]*string{{ptr("App"), ptr("Users"), ptr("Id"), ptr("int"), ptr("1"), ptr("NO"), ptr("def")}}, nil
					}
					return nil, nil
				},
				Push: func(*pb.SchemaFragmentPush) (uint64, error) {
					pushed = true
					return 1, nil
				},
			}
			if err := refetcher.Run(&pb.Refetch{Catalog: "def", Schema: "App"}); err == nil || pushed {
				t.Fatalf("Run err = %v, pushed = %v; want refused without a push", err, pushed)
			}
		})
	}
}

func TestPostgresQuotedNamesStayDistinct(t *testing.T) {
	target := dbtest.Postgres(t)
	admin := dbtest.OpenPostgres(t, "")
	name := uniqueFixtureName("pm_names_pg")
	database := createPostgresRefetchDatabase(t, admin, target, name)
	for _, statement := range []string{
		`CREATE SCHEMA "Sales"`,
		`CREATE SCHEMA sales`,
		`CREATE TABLE "Sales"."Users" (id INT NOT NULL, "Email" TEXT)`,
		`CREATE TABLE sales.users (id INT NOT NULL, email TEXT)`,
		`CREATE TABLE "Sales".users (id INT NOT NULL, "EMAIL" TEXT)`,
		`ALTER DATABASE ` + quotePgIdentifier(name) + ` SET search_path = "Sales", Public`,
	} {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("seed %q: %v", statement, err)
		}
	}

	bulk := introspectTarget(t, introspect.OpenPostgresTarget, PgDb{}, introspect.ProbePostgresNamespace, target, name)
	if got := bulk.GetDefaultSchemas(); !slices.Equal(got, []string{"pg_catalog", "Sales", "public"}) {
		t.Errorf("DefaultSchemas = %v, want [pg_catalog Sales public]", got)
	}
	cols := bulk.GetCatalog().GetColumns()
	if got, want := relationKeys(cols, "Sales"), []relationKey{
		{"Sales", "Users", "Email"}, {"Sales", "Users", "id"}, {"Sales", "users", "EMAIL"}, {"Sales", "users", "id"},
	}; !slices.Equal(got, want) {
		t.Errorf("pushed Sales columns = %v, want %v", got, want)
	}
	if got, want := relationKeys(cols, "sales"), []relationKey{{"sales", "users", "email"}, {"sales", "users", "id"}}; !slices.Equal(got, want) {
		t.Errorf("pushed sales columns = %v, want %v", got, want)
	}

	conn := pinConn(t, database)
	assertFragmentMatchesBulk(t, PgDb{}, conn, name, bulk, "Sales")
	assertFragmentMatchesBulk(t, PgDb{}, conn, name, bulk, "sales")
	if bytes.Equal(trustedRefetchHash(t, PgDb{}, conn, "Sales"), trustedRefetchHash(t, PgDb{}, conn, "sales")) {
		t.Fatal(`schemas "Sales" and sales hash identically`)
	}
}
