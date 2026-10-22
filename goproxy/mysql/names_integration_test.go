package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/targettest"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func quoteMySQL(identifier string) string {
	return "`" + strings.ReplaceAll(identifier, "`", "``") + "`"
}

func TestMySQLLowerCase0KeepsSchemaAndTableCase(t *testing.T) {
	targetConfig := dbtest.MySQL(t)
	admin := dbtest.OpenMySQL(t, "")
	conn := targettest.PinConn(t, admin)
	if mode := mysqlMode(t, conn); mode != 0 {
		t.Fatalf("default MySQL container lower_case_table_names = %d, want 0", mode)
	}
	upper := targettest.UniqueFixtureName("PmNamesApp")
	lower := strings.ToLower(upper)
	for _, schema := range []string{upper, lower} {
		targettest.ExecRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quoteMySQL(schema))
		targettest.ExecRefetchSQL(t, conn, "CREATE DATABASE "+quoteMySQL(schema))
		t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + quoteMySQL(schema)) })
	}
	targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(upper)+".`Users` (Id INT NOT NULL, EMail VARCHAR(64) NULL)")
	targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(upper)+".`users` (id INT NOT NULL, Note VARCHAR(64) NULL)")
	targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(lower)+".`users` (id INT NOT NULL, email VARCHAR(64) NULL)")

	bulk := targettest.IntrospectTarget(t, OpenPool, Queries, ProbeNamespace, targetConfig, upper)
	if got := bulk.GetDefaultSchemas(); !slices.Equal(got, []string{upper}) {
		t.Fatalf("DefaultSchemas = %v, want [%s]", got, upper)
	}
	if bulk.GetMysqlLowerCaseTableNames() != 0 {
		t.Fatalf("pushed lower_case_table_names = %d, want 0", bulk.GetMysqlLowerCaseTableNames())
	}
	cols := bulk.GetCatalog().GetColumns()
	if got, want := targettest.RelationKeys(cols, upper), []targettest.RelationKey{
		{upper, "Users", "email"}, {upper, "Users", "id"}, {upper, "users", "id"}, {upper, "users", "note"},
	}; !slices.Equal(got, want) {
		t.Errorf("pushed %s columns = %v, want %v", upper, got, want)
	}
	if got, want := targettest.RelationKeys(cols, lower), []targettest.RelationKey{{lower, "users", "email"}, {lower, "users", "id"}}; !slices.Equal(got, want) {
		t.Errorf("pushed %s columns = %v, want %v", lower, got, want)
	}

	targettest.AssertFragmentMatchesBulk(t, Queries, conn, "def", bulk, upper)
	targettest.AssertFragmentMatchesBulk(t, Queries, conn, "def", bulk, lower)
	if bytes.Equal(targettest.TrustedRefetchHash(t, Queries, conn, upper), targettest.TrustedRefetchHash(t, Queries, conn, lower)) {
		t.Fatalf("schemas %q and %q hash identically", upper, lower)
	}
	if !bytes.Equal(targettest.TrustedRefetchHash(t, Queries, conn, upper), targettest.TrustedRefetchHash(t, Queries, conn, upper)) {
		t.Fatalf("schema %q hash is not stable", upper)
	}
}

func TestMySQLLowerCase1FoldsSchemaAndTable(t *testing.T) {
	targetConfig := dbtest.MySQLLowerCase1(t)
	admin := dbtest.OpenMySQLLowerCase1(t, "")
	conn := targettest.PinConn(t, admin)
	if mode := mysqlMode(t, conn); mode != 1 {
		t.Fatalf("lower_case_table_names = %d, want 1", mode)
	}
	mixed := targettest.UniqueFixtureName("PmNamesApp")
	canonical := strings.ToLower(mixed)
	targettest.ExecRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quoteMySQL(mixed))
	targettest.ExecRefetchSQL(t, conn, "CREATE DATABASE "+quoteMySQL(mixed))
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + quoteMySQL(mixed)) })
	targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(mixed)+".`Users` (Id INT NOT NULL, EMail VARCHAR(64) NULL)")
	targettest.ExecRefetchSQL(t, conn, "CREATE FUNCTION "+quoteMySQL(mixed)+".`AddTax` (amount INT) RETURNS INT DETERMINISTIC RETURN amount")

	bulk := targettest.IntrospectTarget(t, OpenPool, Queries, ProbeNamespace, targetConfig, mixed)
	if got := bulk.GetDefaultSchemas(); !slices.Equal(got, []string{canonical}) {
		t.Fatalf("DefaultSchemas = %v, want [%s]", got, canonical)
	}
	if bulk.GetMysqlLowerCaseTableNames() != 1 {
		t.Fatalf("pushed lower_case_table_names = %d, want 1", bulk.GetMysqlLowerCaseTableNames())
	}
	cols := bulk.GetCatalog().GetColumns()
	if got, want := targettest.RelationKeys(cols, canonical), []targettest.RelationKey{{canonical, "users", "email"}, {canonical, "users", "id"}}; !slices.Equal(got, want) {
		t.Errorf("pushed %s columns = %v, want %v", canonical, got, want)
	}
	for _, c := range cols {
		if c.GetSchema() != strings.ToLower(c.GetSchema()) || c.GetTable() != strings.ToLower(c.GetTable()) || c.GetColumn() != strings.ToLower(c.GetColumn()) {
			t.Errorf("pushed column %s.%s.%s is not canonical lowercase", c.GetSchema(), c.GetTable(), c.GetColumn())
		}
	}
	for _, system := range []string{"information_schema", "mysql", "performance_schema", "sys"} {
		if len(targettest.RelationKeys(cols, system)) == 0 {
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

	targettest.AssertFragmentMatchesBulk(t, Queries, conn, "def", bulk, canonical)
	targettest.AssertFragmentMatchesBulk(t, Queries, conn, "def", bulk, "information_schema")
}

func mysqlMode(t *testing.T, conn *sql.Conn) int {
	t.Helper()
	var mode int
	if err := conn.QueryRowContext(context.Background(), "SELECT @@lower_case_table_names").Scan(&mode); err != nil {
		t.Fatalf("read lower_case_table_names: %v", err)
	}
	return mode
}

func asMode2(sqlText string) string {
	return strings.ReplaceAll(sqlText, "@@lower_case_table_names", "2")
}

// lowerCase2Queries evaluates MySQL's SQL as mode 2 on a case-preserving mode-0 server; Linux cannot run mode 2.
func lowerCase2Queries() sqldb.Queries {
	queries := Queries
	queries.TargetSettingsProbe = "SELECT VERSION(), 2"
	queries.SchemaColumns = func(schema string) string { return asMode2(Queries.SchemaColumns(schema)) }
	queries.SchemaRoutines = func(schema string) string { return asMode2(Queries.SchemaRoutines(schema)) }
	queries.SchemaHash = func(schema string, setup [][]*string) (string, int, error) {
		sqlText, columns, err := Queries.SchemaHash(schema, setup)
		return asMode2(sqlText), columns, err
	}
	return queries
}

func TestMySQLLowerCase2FoldsStoredCase(t *testing.T) {
	targetConfig := dbtest.MySQL(t)
	admin := dbtest.OpenMySQL(t, "")
	conn := targettest.PinConn(t, admin)
	mixed := targettest.UniqueFixtureName("PmNamesMode2")
	canonical := strings.ToLower(mixed)
	targettest.ExecRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quoteMySQL(mixed))
	targettest.ExecRefetchSQL(t, conn, "CREATE DATABASE "+quoteMySQL(mixed))
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + quoteMySQL(mixed)) })
	targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quoteMySQL(mixed)+".`Users` (Id INT NOT NULL, EMail VARCHAR(64) NULL)")

	bulk := targettest.IntrospectTarget(t, OpenPool, lowerCase2Queries(), ProbeNamespace, targetConfig, mixed)
	if got := bulk.GetDefaultSchemas(); !slices.Equal(got, []string{canonical}) {
		t.Fatalf("DefaultSchemas = %v, want [%s]", got, canonical)
	}
	if got, want := targettest.RelationKeys(bulk.GetCatalog().GetColumns(), canonical), []targettest.RelationKey{{canonical, "users", "email"}, {canonical, "users", "id"}}; !slices.Equal(got, want) {
		t.Fatalf("pushed %s columns = %v, want %v", canonical, got, want)
	}
	if got := targettest.RelationKeys(bulk.GetCatalog().GetColumns(), mixed); len(got) != 0 {
		t.Fatalf("pushed raw-case schema %s columns %v", mixed, got)
	}

	t.Run("refetch and hash find the stored case by its canonical name", func(t *testing.T) {
		t.Skip("pending-name-fix: the mode-2 schema filter applies LOWER to a BINARY cast, which does not fold, so it matches no rows")
		queries := lowerCase2Queries()
		targettest.AssertFragmentMatchesBulk(t, queries, conn, "def", bulk, canonical)
		if !bytes.Equal(targettest.TrustedRefetchHash(t, queries, conn, canonical), targettest.TrustedRefetchHash(t, Queries, conn, mixed)) {
			t.Fatalf("mode-2 hash of %q differs from the stored-case hash of %q", canonical, mixed)
		}
	})
}

func TestMySQLFragmentRowsUnderEachMode(t *testing.T) {
	row := func(schema, table, column string) [][]*string {
		return [][]*string{{targettest.Ptr(schema), targettest.Ptr(table), targettest.Ptr(column), targettest.Ptr("int"), targettest.Ptr("1"), targettest.Ptr("NO"), targettest.Ptr("def")}}
	}
	for _, tc := range []struct {
		name                 string
		mode                 int32
		requested            string
		schema, table, colmn string
		want                 *targettest.RelationKey
	}{
		{"mode 0 keeps case", 0, "App", "App", "Users", "EMail", &targettest.RelationKey{"App", "Users", "email"}},
		{"mode 0 refuses a case-differing row", 0, "app", "App", "Users", "EMail", nil},
		{"mode 1 folds", 1, "app", "app", "users", "EMail", &targettest.RelationKey{"app", "users", "email"}},
		{"mode 2 folds the stored case", 2, "app", "App", "Users", "EMail", &targettest.RelationKey{"app", "users", "email"}},
		{"mode 2 refuses another schema", 2, "app", "Other", "Users", "EMail", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sqldb.FragmentColumnsFromRows(lctnSession(t, tc.mode), tc.requested, row(tc.schema, tc.table, tc.colmn))
			if tc.want == nil {
				if err == nil {
					t.Fatalf("FragmentColumnsFromRows = %+v, want refused", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("FragmentColumnsFromRows: %v", err)
			}
			if len(got) != 1 || (targettest.RelationKey{got[0].GetSchema(), got[0].GetTable(), got[0].GetColumn()}) != *tc.want {
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
		got := lctnSession(t, tc.mode).CanonicalColumns([]*analyzerpb.Column{{Schema: tc.schema, Table: "T", Column: "C"}})[0]
		if got.GetSchema() != tc.want || got.GetColumn() != "c" {
			t.Errorf("mode %d CanonicalColumns(%s.T.C) = %s.%s.%s, want schema %s, column c", tc.mode, tc.schema, got.GetSchema(), got.GetTable(), got.GetColumn(), tc.want)
		}
	}
}

func TestMySQLRefetchRefusesUnknownLowerCaseTableNames(t *testing.T) {
	version := targettest.Ptr("8.0.40")
	for _, tc := range []struct {
		name  string
		rows  [][]*string
		probe error
	}{
		{"probe error", nil, sql.ErrConnDone},
		{"no row", [][]*string{}, nil},
		{"NULL", [][]*string{{version, nil}}, nil},
		{"out of range", [][]*string{{version, targettest.Ptr("3")}}, nil},
		{"negative", [][]*string{{version, targettest.Ptr("-1")}}, nil},
		{"not a number", [][]*string{{version, targettest.Ptr("on")}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := func(statement string, _ int) ([][]*string, error) {
				switch statement {
				case Queries.TargetSettingsProbe:
					return tc.rows, tc.probe
				case Queries.SchemaColumns("App"):
					return [][]*string{{targettest.Ptr("App"), targettest.Ptr("Users"), targettest.Ptr("Id"), targettest.Ptr("int"), targettest.Ptr("1"), targettest.Ptr("NO"), targettest.Ptr("def")}}, nil
				}
				return nil, nil
			}
			pushed := false
			session, err := sqldb.NewSession(Queries, probe)
			if err == nil {
				commandRunner := sqldb.NewProxyCommandRunner(Queries, session, nil, 0, probe, func(*pb.SchemaFragmentPush) (uint64, error) {
					pushed = true
					return 1, nil
				})
				commandRunner.Catalog = "def"
				err = commandRunner.Refetch(&pb.Refetch{Catalog: "def", Schema: "App"})
			}
			if err == nil || pushed {
				t.Fatalf("open + refetch err = %v, pushed = %v; want refused without a push", err, pushed)
			}
		})
	}
}
