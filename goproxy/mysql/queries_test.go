package mysql

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/targettest"
)

func TestMySqlSchemaHashSQL(t *testing.T) {
	queries := Queries
	schema := "hostile'\\name"
	sql, columns, err := queries.SchemaHash(schema, nil)
	if err != nil {
		t.Fatalf("SchemaHashSQL: %v", err)
	}
	if columns != 3 {
		t.Fatalf("columns = %d, want 3", columns)
	}
	for _, fragment := range []string{
		"SET_VAR(group_concat_max_len=33554432)",
		"LENGTH(CAST(sn AS BINARY)), ':'",
		"LENGTH(CAST(tn AS BINARY)), ':'",
		"LENGTH(CAST(cn AS BINARY)), ':'",
		"LENGTH(CAST(dt AS BINARY)), ':'",
		"LENGTH(CAST(op AS CHAR CHARACTER SET ascii)), ':'",
		"LENGTH(CAST(nl AS BINARY)), ':'",
		"ORDER BY CAST(tn AS BINARY), op, CAST(cn AS BINARY)",
		"SELECT ROUTINE_SCHEMA, '', ROUTINE_NAME, 'function', 0, 'NO'",
		"X'" + fmt.Sprintf("%x", []byte(schema)) + "'",
		// The WHERE filter must be mode-aware (CASE WHEN @@lower_case_table_names = 2 THEN LOWER(...)):
		// a canonical (possibly-folded) schema parameter must still match a live mode-2 server whose
		// information_schema preserves the original stored case.
		"CASE WHEN @@lower_case_table_names = 2 THEN LOWER(CAST(TABLE_SCHEMA AS BINARY)) ELSE CAST(TABLE_SCHEMA AS BINARY) END",
	} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("SchemaHashSQL missing %q:\n%s", fragment, sql)
		}
	}
	if strings.Contains(strings.ToUpper(sql), "SET SESSION") {
		t.Fatalf("SchemaHashSQL mutates session state:\n%s", sql)
	}
	if strings.Contains(sql, "CONCAT(HEX(") {
		t.Fatalf("SchemaHashSQL uses forbidden bare HEX concatenation:\n%s", sql)
	}
	// The hashed/selected TABLE_SCHEMA value itself (aliased sn) must stay the RAW live content — only
	// the WHERE-filter comparison folds for mode 2. Folding what's hashed would make the hash no longer
	// fingerprint the database's actual bytes.
	if !strings.Contains(sql, "SELECT TABLE_SCHEMA AS sn") {
		t.Errorf("SchemaHashSQL must select the raw TABLE_SCHEMA value (not folded) for hashing:\n%s", sql)
	}
	columnsSQL := queries.SchemaColumns(schema)
	for _, fragment := range []string{
		"CAST(TABLE_SCHEMA AS BINARY)",
		"ORDER BY CAST(TABLE_NAME AS BINARY), ORDINAL_POSITION, CAST(COLUMN_NAME AS BINARY)",
		"X'" + fmt.Sprintf("%x", []byte(schema)) + "'",
		"CASE WHEN @@lower_case_table_names = 2 THEN LOWER(CAST(TABLE_SCHEMA AS BINARY)) ELSE CAST(TABLE_SCHEMA AS BINARY) END",
	} {
		if !strings.Contains(columnsSQL, fragment) {
			t.Errorf("SchemaColumnsSQL missing %q: %s", fragment, columnsSQL)
		}
	}
	// SELECT TABLE_SCHEMA (unqualified, the first result column) must stay unfolded too, matching
	// FragmentColumnsFromRows' expectation of the live stored value.
	if !strings.HasPrefix(columnsSQL, "SELECT TABLE_SCHEMA,") {
		t.Errorf("SchemaColumnsSQL must SELECT the raw TABLE_SCHEMA value (not folded): %s", columnsSQL)
	}
	if strings.Contains(strings.ToUpper(columnsSQL), "NOT IN") {
		t.Fatalf("SchemaColumnsSQL excludes system schemas: %s", columnsSQL)
	}
}

func TestMySqlNormalizeColumns(t *testing.T) {
	in := []*analyzerpb.Column{
		{Schema: "AppDB", Table: "UserRows", Column: "CustomerID", DataType: "int", Ordinal: 1, Nullable: true},
	}
	// mode 1 (case-insensitive): schema/table fold too, alongside the always-unconditional column fold.
	out := Queries.NormalizeColumns(1, in)
	if len(out) != 1 {
		t.Fatalf("NormalizeColumns returned %d columns, want 1", len(out))
	}
	got := out[0]
	if got.GetSchema() != "appdb" || got.GetTable() != "userrows" || got.GetColumn() != "customerid" {
		t.Errorf("mode 1: got %s.%s.%s, want appdb.userrows.customerid", got.GetSchema(), got.GetTable(), got.GetColumn())
	}
	if got.GetDataType() != "int" || got.GetOrdinal() != 1 || !got.GetNullable() {
		t.Errorf("NormalizeColumns must preserve non-identity fields, got %+v", got)
	}
	// Input must not be mutated (NormalizeColumns builds new analyzerpb.Column values).
	if in[0].GetSchema() != "AppDB" {
		t.Errorf("NormalizeColumns mutated its input: %+v", in[0])
	}

	// mode 0 (case-sensitive): schema/table stay verbatim; the column still folds unconditionally.
	out0 := Queries.NormalizeColumns(0, in)
	if out0[0].GetSchema() != "AppDB" || out0[0].GetTable() != "UserRows" || out0[0].GetColumn() != "customerid" {
		t.Errorf("mode 0: got %s.%s.%s, want AppDB.UserRows.customerid", out0[0].GetSchema(), out0[0].GetTable(), out0[0].GetColumn())
	}

	// A multi-row fragment with a repeated (schema, table) exercises the batched path (one sqlglot
	// parse per distinct table, memoized; column folded per row). Row order and each row's non-identity
	// fields must be preserved.
	multi := []*analyzerpb.Column{
		{Schema: "AppDB", Table: "UserRows", Column: "CustomerID", DataType: "int", Ordinal: 1, Nullable: false},
		{Schema: "AppDB", Table: "UserRows", Column: "EmailAddr", DataType: "varchar", Ordinal: 2, Nullable: true},
		{Schema: "AppDB", Table: "OrderRows", Column: "OrderID", DataType: "bigint", Ordinal: 1, Nullable: false},
	}
	outMulti := Queries.NormalizeColumns(1, multi)
	if len(outMulti) != 3 {
		t.Fatalf("NormalizeColumns returned %d columns, want 3", len(outMulti))
	}
	wantSchema := []string{"appdb", "appdb", "appdb"}
	wantTable := []string{"userrows", "userrows", "orderrows"}
	wantColumn := []string{"customerid", "emailaddr", "orderid"}
	for i, c := range outMulti {
		if c.GetSchema() != wantSchema[i] || c.GetTable() != wantTable[i] || c.GetColumn() != wantColumn[i] {
			t.Errorf("mode 1 row %d: got %s.%s.%s, want %s.%s.%s",
				i, c.GetSchema(), c.GetTable(), c.GetColumn(), wantSchema[i], wantTable[i], wantColumn[i])
		}
		if c.GetDataType() != multi[i].GetDataType() || c.GetOrdinal() != multi[i].GetOrdinal() || c.GetNullable() != multi[i].GetNullable() {
			t.Errorf("mode 1 row %d: non-identity fields not preserved: got %+v, want fields from %+v", i, c, multi[i])
		}
	}
}

// TestFragmentColumnsFromRowsModeAwareSchemaCheck proves sqldb.FragmentColumnsFromRows' schema
// consistency check follows each dialect/mode's own fold rule instead of a blanket case-insensitive
// comparison: mode 2 is the only configuration where a live row's case may legitimately diverge from
// the requested (canonical) schema, so it's the only one where that divergence is accepted.
func TestFragmentColumnsFromRowsModeAwareSchemaCheck(t *testing.T) {
	str := func(s string) *string { return &s }
	row := func(schema string) [][]*string {
		return [][]*string{{str(schema), str("t"), str("c"), str("int"), str("1"), str("NO"), str("def")}}
	}

	t.Run("MySQL mode 0 rejects a case-differing schema (no legitimate divergence)", func(t *testing.T) {
		if _, err := sqldb.FragmentColumnsFromRows(Queries, 0, "App", row("app")); err == nil {
			t.Fatal("FragmentColumnsFromRows succeeded, want a strict mismatch under mode 0")
		}
	})

	t.Run("MySQL mode 2 accepts the live stored spelling diverging in case from the canonical request", func(t *testing.T) {
		got, err := sqldb.FragmentColumnsFromRows(Queries, 2, "app", row("App"))
		if err != nil {
			t.Fatalf("FragmentColumnsFromRows: %v", err)
		}
		if len(got) != 1 || got[0].GetSchema() != "app" {
			t.Fatalf("columns = %+v, want a single row folded to canonical schema %q", got, "app")
		}
	})
}

func TestMySqlSchemaHashFromRows(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	cases := []struct {
		name    string
		rows    [][]*string
		trusted bool
	}{
		{"valid", targettest.Rows(hash, "128", "2"), true},
		{"truncated", targettest.Rows(hash, "64", "2"), false},
		{"nil", [][]*string{{nil, targettest.Ptr("0"), targettest.Ptr("0")}}, false},
		{"extra row", append(targettest.Rows(hash, "64", "1"), targettest.Rows(hash, "64", "1")[0]), false},
		{"short hash", targettest.Rows("abcd", "64", "1"), false},
		{"non-hex hash", targettest.Rows(strings.Repeat("z", 64), "64", "1"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, trusted, err := Queries.SchemaHashFromRows(tc.rows)
			if err != nil {
				t.Fatalf("SchemaHashFromRows: %v", err)
			}
			if trusted != tc.trusted {
				t.Fatalf("trusted = %v, want %v", trusted, tc.trusted)
			}
		})
	}
}

var _ sqldb.Queries = Queries

func TestFoldFunctionNameMatchesTheResolverFold(t *testing.T) {
	if got := Queries.FoldFunctionName("AddTax"); got != "addtax" {
		t.Fatalf("mysql fold = %q, want addtax", got)
	}
}

func TestRoutinesSQLHoldsLoadablesUnderMysqlSchemaOnly(t *testing.T) {
	queries := Queries
	if !strings.Contains(queries.Routines, "SELECT 'mysql', name FROM mysql.func") {
		t.Fatalf("RoutinesSQL = %q, want mysql.func reported under the mysql schema", queries.Routines)
	}
	if !strings.Contains(queries.SchemaRoutines("mysql"), "FROM mysql.func") {
		t.Fatalf("SchemaRoutinesSQL(mysql) = %q, want mysql.func", queries.SchemaRoutines("mysql"))
	}
	if strings.Contains(queries.SchemaRoutines("app"), "mysql.func") {
		t.Fatalf("SchemaRoutinesSQL(app) = %q, want no mysql.func", queries.SchemaRoutines("app"))
	}
	appHash, _, _ := queries.SchemaHash("app", nil)
	mysqlHash, _, _ := queries.SchemaHash("mysql", nil)
	if strings.Contains(appHash, "mysql.func") || !strings.Contains(mysqlHash, "mysql.func") {
		t.Fatal("only the mysql schema's hash covers mysql.func")
	}
}
