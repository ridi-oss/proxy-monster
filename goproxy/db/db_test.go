package db

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func TestMySqlDbConstants(t *testing.T) {
	m := MySqlDb{}
	if m.NamespaceProbeSQL() != "SELECT DATABASE()" {
		t.Errorf("NamespaceProbeSQL() = %q, want %q", m.NamespaceProbeSQL(), "SELECT DATABASE()")
	}
	if m.SupportsTempOverlay() {
		t.Error("SupportsTempOverlay() = true, want false for MySQL")
	}
	if m.TempColumnsProbeSQL() != "" {
		t.Errorf("TempColumnsProbeSQL() = %q, want empty", m.TempColumnsProbeSQL())
	}
}

func TestMySqlSchemaHashSQL(t *testing.T) {
	m := MySqlDb{}
	schema := "hostile'\\name"
	sql, columns, err := m.SchemaHashSQL(schema, nil)
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
	columnsSQL := m.SchemaColumnsSQL(schema)
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
	in := []*pb.Column{
		{Schema: "AppDB", Table: "UserRows", Column: "CustomerID", DataType: "int", Ordinal: 1, Nullable: true},
	}
	// mode 1 (case-insensitive): schema/table fold too, alongside the always-unconditional column fold.
	out := (MySqlDb{}).NormalizeColumns(1, in)
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
	// Input must not be mutated (NormalizeColumns builds new pb.Column values).
	if in[0].GetSchema() != "AppDB" {
		t.Errorf("NormalizeColumns mutated its input: %+v", in[0])
	}

	// mode 0 (case-sensitive): schema/table stay verbatim; the column still folds unconditionally.
	out0 := (MySqlDb{}).NormalizeColumns(0, in)
	if out0[0].GetSchema() != "AppDB" || out0[0].GetTable() != "UserRows" || out0[0].GetColumn() != "customerid" {
		t.Errorf("mode 0: got %s.%s.%s, want AppDB.UserRows.customerid", out0[0].GetSchema(), out0[0].GetTable(), out0[0].GetColumn())
	}

	// A multi-row fragment with a repeated (schema, table) exercises the batched path (one sqlglot
	// parse per distinct table, memoized; column folded per row). Row order and each row's non-identity
	// fields must be preserved.
	multi := []*pb.Column{
		{Schema: "AppDB", Table: "UserRows", Column: "CustomerID", DataType: "int", Ordinal: 1, Nullable: false},
		{Schema: "AppDB", Table: "UserRows", Column: "EmailAddr", DataType: "varchar", Ordinal: 2, Nullable: true},
		{Schema: "AppDB", Table: "OrderRows", Column: "OrderID", DataType: "bigint", Ordinal: 1, Nullable: false},
	}
	outMulti := (MySqlDb{}).NormalizeColumns(1, multi)
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

func TestPgNormalizeColumnsIsIdentity(t *testing.T) {
	in := []*pb.Column{{Schema: "Sales", Table: "OrderItems", Column: "CustomerID"}}
	out := (PgDb{}).NormalizeColumns(0, in)
	if len(out) != 1 || out[0] != in[0] {
		t.Errorf("PgDb.NormalizeColumns must be an identity passthrough, got %+v", out)
	}
}

// TestFragmentColumnsFromRowsModeAwareSchemaCheck proves engine.FragmentColumnsFromRows' schema
// consistency check follows each dialect/mode's own fold rule instead of a blanket case-insensitive
// comparison: mode 2 is the only configuration where a live row's case may legitimately diverge from
// the requested (canonical) schema, so it's the only one where that divergence is accepted.
func TestFragmentColumnsFromRowsModeAwareSchemaCheck(t *testing.T) {
	str := func(s string) *string { return &s }
	row := func(schema string) [][]*string {
		return [][]*string{{str(schema), str("t"), str("c"), str("int"), str("1"), str("NO")}}
	}

	t.Run("MySQL mode 0 rejects a case-differing schema (no legitimate divergence)", func(t *testing.T) {
		if _, err := engine.FragmentColumnsFromRows(MySqlDb{}, 0, "App", row("app")); err == nil {
			t.Fatal("FragmentColumnsFromRows succeeded, want a strict mismatch under mode 0")
		}
	})

	t.Run("MySQL mode 2 accepts the live stored spelling diverging in case from the canonical request", func(t *testing.T) {
		got, err := engine.FragmentColumnsFromRows(MySqlDb{}, 2, "app", row("App"))
		if err != nil {
			t.Fatalf("FragmentColumnsFromRows: %v", err)
		}
		if len(got) != 1 || got[0].GetSchema() != "app" {
			t.Fatalf("columns = %+v, want a single row folded to canonical schema %q", got, "app")
		}
	})

	t.Run("Postgres rejects a case-differing schema (Postgres never folds)", func(t *testing.T) {
		if _, err := engine.FragmentColumnsFromRows(PgDb{}, 0, "Sales", row("sales")); err == nil {
			t.Fatal("FragmentColumnsFromRows succeeded, want a strict mismatch on Postgres")
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
		{"valid", rows(hash, "128", "2"), true},
		{"truncated", rows(hash, "64", "2"), false},
		{"nil", [][]*string{{nil, ptr("0"), ptr("0")}}, false},
		{"extra row", append(rows(hash, "64", "1"), rows(hash, "64", "1")[0]), false},
		{"short hash", rows("abcd", "64", "1"), false},
		{"non-hex hash", rows(strings.Repeat("z", 64), "64", "1"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, trusted, err := (MySqlDb{}).SchemaHashFromRows(tc.rows)
			if err != nil {
				t.Fatalf("SchemaHashFromRows: %v", err)
			}
			if trusted != tc.trusted {
				t.Fatalf("trusted = %v, want %v", trusted, tc.trusted)
			}
		})
	}
}

func TestPgDbConstants(t *testing.T) {
	p := PgDb{}
	namespaceSQL := p.NamespaceProbeSQL()
	for _, fragment := range []string{
		"pg_catalog.current_schemas(true)",
		"pg_catalog.pg_proc",
		"p.proname OPERATOR(pg_catalog.=) 'unnest'::pg_catalog.name",
		"p.pronamespace OPERATOR(pg_catalog.<>) 'pg_catalog'::pg_catalog.regnamespace",
		"pg_catalog.pg_function_is_visible(p.oid)",
		"pg_catalog.pg_type_is_visible(",
		"'pg_catalog.xid'::pg_catalog.regtype::pg_catalog.oid",
		"'[]'::pg_catalog.json",
	} {
		if !strings.Contains(namespaceSQL, fragment) {
			t.Errorf("NamespaceProbeSQL missing %q:\n%s", fragment, namespaceSQL)
		}
	}
	if !p.SupportsTempOverlay() {
		t.Error("SupportsTempOverlay() = false, want true for Postgres")
	}
	sql := p.TempColumnsProbeSQL()
	if !strings.Contains(sql, "pg_temp%") {
		t.Errorf("TempColumnsProbeSQL() = %q, want it to contain the pg_temp%% predicate", sql)
	}
	if !strings.Contains(sql, "pg_catalog.pg_attribute") {
		t.Errorf("TempColumnsProbeSQL() = %q, want it to reference pg_catalog.pg_attribute", sql)
	}
}

func TestPgSchemaHashSQL(t *testing.T) {
	p := PgDb{}
	schema := "hostile'\\schema"
	cryptoSQL, columns, err := p.SchemaHashSQL(schema, [][]*string{{ptr(`crypto"schema`)}})
	if err != nil {
		t.Fatalf("SchemaHashSQL pgcrypto: %v", err)
	}
	if columns != 3 {
		t.Fatalf("columns = %d, want 3", columns)
	}
	for _, fragment := range []string{
		`"crypto""schema".digest`,
		"pg_catalog.encode(",
		"pg_catalog.convert_to(",
		"pg_catalog.string_agg(",
		"pg_catalog.octet_length(",
		`COLLATE "C"`,
		"pg_catalog.convert_from('\\x" + fmt.Sprintf("%x", []byte(schema)) + "'::pg_catalog.bytea, 'UTF8')",
	} {
		if !strings.Contains(cryptoSQL, fragment) {
			t.Errorf("pgcrypto SchemaHashSQL missing %q:\n%s", fragment, cryptoSQL)
		}
	}
	fallbackSQL, _, err := p.SchemaHashSQL(schema, nil)
	if err != nil {
		t.Fatalf("SchemaHashSQL fallback: %v", err)
	}
	if !strings.Contains(fallbackSQL, "pg_catalog.md5(") || strings.Contains(fallbackSQL, ".digest(") {
		t.Fatalf("fallback is not fully qualified pg_catalog.md5:\n%s", fallbackSQL)
	}
	columnsSQL := p.SchemaColumnsSQL(schema)
	for _, fragment := range []string{`COLLATE "C"`, "ordinal_position", "pg_catalog.convert_from('\\x" + fmt.Sprintf("%x", []byte(schema))} {
		if !strings.Contains(columnsSQL, fragment) {
			t.Errorf("SchemaColumnsSQL missing %q: %s", fragment, columnsSQL)
		}
	}
}

func TestPgSchemaHashFromRows(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	md5 := strings.Repeat("cd", 16)
	cases := []struct {
		name    string
		rows    [][]*string
		trusted bool
	}{
		{"sha256", rows(sha, "2", "0"), true},
		{"md5 fallback", rows(md5, "2", "0"), true},
		{"null row blob", rows(sha, "2", "1"), false},
		{"nil", [][]*string{{ptr(sha), nil, ptr("0")}}, false},
		{"extra row", append(rows(sha, "1", "0"), rows(sha, "1", "0")[0]), false},
		{"short", rows("abcd", "1", "0"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, trusted, err := (PgDb{}).SchemaHashFromRows(tc.rows)
			if err != nil {
				t.Fatalf("SchemaHashFromRows: %v", err)
			}
			if trusted != tc.trusted {
				t.Fatalf("trusted = %v, want %v", trusted, tc.trusted)
			}
		})
	}
}

func ptr(value string) *string { return &value }
func rows(values ...string) [][]*string {
	row := make([]*string, len(values))
	for i := range values {
		row[i] = ptr(values[i])
	}
	return [][]*string{row}
}

var _ engine.Db = MySqlDb{}
var _ engine.Db = PgDb{}
