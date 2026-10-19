package postgres

import (
	"fmt"
	"strings"
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/targettest"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

func TestPgNormalizeColumnsIsIdentity(t *testing.T) {
	in := []*analyzerpb.Column{{Schema: "Sales", Table: "OrderItems", Column: "CustomerID"}}
	out := (TargetSQL{}).NormalizeColumns(0, in)
	if len(out) != 1 || out[0] != in[0] {
		t.Errorf("TargetSQL.NormalizeColumns must be an identity passthrough, got %+v", out)
	}
}

func TestPgDbConstants(t *testing.T) {
	p := TargetSQL{}
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
	p := TargetSQL{}
	schema := "hostile'\\schema"
	cryptoSQL, columns, err := p.SchemaHashSQL(schema, [][]*string{{targettest.Ptr(`crypto"schema`)}})
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
		"SELECT n.nspname, '', p.proname, 'function', 0, 'NO'",
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
		{"sha256", targettest.Rows(sha, "2", "0"), true},
		{"md5 fallback", targettest.Rows(md5, "2", "0"), true},
		{"null row blob", targettest.Rows(sha, "2", "1"), false},
		{"nil", [][]*string{{targettest.Ptr(sha), nil, targettest.Ptr("0")}}, false},
		{"extra row", append(targettest.Rows(sha, "1", "0"), targettest.Rows(sha, "1", "0")[0]), false},
		{"short", targettest.Rows("abcd", "1", "0"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, trusted, err := (TargetSQL{}).SchemaHashFromRows(tc.rows)
			if err != nil {
				t.Fatalf("SchemaHashFromRows: %v", err)
			}
			if trusted != tc.trusted {
				t.Fatalf("trusted = %v, want %v", trusted, tc.trusted)
			}
		})
	}
}

var _ relay.Db = TargetSQL{}

func TestFragmentColumnsFromRowsRefusesACaseDifferingSchema(t *testing.T) {
	row := targettest.Rows("sales", "t", "c", "int", "1", "NO", "def")
	if _, err := sqldb.FragmentColumnsFromRows(TargetSQL{}, 0, "Sales", row); err == nil {
		t.Fatal("FragmentColumnsFromRows succeeded, want a strict mismatch on Postgres")
	}
}

func TestFoldFunctionNameMatchesTheResolverFold(t *testing.T) {
	// PostgreSQL folds ASCII only, so a non-ASCII upper-case letter keeps its spelling.
	if got := (TargetSQL{}).FoldFunctionName("PG_Read_File"); got != "pg_read_file" {
		t.Fatalf("postgres fold = %q, want pg_read_file", got)
	}
	if got := (TargetSQL{}).FoldFunctionName("ÄBC"); got != "Äbc" {
		t.Fatalf("postgres must not fold non-ASCII: got %q, want Äbc", got)
	}
}

func TestRoutinesSQLReadsPgProc(t *testing.T) {
	if !strings.Contains(TargetSQL{}.RoutinesSQL(), "pg_catalog.pg_proc") {
		t.Fatalf("RoutinesSQL = %q, want pg_proc", TargetSQL{}.RoutinesSQL())
	}
}
