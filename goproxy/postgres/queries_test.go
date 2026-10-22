package postgres

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/targettest"
)

func TestPgCanonicalColumnsIsIdentity(t *testing.T) {
	in := []*analyzerpb.Column{{Schema: "Sales", Table: "OrderItems", Column: "CustomerID"}}
	out := pgFolder(t).CanonicalColumns(in)
	if len(out) != 1 || !proto.Equal(out[0], in[0]) {
		t.Errorf("Postgres CanonicalColumns must keep every name, got %+v", out)
	}
}

func TestPgProbeSQL(t *testing.T) {
	namespaceSQL := namespaceProbeSQL
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
	sql := tempColumnsProbeSQL
	if !strings.Contains(sql, "pg_temp%") {
		t.Errorf("TempColumnsProbeSQL() = %q, want it to contain the pg_temp%% predicate", sql)
	}
	if !strings.Contains(sql, "pg_catalog.pg_attribute") {
		t.Errorf("TempColumnsProbeSQL() = %q, want it to reference pg_catalog.pg_attribute", sql)
	}
}

func TestPgSchemaHashSQL(t *testing.T) {
	queries := Queries
	schema := "hostile'\\schema"
	cryptoSQL, columns, err := queries.SchemaHash(schema, [][]*string{{targettest.Ptr(`crypto"schema`)}})
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
	fallbackSQL, _, err := queries.SchemaHash(schema, nil)
	if err != nil {
		t.Fatalf("SchemaHashSQL fallback: %v", err)
	}
	if !strings.Contains(fallbackSQL, "pg_catalog.md5(") || strings.Contains(fallbackSQL, ".digest(") {
		t.Fatalf("fallback is not fully qualified pg_catalog.md5:\n%s", fallbackSQL)
	}
	columnsSQL := queries.SchemaColumns(schema)
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

func TestFragmentColumnsFromRowsRefusesACaseDifferingSchema(t *testing.T) {
	row := targettest.Rows("sales", "t", "c", "int", "1", "NO", "def")
	if _, err := sqldb.FragmentColumnsFromRows(pgFolder(t), "Sales", row); err == nil {
		t.Fatal("FragmentColumnsFromRows succeeded, want a strict mismatch on Postgres")
	}
}

func TestFoldFunctionNameMatchesTheResolverFold(t *testing.T) {
	// A Postgres proname is already exact.
	for _, name := range []string{"pg_read_file", "GetSSN", "UPPER", "ÄBC"} {
		if got := pgFolder(t).FunctionName(name).String(); got != name {
			t.Fatalf("postgres fold = %q, want %q", got, name)
		}
	}
}

func TestRoutinesSQLReadsPgProc(t *testing.T) {
	if !strings.Contains(Queries.Routines, "pg_catalog.pg_proc") {
		t.Fatalf("RoutinesSQL = %q, want pg_proc", Queries.Routines)
	}
}

func pgFolder(t *testing.T) *engines.Session {
	t.Helper()
	session, err := engines.Postgres.NewSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	return session
}
