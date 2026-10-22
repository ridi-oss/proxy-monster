package engines

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
)

func TestParse(t *testing.T) {
	for _, e := range All {
		if got, err := Parse(e.WireName); err != nil || got != e {
			t.Errorf("Parse(%q) = %v, %v", e.WireName, got, err)
		}
		if got, ok := ByProto(e.Proto); !ok || got != e {
			t.Errorf("ByProto(%s) = %v, %v", e.Proto, got, ok)
		}
	}
	for _, bad := range []string{"MySQL", "Postgres", "Athena", "postgresql", "oracle", ""} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) = nil error", bad)
		}
	}
	if _, ok := ByProto(pb.Engine_ENGINE_UNSPECIFIED); ok {
		t.Error("ENGINE_UNSPECIFIED is not an engine")
	}
}

func TestFacts(t *testing.T) {
	for _, c := range []struct {
		e      *Engine
		lctn   int32
		schema string
		want   bool
	}{
		{MySQL, 0, "information_schema", true}, {MySQL, 0, "INFORMATION_SCHEMA", true}, {MySQL, 0, "sys", true},
		{MySQL, 0, "mysql", true}, {MySQL, 0, "performance_schema", true}, {MySQL, 0, "app", false},
		{MySQL, 0, "SYS", false}, {MySQL, 0, "Mysql", false}, {MySQL, 0, "PERFORMANCE_SCHEMA", false},
		{MySQL, 1, "SYS", true}, {MySQL, 2, "Mysql", true},
		{Postgres, 0, "pg_catalog", true}, {Postgres, 0, "PG_CATALOG", false}, {Postgres, 0, "pg_temp_3", true},
		{Postgres, 0, "pg_toast_temp_1", true}, {Postgres, 0, "public", false}, {Postgres, 0, "pg_toast", true},
		{Postgres, 0, "pg_temp", false},
		{Athena, 0, "information_schema", true}, {Athena, 0, "Information_Schema", true}, {Athena, 0, "sales", false},
	} {
		if got := c.e.IsSystemSchema(sessionFor(t, c.e, c.lctn).CatalogSchemaName(&pb.Column{Schema: c.schema})); got != c.want {
			t.Errorf("%s lctn=%d IsSystemSchema(%s): %v", c.e.WireName, c.lctn, c.schema, got)
		}
	}
	if athenaName("\u0130X") != "ix" || athenaName("ΣΑΣ") != "σασ" {
		t.Error("Athena folds per code point")
	}
	if (SchemaName{}).String() != "" || MySQL.IsSystemSchema(SchemaName{}) {
		t.Error("the zero SchemaName is no system schema")
	}
	for _, c := range []struct {
		e      *Engine
		schema string
		want   bool
	}{
		{Postgres, "pg_temp", true}, {Postgres, "pg_temp_3", true}, {Postgres, "PG_TEMP", false}, {Postgres, "pg_tempx", false},
		{MySQL, "pg_temp", false}, {Athena, "pg_temp", false},
	} {
		if got := c.e.IsTempSchema(SchemaName{c.schema}); got != c.want {
			t.Errorf("%s IsTempSchema(%s): %v", c.e.WireName, c.schema, got)
		}
	}
	if MySQL.CatalogName("app").String() != "def" || Postgres.CatalogName("App").String() != "App" || Athena.CatalogName("AwsDataCatalog").String() != "awsdatacatalog" {
		t.Fatal("catalog names")
	}
	if !MySQL.Traits.DefaultSchemaSettable || !Postgres.Traits.DefaultSchemaSettable || Athena.Traits.DefaultSchemaSettable {
		t.Fatal("default schema settable")
	}
	if MySQL.Traits.IdentifierQuote != "`" || Postgres.Traits.IdentifierQuote != `"` || Athena.Traits.IdentifierQuote != `"` {
		t.Fatal("identifier quotes")
	}
	if MySQL.Placeholder(2) != "?" || Postgres.Placeholder(2) != "$2" || Athena.Placeholder(2) != "?" {
		t.Fatal("placeholders")
	}
}

func TestIntrospectedColumns(t *testing.T) {
	for _, c := range []struct {
		e    *Engine
		lctn int32
		in   [4]string
		want [4]string
	}{
		{MySQL, 0, [4]string{"def", "App", "Users", "ID"}, [4]string{"def", "App", "Users", "id"}},
		{MySQL, 0, [4]string{"def", "SYS", "t", "c"}, [4]string{"def", "SYS", "t", "c"}},
		{MySQL, 1, [4]string{"def", "App", "Users", "ID"}, [4]string{"def", "app", "users", "id"}},
		{MySQL, 2, [4]string{"def", "App", "Users", "ID"}, [4]string{"def", "app", "users", "id"}},
		{MySQL, 0, [4]string{"def", "information_schema", "schemata", "schema_name"}, [4]string{"def", "information_schema", "schemata", "schema_name"}},
		{MySQL, 0, [4]string{"def", "INFORMATION_SCHEMA", "SCHEMATA", "SCHEMA_NAME"}, [4]string{"def", "information_schema", "schemata", "schema_name"}},
		{MySQL, 0, [4]string{"def", "Information_Schema", "Schemata", "x"}, [4]string{"def", "information_schema", "schemata", "x"}},
		{MySQL, 1, [4]string{"def", "app", "t", "\u212A"}, [4]string{"def", "app", "t", "k"}},
		{MySQL, 1, [4]string{"def", "app", "t", "CAFÉ"}, [4]string{"def", "app", "t", "café"}},
		{MySQL, 1, [4]string{"def", "`x`", "a.b", "c"}, [4]string{"def", "`x`", "a.b", "c"}},
		{Postgres, 0, [4]string{"App", "Public", "Users", "SSN"}, [4]string{"App", "Public", "Users", "SSN"}},
		{Athena, 0, [4]string{"AwsDataCatalog", "HR", "Salaries", "SSN"}, [4]string{"awsdatacatalog", "hr", "salaries", "ssn"}},
	} {
		got := sessionFor(t, c.e, c.lctn).CatalogColumnNames([]*pb.Column{{Catalog: c.in[0], Schema: c.in[1], Table: c.in[2], Column: c.in[3]}})[0]
		if [4]string{got.Catalog().String(), got.Schema().String(), got.Table(), got.Column()} != c.want {
			t.Errorf("%s lctn=%d %v: %+v", c.e.WireName, c.lctn, c.in, got)
		}
	}
}

// mysqlCatalogColumnNames parses each distinct (schema, table) once; the batch must equal a row-by-row call.
func TestIntrospectedColumnsBatchEqualsPerRow(t *testing.T) {
	rows := []*pb.Column{
		{Catalog: "def", Schema: "App", Table: "Users", Column: "ID"},
		{Catalog: "def", Schema: "App", Table: "Users", Column: "Name"},
		{Catalog: "def", Schema: "App", Table: "Orders", Column: "Total"},
		{Catalog: "def", Schema: "INFORMATION_SCHEMA", Table: "SCHEMATA", Column: "SCHEMA_NAME"},
		{Catalog: "def", Schema: "Other", Table: "T", Column: "\u212A"},
		{Catalog: "def", Schema: "Other", Table: "T", Column: "CAFÉ"},
	}
	for _, e := range All {
		for _, lctn := range []int32{0, 1, 2} {
			batch := sessionFor(t, e, lctn).CatalogColumnNames(rows)
			if len(batch) != len(rows) {
				t.Fatalf("%s lctn=%d: %d rows for %d", e.WireName, lctn, len(batch), len(rows))
			}
			for i, row := range rows {
				if one := sessionFor(t, e, lctn).CatalogColumnNames([]*pb.Column{row})[0]; batch[i] != one {
					t.Errorf("%s lctn=%d row %d: batch %+v, alone %+v", e.WireName, lctn, i, batch[i], one)
				}
			}
		}
		if got := sessionFor(t, e, 0).CatalogColumnNames(nil); len(got) != 0 {
			t.Errorf("%s: empty input gave %v", e.WireName, got)
		}
	}
}

func TestParseColumn(t *testing.T) {
	for _, c := range []struct {
		e    *Engine
		lctn int32
		in   [4]string
		want [4]string
	}{
		{Postgres, 0, [4]string{"shop", "Public", "Users", "SSN"}, [4]string{"shop", "public", "users", "ssn"}},
		{Postgres, 0, [4]string{"shop", `"App"`, `"T"`, `"SSN"`}, [4]string{"shop", "App", "T", "SSN"}},
		{Postgres, 0, [4]string{"shop", `"a""b"`, "t", "c"}, [4]string{"shop", `a"b`, "t", "c"}},
		{MySQL, 0, [4]string{"def", "App", "Users", "SSN"}, [4]string{"def", "App", "Users", "ssn"}},
		{MySQL, 0, [4]string{"def", "INFORMATION_SCHEMA", "TABLES", "TABLE_NAME"}, [4]string{"def", "information_schema", "tables", "table_name"}},
		{MySQL, 1, [4]string{"def", "App", "`Users`", "`SSN`"}, [4]string{"def", "app", "users", "ssn"}},
		{MySQL, 2, [4]string{"def", "App", "Users", "SSN"}, [4]string{"def", "app", "users", "ssn"}},
		{Athena, 0, [4]string{"AwsDataCatalog", "HR", `"Salaries"`, "SSN"}, [4]string{"awsdatacatalog", "hr", "salaries", "ssn"}},
		{Postgres, 0, [4]string{"shop", "public", "t", ""}, [4]string{"shop", "public", "t", ""}},
	} {
		got, err := sessionFor(t, c.e, c.lctn).ParseColumn(c.in[0], c.in[1], c.in[2], c.in[3])
		if err != nil || [4]string{got.Catalog().String(), got.Schema().String(), got.Table(), got.Column()} != c.want {
			t.Errorf("%s lctn=%d %v: %+v %v", c.e.WireName, c.lctn, c.in, got, err)
		}
	}
	for _, bad := range []string{"a b", "a.b", "1x", `"unclosed`, "'SSN'"} {
		if got, err := sessionFor(t, Postgres, 0).ParseColumn("shop", "public", bad, "c"); err == nil {
			t.Errorf("%q parsed as %+v", bad, got)
		}
	}
}

func TestParsedSchema(t *testing.T) {
	for _, c := range []struct {
		e      *Engine
		lctn   int32
		quoted bool
		in     string
		want   string
	}{
		{Postgres, 0, false, "PG_TEMP", "pg_temp"},
		{Postgres, 0, true, "PG_TEMP", "PG_TEMP"},
		{MySQL, 0, false, "App", "App"},
		{MySQL, 1, true, "App", "app"},
		{Athena, 0, true, "HR", "hr"},
	} {
		id := exp.Identifier(exp.Args{"this": c.in, "quoted": c.quoted})
		if got := sessionFor(t, c.e, c.lctn).ParsedSchema(id); got.String() != c.want || id.Name() != c.in {
			t.Errorf("%s lctn=%d %q quoted=%v: %q, input now %q", c.e.WireName, c.lctn, c.in, c.quoted, got, id.Name())
		}
	}
	if !Postgres.IsTempSchema(sessionFor(t, Postgres, 0).ParsedSchema(exp.Identifier(exp.Args{"this": "pg_temp_3"}))) || Postgres.IsTempSchema(sessionFor(t, Postgres, 0).ParsedSchema(exp.Identifier(exp.Args{"this": "PG_TEMP", "quoted": true}))) {
		t.Error("temp schema")
	}
}

// sessionFor is the engine on a target reporting lctn; only MySQL reads it.
func sessionFor(t *testing.T, e *Engine, lctn int32) *Session {
	t.Helper()
	session, err := e.NewSession(&pb.TargetSettings{EngineVersion: "8.0.44", MysqlLowerCaseTableNames: &lctn})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestSession(t *testing.T) {
	for _, bad := range []int32{-1, 3} {
		if _, err := MySQL.NewSession(&pb.TargetSettings{MysqlLowerCaseTableNames: &bad}); err == nil {
			t.Errorf("lower_case_table_names %d accepted", bad)
		}
	}
	one := int32(1)
	for _, missing := range []*pb.TargetSettings{nil, {EngineVersion: "8.0.44"}, {MysqlLowerCaseTableNames: &one}} {
		if _, err := MySQL.NewSession(missing); err == nil {
			t.Errorf("MySQL bound %v without its version or lower_case_table_names", missing)
		}
	}
	if _, err := Postgres.NewSession(nil); err != nil {
		t.Error(err)
	}
}
