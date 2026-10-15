package engines

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
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
		schema string
		want   bool
	}{
		{MySQL, "INFORMATION_SCHEMA", true}, {MySQL, "sys", true}, {MySQL, "app", false},
		{Postgres, "pg_catalog", true}, {Postgres, "PG_CATALOG", false}, {Postgres, "pg_temp_3", true}, {Postgres, "pg_toast_temp_1", true}, {Postgres, "public", false},
		{Postgres, "pg_toast", true}, {Postgres, "pg_temp", false},
		{Athena, "Information_Schema", true}, {Athena, "sales", false},
	} {
		if got := c.e.IsSystemSchema(c.schema); got != c.want {
			t.Errorf("%s IsSystemSchema(%s): %v", c.e.WireName, c.schema, got)
		}
	}
	for _, c := range []struct {
		e      *Engine
		schema string
		want   bool
	}{
		{Postgres, "pg_temp", true}, {Postgres, "pg_temp_3", true}, {Postgres, "PG_TEMP", false}, {Postgres, "pg_tempx", false},
		{MySQL, "pg_temp", false}, {Athena, "pg_temp", false},
	} {
		if got := c.e.IsTempSchema(c.schema); got != c.want {
			t.Errorf("%s IsTempSchema(%s): %v", c.e.WireName, c.schema, got)
		}
	}
	if MySQL.CatalogName("app") != "def" || Postgres.CatalogName("App") != "App" || Athena.CatalogName("AwsDataCatalog") != "awsdatacatalog" {
		t.Fatal("catalog names")
	}
	if !MySQL.DefaultSchemaSettable || !Postgres.DefaultSchemaSettable || Athena.DefaultSchemaSettable {
		t.Fatal("default schema settable")
	}
	if MySQL.Placeholder(2) != "?" || Postgres.Placeholder(2) != "$2" || Athena.Placeholder(2) != "?" {
		t.Fatal("placeholders")
	}
}
