package engine

import "testing"

func TestDefinitions(t *testing.T) {
	mysql, _ := ByWireName("MySQL")
	pg, _ := ByWireName("postgres")
	athena, _ := ByWireName("athena")
	if _, ok := ByWireName("postgresql"); ok {
		t.Fatal("postgresql is not a wire name")
	}
	for _, c := range []struct {
		d      *Definition
		schema string
		want   bool
	}{
		{mysql, "INFORMATION_SCHEMA", true}, {mysql, "sys", true}, {mysql, "app", false},
		{pg, "pg_catalog", true}, {pg, "PG_CATALOG", false}, {pg, "pg_temp_3", true}, {pg, "pg_toast_temp_1", true}, {pg, "public", false},
		{pg, "pg_toast", true}, {pg, "pg_temp", false},
		{athena, "Information_Schema", true}, {athena, "sales", false},
	} {
		if got := c.d.IsSystemSchema(c.schema); got != c.want {
			t.Errorf("%s %s: %v", c.d.WireName, c.schema, got)
		}
	}
	if mysql.CatalogName("app") != "def" || pg.CatalogName("App") != "App" || athena.CatalogName("AwsDataCatalog") != "awsdatacatalog" {
		t.Fatal("catalog names")
	}
	if !mysql.DefaultSchemaSettable || !pg.DefaultSchemaSettable || athena.DefaultSchemaSettable {
		t.Fatal("default schema settable")
	}
}
