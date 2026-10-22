package mysql

import (
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func TestMySQLNormalizationPreservesCatalog(t *testing.T) {
	column := &analyzerpb.Column{Catalog: "def", Schema: "App", Table: "Orders", Column: "ID", Ordinal: 1}
	normalized := lctnSession(t, 1).CanonicalColumns([]*analyzerpb.Column{column})
	if len(normalized) != 1 || normalized[0].GetCatalog() != "def" || normalized[0].GetSchema() != "app" {
		t.Fatalf("normalized column = %v", normalized)
	}
	normalized[0].Catalog = "changed"
	if column.GetCatalog() != "def" {
		t.Fatal("normalization aliased the input catalog")
	}
}
