package db

import (
	"slices"
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

func equalColumns(left, right []*analyzerpb.Column) bool {
	return slices.EqualFunc(left, right, func(a, b *analyzerpb.Column) bool { return proto.Equal(a, b) })
}

// inCatalog returns columns stamped with the catalog the connection under test measures.
func inCatalog(catalog string, columns []*analyzerpb.Column) []*analyzerpb.Column {
	out := make([]*analyzerpb.Column, len(columns))
	for i, column := range columns {
		out[i] = proto.Clone(column).(*analyzerpb.Column)
		out[i].Catalog = catalog
	}
	return out
}

func TestMySQLNormalizationPreservesCatalog(t *testing.T) {
	column := &analyzerpb.Column{Catalog: "def", Schema: "App", Table: "Orders", Column: "ID", Ordinal: 1}
	normalized := (MySqlDb{}).NormalizeColumns(1, []*analyzerpb.Column{column})
	if len(normalized) != 1 || normalized[0].GetCatalog() != "def" || normalized[0].GetSchema() != "app" {
		t.Fatalf("normalized column = %v", normalized)
	}
	normalized[0].Catalog = "changed"
	if column.GetCatalog() != "def" {
		t.Fatal("normalization aliased the input catalog")
	}
}
