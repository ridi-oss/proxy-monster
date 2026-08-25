package probe

import (
	"slices"

	"github.com/ridi-oss/sqlglot-go/dialects"
	"github.com/ridi-oss/sqlglot-go/schema"
)

type implicitNonVisibleSchema struct {
	schema.Schema
	columns []string
}

func newQualifySchema(mapping *schema.Mapping, eng engine) (schema.Schema, error) {
	base, err := schema.NewMappingSchema(mapping, eng.Dialect(), eng.NormalizeCatalogOnBuild())
	if err != nil {
		return nil, err
	}
	columns := eng.ImplicitNonVisibleColumns()
	if len(columns) == 0 {
		return base, nil
	}
	return &implicitNonVisibleSchema{Schema: base, columns: columns}, nil
}

// sqlglot resolves explicit columns with onlyVisible=false and expands stars with onlyVisible=true.
func (s *implicitNonVisibleSchema) ColumnNames(table any, onlyVisible bool, dialect dialects.DialectType, normalize *bool) ([]string, error) {
	columns, err := s.Schema.ColumnNames(table, onlyVisible, dialect, normalize)
	if err != nil || onlyVisible {
		return columns, err
	}
	out := append([]string(nil), columns...)
	for _, implicit := range s.columns {
		if !slices.Contains(columns, implicit) {
			out = append(out, implicit)
		}
	}
	return out, nil
}

var _ schema.Schema = (*implicitNonVisibleSchema)(nil)
