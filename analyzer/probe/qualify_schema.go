package probe

import (
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/schema"
)

// newQualifySchema: ctid/xmin resolve when written but never expand from `*`, `t.*`, NATURAL or USING;
// a function table (`FROM pg_available_extension_versions()`) answers with its alias column names.
func newQualifySchema(mapping, implicit *schema.Mapping, eng engine) (schema.Schema, error) {
	base, err := schema.NewMappingSchemaWithImplicit(mapping, implicit, eng.Dialect(), eng.NormalizeCatalogOnBuild())
	if err != nil {
		return nil, err
	}
	return &functionTableSchema{Schema: base}, nil
}

type functionTableSchema struct {
	schema.Schema
}

// A function table's columns are its alias column names (`AS u(a, b)`, or stamped by
// markBuiltinFunctionRow); it has no implicit columns, so visible and full lists agree.
func (s *functionTableSchema) ColumnNames(table any, onlyVisible bool, dialect dialects.DialectType, normalize *bool) ([]string, error) {
	if node, ok := table.(exp.Expression); ok && node != nil && node.Kind() == exp.KindTable {
		if this := node.This(); this != nil && this.Is(exp.TraitFunc) {
			return node.AliasColumnNames(), nil
		}
	}
	return s.Schema.ColumnNames(table, onlyVisible, dialect, normalize)
}

var _ schema.Schema = (*functionTableSchema)(nil)
