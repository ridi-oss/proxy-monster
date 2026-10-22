package engines

// CatalogName is a catalog name in its engine's canonical spelling.
type CatalogName struct{ name string }

func (n CatalogName) String() string { return n.name }

// SchemaName is a schema name in its engine's canonical spelling.
type SchemaName struct{ name string }

func (n SchemaName) String() string { return n.name }

// schemas is canonical schema names written as literals in this package.
func schemas(names ...string) []SchemaName {
	out := make([]SchemaName, len(names))
	for i, n := range names {
		out[i] = SchemaName{n}
	}
	return out
}

// ColumnName is a column's catalog, schema, table and column name in its engine's canonical spelling.
type ColumnName struct {
	catalog CatalogName
	schema  SchemaName
	table   string
	column  string
}

func (n ColumnName) Catalog() CatalogName { return n.catalog }
func (n ColumnName) Schema() SchemaName   { return n.schema }
func (n ColumnName) Table() string        { return n.table }
func (n ColumnName) Column() string       { return n.column }
