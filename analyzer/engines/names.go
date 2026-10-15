package engines

import (
	"fmt"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	sqlglot "github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
)

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

// CaseMode is how a MySQL datasource folds names: lower_case_table_names as the target reported it. Other
// engines have one fixed rule and take the zero CaseMode.
type CaseMode struct {
	lowerCaseTableNames int
	reported            bool
}

// ReportedCaseMode is the lower_case_table_names a MySQL target reported: 0, 1 or 2.
func ReportedCaseMode(lowerCaseTableNames int) (CaseMode, error) {
	if lowerCaseTableNames < 0 || lowerCaseTableNames > 2 {
		return CaseMode{}, fmt.Errorf("lower_case_table_names must be 0, 1 or 2, not %d", lowerCaseTableNames)
	}
	return CaseMode{lowerCaseTableNames, true}, nil
}

// LowerCaseTableNames is the reported value; ok is false for the zero CaseMode.
func (m CaseMode) LowerCaseTableNames() (lowerCaseTableNames int, ok bool) {
	return m.lowerCaseTableNames, m.reported
}

// mysqlDialect folds identifiers as lower_case_table_names does, with MySQL's utf8mb3_general_ci map: under 0
// table and database names keep their case and everything else folds; under 1 and 2 everything folds. A mode
// the target never reported is a caller bug: guessing 0 would key names the analyzer never matches.
func mysqlDialect(mode CaseMode) *dialects.Dialect {
	if !mode.reported {
		panic("engines: MySQL needs a reported lower_case_table_names")
	}
	d := dialects.MySQL()
	if mode.lowerCaseTableNames == 0 {
		d.NormalizationStrategy = dialects.MySQLCaseSensitiveTableNames
	} else {
		d.NormalizationStrategy = dialects.MySQLCaseInsensitive
	}
	return d
}

var athenaDialect = dialects.Athena()

// athenaName folds a name as Athena resolves it, case-insensitively: AwsDataCatalog -> awsdatacatalog.
func athenaName(name string) string { return athenaDialect.FoldIdentifierName(name, false) }

// IntrospectedColumns puts names the target DB's own catalog returned in canonical spelling: an introspected
// column, DATABASE(), a stored default schema. MySQL folds by lower_case_table_names, Postgres keeps them, Athena
// folds all.
func (e *Engine) IntrospectedColumns(mode CaseMode, rows []*pb.Column) []ColumnName {
	return e.introspected(mode, rows)
}

// IntrospectedSchema is IntrospectedColumns for a row that names only a schema.
func (e *Engine) IntrospectedSchema(mode CaseMode, row *pb.Column) SchemaName {
	return e.introspected(mode, []*pb.Column{row})[0].Schema()
}

// ParseColumn reads names a person typed as SQL identifiers in the engine's dialect: unquoted folds, quoted stays
// exact (MySQL folds by lower_case_table_names either way). Postgres: Users.SSN -> users.ssn, "App"."T" -> App.T.
// A part that is not one identifier, such as a.b, is an error.
func (e *Engine) ParseColumn(mode CaseMode, catalog, schema, table, column string) (ColumnName, error) {
	d := e.dialect(mode)
	parts := make([]exp.Expression, 4)
	for i, text := range []string{catalog, schema, table, column} {
		id, err := parseIdentifier(d, text)
		if err != nil {
			return ColumnName{}, err
		}
		parts[i] = id
	}
	exp.Table(exp.Args{"this": parts[2], "schema": parts[1], "catalog": parts[0]})
	for _, id := range parts {
		d.NormalizeIdentifier(id)
	}
	return ColumnName{CatalogName{parts[0].Name()}, SchemaName{parts[1].Name()}, parts[2].Name(), parts[3].Name()}, nil
}

// ParsedSchema is a schema identifier from a parsed statement, folded by the engine's dialect: unquoted folds,
// quoted stays exact. The statement is not changed.
func (e *Engine) ParsedSchema(mode CaseMode, id exp.Expression) SchemaName {
	id = id.Copy()
	// NormalizeIdentifier reads the parent to tell a schema name from a column name.
	exp.Table(exp.Args{"this": exp.Identifier(exp.Args{"this": ""}), "schema": id})
	e.dialect(mode).NormalizeIdentifier(id)
	return SchemaName{id.Name()}
}

// parseIdentifier reads one identifier; an empty part (a key without a column) stays empty.
func parseIdentifier(d *dialects.Dialect, text string) (exp.Expression, error) {
	if text == "" || exp.IsSafeIdentifier(text) {
		return exp.Identifier(exp.Args{"this": text, "quoted": false}), nil
	}
	id, err := sqlglot.ParseInto(text, d, exp.KindIdentifier)
	if err != nil || id == nil || id.Kind() != exp.KindIdentifier {
		return nil, fmt.Errorf("%q is not an identifier", text)
	}
	return id, nil
}

// mysqlIntrospected folds catalog rows by lower_case_table_names: under 0, App.Users.ID -> App.Users.id; under
// 1 or 2, app.users.id. Each distinct (schema, table) is folded once.
func mysqlIntrospected(mode CaseMode, rows []*pb.Column) []ColumnName {
	d := mysqlDialect(mode)
	type relation struct{ schema, table string }
	relations := make(map[relation]relation)
	out := make([]ColumnName, len(rows))
	for i, row := range rows {
		key := relation{row.GetSchema(), row.GetTable()}
		canonical, ok := relations[key]
		if !ok {
			// NormalizeIdentifier reads each identifier's parent to tell a table or schema name from a column.
			schemaID := exp.Identifier(exp.Args{"this": key.schema, "quoted": false})
			tableID := exp.Identifier(exp.Args{"this": key.table, "quoted": false})
			exp.Table(exp.Args{"this": tableID, "schema": schemaID})
			d.NormalizeIdentifier(schemaID)
			d.NormalizeIdentifier(tableID)
			canonical = relation{schemaID.Name(), tableID.Name()}
			relations[key] = canonical
		}
		out[i] = ColumnName{CatalogName{row.GetCatalog()}, SchemaName{canonical.schema}, canonical.table, d.FoldIdentifierName(row.GetColumn(), false)}
	}
	return out
}

// postgresIntrospected keeps catalog rows as they are: pg_catalog already holds the exact names.
func postgresIntrospected(_ CaseMode, rows []*pb.Column) []ColumnName {
	out := make([]ColumnName, len(rows))
	for i, row := range rows {
		out[i] = ColumnName{CatalogName{row.GetCatalog()}, SchemaName{row.GetSchema()}, row.GetTable(), row.GetColumn()}
	}
	return out
}

// athenaIntrospected folds every part of a catalog row: AwsDataCatalog.HR.Salaries.SSN ->
// awsdatacatalog.hr.salaries.ssn.
func athenaIntrospected(_ CaseMode, rows []*pb.Column) []ColumnName {
	out := make([]ColumnName, len(rows))
	for i, row := range rows {
		out[i] = ColumnName{CatalogName{athenaName(row.GetCatalog())}, SchemaName{athenaName(row.GetSchema())}, athenaName(row.GetTable()), athenaName(row.GetColumn())}
	}
	return out
}
