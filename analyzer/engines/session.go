package engines

import (
	"fmt"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/tokens"
	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// Datasource is an engine as one datasource spells names: MySQL folds by the lower_case_table_names its target reported.
type Datasource struct {
	*Engine
	dialect *dialects.Dialect
	version string
}

// Datasource binds the engine to what one datasource's target reported; MySQL requires lower_case_table_names.
func (e *Engine) Datasource(targetSettings *pb.TargetSettings) (Datasource, error) {
	d := e.Traits.dialect()
	if e.Traits.datasourceDialect != nil {
		var err error
		if d, err = e.Traits.datasourceDialect(targetSettings); err != nil {
			return Datasource{}, err
		}
	}
	return Datasource{e, d, targetSettings.GetEngineVersion()}, nil
}

// sessionSettings is what one analysis call reads: the engine, how the target spells names, the dialect the
// session's statements parse by, and what the session observed (MySQL ansi_quotes, Postgres shadowed
// functions, the Athena workgroup).
type sessionSettings struct {
	engine      *Engine
	datasource  Datasource
	dialect     *dialects.Dialect
	observation *pb.SessionObservation
}

// sessionSettings is t with what one session observed.
func (t Datasource) sessionSettings(observation *pb.SessionObservation) (*sessionSettings, error) {
	d, err := t.Traits.sessionDialect(t, observation)
	if err != nil {
		return nil, err
	}
	if observation != nil {
		observation = proto.Clone(observation).(*pb.SessionObservation)
	}
	return &sessionSettings{engine: t.Engine, datasource: t, dialect: d, observation: observation}, nil
}

// newSessionSettings reads config, failing closed on a target or session the engine
// cannot analyze (MySQL without its version or lower_case_table_names).
func newSessionSettings(config *pb.EngineConfig) (*sessionSettings, error) {
	if config == nil {
		return nil, fmt.Errorf("engine config is required")
	}
	e, ok := ByProto(config.GetEngine())
	if !ok {
		return nil, fmt.Errorf("unsupported engine %s", config.GetEngine())
	}
	datasource, err := e.Datasource(config.GetTarget())
	if err != nil {
		return nil, err
	}
	return datasource.sessionSettings(config.GetSession())
}

// Dialect is the sqlglot dialect the datasource's canonical names fold by.
func (t Datasource) Dialect() *dialects.Dialect { return t.dialect }

// IntrospectedColumns puts names the target DB's own catalog returned in canonical spelling: an introspected
// column, DATABASE(), a stored default schema. MySQL folds by lower_case_table_names, Postgres keeps them, Athena
// folds all.
func (t Datasource) IntrospectedColumns(rows []*pb.Column) []ColumnName {
	return t.Traits.introspected(t.dialect, rows)
}

// IntrospectedSchema is IntrospectedColumns for a row that names only a schema.
func (t Datasource) IntrospectedSchema(row *pb.Column) SchemaName {
	return t.IntrospectedColumns([]*pb.Column{row})[0].Schema()
}

// ParseColumn reads names a person typed as SQL identifiers in the engine's dialect: unquoted folds, quoted stays
// exact (MySQL folds by lower_case_table_names either way). Postgres: Users.SSN -> users.ssn, "App"."T" -> App.T.
// A part that is not one identifier, such as a.b, is an error.
func (t Datasource) ParseColumn(catalog, schema, table, column string) (ColumnName, error) {
	d := t.dialect
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
func (t Datasource) ParsedSchema(id exp.Expression) SchemaName {
	id = id.Copy()
	// NormalizeIdentifier reads the parent to tell a schema name from a column name.
	exp.Table(exp.Args{"this": exp.Identifier(exp.Args{"this": ""}), "schema": id})
	t.dialect.NormalizeIdentifier(id)
	return SchemaName{id.Name()}
}

// isTempSchemaID reports whether a parsed schema identifier is the session temp schema; nil is not.
func (t Datasource) isTempSchemaID(id exp.Expression) bool {
	return id != nil && t.IsTempSchema(t.ParsedSchema(id))
}

// isBuiltinQualifier reports whether a call or type qualifier is one identifier naming BuiltinSchema: Postgres
// pg_catalog, not the distinct user schema "PG_CATALOG".
func (t Datasource) isBuiltinQualifier(qualifier exp.Expression) bool {
	return t.Traits.BuiltinSchema != SchemaName{} && qualifier != nil && qualifier.Kind() == exp.KindIdentifier &&
		t.ParsedSchema(qualifier) == t.Traits.BuiltinSchema
}

// parseIdentifier reads one identifier; an empty part (a key without a column) stays empty.
func parseIdentifier(d *dialects.Dialect, text string) (exp.Expression, error) {
	if text == "" || exp.IsSafeIdentifier(text) {
		return exp.Identifier(exp.Args{"this": text, "quoted": false}), nil
	}
	// ParseInto reads a string literal as an identifier too: 'SSN' must not become SSN.
	toks, err := d.NewTokenizer().Tokenize(text)
	if err != nil || len(toks) != 1 || (toks[0].TokenType != tokens.IDENTIFIER && toks[0].TokenType != tokens.VAR) {
		return nil, fmt.Errorf("%q is not an identifier", text)
	}
	id, err := sqlglot.ParseInto(text, d, exp.KindIdentifier)
	if err != nil || id == nil || id.Kind() != exp.KindIdentifier {
		return nil, fmt.Errorf("%q is not an identifier", text)
	}
	return id, nil
}
