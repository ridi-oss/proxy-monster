package engines

import (
	"fmt"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/schema"
	"github.com/ridi-oss/sqlglot-go/tokens"
	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// sessionDialect is the dialect a session parses, qualifies and generates by, for what it observed (MySQL
// ansi_quotes); it fails on an observation the analysis cannot use.
type sessionDialect func(observation *pb.SessionObservation) (*dialects.Dialect, error)

// Session is the engine on one connection to a target. It folds names to the form the target stores them in,
// by what the target reported: MySQL by lower_case_table_names, Postgres unquoted only, Athena all.
type Session struct {
	engine         *Engine
	targetSettings *pb.TargetSettings
	targetDialect  *dialects.Dialect
	sessionDialect sessionDialect
	// dialect and observation are what the session last observed; statements parse by dialect.
	dialect     *dialects.Dialect
	observation *pb.SessionObservation
}

// NewSession is the engine on a connection to a target that reported targetSettings; MySQL requires
// lower_case_table_names. It analyzes statements once Update records the session.
func (e *Engine) NewSession(targetSettings *pb.TargetSettings) (*Session, error) {
	if targetSettings == nil {
		targetSettings = &pb.TargetSettings{}
	}
	d, sessionDialect, err := e.Traits.targetDialect(targetSettings)
	if err != nil {
		return nil, err
	}
	return &Session{engine: e, targetSettings: proto.Clone(targetSettings).(*pb.TargetSettings), targetDialect: d, sessionDialect: sessionDialect}, nil
}

// Update records what the session observed (MySQL ansi_quotes, Postgres shadowed functions, the Athena
// workgroup); its statements parse by the dialect that picks. It fails on an observation the analysis cannot use.
func (s *Session) Update(observation *pb.SessionObservation) error {
	d, err := s.sessionDialect(observation)
	if err != nil {
		return err
	}
	if observation != nil {
		observation = proto.Clone(observation).(*pb.SessionObservation)
	}
	s.dialect, s.observation = d, observation
	return nil
}

// newSession reads config, failing closed on a target or session the engine
// cannot analyze (MySQL without its version or lower_case_table_names).
func newSession(config *pb.EngineConfig) (*Session, error) {
	if config == nil {
		return nil, fmt.Errorf("engine config is required")
	}
	e, ok := ByProto(config.GetEngine())
	if !ok {
		return nil, fmt.Errorf("unsupported engine %s", config.GetEngine())
	}
	session, err := e.NewSession(config.GetTarget())
	if err != nil {
		return nil, err
	}
	if err := session.Update(config.GetSession()); err != nil {
		return nil, err
	}
	return session, nil
}

// Engine is the session's engine.
func (s *Session) Engine() *Engine { return s.engine }

// EngineVersion is the server version the target reported.
func (s *Session) EngineVersion() string { return s.targetSettings.GetEngineVersion() }

// TargetSettings is what the target reported, lower_case_table_names included.
func (s *Session) TargetSettings() *pb.TargetSettings {
	return proto.Clone(s.targetSettings).(*pb.TargetSettings)
}

// CatalogColumnNames puts names the target DB's own catalog returned in canonical spelling: an introspected
// column, DATABASE(), a stored default schema. MySQL folds by lower_case_table_names, Postgres keeps them, Athena
// folds all.
func (s *Session) CatalogColumnNames(rows []*pb.Column) []ColumnName {
	return s.engine.Traits.catalogColumnNames(s.targetDialect, rows)
}

// CanonicalColumns is rows cloned with their names in canonical spelling, for the proxy's catalog push.
func (s *Session) CanonicalColumns(rows []*pb.Column) []*pb.Column {
	names := s.CatalogColumnNames(rows)
	out := make([]*pb.Column, len(rows))
	for i, row := range rows {
		out[i] = proto.Clone(row).(*pb.Column)
		out[i].Schema, out[i].Table, out[i].Column = names[i].Schema().String(), names[i].Table(), names[i].Column()
	}
	return out
}

// CanonicalSchemas is schema names in canonical spelling: MySQL under lower_case_table_names=1, App -> app.
func (s *Session) CanonicalSchemas(schemas []string) []SchemaName {
	rows := make([]*pb.Column, len(schemas))
	for i, schema := range schemas {
		rows[i] = &pb.Column{Schema: schema}
	}
	out := make([]SchemaName, len(schemas))
	for i, name := range s.CatalogColumnNames(rows) {
		out[i] = name.Schema()
	}
	return out
}

// FunctionName is a routine name as the analyzer keys it: MySQL AddTax -> addtax; Postgres keeps the proname.
func (s *Session) FunctionName(name string) FunctionName {
	if s.engine.Traits.functionName == nil {
		return FunctionName{name}
	}
	return s.engine.Traits.functionName(name)
}

// FunctionNames is FunctionName over names, without duplicates, in first-seen order.
func (s *Session) FunctionNames(names []string) []FunctionName {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[FunctionName]struct{}, len(names))
	out := make([]FunctionName, 0, len(names))
	for _, name := range names {
		functionName := s.FunctionName(name)
		if _, dup := seen[functionName]; !dup {
			seen[functionName] = struct{}{}
			out = append(out, functionName)
		}
	}
	return out
}

// CatalogSchemaName is CatalogColumnNames for a row that names only a schema.
func (s *Session) CatalogSchemaName(row *pb.Column) SchemaName {
	return s.CatalogColumnNames([]*pb.Column{row})[0].Schema()
}

// ParseColumn reads names a person typed as SQL identifiers in the engine's dialect: unquoted folds, quoted stays
// exact (MySQL folds by lower_case_table_names either way). Postgres: Users.SSN -> users.ssn, "App"."T" -> App.T.
// A part that is not one identifier, such as a.b, is an error.
func (s *Session) ParseColumn(catalog, schema, table, column string) (ColumnName, error) {
	d := s.targetDialect
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
func (s *Session) ParsedSchema(id exp.Expression) SchemaName {
	id = id.Copy()
	// NormalizeIdentifier reads the parent to tell a schema name from a column name.
	exp.Table(exp.Args{"this": exp.Identifier(exp.Args{"this": ""}), "schema": id})
	s.targetDialect.NormalizeIdentifier(id)
	return SchemaName{id.Name()}
}

// isTempSchemaID reports whether a parsed schema identifier is the session temp schema; nil is not.
func (s *Session) isTempSchemaID(id exp.Expression) bool {
	return id != nil && s.engine.IsTempSchema(s.ParsedSchema(id))
}

// isBuiltinQualifier reports whether a call or type qualifier is one identifier naming BuiltinSchema: Postgres
// pg_catalog, not the distinct user schema "PG_CATALOG".
func (s *Session) isBuiltinQualifier(qualifier exp.Expression) bool {
	return s.engine.Traits.BuiltinSchema != SchemaName{} && qualifier != nil && qualifier.Kind() == exp.KindIdentifier &&
		s.ParsedSchema(qualifier) == s.engine.Traits.BuiltinSchema
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

func (s *Session) bareCallIsBuiltin(name string) bool {
	return s.engine.Traits.bareCallIsBuiltin(s, name)
}

func (s *Session) isSafeTypeReference(dt, kind exp.Expression, namespace NamespaceConfig) bool {
	return s.engine.Traits.isSafeTypeReference(s, dt, kind, namespace)
}

func (s *Session) nativeOutputLabel(projection, query exp.Expression) (string, bool) {
	return s.engine.Traits.nativeOutputLabel(s, projection, query)
}

func (s *Session) diagnosticLeakKeys(report ProbeResult, qualifySchema schema.Schema) map[string]bool {
	return s.engine.Traits.diagnosticLeakKeys(s, report, qualifySchema)
}
