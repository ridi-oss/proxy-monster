// Package engines is the one list of target engines and the static facts every Go module shares.
package engines

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/sqlglot-go/dialects"
)

// Engine is one target engine.
type Engine struct {
	// WireName is the persistence, registration, and JSON name.
	WireName string
	// Proto is the engine in the proxy and analyzer protos.
	Proto pb.Engine
	// DefaultSchemaSettable reports whether the engine has a statement that sets a session's default schema.
	DefaultSchemaSettable bool
	// DefaultProxyPort and DefaultTargetPort are the ports the proxy listens on and dials when config gives none.
	DefaultProxyPort  int
	DefaultTargetPort int
	// BuiltinSchema holds the engine's builtin functions and types; the zero SchemaName when it has none.
	BuiltinSchema SchemaName
	// IdentifierQuote quotes an identifier in the engine's SQL; a quote inside the name is doubled.
	IdentifierQuote string

	// numberedPlaceholders is Postgres's $1, $2 instead of ?.
	numberedPlaceholders bool
	// systemSchemas are the fixed system schemas: MySQL information_schema, mysql, performance_schema, sys.
	systemSchemas []SchemaName
	// tempSchema is the session temp schema, also numbered per backend: Postgres pg_temp, pg_temp_3.
	tempSchema SchemaName
	// sessionSchemaPrefixes start the per-session system schemas: Postgres pg_temp_3, pg_toast, pg_toast_temp_3.
	sessionSchemaPrefixes []SchemaName
	// catalogName is the catalog a datasource's tables are keyed under: MySQL def, Postgres the database as
	// registered, Athena AwsDataCatalog -> awsdatacatalog.
	catalogName func(registeredDbName string) CatalogName
	// introspected puts rows the target's own catalog returned in canonical spelling: MySQL App.Users.ID ->
	// app.users.id under lower_case_table_names=1, Postgres unchanged.
	introspected func(mode CaseMode, rows []*pb.Column) []ColumnName
	// dialect is the engine's sqlglot dialect: canonical names fold by it and analyzers parse with it. MySQL's follows the CaseMode.
	dialect func(mode CaseMode) *dialects.Dialect
}

var (
	MySQL = &Engine{
		WireName: "mysql", Proto: pb.Engine_MYSQL, DefaultSchemaSettable: true,
		DefaultProxyPort: 6033, DefaultTargetPort: 3307, IdentifierQuote: "`",
		systemSchemas: schemas("information_schema", "mysql", "performance_schema", "sys"),
		// MySQL has one catalog, def, whatever the database.
		catalogName:  func(string) CatalogName { return CatalogName{"def"} },
		introspected: mysqlIntrospected,
		dialect:      mysqlDialect,
	}
	Postgres = &Engine{
		WireName: "postgres", Proto: pb.Engine_POSTGRES, DefaultSchemaSettable: true,
		DefaultProxyPort: 6432, DefaultTargetPort: 5433, IdentifierQuote: `"`, numberedPlaceholders: true,
		BuiltinSchema:         SchemaName{"pg_catalog"},
		systemSchemas:         schemas("pg_catalog", "information_schema"),
		tempSchema:            SchemaName{"pg_temp"},
		sessionSchemaPrefixes: schemas("pg_temp_", "pg_toast"),
		// The database name is a connection parameter libpq matches exactly, not SQL text, so it is not folded.
		catalogName:  func(registeredDbName string) CatalogName { return CatalogName{registeredDbName} },
		introspected: postgresIntrospected,
		dialect:      func(CaseMode) *dialects.Dialect { return dialects.Postgres() },
	}
	Athena = &Engine{
		WireName: "athena", Proto: pb.Engine_ATHENA,
		DefaultProxyPort: 6443, DefaultTargetPort: 443, IdentifierQuote: `"`,
		systemSchemas: schemas("information_schema"),
		// Athena resolves catalog names case-insensitively.
		catalogName:  func(registeredDbName string) CatalogName { return CatalogName{athenaName(registeredDbName)} },
		introspected: athenaIntrospected,
		dialect:      func(CaseMode) *dialects.Dialect { return dialects.Athena() },
	}
	// All is every engine, MySQL first.
	All = []*Engine{MySQL, Postgres, Athena}
)

// Parse maps an exact wire name to its engine; anything else, a different case included, is an error.
func Parse(wireName string) (*Engine, error) {
	if i := slices.IndexFunc(All, func(e *Engine) bool { return e.WireName == wireName }); i >= 0 {
		return All[i], nil
	}
	return nil, fmt.Errorf("unsupported engine %q (expected mysql, postgres, or athena)", wireName)
}

// ByProto is the engine a proto Engine denotes; ENGINE_UNSPECIFIED and unknown values are not one.
func ByProto(p pb.Engine) (*Engine, bool) {
	i := slices.IndexFunc(All, func(e *Engine) bool { return e.Proto == p })
	if i < 0 {
		return nil, false
	}
	return All[i], true
}

// Placeholder is the nth (1-based) bind-parameter placeholder: "?" or "$n".
func (e *Engine) Placeholder(n int) string {
	if e.numberedPlaceholders {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

// IsSystemSchema reports whether schema is a fixed system schema or a per-session one (Postgres pg_temp_3,
// pg_toast).
func (e *Engine) IsSystemSchema(schema SchemaName) bool {
	if slices.Contains(e.systemSchemas, schema) {
		return true
	}
	return slices.ContainsFunc(e.sessionSchemaPrefixes, func(p SchemaName) bool { return strings.HasPrefix(schema.name, p.name) })
}

// IsTempSchema reports whether schema is the session temp schema (pg_temp, pg_temp_3).
func (e *Engine) IsTempSchema(schema SchemaName) bool {
	return e.tempSchema != SchemaName{} && (schema == e.tempSchema || strings.HasPrefix(schema.name, e.tempSchema.name+"_"))
}

// CatalogName is the catalog the analyzer keys a datasource's tables under, from the database name the
// datasource was registered with (not normalized): MySQL "def", Postgres the name as is, Athena folded.
func (e *Engine) CatalogName(registeredDbName string) CatalogName {
	return e.catalogName(registeredDbName)
}

// Dialect is the engine's sqlglot dialect: canonical names fold by it and analyzers parse with it. MySQL's follows the CaseMode.
func (e *Engine) Dialect(mode CaseMode) *dialects.Dialect {
	return e.dialect(mode)
}
