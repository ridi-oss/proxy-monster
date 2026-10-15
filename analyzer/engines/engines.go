// Package engines is the one list of target engines: the facts every Go module shares and each engine's SQL analyzer.
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
	// newAnalyzer builds the per-request analyzer from a statement's EngineConfig: MySQL reads its version
	// and lower_case_table_names from it.
	newAnalyzer func(e *Engine, config *pb.EngineConfig) (analyzer, error)
	// normalizeRules are the lexer rules SqlNormalize applies: MySQL refuses `/*! */`, Postgres folds identifiers.
	normalizeRules func() normalizeRules
	// configFailureDialect parses a SHOW while the engine config is incomplete; nil fails it closed.
	configFailureDialect func() *dialects.Dialect

	// connectionProperties are the ConnectionInfo keys the engine's proxies may publish: Athena region, workgroup.
	connectionProperties []string
	// catalogIsConnectionIndependent: one connection's catalog answers for all; false for Postgres pg_temp_*.
	catalogIsConnectionIndependent bool
	// checksTargetErrors: the proxy can prepare a statement on the target without running it.
	checksTargetErrors bool
	// needsCaseMode: typed names wait for the target to report MySQL lower_case_table_names.
	needsCaseMode bool
	// implicitColumns are on every table beyond the introspected ones: Postgres ctid tid, xmin xid.
	implicitColumns []*pb.ImplicitColumn
	// defaultSchemaPrefix starts the statement that sets a session's default schema: MySQL "USE ".
	defaultSchemaPrefix string
	// defaultSchema is the schema an unqualified table resolves to: MySQL the registered database, Postgres public.
	defaultSchema func(registeredDbName string) string
	// serverVersion reads a comparable version from version(): "8.0.mysql_aurora.3.04.0" -> 8.0, aurora.
	serverVersion func(raw string) *pb.ServerVersion
	// manifestSeries is the classification-manifest series of a version: MySQL 8.0.44 -> 8.0, Postgres 16.4 -> 16.
	manifestSeries func(version string) string
	// functionCatalog tiers introspected routines into the analyzer's function inventory.
	functionCatalog func(e *Engine, routines []*pb.SchemaFunctions, version string) *pb.FunctionCatalog
	// connectionInfoValid reports whether the engine's proxies may publish info.
	connectionInfoValid func(e *Engine, info *pb.EngineConnectionInfo) bool
	// analyzerConfig is the EngineConfig for one decision, or for a batch split; nil when a split cannot run yet.
	analyzerConfig func(e *Engine, ds *pb.EngineDatasource, session *pb.SessionObservation, split bool) (*pb.EngineConfig, error)
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
		newAnalyzer:  newMySQLAnalyzer,
		normalizeRules: func() normalizeRules {
			d := dialects.MySQL()
			return normalizeRules{dialect: d, wordDialect: d, rejectExecutableComments: true}
		},
		configFailureDialect: dialects.MySQL,

		catalogIsConnectionIndependent: true, checksTargetErrors: true, needsCaseMode: true,
		defaultSchemaPrefix: "USE ",
		defaultSchema:       func(registeredDbName string) string { return registeredDbName },
		serverVersion:       mysqlServerVersion,
		manifestSeries:      mysqlManifestSeries,
		functionCatalog:     mysqlFunctionCatalog,
		connectionInfoValid: nativeConnectionInfoValid,
		analyzerConfig:      mysqlAnalyzerConfig,
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
		newAnalyzer:  newPostgresAnalyzer,
		normalizeRules: func() normalizeRules {
			d := dialects.Postgres()
			return normalizeRules{dialect: d, wordDialect: d, foldIdentifiers: true}
		},

		checksTargetErrors:  true,
		implicitColumns:     postgresSystemColumns,
		defaultSchemaPrefix: "SET search_path TO ",
		defaultSchema:       func(string) string { return "public" },
		serverVersion:       postgresServerVersion,
		manifestSeries:      func(version string) string { return strings.SplitN(version, ".", 2)[0] },
		functionCatalog:     postgresFunctionCatalog,
		connectionInfoValid: nativeConnectionInfoValid,
		analyzerConfig:      sessionAnalyzerConfig,
	}
	Athena = &Engine{
		WireName: "athena", Proto: pb.Engine_ATHENA,
		DefaultProxyPort: 6443, DefaultTargetPort: 443, IdentifierQuote: `"`,
		systemSchemas: schemas("information_schema"),
		// Athena resolves catalog names case-insensitively.
		catalogName:  func(registeredDbName string) CatalogName { return CatalogName{athenaName(registeredDbName)} },
		introspected: athenaIntrospected,
		dialect:      func(CaseMode) *dialects.Dialect { return dialects.Athena() },
		newAnalyzer:  newAthenaAnalyzer,
		normalizeRules: func() normalizeRules {
			return normalizeRules{dialect: dialects.Athena(), wordDialect: dialects.Trino(), hiveDialect: dialects.Hive(), foldIdentifiers: true}
		},

		connectionProperties:           []string{"region", "workgroup", "catalog", "database"},
		catalogIsConnectionIndependent: true,
		defaultSchema:                  func(registeredDbName string) string { return registeredDbName },
		serverVersion:                  athenaServerVersion,
		manifestSeries:                 func(version string) string { return version },
		functionCatalog:                athenaFunctionCatalog,
		connectionInfoValid:            athenaConnectionInfoValid,
		analyzerConfig:                 athenaAnalyzerConfig,
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
