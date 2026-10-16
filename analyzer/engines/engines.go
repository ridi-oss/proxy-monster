// Package engines is the one list of target engines: the facts every Go module shares and each engine's SQL analyzer.
//
// An engine is known at three levels, each with its own Dialect:
//   - Engine: the facts every datasource of the engine shares.
//   - Datasource: the engine bound to what one datasource's target reported (MySQL lower_case_table_names);
//     names fold by its dialect.
//   - session: one statement's analyzer, the datasource plus what the proxy observed on the session (MySQL
//     ansi_quotes); statements parse by its dialect.
package engines

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ridi-oss/sqlglot-go/dialects"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// starOrder is a merging join's star-expansion column order: the merged common columns, then the
// remaining columns of each side.
type starOrder int

const (
	// starOrderCommonLeftRight: common columns, the left table's rest, the right's (PostgreSQL).
	starOrderCommonLeftRight starOrder = iota
	// starOrderCommonRightLeft: common columns, the RIGHT table's rest, the left's — MySQL expands
	// `a RIGHT JOIN b` as `b LEFT JOIN a`.
	starOrderCommonRightLeft
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
	introspected func(d *dialects.Dialect, rows []*pb.Column) []ColumnName
	// dialect is the engine's dialect before any datasource is known.
	dialect func() *dialects.Dialect
	// datasourceDialect is the dialect a datasource's names fold by: MySQL's follows the lower_case_table_names its
	// target reported. Nil keeps the engine's.
	datasourceDialect func(ds *pb.EngineDatasource) (*dialects.Dialect, error)
	// newSession builds one statement's analyzer: MySQL reads ansi_quotes, Athena the workgroup.
	newSession func(ds Datasource, observed *pb.SessionObservation) (session, error)
	// normalizeRules are the lexer rules SqlNormalize applies: MySQL refuses `/*! */`, Postgres folds identifiers.
	normalizeRules func() normalizeRules
	// showsWithoutSession parses a SHOW by the engine's dialect when no session can be built (MySQL before
	// lower_case_table_names is reported); elsewhere that fails closed.
	showsWithoutSession bool
	// foldColumn is a column name as the engine compares it: MySQL and Athena fold, Postgres keeps it exact.
	foldColumn func(name string) string
	// normalizeCatalogOnBuild folds the introspected catalog when the analyzer builds its schema; Postgres keeps
	// it, since quoted and unquoted names can be distinct real columns.
	normalizeCatalogOnBuild bool
	// allowsCrossCatalog lets a statement resolve a table outside the session's catalog; MySQL and Postgres
	// address one catalog per connection.
	allowsCrossCatalog bool
	// preservesCatalogQualifier keeps the catalog in the SQL sent to the target; elsewhere it is analyzer-only.
	preservesCatalogQualifier bool
	// rejectsDuplicateDerivedOutputLabels: a derived table or CTE with colliding output labels is an error
	// (MySQL ER_DUP_FIELDNAME); Postgres rejects only a reference to one.
	rejectsDuplicateDerivedOutputLabels bool
	// rightJoinStarOrder is how a NATURAL/USING RIGHT JOIN's star expansion is ordered.
	rightJoinStarOrder starOrder
	// builtinFunctionRows are the columns a builtin table function returns without an alias list:
	// unnest -> [unnest]. Any other call needs an explicit AS f(a, b).
	builtinFunctionRows map[string][]string
	// passthroughCommands are the commands a statement that degraded to an unstructured Command may relay as;
	// anything else fails closed.
	passthroughCommands []string
	// syntaxCalls are call-shaped syntax over one subquery, lowercase: Postgres ARRAY(SELECT ...) is no pg_proc function.
	syntaxCalls []string

	// connectionProperties are the ConnectionInfo keys the engine's proxies may publish: Athena region, workgroup.
	connectionProperties []string
	// catalogIsConnectionIndependent: one connection's catalog answers for all; false for Postgres pg_temp_*.
	catalogIsConnectionIndependent bool
	// checksTargetErrors: the proxy can prepare a statement on the target without running it.
	checksTargetErrors bool
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
	// analyzerConfig is the EngineConfig for one decision or a batch split.
	analyzerConfig func(e *Engine, ds *pb.EngineDatasource, session *pb.SessionObservation) *pb.EngineConfig
}

var (
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
