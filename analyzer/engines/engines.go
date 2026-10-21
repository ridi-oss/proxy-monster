// Package engines is the one list of target engines: the facts every Go module shares and each engine's SQL analyzer.
//
// An engine is known at three levels, each with its own Dialect:
//   - Engine: the facts every datasource of the engine shares.
//   - Datasource: the engine bound to what one datasource's target reported (MySQL lower_case_table_names);
//     names fold by its dialect.
//   - sessionSettings: one analysis call, the Datasource plus what the proxy observed on the session (MySQL
//     ansi_quotes); statements parse by its dialect.
package engines

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/schema"

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

// Engine is one target engine: what it is and how its target behaves, and its steps in a statement's analysis.
type Engine struct {
	// WireName is the persistence, registration, and JSON name.
	WireName string
	// Proto is the engine in the proxy and analyzer protos.
	Proto pb.Engine
	// DefaultProxyPort and DefaultTargetPort are the ports the proxy listens on and dials when config gives none.
	DefaultProxyPort  int
	DefaultTargetPort int
	Traits            EngineTraits
	hooks             engineHooks
}

// EngineTraits is what an engine is and how its target behaves.
type EngineTraits struct {
	// DefaultSchemaSettable reports whether the engine has a statement that sets a session's default schema.
	DefaultSchemaSettable bool
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
	datasourceDialect func(targetSettings *pb.TargetSettings) (*dialects.Dialect, error)
	// sessionDialect is the target's dialect with what the session observed (MySQL ansi_quotes), used to
	// parse, qualify and generate alike; it fails on settings the analysis cannot use.
	sessionDialect func(datasource Datasource, observation *pb.SessionObservation) (*dialects.Dialect, error)
	// bareCallIsBuiltin: is a bare call (`unnest(...)`, no schema) guaranteed to be the
	// pg_catalog builtin? PostgreSQL picks a function across every search_path schema by argument
	// type, so a user `public.unnest(int[])` beats `pg_catalog.unnest(anyarray)` for an int[] argument
	// even with pg_catalog first. false = fail closed, the row stays unknown.
	bareCallIsBuiltin func(settings *sessionSettings, name string) bool
	// showUtilityCommand names the utility grant a SHOW form requires ("" for none), so an engine can
	// classify a data-bearing SHOW (e.g. SHOW PARTITIONS) as a result read.
	showUtilityCommand func(root exp.Expression) string
	// isSafeTypeReference: a type sqlglot marked user-defined that is trusted anyway (`'1'::xid` when
	// it must be pg_catalog.xid). False keeps the user-type fail-close.
	isSafeTypeReference func(settings *sessionSettings, dt, kind exp.Expression, namespace NamespaceConfig) bool
	// systemSchemaFirst: an unqualified name resolves in the system schema first (PostgreSQL: pg_catalog
	// precedes every user schema on searchPath, pg_temp aside; MySQL: never).
	systemSchemaFirst func(searchPath []string) bool
	// nativeOutputLabel computes the output label THIS engine's target DB natively assigns to an
	// unaliased projection: PostgreSQL derives it from the resolved expression (parse_target.c
	// FigureColname, written function names from the parse-time SpanText); MySQL uses the
	// projection's verbatim source spelling (SpanText). query is the SELECT the projection belongs
	// to, for resolving references to its derived sources. ok=false means the label is unknowable —
	// the caller leaves Qualify's synthetic name.
	nativeOutputLabel func(settings *sessionSettings, projection, query exp.Expression) (string, bool)
	// diagnosticLeakKeys is the column keys this statement's target-DB error/warning diagnostic could echo
	// — engine-specific, since what a diagnostic contains is (MySQL echoes the operated value; PostgreSQL
	// also dumps a failed write's whole row via `DETAIL: Failing row contains (…)`). Start from
	// referencedColumnKeys (the shared template) and add engine channels on top.
	diagnosticLeakKeys func(settings *sessionSettings, report ProbeResult, qualifySchema schema.Schema) map[string]bool
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
	if e.Traits.numberedPlaceholders {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

// IsSystemSchema reports whether schema is a fixed system schema or a per-session one (Postgres pg_temp_3,
// pg_toast).
func (e *Engine) IsSystemSchema(schema SchemaName) bool {
	if slices.Contains(e.Traits.systemSchemas, schema) {
		return true
	}
	return slices.ContainsFunc(e.Traits.sessionSchemaPrefixes, func(p SchemaName) bool { return strings.HasPrefix(schema.name, p.name) })
}

// IsTempSchema reports whether schema is the session temp schema (pg_temp, pg_temp_3).
func (e *Engine) IsTempSchema(schema SchemaName) bool {
	return e.Traits.tempSchema != SchemaName{} && (schema == e.Traits.tempSchema || strings.HasPrefix(schema.name, e.Traits.tempSchema.name+"_"))
}

// CatalogName is the catalog the analyzer keys a datasource's tables under, from the database name the
// datasource was registered with (not normalized): MySQL "def", Postgres the name as is, Athena folded.
func (e *Engine) CatalogName(registeredDbName string) CatalogName {
	return e.Traits.catalogName(registeredDbName)
}
