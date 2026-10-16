package engines

import (
	"fmt"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/optimizer"
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

// analyzer owns every analyzer-specific analysis decision, built once per Probe call from the caller's
// EngineConfig — everything an analyzer needs (server version, MySQL's lower_case_table_names, the
// sqlglot-go Dialect built from them) is captured at construction, so nothing downstream re-derives
// it from a namespace or re-parses it from a bare wire-name string.
type analyzer interface {
	// WireName is the canonical lowercase sqlglot-go dialect name ("mysql" | "postgres").
	WireName() string
	// Dialect is the single *dialects.Dialect built once from this engine's config — reused for
	// parsing, catalog normalization, Qualify, and SQL generation alike (sqlglot-go accepts a
	// *Dialect directly everywhere a dialect argument is taken, MySQLVersion included, so there is
	// no separate parse-only string form to keep in sync with this one).
	Dialect() *dialects.Dialect
	NormalizeCatalogOnBuild() bool
	// BuiltinFunctionRow: the columns a builtin function table returns when called without an
	// alias column list: `FROM unnest(arr)` -> [unnest], `FROM pg_available_extension_versions()` ->
	// [name, version, ...]. nil = not a builtin we know; the call then needs an explicit `AS f(a, b)`.
	BuiltinFunctionRow(name string) []string
	// BareCallIsBuiltin: is a bare call (`unnest(...)`, no schema) guaranteed to be the
	// pg_catalog builtin? PostgreSQL picks a function across every search_path schema by argument
	// type, so a user `public.unnest(int[])` beats `pg_catalog.unnest(anyarray)` for an int[] argument
	// even with pg_catalog first. false = fail closed, the row stays unknown.
	BareCallIsBuiltin(name string) bool
	PostgresSystemXIDVisible() bool
	// AllowsCrossCatalog reports whether a statement may resolve a table in a catalog other than the
	// session's. MySQL and PostgreSQL address one catalog per connection, so a foreign catalog fails closed.
	AllowsCrossCatalog() bool
	// PreservesCatalogQualifier reports whether the catalog is a real third name component in executable
	// SQL. When false the analyzer-only catalog is stripped from the SQL rendered for the target DB.
	PreservesCatalogQualifier() bool
	// ConfigureNamespace maps the session's namespace onto the qualifier's resolution options: a search
	// path for engines that have one, a fixed catalog and default schema for engines that do not.
	ConfigureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig)
	FoldColumn(column string) string
	// IsTempSchema reports whether a DDL target's schema identifier denotes session-local (temporary)
	// storage for this engine, so the DDL is not catalog-changing. The schema is passed as its parsed
	// identifier node (nil for an unqualified target) so the engine folds it through sqlglot-go's
	// dialect normalization — honoring quoting and the engine's case rules — never a raw Go lowercase.
	// Engine-specific: PostgreSQL's pg_temp; MySQL has no temp-schema convention (its temporary tables
	// are marked by the TEMPORARY keyword).
	IsTempSchema(schema exp.Expression) bool
	// IsTrustedSystemQualifier reports whether a call/type qualifier names THIS engine's trusted system
	// schema, so a call under it is a system builtin rather than user code. Engine-specific, and the
	// reason it cannot be a name comparison at the call site: `pg_catalog` is a PostgreSQL schema, so a
	// MySQL database literally named `pg_catalog` is ordinary user code and never trusted.
	IsTrustedSystemQualifier(qualifier exp.Expression) bool
	// RewriteStatement optionally rewrites a parsed statement into the SQL the proxy should relay to the
	// target DB, returning "" to leave it unchanged.
	RewriteStatement(root exp.Expression) string
	// PrepareStatement runs before classification on the single parsed statement: an engine that binds
	// request parameters into the tree, or resolves a server-side prepared statement into its body, does it
	// here. It returns the statement to analyze, whether the proxy must submit regenerated text, and either
	// an error (fail closed) or facts that end the analysis (a request for more input).
	PrepareStatement(root exp.Expression) (prepared exp.Expression, regenerate bool, stop *pb.StatementFacts, err error)
	// FinishSubmission runs after a resolved analysis on the tree the proxy will submit (the lineage rewrite
	// re-parsed, or the prepared original) and may edit it (a row cap); true means the text must be
	// regenerated.
	FinishSubmission(submission exp.Expression) bool
	// StampSubmission records on facts what the proxy needs beside the regenerated text (Athena: the
	// execution-parameter list that goes with it). Called only when the text was regenerated.
	StampSubmission(facts *pb.StatementFacts)
	// CommandPassthrough reports whether a statement that DEGRADED to an unstructured Command (the
	// structured node forms never reach it) may relay as a benign session/metadata passthrough for
	// this engine. False = fail closed.
	CommandPassthrough(command string) bool
	// ShowUtilityCommand names the utility grant a SHOW form requires ("" for none), so an engine can
	// classify a data-bearing SHOW (e.g. SHOW PARTITIONS) as a result read.
	ShowUtilityCommand(root exp.Expression) string
	// RejectsDuplicateDerivedOutputLabels reports whether this engine's target DB rejects a derived-table
	// or CTE body whose output labels collide (MySQL ER_DUP_FIELDNAME; PostgreSQL allows duplicate
	// OUTPUT labels and rejects only a reference to one).
	RejectsDuplicateDerivedOutputLabels() bool
	// RightJoinStarOrder is how this engine's target DB orders a NATURAL/USING RIGHT JOIN's star
	// expansion. A plain ON right join is written order on both engines.
	RightJoinStarOrder() starOrder
	// IsSafeTypeReference: a type sqlglot marked user-defined that is trusted anyway (`'1'::xid` when
	// it must be pg_catalog.xid). False keeps the user-type fail-close.
	IsSafeTypeReference(dt, kind exp.Expression, namespace NamespaceConfig) bool
	// SystemSchemaFirst: an unqualified name resolves in the system schema first (PostgreSQL: pg_catalog
	// precedes every user schema on searchPath, pg_temp aside; MySQL: never).
	SystemSchemaFirst(searchPath []string) bool
	// NativeOutputLabel computes the output label THIS engine's target DB natively assigns to an
	// unaliased projection: PostgreSQL derives it from the resolved expression (parse_target.c
	// FigureColname, written function names from the parse-time SpanText); MySQL uses the
	// projection's verbatim source spelling (SpanText). query is the SELECT the projection belongs
	// to, for resolving references to its derived sources. ok=false means the label is unknowable —
	// the caller leaves Qualify's synthetic name.
	NativeOutputLabel(projection, query exp.Expression) (string, bool)
	// DiagnosticLeakKeys is the column keys this statement's target-DB error/warning diagnostic could echo
	// — engine-specific, since what a diagnostic contains is (MySQL echoes the operated value; PostgreSQL
	// also dumps a failed write's whole row via `DETAIL: Failing row contains (…)`). Start from
	// referencedColumnKeys (the shared template) and add engine channels on top.
	DiagnosticLeakKeys(report ProbeResult, qualifySchema schema.Schema) map[string]bool
}

// referencedColumnKeys is the shared diagnostic-leak template: every column the statement references —
// what any engine's diagnostic message can echo (`Truncated incorrect INTEGER value: '010-1234-5678'`).
func referencedColumnKeys(report ProbeResult) map[string]bool {
	keys := map[string]bool{}
	for _, origin := range report.Origins {
		for _, key := range origin.Origins {
			keys[key] = true
		}
	}
	for _, refs := range report.References {
		for _, key := range refs {
			keys[key] = true
		}
	}
	return keys
}

// createAnalyzer builds the analyzer for config, validating its engine-specific settings (MySQL's
// required version + lower_case_table_names) fail-closed. config is the exact EngineConfig the
// control-plane forwarded from what the proxy reported at introspection time — createAnalyzer does not
// re-derive or clean any of it, only validates and builds the sqlglot-go Dialect(s) it implies.
func createAnalyzer(config *pb.EngineConfig) (analyzer, error) {
	if config == nil {
		return nil, fmt.Errorf("engine config is required")
	}
	switch config.GetEngine() {
	case pb.Engine_MYSQL:
		return newMySQLAnalyzer(config)
	case pb.Engine_POSTGRES:
		return newPostgresAnalyzer(config)
	case pb.Engine_ATHENA:
		return newAthenaAnalyzer(config)
	default:
		return nil, fmt.Errorf("unsupported engine %s", config.GetEngine())
	}
}
