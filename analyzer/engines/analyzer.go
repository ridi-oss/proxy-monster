package engines

import (
	"fmt"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/optimizer"
	"github.com/ridi-oss/sqlglot-go/schema"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// session makes every engine-specific analysis decision that depends on the statement or the session, built per
// Probe call from the caller's EngineConfig.
type session interface {
	// Datasource is the engine as this datasource spells names.
	Datasource() Datasource
	// Dialect is the datasource's dialect with what the session observed (MySQL ansi_quotes), used to parse,
	// qualify and generate alike.
	Dialect() *dialects.Dialect
	// BareCallIsBuiltin: is a bare call (`unnest(...)`, no schema) guaranteed to be the
	// pg_catalog builtin? PostgreSQL picks a function across every search_path schema by argument
	// type, so a user `public.unnest(int[])` beats `pg_catalog.unnest(anyarray)` for an int[] argument
	// even with pg_catalog first. false = fail closed, the row stays unknown.
	BareCallIsBuiltin(name string) bool
	// ConfigureNamespace maps the session's namespace onto the qualifier's resolution options: a search
	// path for engines that have one, a fixed catalog and default schema for engines that do not.
	ConfigureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig)
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
	// ShowUtilityCommand names the utility grant a SHOW form requires ("" for none), so an engine can
	// classify a data-bearing SHOW (e.g. SHOW PARTITIONS) as a result read.
	ShowUtilityCommand(root exp.Expression) string
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

// openSession builds the analyzer for config, failing closed on a datasource or session the engine cannot
// use (MySQL without its version or lower_case_table_names).
func openSession(config *pb.EngineConfig) (session, error) {
	if config == nil {
		return nil, fmt.Errorf("engine config is required")
	}
	e, ok := ByProto(config.GetEngine())
	if !ok {
		return nil, fmt.Errorf("unsupported engine %s", config.GetEngine())
	}
	ds, err := e.Datasource(config.GetDatasource())
	if err != nil {
		return nil, err
	}
	return e.newSession(ds, config.GetSession())
}
