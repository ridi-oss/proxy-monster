package engines

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

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

// analyzer makes every engine-specific analysis decision for one statement, built per Probe call from the
// caller's EngineConfig — everything it needs (server version, MySQL's lower_case_table_names, the
// sqlglot-go Dialect built from them) is captured at construction, so nothing downstream re-derives
// it from a namespace or re-parses it from a bare wire-name string.
type analyzer interface {
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
	e, ok := ByProto(config.GetEngine())
	if !ok {
		return nil, fmt.Errorf("unsupported engine %s", config.GetEngine())
	}
	return e.newAnalyzer(e, config)
}

// TODO: split mysqlAnalyzer and postgresAnalyzer into analyzer_mysql.go / analyzer_postgres.go — this file should
// hold only the shared interface + createAnalyzer factory; the two impls share nothing but that interface.
type mysqlAnalyzer struct {
	dialect *dialects.Dialect
}

func newMySQLAnalyzer(e *Engine, config *pb.EngineConfig) (analyzer, error) {
	if config.MysqlLowerCaseTableNames == nil {
		return nil, fmt.Errorf("mysqlLowerCaseTableNames is required for mysql")
	}
	mode, err := ReportedCaseMode(int(config.GetMysqlLowerCaseTableNames()))
	if err != nil {
		return nil, err
	}
	versionID := mysqlVersionID(config.GetEngineVersion())
	if versionID <= 0 {
		return nil, fmt.Errorf("engine version is required for mysql")
	}
	// Build one Dialect that serves parse, qualify, and generate alike. The normalization strategy (from
	// lower_case_table_names) and MySQLVersion (gates executable-comment support) compose with a
	// conditional mysql_ansi_quotes into a single settings string resolved by GetOrRaise. ansi_quotes MUST
	// go through settings resolution rather than a direct field-set: it rewrites the tokenizer config
	// (applyMySQLAnsiQuotes — `"` becomes a quoted-identifier delimiter, not a string), which only runs at
	// resolution time. When the target DB's live sql_mode carries ANSI_QUOTES, the analyzer then reads a
	// masked column quoted with `"` as the real column and still masks it (instead of the proxy having to
	// fail the connection closed). e.Dialect only ever sets the strategy, so its
	// SettingsString round-trips losslessly as the base.
	settings := e.Dialect(mode).SettingsString() +
		fmt.Sprintf(", mysql_version=%d, opaque_functions=true", versionID)
	if config.GetSession().GetMysql().GetAnsiQuotes() {
		settings += ", mysql_ansi_quotes=true"
	}
	dialect, err := dialects.GetOrRaise(settings)
	if err != nil {
		return nil, fmt.Errorf("build mysql dialect: %w", err)
	}
	return &mysqlAnalyzer{dialect: dialect}, nil
}

func (e *mysqlAnalyzer) PrepareStatement(root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
	return root, false, nil, nil
}
func (e *mysqlAnalyzer) FinishSubmission(exp.Expression) bool { return false }
func (e *mysqlAnalyzer) StampSubmission(*pb.StatementFacts)   {}
func (e *mysqlAnalyzer) Dialect() *dialects.Dialect           { return e.dialect }

// MySQL's catalog needs build-time folding: columns are always case-insensitive, while relation
// spelling follows lower_case_table_names and the information_schema exception.
func (e *mysqlAnalyzer) NormalizeCatalogOnBuild() bool   { return true }
func (e *mysqlAnalyzer) AllowsCrossCatalog() bool        { return false }
func (e *mysqlAnalyzer) PreservesCatalogQualifier() bool { return false }

func (e *mysqlAnalyzer) ConfigureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig) {
	opts.SearchPath = namespace.SearchPath
}

func (e *mysqlAnalyzer) BuiltinFunctionRow(string) []string { return nil }
func (e *mysqlAnalyzer) BareCallIsBuiltin(string) bool      { return false }
func (e *mysqlAnalyzer) PostgresSystemXIDVisible() bool     { return false }

func (e *mysqlAnalyzer) FoldColumn(column string) string {
	return e.dialect.FoldIdentifierName(column, false)
}

// MySQL has no temp-schema convention — temporary tables are marked by the TEMPORARY keyword (a
// temporary arg / TemporaryProperty on the DDL), which isTemporaryDDL detects directly off the tree.
func (e *mysqlAnalyzer) IsTempSchema(exp.Expression) bool { return false }

// MySQL has no trusted system-schema qualifier: its system databases (mysql, information_schema,
// performance_schema, sys) are access-controlled resources the system-classification manifest covers,
// not a blanket pass for calls made under them.
func (e *mysqlAnalyzer) IsTrustedSystemQualifier(exp.Expression) bool { return false }

// MySQL labels an unaliased computed projection with its verbatim source text (`1 +    1` keeps
// its exact spacing; verified against MySQL 8.0), truncated to 255 runes as the server does for
// implicit labels. Fails closed on an unstamped node (only parse-time projections carry text).
func (e *mysqlAnalyzer) NativeOutputLabel(projection, _ exp.Expression) (string, bool) {
	text, ok := projection.SpanText()
	if !ok {
		return "", false
	}
	if runes := []rune(text); len(runes) > 255 {
		text = string(runes[:255])
	}
	return text, true
}

// RewriteStatement pins a single, session-scoped `SET character_set_results = NULL` — the default MySQL
// Connector/J (and so DBeaver) session-init, which asks the target DB to return each column in its own charset
// for client-side decoding — to utf8mb4, so the wire masker keeps decoding results as UTF-8. Only that exact
// form is rewritten; a compound SET, GLOBAL/PERSIST scope, a same-named user variable, a qualified or
// bogus-scoped target, or any non-NULL value is left untouched (and still fails closed at the wire session
// invariant). Recognition is on the parsed AST, so every spelling MySQL accepts reduces to the same check.
func (e *mysqlAnalyzer) RewriteStatement(root exp.Expression) string {
	if root.Kind() != exp.KindSet {
		return ""
	}
	// setUtilityCommands is non-empty for GLOBAL/PERSIST/PERSIST_ONLY/PASSWORD; a single session assignment
	// carries exactly one SetItem and no utility command.
	items := root.FindAll(exp.KindSetItem)
	if len(items) != 1 || len(setUtilityCommands(root)) != 0 {
		return ""
	}
	eq := items[0].This()
	if eq == nil || eq.Kind() != exp.KindEQ || eq.Left() == nil || eq.Right() == nil {
		return ""
	}
	// The target must be the SYSTEM variable, not a same-named user variable or a qualified column. A bare
	// `character_set_results` parses to an unqualified Column; `@@[session.]character_set_results` to a
	// SessionParameter; but `@character_set_results` (a user variable) parses to a Parameter whose Name()
	// still returns "character_set_results", and `x.character_set_results` to a qualified Column — both would
	// otherwise be turned into a system-variable SET the client never asked for.
	left := eq.Left()
	switch left.Kind() {
	case exp.KindColumn:
		if left.TableName() != "" {
			return ""
		}
	case exp.KindSessionParameter:
		// `@@[session.|local.]character_set_results` is this session's variable; `@@global.` is excluded by
		// setUtilityCommands above, but a bogus scope (`@@nonsense.…`) reaches here — MySQL would reject it,
		// so it must not normalize into a successful pin.
		switch strings.ToLower(fmt.Sprint(left.Arg("kind"))) {
		case "<nil>", "", "session", "local":
		default:
			return ""
		}
	default:
		return ""
	}
	// A system-variable name is ASCII and case-insensitive — MySQL matches it independent of
	// lower_case_table_names — so it is compared case-folded, not through the dialect's schema-identifier
	// folding (which is for table/column names). utf8mb4 is full Unicode, so the pin is lossless.
	if !strings.EqualFold(left.Name(), "character_set_results") {
		return ""
	}
	if eq.Right().Kind() != exp.KindNull {
		return ""
	}
	return "SET character_set_results = utf8mb4"
}

// MySQL diagnostics echo only the operated value (`Truncated incorrect INTEGER value: '010-…'`) —
// always an already-referenced column — and never dump unreferenced ones, so the template is the whole set.
func (e *mysqlAnalyzer) DiagnosticLeakKeys(report ProbeResult, _ schema.Schema) map[string]bool {
	return referencedColumnKeys(report)
}

// A statement that degrades to an unstructured Command is one the analyzer cannot vouch for on
// MySQL (an unrecognized SHOW carries data; RESET MASTER/REPLICA is a privileged admin op).
func (e *mysqlAnalyzer) CommandPassthrough(string) bool { return false }
func (e *mysqlAnalyzer) ShowUtilityCommand(root exp.Expression) string {
	return showUtilityCommand(root)
}

// MySQL rejects a derived-table/CTE body with duplicated output labels: ER_DUP_FIELDNAME.
func (e *mysqlAnalyzer) RejectsDuplicateDerivedOutputLabels() bool { return true }

func (e *mysqlAnalyzer) RightJoinStarOrder() starOrder { return starOrderCommonRightLeft }

// MySQL has no search path; a bare name never resolves in a system schema.
func (e *mysqlAnalyzer) SystemSchemaFirst([]string) bool { return false }

func (e *mysqlAnalyzer) IsSafeTypeReference(exp.Expression, exp.Expression, NamespaceConfig) bool {
	return false
}

type postgresAnalyzer struct {
	dialect                   *dialects.Dialect
	shadowedFunctions         map[string]bool
	functionShadowingObserved bool
	systemXIDVisible          bool
}

func postgresOpaqueDialect(e *Engine) *dialects.Dialect {
	d, err := dialects.GetOrRaise(e.Dialect(CaseMode{}).SettingsString() + ", opaque_functions=true")
	if err != nil {
		panic(err)
	}
	return d
}

func newPostgresAnalyzer(e *Engine, config *pb.EngineConfig) (analyzer, error) {
	session := config.GetSession().GetPostgres()
	if !session.GetFunctionShadowingObserved() && len(session.GetShadowedFunctions()) != 0 {
		return nil, fmt.Errorf("shadowedFunctions requires an observed function-shadowing context")
	}
	shadowed := make(map[string]bool, len(session.GetShadowedFunctions()))
	for _, name := range session.GetShadowedFunctions() {
		if name == "" {
			return nil, fmt.Errorf("shadowedFunctions contains invalid function name %q", name)
		}
		if shadowed[name] {
			return nil, fmt.Errorf("shadowedFunctions contains duplicate function name %q", name)
		}
		shadowed[name] = true
	}
	return &postgresAnalyzer{
		dialect:                   postgresOpaqueDialect(e),
		shadowedFunctions:         shadowed,
		functionShadowingObserved: session.GetFunctionShadowingObserved(),
		systemXIDVisible:          session.GetSystemXidVisible(),
	}, nil
}

func (e *postgresAnalyzer) PrepareStatement(root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
	return root, false, nil, nil
}
func (e *postgresAnalyzer) FinishSubmission(exp.Expression) bool { return false }
func (e *postgresAnalyzer) StampSubmission(*pb.StatementFacts)   {}
func (e *postgresAnalyzer) Dialect() *dialects.Dialect           { return e.dialect }

// PostgreSQL does not fold the introspected catalog: quoted and unquoted names can identify distinct
// real columns, while query-side qualification already preserves quoted names and folds unquoted ones.
func (e *postgresAnalyzer) NormalizeCatalogOnBuild() bool   { return false }
func (e *postgresAnalyzer) AllowsCrossCatalog() bool        { return false }
func (e *postgresAnalyzer) PreservesCatalogQualifier() bool { return false }

func (e *postgresAnalyzer) ConfigureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig) {
	opts.SearchPath = namespace.SearchPath
}

func (e *postgresAnalyzer) BuiltinFunctionRow(name string) []string {
	switch name {
	case "pg_available_extension_versions":
		return []string{"name", "version", "superuser", "trusted", "relocatable", "schema", "requires", "comment"}
	case "unnest":
		return []string{"unnest"}
	default:
		return nil
	}
}

// A zero-argument builtin has one signature, so the earliest schema wins and pg_catalog first settles
// it. unnest is polymorphic: trusted only when the session's namespace probe ran and listed no user unnest.
func (e *postgresAnalyzer) BareCallIsBuiltin(name string) bool {
	if name != "unnest" {
		return true
	}
	return e.functionShadowingObserved && !e.shadowedFunctions[name]
}

func (e *postgresAnalyzer) PostgresSystemXIDVisible() bool { return e.systemXIDVisible }

func (e *postgresAnalyzer) FoldColumn(column string) string { return column }

// A DDL target in pg_temp (or a numbered pg_temp_<n>) is session-local, not catalog-changing; a quoted
// "PG_TEMP" is a distinct user schema.
func (e *postgresAnalyzer) IsTempSchema(schema exp.Expression) bool {
	if schema == nil {
		return false
	}
	return Postgres.IsTempSchema(Postgres.ParsedSchema(CaseMode{}, schema))
}

// pg_catalog is PostgreSQL's system schema: a call qualified by it is a builtin, so it carries no
// unclassified Function grant. Only a single bare identifier qualifies — a quoted "PG_CATALOG" keeps its
// case and is a DISTINCT user schema PostgreSQL's case-sensitive `pg_` reservation allows to exist, so a
// user function there must not inherit a builtin's pass.
func (e *postgresAnalyzer) IsTrustedSystemQualifier(qualifier exp.Expression) bool {
	if qualifier == nil || qualifier.Kind() != exp.KindIdentifier {
		return false
	}
	return Postgres.ParsedSchema(CaseMode{}, qualifier) == Postgres.BuiltinSchema
}

// PostgreSQL has no relay rewrite: client_encoding is handled on the wire, not by an analyzer rewrite,
// so there is nothing to rewrite here.
func (e *postgresAnalyzer) RewriteStatement(exp.Expression) string { return "" }

// A statement that degrades to an unstructured Command on PostgreSQL can only be a benign
// session/config form: RESET restores defaults (de-escalation), an unmodeled SHOW is a read-only
// GUC read (no table data). Everything else stays fail-closed at the caller.
func (e *postgresAnalyzer) CommandPassthrough(command string) bool {
	return command == "RESET" || command == "SHOW"
}
func (e *postgresAnalyzer) ShowUtilityCommand(root exp.Expression) string {
	return showUtilityCommand(root)
}

// PostgreSQL allows duplicate OUTPUT labels; only a reference to one is ambiguous.
func (e *postgresAnalyzer) RejectsDuplicateDerivedOutputLabels() bool { return false }

func (e *postgresAnalyzer) RightJoinStarOrder() starOrder { return starOrderCommonLeftRight }

func (e *postgresAnalyzer) SystemSchemaFirst(searchPath []string) bool {
	return postgresCatalogFirstAfterTempSchemas(searchPath)
}

func (e *postgresAnalyzer) IsSafeTypeReference(dt, kind exp.Expression, namespace NamespaceConfig) bool {
	return e.isSafeXIDType(dt, kind, namespace)
}

// `'1'::pg_catalog.xid` is safe. Bare `'1'::xid` is safe only when pg_catalog is first on search_path
// (after pg_temp) and the proxy saw pg_catalog.xid visible, so no user type can shadow it. `xid(4)` never.
func (e *postgresAnalyzer) isSafeXIDType(dt, kind exp.Expression, namespace NamespaceConfig) bool {
	if kind == nil || len(dt.Expressions()) != 0 {
		return false
	}
	leaf := kind
	var qualifier exp.Expression
	if kind.Kind() == exp.KindDot {
		qualifier = kind.Left()
		leaf = kind.Right()
	} else if kind.Kind() != exp.KindIdentifier {
		return false
	}
	if leaf == nil || leaf.Kind() != exp.KindIdentifier {
		return false
	}
	folded := leaf.Copy()
	e.dialect.NormalizeIdentifier(folded)
	if folded.Name() != "xid" {
		return false
	}
	if qualifier != nil {
		return e.IsTrustedSystemQualifier(qualifier)
	}
	return e.PostgresSystemXIDVisible() && postgresCatalogFirstAfterTempSchemas(namespace.SearchPath)
}

// PostgreSQL names an unaliased projection per parse_target.c FigureColname; a call is labeled by
// its WRITTEN function name, read from the projection's parse-time SpanText.
func (e *postgresAnalyzer) NativeOutputLabel(projection, query exp.Expression) (string, bool) {
	return nativeOutputLabel(projection, query, e, 0)
}

// PostgreSQL adds a failed write's WHOLE target row to the template: `INSERT INTO users (id) …` can fail
// with `DETAIL: Failing row contains (1, 010-1234-5678, …)` — columns the statement never named. If the
// row cannot be enumerated, an unresolvable sentinel key emits so the control-plane fails closed.
func (e *postgresAnalyzer) DiagnosticLeakKeys(report ProbeResult, qualifySchema schema.Schema) map[string]bool {
	keys := referencedColumnKeys(report)
	if !report.IsWrite || report.WriteTarget == nil {
		return keys
	}
	id := report.WriteTarget
	// Quoted identifiers + normalize=false, matching how the prober enumerates a physical table.
	table := exp.Table(exp.Args{
		"this":    exp.ToIdentifier(id.table, true),
		"schema":  exp.ToIdentifier(id.schema, true),
		"catalog": exp.ToIdentifier(id.catalog, true),
	})
	// onlyVisible: "Failing row contains (...)" never lists ctid or xmin.
	cols, err := qualifySchema.ColumnNames(table, true, e.dialect, boolPtr(false))
	if err != nil || len(cols) == 0 {
		// Can't enumerate the row → emit a column no catalog resolves, so the control-plane fails closed.
		keys[id.String()+".*"] = true
		return keys
	}
	for _, col := range cols {
		keys[id.String()+"."+col] = true
	}
	return keys
}

var mysqlVersionPattern = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?`)

// mysqlVersionID converts a clean MySQL version string (e.g. "8.0.46" or the patch-less "8.0") to
// its MYSQL_VERSION_ID-style integer (major*10000 + minor*100 + patch, e.g. 80046). Zero means the
// value is not a recognizable major.minor[.patch] string. The match is a prefix match, not anchored
// at the end, so it also extracts cleanly from a raw, undecorated server-reported string (MySQL's
// "8.0.46-log", or an Aurora-suffixed "8.0.46 (aurora 3.04.0)") without the caller needing to clean
// it first.
func mysqlVersionID(version string) int {
	m := mysqlVersionPattern.FindStringSubmatch(version)
	if m == nil {
		return 0
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch := 0
	if m[3] != "" {
		patch, _ = strconv.Atoi(m[3])
	}
	return major*10000 + minor*100 + patch
}
