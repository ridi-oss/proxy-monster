package probe

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/schema"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// engine owns every engine-specific analysis decision, built once per Probe call from the caller's
// EngineConfig — everything an engine needs (server version, MySQL's lower_case_table_names, the
// sqlglot-go Dialect built from them) is captured at construction, so nothing downstream re-derives
// it from a namespace or re-parses it from a bare wire-name string.
type engine interface {
	// WireName is the canonical lowercase sqlglot-go dialect name ("mysql" | "postgres").
	WireName() string
	// Dialect is the single *dialects.Dialect built once from this engine's config — reused for
	// parsing, catalog normalization, Qualify, and SQL generation alike (sqlglot-go accepts a
	// *Dialect directly everywhere a dialect argument is taken, MySQLVersion included, so there is
	// no separate parse-only string form to keep in sync with this one).
	Dialect() *dialects.Dialect
	NormalizeCatalogOnBuild() bool
	ImplicitNonVisibleColumns() []string
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
	// FinalizeStatementIdentity is the engine's post-classification pass over a resolved statement:
	// it may pin identities the target DB would otherwise resolve live (mutating facts.RewrittenSql)
	// or overwrite facts with a fail-closed denial when an identity cannot be pinned. root is the
	// folded statement, sql the client's original text. Runs once per statement, after the kind
	// switch in EmitFacts.
	FinalizeStatementIdentity(root exp.Expression, sql string, facts *pb.StatementFacts, namespace NamespaceConfig) *pb.StatementFacts
	// IsSafeNoFromFunction reports whether a bare (unqualified) anonymous function name is a
	// known-safe builtin that needs no no-FROM Function grant — the cross-engine set plus this
	// engine's own pseudo-functions.
	IsSafeNoFromFunction(name string) bool
	// IsTrustedInformationSchemaCall reports whether a schema-qualified call is one of this engine's
	// trusted information_schema helper builtins, needing no Function grant.
	IsTrustedInformationSchemaCall(qualifier exp.Expression, leaf string) bool
	// CommandPassthrough reports whether a statement that DEGRADED to an unstructured Command (the
	// structured node forms never reach it) may relay as a benign session/metadata passthrough for
	// this engine. False = fail closed.
	CommandPassthrough(command string) bool
	// RejectsDuplicateDerivedLabels reports whether this engine's target DB rejects a derived-table
	// or CTE body whose output labels collide (MySQL ER_DUP_FIELDNAME; PostgreSQL allows duplicate
	// OUTPUT labels and rejects only a reference to one).
	RejectsDuplicateDerivedLabels() bool
	// ExpandsNaturalJoins reports whether the prober expands NATURAL JOIN through this engine's
	// catalog-backed USING semantics; false fails closed (shared-column lineage stays ambiguous).
	ExpandsNaturalJoins() bool
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

// createEngine builds the engine for config, validating its engine-specific settings (MySQL's
// required version + lower_case_table_names) fail-closed. config is the exact EngineConfig the
// control-plane forwarded from what the proxy reported at introspection time — createEngine does not
// re-derive or clean any of it, only validates and builds the sqlglot-go Dialect(s) it implies.
func createEngine(config *pb.EngineConfig) (engine, error) {
	if config == nil {
		return nil, fmt.Errorf("engine config is required")
	}
	switch config.GetEngine() {
	case pb.Engine_MYSQL:
		return newMySQLEngine(config)
	case pb.Engine_POSTGRES:
		return newPostgresEngine(config)
	default:
		return nil, fmt.Errorf("unsupported engine %s", config.GetEngine())
	}
}

// TODO: split mysqlEngine and postgresEngine into engine_mysql.go / engine_postgres.go — this file should
// hold only the shared interface + createEngine factory; the two impls share nothing but that interface.
type mysqlEngine struct {
	dialect *dialects.Dialect
}

func newMySQLEngine(config *pb.EngineConfig) (*mysqlEngine, error) {
	if len(config.GetPostgresShadowedFunctions()) != 0 || config.GetPostgresFunctionShadowingObserved() {
		return nil, fmt.Errorf("postgres function shadowing context is not valid for mysql")
	}
	if config.PostgresSystemXidVisible != nil {
		return nil, fmt.Errorf("postgres type visibility context is not valid for mysql")
	}
	if config.MysqlLowerCaseTableNames == nil {
		return nil, fmt.Errorf("mysqlLowerCaseTableNames is required for mysql")
	}
	lowerCaseTableNames := int(config.GetMysqlLowerCaseTableNames())
	if lowerCaseTableNames < 0 || lowerCaseTableNames > 2 {
		return nil, fmt.Errorf("mysqlLowerCaseTableNames must be 0, 1, or 2")
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
	// fail the connection closed). mysqlNormalizationDialect only ever sets the strategy, so its
	// SettingsString round-trips losslessly as the base.
	settings := mysqlNormalizationDialect(lowerCaseTableNames).SettingsString() +
		fmt.Sprintf(", mysql_version=%d", versionID)
	if config.GetMysqlAnsiQuotes() {
		settings += ", mysql_ansi_quotes=true"
	}
	dialect, err := dialects.GetOrRaise(settings)
	if err != nil {
		return nil, fmt.Errorf("build mysql dialect: %w", err)
	}
	return &mysqlEngine{dialect: dialect}, nil
}

func (e *mysqlEngine) WireName() string           { return "mysql" }
func (e *mysqlEngine) Dialect() *dialects.Dialect { return e.dialect }

// MySQL's catalog needs build-time folding: columns are always case-insensitive, while relation
// spelling follows lower_case_table_names and the information_schema exception.
func (e *mysqlEngine) NormalizeCatalogOnBuild() bool { return true }

func (e *mysqlEngine) ImplicitNonVisibleColumns() []string { return nil }

func (e *mysqlEngine) FoldColumn(column string) string {
	return e.dialect.FoldIdentifierName(column, false)
}

// MySQL has no temp-schema convention — temporary tables are marked by the TEMPORARY keyword (a
// temporary arg / TemporaryProperty on the DDL), which isTemporaryDDL detects directly off the tree.
func (e *mysqlEngine) IsTempSchema(exp.Expression) bool { return false }

// MySQL has no trusted system-schema qualifier: its system databases (mysql, information_schema,
// performance_schema, sys) are access-controlled resources the system-classification manifest covers,
// not a blanket pass for calls made under them.
func (e *mysqlEngine) IsTrustedSystemQualifier(exp.Expression) bool { return false }

// MySQL labels an unaliased computed projection with its verbatim source text (`1 +    1` keeps
// its exact spacing; verified against MySQL 8.0), truncated to 255 runes as the server does for
// implicit labels. Fails closed on an unstamped node (only parse-time projections carry text).
func (e *mysqlEngine) NativeOutputLabel(projection, _ exp.Expression) (string, bool) {
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
func (e *mysqlEngine) RewriteStatement(root exp.Expression) string {
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
func (e *mysqlEngine) DiagnosticLeakKeys(report ProbeResult, _ schema.Schema) map[string]bool {
	return referencedColumnKeys(report)
}

// MySQL resolves statement identities at parse time against a fixed namespace — nothing to pin.
func (e *mysqlEngine) FinalizeStatementIdentity(_ exp.Expression, _ string, facts *pb.StatementFacts, _ NamespaceConfig) *pb.StatementFacts {
	return facts
}

// `values` is MySQL's INSERT … ON DUPLICATE KEY UPDATE pseudo-function — it names the value that
// would have been inserted, not a callable function; its lineage is traced in probe.go.
func (e *mysqlEngine) IsSafeNoFromFunction(name string) bool {
	return safeNoFromFunctions[name] || name == "values"
}

// MySQL's information_schema holds tables only — a function call qualified by it is user code.
func (e *mysqlEngine) IsTrustedInformationSchemaCall(exp.Expression, string) bool { return false }

// A statement that degrades to an unstructured Command is one the analyzer cannot vouch for on
// MySQL (an unrecognized SHOW carries data; RESET MASTER/REPLICA is a privileged admin op).
func (e *mysqlEngine) CommandPassthrough(string) bool { return false }

// MySQL rejects a derived-table/CTE body with duplicated output labels: ER_DUP_FIELDNAME.
func (e *mysqlEngine) RejectsDuplicateDerivedLabels() bool { return true }

func (e *mysqlEngine) ExpandsNaturalJoins() bool { return false }

type postgresEngine struct {
	dialect                   *dialects.Dialect
	shadowedFunctions         map[string]bool
	functionShadowingObserved bool
	systemXIDVisible          bool
}

func newPostgresEngine(config *pb.EngineConfig) (*postgresEngine, error) {
	if !config.GetPostgresFunctionShadowingObserved() && len(config.GetPostgresShadowedFunctions()) != 0 {
		return nil, fmt.Errorf("postgresShadowedFunctions requires an observed function-shadowing context")
	}
	shadowed := make(map[string]bool, len(config.GetPostgresShadowedFunctions()))
	for _, name := range config.GetPostgresShadowedFunctions() {
		if name == "" || name != strings.ToLower(name) {
			return nil, fmt.Errorf("postgresShadowedFunctions contains invalid function name %q", name)
		}
		if shadowed[name] {
			return nil, fmt.Errorf("postgresShadowedFunctions contains duplicate function name %q", name)
		}
		shadowed[name] = true
	}
	return &postgresEngine{
		dialect:                   dialects.Postgres(),
		shadowedFunctions:         shadowed,
		functionShadowingObserved: config.GetPostgresFunctionShadowingObserved(),
		systemXIDVisible:          config.GetPostgresSystemXidVisible(),
	}, nil
}

func (e *postgresEngine) WireName() string           { return "postgres" }
func (e *postgresEngine) Dialect() *dialects.Dialect { return e.dialect }

// PostgreSQL does not fold the introspected catalog: quoted and unquoted names can identify distinct
// real columns, while query-side qualification already preserves quoted names and folds unquoted ones.
func (e *postgresEngine) NormalizeCatalogOnBuild() bool { return false }

func (e *postgresEngine) ImplicitNonVisibleColumns() []string {
	return []string{"tableoid", "xmin", "cmin", "xmax", "cmax", "ctid"}
}

func (e *postgresEngine) FoldColumn(column string) string { return column }

// PostgreSQL places session-temporary objects in pg_temp (a per-backend alias for the numbered
// pg_temp_<n> temp schema), so a DDL target there is session-local, not catalog-changing. Read off the
// already-folded spelling (EmitFacts normalizes the statement's identifiers up front, quote-aware), so
// an unquoted pg_temp/PG_TEMP matches while a quoted "PG_TEMP" — a distinct case-sensitive user schema —
// does not. A raw strings.ToLower here would wrongly conflate the two and mis-fold non-ASCII.
func (e *postgresEngine) IsTempSchema(schema exp.Expression) bool {
	if schema == nil {
		return false
	}
	name := schema.Name()
	return name == "pg_temp" || strings.HasPrefix(name, "pg_temp_")
}

// pg_catalog is PostgreSQL's system schema: a call qualified by it is a builtin, so it carries no
// unclassified Function grant. Only a single bare identifier qualifies — a quoted "PG_CATALOG" keeps its
// case and is a DISTINCT user schema PostgreSQL's case-sensitive `pg_` reservation allows to exist, so a
// user function there must not inherit a builtin's pass.
func (e *postgresEngine) IsTrustedSystemQualifier(qualifier exp.Expression) bool {
	if qualifier == nil || qualifier.Kind() != exp.KindIdentifier {
		return false
	}
	return qualifier.Name() == "pg_catalog"
}

// PostgreSQL has no relay rewrite: client_encoding is handled on the wire, not by an analyzer rewrite,
// so there is nothing to rewrite here.
func (e *postgresEngine) RewriteStatement(exp.Expression) string { return "" }

// PostgreSQL resolves object identities live (search_path, type/function visibility), so a fresh
// statement needs no pinning yet — later work pins trusted resolutions here.
func (e *postgresEngine) FinalizeStatementIdentity(_ exp.Expression, _ string, facts *pb.StatementFacts, _ NamespaceConfig) *pb.StatementFacts {
	return facts
}

func (e *postgresEngine) IsSafeNoFromFunction(name string) bool { return safeNoFromFunctions[name] }

// postgresInformationSchemaFunctions are PostgreSQL's information_schema helper builtins — stable,
// read-only transforms of their arguments (pgJDBC metadata queries call them). Safe ONLY under an
// explicit `information_schema.` qualifier; the unqualified spelling stays gated so a same-named
// user function cannot inherit the pass.
var postgresInformationSchemaFunctions = stringSet(
	"_pg_char_max_length", "_pg_char_octet_length", "_pg_datetime_precision", "_pg_expandarray",
	"_pg_index_position", "_pg_interval_type", "_pg_numeric_precision", "_pg_numeric_precision_radix",
	"_pg_numeric_scale", "_pg_truetypid", "_pg_truetypmod",
)

func (e *postgresEngine) IsTrustedInformationSchemaCall(qualifier exp.Expression, leaf string) bool {
	return qualifier != nil && qualifier.Kind() == exp.KindIdentifier &&
		qualifier.Name() == "information_schema" && postgresInformationSchemaFunctions[leaf]
}

// A statement that degrades to an unstructured Command on PostgreSQL can only be a benign
// session/config form: RESET restores defaults (de-escalation), an unmodeled SHOW is a read-only
// GUC read (no table data). Everything else stays fail-closed at the caller.
func (e *postgresEngine) CommandPassthrough(command string) bool {
	return command == "RESET" || command == "SHOW"
}

// PostgreSQL allows duplicate OUTPUT labels; only a reference to one is ambiguous.
func (e *postgresEngine) RejectsDuplicateDerivedLabels() bool { return false }

func (e *postgresEngine) ExpandsNaturalJoins() bool { return true }

// PostgreSQL names an unaliased projection per parse_target.c FigureColname; a call is labeled by
// its WRITTEN function name, read from the projection's parse-time SpanText.
func (e *postgresEngine) NativeOutputLabel(projection, query exp.Expression) (string, bool) {
	return nativeOutputLabel(projection, query, e, 0)
}

// PostgreSQL adds a failed write's WHOLE target row to the template: `INSERT INTO users (id) …` can fail
// with `DETAIL: Failing row contains (1, 010-1234-5678, …)` — columns the statement never named. If the
// row cannot be enumerated, an unresolvable sentinel key emits so the control-plane fails closed.
func (e *postgresEngine) DiagnosticLeakKeys(report ProbeResult, qualifySchema schema.Schema) map[string]bool {
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
	cols, err := qualifySchema.ColumnNames(table, false, e.dialect, boolPtr(false))
	if err != nil || len(cols) == 0 {
		// Can't enumerate the row → emit a column no catalog resolves, so the control-plane fails closed.
		keys[id.String()+".*"] = true
		return keys
	}
	// The qualify schema also lists the implicit system columns (ctid, xmin, …); a `Failing row
	// contains (…)` DETAIL echoes only the real row.
	implicit := map[string]bool{}
	for _, col := range e.ImplicitNonVisibleColumns() {
		implicit[col] = true
	}
	for _, col := range cols {
		if implicit[col] {
			continue
		}
		keys[id.String()+"."+col] = true
	}
	return keys
}

// mysqlNormalizationDialect returns a MySQL *Dialect configured with the identifier-normalization
// strategy for the server's lower_case_table_names. Under lctn=0 the server is case-sensitive for
// table/db names but STILL case-insensitive for columns, so the role-aware
// mysql_case_sensitive_table_names strategy folds every identifier except table/db names; under
// lctn=1/2 all identifiers are case-insensitive, so mysql_case_insensitive folds them all. Both fold
// with MySQL's exact utf8mb3_general_ci map (MySQLLower). sqlglot-go's mysql default is CASE_SENSITIVE
// (a no-op, for upstream faithfulness), so the strategy is set explicitly here. We pass the typed
// *Dialect straight to Qualify so its normalization and qualification passes share one configuration.
func mysqlNormalizationDialect(mysqlLowerCaseTableNames int) *dialects.Dialect {
	d := dialects.MySQL()
	if mysqlLowerCaseTableNames == 0 {
		d.NormalizationStrategy = dialects.MySQLCaseSensitiveTableNames
	} else {
		d.NormalizationStrategy = dialects.MySQLCaseInsensitive
	}
	return d
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
