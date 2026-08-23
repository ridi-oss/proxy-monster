package probe

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// engine owns every engine-specific analysis decision, built once per Probe call from the caller's
// EngineConfig — everything an engine needs (server version, MySQL's lower_case_table_names, the
// sqlglot-go Dialect built from them) is captured at construction, so nothing downstream re-derives
// it from a namespace or re-parses it from a bare wire-name string.
type engine interface {
	Type() pb.Engine
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
	// RewriteStatement optionally rewrites a parsed statement into the SQL the proxy should relay to the
	// target DB, returning "" to leave it unchanged.
	RewriteStatement(root exp.Expression) string
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

func (e *mysqlEngine) Type() pb.Engine            { return pb.Engine_MYSQL }
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

type postgresEngine struct {
	dialect *dialects.Dialect
}

func newPostgresEngine(*pb.EngineConfig) (*postgresEngine, error) {
	return &postgresEngine{dialect: dialects.Postgres()}, nil
}

func (e *postgresEngine) Type() pb.Engine            { return pb.Engine_POSTGRES }
func (e *postgresEngine) WireName() string           { return "postgres" }
func (e *postgresEngine) Dialect() *dialects.Dialect { return e.dialect }

// PostgreSQL does not fold the introspected catalog: quoted and unquoted names can identify distinct
// real columns, while query-side qualification already preserves quoted names and folds unquoted ones.
func (e *postgresEngine) NormalizeCatalogOnBuild() bool { return false }

func (e *postgresEngine) ImplicitNonVisibleColumns() []string { return []string{"ctid"} }

func (e *postgresEngine) FoldColumn(column string) string { return column }

// PostgreSQL places session-temporary objects in pg_temp (a per-backend alias for the numbered
// pg_temp_<n> temp schema), so a DDL target there is session-local, not catalog-changing. The schema
// identifier is folded through the dialect's NormalizeIdentifier — the same quote-aware normalization
// the analyzer applies to every other identifier — so an unquoted pg_temp/PG_TEMP matches (PostgreSQL
// lowercases unquoted identifiers) while a quoted "PG_TEMP", a distinct case-sensitive user schema,
// does not. A raw strings.ToLower would wrongly conflate the two and also mis-fold non-ASCII. A
// deep-copied node is folded so the shared parse tree is never mutated by this read-only check.
func (e *postgresEngine) IsTempSchema(schema exp.Expression) bool {
	if schema == nil {
		return false
	}
	id := schema.Copy()
	e.dialect.NormalizeIdentifier(id)
	name := id.Name()
	return name == "pg_temp" || strings.HasPrefix(name, "pg_temp_")
}

// PostgreSQL has no relay rewrite: client_encoding is handled on the wire, not by an analyzer rewrite,
// so there is nothing to rewrite here.
func (e *postgresEngine) RewriteStatement(exp.Expression) string { return "" }

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
