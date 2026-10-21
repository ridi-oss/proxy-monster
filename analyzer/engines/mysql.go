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

var MySQL = &Engine{
	WireName: "mysql", Proto: pb.Engine_MYSQL, DefaultSchemaSettable: true,
	DefaultProxyPort: 6033, DefaultTargetPort: 3307, IdentifierQuote: "`",
	systemSchemas: schemas("information_schema", "mysql", "performance_schema", "sys"),
	// MySQL has one catalog, def, whatever the database.
	catalogName:       func(string) CatalogName { return CatalogName{"def"} },
	introspected:      mysqlIntrospected,
	dialect:           dialects.MySQL,
	datasourceDialect: mysqlDialect,
	newSession:        newMySQLSession,
	normalizeRules: func() normalizeRules {
		d := dialects.MySQL()
		return normalizeRules{dialect: d, wordDialect: d, rejectExecutableComments: true}
	},
	showsWithoutSession:                 true,
	foldColumn:                          mysqlColumn,
	normalizeCatalogOnBuild:             true,
	rejectsDuplicateDerivedOutputLabels: true,
	rightJoinStarOrder:                  starOrderCommonRightLeft,
}

// mysqlDialect folds identifiers as lower_case_table_names does, with MySQL's utf8mb3_general_ci map: under 0
// table and database names keep their case and everything else folds; under 1 and 2 everything folds. Guessing an
// unreported value would key names the analyzer never matches.
func mysqlDialect(reported *pb.EngineDatasource) (*dialects.Dialect, error) {
	if reported == nil || reported.MysqlLowerCaseTableNames == nil {
		return nil, fmt.Errorf("lower_case_table_names is required for mysql")
	}
	n := reported.GetMysqlLowerCaseTableNames()
	if n < 0 || n > 2 {
		return nil, fmt.Errorf("lower_case_table_names must be 0, 1 or 2, not %d", n)
	}
	d := dialects.MySQL()
	if n == 0 {
		d.NormalizationStrategy = dialects.MySQLCaseSensitiveTableNames
	} else {
		d.NormalizationStrategy = dialects.MySQLCaseInsensitive
	}
	return d, nil
}

// mysqlColumn folds a column name: MySQL compares columns case-insensitively whatever lower_case_table_names is.
func mysqlColumn(name string) string { return mysqlColumnDialect.FoldIdentifierName(name, false) }

var mysqlColumnDialect = func() *dialects.Dialect {
	one := int32(1)
	d, _ := mysqlDialect(&pb.EngineDatasource{MysqlLowerCaseTableNames: &one})
	return d
}()

// mysqlIntrospected folds catalog rows by lower_case_table_names: under 0, App.Users.ID -> App.Users.id; under
// 1 or 2, app.users.id. Each distinct (schema, table) is folded once.
func mysqlIntrospected(d *dialects.Dialect, rows []*pb.Column) []ColumnName {
	type relation struct{ schema, table string }
	relations := make(map[relation]relation)
	out := make([]ColumnName, len(rows))
	for i, row := range rows {
		key := relation{row.GetSchema(), row.GetTable()}
		canonical, ok := relations[key]
		if !ok {
			// NormalizeIdentifier reads each identifier's parent to tell a table or schema name from a column.
			schemaID := exp.Identifier(exp.Args{"this": key.schema, "quoted": false})
			tableID := exp.Identifier(exp.Args{"this": key.table, "quoted": false})
			exp.Table(exp.Args{"this": tableID, "schema": schemaID})
			d.NormalizeIdentifier(schemaID)
			d.NormalizeIdentifier(tableID)
			canonical = relation{schemaID.Name(), tableID.Name()}
			relations[key] = canonical
		}
		out[i] = ColumnName{CatalogName{row.GetCatalog()}, SchemaName{canonical.schema}, canonical.table, mysqlColumn(row.GetColumn())}
	}
	return out
}

type mysqlSession struct {
	datasource Datasource
	dialect    *dialects.Dialect
}

func (e *mysqlSession) Datasource() Datasource { return e.datasource }

func newMySQLSession(ds Datasource, observed *pb.SessionObservation) (session, error) {
	versionID := mysqlVersionID(ds.version)
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
	// fail the connection closed). ds.Dialect only ever sets the strategy, so its
	// SettingsString round-trips losslessly as the base.
	settings := ds.Dialect().SettingsString() +
		fmt.Sprintf(", mysql_version=%d, opaque_functions=true", versionID)
	if observed.GetMysql().GetAnsiQuotes() {
		settings += ", mysql_ansi_quotes=true"
	}
	dialect, err := dialects.GetOrRaise(settings)
	if err != nil {
		return nil, fmt.Errorf("build mysql dialect: %w", err)
	}
	return &mysqlSession{datasource: ds, dialect: dialect}, nil
}

func (e *mysqlSession) PrepareStatement(root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
	return root, false, nil, nil
}

func (e *mysqlSession) FinishSubmission(exp.Expression) bool { return false }

func (e *mysqlSession) StampSubmission(*pb.StatementFacts) {}

func (e *mysqlSession) Dialect() *dialects.Dialect { return e.dialect }

func (e *mysqlSession) ConfigureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig) {
	opts.SearchPath = namespace.SearchPath
}

func (e *mysqlSession) BareCallIsBuiltin(string) bool { return false }

// MySQL labels an unaliased computed projection with its verbatim source text (`1 +    1` keeps
// its exact spacing; verified against MySQL 8.0), truncated to 255 runes as the server does for
// implicit labels. Fails closed on an unstamped node (only parse-time projections carry text).
func (e *mysqlSession) NativeOutputLabel(projection, _ exp.Expression) (string, bool) {
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
func (e *mysqlSession) RewriteStatement(root exp.Expression) string {
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
func (e *mysqlSession) DiagnosticLeakKeys(report ProbeResult, _ schema.Schema) map[string]bool {
	return referencedColumnKeys(report)
}

func (e *mysqlSession) ShowUtilityCommand(root exp.Expression) string {
	return showUtilityCommand(root)
}

// MySQL has no search path; a bare name never resolves in a system schema.
func (e *mysqlSession) SystemSchemaFirst([]string) bool { return false }

func (e *mysqlSession) IsSafeTypeReference(exp.Expression, exp.Expression, NamespaceConfig) bool {
	return false
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

func containsUnsafeMySQLComment(gap []rune) bool {
	text := string(gap)
	return strings.Contains(text, "/*!") || strings.Contains(text, "/*+")
}

// CanonicalMySQLRelation resolves a MySQL schema/table/column's canonical spelling under a given
// lower_case_table_names mode — including the information_schema exception (always
// case-insensitive, regardless of mode) — via the same role-aware Dialect the analyzer's own catalog
// build and query resolution use (mysqlNormalizationDialect + Dialect.NormalizeIdentifier). It is
// exported (via cmd/libsqlglot) so the control-plane's PII-classification keys resolve identically to
// whatever the analyzer treats as canonical.
//
// schemaName and table are wired into a throwaway *exp.Table (the Table value itself is discarded)
// purely so NormalizeIdentifier can read each part's parent to detect relation-level role and the
// information_schema exception — a detached identifier has no parent, so this AST wiring is what
// makes the check possible. Catalog is never folded (by either language), so it takes no part here.
// column folds unconditionally via FoldIdentifierName — a column name's role is never ambiguous,
// matching probe.go's canonicalColumn.
func CanonicalMySQLRelation(mysqlLowerCaseTableNames int, schemaName, table, column string) (canonicalSchema, canonicalTable, canonicalColumn string) {
	d := mysqlNormalizationDialect(mysqlLowerCaseTableNames)

	schemaID := exp.ParseIdentifier(schemaName, d)
	tableID := exp.ParseIdentifier(table, d)
	exp.Table(exp.Args{"this": tableID, "schema": schemaID})

	d.NormalizeIdentifier(schemaID)
	d.NormalizeIdentifier(tableID)

	return schemaID.Name(), tableID.Name(), d.FoldIdentifierName(column, false)
}

// NormalizeMySQLColumns folds a batch of column identities to their canonical spelling, memoizing the
// per-(schema, table) work. Semantically identical to calling CanonicalMySQLRelation for each row, but
// O(distinct tables) sqlglot parses instead of O(columns): within a schema fragment the schema is
// constant and each table's columns repeat its name, so re-parsing schema+table per column (as the
// per-row path does) is pure waste — the dominant cost on a wide schema. Column names still fold
// per row (a cheap name fold, no identifier parse). schemas/tables/columns are parallel, equal-length.
func NormalizeMySQLColumns(mysqlLowerCaseTableNames int, schemas, tables, columns []string) (outSchemas, outTables, outColumns []string) {
	n := len(columns)
	outSchemas = make([]string, n)
	outTables = make([]string, n)
	outColumns = make([]string, n)
	d := mysqlNormalizationDialect(mysqlLowerCaseTableNames)
	type rel struct{ schema, table string }
	cache := make(map[rel][2]string)
	for i := 0; i < n; i++ {
		key := rel{schemas[i], tables[i]}
		canon, ok := cache[key]
		if !ok {
			schemaID := exp.ParseIdentifier(key.schema, d)
			tableID := exp.ParseIdentifier(key.table, d)
			exp.Table(exp.Args{"this": tableID, "schema": schemaID})
			d.NormalizeIdentifier(schemaID)
			d.NormalizeIdentifier(tableID)
			canon = [2]string{schemaID.Name(), tableID.Name()}
			cache[key] = canon
		}
		outSchemas[i] = canon[0]
		outTables[i] = canon[1]
		outColumns[i] = d.FoldIdentifierName(columns[i], false)
	}
	return outSchemas, outTables, outColumns
}
