package engines

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

var MySQL = &Engine{
	WireName: "mysql", Proto: pb.Engine_MYSQL,
	DefaultProxyPort: 6033, DefaultTargetPort: 3307,
	Traits: EngineTraits{
		DefaultSchemaSettable: true,
		IdentifierQuote:       "`",
		systemSchemas:         schemas("information_schema", "mysql", "performance_schema", "sys"),
		// MySQL has one catalog, def, whatever the database.
		catalogName:         func(string) CatalogName { return CatalogName{"def"} },
		catalogColumnNames:  mysqlCatalogColumnNames,
		functionName:        func(name string) FunctionName { return FunctionName{dialects.MySQLLower(name)} },
		targetDialect:       mysqlDialect,
		bareCallIsBuiltin:   noBuiltinBareCall,
		showUtilityCommand:  showUtilityCommand,
		isSafeTypeReference: noSafeTypeReference,
		// MySQL has no search path; a bare name never resolves in a system schema.
		systemSchemaFirst: noSystemSchemaFirst,
		nativeOutputLabel: mysqlNativeOutputLabel,
		// MySQL diagnostics echo only the operated value (`Truncated incorrect INTEGER value: '010-…'`) —
		// always an already-referenced column — and never dump unreferenced ones, so the template is the whole set.
		diagnosticLeakKeys: referencedColumnLeakKeys,
		normalizeRules: func() normalizeRules {
			return normalizeRules{dialect: dialects.MySQL(), rejectExecutableComments: true}
		},
		foldColumn:                          mysqlColumn,
		normalizeCatalogOnBuild:             true,
		rejectsDuplicateDerivedOutputLabels: true,
		rightJoinStarOrder:                  starOrderCommonRightLeft,

		catalogIsConnectionIndependent: true,
		checksTargetErrors:             true,
		defaultSchemaPrefix:            "USE ",
		defaultSchema:                  func(registeredDbName string) string { return registeredDbName },
		serverVersion:                  mysqlServerVersion,
		manifestSeries:                 mysqlManifestSeries,
		functionCatalog:                mysqlFunctionCatalog,
	},
	hooks: mysqlHooks{},
}

// mysqlDialect folds identifiers as lower_case_table_names does, with MySQL's utf8mb3_general_ci map: under 0
// table and database names keep their case and everything else folds; under 1 and 2 everything folds. Guessing an
// unreported value would key names the analyzer never matches. The version gates executable comments.
func mysqlDialect(targetSettings *pb.TargetSettings) (*dialects.Dialect, sessionDialect, error) {
	if targetSettings == nil || targetSettings.MysqlLowerCaseTableNames == nil {
		return nil, nil, fmt.Errorf("lower_case_table_names is required for mysql")
	}
	n := targetSettings.GetMysqlLowerCaseTableNames()
	if n < 0 || n > 2 {
		return nil, nil, fmt.Errorf("lower_case_table_names must be 0, 1 or 2, not %d", n)
	}
	versionID := mysqlVersionID(targetSettings.GetEngineVersion())
	if versionID <= 0 {
		return nil, nil, fmt.Errorf("engine version is required for mysql")
	}
	settings := mysqlNameDialect(n).SettingsString() + fmt.Sprintf(", mysql_version=%d, opaque_functions=true", versionID)
	d, err := dialects.GetOrRaise(settings)
	if err != nil {
		return nil, nil, fmt.Errorf("build mysql dialect: %w", err)
	}
	// ANSI_QUOTES goes through settings resolution, not a field-set: it rewrites the tokenizer config
	// (applyMySQLAnsiQuotes — `"` becomes a quoted-identifier delimiter, not a string), which only runs at
	// resolution time. When the target DB's live sql_mode carries ANSI_QUOTES, the analyzer then reads a masked
	// column quoted with `"` as the real column and still masks it (instead of the proxy having to fail the
	// connection closed).
	ansiQuotes, err := dialects.GetOrRaise(settings + ", mysql_ansi_quotes=true")
	if err != nil {
		return nil, nil, fmt.Errorf("build mysql dialect: %w", err)
	}
	return d, func(observation *pb.SessionObservation) (*dialects.Dialect, error) {
		if observation.GetMysql().GetAnsiQuotes() {
			return ansiQuotes, nil
		}
		return d, nil
	}, nil
}

func mysqlNameDialect(lowerCaseTableNames int32) *dialects.Dialect {
	d := dialects.MySQL()
	if lowerCaseTableNames == 0 {
		d.NormalizationStrategy = dialects.MySQLCaseSensitiveTableNames
	} else {
		d.NormalizationStrategy = dialects.MySQLCaseInsensitive
	}
	return d
}

// mysqlColumn folds a column name: MySQL compares columns case-insensitively whatever lower_case_table_names is.
func mysqlColumn(name string) string { return mysqlColumnDialect.FoldIdentifierName(name, false) }

var mysqlColumnDialect = mysqlNameDialect(1)

// mysqlCatalogColumnNames folds catalog rows by lower_case_table_names: under 0, App.Users.ID -> App.Users.id; under
// 1 or 2, app.users.id. Each distinct (schema, table) is folded once.
func mysqlCatalogColumnNames(d *dialects.Dialect, rows []*pb.Column) []ColumnName {
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

// MySQL labels an unaliased computed projection with its verbatim source text (`1 +    1` keeps
// its exact spacing; verified against MySQL 8.0), truncated to 255 runes as the server does for
// implicit labels. Fails closed on an unstamped node (only parse-time projections carry text).
func mysqlNativeOutputLabel(_ *Session, projection, _ exp.Expression) (string, bool) {
	text, ok := projection.SpanText()
	if !ok {
		return "", false
	}
	if runes := []rune(text); len(runes) > 255 {
		text = string(runes[:255])
	}
	return text, true
}

type mysqlHooks struct{ sharedHooks }

// rewriteStatement pins a single, session-scoped `SET character_set_results = NULL` — the default MySQL
// Connector/J (and so DBeaver) session-init, which asks the target DB to return each column in its own charset
// for client-side decoding — to utf8mb4, so the wire masker keeps decoding results as UTF-8. Only that exact
// form is rewritten; a compound SET, GLOBAL/PERSIST scope, a same-named user variable, a qualified or
// bogus-scoped target, or any non-NULL value is left untouched (and still fails closed at the wire session
// invariant). Recognition is on the parsed AST, so every spelling MySQL accepts reduces to the same check.
func (mysqlHooks) rewriteStatement(root exp.Expression) string {
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

var mysqlNatives = map[string][]string{"8.0": nativeFunctions("mysql", "8.0"), "8.4": nativeFunctions("mysql", "8.4")}

var mysqlMinorVersion = regexp.MustCompile(`(\d+)\.(\d+)`)

// mysqlNativeFunctions are the builtins of the nearest pinned series: 8.4+ -> 8.4, anything else -> 8.0.
func mysqlNativeFunctions(version string) []string {
	m := mysqlMinorVersion.FindStringSubmatch(version)
	if m == nil {
		return mysqlNatives["8.0"]
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major == 8 && minor >= 4 {
		return mysqlNatives["8.4"]
	}
	return mysqlNatives["8.0"]
}

// {"mysql": [fnv_64], "app": [add_tax]} -> builtins = pinned natives, loadables = [fnv_64], udf app = [add_tax].
func mysqlFunctionCatalog(_ *Engine, routines []*pb.SchemaFunctions, version string) *pb.FunctionCatalog {
	catalog := &pb.FunctionCatalog{BuiltinFunctions: slices.Clone(mysqlNativeFunctions(version))}
	for _, r := range routines {
		if r.GetSchema() == "mysql" {
			catalog.LoadableFunctions = append(catalog.LoadableFunctions, r.GetNames()...)
		} else {
			catalog.UdfSchemas = append(catalog.UdfSchemas, &pb.SchemaFunctions{Schema: r.GetSchema(), Names: r.GetNames()})
		}
	}
	return catalog
}

var patchVersion = regexp.MustCompile(`\d+\.\d+\.\d+`)

var minorVersion = regexp.MustCompile(`\d+\.\d+`)

// 8.0.mysql_aurora.3.04.0 identifies MySQL 8.0, not Aurora 3.04.0.
func mysqlServerVersion(raw string) *pb.ServerVersion {
	if strings.TrimSpace(raw) == "" {
		return &pb.ServerVersion{}
	}
	base, _, _ := strings.Cut(raw, "mysql_aurora")
	base, _, _ = strings.Cut(base, "(aurora")
	version := patchVersion.FindString(base)
	if version == "" {
		version = minorVersion.FindString(base)
	}
	return &pb.ServerVersion{Version: nonEmpty(version), Aurora: isAurora(raw)}
}

// 8.0.44 -> 8.0.
func mysqlManifestSeries(version string) string {
	parts := strings.Split(version, ".")
	return strings.Join(parts[:min(2, len(parts))], ".")
}
