package engines

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/schema"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

var Postgres = &Engine{
	WireName: "postgres", Proto: pb.Engine_POSTGRES,
	DefaultProxyPort: 6432, DefaultTargetPort: 5433,
	Traits: EngineTraits{
		DefaultSchemaSettable: true,
		IdentifierQuote:       `"`, numberedPlaceholders: true,
		BuiltinSchema:         SchemaName{"pg_catalog"},
		systemSchemas:         schemas("pg_catalog", "information_schema"),
		tempSchema:            SchemaName{"pg_temp"},
		sessionSchemaPrefixes: schemas("pg_temp_", "pg_toast"),
		// The database name is a connection parameter libpq matches exactly, not SQL text, so it is not folded.
		catalogName:        func(registeredDbName string) CatalogName { return CatalogName{registeredDbName} },
		catalogColumnNames: postgresCatalogColumnNames,
		functionName: func(name string) FunctionName {
			return FunctionName{dialects.Postgres().FoldIdentifierName(name, false)}
		},
		targetDialect: func(*pb.TargetSettings) (*dialects.Dialect, sessionDialect, error) {
			d, err := dialects.GetOrRaise("postgres, opaque_functions=true")
			return d, func(observation *pb.SessionObservation) (*dialects.Dialect, error) {
				return d, checkPostgresObservation(observation)
			}, err
		},
		bareCallIsBuiltin:   postgresBareCallIsBuiltin,
		showUtilityCommand:  showUtilityCommand,
		isSafeTypeReference: postgresSafeXIDType,
		systemSchemaFirst:   postgresCatalogFirstAfterTempSchemas,
		nativeOutputLabel:   postgresNativeOutputLabel,
		diagnosticLeakKeys:  postgresDiagnosticLeakKeys,
		normalizeRules: func() normalizeRules {
			return normalizeRules{dialect: dialects.Postgres(), foldIdentifiers: true}
		},
		foldColumn: func(name string) string { return name },
		builtinFunctionRows: map[string][]string{
			"pg_available_extension_versions": {"name", "version", "superuser", "trusted", "relocatable", "schema", "requires", "comment"},
			"unnest":                          {"unnest"},
		},
		// RESET restores defaults; an unmodeled SHOW reads a GUC, not table data.
		passthroughCommands: []string{"RESET", "SHOW"},
		syntaxCalls:         []string{"array"},
	},
	// PostgreSQL has no relay rewrite: client_encoding is handled on the wire, not by an analyzer rewrite,
	// so there is nothing to rewrite here.
	hooks: sharedHooks{},
}

// postgresCatalogColumnNames keeps catalog rows as they are: pg_catalog already holds the exact names.
func postgresCatalogColumnNames(_ *dialects.Dialect, rows []*pb.Column) []ColumnName {
	out := make([]ColumnName, len(rows))
	for i, row := range rows {
		out[i] = ColumnName{CatalogName{row.GetCatalog()}, SchemaName{row.GetSchema()}, row.GetTable(), row.GetColumn()}
	}
	return out
}

// checkPostgresObservation checks the observed function shadowing, which bareCallIsBuiltin trusts.
func checkPostgresObservation(observation *pb.SessionObservation) error {
	postgresSession := observation.GetPostgres()
	if !postgresSession.GetFunctionShadowingObserved() && len(postgresSession.GetShadowedFunctions()) != 0 {
		return fmt.Errorf("shadowedFunctions requires an observed function-shadowing context")
	}
	shadowed := make(map[string]bool, len(postgresSession.GetShadowedFunctions()))
	for _, name := range postgresSession.GetShadowedFunctions() {
		if name == "" {
			return fmt.Errorf("shadowedFunctions contains invalid function name %q", name)
		}
		if shadowed[name] {
			return fmt.Errorf("shadowedFunctions contains duplicate function name %q", name)
		}
		shadowed[name] = true
	}
	return nil
}

// A zero-argument builtin has one signature, so the earliest schema wins and pg_catalog first settles
// it. unnest is polymorphic: trusted only when the session's namespace probe ran and listed no user unnest.
func postgresBareCallIsBuiltin(session *Session, name string) bool {
	if name != "unnest" {
		return true
	}
	postgresSession := session.observation.GetPostgres()
	return postgresSession.GetFunctionShadowingObserved() && !slices.Contains(postgresSession.GetShadowedFunctions(), name)
}

// `'1'::pg_catalog.xid` is safe. Bare `'1'::xid` is safe only when pg_catalog is first on search_path
// (after pg_temp) and the proxy saw pg_catalog.xid visible, so no user type can shadow it. `xid(4)` never.
func postgresSafeXIDType(session *Session, dt, kind exp.Expression, namespace NamespaceConfig) bool {
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
	session.dialect.NormalizeIdentifier(folded)
	if folded.Name() != "xid" {
		return false
	}
	if qualifier != nil {
		return session.isBuiltinQualifier(qualifier)
	}
	return session.observation.GetPostgres().GetSystemXidVisible() && postgresCatalogFirstAfterTempSchemas(namespace.SearchPath)
}

// PostgreSQL names an unaliased projection per parse_target.c FigureColname; a call is labeled by
// its WRITTEN function name, read from the projection's parse-time SpanText.
func postgresNativeOutputLabel(session *Session, projection, query exp.Expression) (string, bool) {
	return nativeOutputLabel(projection, query, session, 0)
}

// PostgreSQL adds a failed write's WHOLE target row to the template: `INSERT INTO users (id) …` can fail
// with `DETAIL: Failing row contains (1, 010-1234-5678, …)` — columns the statement never named. If the
// row cannot be enumerated, an unresolvable sentinel key emits so the control-plane fails closed.
func postgresDiagnosticLeakKeys(session *Session, report ProbeResult, qualifySchema schema.Schema) map[string]bool {
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
	cols, err := qualifySchema.ColumnNames(table, true, session.dialect, boolPtr(false))
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

// PostgreSQL's implicit output-label rules, ported from FigureColname/FigureColnameInternal in
// the server's parser (src/backend/parser/parse_target.c) and verified against a live PostgreSQL
// 16: a call is labeled by its written function name, a cast overrides only a weak inner name
// (strength ≤ 1), CASE takes its ELSE's name, a scalar subquery its single output's resname, and
// anything nameless falls back to "?column?".

// nativeOutputLabel is FigureColname for one projection: the label PostgreSQL assigns to an
// unaliased output, with the no-name fallback applied. query is the SELECT the projection belongs
// to, for resolving references to its derived sources. ok=false means the label is unknowable —
// the caller must not stamp.
func nativeOutputLabel(node exp.Expression, query exp.Expression, session *Session, depth int) (string, bool) {
	name, strength, ok := figureLabel(node, query, session, depth)
	if !ok {
		return "", false
	}
	if strength == 0 || name == "" {
		return "?column?", true
	}
	return name, true
}

// figureLabel mirrors PostgreSQL's FigureColnameInternal: (label, strength, resolvable) where
// strength 0 = no name (caller falls back to ?column?), 1 = weak (a cast may override it),
// 2 = strong.
func figureLabel(node exp.Expression, query exp.Expression, session *Session, depth int) (string, int, bool) {
	if node == nil || depth > 20 {
		return "", 0, false
	}
	switch node.Kind() {
	case exp.KindColumn:
		// A reference to a derived table or CTE carries that source's projection label — in real
		// PostgreSQL the reference's column NAME is the inner resname; here the inner name may be
		// synthetic, so resolve through to the defining expression.
		if table := node.TableName(); table != "" && syntheticLabelPattern.MatchString(node.Name()) {
			if inner, innerSelect := derivedSourceProjection(query, table, node.Name()); inner != nil {
				return figureProjectionLabel(inner, innerSelect, session, depth+1)
			}
			return "", 0, false
		}
		if name := node.Name(); name != "" {
			return name, 2, true
		}
		return "", 0, false
	case exp.KindDot, exp.KindTableColumn, exp.KindIdentifier:
		if name := node.Name(); name != "" {
			return name, 2, true
		}
		return "", 0, false
	case exp.KindParen, exp.KindCollate:
		return figureLabel(node.This(), query, session, depth+1)
	case exp.KindBracket:
		// Indirection keeps the base expression's label: `(array[1,2])[1]` is `array`.
		return figureLabel(node.This(), query, session, depth+1)
	case exp.KindCast, exp.KindTryCast:
		name, strength, ok := figureLabel(node.This(), query, session, depth+1)
		if ok && strength == 2 {
			return name, 2, true
		}
		if label, mapped := postgresCastLabel(node); mapped {
			return label, 1, true
		}
		return name, strength, ok
	case exp.KindCase:
		if defresult, ok := node.Arg("default").(exp.Expression); ok && defresult != nil {
			if name, strength, ok := figureLabel(defresult, query, session, depth+1); ok && strength == 2 {
				return name, 2, true
			}
		}
		return "case", 1, true
	case exp.KindSubquery:
		return subqueryLabel(node, session, depth)
	case exp.KindWindow, exp.KindFilter:
		return figureLabel(node.This(), query, session, depth+1)
	case exp.KindAtTimeZone:
		return "timezone", 2, true
	case exp.KindTrim:
		switch strings.ToUpper(node.Text("position")) {
		case "LEADING":
			return "ltrim", 2, true
		case "TRAILING":
			return "rtrim", 2, true
		}
		return "btrim", 2, true
	}
	if label, ok := postgresFixedKindLabels[node.Kind()]; ok {
		return label, 2, true
	}
	if node.Kind() == exp.KindAnonymous {
		// An Anonymous call keeps the client's spelling as its AST name — safe without a span.
		if name := normalizedFunctionName(node, session); name != "" {
			return name, 2, true
		}
		return "", 0, false
	}
	if node.Is(exp.TraitFunc) {
		// A DEDICATED function kind canonicalizes its AST name (`char_length` parses to Length,
		// `position(...)` to StrPosition) but PostgreSQL labels the call by its WRITTEN name, so
		// read that off the node's source span; no span (a sub-expression) → unknowable.
		return writtenFunctionLabel(node)
	}
	// Operators, literals, boolean tests, … — PostgreSQL gives them no name (→ ?column?).
	return "", 0, true
}

// writtenFunctionLabel is the function name as the client wrote it: the leading identifier of the
// call's parse-time SpanText, folded per PostgreSQL's case rule (unquoted → lowercase, quoted →
// verbatim).
func writtenFunctionLabel(node exp.Expression) (string, int, bool) {
	text, ok := node.SpanText()
	if !ok {
		return "", 0, false
	}
	open := strings.IndexByte(text, '(')
	if open <= 0 {
		return "", 0, false
	}
	written := strings.TrimSpace(text[:open])
	if len(written) >= 2 && written[0] == '"' && written[len(written)-1] == '"' {
		return strings.ReplaceAll(written[1:len(written)-1], `""`, `"`), 2, true
	}
	if !functionLabelPattern.MatchString(written) {
		return "", 0, false
	}
	return strings.ToLower(written), 2, true
}

// figureProjectionLabel is the label of one projection inside a derived source: its resname (the
// explicit alias when real) or FigureColname of its expression.
func figureProjectionLabel(projection exp.Expression, query exp.Expression, session *Session, depth int) (string, int, bool) {
	if projection == nil || depth > 20 {
		return "", 0, false
	}
	if projection.Kind() == exp.KindAlias {
		if alias := projection.Alias(); alias != "" && !syntheticLabelPattern.MatchString(alias) {
			return alias, 2, true
		}
		return figureLabel(projection.This(), query, session, depth+1)
	}
	return figureLabel(projection, query, session, depth+1)
}

// subqueryLabel is a scalar subquery's label: its single output column's resname.
func subqueryLabel(subquery exp.Expression, session *Session, depth int) (string, int, bool) {
	sel := leftmostSelect(subquery.This())
	if sel == nil {
		return "", 0, false
	}
	projections := sel.Selects()
	if len(projections) != 1 {
		return "", 0, false
	}
	name, strength, ok := figureProjectionLabel(projections[0], sel, session, depth+1)
	if !ok || strength == 0 || name == "" {
		return "", 0, ok
	}
	return name, 2, true
}

// derivedSourceProjection finds the derived table or CTE named alias among query's sources and
// returns its projection labeled name (by alias or output name) plus the SELECT it projects from.
func derivedSourceProjection(query exp.Expression, alias, name string) (exp.Expression, exp.Expression) {
	sel := sourceSelect(query, alias)
	if sel == nil {
		return nil, nil
	}
	for _, projection := range sel.Selects() {
		if projection.AliasOrName() == name {
			return projection, sel
		}
	}
	return nil, nil
}

func sourceSelect(query exp.Expression, alias string) exp.Expression {
	check := func(node exp.Expression) exp.Expression {
		if node != nil && node.Kind() == exp.KindSubquery && node.Alias() == alias {
			return leftmostSelect(node.This())
		}
		return nil
	}
	if from := asExpression(query.Arg("from_")); from != nil {
		if sel := check(from.This()); sel != nil {
			return sel
		}
		for _, e := range expressionsFor(from, "expressions") {
			if sel := check(e); sel != nil {
				return sel
			}
		}
	}
	for _, join := range expressionsFor(query, "joins") {
		if sel := check(join.This()); sel != nil {
			return sel
		}
	}
	if with := asExpression(query.Arg("with_")); with != nil {
		for _, cte := range with.Expressions() {
			if cte.Alias() == alias {
				return leftmostSelect(cte.This())
			}
		}
	}
	return nil
}

// postgresCastTypeLabels maps sqlglot's DType to the type name PostgreSQL uses as a cast's output
// label when the cast argument itself has none (`1::int` labels `int4`).
var postgresCastTypeLabels = map[exp.DType]string{
	exp.DTypeInt:         "int4",
	exp.DTypeSmallInt:    "int2",
	exp.DTypeBigInt:      "int8",
	exp.DTypeBoolean:     "bool",
	exp.DTypeFloat:       "float4",
	exp.DTypeDouble:      "float8",
	exp.DTypeDecimal:     "numeric",
	exp.DTypeText:        "text",
	exp.DTypeVarchar:     "varchar",
	exp.DTypeChar:        "bpchar",
	exp.DTypeBpchar:      "bpchar",
	exp.DTypeDate:        "date",
	exp.DTypeTime:        "time",
	exp.DTypeTimeTz:      "timetz",
	exp.DTypeTimestamp:   "timestamp",
	exp.DTypeTimestampTz: "timestamptz",
	exp.DTypeUUID:        "uuid",
	exp.DTypeJSON:        "json",
	exp.DTypeJSONB:       "jsonb",
	exp.DTypeInterval:    "interval",
	exp.DTypeName:        "name",
	exp.DTypeInet:        "inet",
}

var postgresFixedKindLabels = map[exp.Kind]string{
	exp.KindExists:           "exists",
	exp.KindArray:            "array",
	exp.KindTuple:            "row",
	exp.KindInterval:         "interval",
	exp.KindCurrentDate:      "current_date",
	exp.KindCurrentTime:      "current_time",
	exp.KindCurrentTimestamp: "current_timestamp",
	exp.KindLocaltime:        "localtime",
	exp.KindLocaltimestamp:   "localtimestamp",
	exp.KindCurrentSchema:    "current_schema",
	exp.KindCurrentCatalog:   "current_catalog",
	exp.KindCurrentUser:      "current_user",
	exp.KindSessionUser:      "session_user",
}

func postgresCastLabel(cast exp.Expression) (string, bool) {
	to, _ := cast.Arg("to").(exp.Expression)
	if to == nil {
		return "", false
	}
	if dtype, ok := to.Arg("this").(exp.DType); ok {
		if label, mapped := postgresCastTypeLabels[dtype]; mapped {
			return label, true
		}
		if dtype == exp.DTypeUserDefined {
			if kind, ok := to.Arg("kind").(exp.Expression); ok && kind.Kind() == exp.KindIdentifier {
				return kind.Name(), true
			}
		}
	}
	return "", false
}

var functionLabelPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func postgresCatalogFirstAfterTempSchemas(searchPath []string) bool {
	for _, schema := range searchPath {
		if schema == "pg_temp" || strings.HasPrefix(schema, "pg_temp_") {
			continue
		}
		return schema == "pg_catalog"
	}
	return false
}
