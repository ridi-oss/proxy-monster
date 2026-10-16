package engines

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/optimizer"
	"github.com/ridi-oss/sqlglot-go/schema"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

type postgresAnalyzer struct {
	dialect                   *dialects.Dialect
	shadowedFunctions         map[string]bool
	functionShadowingObserved bool
	systemXIDVisible          bool
}

func postgresOpaqueDialect() *dialects.Dialect {
	d, err := dialects.GetOrRaise("postgres, opaque_functions=true")
	if err != nil {
		panic(err)
	}
	return d
}

func newPostgresAnalyzer(config *pb.EngineConfig) (*postgresAnalyzer, error) {
	session := config.GetSession().GetPostgres()
	if !session.GetFunctionShadowingObserved() && len(session.GetShadowedFunctions()) != 0 {
		return nil, fmt.Errorf("shadowedFunctions requires an observed function-shadowing context")
	}
	shadowed := make(map[string]bool, len(session.GetShadowedFunctions()))
	for _, name := range session.GetShadowedFunctions() {
		if name == "" || name != strings.ToLower(name) {
			return nil, fmt.Errorf("shadowedFunctions contains invalid function name %q", name)
		}
		if shadowed[name] {
			return nil, fmt.Errorf("shadowedFunctions contains duplicate function name %q", name)
		}
		shadowed[name] = true
	}
	return &postgresAnalyzer{
		dialect:                   postgresOpaqueDialect(),
		shadowedFunctions:         shadowed,
		functionShadowingObserved: session.GetFunctionShadowingObserved(),
		systemXIDVisible:          session.GetSystemXidVisible(),
	}, nil
}

func (e *postgresAnalyzer) WireName() string { return "postgres" }

func (e *postgresAnalyzer) PrepareStatement(root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
	return root, false, nil, nil
}

func (e *postgresAnalyzer) FinishSubmission(exp.Expression) bool { return false }

func (e *postgresAnalyzer) StampSubmission(*pb.StatementFacts) {}

func (e *postgresAnalyzer) Dialect() *dialects.Dialect { return e.dialect }

// PostgreSQL does not fold the introspected catalog: quoted and unquoted names can identify distinct
// real columns, while query-side qualification already preserves quoted names and folds unquoted ones.
func (e *postgresAnalyzer) NormalizeCatalogOnBuild() bool { return false }

func (e *postgresAnalyzer) AllowsCrossCatalog() bool { return false }

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

// PostgreSQL places session-temporary objects in pg_temp (a per-backend alias for the numbered
// pg_temp_<n> temp schema), so a DDL target there is session-local, not catalog-changing. Read off the
// already-folded spelling (EmitFacts normalizes the statement's identifiers up front, quote-aware), so
// an unquoted pg_temp/PG_TEMP matches while a quoted "PG_TEMP" — a distinct case-sensitive user schema —
// does not. A raw strings.ToLower here would wrongly conflate the two and mis-fold non-ASCII.
func (e *postgresAnalyzer) IsTempSchema(schema exp.Expression) bool {
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
func (e *postgresAnalyzer) IsTrustedSystemQualifier(qualifier exp.Expression) bool {
	if qualifier == nil || qualifier.Kind() != exp.KindIdentifier {
		return false
	}
	return qualifier.Name() == "pg_catalog"
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

// PostgreSQL's implicit output-label rules, ported from FigureColname/FigureColnameInternal in
// the server's parser (src/backend/parser/parse_target.c) and verified against a live PostgreSQL
// 16: a call is labeled by its written function name, a cast overrides only a weak inner name
// (strength ≤ 1), CASE takes its ELSE's name, a scalar subquery its single output's resname, and
// anything nameless falls back to "?column?".

// nativeOutputLabel is FigureColname for one projection: the label PostgreSQL assigns to an
// unaliased output, with the no-name fallback applied. query is the SELECT the projection belongs
// to, for resolving references to its derived sources. ok=false means the label is unknowable —
// the caller must not stamp.
func nativeOutputLabel(node exp.Expression, query exp.Expression, eng analyzer, depth int) (string, bool) {
	name, strength, ok := figureLabel(node, query, eng, depth)
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
func figureLabel(node exp.Expression, query exp.Expression, eng analyzer, depth int) (string, int, bool) {
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
				return figureProjectionLabel(inner, innerSelect, eng, depth+1)
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
		return figureLabel(node.This(), query, eng, depth+1)
	case exp.KindBracket:
		// Indirection keeps the base expression's label: `(array[1,2])[1]` is `array`.
		return figureLabel(node.This(), query, eng, depth+1)
	case exp.KindCast, exp.KindTryCast:
		name, strength, ok := figureLabel(node.This(), query, eng, depth+1)
		if ok && strength == 2 {
			return name, 2, true
		}
		if label, mapped := postgresCastLabel(node); mapped {
			return label, 1, true
		}
		return name, strength, ok
	case exp.KindCase:
		if defresult, ok := node.Arg("default").(exp.Expression); ok && defresult != nil {
			if name, strength, ok := figureLabel(defresult, query, eng, depth+1); ok && strength == 2 {
				return name, 2, true
			}
		}
		return "case", 1, true
	case exp.KindSubquery:
		return subqueryLabel(node, eng, depth)
	case exp.KindWindow, exp.KindFilter:
		return figureLabel(node.This(), query, eng, depth+1)
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
		if name := normalizedFunctionName(node, eng); name != "" {
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
func figureProjectionLabel(projection exp.Expression, query exp.Expression, eng analyzer, depth int) (string, int, bool) {
	if projection == nil || depth > 20 {
		return "", 0, false
	}
	if projection.Kind() == exp.KindAlias {
		if alias := projection.Alias(); alias != "" && !syntheticLabelPattern.MatchString(alias) {
			return alias, 2, true
		}
		return figureLabel(projection.This(), query, eng, depth+1)
	}
	return figureLabel(projection, query, eng, depth+1)
}

// subqueryLabel is a scalar subquery's label: its single output column's resname.
func subqueryLabel(subquery exp.Expression, eng analyzer, depth int) (string, int, bool) {
	sel := leftmostSelect(subquery.This())
	if sel == nil {
		return "", 0, false
	}
	projections := sel.Selects()
	if len(projections) != 1 {
		return "", 0, false
	}
	name, strength, ok := figureProjectionLabel(projections[0], sel, eng, depth+1)
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
