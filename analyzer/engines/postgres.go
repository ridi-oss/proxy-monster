package engines

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/optimizer"
	"github.com/ridi-oss/sqlglot-go/schema"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

var Postgres = &Engine{
	WireName: "postgres", Proto: pb.Engine_POSTGRES, DefaultSchemaSettable: true,
	DefaultProxyPort: 6432, DefaultTargetPort: 5433, IdentifierQuote: `"`, numberedPlaceholders: true,
	BuiltinSchema:         SchemaName{"pg_catalog"},
	systemSchemas:         schemas("pg_catalog", "information_schema"),
	tempSchema:            SchemaName{"pg_temp"},
	sessionSchemaPrefixes: schemas("pg_temp_", "pg_toast"),
	// The database name is a connection parameter libpq matches exactly, not SQL text, so it is not folded.
	catalogName:  func(registeredDbName string) CatalogName { return CatalogName{registeredDbName} },
	introspected: postgresIntrospected,
	dialect:      dialects.Postgres,
	newSession:   newPostgresSession,
	normalizeRules: func() normalizeRules {
		d := dialects.Postgres()
		return normalizeRules{dialect: d, wordDialect: d, foldIdentifiers: true}
	},
	foldColumn: func(name string) string { return name },
	builtinFunctionRows: map[string][]string{
		"pg_available_extension_versions": {"name", "version", "superuser", "trusted", "relocatable", "schema", "requires", "comment"},
		"unnest":                          {"unnest"},
	},
	// RESET restores defaults; an unmodeled SHOW reads a GUC, not table data.
	passthroughCommands: []string{"RESET", "SHOW"},
	syntaxCalls:         []string{"array"},

	checksTargetErrors:  true,
	implicitColumns:     postgresSystemColumns,
	defaultSchemaPrefix: "SET search_path TO ",
	defaultSchema:       func(string) string { return "public" },
	serverVersion:       postgresServerVersion,
	manifestSeries:      func(version string) string { return strings.SplitN(version, ".", 2)[0] },
	functionCatalog:     postgresFunctionCatalog,
	connectionInfoValid: nativeConnectionInfoValid,
	analyzerConfig:      sessionAnalyzerConfig,
}

// postgresIntrospected keeps catalog rows as they are: pg_catalog already holds the exact names.
func postgresIntrospected(_ *dialects.Dialect, rows []*pb.Column) []ColumnName {
	out := make([]ColumnName, len(rows))
	for i, row := range rows {
		out[i] = ColumnName{CatalogName{row.GetCatalog()}, SchemaName{row.GetSchema()}, row.GetTable(), row.GetColumn()}
	}
	return out
}

type postgresSession struct {
	datasource                Datasource
	dialect                   *dialects.Dialect
	shadowedFunctions         map[string]bool
	functionShadowingObserved bool
	systemXIDVisible          bool
}

func newPostgresSession(ds Datasource, observed *pb.SessionObservation) (session, error) {
	d, err := dialects.GetOrRaise(ds.Dialect().SettingsString() + ", opaque_functions=true")
	if err != nil {
		return nil, err
	}
	session := observed.GetPostgres()
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
	return &postgresSession{
		datasource:                ds,
		dialect:                   d,
		shadowedFunctions:         shadowed,
		functionShadowingObserved: session.GetFunctionShadowingObserved(),
		systemXIDVisible:          session.GetSystemXidVisible(),
	}, nil
}

func (e *postgresSession) PrepareStatement(root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
	return root, false, nil, nil
}

func (e *postgresSession) FinishSubmission(exp.Expression) bool { return false }

func (e *postgresSession) StampSubmission(*pb.StatementFacts) {}

func (e *postgresSession) Datasource() Datasource { return e.datasource }

func (e *postgresSession) Dialect() *dialects.Dialect { return e.dialect }

func (e *postgresSession) ConfigureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig) {
	opts.SearchPath = namespace.SearchPath
}

// A zero-argument builtin has one signature, so the earliest schema wins and pg_catalog first settles
// it. unnest is polymorphic: trusted only when the session's namespace probe ran and listed no user unnest.
func (e *postgresSession) BareCallIsBuiltin(name string) bool {
	if name != "unnest" {
		return true
	}
	return e.functionShadowingObserved && !e.shadowedFunctions[name]
}

// PostgreSQL has no relay rewrite: client_encoding is handled on the wire, not by an analyzer rewrite,
// so there is nothing to rewrite here.
func (e *postgresSession) RewriteStatement(exp.Expression) string { return "" }

func (e *postgresSession) ShowUtilityCommand(root exp.Expression) string {
	return showUtilityCommand(root)
}

func (e *postgresSession) SystemSchemaFirst(searchPath []string) bool {
	return e.catalogFirstAfterTempSchemas(searchPath)
}

func (e *postgresSession) IsSafeTypeReference(dt, kind exp.Expression, namespace NamespaceConfig) bool {
	return e.isSafeXIDType(dt, kind, namespace)
}

// `'1'::pg_catalog.xid` is safe. Bare `'1'::xid` is safe only when pg_catalog is first on search_path
// (after pg_temp) and the proxy saw pg_catalog.xid visible, so no user type can shadow it. `xid(4)` never.
func (e *postgresSession) isSafeXIDType(dt, kind exp.Expression, namespace NamespaceConfig) bool {
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
		return e.datasource.isBuiltinQualifier(qualifier)
	}
	return e.systemXIDVisible && e.catalogFirstAfterTempSchemas(namespace.SearchPath)
}

// PostgreSQL names an unaliased projection per parse_target.c FigureColname; a call is labeled by
// its WRITTEN function name, read from the projection's parse-time SpanText.
func (e *postgresSession) NativeOutputLabel(projection, query exp.Expression) (string, bool) {
	return nativeOutputLabel(projection, query, e, 0)
}

// PostgreSQL adds a failed write's WHOLE target row to the template: `INSERT INTO users (id) …` can fail
// with `DETAIL: Failing row contains (1, 010-1234-5678, …)` — columns the statement never named. If the
// row cannot be enumerated, an unresolvable sentinel key emits so the control-plane fails closed.
func (e *postgresSession) DiagnosticLeakKeys(report ProbeResult, qualifySchema schema.Schema) map[string]bool {
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
func nativeOutputLabel(node exp.Expression, query exp.Expression, sess session, depth int) (string, bool) {
	name, strength, ok := figureLabel(node, query, sess, depth)
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
func figureLabel(node exp.Expression, query exp.Expression, sess session, depth int) (string, int, bool) {
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
				return figureProjectionLabel(inner, innerSelect, sess, depth+1)
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
		return figureLabel(node.This(), query, sess, depth+1)
	case exp.KindBracket:
		// Indirection keeps the base expression's label: `(array[1,2])[1]` is `array`.
		return figureLabel(node.This(), query, sess, depth+1)
	case exp.KindCast, exp.KindTryCast:
		name, strength, ok := figureLabel(node.This(), query, sess, depth+1)
		if ok && strength == 2 {
			return name, 2, true
		}
		if label, mapped := postgresCastLabel(node); mapped {
			return label, 1, true
		}
		return name, strength, ok
	case exp.KindCase:
		if defresult, ok := node.Arg("default").(exp.Expression); ok && defresult != nil {
			if name, strength, ok := figureLabel(defresult, query, sess, depth+1); ok && strength == 2 {
				return name, 2, true
			}
		}
		return "case", 1, true
	case exp.KindSubquery:
		return subqueryLabel(node, sess, depth)
	case exp.KindWindow, exp.KindFilter:
		return figureLabel(node.This(), query, sess, depth+1)
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
		if name := normalizedFunctionName(node, sess); name != "" {
			return name, 2, true
		}
		return "", 0, false
	}
	if node.Is(exp.TraitFunc) {
		// A DEDICATED function kind canonicalizes its AST name (`char_length` parses to Length,
		// `position(...)` to StrPosition) but PostgreSQL labels the call by its WRITTEN name, so
		// read that off the node's source span; no span (a sub-expression) → unknowable.
		return writtenFunctionLabel(node, sess)
	}
	// Operators, literals, boolean tests, … — PostgreSQL gives them no name (→ ?column?).
	return "", 0, true
}

// writtenFunctionLabel is the function name as the client wrote it: the leading identifier of the
// call's parse-time SpanText, folded per PostgreSQL's case rule (unquoted → lowercase, quoted →
// verbatim).
func writtenFunctionLabel(node exp.Expression, sess session) (string, int, bool) {
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
	return sess.Dialect().FoldIdentifierName(written, false), 2, true
}

// figureProjectionLabel is the label of one projection inside a derived source: its resname (the
// explicit alias when real) or FigureColname of its expression.
func figureProjectionLabel(projection exp.Expression, query exp.Expression, sess session, depth int) (string, int, bool) {
	if projection == nil || depth > 20 {
		return "", 0, false
	}
	if projection.Kind() == exp.KindAlias {
		if alias := projection.Alias(); alias != "" && !syntheticLabelPattern.MatchString(alias) {
			return alias, 2, true
		}
		return figureLabel(projection.This(), query, sess, depth+1)
	}
	return figureLabel(projection, query, sess, depth+1)
}

// subqueryLabel is a scalar subquery's label: its single output column's resname.
func subqueryLabel(subquery exp.Expression, sess session, depth int) (string, int, bool) {
	sel := leftmostSelect(subquery.This())
	if sel == nil {
		return "", 0, false
	}
	projections := sel.Selects()
	if len(projections) != 1 {
		return "", 0, false
	}
	name, strength, ok := figureProjectionLabel(projections[0], sel, sess, depth+1)
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

var postgresSystemColumns = []*pb.ImplicitColumn{
	{Name: "ctid", DataType: "tid"},
	{Name: "xmin", DataType: "xid"},
	{Name: "xmax", DataType: "xid"},
	{Name: "cmin", DataType: "cid"},
	{Name: "cmax", DataType: "cid"},
	{Name: "tableoid", DataType: "oid"},
}

// PostgreSQL functions the grammar reserves as keywords: no pg_proc row, and no user function can shadow them.
var postgresGrammarFunctions = []string{
	"coalesce", "greatest", "least", "nullif", "grouping",
	"xmlconcat", "xmlelement", "xmlforest", "xmlparse", "xmlpi", "xmlroot", "xmltable",
}

// {"pg_catalog": [abs], "public": [add_tax], "pg_temp_3": [x]} -> builtins = [abs, coalesce, ...], udf public =
// [add_tax], pg_temp_3 dropped.
func postgresFunctionCatalog(e *Engine, routines []*pb.SchemaFunctions, _ string) *pb.FunctionCatalog {
	var pgCatalog []string
	for _, r := range routines {
		if r.GetSchema() == "pg_catalog" {
			pgCatalog = append(pgCatalog, r.GetNames()...)
		}
	}
	pgCatalog = distinct(append(pgCatalog, postgresGrammarFunctions...))
	catalog := &pb.FunctionCatalog{
		BuiltinFunctions:      pgCatalog,
		SystemFunctionSchemas: []*pb.SchemaFunctions{{Schema: "pg_catalog", Names: pgCatalog}},
	}
	for _, r := range routines {
		schema := SchemaName{name: r.GetSchema()}
		switch {
		case r.GetSchema() == "pg_catalog":
		case slices.Contains(e.systemSchemas, schema):
			catalog.SystemFunctionSchemas = append(catalog.SystemFunctionSchemas, &pb.SchemaFunctions{Schema: r.GetSchema(), Names: r.GetNames()})
		case !e.IsSystemSchema(schema):
			catalog.UdfSchemas = append(catalog.UdfSchemas, &pb.SchemaFunctions{Schema: r.GetSchema(), Names: r.GetNames()})
		}
	}
	return catalog
}

var postgresVersionPattern = regexp.MustCompile(`PostgreSQL\s+(\d+(?:\.\d+)?)`)

var numericVersion = regexp.MustCompile(`\d+(?:\.\d+)?`)

// "PostgreSQL 16.4 on x86_64" -> 16.4.
func postgresServerVersion(raw string) *pb.ServerVersion {
	if strings.TrimSpace(raw) == "" {
		return &pb.ServerVersion{}
	}
	version := ""
	if m := postgresVersionPattern.FindStringSubmatch(raw); m != nil {
		version = m[1]
	} else {
		version = numericVersion.FindString(raw)
	}
	return &pb.ServerVersion{Version: nonEmpty(version), Aurora: isAurora(raw)}
}

var functionLabelPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// searchPath is the session's schemas as the proxy read them from the target.
func (e *postgresSession) catalogFirstAfterTempSchemas(searchPath []string) bool {
	for _, s := range searchPath {
		schema := e.datasource.IntrospectedSchema(&pb.Column{Schema: s})
		if e.datasource.IsTempSchema(schema) {
			continue
		}
		return schema == e.datasource.BuiltinSchema
	}
	return false
}
