// PostgreSQL's implicit output-label rules, ported from FigureColname/FigureColnameInternal in
// the server's parser (src/backend/parser/parse_target.c) and verified against a live PostgreSQL
// 16: a call is labeled by its written function name, a cast overrides only a weak inner name
// (strength ≤ 1), CASE takes its ELSE's name, a scalar subquery its single output's resname, and
// anything nameless falls back to "?column?".
package probe

import (
	"strings"

	exp "github.com/ridi-oss/sqlglot-go/expressions"
)

// normalizedFunctionName is a call's name folded through the dialect's quote-aware
// NormalizeIdentifier — an unquoted spelling lowercases, a quoted one keeps its case.
func normalizedFunctionName(function exp.Expression, eng engine) string {
	if identifier, ok := function.Arg("this").(exp.Expression); ok && identifier.Kind() == exp.KindIdentifier {
		identifier = identifier.Copy()
		eng.Dialect().NormalizeIdentifier(identifier)
		return identifier.Name()
	}
	return strings.ToLower(function.Name())
}

// nativeOutputLabel is FigureColname for one projection: the label PostgreSQL assigns to an
// unaliased output, with the no-name fallback applied. query is the SELECT the projection belongs
// to, for resolving references to its derived sources. ok=false means the label is unknowable —
// the caller must not stamp.
func nativeOutputLabel(node exp.Expression, query exp.Expression, eng engine, depth int) (string, bool) {
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
func figureLabel(node exp.Expression, query exp.Expression, eng engine, depth int) (string, int, bool) {
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
func figureProjectionLabel(projection exp.Expression, query exp.Expression, eng engine, depth int) (string, int, bool) {
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
func subqueryLabel(subquery exp.Expression, eng engine, depth int) (string, int, bool) {
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

// leftmostSelect unwraps parens/subqueries and takes a set operation's first branch — the branch
// PostgreSQL takes output names from.
func leftmostSelect(node exp.Expression) exp.Expression {
	for node != nil {
		switch {
		case node.Kind() == exp.KindSelect:
			return node
		case node.Kind() == exp.KindSubquery || node.Kind() == exp.KindParen:
			node = node.This()
		case node.Is(exp.TraitSetOperation):
			node = node.Left()
		default:
			return nil
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
