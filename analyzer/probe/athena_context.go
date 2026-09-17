package probe

import (
	"fmt"
	"sort"
	"strconv"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/generator"
	"github.com/ridi-oss/sqlglot-go/tokens"
)

func athenaParameterExpressions(sql string, eng engine) ([]exp.Expression, error) {
	root, err := singleStatement("SELECT "+sql, eng)
	if err != nil {
		return nil, err
	}
	if root.Kind() != exp.KindSelect || len(root.Selects()) == 0 ||
		!root.Equal(exp.Select(exp.Args{"expressions": root.Selects()})) {
		return nil, fmt.Errorf("expected SQL parameter expressions")
	}
	for _, expression := range root.Selects() {
		if expression.Kind() == exp.KindAlias || expression.Find(exp.KindPlaceholder) != nil ||
			expression.Find(exp.KindParameter) != nil || expression.Find(exp.KindSessionParameter) != nil ||
			expression.Find(exp.KindColumn) != nil || expression.Find(exp.TraitQuery) != nil || expression.Find(exp.KindStar) != nil {
			return nil, fmt.Errorf("parameter is not a scalar expression")
		}
	}
	return root.Selects(), nil
}

func bindAthenaParameters(root exp.Expression, parameters []string, eng engine) error {
	if root.Find(exp.KindParameter) != nil || root.Find(exp.KindSessionParameter) != nil {
		return fmt.Errorf("Athena requires positional question-mark parameters")
	}
	placeholders := root.FindAll(exp.KindPlaceholder)
	if len(placeholders) != len(parameters) {
		return fmt.Errorf("expected %d execution parameters, got %d", len(placeholders), len(parameters))
	}
	positions := make(map[exp.Expression]int, len(placeholders))
	for _, placeholder := range placeholders {
		start, end, ok := placeholder.Span()
		text, hasText := placeholder.SpanText()
		if !ok || end != start+1 || !hasText || text != "?" || placeholder.Arg("this") != nil {
			return fmt.Errorf("parameter position is not proven")
		}
		positions[placeholder] = start
		inWhere := false
		for parent := placeholder.Parent(); parent != nil; parent = parent.Parent() {
			if parent.Kind() == exp.KindWhere {
				inWhere = true
				break
			}
			if parent.Is(exp.TraitQuery) {
				break
			}
		}
		if !inWhere {
			return fmt.Errorf("Athena parameters must occur in WHERE")
		}
	}
	sort.Slice(placeholders, func(i, j int) bool { return positions[placeholders[i]] < positions[placeholders[j]] })
	for i, placeholder := range placeholders {
		expressions, err := athenaParameterExpressions(parameters[i], eng)
		if err != nil {
			return err
		}
		if len(expressions) != 1 {
			return fmt.Errorf("expected one expression per execution parameter")
		}
		placeholder.Replace(exp.Paren(exp.Args{"this": expressions[0].Copy()}))
	}
	return nil
}

func athenaExecute(root exp.Expression, eng engine) (string, []string, error) {
	if root.Expr() == nil {
		return "", nil, fmt.Errorf("prepared statement name is required")
	}
	tail := root.Expr().Name()
	parsed, err := eng.Dialect().NewTokenizer().Tokenize(tail)
	if err != nil || len(parsed) == 0 || (parsed[0].TokenType != tokens.VAR && parsed[0].TokenType != tokens.IDENTIFIER) {
		return "", nil, fmt.Errorf("invalid prepared statement name")
	}
	name := parsed[0].Text
	if len(parsed) == 1 {
		return name, nil, nil
	}
	if len(parsed) < 3 || parsed[1].TokenType != tokens.USING {
		return "", nil, fmt.Errorf("expected EXECUTE name USING expressions")
	}
	runes := []rune(tail)
	expressions, err := athenaParameterExpressions(string(runes[parsed[2].Start:]), eng)
	if err != nil {
		return "", nil, err
	}
	parameters := make([]string, len(expressions))
	for i, expression := range expressions {
		parameters[i], err = sqlglot.Generate(expression, eng.Dialect(), generator.Options{})
		if err != nil {
			return "", nil, err
		}
	}
	return name, parameters, nil
}

// capAthenaRows adds LIMIT maxRows to a top-level query that has none or a larger literal one. Athena has no
// session row cap, so an uncapped SELECT would scan and store the whole result before the proxy truncates it.
func capAthenaRows(root exp.Expression, maxRows uint32) bool {
	if root == nil || !root.Is(exp.TraitQuery) {
		return false
	}
	limit, _ := root.Arg("limit").(exp.Expression)
	if limit != nil {
		current, _ := limit.Arg("expression").(exp.Expression)
		if current == nil || !current.IsNumber() {
			return false
		}
		value, err := strconv.ParseUint(current.Name(), 10, 32)
		if err != nil || value <= uint64(maxRows) {
			return false
		}
		limit.Set("expression", exp.LiteralNumber(int64(maxRows)))
		return true
	}
	root.Set("limit", exp.Limit(exp.Args{"expression": exp.LiteralNumber(int64(maxRows))}))
	return true
}
