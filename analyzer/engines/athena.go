package engines

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/generator"
	"github.com/ridi-oss/sqlglot-go/optimizer"
	"github.com/ridi-oss/sqlglot-go/schema"
	"github.com/ridi-oss/sqlglot-go/tokens"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// athenaAnalyzer speaks Trino for DML and Hive for DDL. Unlike MySQL and PostgreSQL it addresses many catalogs
// from one session, so cross-catalog references resolve and the catalog stays in the executable SQL. A
// query is one StartQueryExecution call: the request's positional parameters are bound into the tree before
// analysis, EXECUTE resolves to the workgroup-stored definition, and the editor row cap becomes a LIMIT.
type athenaAnalyzer struct {
	dialect *dialects.Dialect
	scope   *pb.AthenaSqlContext
}

func newAthenaAnalyzer(config *pb.EngineConfig) (*athenaAnalyzer, error) {
	scope := config.GetSession().GetAthena()
	if scope == nil || strings.TrimSpace(scope.GetWorkgroup()) == "" {
		return nil, fmt.Errorf("Athena workgroup scope is required")
	}
	return &athenaAnalyzer{dialect: dialects.Athena(), scope: scope}, nil
}

// PrepareStatement binds ExecutionParameters into the statement's `?` placeholders in SQL order so lineage
// runs on the bound text, and resolves EXECUTE against a supplied prepared definition or asks for the one
// it needs. An empty statement carries no parameters.
func (e *athenaAnalyzer) PrepareStatement(root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
	parameters := append([]string(nil), e.scope.GetExecutionParameters()...)
	if root.Kind() == exp.KindSemicolon {
		if len(parameters) != 0 {
			return nil, false, nil, fmt.Errorf("empty SQL cannot carry execution parameters")
		}
		return root, false, nil, nil
	}
	regenerate := len(parameters) > 0
	if root.Kind() == exp.KindCommand && root.Keyword() == "EXECUTE" {
		name, using, err := athenaExecute(root, e)
		if err != nil {
			return nil, false, nil, err
		}
		if len(parameters) > 0 {
			return nil, false, nil, fmt.Errorf("EXECUTE cannot also carry execution parameters")
		}
		var definition *pb.AthenaPreparedDefinition
		for _, candidate := range e.scope.GetPreparedDefinitions() {
			if candidate.GetName() == name && candidate.GetWorkgroup() == e.scope.GetWorkgroup() {
				if definition != nil {
					return nil, false, nil, fmt.Errorf("duplicate prepared definition")
				}
				definition = candidate
			}
		}
		if definition == nil {
			facts := unanalyzableFacts("VALIDATE", "prepared definition is required")
			facts.AthenaPreparedDefinitionNeed = &pb.AthenaPreparedDefinitionNeed{Workgroup: e.scope.GetWorkgroup(), Name: name}
			return nil, false, facts, nil
		}
		if root, err = singleStatement(definition.GetQueryString(), e); err != nil {
			return nil, false, nil, err
		}
		if root.Kind() == exp.KindCommand {
			return nil, false, nil, fmt.Errorf("prepared definition is not a structured statement")
		}
		parameters = using
		regenerate = true
	}
	if err := bindAthenaParameters(root, parameters, e); err != nil {
		return nil, false, nil, err
	}
	return root, regenerate, nil, nil
}

// FinishSubmission caps the submitted query at the editor's max_rows: Athena has no session row cap, so an
// uncapped SELECT would scan and store the whole result before the proxy truncates it.
func (e *athenaAnalyzer) FinishSubmission(submission exp.Expression) bool {
	return e.scope.GetMaxRows() > 0 && capAthenaRows(submission, e.scope.GetMaxRows())
}

// StampSubmission: binding folded every parameter into the text, so the list the proxy submits is empty.
func (e *athenaAnalyzer) StampSubmission(facts *pb.StatementFacts) {
	facts.Submission = &pb.Submission{Engine: &pb.Submission_Athena{Athena: &pb.AthenaSubmission{}}}
}

func (e *athenaAnalyzer) WireName() string { return "athena" }

func (e *athenaAnalyzer) Dialect() *dialects.Dialect { return e.dialect }

func (e *athenaAnalyzer) NormalizeCatalogOnBuild() bool { return true }

func (e *athenaAnalyzer) AllowsCrossCatalog() bool { return true }

func (e *athenaAnalyzer) PreservesCatalogQualifier() bool { return true }

func (e *athenaAnalyzer) ConfigureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig) {
	if len(namespace.SearchPath) != 1 {
		panic("Athena requires one current database")
	}
	opts.Catalog = namespace.Catalog
	opts.DefaultSchema = namespace.SearchPath[0]
}

func (e *athenaAnalyzer) FoldColumn(column string) string {
	return e.dialect.FoldIdentifierName(column, false)
}

func (e *athenaAnalyzer) IsTempSchema(exp.Expression) bool { return false }

func (e *athenaAnalyzer) IsTrustedSystemQualifier(exp.Expression) bool { return false }

func (e *athenaAnalyzer) RewriteStatement(exp.Expression) string { return "" }

func (e *athenaAnalyzer) IsTrustedInformationSchemaCall(exp.Expression, string) bool { return false }

func (e *athenaAnalyzer) CommandPassthrough(string) bool { return false }

func (e *athenaAnalyzer) RejectsDuplicateDerivedOutputLabels() bool { return false }

func (e *athenaAnalyzer) RightJoinStarOrder() starOrder { return starOrderCommonLeftRight }

// Athena has no builtin function tables and no search path, so a bare call never resolves in a system schema.
func (e *athenaAnalyzer) BuiltinFunctionRow(string) []string { return nil }

func (e *athenaAnalyzer) BareCallIsBuiltin(string) bool { return false }

func (e *athenaAnalyzer) SystemSchemaFirst([]string) bool { return false }

func (e *athenaAnalyzer) PostgresSystemXIDVisible() bool { return false }

func (e *athenaAnalyzer) IsSafeTypeReference(exp.Expression, exp.Expression, NamespaceConfig) bool {
	return false
}

func (e *athenaAnalyzer) DiagnosticLeakKeys(report ProbeResult, _ schema.Schema) map[string]bool {
	return referencedColumnKeys(report)
}

func (e *athenaAnalyzer) ShowUtilityCommand(root exp.Expression) string {
	if root.Text("this") == "PARTITIONS" {
		return "SHOW_PARTITIONS"
	}
	return ""
}

func (e *athenaAnalyzer) NativeOutputLabel(projection, query exp.Expression) (string, bool) {
	// Result labels do not make unnamed derived-table fields addressable.
	if _, derived := derivedBodySelects(query.Root())[query]; derived {
		return "", false
	}
	for i, candidate := range query.Selects() {
		if candidate == projection || candidate.Kind() == exp.KindAlias && candidate.This() == projection {
			return fmt.Sprintf("_col%d", i), true
		}
	}
	return "", false
}

func athenaParameterExpressions(sql string, eng analyzer) ([]exp.Expression, error) {
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

func bindAthenaParameters(root exp.Expression, parameters []string, eng analyzer) error {
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

func athenaExecute(root exp.Expression, eng analyzer) (string, []string, error) {
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
