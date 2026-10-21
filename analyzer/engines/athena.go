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
	"github.com/ridi-oss/sqlglot-go/tokens"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

var Athena = &Engine{
	WireName: "athena", Proto: pb.Engine_ATHENA,
	DefaultProxyPort: 6443, DefaultTargetPort: 443,
	Traits: EngineTraits{
		IdentifierQuote: `"`,
		systemSchemas:   schemas("information_schema"),
		// Athena resolves catalog names case-insensitively.
		catalogName:    func(registeredDbName string) CatalogName { return CatalogName{athenaName(registeredDbName)} },
		introspected:   athenaIntrospected,
		dialect:        dialects.Athena,
		sessionDialect: athenaSessionDialect,
		// Athena has no search path, so a bare call never resolves in a system schema.
		bareCallIsBuiltin:   noBuiltinBareCall,
		showUtilityCommand:  athenaShowUtilityCommand,
		isSafeTypeReference: noSafeTypeReference,
		systemSchemaFirst:   noSystemSchemaFirst,
		nativeOutputLabel:   athenaNativeOutputLabel,
		diagnosticLeakKeys:  referencedColumnLeakKeys,
		normalizeRules: func() normalizeRules {
			return normalizeRules{dialect: dialects.Athena(), foldIdentifiers: true}
		},
		foldColumn:                athenaName,
		normalizeCatalogOnBuild:   true,
		allowsCrossCatalog:        true,
		preservesCatalogQualifier: true,
	},
	hooks: athenaHooks{},
}

var athenaDialect = dialects.Athena()

// athenaName folds a name as Athena resolves it, case-insensitively: AwsDataCatalog -> awsdatacatalog.
func athenaName(name string) string { return athenaDialect.FoldIdentifierName(name, false) }

// athenaIntrospected folds every part of a catalog row: AwsDataCatalog.HR.Salaries.SSN ->
// awsdatacatalog.hr.salaries.ssn.
func athenaIntrospected(_ *dialects.Dialect, rows []*pb.Column) []ColumnName {
	out := make([]ColumnName, len(rows))
	for i, row := range rows {
		out[i] = ColumnName{CatalogName{athenaName(row.GetCatalog())}, SchemaName{athenaName(row.GetSchema())}, athenaName(row.GetTable()), athenaName(row.GetColumn())}
	}
	return out
}

// Athena speaks Trino for DML and Hive for DDL. Unlike MySQL and PostgreSQL it addresses many catalogs
// from one session, so cross-catalog references resolve and the catalog stays in the executable SQL. A
// query is one StartQueryExecution call: the request's positional parameters are bound into the tree before
// analysis, EXECUTE resolves to the workgroup-stored definition, and the editor row cap becomes a LIMIT.
func athenaSessionDialect(datasource Datasource, observation *pb.SessionObservation) (*dialects.Dialect, error) {
	if strings.TrimSpace(observation.GetAthena().GetWorkgroup()) == "" {
		return nil, fmt.Errorf("Athena workgroup scope is required")
	}
	return datasource.Dialect(), nil
}

type athenaHooks struct{ sharedHooks }

// prepareStatement binds ExecutionParameters into the statement's `?` placeholders in SQL order so lineage
// runs on the bound text, and resolves EXECUTE against a supplied prepared definition or asks for the one
// it needs. An empty statement carries no parameters.
func (athenaHooks) prepareStatement(settings *sessionSettings, root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
	sqlContext := settings.observation.GetAthena()
	parameters := append([]string(nil), sqlContext.GetExecutionParameters()...)
	if root.Kind() == exp.KindSemicolon {
		if len(parameters) != 0 {
			return nil, false, nil, fmt.Errorf("empty SQL cannot carry execution parameters")
		}
		return root, false, nil, nil
	}
	regenerate := len(parameters) > 0
	if root.Kind() == exp.KindCommand && root.Keyword() == "EXECUTE" {
		name, using, err := athenaExecute(root, settings)
		if err != nil {
			return nil, false, nil, err
		}
		if len(parameters) > 0 {
			return nil, false, nil, fmt.Errorf("EXECUTE cannot also carry execution parameters")
		}
		var definition *pb.AthenaPreparedDefinition
		for _, candidate := range sqlContext.GetPreparedDefinitions() {
			if candidate.GetName() == name && candidate.GetWorkgroup() == sqlContext.GetWorkgroup() {
				if definition != nil {
					return nil, false, nil, fmt.Errorf("duplicate prepared definition")
				}
				definition = candidate
			}
		}
		if definition == nil {
			facts := unanalyzableFacts("VALIDATE", "prepared definition is required")
			facts.AthenaPreparedDefinitionNeed = &pb.AthenaPreparedDefinitionNeed{Workgroup: sqlContext.GetWorkgroup(), Name: name}
			return nil, false, facts, nil
		}
		if root, err = singleStatement(definition.GetQueryString(), settings); err != nil {
			return nil, false, nil, err
		}
		if root.Kind() == exp.KindCommand {
			return nil, false, nil, fmt.Errorf("prepared definition is not a structured statement")
		}
		parameters = using
		regenerate = true
	}
	if err := bindAthenaParameters(root, parameters, settings); err != nil {
		return nil, false, nil, err
	}
	return root, regenerate, nil, nil
}

// finishSubmission caps the submitted query at the editor's max_rows: Athena has no session row cap, so an
// uncapped SELECT would scan and store the whole result before the proxy truncates it.
func (athenaHooks) finishSubmission(settings *sessionSettings, submission exp.Expression) bool {
	maxRows := settings.observation.GetAthena().GetMaxRows()
	return maxRows > 0 && capAthenaRows(submission, maxRows)
}

// stampSubmission: binding folded every parameter into the text, so the list the proxy submits is empty.
func (athenaHooks) stampSubmission(facts *pb.StatementFacts) {
	facts.Submission = &pb.Submission{Engine: &pb.Submission_Athena{Athena: &pb.AthenaSubmission{}}}
}

func (athenaHooks) configureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig) {
	if len(namespace.SearchPath) != 1 {
		panic("Athena requires one current database")
	}
	opts.Catalog = namespace.Catalog
	opts.DefaultSchema = namespace.SearchPath[0]
}

func athenaShowUtilityCommand(root exp.Expression) string {
	if root.Text("this") == "PARTITIONS" {
		return "SHOW_PARTITIONS"
	}
	return ""
}

func athenaNativeOutputLabel(_ *sessionSettings, projection, query exp.Expression) (string, bool) {
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

func athenaParameterExpressions(sql string, settings *sessionSettings) ([]exp.Expression, error) {
	root, err := singleStatement("SELECT "+sql, settings)
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

func bindAthenaParameters(root exp.Expression, parameters []string, settings *sessionSettings) error {
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
		expressions, err := athenaParameterExpressions(parameters[i], settings)
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

func athenaExecute(root exp.Expression, settings *sessionSettings) (string, []string, error) {
	if root.Expr() == nil {
		return "", nil, fmt.Errorf("prepared statement name is required")
	}
	tail := root.Expr().Name()
	parsed, err := settings.dialect.NewTokenizer().Tokenize(tail)
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
	expressions, err := athenaParameterExpressions(string(runes[parsed[2].Start:]), settings)
	if err != nil {
		return "", nil, err
	}
	parameters := make([]string, len(expressions))
	for i, expression := range expressions {
		parameters[i], err = sqlglot.Generate(expression, settings.dialect, generator.Options{})
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
