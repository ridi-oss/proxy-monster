package engines

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/optimizer"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

var BigQuery = &Engine{
	WireName: "bigquery", Proto: pb.Engine_BIGQUERY,
	DefaultProxyPort: 6444, DefaultTargetPort: 443,
	Traits: EngineTraits{
		IdentifierQuote:    "`",
		catalogName:        func(project string) CatalogName { return CatalogName{project} },
		catalogColumnNames: bigqueryCatalogColumnNames,
		targetDialect: func(*pb.TargetSettings) (*dialects.Dialect, sessionDialect, error) {
			d := dialects.BigQuery()
			return d, func(observation *pb.SessionObservation) (*dialects.Dialect, error) {
				return d, checkBigQueryObservation(observation)
			}, nil
		},
		bareCallIsBuiltin:         noBuiltinBareCall,
		showUtilityCommand:        func(exp.Expression) string { return "" },
		isSafeTypeReference:       noSafeTypeReference,
		systemSchemaFirst:         noSystemSchemaFirst,
		nativeOutputLabel:         bigqueryNativeOutputLabel,
		diagnosticLeakKeys:        referencedColumnLeakKeys,
		foldColumn:                bigqueryColumn,
		allowsCrossCatalog:        true,
		preservesCatalogQualifier: true,
		syntaxCalls:               []string{"array"},
		unlistedCalls:             map[exp.Kind]string{exp.KindAIEmbed: "ai.embed", exp.KindAIGenerate: "ai.generate", exp.KindAISimilarity: "ai.similarity"},

		connectionProperties:           []string{"project", "location", "dataset"},
		catalogIsConnectionIndependent: true,
		defaultSchema:                  func(registeredDbName string) string { return registeredDbName },
		serverVersion:                  func(string) *pb.ServerVersion { return &pb.ServerVersion{} },
		manifestSeries:                 func(version string) string { return version },
		functionCatalog:                bigqueryFunctionCatalog,
		connectionPropertyPatterns:     map[string]*regexp.Regexp{"project": bigqueryProject, "location": bigqueryLocation},
		endpointIsURL:                  true,
		defaultSession:                 bigqueryDefaultSession,
	},
	hooks: bigqueryHooks{},
}

var bigqueryDialect = dialects.BigQuery()

// bigqueryColumn folds a column name; datasets and tables keep their case: Users.Email -> Users.email.
func bigqueryColumn(name string) string { return bigqueryDialect.FoldIdentifierName(name, false) }

func bigqueryCatalogColumnNames(_ *dialects.Dialect, rows []*pb.Column) []ColumnName {
	out := make([]ColumnName, len(rows))
	for i, row := range rows {
		out[i] = ColumnName{CatalogName{row.GetCatalog()}, SchemaName{row.GetSchema()}, row.GetTable(), bigqueryColumn(row.GetColumn())}
	}
	return out
}

// GoogleSQL addresses any project from one job, so the project stays in the executable SQL. A query is one
// jobs.query or jobs.insert call: its typed parameters arrive as literals and are bound into the tree, and
// the editor row cap becomes a LIMIT.
func checkBigQueryObservation(observation *pb.SessionObservation) error {
	if strings.TrimSpace(observation.GetBigquery().GetProject()) == "" {
		return fmt.Errorf("BigQuery job project is required")
	}
	return nil
}

type bigqueryHooks struct{ sharedHooks }

// prepareStatement binds the request's parameters, named (@id) or positional (?), never both. A bound
// statement is always regenerated, so the proxy submits it without the client's parameter list.
func (bigqueryHooks) prepareStatement(session *Session, root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
	parameters := session.observation.GetBigquery().GetParameters()
	if root.Kind() == exp.KindSemicolon {
		if len(parameters) != 0 {
			return nil, false, nil, fmt.Errorf("empty SQL cannot carry query parameters")
		}
		return root, false, nil, nil
	}
	if err := bindBigQueryParameters(root, parameters, session); err != nil {
		return nil, false, nil, err
	}
	return root, len(parameters) > 0, nil, nil
}

func (bigqueryHooks) finishSubmission(session *Session, submission exp.Expression) bool {
	maxRows := session.observation.GetBigquery().GetMaxRows()
	return maxRows > 0 && capAthenaRows(submission, maxRows)
}

func (bigqueryHooks) stampSubmission(facts *pb.StatementFacts) {
	facts.Submission = &pb.Submission{Engine: &pb.Submission_Bigquery{Bigquery: &pb.BigQuerySubmission{}}}
}

// configureNamespace resolves `ds.t` in the job project and `t` in the request's default dataset, which may
// live in another project; without one, `t` resolves in the registered dataset.
func (bigqueryHooks) configureNamespace(session *Session, opts *optimizer.QualifyOpts, namespace NamespaceConfig) {
	if len(namespace.SearchPath) != 1 {
		panic("BigQuery requires one default dataset")
	}
	opts.Catalog = namespace.Catalog
	opts.DefaultSchema = namespace.SearchPath[0]
	sqlContext := session.observation.GetBigquery()
	if sqlContext.GetDefaultDatasetId() == "" {
		return
	}
	opts.DefaultSchema = sqlContext.GetDefaultDatasetId()
	if project := sqlContext.GetDefaultDatasetProjectId(); project != "" && project != namespace.Catalog {
		opts.DefaultSchemaCatalog = project
	}
}

// bindBigQueryParameters replaces each @name or ? with its literal; a system variable (`@@dataset_id`)
// denies.
func bindBigQueryParameters(root exp.Expression, parameters []*pb.BigQueryParameter, session *Session) error {
	named := map[string]exp.Expression{}
	var positional []exp.Expression
	for _, parameter := range parameters {
		expressions, err := parameterExpressions(parameter.GetValue(), session)
		if err != nil {
			return err
		}
		if len(expressions) != 1 {
			return fmt.Errorf("expected one expression per query parameter")
		}
		if parameter.GetName() == "" {
			positional = append(positional, expressions[0])
			continue
		}
		key := strings.ToLower(parameter.GetName())
		if _, duplicate := named[key]; duplicate {
			return fmt.Errorf("duplicate query parameter %q", parameter.GetName())
		}
		named[key] = expressions[0]
	}
	if len(named) > 0 && len(positional) > 0 {
		return fmt.Errorf("query parameters must be all named or all positional")
	}
	placeholders := root.FindAll(exp.KindPlaceholder)
	if len(placeholders) != len(positional) {
		return fmt.Errorf("expected %d positional query parameters, got %d", len(placeholders), len(positional))
	}
	ordered, err := spanOrder(placeholders)
	if err != nil {
		return err
	}
	for i, placeholder := range ordered {
		placeholder.Replace(boundValue(positional[i]))
	}
	for _, parameter := range root.FindAll(exp.KindParameter) {
		name, ok := parameter.Arg("this").(exp.Expression)
		if !ok || name.Kind() == exp.KindParameter || parameter.Parent() != nil && parameter.Parent().Kind() == exp.KindParameter {
			return fmt.Errorf("system variables are not supported")
		}
		value, ok := named[strings.ToLower(name.Name())]
		if !ok {
			return fmt.Errorf("query parameter @%s is not supplied", name.Name())
		}
		parameter.Replace(boundValue(value))
	}
	return nil
}

// boundValue keeps a literal bare, since LIMIT and OFFSET take only a literal, and parenthesizes the rest.
func boundValue(value exp.Expression) exp.Expression {
	if value.Kind() == exp.KindLiteral {
		return value.Copy()
	}
	return exp.Paren(exp.Args{"this": value.Copy()})
}

// spanOrder sorts nodes by their position in the source; a node without a span fails closed.
func spanOrder(nodes []exp.Expression) ([]exp.Expression, error) {
	starts := make(map[exp.Expression]int, len(nodes))
	for _, node := range nodes {
		start, _, ok := node.Span()
		if !ok {
			return nil, fmt.Errorf("parameter position is not proven")
		}
		starts[node] = start
	}
	ordered := slices.Clone(nodes)
	slices.SortFunc(ordered, func(a, b exp.Expression) int { return starts[a] - starts[b] })
	return ordered, nil
}

// BigQuery names an unaliased computed column f0_, f1_ by a counter the generated SQL cannot reproduce, so
// only a column reference has a known label.
func bigqueryNativeOutputLabel(_ *Session, projection, _ exp.Expression) (string, bool) {
	if projection.Kind() == exp.KindColumn {
		return projection.Name(), true
	}
	return "", false
}

var bigqueryNatives = nativeFunctions("bigquery", "1")

func bigqueryFunctionCatalog(_ *Engine, routines []*pb.SchemaFunctions, _ string) *pb.FunctionCatalog {
	return &pb.FunctionCatalog{BuiltinFunctions: slices.Clone(bigqueryNatives), UdfSchemas: routines}
}

var (
	// my-project, or a domain-scoped example.com:my-project.
	bigqueryProject = regexp.MustCompile(`^(?:[a-z0-9.-]+:)?[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	// US, eu, asia-northeast3, or an Omni aws-us-east-1.
	bigqueryLocation = regexp.MustCompile(`^(?i:us|eu)$|^[a-z]+(?:-[a-z0-9]+)+$`)
)

// bigqueryDefaultSession is the datasource's registered project and dataset, with no parameters.
func bigqueryDefaultSession(targetSettings *pb.TargetSettings) *pb.SessionObservation {
	properties := targetSettings.GetProperties()
	return &pb.SessionObservation{Engine: &pb.SessionObservation_Bigquery{Bigquery: &pb.BigQuerySqlContext{
		Project: properties["project"], DefaultDatasetId: properties["dataset"],
	}}}
}
