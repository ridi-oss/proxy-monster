package probe

import (
	"fmt"
	"strings"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/optimizer"
	"github.com/ridi-oss/sqlglot-go/schema"
)

// athenaEngine speaks Trino for DML and Hive for DDL. Unlike MySQL and PostgreSQL it addresses many catalogs
// from one session, so cross-catalog references resolve and the catalog stays in the executable SQL. A
// query is one StartQueryExecution call: the request's positional parameters are bound into the tree before
// analysis, EXECUTE resolves to the workgroup-stored definition, and the editor row cap becomes a LIMIT.
type athenaEngine struct {
	dialect *dialects.Dialect
	scope   *pb.AthenaSqlContext
}

func newAthenaEngine(config *pb.EngineConfig) (*athenaEngine, error) {
	scope := config.GetSession().GetAthena()
	if scope == nil || strings.TrimSpace(scope.GetWorkgroup()) == "" {
		return nil, fmt.Errorf("Athena workgroup scope is required")
	}
	return &athenaEngine{dialect: dialects.Athena(), scope: scope}, nil
}

// PrepareStatement binds ExecutionParameters into the statement's `?` placeholders in SQL order so lineage
// runs on the bound text, and resolves EXECUTE against a supplied prepared definition or asks for the one
// it needs. An empty statement carries no parameters.
func (e *athenaEngine) PrepareStatement(root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
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
func (e *athenaEngine) FinishSubmission(submission exp.Expression) bool {
	return e.scope.GetMaxRows() > 0 && capAthenaRows(submission, e.scope.GetMaxRows())
}

// StampSubmission: binding folded every parameter into the text, so the list the proxy submits is empty.
func (e *athenaEngine) StampSubmission(facts *pb.StatementFacts) {
	facts.Submission = &pb.Submission{Engine: &pb.Submission_Athena{Athena: &pb.AthenaSubmission{}}}
}

func (e *athenaEngine) WireName() string                { return "athena" }
func (e *athenaEngine) Dialect() *dialects.Dialect      { return e.dialect }
func (e *athenaEngine) NormalizeCatalogOnBuild() bool   { return true }
func (e *athenaEngine) AllowsCrossCatalog() bool        { return true }
func (e *athenaEngine) PreservesCatalogQualifier() bool { return true }
func (e *athenaEngine) ConfigureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig) {
	if len(namespace.SearchPath) != 1 {
		panic("Athena requires one current database")
	}
	opts.Catalog = namespace.Catalog
	opts.DefaultSchema = namespace.SearchPath[0]
}

func (e *athenaEngine) FoldColumn(column string) string {
	return e.dialect.FoldIdentifierName(column, false)
}
func (e *athenaEngine) IsTempSchema(exp.Expression) bool                           { return false }
func (e *athenaEngine) IsTrustedSystemQualifier(exp.Expression) bool               { return false }
func (e *athenaEngine) RewriteStatement(exp.Expression) string                     { return "" }
func (e *athenaEngine) IsTrustedInformationSchemaCall(exp.Expression, string) bool { return false }
func (e *athenaEngine) CommandPassthrough(string) bool                             { return false }
func (e *athenaEngine) RejectsDuplicateDerivedOutputLabels() bool                  { return false }
func (e *athenaEngine) RightJoinStarOrder() starOrder                              { return starOrderCommonLeftRight }

// Athena has no builtin function tables and no search path, so a bare call never resolves in a system schema.
func (e *athenaEngine) BuiltinFunctionRow(string) []string { return nil }
func (e *athenaEngine) BareCallIsBuiltin(string) bool      { return false }
func (e *athenaEngine) SystemSchemaFirst([]string) bool    { return false }
func (e *athenaEngine) PostgresSystemXIDVisible() bool     { return false }
func (e *athenaEngine) IsSafeTypeReference(exp.Expression, exp.Expression, NamespaceConfig) bool {
	return false
}
func (e *athenaEngine) DiagnosticLeakKeys(report ProbeResult, _ schema.Schema) map[string]bool {
	return referencedColumnKeys(report)
}

func (e *athenaEngine) ShowUtilityCommand(root exp.Expression) string {
	if root.Text("this") == "PARTITIONS" {
		return "SHOW_PARTITIONS"
	}
	return ""
}

func (e *athenaEngine) NativeOutputLabel(projection, query exp.Expression) (string, bool) {
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
