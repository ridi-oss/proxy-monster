package probe

import (
	"fmt"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/optimizer"
	"github.com/ridi-oss/sqlglot-go/schema"
)

type athenaEngine struct {
	dialect *dialects.Dialect
}

func newAthenaEngine(*pb.EngineConfig) (*athenaEngine, error) {
	return &athenaEngine{dialect: dialects.Athena()}, nil
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

var athenaSafeNoFromFunctions = stringSet(
	"current_catalog", "current_schema", "current_user", "current_date", "current_time",
	"current_timestamp", "localtime", "localtimestamp", "now", "version",
	"abs", "ceil", "ceiling", "floor", "round", "mod", "power", "pow", "sqrt",
	"exp", "ln", "log", "log10", "log2", "sign", "pi", "degrees", "radians",
	"sin", "cos", "tan", "asin", "acos", "atan", "atan2", "rand", "random", "uuid",
	"length", "lower", "upper", "trim", "ltrim", "rtrim", "lpad", "rpad", "substr",
	"substring", "concat", "concat_ws", "replace", "reverse", "split_part",
	"cast", "coalesce", "nullif", "greatest", "least", "if", "typeof",
)

func (e *athenaEngine) IsSafeNoFromFunction(name string) bool {
	return athenaSafeNoFromFunctions[name]
}
