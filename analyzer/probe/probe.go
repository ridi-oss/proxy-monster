package probe

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

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

const (
	PREDICATE = "PREDICATE"
	JOIN      = "JOIN"
	GROUP_BY  = "GROUP_BY"
	ORDER_BY  = "ORDER_BY"
	AGGREGATE = "AGGREGATE"
	SUBQUERY  = "SUBQUERY"
	SET_OP    = "SET_OP"
	RECURSIVE = "RECURSIVE"
	DERIVED   = "DERIVED"
	OTHER     = "OTHER"
)

type OriginInfo struct {
	Column  string   `json:"column"`
	Origins []string `json:"origins"`
	// Derived is true when Column is a computed expression over Origins (e.g. upper(ssn)), not a
	// direct projection. Enforcement redacts a masked base column here in full, rather than denying.
	Derived bool `json:"derived,omitempty"`
}

// SourceInfo is one physical target-DB relation the statement scans (docs/facts-emission.md).
// `Table` is the fully-qualified `catalog.schema.table` identity. `Covered` is true when at least one
// traced column fact (an origin base or a reference) names this table — meaning the existing column
// authorization already gates the scan. An UNCOVERED table (Covered=false) is a scan that reads the
// relation while tracing zero of its columns (`count(*)`, `SELECT 1`, `EXISTS`, a cross-join side that
// only multiplies cardinality); its existence/row-count leaks unless a `result.read` grant covers the
// Table resource, so the control-plane must gate it. Coverage is per-TABLE (not per scan occurrence):
// once any column of a table is a granted fact, the principal can already observe that table's
// cardinality, so no additional Table grant is required for another uncovered occurrence of the SAME
// table. Computed from the FINAL emitted facts (not speculative resolution), so an ambiguous unqualified
// column that resolves to nothing leaves its table uncovered → gated, fail-closed.
type SourceInfo struct {
	Catalog string `json:"catalog"`
	Schema  string `json:"schema"`
	Table   string `json:"table"`
	Covered bool   `json:"covered"`
}

type ProbeResult struct {
	Resolved      bool                `json:"resolved"`
	FailedStage   *string             `json:"failedStage"`
	Detail        string              `json:"detail"`
	OutputColumns int                 `json:"outputColumns"`
	TracedColumns int                 `json:"tracedColumns"`
	Origins       []OriginInfo        `json:"origins"`
	References    map[string][]string `json:"references"`
	Sources       []SourceInfo        `json:"sources"`
	Functions     []string            `json:"functions"`
	IsWrite       bool                `json:"isWrite"`
	WriteTarget   *tableID            `json:"-"`
	RewrittenSQL  *string             `json:"rewrittenSql"`
	// Base columns a literal is compared against in a predicate, keyed by clause. Deliberately NOT folded
	// into References: the parity oracle diffs that map field-by-field and produces no such fact.
	PredicateLiterals []PredicateLiteralRef `json:"predicateLiterals,omitempty"`
}

// PredicateLiteralRef is one literal-vs-column comparison: the resolved base column key and the clause it
// sits in. Advisory only — it gates whether statement TEXT may leave the console, never whether the
// statement runs.
type PredicateLiteralRef struct {
	Column string `json:"column"`
	Clause string `json:"clause"`
}

// NamespaceConfig resolves unqualified table names — catalog + search path only. Engine-specific
// settings (MySQL's lower_case_table_names, the server version) live on EngineConfig instead: a
// namespace is the same shape for every engine.
type NamespaceConfig struct {
	Catalog    string   `json:"catalog"`
	SearchPath []string `json:"searchPath"`
}

type tableID struct {
	catalog string
	schema  string
	table   string
}

func (id tableID) String() string {
	return id.catalog + "." + id.schema + "." + id.table
}

type prober struct {
	engine    engine
	namespace NamespaceConfig

	root         exp.Expression
	qroot        exp.Expression
	analyzeQuery exp.Expression
	payloadQuery exp.Expression
	isWrite      bool
	relOverflow  bool // set when the relation resolver hits its depth guard → fail closed (resolved=false)

	scopes        []*optimizer.Scope
	col2scope     map[exp.Expression]*optimizer.Scope
	scopeOfSelect map[exp.Expression]*optimizer.Scope
	writeScope    *optimizer.Scope

	references map[string]map[string]bool
	// column key -> clause, for every base column a literal is compared against in a predicate.
	predicateLiterals map[string]string
	opaqueSelects     map[exp.Expression]bool

	qualifySchema     schema.Schema
	dialect           *dialects.Dialect // the engine's resolved Dialect — parse, qualify, and generate all share this one instance
	physicalTables    map[exp.Expression]tableID
	nonPhysicalTables map[exp.Expression]bool
	newTargets        map[exp.Expression]bool

	naturalStarOrders  map[exp.Expression][]naturalStarColumn
	naturalStarPending map[exp.Expression]bool
}

type resolveKey struct {
	scope *optimizer.Scope
	alias string
	name  string
}

type identKey struct {
	scope *optimizer.Scope
	alias string
	name  string
}

type naturalStarColumn struct {
	name   string
	tables []string
}

func Probe(sql string, engineConfig *pb.EngineConfig, sch *schema.Mapping, namespace NamespaceConfig) ProbeResult {
	eng, err := createEngine(engineConfig)
	if err != nil {
		return failResult("VALIDATE", err.Error())
	}
	validatedNamespace, err := validateNamespace(namespace)
	if err != nil {
		return failResult("VALIDATE", err.Error())
	}
	if err := detectRenderCollisions(sch); err != nil {
		return failResult("VALIDATE", err.Error())
	}
	qualifySchema, err := schema.NewMappingSchema(sch, eng.Dialect(), eng.NormalizeCatalogOnBuild())
	if err != nil {
		return failResult("VALIDATE", err.Error())
	}
	var parsed []exp.Expression
	if fail := runStage("PARSE", func() {
		var parseErr error
		parsed, parseErr = sqlglot.Parse(sql, eng.Dialect())
		if parseErr != nil {
			panic(parseErr)
		}
	}); fail != nil {
		return *fail
	}
	stmts := nonNilStatements(parsed)
	if len(stmts) != 1 {
		return failResult("PARSE", fmt.Sprintf("expected 1 statement, got %d", len(stmts)))
	}
	root := stmts[0]
	if !hasSyntheticAlias(root) {
		if err := stampNativeOutputLabels(root, eng); err != nil {
			return failResult("VALIDATE", err.Error())
		}
	}
	return probeParsed(root, eng, qualifySchema, validatedNamespace)
}

func probeParsed(root exp.Expression, eng engine, qualifySchema schema.Schema, namespace NamespaceConfig) (out ProbeResult) {
	p := &prober{
		engine:            eng,
		namespace:         namespace,
		root:              root,
		qualifySchema:     qualifySchema,
		dialect:           eng.Dialect(),
		references:        map[string]map[string]bool{},
		opaqueSelects:     map[exp.Expression]bool{},
		physicalTables:    map[exp.Expression]tableID{},
		nonPhysicalTables: map[exp.Expression]bool{},
		newTargets:        map[exp.Expression]bool{},

		naturalStarOrders:  map[exp.Expression][]naturalStarColumn{},
		naturalStarPending: map[exp.Expression]bool{},
	}
	// Emit the called-function facts even when analysis FAILS after parsing — an unsupported/
	// unresolved statement (`SELECT * FROM dblink(...)`, a data-modifying CTE, PIVOT, …) that resolves=false.
	// The success path sets Functions from calledFunctions() at the final return; this defer backfills them on
	// any POST-PARSE failResult (p.root is set once parsing succeeds), so the control-plane can gate a
	// dangerous function that hides in an unanalyzable statement — closing the residue where a resolved=false
	// dangerous call took the exception.unanalyzable relay unGated. A pre-parse failure leaves p.root nil → no
	// backfill (nothing parsed to walk). It only runs when Functions is empty, so a success is never touched.
	defer func() {
		if !out.Resolved && p.root != nil && len(out.Functions) == 0 {
			out.Functions = p.calledFunctions()
		}
	}()
	if !isKnownRoot(p.root) {
		return failResult("PARSE", fmt.Sprintf("unsupported root %s", exp.ClassName(p.root.Kind())))
	}

	if fail := p.classifyWrite(); fail != nil {
		return *fail
	}

	for _, cte := range p.root.FindAll(exp.KindCTE) {
		body := cte.This()
		if body != nil && (body.Kind() == exp.KindInsert || body.Kind() == exp.KindUpdate || body.Kind() == exp.KindDelete || body.Kind() == exp.KindMerge) {
			return failResult("VALIDATE", "data-modifying CTE not supported")
		}
	}
	if len(p.root.FindAll(exp.KindPivot)) > 0 {
		return failResult("VALIDATE", "PIVOT/UNPIVOT not supported")
	}
	for _, oc := range p.root.FindAll(exp.KindOnConflict) {
		if truthy(oc.Arg("constraint")) {
			return failResult("VALIDATE", "ON CONFLICT ON CONSTRAINT — cannot map a named constraint to columns")
		}
	}
	if fail := runStage("VALIDATE", func() {
		p.qroot = p.root.Copy()
		p.expandNaturalJoins(p.qroot)
		p.markNewTargets(p.qroot)
		// MySQL's DELETE target-alias list names sources already present under FROM. Keeping the
		// selector nodes during qualification makes the native DML scope reject the duplicate alias;
		// they are not independent reads, so remove them from the analysis copy after marking them.
		if p.qroot.Kind() == exp.KindDelete && truthy(p.qroot.Arg("tables")) {
			p.qroot.Set("tables", nil)
		}
		report := make(map[exp.Expression]optimizer.ResolvedSource)
		opts := p.qualifyOptions(report)
		p.qroot = optimizer.Qualify(p.qroot, opts)
		if err := p.completeResolutionReport(report); err != nil {
			panic(err)
		}
		if err := p.consumeResolutionReport(report); err != nil {
			panic(err)
		}
	}); fail != nil {
		return *fail
	}

	for {
		var dead []exp.Expression
		for _, with := range p.qroot.FindAll(exp.KindWith) {
			for _, cte := range with.Expressions() {
				if !p.cteReferenced(cte, p.qroot) {
					dead = append(dead, cte)
				}
			}
		}
		if len(dead) == 0 {
			break
		}
		for _, cte := range dead {
			with := cte.Parent()
			cte.Pop()
			if with != nil && with.Kind() == exp.KindWith && len(with.Expressions()) == 0 {
				with.Pop()
			}
		}
	}

	if fail := runStage("CONVERT", func() {
		p.buildScopes()
	}); fail != nil {
		return *fail
	}

	if p.qroot.Kind() == exp.KindInsert && isSelectOrSet(p.qroot.Expr()) {
		p.payloadQuery = p.qroot.Expr()
	} else if p.qroot.Kind() == exp.KindSelect && p.qroot.Arg("into") != nil {
		p.payloadQuery = p.qroot
	}

	var result ProbeResult
	if fail := runStage("LINEAGE", func() {
		result = p.lineage()
	}); fail != nil {
		return *fail
	}
	return result
}

func (p *prober) expandNaturalJoins(root exp.Expression) {
	for _, scope := range optimizer.TraverseScope(root) {
		if scope == nil || scope.Expression == nil {
			continue
		}
		joins := expressionsFor(scope.Expression, "joins")
		needsExpansion := false
		for _, join := range joins {
			// Any NATURAL or USING join merges its common columns first in the star order, which
			// differs from sqlglot's per-table expansion — every such scope needs the merge pass.
			if isNaturalJoin(join) || len(expressionsFor(join, "using")) > 0 {
				needsExpansion = true
				break
			}
		}
		if !needsExpansion {
			continue
		}
		if scope.Expression.Kind() != exp.KindSelect {
			panic(fmt.Errorf("NATURAL JOIN is unsupported in %s", exp.ClassName(scope.Expression.Kind())))
		}

		sourceOrder := p.fromSourceOrder(scope.Expression)
		if len(sourceOrder) != len(joins)+1 {
			panic(fmt.Errorf("NATURAL JOIN source order is incomplete"))
		}
		resolver := optimizer.NewResolver(scope, p.qualifySchema, false)
		sourceColumns := func(alias string) []naturalStarColumn {
			names := resolver.GetSourceColumns(alias, true)
			if len(names) == 0 {
				panic(fmt.Errorf("NATURAL JOIN source %q has no known columns", alias))
			}
			columns := make([]naturalStarColumn, 0, len(names))
			for _, name := range names {
				if name == "*" {
					panic(fmt.Errorf("NATURAL JOIN source %q has an unknown column set", alias))
				}
				columns = append(columns, naturalStarColumn{name: name, tables: []string{alias}})
			}
			return columns
		}

		prefix := []naturalStarColumn{}
		group := sourceColumns(sourceOrder[0])
		outerMerged := false
		for i, join := range joins {
			right := sourceColumns(sourceOrder[i+1])
			if isCommaJoin(join) {
				prefix = append(prefix, group...)
				group = right
				continue
			}
			kind := strings.ToUpper(fmt.Sprint(join.Arg("kind")))
			side := strings.ToUpper(fmt.Sprint(join.Arg("side")))
			if kind == "SEMI" || kind == "ANTI" || side == "SEMI" || side == "ANTI" {
				panic(fmt.Errorf("NATURAL JOIN with %s%s join is unsupported", side, kind))
			}

			mergeLeft, mergeRight := group, right
			if side == "RIGHT" && p.engine.RightJoinStarOrder() == starOrderCommonRightLeft {
				mergeLeft, mergeRight = right, group
			}
			using := p.joinUsingColumns(join)
			if isNaturalJoin(join) {
				// Both targets reject NATURAL combined with ON/USING as a syntax error; expanding it
				// would hand back data for a statement the target would refuse.
				if join.Arg("on") != nil || len(using) > 0 {
					panic(fmt.Errorf("NATURAL JOIN with an ON/USING clause is invalid on the target"))
				}
				var err error
				using, err = naturalCommonColumns(mergeLeft, mergeRight, p.engine.FoldColumn)
				if err != nil {
					panic(err)
				}
				join.Set("method", nil)
				if strings.EqualFold(fmt.Sprint(join.Arg("kind")), "NATURAL") {
					join.Set("kind", nil)
				}
				if len(using) == 0 {
					if side == "" {
						join.Set("kind", "CROSS")
						join.Set("side", nil)
					} else {
						join.Set("on", exp.Boolean(exp.Args{"this": true}))
					}
				} else {
					identifiers := make([]exp.Expression, 0, len(using))
					for _, name := range using {
						identifiers = append(identifiers, exp.ToIdentifier(name, true))
					}
					join.Set("using", identifiers)
				}
			}

			if len(using) > 0 {
				// Qualify expands USING against the first scope source carrying the name, so a key
				// whose value lives elsewhere would bind the join to the wrong table: a same-named
				// column in an earlier comma group, or a merged value produced by a preceding
				// RIGHT/FULL join (its carrier is not the leftmost table). Fail closed on both.
				if outerMerged {
					panic(fmt.Errorf("NATURAL/USING join after an outer merging join — the merged key needs COALESCE semantics"))
				}
				for _, name := range using {
					folded := p.engine.FoldColumn(name)
					for _, column := range prefix {
						if p.engine.FoldColumn(column.name) == folded {
							panic(fmt.Errorf("NATURAL/USING key %q also names a column outside the joined tables", name))
						}
					}
				}
				if side == "RIGHT" || side == "FULL" {
					outerMerged = true
				}
			}

			if len(using) == 0 {
				group = append(append([]naturalStarColumn{}, mergeLeft...), mergeRight...)
				continue
			}
			merged, err := mergeUsingColumns(mergeLeft, mergeRight, using, p.engine.FoldColumn)
			if err != nil {
				panic(err)
			}
			group = merged
		}
		p.naturalStarOrders[scope.Expression] = append(prefix, group...)
		for _, proj := range scope.Expression.Selects() {
			if proj.Kind() == exp.KindStar {
				p.naturalStarPending[scope.Expression] = true
			}
		}
	}

	for _, join := range root.FindAll(exp.KindJoin) {
		if isNaturalJoin(join) {
			panic(fmt.Errorf("NATURAL JOIN source shape is unsupported"))
		}
	}
}

func isNaturalJoin(join exp.Expression) bool {
	return join != nil && (strings.EqualFold(fmt.Sprint(join.Arg("method")), "NATURAL") ||
		strings.EqualFold(fmt.Sprint(join.Arg("kind")), "NATURAL"))
}

func isCommaJoin(join exp.Expression) bool {
	return join != nil && join.Arg("method") == nil && join.Arg("kind") == nil &&
		join.Arg("side") == nil && join.Arg("on") == nil && len(expressionsFor(join, "using")) == 0
}

func (p *prober) joinUsingColumns(join exp.Expression) []string {
	using := expressionsFor(join, "using")
	out := make([]string, 0, len(using))
	for _, identifier := range using {
		identifier = identifier.Copy()
		p.dialect.NormalizeIdentifier(identifier)
		out = append(out, identifier.Name())
	}
	return out
}

func naturalCommonColumns(left, right []naturalStarColumn, fold func(string) string) ([]string, error) {
	leftCounts := map[string]int{}
	rightCounts := map[string]int{}
	for _, column := range left {
		leftCounts[fold(column.name)]++
	}
	for _, column := range right {
		rightCounts[fold(column.name)]++
	}
	common := []string{}
	seen := map[string]bool{}
	for _, column := range left {
		key := fold(column.name)
		if seen[key] || rightCounts[key] == 0 {
			continue
		}
		seen[key] = true
		if leftCounts[key] != 1 || rightCounts[key] != 1 {
			return nil, fmt.Errorf("NATURAL JOIN common column %q is ambiguous", column.name)
		}
		common = append(common, column.name)
	}
	return common, nil
}

func mergeUsingColumns(left, right []naturalStarColumn, using []string, fold func(string) string) ([]naturalStarColumn, error) {
	leftByName := map[string][]naturalStarColumn{}
	rightByName := map[string][]naturalStarColumn{}
	for _, column := range left {
		leftByName[fold(column.name)] = append(leftByName[fold(column.name)], column)
	}
	for _, column := range right {
		rightByName[fold(column.name)] = append(rightByName[fold(column.name)], column)
	}

	merged := make([]naturalStarColumn, 0, len(left)+len(right))
	usingSet := map[string]bool{}
	for _, rawName := range using {
		name := fold(rawName)
		if usingSet[name] {
			return nil, fmt.Errorf("JOIN USING column %q appears more than once", rawName)
		}
		usingSet[name] = true
		leftMatches := leftByName[name]
		rightMatches := rightByName[name]
		if len(leftMatches) != 1 || len(rightMatches) != 1 {
			return nil, fmt.Errorf("JOIN USING column %q is missing or ambiguous", rawName)
		}
		tables := append([]string(nil), leftMatches[0].tables...)
		for _, table := range rightMatches[0].tables {
			found := false
			for _, existing := range tables {
				if existing == table {
					found = true
					break
				}
			}
			if !found {
				tables = append(tables, table)
			}
		}
		merged = append(merged, naturalStarColumn{name: leftMatches[0].name, tables: tables})
	}
	for _, column := range left {
		if !usingSet[fold(column.name)] {
			merged = append(merged, column)
		}
	}
	for _, column := range right {
		if !usingSet[fold(column.name)] {
			merged = append(merged, column)
		}
	}
	return merged, nil
}

func tableNodes(node exp.Expression) []exp.Expression {
	if node == nil {
		return nil
	}
	if node.Kind() == exp.KindTable {
		return []exp.Expression{node}
	}
	return node.FindAll(exp.KindTable)
}

func (p *prober) markNewTargets(root exp.Expression) {
	mark := func(node exp.Expression) {
		for _, table := range tableNodes(node) {
			p.newTargets[table] = true
		}
	}
	switch root.Kind() {
	case exp.KindCreate:
		mark(root.This())
	case exp.KindSelect:
		mark(asExpression(root.Arg("into")))
	case exp.KindDelete:
		// MySQL's `DELETE alias FROM table AS alias` stores the alias selector as a Table node in
		// `tables`; it names the already-resolved target and is not an independent physical table.
		for _, selector := range expressionsFor(root, "tables") {
			for _, table := range tableNodes(selector) {
				p.nonPhysicalTables[table] = true
			}
		}
	}
}

func (p *prober) qualifyOptions(report map[exp.Expression]optimizer.ResolvedSource) optimizer.QualifyOpts {
	opts := optimizer.DefaultQualifyOpts()
	opts.Dialect = p.dialect
	opts.Schema = p.qualifySchema
	opts.SearchPath = p.namespace.SearchPath
	opts.ResolutionReport = report
	opts.InferSchema = boolPtr(false)
	opts.ValidateQualifyColumns = !p.isWrite
	return opts
}

// queryIslands returns the outermost query nodes embedded in a non-query statement. Qualifying one
// island covers its nested queries too, while avoiding repeated mutation of the same subtree.
func queryIslands(root exp.Expression) []exp.Expression {
	if root == nil {
		return nil
	}
	var islands []exp.Expression
	for _, query := range root.FindAll(exp.TraitQuery) {
		if query == root || query.Kind() == exp.KindSubquery {
			continue
		}
		nested := false
		for parent := query.Parent(); parent != nil && parent != root; parent = parent.Parent() {
			// A Subquery node is only a wrapper around its query and does not make that query a
			// nested qualification unit. A real enclosing SELECT/set operation does.
			if parent.Kind() != exp.KindSubquery && parent.Is(exp.TraitQuery) {
				nested = true
				break
			}
		}
		if !nested {
			islands = append(islands, query)
		}
	}
	return islands
}

func resolutionNeedsCompletion(resolved optimizer.ResolvedSource, ok bool) bool {
	return !ok || (resolved.Kind == optimizer.Physical && (resolved.Schema == "" || resolved.Table == ""))
}

func nearestAncestorWith(query, root exp.Expression) exp.Expression {
	for node := query.Parent(); node != nil; node = node.Parent() {
		if with := asExpression(firstNonNil(node.Arg("with"), node.Arg("with_"))); with != nil {
			return with
		}
		if node == root {
			break
		}
	}
	return nil
}

func (p *prober) traverseQueryIsland(query exp.Expression) []*optimizer.Scope {
	with := nearestAncestorWith(query, p.qroot)
	if with == nil {
		return optimizer.TraverseScope(query)
	}

	queryParent, queryKey, queryIndex := query.Parent(), query.ArgKey(), query.Index()
	withParent, withKey, withIndex := with.Parent(), with.ArgKey(), with.Index()
	var wrapper exp.Expression
	var scopes []*optimizer.Scope
	func() {
		defer query.SetParent(queryParent, queryKey, queryIndex)
		defer with.SetParent(withParent, withKey, withIndex)
		wrapper = exp.Select(exp.Args{
			"expressions": []exp.Expression{exp.Subquery(exp.Args{"this": query})},
			"with_":       with,
		})
		scopes = optimizer.TraverseScope(wrapper)
	}()

	out := make([]*optimizer.Scope, 0, len(scopes))
	for _, sc := range scopes {
		if sc.Expression != wrapper {
			out = append(out, sc)
		}
	}
	return out
}

func (p *prober) qualifyQueryIsland(query exp.Expression, report map[exp.Expression]optimizer.ResolvedSource) {
	opts := p.qualifyOptions(report)
	opts.ValidateQualifyColumns = false
	with := nearestAncestorWith(query, p.qroot)
	if with == nil {
		optimizer.Qualify(query, opts)
		return
	}

	// Give the library the island's lexical CTE context while retaining the original query/table nodes
	// as report keys. Only the WITH definitions are copied; restore the query's real parent metadata after
	// the temporary wrapper is qualified.
	parent, key, index := query.Parent(), query.ArgKey(), query.Index()
	defer query.SetParent(parent, key, index)
	wrapper := exp.Select(exp.Args{
		"expressions": []exp.Expression{exp.Subquery(exp.Args{"this": query})},
		"with_":       with.Copy(),
	})
	optimizer.Qualify(wrapper, opts)
}

// v0.5.0's compatibility qualification traversal does not visit INSERT scalar-subquery islands and
// does not stamp tables inside native DML source subqueries. Re-run Qualify only for an affected query
// island and merge its report entries back by exact AST node. A temporary wrapper supplies enclosing CTE
// context, so a virtual source can never be mistaken for a same-named physical table. No identity is
// reconstructed from AST fields.
func (p *prober) completeResolutionReport(report map[exp.Expression]optimizer.ResolvedSource) error {
	for _, query := range queryIslands(p.qroot) {
		needsCompletion := false
		for _, table := range query.FindAll(exp.KindTable) {
			if resolved, ok := report[table]; resolutionNeedsCompletion(resolved, ok) {
				needsCompletion = true
				break
			}
		}
		if !needsCompletion {
			continue
		}

		localReport := make(map[exp.Expression]optimizer.ResolvedSource)
		p.qualifyQueryIsland(query, localReport)
		for _, table := range query.FindAll(exp.KindTable) {
			current, ok := report[table]
			if !resolutionNeedsCompletion(current, ok) {
				continue
			}
			resolved, found := localReport[table]
			if !found {
				return fmt.Errorf("table %q is missing from the resolution report", table.Name())
			}
			report[table] = resolved
		}
	}
	return nil
}

func (p *prober) consumeResolutionReport(report map[exp.Expression]optimizer.ResolvedSource) error {
	for _, table := range p.qroot.FindAll(exp.KindTable) {
		if p.newTargets[table] || p.nonPhysicalTables[table] {
			continue
		}
		if this := table.This(); this == nil || this.Kind() != exp.KindIdentifier {
			continue
		}
		resolved, ok := report[table]
		if !ok {
			return fmt.Errorf("table %q is missing from the resolution report", table.Name())
		}
		switch resolved.Kind {
		case optimizer.Physical:
			catalog := resolved.Catalog
			if catalog == "" {
				catalog = p.namespace.Catalog
			} else if catalog != p.namespace.Catalog {
				return fmt.Errorf("foreign catalog %q", resolved.Catalog)
			}
			if resolved.Schema == "" || resolved.Table == "" {
				return fmt.Errorf("physical table %q has incomplete resolved identity", table.Name())
			}
			id := tableID{catalog: catalog, schema: resolved.Schema, table: resolved.Table}
			// table is already fully qualified by the Qualify pass that just ran, so Find consults
			// exactly the same catalog identity Qualify itself resolved against — no separately
			// maintained existence map to drift out of sync with it.
			found, findErr := p.qualifySchema.Find(table, false, false)
			if findErr != nil {
				return findErr
			}
			if found == nil {
				return fmt.Errorf("unknown table %s", id.String())
			}
			p.physicalTables[table] = id
		case optimizer.CTE, optimizer.Derived, optimizer.Subquery:
			continue
		case optimizer.Unresolved:
			return fmt.Errorf("table %q is unresolved", table.Name())
		default:
			return fmt.Errorf("table %q has unknown resolution kind %v", table.Name(), resolved.Kind)
		}
	}
	return nil
}

func (p *prober) resolvedTableID(table exp.Expression) (tableID, bool) {
	id, ok := p.physicalTables[table]
	return id, ok
}

// canonicalColumn folds column (unconditional and context-free — a column name's role is never
// ambiguous the way a table/schema name's is) and checks it against table, which is already fully
// qualified — HasColumn is called with normalize=false so it doesn't refold what's already canonical.
func (p *prober) canonicalColumn(table exp.Expression, column string) (string, bool) {
	column = p.engine.FoldColumn(column)
	ok, err := p.qualifySchema.HasColumn(table, column, p.dialect, boolPtr(false))
	if err != nil || !ok {
		return "", false
	}
	return column, true
}

// tableColumns returns every column of an already-resolved physical table, for whole-row/`*`
// expansion. table is already fully qualified (it comes from p.physicalTables), so normalize=false —
// this is a pure lookup against sqlglot-go's own catalog, not a fold decision.
func (p *prober) tableColumns(table exp.Expression) []string {
	columns, err := p.qualifySchema.ColumnNames(table, false, p.dialect, boolPtr(false))
	if err != nil {
		return nil
	}
	return columns
}

func (p *prober) columnKey(table exp.Expression, column string) (string, bool) {
	id, ok := p.resolvedTableID(table)
	if !ok {
		return "", false
	}
	canonical, ok := p.canonicalColumn(table, column)
	if !ok {
		return "", false
	}
	return id.String() + "." + canonical, true
}

func (p *prober) writeTargetTable() exp.Expression {
	if p.qroot == nil {
		return nil
	}
	var target exp.Expression
	switch p.qroot.Kind() {
	case exp.KindInsert, exp.KindUpdate, exp.KindDelete, exp.KindMerge, exp.KindCreate:
		target = p.qroot.This()
	case exp.KindSelect:
		target = asExpression(p.qroot.Arg("into"))
	}
	for _, table := range tableNodes(target) {
		return table
	}
	return nil
}

// writeTargetNodes is the set of table NODES that are the write target of an INSERT/UPDATE/DELETE/
// MERGE/CREATE (or SELECT ... INTO) — the mutated relation, gated by sql.<kind>. Excludes the
// target occurrence from scanned-source facts; a distinct read occurrence of the same table is
// unaffected. Node-keyed (not tableID) so the target and an aliased self-read stay distinguishable.
func (p *prober) writeTargetNodes() map[exp.Expression]bool {
	out := map[exp.Expression]bool{}
	if p.qroot == nil {
		return out
	}
	var target exp.Expression
	switch p.qroot.Kind() {
	case exp.KindInsert, exp.KindUpdate, exp.KindDelete, exp.KindMerge, exp.KindCreate:
		target = p.qroot.This()
	case exp.KindSelect:
		target = asExpression(p.qroot.Arg("into"))
	}
	for _, table := range tableNodes(target) {
		out[table] = true
	}
	return out
}

func (p *prober) classifyWrite() *ProbeResult {
	p.isWrite = false
	p.analyzeQuery = p.root

	switch p.root.Kind() {
	case exp.KindCreate:
		// Unwrapped, and the UNWRAPPED body is what gets analyzed: lineage over a Subquery wrapper finds
		// no source columns, so a parenthesized CTAS would be a write with an empty grant set.
		if body := unwrapSubquery(p.root.Expr()); isSelectOrSet(body) {
			p.isWrite = true
			p.analyzeQuery = body
		} else {
			fail := failResult("VALIDATE", "CREATE without analyzable query")
			return &fail
		}
	case exp.KindInsert, exp.KindUpdate, exp.KindDelete, exp.KindMerge:
		p.isWrite = true
		p.analyzeQuery = nil
	case exp.KindSelect:
		if p.root.Arg("into") != nil {
			p.isWrite = true
			p.analyzeQuery = nil
		}
	}
	// A SELECT ... INTO anywhere — including one hoisted onto a set-operation root or buried in a union
	// branch — writes to a file/variable/table the masker cannot reach, so its read columns are a
	// non-maskable write payload, not maskable output. The KindSelect case catches the top-level form;
	// this catches the set-operation form the switch does not.
	if !p.isWrite && len(p.root.FindAll(exp.KindInto)) > 0 {
		p.isWrite = true
		p.analyzeQuery = nil
	}
	return nil
}

type failPanic struct{ result ProbeResult }

func runStage(stage string, fn func()) *ProbeResult {
	var fail *ProbeResult
	func() {
		defer func() {
			if r := recover(); r != nil {
				if f, ok := r.(failPanic); ok {
					fail = &f.result
					return
				}
				f := failResult(stage, panicDetail(r))
				fail = &f
			}
		}()
		fn()
	}()
	return fail
}

func nonNilStatements(parsed []exp.Expression) []exp.Expression {
	stmts := make([]exp.Expression, 0, len(parsed))
	for _, stmt := range parsed {
		if stmt != nil {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

func failResult(stage string, detail string) ProbeResult {
	stageCopy := stage
	return ProbeResult{
		Resolved:      false,
		FailedStage:   &stageCopy,
		Detail:        truncateDetail(detail),
		OutputColumns: 0,
		TracedColumns: 0,
		Origins:       []OriginInfo{},
		References:    map[string][]string{},
		Sources:       []SourceInfo{},
		Functions:     []string{},
		IsWrite:       false,
		RewrittenSQL:  nil,
	}
}

func panicDetail(r any) string {
	if err, ok := r.(error); ok {
		return truncateDetail(err.Error())
	}
	return truncateDetail(fmt.Sprint(r))
}

func truncateDetail(detail string) string {
	runes := []rune(detail)
	if len(runes) > 150 {
		return string(runes[:150])
	}
	return detail
}

func isKnownRoot(e exp.Expression) bool {
	if e == nil {
		return false
	}
	if e.Is(exp.TraitSetOperation) {
		return true
	}
	switch e.Kind() {
	case exp.KindSelect, exp.KindInsert, exp.KindUpdate, exp.KindDelete, exp.KindMerge, exp.KindCreate:
		return true
	}
	return false
}

// unwrapSubquery peels parenthesis wrappers off an expression, returning the statement inside.
//
// Parentheses are real syntax, so sqlglot models `(SELECT …)` as a Subquery around the Select. Any
// check that asks "is this a query?" has to look through that wrapper, or the same statement is
// classified two ways depending on whether the author wrote a pair of parentheses — and for a CREATE
// body, the parenthesized spelling would emit no column grants at all. Loops rather than unwrapping
// once, since nothing stops `((SELECT …))`.
func unwrapSubquery(e exp.Expression) exp.Expression {
	for e != nil && e.Kind() == exp.KindSubquery && e.This() != nil {
		e = e.This()
	}
	return e
}

// createReadsColumns reports whether a CREATE's AS-body reads or computes a value, and therefore needs
// lineage rather than the catalog-changing class (which emits no column/function grants and no masks).
//
// It inspects only the `AS <body>` clause (root.Expr()); a bare column list, CREATE INDEX, generated
// columns, and DEFAULT/CHECK expressions live in other args and stay catalog-only DDL — the uniform-DDL
// model. Within the body it is deliberately broad: a query, a column reference, or a function call
// anywhere inside means the value is not free. A VALUES row hides all three from a check on the immediate
// child — `AS (SELECT …)` is a Subquery, `AS VALUES ((SELECT …))` buries a Select, and
// `AS VALUES (query_to_xml('SELECT ssn …'))` invokes a data-leak function the function gate must still
// see — each of which the catalog-only path would drop on the floor. A literal-only VALUES matches none
// and stays value-free DDL.
func createReadsColumns(root exp.Expression) bool {
	body := unwrapSubquery(root.Expr())
	if body == nil {
		return false
	}
	if isSelectOrSet(body) {
		return true
	}
	// VALUES is the one non-query CTAS/VIEW body that still materializes computed values: a row can hide a
	// subquery, a column reference, or a function call (a data-leak function like query_to_xml) with no
	// top-level Select, each of which the catalog-only path would drop. Literal-only VALUES matches none.
	// Any other AS-body — a CREATE FUNCTION routine definition, say — is not a data-materializing query, so
	// it keeps the narrow Select probe and stays catalog-only DDL.
	if body.Kind() == exp.KindValues {
		return bodyReferencesData(body)
	}
	return len(body.FindAll(exp.KindSelect)) > 0
}

// bodyReferencesData reports whether an expression subtree reads a column, runs a query, or calls a
// function — anything the value-free catalog-changing path would fail to gate.
func bodyReferencesData(body exp.Expression) bool {
	if len(body.FindAll(exp.KindSelect)) > 0 || len(body.FindAll(exp.KindColumn)) > 0 {
		return true
	}
	for _, node := range body.Walk() {
		if node != nil && node.Is(exp.TraitFunc) {
			return true
		}
	}
	return false
}

func isSelectOrSet(e exp.Expression) bool {
	return e != nil && (e.Kind() == exp.KindSelect || e.Is(exp.TraitSetOperation))
}

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

// generateExecutableSQL renders root back to SQL under dialect — the SAME *dialects.Dialect object
// the engine already built for Qualify, not a bare wire-name string. A bare name like "mysql" would
// lose the NormalizationStrategy this query was actually qualified under (Generate resolves any
// non-*Dialect value via dialects.GetOrRaise, which builds a fresh DEFAULT dialect on every call), so
// a lower_case_table_names=1/2 table could regenerate with the wrong identifier casing.
func generateExecutableSQL(root exp.Expression, dialect *dialects.Dialect) (string, error) {
	executable := root.Copy()
	// Catalog is part of the analyzer's identity, but neither PostgreSQL nor MySQL accepts it as an
	// executable third table-name component. Keep the real schema/database qualification and remove only
	// the analyzer-only catalog from the copy rendered for target-DB execution.
	for _, table := range executable.FindAll(exp.KindTable) {
		table.Set("catalog", nil)
	}
	return sqlglot.Generate(executable, dialect, generator.Options{})
}

func (p *prober) buildScopes() {
	p.scopes = optimizer.TraverseScope(p.qroot)
	// INSERT has no native root query, and the root traversal can omit SELECTs nested under VALUES/SET,
	// so retain those query scopes as independent analysis graphs for the INSERT conservation
	// paths. UPDATE/DELETE/MERGE stay on the single native traversal graph validated below.
	if p.qroot.Kind() == exp.KindInsert {
		seenExpressions := map[exp.Expression]bool{}
		for _, sc := range p.scopes {
			seenExpressions[sc.Expression] = true
		}
		for _, query := range queryIslands(p.qroot) {
			if seenExpressions[query] {
				continue
			}
			for _, sc := range p.traverseQueryIsland(query) {
				if !seenExpressions[sc.Expression] {
					p.scopes = append(p.scopes, sc)
					seenExpressions[sc.Expression] = true
				}
			}
		}
	}
	p.col2scope = map[exp.Expression]*optimizer.Scope{}
	for _, sc := range p.scopes {
		for _, c := range sc.Columns() {
			p.col2scope[c] = sc
		}
	}
	p.scopeOfSelect = map[exp.Expression]*optimizer.Scope{}
	for _, sc := range p.scopes {
		p.scopeOfSelect[sc.Expression] = sc
	}

	p.writeScope = nil
	switch p.qroot.Kind() {
	case exp.KindUpdate, exp.KindDelete, exp.KindMerge:
		if optimizer.BuildScope(p.qroot) == nil {
			panic("incomplete DML-root scope")
		}
		for _, sc := range p.scopes {
			if sc.Expression == p.qroot {
				p.writeScope = sc
				break
			}
		}
		if p.writeScope == nil {
			panic("DML-root scope is missing from traversal")
		}
	}
}

func (p *prober) lineage() ProbeResult {
	p.references = map[string]map[string]bool{}

	p.opaqueSelects = map[exp.Expression]bool{}
	for _, node := range append(p.qroot.FindAll(exp.KindSelect), p.findAllSetOperations(p.qroot)...) {
		if p.isExpressionSubquery(node) {
			p.opaqueSelects[node] = true
			p.addRef(SUBQUERY, p.bases(node.FindAll(exp.KindColumn)))
		}
	}

	for _, so := range p.findAllSetOperations(p.qroot) {
		distinct := so.Arg("distinct")
		if so.Kind() == exp.KindUnion && !truthy(distinct) {
			continue
		}
		for _, sel := range so.FindAll(exp.KindSelect) {
			if sel.FindAncestor(exp.KindUnion, exp.KindExcept, exp.KindIntersect) == so || sel.Parent() == so {
				p.addRef(SET_OP, p.bases(sel.Selects()))
			}
		}
	}

	for _, with := range p.qroot.FindAll(exp.KindWith) {
		if truthy(with.Arg("recursive")) {
			for _, cte := range with.Expressions() {
				if !p.cteReferenced(cte, p.qroot) {
					continue
				}
				if body := cte.This(); body != nil {
					p.addRef(RECURSIVE, p.bases(body.FindAll(exp.KindColumn)))
				}
			}
		}
	}

	addClause := func(nodes []exp.Expression, ctx string) {
		for _, n := range nodes {
			if n == nil || p.enclosingOpaque(n) != nil {
				continue
			}
			p.addRef(ctx, p.bases([]exp.Expression{n}))
		}
	}
	addOutputRefs := func(sel exp.Expression, terms []exp.Expression, ctx string) {
		projs := sel.Selects()
		for _, t := range terms {
			if t == nil || p.enclosingOpaque(t) != nil {
				continue
			}
			inner := t
			if t.Kind() == exp.KindOrdered {
				inner = t.This()
			}
			if inner != nil && inner.Kind() == exp.KindLiteral && inner.IsInt() {
				idx64, _ := strconv.ParseInt(inner.Name(), 10, 64)
				i := int(idx64) - 1
				if i >= 0 && i < len(projs) {
					p.addRef(ctx, p.bases([]exp.Expression{projs[i]}))
				}
				continue
			}
			for _, col := range inner.FindAll(exp.KindColumn) {
				b := p.resolve(col, map[resolveKey]bool{})
				if len(b) == 0 && col.TableName() == "" {
					for _, proj := range projs {
						if proj.AliasOrName() == col.Name() {
							b = p.bases([]exp.Expression{proj})
							break
						}
					}
				}
				p.addRef(ctx, b)
			}
		}
	}

	for _, sel := range p.qroot.FindAll(exp.KindSelect) {
		if p.opaqueSelects[sel] {
			continue
		}
		if w := asExpression(sel.Arg("where")); w != nil {
			addClause([]exp.Expression{w.This()}, PREDICATE)
			p.addPredicateLiterals(w.This(), "WHERE")
		}
		if h := asExpression(sel.Arg("having")); h != nil {
			addClause([]exp.Expression{h.This()}, PREDICATE)
			p.addPredicateLiterals(h.This(), "HAVING")
		}
		if g := asExpression(sel.Arg("group")); g != nil {
			gcols := append([]exp.Expression(nil), g.Expressions()...)
			for _, key := range []string{"rollup", "cube", "grouping_sets"} {
				gcols = append(gcols, expressionsFor(g, key)...)
			}
			addOutputRefs(sel, gcols, GROUP_BY)
		}
		if q := asExpression(sel.Arg("qualify")); q != nil {
			addClause([]exp.Expression{q.This()}, PREDICATE)
			p.addPredicateLiterals(q.This(), "QUALIFY")
		}
		for _, j := range expressionsFor(sel, "joins") {
			if on := asExpression(j.Arg("on")); on != nil {
				addClause([]exp.Expression{on}, JOIN)
				p.addPredicateLiterals(on, "JOIN")
			}
			addClause(expressionsFor(j, "using"), JOIN)
		}
		if order := asExpression(sel.Arg("order")); order != nil {
			addOutputRefs(sel, order.Expressions(), ORDER_BY)
		}
		if dstn := asExpression(sel.Arg("distinct")); dstn != nil {
			on := asExpression(dstn.Arg("on"))
			if on == nil {
				addClause(sel.Selects(), GROUP_BY)
			} else {
				keys := []exp.Expression{on}
				if on.Kind() == exp.KindTuple {
					keys = on.Expressions()
				}
				addOutputRefs(sel, keys, GROUP_BY)
			}
		}
	}

	// A native UPDATE or DELETE keeps its WHERE on the statement root, not on a Select, so the Select walk
	// above never reaches it. The protected value in `UPDATE … WHERE ssn = '…'` hides exactly as it does in
	// a SELECT, and absence of the fact is read as "safe" downstream — so the predicate must be collected.
	switch p.qroot.Kind() {
	case exp.KindUpdate, exp.KindDelete:
		if w := asExpression(p.qroot.Arg("where")); w != nil {
			p.addPredicateLiterals(w.This(), "WHERE")
		}
	}

	for _, so := range p.findAllSetOperations(p.qroot) {
		order := asExpression(so.Arg("order"))
		if order == nil {
			continue
		}
		branches := p.leafSelects(so)
		var left exp.Expression
		if len(branches) > 0 {
			left = branches[0]
		}
		posBases := []map[string]bool{}
		if left != nil {
			for i := range left.Selects() {
				b := map[string]bool{}
				for _, br := range branches {
					selects := br.Selects()
					if i < len(selects) {
						addSet(b, p.bases([]exp.Expression{selects[i]}))
					}
				}
				posBases = append(posBases, b)
			}
		}
		nameOf := map[string]map[string]bool{}
		if left != nil {
			for i, b := range posBases {
				nameOf[left.Selects()[i].AliasOrName()] = b
			}
		}
		for _, t := range order.Expressions() {
			inner := t
			if t.Kind() == exp.KindOrdered {
				inner = t.This()
			}
			if inner != nil && inner.Kind() == exp.KindLiteral && inner.IsInt() {
				idx64, _ := strconv.ParseInt(inner.Name(), 10, 64)
				i := int(idx64) - 1
				if i >= 0 && i < len(posBases) {
					p.addRef(ORDER_BY, posBases[i])
				}
			} else if inner != nil {
				for _, col := range inner.FindAll(exp.KindColumn) {
					b := p.resolve(col, map[resolveKey]bool{})
					if len(b) == 0 {
						b = nameOf[col.Name()]
					}
					p.addRef(ORDER_BY, b)
				}
			}
		}
	}

	for _, over := range p.qroot.FindAll(exp.KindWindow) {
		if p.enclosingOpaque(over) == nil {
			addClause(expressionsFor(over, "partition_by"), PREDICATE)
			if o := asExpression(over.Arg("order")); o != nil {
				addClause(o.Expressions(), ORDER_BY)
			}
		}
	}
	for _, filt := range p.qroot.FindAll(exp.KindFilter) {
		if p.enclosingOpaque(filt) == nil {
			addClause([]exp.Expression{filt.Expr()}, AGGREGATE)
		}
	}

	for _, sel := range p.qroot.FindAll(exp.KindSelect) {
		if p.opaqueSelects[sel] {
			continue
		}
		srcNodes := []exp.Expression{}
		if frm := asExpression(sel.Arg("from")); frm != nil {
			srcNodes = append(srcNodes, frm)
		}
		for _, j := range expressionsFor(sel, "joins") {
			if j.This() != nil {
				srcNodes = append(srcNodes, j.This())
			}
		}
		srcNodes = append(srcNodes, expressionsFor(sel, "laterals")...)
		for _, node := range srcNodes {
			for _, c := range node.FindAll(exp.KindColumn) {
				if c.FindAncestor(exp.KindSelect) == sel {
					p.addRef(OTHER, p.bases([]exp.Expression{c}))
				}
			}
		}
	}

	// Whole-row / composite references (docs/relation-model.md), via the one relation resolver
	// (relation.go). A relation used as a value touches every column it carries; those columns land in
	// references (OTHER) → a protected one there is a DENY. Fail-closed: an unresolved field expands to
	// the whole relation. Relation-valued columns and nested composites are followed through (the
	// per-node handling missed them — a `users AS sub` projection resolved to nothing).
	for _, tc := range p.qroot.FindAll(exp.KindTableColumn) {
		if tc.FindAncestor(exp.KindDot) != nil {
			continue // handled as the base of its Dot
		}
		// column-first: a bare name PG binds to an outer column is a scalar read, not a whole-row
		// value; only a name that is a column nowhere in the chain is a relation.
		r := p.relationOf(tc.Name(), p.scopeChainFor(tc), 0)
		if r.scalar != nil {
			p.addRef(OTHER, r.scalar)
		} else if r.rel != nil {
			p.addRef(OTHER, p.relationColumns(r.rel)) // a genuine whole-row value → all its columns
		}
	}
	for _, dot := range p.qroot.FindAll(exp.KindDot) {
		if dot.FindAncestor(exp.KindDot) != nil {
			continue // inner segment of a nested composite; resolved from the outermost Dot
		}
		rel, ok := p.relationOfNode(dot.This(), 0)
		if !ok {
			continue // base is not a relation (ordinary struct/JSON path etc.) — normal lineage handles it
		}
		fld := ""
		if dot.Expr() != nil {
			fld = dot.Expr().Name() // AS-IS; relationField lowercases only for the schema lookup
		}
		if bases, found := p.relationField(rel, fld); found {
			p.addRef(OTHER, bases) // (x).f → the specific base column(s)
		} else {
			p.addRef(OTHER, p.relationColumns(rel)) // unresolved field → whole relation (fail closed)
		}
	}
	for _, c := range p.qroot.FindAll(exp.KindColumn) {
		if c.This() != nil && c.This().Kind() == exp.KindStar && c.TableName() != "" {
			if src := p.srcInScope(c, c.TableName()); src != nil { // AS-IS (folded) source-alias lookup
				p.addRef(OTHER, p.relationColumns(src)) // x.* → all of x's columns
			}
		}
	}

	// (The write-side conservation sweep for orphaned payload clauses lives in the write block below,
	// where destIDs is in scope — see "Write-side conservation sweep".)

	// The relation resolver hit its recursion/cycle guard on some composite chain — fail closed rather
	// than emit partial lineage that could ALLOW a protected read.
	if p.relOverflow {
		return failResult("LINEAGE", "relation-resolution depth exceeded (possible composite cycle)")
	}

	var rewrittenSQL *string
	if p.analyzeQuery != nil && !p.isWrite {
		for _, sel := range p.qroot.FindAll(exp.KindSelect) {
			for _, proj := range sel.Selects() {
				if p.isStar(proj) {
					return failResult("VALIDATE", "unexpandable `*` (table-function / array / LATERAL source) — cannot bind mask ordinals")
				}
			}
		}
		oBranches := []exp.Expression{p.analyzeQuery}
		if p.analyzeQuery.Is(exp.TraitSetOperation) {
			oBranches = p.leafSelects(p.analyzeQuery)
		}
		qBranches := []exp.Expression{p.qroot}
		if p.qroot.Is(exp.TraitSetOperation) {
			qBranches = p.leafSelects(p.qroot)
		}
		starExpanded := false
		for i, qsel := range qBranches {
			var osel exp.Expression
			if i < len(oBranches) {
				osel = oBranches[i]
			}
			if osel == nil {
				continue
			}
			hasStar := false
			for _, proj := range osel.Selects() {
				if p.isStar(proj) {
					hasStar = true
					break
				}
			}
			if !hasStar {
				continue
			}
			ok, why := p.expandableSources(osel)
			if !ok {
				return failResult("VALIDATE", fmt.Sprintf("`*` over %s — outside the faithful-expansion envelope", why))
			}
			bareStar := false
			starCount := 0
			for _, proj := range osel.Selects() {
				if proj.Kind() == exp.KindStar {
					bareStar = true
				}
				if p.isStar(proj) {
					starCount++
				}
			}
			if bareStar {
				if starCount > 1 {
					return failResult("VALIDATE", "bare `*` mixed with another star — column order can't bind to mask ordinals")
				}
				p.resortBareStarInplace(osel, qsel)
			}
			starExpanded = true
		}
		// A merged star inside a derived table/CTE never reaches resortBareStarInplace (only the
		// outer branches are resorted), so its expansion order — and the outer scope's ordinals
		// with it — would silently disagree with the target.
		if len(p.naturalStarPending) > 0 {
			return failResult("VALIDATE", "NATURAL/USING `*` inside a derived scope — column order can't bind to mask ordinals")
		}
		if starExpanded {
			relayRoot := p.qroot
			// Repair the outermost display labels on a relay-only copy — lineage and mask ordinals
			// keep reading p.qroot. Only projections the pre-Qualify stamping skipped (duplicate
			// native labels, legal as OUTPUT) still carry `_col_N` here. Skipped when the client
			// wrote a `_col_N` alias anywhere: client labels are then indistinguishable.
			if hasSyntheticAlias(p.qroot) && !hasSyntheticAlias(p.root) {
				restored := p.qroot.Copy()
				if restoreRelayOutputLabels(restored, p.engine) {
					relayRoot = restored
				}
			}
			s, err := generateExecutableSQL(relayRoot, p.dialect)
			if err != nil {
				panic(err)
			}
			rewrittenSQL = &s
		}
	}

	origins := []OriginInfo{}
	if p.analyzeQuery != nil {
		aq := p.qroot
		if p.root.Kind() == exp.KindCreate {
			aq = p.qroot.Expr()
		}
		if aq != nil && aq.Is(exp.TraitSetOperation) {
			branches := p.leafSelects(aq)
			branchSelects := make([][]exp.Expression, 0, len(branches))
			for _, br := range branches {
				branchSelects = append(branchSelects, br.Selects())
			}
			leftSels := []exp.Expression{}
			if len(branchSelects) > 0 {
				leftSels = branchSelects[0]
			}
			for i := range leftSels {
				srcs := map[string]bool{}
				identity := true
				for _, bs := range branchSelects {
					if i < len(bs) {
						b, sub := p.projIdent(bs[i], map[identKey]bool{})
						addSet(srcs, b)
						identity = identity && sub
					}
				}
				if identity {
					origins = append(origins, OriginInfo{Column: leftSels[i].AliasOrName(), Origins: sortedSet(srcs)})
				} else {
					origins = append(origins, OriginInfo{Column: leftSels[i].AliasOrName(), Origins: []string{}})
					p.addRef(DERIVED, srcs)
				}
			}
		} else if aq != nil {
			// SELECT DISTINCT dedups on the real output values (before any masking), so the returned
			// row count is a function of the derived value — redacting the cell can't hide it. Such a
			// query is not safely redactable; its derived outputs stay a DERIVED reference (→ DENY).
			distinct := aq.Arg("distinct") != nil
			for _, proj := range aq.Selects() {
				bases, isID := p.projIdent(proj, map[identKey]bool{})
				switch {
				case isID:
					origins = append(origins, OriginInfo{Column: proj.AliasOrName(), Origins: sortedSet(bases)})
				case !distinct && p.redactableTransform(proj):
					// A pure per-row scalar transform (no aggregate/window/subquery). Carry its base
					// columns on the ordinal with Derived=true (not a DERIVED reference), so enforcement
					// can redact a masked base column in full instead of denying: row identity/order/
					// count is fixed by the non-derived parts of the query, so blanking the cell leaks
					// nothing. A base column that ALSO reaches a row-shaping position (predicate/join/
					// order/group/set-op) is recorded in that reference bucket independently and still
					// denies (the reference check runs before the ordinal redaction).
					origins = append(origins, OriginInfo{Column: proj.AliasOrName(), Origins: sortedSet(bases), Derived: true})
				default:
					// Aggregate/window/subquery output, or a DISTINCT query: row-collapsing or
					// reshaping, so not safely redactable — keep it a DERIVED reference (→ DENY for a
					// masked base column).
					origins = append(origins, OriginInfo{Column: proj.AliasOrName(), Origins: []string{}})
					p.addRef(DERIVED, bases)
				}
			}
		}
	}

	accounted := map[string]bool{}
	for _, origin := range origins {
		for _, value := range origin.Origins {
			accounted[value] = true
		}
	}
	for _, cols := range p.references {
		addSet(accounted, cols)
	}

	skipArgs := map[string]bool{"expressions": true, "from": true, "from_": true, "joins": true, "with": true, "with_": true, "laterals": true, "pivots": true, "into": true, "hint": true, "kind": true, "operation": true, "operation_modifiers": true}
	for _, sel := range p.qroot.FindAll(exp.KindSelect) {
		if p.opaqueSelects[sel] {
			continue
		}
		for key, node := range exp.ArgsOf(sel) {
			if skipArgs[key] {
				continue
			}
			for _, sub := range expressionsFromAny(node) {
				for _, c := range sub.FindAll(exp.KindColumn) {
					if p.enclosingOpaque(c) == nil {
						p.addRef(OTHER, subtractSet(p.resolve(c, map[resolveKey]bool{}), accounted))
					}
				}
			}
		}
	}

	if p.isWrite {
		destIDs := map[exp.Expression]bool{}
		for _, ins := range p.qroot.FindAll(exp.KindInsert) {
			this := ins.This()
			if this != nil && (this.Kind() == exp.KindSchema || this.Kind() == exp.KindTuple) {
				for _, c := range this.FindAll(exp.KindColumn) {
					destIDs[c] = true
				}
			}
		}
		for _, eq := range p.setAssignments(p.qroot) {
			if lhs := eq.This(); lhs != nil && lhs.Kind() == exp.KindColumn {
				destIDs[lhs] = true
			}
		}
		phys := map[tableID]exp.Expression{}
		for table, id := range p.physicalTables {
			if id.catalog != "" && within(table, p.qroot) && !p.newTargets[table] {
				phys[id] = table
			}
		}
		var writePhys []exp.Expression
		if p.writeScope != nil {
			for _, src := range p.writeScope.Sources {
				if tbl, ok := src.(exp.Expression); ok && tbl != nil && tbl.Kind() == exp.KindTable {
					if _, found := p.resolvedTableID(tbl); found {
						writePhys = append(writePhys, tbl)
					}
				}
			}
		}
		hasOnConflict := len(p.qroot.FindAll(exp.KindOnConflict)) > 0
		aliasNamesCI := map[string]bool{}
		for _, scope := range p.scopes {
			for key := range scope.Sources {
				aliasNamesCI[strings.ToLower(key)] = true
			}
		}
		if p.writeScope != nil {
			for key := range p.writeScope.Sources {
				aliasNamesCI[strings.ToLower(key)] = true
			}
		}

		resolveWS := func(alias, name string) map[string]bool {
			if p.writeScope == nil || alias == "" {
				return map[string]bool{}
			}
			src := p.writeScope.Sources[alias]
			if src == nil {
				return map[string]bool{}
			}
			if tbl, ok := src.(exp.Expression); ok && tbl != nil && tbl.Kind() == exp.KindTable {
				if key, found := p.columnKey(tbl, name); found {
					return stringSet(key)
				}
				return map[string]bool{}
			}
			if sc, ok := src.(*optimizer.Scope); ok {
				return p.resolveScopeOutput(sc, name, map[resolveKey]bool{})
			}
			return map[string]bool{}
		}
		wbase := func(name, alias string, col exp.Expression) (map[string]bool, bool) {
			bases := map[string]bool{}
			if col != nil {
				bases = p.resolve(col, map[resolveKey]bool{})
			}
			if len(bases) == 0 && alias != "" {
				bases = resolveWS(alias, name)
			}
			if len(bases) == 0 {
				if target := p.writeTargetTable(); target != nil && !p.newTargets[target] {
					targetName := target.AliasOrName()
					if alias == "" || alias == targetName || (target.Alias() == "" && alias == target.Name()) {
						if key, found := p.columnKey(target, name); found {
							bases = stringSet(key)
						}
					}
				}
			}
			if len(bases) == 0 && alias == "" && p.writeScope != nil {
				matches := []string{}
				seen := map[tableID]bool{}
				for _, source := range p.writeScope.Sources {
					table, physical := source.(exp.Expression)
					if !physical || table == nil || table.Kind() != exp.KindTable {
						continue
					}
					id, resolved := p.resolvedTableID(table)
					if !resolved || seen[id] {
						continue
					}
					seen[id] = true
					if key, found := p.columnKey(table, name); found {
						matches = append(matches, key)
					}
				}
				if len(matches) == 1 {
					bases = stringSet(matches[0])
				}
			}
			if len(bases) == 0 {
				return nil, false
			}
			// No catalog-wide whitelist re-check here: every producer of bases above already went
			// through columnKey (directly, or via resolve/resolveIn/resolveScopeOutput's recursive
			// bottoming-out at a physical table) — each of those calls canonicalColumn, which is
			// itself a real existence check against qualifySchema. A second check here would be
			// redundant, not additional defense — there was no independent source of bases that
			// skipped it.
			return bases, true
		}

		for _, c := range p.qroot.FindAll(exp.KindColumn) {
			columnScope := p.col2scope[c]
			if destIDs[c] || (columnScope != nil && columnScope.Expression != p.qroot) {
				continue
			}
			if c.This() != nil && c.This().Kind() == exp.KindStar {
				continue
			}
			if c.FindAncestor(exp.KindDot) != nil {
				continue // relation/composite field access is conserved by the unified resolver above
			}
			if c.TableName() == "" && p.writeScope != nil && c.Name() != "" {
				if wsrc, ok := p.writeScope.Sources[c.Name()]; ok {
					hasColumn := false
					for _, tbl := range writePhys {
						if _, found := p.canonicalColumn(tbl, c.Name()); found {
							hasColumn = true
							break
						}
					}
					if !hasColumn {
						if tbl, ok := wsrc.(exp.Expression); ok && tbl != nil && tbl.Kind() == exp.KindTable {
							p.addRef(OTHER, subtractSet(p.relationColumns(tbl), accounted))
							continue
						}
					}
				}
			}
			if strings.ToLower(c.TableName()) == "excluded" && hasOnConflict && !aliasNamesCI["excluded"] {
				continue
			}
			bases, ok := wbase(c.Name(), c.TableName(), c)
			if !ok {
				return failResult("VALIDATE", fmt.Sprintf("unresolved column '%s' in write", c.Name()))
			}
			p.addRef(OTHER, subtractSet(bases, accounted))
		}
		// Write-side conservation sweep (docs/relation-model.md — one resolver at EVERY consumption
		// site, not per-clause guards). The loop above skips columns owned by a nested scope
		// (p.col2scope[c] != nil): the payload subqueries of every orphaned write clause — SET,
		// RETURNING, VALUES, MERGE-action SET, ON CONFLICT DO UPDATE. A protected column read there — a
		// bare name PG binds column-first to the write target/outer (a correlated `(SELECT ssn)`), or a
		// whole-row value (`to_jsonb(u)`) — must still reach references. Resolve each column-first and add
		// any base not already referenced (dedup keeps bucket parity: cols the read/subquery passes
		// already routed are not duplicated). A column INSIDE a SELECT-bodied write's payload
		// (INSERT…SELECT via payloadQuery, CTAS/CREATE-VIEW via analyzeQuery) — its SELECT body, incl.
		// CTE/derived sources — is output/origins with dead-column elimination, so it is skipped here
		// (else dead columns over-deny). But RETURNING sits OUTSIDE the payload and
		// must still be swept — hence a per-column check, not a whole-write gate.
		// The QUALIFIED payload SELECT body of a SELECT-bodied write (INSERT…SELECT / CTAS / CREATE
		// VIEW). Its columns are output/origins with dead-column elimination — skip them; RETURNING,
		// which sits outside this, is still swept. (p.analyzeQuery/payloadQuery are pre-qualify nodes, so
		// they can't be matched against qroot columns — re-derive from qroot.)
		var payloadBody exp.Expression
		if p.qroot.Kind() == exp.KindInsert || p.qroot.Kind() == exp.KindCreate {
			if e := p.qroot.Expr(); e != nil && (e.Kind() == exp.KindSelect || e.Is(exp.TraitSetOperation)) {
				payloadBody = e
			}
		}
		for _, c := range p.qroot.FindAll(exp.KindColumn) {
			if destIDs[c] || p.col2scope[c] == nil {
				continue
			}
			if c.This() != nil && c.This().Kind() == exp.KindStar {
				continue
			}
			if within(c, payloadBody) || c.FindAncestor(exp.KindCTE) != nil {
				continue // inside the payload SELECT body, or a CTE definition — its consumers in the
				// write clauses are swept separately, so dead CTE columns don't over-deny.
			}
			var bases map[string]bool
			if c.TableName() != "" {
				bases = p.resolve(c, map[resolveKey]bool{})
			} else if r := p.relationOf(c.Name(), p.scopeChainFor(c), 0); r.scalar != nil {
				bases = r.scalar
			} else if r.rel != nil {
				bases = p.relationColumns(r.rel)
			}
			for b := range bases {
				if !p.alreadyReferenced(b) {
					p.addRef(OTHER, stringSet(b))
				}
			}
		}
		if p.payloadQuery != nil {
			branches := []exp.Expression{p.payloadQuery}
			if p.payloadQuery.Is(exp.TraitSetOperation) {
				branches = p.leafSelects(p.payloadQuery)
			}
			for _, s := range branches {
				p.addRef(OTHER, subtractSet(p.bases(s.Selects()), accounted))
			}
		}
		for _, j := range p.qroot.FindAll(exp.KindJoin) {
			for _, ident := range expressionsFor(j, "using") {
				bases, ok := wbase(ident.Name(), "", nil)
				if !ok {
					return failResult("VALIDATE", fmt.Sprintf("unresolved USING column '%s' in write", ident.Name()))
				}
				p.addRef(OTHER, subtractSet(bases, accounted))
			}
		}
		if len(p.qroot.FindAll(exp.KindStar)) > 0 {
			for _, table := range phys {
				for _, column := range p.tableColumns(table) {
					if key, found := p.columnKey(table, column); found {
						p.addRef(OTHER, stringSet(key))
					}
				}
			}
		}
		for _, fn := range p.qroot.FindAll(exp.TraitFunc) {
			if strings.ToLower(fn.Name()) == "values" {
				for _, a := range fn.FindAll(exp.KindIdentifier) {
					bases, ok := wbase(a.Name(), "", nil)
					if !ok {
						return failResult("VALIDATE", fmt.Sprintf("unresolved VALUES() column '%s' in write", a.Name()))
					}
					p.addRef(OTHER, subtractSet(bases, accounted))
				}
			}
		}
	}

	refsOut := map[string][]string{}
	for key, values := range p.references {
		if len(values) > 0 {
			refsOut[key] = sortedSet(values)
		}
	}
	traced := 0
	for _, origin := range origins {
		if len(origin.Origins) > 0 {
			traced++
		}
	}
	var writeTarget *tableID
	if p.isWrite {
		if node := p.writeTargetTable(); node != nil {
			if id, ok := p.resolvedTableID(node); ok {
				writeTarget = &id
			}
		}
	}
	return ProbeResult{
		Resolved:          true,
		FailedStage:       nil,
		Detail:            "ok",
		OutputColumns:     len(origins),
		TracedColumns:     traced,
		Origins:           origins,
		References:        refsOut,
		Sources:           p.scannedSources(origins, refsOut),
		Functions:         p.calledFunctions(),
		IsWrite:           p.isWrite,
		WriteTarget:       writeTarget,
		RewrittenSQL:      rewrittenSQL,
		PredicateLiterals: p.predicateLiteralRefs(),
	}
}

// predicateLiteralRefs renders the collected literal-vs-column comparisons in a stable order, so a golden
// file and a proto payload do not churn on map iteration.
func (p *prober) predicateLiteralRefs() []PredicateLiteralRef {
	if len(p.predicateLiterals) == 0 {
		return nil
	}
	keys := make([]string, 0, len(p.predicateLiterals))
	for k := range p.predicateLiterals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]PredicateLiteralRef, 0, len(keys))
	for _, k := range keys {
		out = append(out, PredicateLiteralRef{Column: k, Clause: p.predicateLiterals[k]})
	}
	return out
}

// calledFunctions emits the DISTINCT bare names of Anonymous function calls in the statement
// (docs/facts-emission.md). sqlglot drops a function's schema qualifier at parse time — `pg_catalog.
// pg_read_file`, `mysql.rds_kill`, and a bare `pg_read_file` are indistinguishable post-parse — so only the
// bare name is emitted; the control-plane resolver (SystemClassificationService.tagForFunction) classifies
// it against the datasource's system/logical schemas. Only Anonymous nodes are emitted: every vendor
// IO/exec/admin function (pg_read_file, dblink, lo_*, load_file, rds_*, keyring_*, get_raw_page, …) parses
// Anonymous, whereas standard-SQL builtins with dedicated node kinds (Count, Cast, Substring, …) are safe,
// out of the shipped dangerous set, and carry unreliable Name()s (`count(*)` → "*"). Names are lowercased
// so the resolver's fold-insensitive match is stable. The control plane classifies these names against the
// per-version manifest and the version-independent BaselineDangerousFunctions floor; functionCallGrants
// separately preserves qualifiers and provides the fail-closed Function grant.
func (p *prober) calledFunctions() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, fn := range p.root.FindAll(exp.TraitFunc) {
		if fn.Kind() != exp.KindAnonymous {
			continue
		}
		name := strings.ToLower(fn.Name())
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// scannedSources emits one SourceInfo per DISTINCT physical relation the statement scans
// (docs/facts-emission.md). p.physicalTables holds only relations the resolution report proved
// Physical — a shadowed CTE reference resolves to CTE/Derived and is absent, so `WITH t AS (...)
// SELECT count(*) FROM t` emits no physical `t` (ALLOW), while a CTE BODY that reads the real table
// does (a scanned source, gated). Write TARGETS are excluded upstream (p.newTargets is skipped in
// consumeResolutionReport), so an INSERT/UPDATE/DELETE target is never a scanned source.
//
// Coverage is per-TABLE and computed from the FINAL emitted facts: a table is covered iff some origin
// base or reference key begins with `<catalog.schema.table>.` — i.e. a column of it is a traced fact
// the column gate already authorizes. The trailing dot makes the prefix injective (a `users.` prefix
// never matches `users_archive.col`). An unqualified column that stays ambiguous resolves to no base
// key, so its table is left uncovered → gated, never silently covered. Over-attribution can only make
// a table appear UNCOVERED (a dotted pathological name failing the prefix) → over-deny, fail-closed.
func (p *prober) scannedSources(origins []OriginInfo, refs map[string][]string) []SourceInfo {
	baseKeys := map[string]bool{}
	for _, origin := range origins {
		for _, base := range origin.Origins {
			baseKeys[base] = true
		}
	}
	for _, values := range refs {
		for _, base := range values {
			baseKeys[base] = true
		}
	}
	// The write TARGET occurrence is gated by sql.<kind>, not result.read (docs/facts-emission.md:
	// "A write target is not a scanned Table solely because it is the target"). Exclude the target
	// NODE(s), not the tableID — a DIFFERENT occurrence of the same table (a subquery reading old
	// values) is a genuine scanned source and its column reads still emit facts / conservation applies.
	targets := p.writeTargetNodes()
	seen := map[tableID]bool{}
	out := []SourceInfo{}
	for node, id := range p.physicalTables {
		if targets[node] {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		prefix := id.String() + "."
		covered := false
		for base := range baseKeys {
			// A base key is `<catalog>.<schema>.<table>.<column>`. Coverage requires the prefix AND that
			// the remainder (the column) carries no further '.', so a table literally named "x.foo" (a
			// dot in the name) cannot make a clean sibling `x` look covered — its base key `…x.foo.col`
			// has a dotted remainder past the `x.` prefix. A delimiter-bearing identity therefore reads
			// as UNCOVERED → gated → DENIED downstream (authorizeTables/authorizeColumns reject it),
			// fail-closed, instead of relying on that Kotlin guard for correctness.
			if strings.HasPrefix(base, prefix) && !strings.Contains(base[len(prefix):], ".") {
				covered = true
				break
			}
		}
		out = append(out, SourceInfo{Catalog: id.catalog, Schema: id.schema, Table: id.table, Covered: covered})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Catalog != out[j].Catalog {
			return out[i].Catalog < out[j].Catalog
		}
		if out[i].Schema != out[j].Schema {
			return out[i].Schema < out[j].Schema
		}
		return out[i].Table < out[j].Table
	})
	return out
}

func expressionsFromAny(value any) []exp.Expression {
	switch v := value.(type) {
	case nil:
		return nil
	case exp.Expression:
		return []exp.Expression{v}
	case []exp.Expression:
		return v
	case []any:
		out := []exp.Expression{}
		for _, item := range v {
			if expr := asExpression(item); expr != nil {
				out = append(out, expr)
			}
		}
		return out
	default:
		return nil
	}
}

// addPredicateLiterals records every base column a LITERAL is compared against inside one predicate
// subtree, so the control plane can withhold statement text that carries a protected value
// (`WHERE ssn = '987-65-4320'` puts the value in the query, where masking cannot reach it).
//
// Best-effort by construction. A literal can also reach a column through a function, a CASE, a subquery,
// or a bound parameter, none of which this sees. That is why the fact may only ever HIDE text: a consumer
// must treat absence as unknown, never as proof the statement is safe.
//
// The analyzer states the fact and stops. It has no role context and must never acquire one — whether a
// column is CLASSIFIED (reader-neutrally) is the control plane's decision.
func (p *prober) addPredicateLiterals(root exp.Expression, clause string) {
	if root == nil {
		return
	}
	for _, node := range root.FindAll(exp.TraitPredicate) {
		if node == nil || p.enclosingOpaque(node) != nil {
			continue
		}
		// A comparison is interesting only when it actually carries a value. `a.x = b.y` has nothing to
		// leak; `x = 5`, `x IN ('a','b')`, and `x BETWEEN 1 AND 5` do. Different comparison kinds keep
		// their operands under different arg names (Between uses low/high, In uses expressions), so the
		// whole subtree is searched rather than a fixed operand list.
		if len(node.FindAll(exp.KindLiteral)) == 0 {
			continue
		}
		// Attribute to the columns of THIS comparison only. A column reached through a nested predicate
		// belongs to that node, which the same walk visits in its own right.
		for _, col := range node.FindAll(exp.KindColumn) {
			if nearestPredicate(col) != node {
				continue
			}
			for base := range p.bases([]exp.Expression{col}) {
				if p.predicateLiterals == nil {
					p.predicateLiterals = map[string]string{}
				}
				// First clause wins: one column compared in several places is still one fact, and the
				// clause is only for audit legibility.
				if _, seen := p.predicateLiterals[base]; !seen {
					p.predicateLiterals[base] = clause
				}
			}
		}
	}
}

// nearestPredicate walks up to the closest enclosing comparison, so a column is attributed to the
// comparison it actually participates in rather than to every predicate above it.
func nearestPredicate(e exp.Expression) exp.Expression {
	for cur := e; cur != nil; cur = cur.Parent() {
		if cur != e && cur.Is(exp.TraitPredicate) {
			return cur
		}
	}
	return nil
}

func (p *prober) addRef(ctx string, bases map[string]bool) {
	if len(bases) == 0 {
		return
	}
	if p.references[ctx] == nil {
		p.references[ctx] = map[string]bool{}
	}
	addSet(p.references[ctx], bases)
}

func (p *prober) findAllSetOperations(root exp.Expression) []exp.Expression {
	if root == nil {
		return nil
	}
	return root.FindAll(exp.TraitSetOperation)
}

func (p *prober) cteColNames(cte exp.Expression) []string {
	if cte == nil {
		return nil
	}
	cols := expressionsFor(cte, "columns")
	if len(cols) == 0 {
		al := asExpression(cte.Arg("alias"))
		cols = expressionsFor(al, "columns")
	}
	if len(cols) == 0 {
		return nil
	}
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, c.Name())
	}
	return out
}

func (p *prober) resolve(col exp.Expression, seen map[resolveKey]bool) map[string]bool {
	if col == nil {
		return map[string]bool{}
	}
	scope := p.col2scope[col]
	if scope == nil {
		return map[string]bool{}
	}
	return p.resolveIn(col.Name(), col.TableName(), scope, seen)
}

func (p *prober) resolveIn(name, alias string, scope *optimizer.Scope, seen map[resolveKey]bool) map[string]bool {
	key := resolveKey{scope: scope, alias: alias, name: name}
	if seen[key] {
		return map[string]bool{}
	}
	seen[key] = true
	for current := scope; current != nil; current = current.Parent {
		if alias != "" {
			src, ok := current.Sources[alias]
			if !ok {
				continue
			}
			if tbl, ok := src.(exp.Expression); ok && tbl != nil && tbl.Kind() == exp.KindTable {
				if column, found := p.columnKey(tbl, name); found {
					return stringSet(column)
				}
				return map[string]bool{}
			}
			if derived, ok := src.(*optimizer.Scope); ok {
				return p.resolveScopeOutput(derived, name, seen)
			}
			return map[string]bool{}
		}

		matches := []map[string]bool{}
		for _, src := range current.Sources {
			if tbl, ok := src.(exp.Expression); ok && tbl != nil && tbl.Kind() == exp.KindTable {
				if column, found := p.columnKey(tbl, name); found {
					matches = append(matches, stringSet(column))
				}
			} else if derived, ok := src.(*optimizer.Scope); ok {
				if columns := p.resolveScopeOutput(derived, name, seen); len(columns) > 0 {
					matches = append(matches, columns)
				}
			}
		}
		if len(matches) == 1 {
			return matches[0]
		}
		if len(matches) > 1 {
			return map[string]bool{}
		}
	}
	return map[string]bool{}
}

func (p *prober) resolveScopeOutput(scope *optimizer.Scope, outName string, seen map[resolveKey]bool) map[string]bool {
	out := map[string]bool{}
	if scope == nil || scope.Expression == nil {
		return out
	}
	expr := scope.Expression
	if expr.Is(exp.TraitSetOperation) {
		branches := p.leafSelects(expr)
		var names []string
		if cte := expr.Parent(); cte != nil && cte.Kind() == exp.KindCTE {
			names = p.cteColNames(cte)
		}
		if len(names) == 0 && len(branches) > 0 {
			for _, proj := range branches[0].Selects() {
				names = append(names, proj.AliasOrName())
			}
		}
		for i, nm := range names {
			if nm == outName {
				for _, br := range branches {
					selects := br.Selects()
					if i < len(selects) {
						addSet(out, p.bases([]exp.Expression{selects[i]}))
					}
				}
			}
		}
		return out
	}
	if scope.IsUnion() {
		for _, branch := range scope.UnionScopes {
			addSet(out, p.resolveScopeOutput(branch, outName, seen))
		}
		return out
	}
	if expr.Kind() != exp.KindSelect {
		return out
	}
	matched := []exp.Expression{}
	for _, proj := range expr.Selects() {
		if proj.AliasOrName() == outName {
			matched = append(matched, proj)
		}
	}
	if len(matched) == 0 {
		if cte := expr.Parent(); cte != nil && cte.Kind() == exp.KindCTE {
			names := p.cteColNames(cte)
			for i, nm := range names {
				if nm == outName && i < len(expr.Selects()) {
					matched = []exp.Expression{expr.Selects()[i]}
					break
				}
			}
		}
	}
	for _, proj := range matched {
		for _, c := range proj.FindAll(exp.KindColumn) {
			addSet(out, p.resolveIn(c.Name(), c.TableName(), scope, seen))
		}
	}
	return out
}

func (p *prober) resolveIdent(col exp.Expression, seen map[identKey]bool) (map[string]bool, bool) {
	if col == nil {
		return map[string]bool{}, true
	}
	scope := p.col2scope[col]
	if scope == nil {
		return map[string]bool{}, true
	}
	key := identKey{scope: scope, alias: col.TableName(), name: col.Name()}
	if seen[key] {
		return map[string]bool{}, true
	}
	seen2 := copyIdentSeen(seen)
	seen2[key] = true
	var src any
	for sc := scope; sc != nil; sc = sc.Parent {
		if col.TableName() != "" {
			if candidate, ok := sc.Sources[col.TableName()]; ok {
				src = candidate
				break
			}
		} else if len(sc.Sources) == 1 {
			for _, candidate := range sc.Sources {
				src = candidate
			}
			break
		}
	}
	if src == nil {
		return map[string]bool{}, true
	}
	if tbl, ok := src.(exp.Expression); ok && tbl != nil && tbl.Kind() == exp.KindTable {
		if key, found := p.columnKey(tbl, col.Name()); found {
			return stringSet(key), true
		}
		return map[string]bool{}, false
	}
	if sc, ok := src.(*optimizer.Scope); ok {
		return p.scopeOutIdent(sc, col.Name(), seen2)
	}
	return map[string]bool{}, true
}

func copyIdentSeen(in map[identKey]bool) map[identKey]bool {
	out := make(map[identKey]bool, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (p *prober) scopeOutIdent(scope *optimizer.Scope, outName string, seen map[identKey]bool) (map[string]bool, bool) {
	if scope == nil || scope.Expression == nil {
		return map[string]bool{}, true
	}
	expr := scope.Expression
	if expr.Is(exp.TraitSetOperation) {
		branches := p.leafSelects(expr)
		var names []string
		if cte := expr.Parent(); cte != nil && cte.Kind() == exp.KindCTE {
			names = p.cteColNames(cte)
		}
		if len(names) == 0 && len(branches) > 0 {
			for _, proj := range branches[0].Selects() {
				names = append(names, proj.AliasOrName())
			}
		}
		out, ident := map[string]bool{}, true
		for i, nm := range names {
			if nm == outName {
				for _, br := range branches {
					selects := br.Selects()
					if i < len(selects) {
						b, sub := p.projIdent(selects[i], seen)
						addSet(out, b)
						ident = ident && sub
					}
				}
			}
		}
		return out, ident
	}
	if scope.IsUnion() {
		out, ident := map[string]bool{}, true
		for _, branch := range scope.UnionScopes {
			b, sub := p.scopeOutIdent(branch, outName, seen)
			addSet(out, b)
			ident = ident && sub
		}
		return out, ident
	}
	if expr.Kind() != exp.KindSelect {
		return map[string]bool{}, true
	}
	matched := []exp.Expression{}
	for _, proj := range expr.Selects() {
		if proj.AliasOrName() == outName {
			matched = append(matched, proj)
		}
	}
	if len(matched) == 0 {
		if cte := expr.Parent(); cte != nil && cte.Kind() == exp.KindCTE {
			names := p.cteColNames(cte)
			for i, nm := range names {
				if nm == outName && i < len(expr.Selects()) {
					matched = []exp.Expression{expr.Selects()[i]}
					break
				}
			}
		}
	}
	out, ident := map[string]bool{}, true
	for _, proj := range matched {
		b, sub := p.projIdent(proj, seen)
		addSet(out, b)
		ident = ident && sub
	}
	return out, ident
}

// redactStringArgKinds is the whitelist of TOTAL, side-effect-free string-function node kinds whose
// output over a masked column may be redacted (not denied). The value maps each kind to the arg names
// that carry STRING operands (recursed into as redactable subtrees); EVERY OTHER present arg must be a
// literal. That keeps a numeric arg (e.g. SUBSTRING start/length) from carrying the column into a
// coercion, and stops any fault-capable subexpression from hiding in a non-string position.
var redactStringArgKinds = map[exp.Kind][]string{
	exp.KindUpper:     {"this", "expressions"},
	exp.KindLower:     {"this", "expressions"},
	exp.KindInitcap:   {"this", "expression"},
	exp.KindLength:    {"this"},
	exp.KindHex:       {"this"},
	exp.KindMD5:       {"this", "expressions"},
	exp.KindSHA2:      {"this"}, // length arg must be a literal
	exp.KindTrim:      {"this", "expression"},
	exp.KindReplace:   {"this", "expression", "replacement"},
	exp.KindConcat:    {"expressions"},
	exp.KindCoalesce:  {"this", "expressions"},
	exp.KindSubstring: {"this"}, // start/length args must be literals
}

// redactAnonFns whitelists TOTAL string functions that parse Anonymous (no dedicated kind), mapping the
// lowercased name to the count of LEADING positional args that carry string operands; the remaining
// args must be literals (e.g. LEFT(str, n) → 1 string arg, n literal).
var redactAnonFns = map[string]int{
	// leading-string-arg count 1 (the rest must be literals)
	"left": 1, "right": 1, "substr": 1, "substring": 1, "mid": 1,
	// single string arg
	"upper": 1, "lower": 1, "ucase": 1, "lcase": 1, "reverse": 1, "initcap": 1,
	"length": 1, "char_length": 1, "character_length": 1, "octet_length": 1, "bit_length": 1,
	"ltrim": 1, "rtrim": 1, "md5": 1, "sha": 1, "sha1": 1, "hex": 1, "quote": 1,
}

func isLiteralNode(e exp.Expression) bool {
	if e == nil {
		return true
	}
	switch e.Kind() {
	case exp.KindLiteral, exp.KindNull, exp.KindBoolean:
		return true
	}
	return false
}

// redactableTransform reports whether proj is a provably TOTAL, side-effect-free transform of the
// masked column: a tree built ONLY from the column, literals, and whitelisted total string functions
// (with every numeric/other argument a literal). Such an output can be safely redacted in full (kind
// NULL) rather than denied, because it cannot fault or warn on the value — so executing it leaks nothing
// through the error-presence / SQLSTATE / warning-count channels. ANYTHING else in the tree — arithmetic
// (division/overflow), cast/coercion, comparison, conditional (CASE/IF), aggregate/window/subquery, or a
// non-whitelisted call — makes the output value-dependent-fault-capable, so it returns false → the
// projection stays a DERIVED reference → DENY. (A blacklist can't be sound here: "does it fault" is
// itself a predicate on the value, and overflow/division/coercion fault intrinsically.)
func (p *prober) redactableTransform(node exp.Expression) bool {
	for node != nil && (node.Kind() == exp.KindParen || node.Kind() == exp.KindAlias) {
		node = node.This()
	}
	if node == nil {
		return false
	}
	switch node.Kind() {
	case exp.KindNull:
		return true
	case exp.KindLiteral:
		// A literal in a STRING-operand position must be a string literal. A numeric/other literal here —
		// e.g. COALESCE(ssn, 0) — forces a type-unification that can constant-fault on PostgreSQL (a
		// value-INDEPENDENT error, not an oracle, but the analyzer must not vouch a query that always
		// errors). Numeric args in numeric positions (SUBSTRING start/length, LEFT n) are unaffected —
		// they go through the literal-required branch below, not this string recursion.
		return node.IsString()
	case exp.KindColumn:
		// A column leaf is redactable only if it is a pure IDENTITY reference to a base column — NOT a
		// column that resolves (through a subquery / derived table / CTE) to a hidden transform. Without
		// this, an oracle buried one scope down — `SELECT c FROM (SELECT cast(ssn AS json) AS c) t`, or
		// even `SELECT upper(c) FROM (…)` — would slip past this surface whitelist yet still execute in
		// the subquery. isID=false means a value-changing transform hides below; fail closed.
		_, isID := p.projIdent(node, map[identKey]bool{})
		return isID
	case exp.KindAnonymous:
		n := redactAnonFns[strings.ToLower(node.Name())]
		if n == 0 {
			return false
		}
		for i, a := range expressionsFromAny(node.Arg("expressions")) {
			if i < n {
				if !p.redactableTransform(a) {
					return false
				}
			} else if !isLiteralNode(a) {
				return false
			}
		}
		return true
	}
	stringArgs, ok := redactStringArgKinds[node.Kind()]
	if !ok {
		return false
	}
	strSet := map[string]bool{}
	for _, s := range stringArgs {
		strSet[s] = true
	}
	for name, val := range exp.ArgsOf(node) {
		elems := expressionsFromAny(val)
		if strSet[name] {
			for _, e := range elems {
				if !p.redactableTransform(e) {
					return false
				}
			}
		} else {
			for _, e := range elems {
				if !isLiteralNode(e) {
					return false
				}
			}
		}
	}
	return true
}

func (p *prober) projIdent(proj exp.Expression, seen map[identKey]bool) (map[string]bool, bool) {
	ic := p.identityCol(proj)
	if ic == nil {
		out := map[string]bool{}
		if proj != nil {
			for _, c := range proj.FindAll(exp.KindColumn) {
				b, _ := p.resolveIdent(c, seen)
				addSet(out, b)
			}
		}
		return out, false
	}
	return p.resolveIdent(ic, seen)
}

func (p *prober) identityCol(proj exp.Expression) exp.Expression {
	for proj != nil && proj.Kind() == exp.KindAlias {
		proj = proj.This()
	}
	if proj != nil && proj.Kind() == exp.KindColumn {
		return proj
	}
	return nil
}

func (p *prober) bases(nodes []exp.Expression) map[string]bool {
	out := map[string]bool{}
	for _, n := range nodes {
		if n == nil {
			continue
		}
		cols := []exp.Expression{n}
		if n.Kind() != exp.KindColumn {
			cols = n.FindAll(exp.KindColumn)
		}
		for _, c := range cols {
			addSet(out, p.resolve(c, map[resolveKey]bool{}))
		}
	}
	return out
}

func (p *prober) leafSelects(setop exp.Expression) []exp.Expression {
	out := []exp.Expression{}
	if setop == nil {
		return out
	}
	for _, side := range []exp.Expression{setop.Left(), setop.Right()} {
		if side == nil {
			continue
		}
		if side.Is(exp.TraitSetOperation) {
			out = append(out, p.leafSelects(side)...)
		} else if side.Kind() == exp.KindSelect {
			out = append(out, side)
		} else if side.Kind() == exp.KindSubquery {
			inner := side.This()
			if inner != nil && inner.Is(exp.TraitSetOperation) {
				out = append(out, p.leafSelects(inner)...)
			} else if inner != nil && inner.Kind() == exp.KindSelect {
				out = append(out, inner)
			}
		}
	}
	return out
}

func (p *prober) fromSourceOrder(sel exp.Expression) []string {
	aliasOf := func(src exp.Expression) string {
		if src == nil {
			return ""
		}
		if src.Kind() == exp.KindSubquery {
			return src.Alias()
		}
		if src.Kind() == exp.KindTable {
			if alias := src.Alias(); alias != "" {
				return alias
			}
			return src.Name()
		}
		return ""
	}
	order := []string{}
	if frm := asExpression(sel.Arg("from_")); frm != nil {
		order = append(order, aliasOf(frm.This()))
		for _, e := range expressionsFor(frm, "expressions") {
			order = append(order, aliasOf(e))
		}
	}
	for _, j := range expressionsFor(sel, "joins") {
		if j.This() != nil {
			order = append(order, aliasOf(j.This()))
		}
	}
	out := []string{}
	for _, item := range order {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (p *prober) isStar(proj exp.Expression) bool {
	return proj != nil && (proj.Kind() == exp.KindStar || (proj.Kind() == exp.KindColumn && proj.This() != nil && proj.This().Kind() == exp.KindStar))
}

func (p *prober) expandableSources(sel exp.Expression) (bool, string) {
	srcs := []exp.Expression{}
	if frm := asExpression(sel.Arg("from_")); frm != nil {
		srcs = append(srcs, frm.This())
	}
	for _, j := range expressionsFor(sel, "joins") {
		srcs = append(srcs, j.This())
	}
	for _, s := range srcs {
		if s == nil {
			return false, "a <nil> source (table-function / VALUES / LATERAL)"
		}
		if s.Kind() == exp.KindSubquery {
			continue
		}
		if s.Kind() == exp.KindTable && s.This() != nil && s.This().Kind() == exp.KindIdentifier {
			continue
		}
		kind := exp.ClassName(s.Kind())
		if s.Kind() == exp.KindTable && s.This() != nil {
			kind = exp.ClassName(s.This().Kind())
		}
		return false, fmt.Sprintf("a %s source (table-function / VALUES / LATERAL)", strings.ToLower(kind))
	}
	return true, ""
}

// Table aliases recorded before Qualify compare folded (MySQL lower_case_table_names folds them
// during qualification; the projection carries the folded spelling).
func (p *prober) naturalStarProjectionMatches(projection exp.Expression, expected naturalStarColumn) bool {
	if projection == nil || projection.AliasOrName() != expected.name {
		return false
	}
	foldTable := func(name string) string { return p.dialect.FoldIdentifierName(name, true) }
	actualTables := map[string]bool{}
	for _, column := range projection.FindAll(exp.KindColumn) {
		if column.Name() != expected.name || column.TableName() == "" {
			return false
		}
		actualTables[foldTable(column.TableName())] = true
	}
	if len(actualTables) != len(expected.tables) {
		return false
	}
	for _, table := range expected.tables {
		if !actualTables[foldTable(table)] {
			return false
		}
	}
	return true
}

func (p *prober) resortBareStarInplace(osel, qsel exp.Expression) {
	starIdx := -1
	for i, proj := range osel.Selects() {
		if proj.Kind() == exp.KindStar {
			starIdx = i
			break
		}
	}
	if starIdx < 0 {
		return
	}
	qs := qsel.Selects()
	nb, na := starIdx, len(osel.Selects())-starIdx-1
	fo := p.fromSourceOrder(qsel)
	pos := map[string]int{}
	for i, alias := range fo {
		pos[alias] = i
	}
	block := append([]exp.Expression(nil), qs[nb:len(qs)-na]...)
	if order, ok := p.naturalStarOrders[qsel]; ok {
		delete(p.naturalStarPending, qsel)
		if len(order) != len(block) {
			panic(fmt.Errorf("NATURAL JOIN star expansion produced %d columns, want %d", len(block), len(order)))
		}
		ordered := make([]exp.Expression, 0, len(block))
		used := make([]bool, len(block))
		for _, column := range order {
			matched := -1
			for i, projection := range block {
				if !used[i] && p.naturalStarProjectionMatches(projection, column) {
					matched = i
					break
				}
			}
			if matched < 0 {
				panic(fmt.Errorf("NATURAL JOIN star output %q could not be ordered faithfully", column.name))
			}
			used[matched] = true
			ordered = append(ordered, block[matched])
		}
		identity := true
		for i := range ordered {
			if ordered[i] != block[i] {
				identity = false
				break
			}
		}
		// Qualify already rebound positional ORDER BY/GROUP BY ordinals against the pre-merge
		// expansion; reordering the select list would leave them pointing at the wrong column.
		if !identity && selectUsesPositionalOrdinals(osel) {
			panic(fmt.Errorf("positional ORDER BY/GROUP BY over a NATURAL/USING star — ordinals cannot bind faithfully"))
		}
		newSelects := append([]exp.Expression(nil), qs[:nb]...)
		newSelects = append(newSelects, ordered...)
		newSelects = append(newSelects, qs[len(qs)-na:]...)
		qsel.Set("expressions", newSelects)
		return
	}
	position := func(proj exp.Expression) int {
		if col := proj.Find(exp.KindColumn); col != nil {
			if value, ok := pos[col.TableName()]; ok {
				return value
			}
		}
		return len(fo)
	}
	sort.SliceStable(block, func(i, j int) bool { return position(block[i]) < position(block[j]) })
	newSelects := append([]exp.Expression(nil), qs[:nb]...)
	newSelects = append(newSelects, block...)
	newSelects = append(newSelects, qs[len(qs)-na:]...)
	qsel.Set("expressions", newSelects)
}

func selectUsesPositionalOrdinals(sel exp.Expression) bool {
	for _, arg := range []string{"order", "group"} {
		clause := asExpression(sel.Arg(arg))
		if clause == nil {
			continue
		}
		for _, lit := range clause.FindAll(exp.KindLiteral) {
			if !truthy(lit.Arg("is_string")) {
				if _, err := strconv.Atoi(lit.Name()); err == nil {
					return true
				}
			}
		}
	}
	return false
}
func (p *prober) cteReferenced(cte exp.Expression, root exp.Expression) bool {
	if cte == nil || root == nil || cte.This() == nil {
		return false
	}
	body := cte.This()
	scopes := optimizer.TraverseScope(root)
	if root.Kind() == exp.KindInsert {
		for _, query := range queryIslands(root) {
			scopes = append(scopes, p.traverseQueryIsland(query)...)
		}
	}
	for _, scope := range scopes {
		for _, selected := range scope.SelectedSources() {
			source, ok := selected.Source.(*optimizer.Scope)
			if !ok || source == nil || source.Expression != body {
				continue
			}
			// A recursive self-reference does not make an otherwise dead CTE live. References from
			// consumers and sibling CTEs do; the outer pruning loop removes dead dependency chains.
			if selected.Node == nil || !within(selected.Node, body) {
				return true
			}
		}
	}
	return false
}

func (p *prober) setAssignments(node exp.Expression) []exp.Expression {
	out := []exp.Expression{}
	for _, upd := range node.FindAll(exp.KindUpdate) {
		for _, e := range expressionsFor(upd, "expressions") {
			if e.Kind() == exp.KindEQ {
				out = append(out, e)
			}
		}
	}
	for _, oc := range node.FindAll(exp.KindOnConflict) {
		for _, e := range expressionsFor(oc, "expressions") {
			if e.Kind() == exp.KindEQ {
				out = append(out, e)
			}
		}
	}
	return out
}

func (p *prober) isExpressionSubquery(node exp.Expression) bool {
	for parent := node.Parent(); parent != nil; parent = parent.Parent() {
		switch parent.Kind() {
		case exp.KindExists, exp.KindIn, exp.KindAny, exp.KindAll:
			return true
		}
		if parent.Is(exp.TraitFunc) || parent.Kind() == exp.KindArray || parent.Kind() == exp.KindUnnest {
			return true
		}
		if parent.Kind() == exp.KindSubquery {
			gp := parent.Parent()
			if gp != nil && (gp.Kind() == exp.KindFrom || gp.Kind() == exp.KindJoin) {
				return false
			}
			if gp != nil && gp.Kind() == exp.KindLateral {
				return true
			}
			if gp == nil || !gp.Is(exp.TraitSetOperation) {
				return true
			}
		}
		if parent.Kind() == exp.KindLateral {
			return true
		}
		if parent.Kind() == exp.KindFrom || parent.Kind() == exp.KindJoin {
			return false
		}
		if parent.Kind() == exp.KindSelect || parent.Kind() == exp.KindInsert || parent.Kind() == exp.KindUpdate || parent.Kind() == exp.KindMerge || parent.Kind() == exp.KindDelete || parent.Kind() == exp.KindCreate {
			return false
		}
	}
	return false
}

func (p *prober) enclosingOpaque(node exp.Expression) exp.Expression {
	for parent := node.Parent(); parent != nil; parent = parent.Parent() {
		if p.opaqueSelects[parent] {
			return parent
		}
	}
	return nil
}

// The relation resolver — srcInScope, relationOfNode, relationField, relationColumns — lives in
// relation.go (composite / whole-row / relation-valued-column resolution).
