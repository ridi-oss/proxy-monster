package probe

import (
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/optimizer"
)

// relation.go — the one relation resolver (see docs/relation-model.md).
//
// A relation used as a VALUE — a bare relation name / whole-row `TableColumn`, or a relation-valued
// column (`SELECT users AS sub`) — denotes the TUPLE of its columns. Composite field access `(x).f`,
// and nested `((a).b).c`, is identical to ordinary column access `x.f`. Everything routes through:
//
//	relationOfNode(node)      node used as a relation  -> a physical table or a derived *Scope
//	relationField(rel, f)     rel.f as a scalar        -> the specific base column(s)   (found=false => DENY)
//	relationColumns(rel)      rel as a whole row       -> ALL its base columns
//
// The recursive cases (a relation-valued column, a nested composite) are what the per-node handling
// missed: sqlglot's scope collects `exp.Column` and skips `TableColumn`, so a `users AS sub`
// projection resolves to nothing (the leak). Here a relation-valued projection is followed through to
// its underlying relation. Fail-closed throughout: anything unresolvable returns found=false / the
// caller expands to the whole relation, so a protected column can never slip out un-referenced.

const relMaxDepth = 24 // guard against pathological/cyclic composite chains

// srcInScope resolves a bare name to its source (an exp.Table or a *optimizer.Scope), column-first is
// already applied by qualify (it only emits TableColumn for genuine relations). Resolution starts from
// the node's own scope when available, otherwise its enclosing SELECT, and chain-walks through the native
// DML-root scope for write clauses.
func (p *prober) srcInScope(node exp.Expression, nm string) any {
	for _, sc := range p.scopeChainFor(node) {
		if src, ok := sc.Sources[nm]; ok {
			return src
		}
	}
	return nil
}

// alreadyReferenced reports whether `base` (a "table.col") is present in any reference bucket — used by
// the write-side conservation sweep to add only genuinely-missed columns (preserving bucket parity).
func (p *prober) alreadyReferenced(base string) bool {
	for _, cols := range p.references {
		if cols[base] {
			return true
		}
	}
	return false
}

// within reports whether node is ancestor or a descendant of it (walking Parent links).
func within(node, ancestor exp.Expression) bool {
	if node == nil || ancestor == nil {
		return false
	}
	for n := node; n != nil; n = n.Parent() {
		if n == ancestor {
			return true
		}
	}
	return false
}

func unwrapParen(e exp.Expression) exp.Expression {
	for e != nil && e.Kind() == exp.KindParen {
		e = e.This()
	}
	return e
}

// scopeChainFor is the chain a bare identifier at `node` resolves against, PG-style: prefer the
// node's own scope, otherwise its enclosing SELECT, then chain-walk parents (correlation) and finally
// the native DML-root scope. One walk covers reads and write clauses such as SET and RETURNING.
func (p *prober) scopeChainFor(node exp.Expression) []*optimizer.Scope {
	start := p.col2scope[node]
	if start == nil {
		if sel := node.FindAncestor(exp.KindSelect); sel != nil {
			start = p.scopeOfSelect[sel]
		}
	}
	var chain []*optimizer.Scope
	seen := map[*optimizer.Scope]bool{}
	hasDMLRoot := false
	for sc := start; sc != nil && !seen[sc]; sc = sc.Parent {
		seen[sc] = true
		chain = append(chain, sc)
		if sc.Expression == p.qroot {
			hasDMLRoot = true
		}
	}
	if p.writeScope != nil && !hasDMLRoot {
		chain = append(chain, p.writeScope)
	}
	return chain
}

// relResult is the tri-state of resolving a bare name used in value position (docs/relation-model.md):
// a SCALAR column (its base cols) — which shadows any relation; a RELATION (table/derived scope, incl.
// a relation-valued column) — which beats a same-named alias; or unresolved (both nil).
type relResult struct {
	scalar map[string]bool // non-nil: a scalar column, these are its base column(s)
	rel    any             // non-nil: a relation (exp.Table | *optimizer.Scope)
}

// relationOf applies PG's column-first, full-chain rule to a bare `name`: walking inner→outer, the
// first source that exposes `name` as a COLUMN wins — a scalar column (its base cols) or a
// relation-valued column (its underlying relation). A column of ANY scope shadows a same-named source
// alias (so a correlated `ssn` binds to the outer users.ssn, and `(sub).ssn` with `SELECT users AS
// sub` picks the users row over a decoy `orders sub` alias); only a name that is a column nowhere is a
// bare relation alias. `depth` guards the recursion — a relation-valued column's value is itself
// resolved — and overflow returns unresolved (the caller fails closed).
func (p *prober) relationOf(name string, chain []*optimizer.Scope, depth int) relResult {
	if depth > relMaxDepth {
		p.relOverflow = true // fail-closed: lineage() turns this into resolved=false
		return relResult{}
	}
	// `name` is used AS-IS: the fold pass already lowercased unquoted identifiers (and preserved
	// case-sensitive PG-quoted ones), so it matches source/projection keys in every dialect; only
	// schema-column lookups (in scopeColumn) lowercase, to match the lowercased schema.
	for _, sc := range chain { // columns first (innermost scope wins); shadows any same-named alias
		if r := p.scopeColumn(sc, name, depth); r.scalar != nil || r.rel != nil {
			return r
		}
	}
	for _, sc := range chain { // then a bare source alias = the whole relation
		if src, ok := sc.Sources[name]; ok {
			return relResult{rel: src}
		}
	}
	return relResult{}
}

// relationBaseOf resolves the BASE of composite field access `(name).field` to a relation. Unlike
// relationOf it does NOT let a scalar column shadow: a relation-valued column still beats a same-named
// alias, but a name that is merely a scalar column (`(id).ssn` where id is also a column) is treated
// as the relation anyway — real PG errors on `.field` of a scalar (`column notation .ssn applied to
// type bigint`), so treating the base as a relation can only OVER-count what a genuine whole-row
// access exposes, never under-count it (fail-safe; see docs/relation-model.md _dot_base_relation).
func (p *prober) relationBaseOf(name string, chain []*optimizer.Scope, depth int) (any, bool) {
	if depth > relMaxDepth {
		p.relOverflow = true
		return nil, false
	}
	for _, sc := range chain { // a relation-valued column beats a same-named alias (decoy)
		if r := p.scopeColumn(sc, name, depth); r.rel != nil {
			return r.rel, true
		}
	}
	for _, sc := range chain { // a source alias = the whole relation (incl. a scalar-column collision)
		if src, ok := sc.Sources[name]; ok {
			return src, true
		}
	}
	return nil, false
}

// scopeColumn resolves how `name` appears as a column of some source directly in `sc`: a scalar column
// (its base cols), a relation-valued column (the relation its value carries — determined by resolving
// that value, NOT a static node-shape check, so it works even where a write's disabled qualify left a
// relation reference as a bare exp.Column), or not a column here.
func (p *prober) scopeColumn(sc *optimizer.Scope, name string, depth int) relResult {
	for _, src := range sc.Sources {
		if tbl, ok := src.(exp.Expression); ok && tbl != nil && tbl.Kind() == exp.KindTable {
			if key, found := p.columnKey(tbl, name); found {
				return relResult{scalar: map[string]bool{key: true}}
			}
		} else if scope, ok := src.(*optimizer.Scope); ok && scope != nil {
			if val := p.scopeProjectionValue(scope, name); val != nil {
				if rel, ok := p.relationOfNode(val, depth+1); ok {
					return relResult{rel: rel} // a relation-valued column
				}
				return relResult{scalar: p.resolveScopeOutput(scope, name, map[resolveKey]bool{})} // scalar derived output
			}
		}
	}
	return relResult{}
}

// scopeProjectionValue returns the value expression of a derived scope's output column `name`
// (unwrapping the AS alias), or nil. This is the node whose shape tells us whether the column is
// relation-valued (a TableColumn / relation reference) or an ordinary scalar.
func (p *prober) scopeProjectionValue(sc *optimizer.Scope, name string) exp.Expression {
	if sc == nil || sc.Expression == nil || sc.Expression.Kind() != exp.KindSelect {
		return nil
	}
	// Match AS-IS: aliases/output names come from the fold pass (unquoted → lower, PG-quoted preserved),
	// so a raw compare is correct in every dialect; a re-.lower() here would miss a quoted PG alias.
	for _, proj := range sc.Expression.Selects() {
		if proj.AliasOrName() == name {
			if proj.Kind() == exp.KindAlias {
				return proj.This()
			}
			return proj
		}
	}
	// CTE column-alias list: (WITH t(a,b) AS ...)
	if cte := sc.Expression.Parent(); cte != nil && cte.Kind() == exp.KindCTE {
		names := p.cteColNames(cte)
		selects := sc.Expression.Selects()
		for i, nm := range names {
			if nm == name && i < len(selects) {
				proj := selects[i]
				if proj.Kind() == exp.KindAlias {
					return proj.This()
				}
				return proj
			}
		}
	}
	return nil
}

// isRelationValued reports whether a projection value denotes a whole relation (a bare relation name
// / TableColumn, or a composite field access) rather than a scalar.
func isRelationValued(val exp.Expression) bool {
	val = unwrapParen(val)
	if val == nil {
		return false
	}
	switch val.Kind() {
	case exp.KindTableColumn:
		return true
	case exp.KindDot:
		return true // (x).y used as a value may itself be relation-valued; resolved recursively
	}
	return false
}

// relationOfNode resolves a node USED AS A RELATION to its underlying relation: a physical table
// (exp.Table) or a derived *optimizer.Scope. Returns found=false if the node is a scalar column or
// cannot be resolved (→ caller fails closed).
func (p *prober) relationOfNode(node exp.Expression, depth int) (any, bool) {
	if node == nil {
		return nil, false
	}
	if depth > relMaxDepth {
		p.relOverflow = true
		return nil, false
	}
	node = unwrapParen(node)
	switch node.Kind() {
	case exp.KindTableColumn:
		// a relation base: relation-valued column beats an alias, but a scalar collision still resolves
		// to the relation (a scalar Dot-base errors in PG — fail-safe over-count).
		return p.relationBaseOf(node.Name(), p.scopeChainFor(node), depth)

	case exp.KindColumn:
		tbl := node.TableName() // AS-IS (folded); see scopeProjectionValue
		nm := node.Name()
		if tbl == "" {
			return p.relationBaseOf(nm, p.scopeChainFor(node), depth)
		}
		// t.c — a relation-valued column: resolve source t, then follow projection c.
		if sc, ok := p.srcInScope(node, tbl).(*optimizer.Scope); ok && sc != nil {
			if val := p.scopeProjectionValue(sc, nm); val != nil {
				return p.relationOfNode(val, depth+1)
			}
		}
		return nil, false // a column of a physical table used as a relation: composite type we can't model

	case exp.KindDot:
		innerRel, ok := p.relationOfNode(node.This(), depth+1)
		if !ok {
			return nil, false
		}
		field := ""
		if node.Expr() != nil {
			field = node.Expr().Name()
		}
		return p.relationOfField(innerRel, field, depth+1)

	case exp.KindSubquery:
		// composite field access on a scalar subquery's row: `(SELECT ... LIMIT 1).field`. The
		// subquery's scope IS the relation; relationField/relationColumns then resolves the field (or
		// expands a relation-valued single projection like `SELECT u`). Otherwise invisible — the Dot
		// base is neither a TableColumn nor a Column.
		if inner := node.This(); inner != nil {
			if sc := p.scopeOfSelect[inner]; sc != nil {
				return sc, true
			}
		}
		return nil, false
	}
	return nil, false
}

// relationOfField returns the relation denoted by rel.field, when `field` is itself relation-valued
// (walks nested composites). found=false when field is scalar or unresolvable.
func (p *prober) relationOfField(rel any, field string, depth int) (any, bool) {
	if depth > relMaxDepth {
		p.relOverflow = true
		return nil, false
	}
	if field == "" {
		return nil, false
	}
	sc, ok := rel.(*optimizer.Scope)
	if !ok || sc == nil {
		return nil, false // a physical table's column as a relation: unmodellable composite → fail closed
	}
	val := p.scopeProjectionValue(sc, field)
	if val == nil || !isRelationValued(val) {
		return nil, false
	}
	return p.relationOfNode(val, depth+1)
}

// relationColumns expands a relation (used as a whole-row value) to ALL its base columns. A
// relation-valued projection is followed through to its underlying relation.
func (p *prober) relationColumns(rel any) map[string]bool {
	out := map[string]bool{}
	p.collectRelationColumns(rel, out, 0)
	return out
}

func (p *prober) collectRelationColumns(rel any, out map[string]bool, depth int) {
	if rel == nil {
		return
	}
	if depth > relMaxDepth {
		p.relOverflow = true
		return
	}
	if tbl, ok := rel.(exp.Expression); ok && tbl != nil && tbl.Kind() == exp.KindTable {
		if _, found := p.resolvedTableID(tbl); !found {
			return
		}
		for _, column := range p.tableColumns(tbl) {
			if key, ok := p.columnKey(tbl, column); ok {
				out[key] = true
			}
		}
		return
	}
	sc, ok := rel.(*optimizer.Scope)
	if !ok || sc == nil || sc.Expression == nil {
		return
	}
	expr := sc.Expression
	if expr.Is(exp.TraitSetOperation) {
		for _, br := range p.leafSelects(expr) {
			addSet(out, p.bases(br.Selects()))
		}
		return
	}
	if expr.Kind() != exp.KindSelect {
		return
	}
	for _, proj := range expr.Selects() {
		val := proj
		if proj.Kind() == exp.KindAlias {
			val = proj.This()
		}
		if isRelationValued(val) {
			if inner, ok := p.relationOfNode(val, depth+1); ok {
				p.collectRelationColumns(inner, out, depth+1)
				continue
			}
		}
		addSet(out, p.bases([]exp.Expression{proj}))
	}
}

// relationField resolves rel.field (scalar composite access) to its specific base column(s).
// found=false => the caller must fail closed (treat as reading the whole relation / DENY).
func (p *prober) relationField(rel any, field string) (map[string]bool, bool) {
	if field == "" {
		return nil, false
	}
	if tbl, ok := rel.(exp.Expression); ok && tbl != nil && tbl.Kind() == exp.KindTable {
		if key, found := p.columnKey(tbl, field); found {
			return map[string]bool{key: true}, true
		}
		return nil, false // unknown field of a known table → fail closed
	}
	if sc, ok := rel.(*optimizer.Scope); ok && sc != nil {
		// a relation-valued derived output is itself a whole row → all its columns
		if val := p.scopeProjectionValue(sc, field); val != nil && isRelationValued(val) {
			if inner, ok := p.relationOfNode(val, 0); ok {
				return p.relationColumns(inner), true
			}
			return nil, false
		}
		bases := p.resolveScopeOutput(sc, field, map[resolveKey]bool{})
		return bases, len(bases) > 0
	}
	return nil, false
}
