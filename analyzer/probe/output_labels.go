package probe

import (
	"fmt"
	"regexp"

	exp "github.com/ridi-oss/sqlglot-go/expressions"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

var syntheticLabelPattern = regexp.MustCompile(`^_col_\d+$`)

var functionLabelPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// hasSyntheticAlias reports whether root aliases anything as `_col_N`. On a qualified tree it
// means Qualify synthesized labels; on the client's ORIGINAL tree it means client labels are
// indistinguishable from synthetic ones, so native-label stamping must be skipped.
func hasSyntheticAlias(root exp.Expression) bool {
	if root == nil {
		return false
	}
	for _, alias := range root.FindAll(exp.KindAlias) {
		if syntheticLabelPattern.MatchString(alias.Alias()) {
			return true
		}
	}
	return false
}

// stampNativeOutputLabels aliases every unaliased computed projection of every SELECT in root
// with the label the engine's target DB would natively assign, BEFORE Qualify runs — so Qualify
// never synthesizes `_col_N` for them, the star expansion references real names, and a client
// reference to a native label (`SELECT c."current_database" FROM (SELECT current_database()) c`,
// valid on the real DB) resolves instead of failing closed.
//
// Duplicate labels follow the target DB's own error direction, verified against PG 16 and MySQL
// 8.0: MySQL rejects a derived-table/CTE body with duplicated labels outright (ER_DUP_FIELDNAME,
// case-insensitive), so that returns an error → the statement fails VALIDATE. PostgreSQL accepts
// duplicated OUTPUT labels and rejects only a REFERENCE to one ("column reference is ambiguous"),
// so a PG duplicate is not stamped (references stay unresolvable) and errors only when the query
// references it through the source alias. A SELECT whose list contains a star is never stamped —
// the star hides labels this pass cannot count. A label the engine cannot compute is left to
// Qualify (its synthetic name may then surface; restoreRelayOutputLabels repairs display labels).
func stampNativeOutputLabels(root exp.Expression, eng engine) error {
	derived := derivedBodySelects(root)
	for _, sel := range root.FindAll(exp.KindSelect) {
		projections := sel.Selects()
		hasStar := false
		for _, projection := range projections {
			if projectionIsStar(projection) {
				hasStar = true
			}
		}

		// A projection is unaliased when it is not an Alias node and not itself a named column —
		// a bare column's own name IS its label and needs no stamp.
		type stamp struct {
			projection exp.Expression
			label      string
		}
		inUse := map[string][]string{} // folded label → display labels seen
		stamps := []stamp{}
		for _, projection := range projections {
			if projection.Kind() == exp.KindAlias || projection.Kind() == exp.KindColumn || projectionIsStar(projection) {
				if name := projection.AliasOrName(); name != "" {
					inUse[eng.FoldColumn(name)] = append(inUse[eng.FoldColumn(name)], name)
				}
				continue
			}
			label, ok := eng.NativeOutputLabel(projection, sel)
			if !ok || label == "" {
				continue
			}
			inUse[eng.FoldColumn(label)] = append(inUse[eng.FoldColumn(label)], label)
			stamps = append(stamps, stamp{projection, label})
		}

		if alias, isDerived := derived[sel]; isDerived && !hasStar {
			for folded, names := range inUse {
				if len(names) < 2 {
					continue
				}
				if eng.Type() == pb.Engine_MYSQL {
					// Real MySQL rejects the derived table itself: ER_DUP_FIELDNAME.
					return fmt.Errorf("duplicate column name '%s' in derived table", names[0])
				}
				// Real PostgreSQL rejects only a reference to the duplicated label.
				if alias != "" && referencesLabel(root, sel, alias, folded, eng) {
					return fmt.Errorf("column reference %q is ambiguous", names[0])
				}
			}
		}
		if hasStar {
			continue // a star hides labels; stamping here could collide with a hidden name
		}

		stamped := map[exp.Expression]string{}
		for _, s := range stamps {
			if len(inUse[eng.FoldColumn(s.label)]) > 1 {
				continue
			}
			stamped[s.projection] = s.label
		}
		if len(stamped) == 0 {
			continue
		}
		// Rebuild the select list with explicit Alias wrappers — AliasExpr would set an `alias`
		// ARG on kinds that accept one (a Window renders it inside OVER(...)), not a wrapper.
		newSelections := make([]exp.Expression, 0, len(projections))
		for _, projection := range projections {
			if label, ok := stamped[projection]; ok {
				projection = exp.AliasNode(exp.Args{"this": projection, "alias": exp.ToIdentifier(label, true)})
			}
			newSelections = append(newSelections, projection)
		}
		sel.Set("expressions", newSelections)
	}
	return nil
}

// derivedBodySelects maps each SELECT that is a derived-table or CTE body to its source alias
// ("" when unaliased). Set-operation bodies map their leftmost branch, the label-bearing one.
func derivedBodySelects(root exp.Expression) map[exp.Expression]string {
	out := map[exp.Expression]string{}
	for _, subquery := range root.FindAll(exp.KindSubquery) {
		if sel := leftmostSelect(subquery.This()); sel != nil {
			out[sel] = subquery.Alias()
		}
	}
	for _, cte := range root.FindAll(exp.KindCTE) {
		if sel := leftmostSelect(cte.This()); sel != nil {
			out[sel] = cte.Alias()
		}
	}
	return out
}

// referencesLabel reports whether any column outside body references alias.label (folded per the
// engine). Alias shadowing in unrelated scopes can over-match — that only fails closed.
func referencesLabel(root, body exp.Expression, alias, foldedLabel string, eng engine) bool {
	inBody := map[exp.Expression]bool{}
	for _, node := range body.Walk(true) {
		inBody[node] = true
	}
	for _, column := range root.FindAll(exp.KindColumn) {
		if inBody[column] {
			continue
		}
		if eng.FoldColumn(column.TableName()) == eng.FoldColumn(alias) && eng.FoldColumn(column.Name()) == foldedLabel {
			return true
		}
	}
	return false
}

// restoreRelayOutputLabels renames the outermost select list's remaining `_col_N` aliases on a
// relay-only tree to their native labels — the display repair for projections
// stampNativeOutputLabels had to skip (a PG duplicate is legal as OUTPUT: two `?column?`s). A
// set-operation root restores its leftmost branch, the label-bearing one. Only the top-level
// alias is touched; a label something still references is left alone.
func restoreRelayOutputLabels(root exp.Expression, eng engine) bool {
	sel := leftmostSelect(root)
	if sel == nil {
		return false
	}
	referenced := map[string]bool{}
	for _, column := range root.FindAll(exp.KindColumn) {
		if column.TableName() == "" && syntheticLabelPattern.MatchString(column.Name()) {
			referenced[column.Name()] = true
		}
	}
	renamed := false
	for _, projection := range sel.Selects() {
		if !syntheticLabelPattern.MatchString(projection.Alias()) || referenced[projection.Alias()] {
			continue
		}
		expression := projection
		if projection.Kind() == exp.KindAlias {
			expression = projection.This()
		}
		native, ok := eng.NativeOutputLabel(expression, sel)
		if !ok || native == "" {
			continue
		}
		projection.Set("alias", exp.ToIdentifier(native, true))
		renamed = true
	}
	return renamed
}

func projectionIsStar(projection exp.Expression) bool {
	return projection != nil && (projection.Kind() == exp.KindStar ||
		(projection.Kind() == exp.KindColumn && projection.This() != nil && projection.This().Kind() == exp.KindStar))
}
