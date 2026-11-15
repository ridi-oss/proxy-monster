package engines

import (
	"fmt"
	"slices"
	"strconv"

	exp "github.com/ridi-oss/sqlglot-go/expressions"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// httpdbHooks is what the engines behind an HTTP API share: the request's parameters are bound into the text,
// the editor row cap becomes a LIMIT, and the proxy submits the regenerated text without the parameter list.
type httpdbHooks struct {
	sharedHooks
	sqlContext func(*pb.SessionObservation) *pb.HttpDbSqlContext
}

// finishSubmission caps the submitted query at the editor's max_rows: these engines have no session row cap,
// so an uncapped SELECT would scan and store the whole result before the proxy truncates it.
func (h httpdbHooks) finishSubmission(session *Session, submission exp.Expression) bool {
	maxRows := h.sqlContext(session.observation).GetMaxRows()
	return maxRows > 0 && capRows(submission, maxRows)
}

// capRows adds LIMIT maxRows to a top-level query that has none or a larger literal one.
func capRows(root exp.Expression, maxRows uint32) bool {
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
