package probe

import (
	"sort"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func columnGrantSet(f *pb.StatementFacts) []string {
	cols := []string{}
	for _, g := range f.GetResultReads() {
		if c := g.GetColumn(); c != nil {
			cols = append(cols, c.GetIdentity().GetTable()+"."+c.GetIdentity().GetColumn())
		}
	}
	sort.Strings(cols)
	return cols
}

// A TABLE-shorthand EXPLAIN reads the scanned table like the `SELECT * FROM t` it abbreviates: the
// grants are EVERY catalog column of the table (the synthetic star expands against the catalog), equal
// to the spelled-out form's, with no output columns (the output is the plan).
func TestExplainTableEmitsEveryTableColumn(t *testing.T) {
	all := []string{"users.email", "users.id", "users.ssn"}
	for _, tc := range []struct {
		name  string
		facts func(*testing.T, string) *pb.StatementFacts
		sqls  []string
	}{
		{"mysql", mysqlFacts, []string{"EXPLAIN TABLE users", "EXPLAIN ANALYZE TABLE users", "EXPLAIN FORMAT=JSON TABLE users"}},
		{"postgres", postgresFacts, []string{"EXPLAIN TABLE users", "EXPLAIN ANALYZE TABLE users", "EXPLAIN (FORMAT JSON) TABLE users"}},
	} {
		spelled := columnGrantSet(tc.facts(t, "EXPLAIN SELECT * FROM users"))
		for _, sql := range tc.sqls {
			f := tc.facts(t, sql)
			if !f.GetResolved() || len(f.GetOutputColumns()) != 0 {
				t.Errorf("%s %q: resolved=%v outCols=%d", tc.name, sql, f.GetResolved(), len(f.GetOutputColumns()))
				continue
			}
			got := columnGrantSet(f)
			if len(got) != len(all) || got[0] != all[0] || got[1] != all[1] || got[2] != all[2] {
				t.Errorf("%s %q: column grants = %v, want every users column %v", tc.name, sql, got, all)
			}
			if len(got) != len(spelled) {
				t.Errorf("%s %q: grants differ from EXPLAIN SELECT * FROM users: %v vs %v", tc.name, sql, got, spelled)
			}
		}
	}
}

// The TABLE-shorthand forms the parser deliberately degrades to Command must stay unanalyzable.
func TestExplainTableDegradedFormsFailClosed(t *testing.T) {
	for _, c := range []struct {
		sql   string
		mysql bool
	}{
		{"EXPLAIN ANALYZE TABLE users PARTITION (p0)", true},
		{"EXPLAIN ANALYZE TABLE users AS JSON", true},
		{"EXPLAIN TABLE users garbage trailing", true},
		{"EXPLAIN TABLE ONLY users", false},
		{"EXPLAIN TABLE users *", false},
		{"EXPLAIN TABLE users garbage trailing", false},
	} {
		var f *pb.StatementFacts
		if c.mysql {
			f = mysqlFacts(t, c.sql)
		} else {
			f = postgresFacts(t, c.sql)
		}
		if f.GetResolved() {
			t.Errorf("%q: must stay unresolved, got kind=%v reads=%+v", c.sql, factsKind(f), f.GetResultReads())
		}
	}
}
