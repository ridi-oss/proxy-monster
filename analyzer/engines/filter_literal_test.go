package engines

import (
	"sort"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// TestFilterLiteralFacts locks the ONE shape of WHERE reference that is emitted as ALLOW_LITERAL_FILTER
// instead of the blanket DENY_STATEMENT: a column used only as the bare operand of `col = literal`,
// `literal = col` or `col IN (literals)`, in a top-level conjunct, on a physical table column.
//
// The negatives carry the weight. A filter on a masked column is an oracle (it answers yes/no about the
// hidden value), and the opt-in only makes sense for a plain equality the caller already knows the answer
// to. Every other shape — a function around the column, LIKE, a range, OR, NOT, a subquery, a derived
// source, a write — must stay an ordinary reference, because each of them can extract a value the caller
// does not already have (`SUBSTRING(email,1,3) = 'abc'`, `email LIKE 'a%'`, `email > 'm'`).
func TestFilterLiteralFacts(t *testing.T) {
	engines := []struct {
		name   string
		ec     *pb.EngineConfig
		ns     *pb.Namespace
		cols   []*pb.Column
		prefix string
	}{
		{
			name: "mysql",
			ec:   &pb.EngineConfig{Engine: pb.Engine_MYSQL, Target: &pb.TargetSettings{EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}},
			ns:   &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}},
			cols: []*pb.Column{
				pbColumn("app", "users", "id", "BIGINT"),
				pbColumn("app", "users", "ssn", "VARCHAR"),
				pbColumn("app", "users", "region", "VARCHAR"),
				pbColumn("app", "orders", "user_id", "BIGINT"),
			},
			prefix: "def.app.",
		},
		{
			name: "postgres",
			ec:   &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			ns:   &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
			cols: []*pb.Column{
				pbColumn("public", "users", "id", "BIGINT"),
				pbColumn("public", "users", "ssn", "VARCHAR"),
				pbColumn("public", "users", "region", "VARCHAR"),
				pbColumn("public", "orders", "user_id", "BIGINT"),
			},
			prefix: "acme.public.",
		},
	}

	for _, e := range engines {
		t.Run(e.name, func(t *testing.T) {
			ssn, region, orderUser := e.prefix+"users.ssn", e.prefix+"users.region", e.prefix+"orders.user_id"
			cases := []struct {
				name       string
				sql        string
				wantFilter []string // columns that must be FilterLiterals
				wantRef    []string // columns that must still be an ordinary reference (any clause)
				noRef      []string // columns that must NOT be a reference (filter-only)
			}{
				// --- allowed: the canonical lookup shapes ---
				{name: "column = literal", sql: "SELECT id FROM users WHERE ssn = 'x'", wantFilter: []string{ssn}, noRef: []string{ssn}},
				{name: "literal = column", sql: "SELECT id FROM users WHERE 'x' = ssn", wantFilter: []string{ssn}, noRef: []string{ssn}},
				{name: "IN list of literals", sql: "SELECT id FROM users WHERE ssn IN ('a', 'b')", wantFilter: []string{ssn}, noRef: []string{ssn}},
				{name: "parenthesised", sql: "SELECT id FROM users WHERE (ssn = 'x')", wantFilter: []string{ssn}, noRef: []string{ssn}},
				{name: "alias qualifier", sql: "SELECT u.id FROM users u WHERE u.ssn = 'x'", wantFilter: []string{ssn}, noRef: []string{ssn}},
				{name: "each conjunct is judged on its own", sql: "SELECT id FROM users WHERE ssn = 'x' AND region = 'KR'", wantFilter: []string{ssn, region}, noRef: []string{ssn, region}},
				{name: "numeric literal", sql: "SELECT id FROM users WHERE id = 7", wantFilter: []string{e.prefix + "users.id"}, noRef: []string{e.prefix + "users.id"}},

				// --- denied: anything that can extract a value the caller does not already have ---
				{name: "function around the column", sql: "SELECT id FROM users WHERE LOWER(ssn) = 'x'", wantRef: []string{ssn}},
				{name: "substring probes a prefix", sql: "SELECT id FROM users WHERE SUBSTRING(ssn, 1, 3) = 'abc'", wantRef: []string{ssn}},
				{name: "cast around the column", sql: "SELECT id FROM users WHERE CAST(ssn AS CHAR) = 'x'", wantRef: []string{ssn}},
				{name: "LIKE", sql: "SELECT id FROM users WHERE ssn LIKE 'a%'", wantRef: []string{ssn}},
				{name: "range probes by binary search", sql: "SELECT id FROM users WHERE ssn > 'm'", wantRef: []string{ssn}},
				{name: "BETWEEN", sql: "SELECT id FROM users WHERE ssn BETWEEN 'a' AND 'm'", wantRef: []string{ssn}},
				{name: "not equal", sql: "SELECT id FROM users WHERE ssn <> 'x'", wantRef: []string{ssn}},
				{name: "OR is not a conjunct", sql: "SELECT id FROM users WHERE ssn = 'x' OR region = 'KR'", wantRef: []string{ssn, region}},
				{name: "NOT", sql: "SELECT id FROM users WHERE NOT (ssn = 'x')", wantRef: []string{ssn}},
				{name: "NOT IN", sql: "SELECT id FROM users WHERE ssn NOT IN ('a', 'b')", wantRef: []string{ssn}},
				{name: "IN with a non-literal member", sql: "SELECT id FROM users WHERE ssn IN ('a', region)", wantRef: []string{ssn}},
				{name: "IN subquery", sql: "SELECT id FROM users WHERE ssn IN (SELECT ssn FROM users)", wantRef: []string{ssn}},
				{name: "column to column", sql: "SELECT id FROM users WHERE ssn = region", wantRef: []string{ssn, region}},
				{name: "also used in ORDER BY", sql: "SELECT id FROM users WHERE ssn = 'x' ORDER BY ssn", wantFilter: []string{ssn}, wantRef: []string{ssn}},
				{name: "also used in GROUP BY", sql: "SELECT ssn, count(*) FROM users WHERE ssn = 'x' GROUP BY ssn", wantFilter: []string{ssn}, wantRef: []string{ssn}},
				{name: "same column filtered and wrapped in the same WHERE", sql: "SELECT id FROM users WHERE ssn = 'x' AND LOWER(ssn) = 'y'", wantFilter: []string{ssn}, wantRef: []string{ssn}},
				{name: "derived column from an expression", sql: "SELECT id FROM (SELECT id, LOWER(ssn) AS ssn FROM users) t WHERE ssn = 'x'", wantRef: []string{ssn}},
				{name: "plain derived column", sql: "SELECT id FROM (SELECT id, ssn FROM users) t WHERE ssn = 'x'", wantRef: []string{ssn}},
				{name: "CTE column", sql: "WITH t AS (SELECT id, ssn FROM users) SELECT id FROM t WHERE ssn = 'x'", wantRef: []string{ssn}},
				{name: "join column compared to a literal in WHERE", sql: "SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id WHERE o.user_id = 7", wantFilter: []string{orderUser}, wantRef: []string{orderUser}}, // the join keeps it a reference
				{name: "UPDATE keeps its WHERE a reference", sql: "UPDATE users SET region = 'JP' WHERE ssn = 'x'", wantRef: []string{ssn}},
				{name: "DELETE keeps its WHERE a reference", sql: "DELETE FROM users WHERE ssn = 'x'", wantRef: []string{ssn}},
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					r := analyzeProbe(t, &pb.AnalyzeRequest{
						Sql: tc.sql, EngineConfig: e.ec, Namespace: e.ns,
						Catalog: snapshotWith(e.cols, &pb.FunctionCatalog{BuiltinFunctions: []string{"count", "lower", "substring", "cast"}}),
					})
					if !r.Resolved {
						t.Fatalf("expected resolved=true; sql=%q detail=%q", tc.sql, r.Detail)
					}
					filters := map[string]bool{}
					for _, k := range r.FilterLiterals {
						filters[k] = true
					}
					refs := map[string]bool{}
					for _, keys := range r.References {
						for _, k := range keys {
							refs[k] = true
						}
					}
					for _, k := range tc.wantFilter {
						if !filters[k] {
							t.Errorf("sql=%q: expected %q in FilterLiterals; got %v", tc.sql, k, r.FilterLiterals)
						}
					}
					for _, k := range tc.wantRef {
						if !refs[k] {
							t.Errorf("sql=%q: expected %q to stay an ordinary reference; References=%v", tc.sql, k, r.References)
						}
					}
					for _, k := range tc.noRef {
						if refs[k] {
							t.Errorf("sql=%q: %q must be filter-only, but it is also a reference: %v", tc.sql, k, r.References)
						}
					}
					if len(tc.wantFilter) == 0 && len(r.FilterLiterals) > 0 {
						t.Errorf("sql=%q: expected NO FilterLiterals (an unsafe shape); got %v", tc.sql, r.FilterLiterals)
					}
					// FilterLiterals is rendered in a stable order, like every other fact.
					if !sort.StringsAreSorted(r.FilterLiterals) {
						t.Errorf("sql=%q: FilterLiterals not sorted: %v", tc.sql, r.FilterLiterals)
					}
				})
			}
		})
	}
}

// TestFilterLiteralFactsGrant checks the emitted GRANT: a filter-only column becomes an
// ALLOW_LITERAL_FILTER column grant, and a column that is ALSO selected keeps its MASK_OUTPUT grant next to
// it, so the control plane judges the two uses independently.
func TestFilterLiteralFactsGrant(t *testing.T) {
	ec := &pb.EngineConfig{Engine: pb.Engine_MYSQL, Target: &pb.TargetSettings{EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}}
	ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}
	cols := []*pb.Column{pbColumn("app", "users", "id", "BIGINT"), pbColumn("app", "users", "ssn", "VARCHAR")}

	facts := analyzeProto(t, &pb.AnalyzeRequest{
		Sql: "SELECT id, ssn FROM users WHERE ssn = 'x'", EngineConfig: ec, Namespace: ns, Catalog: snapshot(cols),
	})
	dispositions := map[pb.MaskedDisposition]bool{}
	for _, read := range facts.GetResultReads() {
		if c := read.GetColumn(); c != nil && c.GetColumn() == "ssn" {
			dispositions[read.GetMaskedDisposition()] = true
		}
	}
	if !dispositions[pb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT] {
		t.Errorf("selected ssn must keep a MASK_OUTPUT grant; got %v", dispositions)
	}
	if !dispositions[pb.MaskedDisposition_MASKED_DISPOSITION_ALLOW_LITERAL_FILTER] {
		t.Errorf("filtered ssn must get an ALLOW_LITERAL_FILTER grant; got %v", dispositions)
	}
	if dispositions[pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT] {
		t.Errorf("a bare `ssn = 'x'` must no longer be a DENY_STATEMENT reference; got %v", dispositions)
	}
}

// TestFilterLiteralExplainStaysDenied keeps an EXPLAIN out of the opt-in: its result is the plan, whose row
// estimates reflect the filter's selectivity, so a filter on a masked column must stay a DENY_STATEMENT
// reference there. The control plane's stored-plan release relies on that.
func TestFilterLiteralExplainStaysDenied(t *testing.T) {
	ec := &pb.EngineConfig{Engine: pb.Engine_MYSQL, Target: &pb.TargetSettings{EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}}
	ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}
	cols := []*pb.Column{pbColumn("app", "users", "id", "BIGINT"), pbColumn("app", "users", "ssn", "VARCHAR")}

	facts := analyzeProto(t, &pb.AnalyzeRequest{
		Sql: "EXPLAIN SELECT id FROM users WHERE ssn = 'x'", EngineConfig: ec, Namespace: ns, Catalog: snapshot(cols),
	})
	var seen []pb.MaskedDisposition
	for _, read := range facts.GetResultReads() {
		if c := read.GetColumn(); c != nil && c.GetColumn() == "ssn" {
			seen = append(seen, read.GetMaskedDisposition())
		}
	}
	if len(seen) == 0 {
		t.Fatalf("expected a grant on ssn; facts=%v", facts)
	}
	for _, d := range seen {
		if d == pb.MaskedDisposition_MASKED_DISPOSITION_ALLOW_LITERAL_FILTER {
			t.Errorf("an EXPLAIN must not carry ALLOW_LITERAL_FILTER; got %v", seen)
		}
	}
}
