package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// TestPredicateLiteralFacts locks the literal-vs-column fact that lets the control plane withhold statement
// TEXT carrying a protected value: `WHERE ssn = '987-65-4320'` puts the value in the query itself, where
// masking cannot reach it, because masking rewrites results and not predicates.
//
// The fact is ADVISORY and one-directional. It may only ever hide text, never authorize or deny a query, so
// a miss costs a hidden statement and never a wrong disclosure. That is why the negative cases below matter
// as much as the positive ones: a column-to-column comparison carries no value to leak, and emitting it
// would hide text for no reason.
//
// The analyzer states which base columns a literal reaches and stops there — it has no role context and must
// never acquire one. Whether a column is protected FOR A GIVEN READER is the control plane's decision.
func TestPredicateLiteralFacts(t *testing.T) {
	// MySQL leads; Postgres re-runs the same shapes.
	engines := []struct {
		name string
		ec   *pb.EngineConfig
		ns   *pb.Namespace
		cols []*pb.ColumnSpec
		ssn  string
		id   string
		reg  string
	}{
		{
			name: "mysql",
			ec:   &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)},
			ns:   &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}},
			cols: []*pb.ColumnSpec{
				columnSpec("def", "app", "users", "id", "BIGINT"),
				columnSpec("def", "app", "users", "ssn", "VARCHAR"),
				columnSpec("def", "app", "users", "region", "VARCHAR"),
				columnSpec("def", "app", "orders", "user_id", "BIGINT"),
			},
			ssn: "def.app.users.ssn", id: "def.app.users.id", reg: "def.app.users.region",
		},
		{
			name: "postgres",
			ec:   &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			ns:   &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
			cols: []*pb.ColumnSpec{
				columnSpec("acme", "public", "users", "id", "BIGINT"),
				columnSpec("acme", "public", "users", "ssn", "VARCHAR"),
				columnSpec("acme", "public", "users", "region", "VARCHAR"),
				columnSpec("acme", "public", "orders", "user_id", "BIGINT"),
			},
			ssn: "acme.public.users.ssn", id: "acme.public.users.id", reg: "acme.public.users.region",
		},
	}

	for _, e := range engines {
		t.Run(e.name, func(t *testing.T) {
			cases := []struct {
				name string
				sql  string
				want []string // base column keys expected to carry a compared literal
			}{
				{
					name: "equality against a literal is the canonical leak",
					sql:  "SELECT id FROM users WHERE ssn = '987-65-4320'",
					want: []string{e.ssn},
				},
				{
					name: "IN list carries its values one level down",
					sql:  "SELECT id FROM users WHERE ssn IN ('a', 'b')",
					want: []string{e.ssn},
				},
				{
					name: "LIKE is a comparison like any other",
					sql:  "SELECT id FROM users WHERE ssn LIKE '9001%'",
					want: []string{e.ssn},
				},
				{
					name: "BETWEEN carries two literals",
					sql:  "SELECT id FROM users WHERE id BETWEEN 1 AND 5",
					want: []string{e.id},
				},
				{
					name: "every column in a conjunction is reported",
					sql:  "SELECT id FROM users WHERE ssn = 'x' AND region = 'KR'",
					want: []string{e.ssn, e.reg},
				},
				{
					// A native UPDATE/DELETE keeps its WHERE off the Select walk; the value leaks the same way.
					name: "UPDATE carries its WHERE literal",
					sql:  "UPDATE users SET region = 'JP' WHERE ssn = '987-65-4320'",
					want: []string{e.ssn},
				},
				{
					name: "DELETE carries its WHERE literal",
					sql:  "DELETE FROM users WHERE ssn = '987-65-4320'",
					want: []string{e.ssn},
				},
				{
					name: "HAVING is a predicate too",
					sql:  "SELECT region, count(*) FROM users GROUP BY region HAVING count(*) > 5",
					want: []string{},
				},
				{
					name: "an alias resolves to its base column",
					sql:  "SELECT u.id FROM users u WHERE u.ssn = 'x'",
					want: []string{e.ssn},
				},
				{
					name: "a literal inside a subquery predicate still resolves",
					sql:  "SELECT id FROM users WHERE id IN (SELECT user_id FROM orders WHERE user_id = 7)",
					want: []string{"", ""}, // filled below: engine-specific orders key
				},
				// --- negatives: nothing to leak, so nothing may be hidden ---
				{
					name: "column-to-column comparison carries no value",
					sql:  "SELECT id FROM users WHERE ssn = region",
					want: []string{},
				},
				{
					name: "a join predicate on two columns carries no value",
					sql:  "SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id",
					want: []string{},
				},
				{
					name: "no predicate at all",
					sql:  "SELECT id, ssn FROM users",
					want: []string{},
				},
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					// The subquery case's expectation depends on the engine's key prefix.
					want := tc.want
					if tc.name == "a literal inside a subquery predicate still resolves" {
						prefix := "def.app."
						if e.name == "postgres" {
							prefix = "acme.public."
						}
						want = []string{prefix + "orders.user_id"}
					}

					r := analyzeProbe(t, &pb.AnalyzeRequest{Sql: tc.sql, EngineConfig: e.ec, Namespace: e.ns, Catalog: e.cols})
					if !r.Resolved {
						t.Fatalf("expected resolved=true; sql=%q detail=%q", tc.sql, r.Detail)
					}
					got := map[string]bool{}
					for _, lit := range r.PredicateLiterals {
						got[lit.Column] = true
					}
					for _, wantKey := range want {
						if !got[wantKey] {
							t.Errorf("sql=%q: expected %q to carry a compared literal; got %v", tc.sql, wantKey, r.PredicateLiterals)
						}
					}
					if len(want) == 0 && len(r.PredicateLiterals) > 0 {
						t.Errorf("sql=%q: expected no predicate literals (nothing to leak); got %v", tc.sql, r.PredicateLiterals)
					}
				})
			}
		})
	}
}

// TestPredicateLiteralClause records which clause a comparison sat in. The clause is for audit legibility
// only — the decision to withhold text keys on the COLUMN, never on where it appeared.
func TestPredicateLiteralClause(t *testing.T) {
	ec := &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}
	ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}
	cols := []*pb.ColumnSpec{
		columnSpec("def", "app", "users", "id", "BIGINT"),
		columnSpec("def", "app", "users", "ssn", "VARCHAR"),
		columnSpec("def", "app", "orders", "user_id", "BIGINT"),
	}

	r := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          "SELECT u.id FROM users u JOIN orders o ON o.user_id = 7 WHERE u.ssn = 'x'",
		EngineConfig: ec, Namespace: ns, Catalog: cols,
	})
	if !r.Resolved {
		t.Fatalf("expected resolved=true; detail=%q", r.Detail)
	}
	byColumn := map[string]string{}
	for _, lit := range r.PredicateLiterals {
		byColumn[lit.Column] = lit.Clause
	}
	if byColumn["def.app.users.ssn"] != "WHERE" {
		t.Errorf("expected ssn in WHERE; got %v", r.PredicateLiterals)
	}
	if byColumn["def.app.orders.user_id"] != "JOIN" {
		t.Errorf("expected orders.user_id in JOIN; got %v", r.PredicateLiterals)
	}
}
