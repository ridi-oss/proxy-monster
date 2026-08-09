package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// TestCteShadowsPhysicalDecoyMustDeny locks the CTE-scope-aware-stamping invariant for the MySQL
// lower_case_table_names=0 prequalification adapter: a bare
// name that is a visible CTE in an outer scope MUST NOT be stamped as a same-named physical table.
// Qualifying a DML-contained query island in isolation loses the outer WITH, so a same-named physical
// decoy (`protected`) would be stamped and the real CTE lineage (`users.ssn`) dropped — a fail-open
// leak. Each statement reads users.ssn through the CTE; the probe MUST surface it (references/origins)
// or fail closed unresolved, never resolve-and-ALLOW.
func TestCteShadowsPhysicalDecoyMustDeny(t *testing.T) {
	// Every CTE name below ALSO exists as a physical table (with an ssn column, so a wrong bind resolves
	// to the decoy's ssn instead of users.ssn) — otherwise the test would pass vacuously via a
	// column-not-found fail-close rather than by proving the CTE bind.
	cols := []*pb.ColumnSpec{
		columnSpec("def", "App", "users", "id", "BIGINT"),
		columnSpec("def", "App", "users", "ssn", "VARCHAR"),
		columnSpec("def", "App", "sink", "id", "BIGINT"),
		columnSpec("def", "App", "sink", "data", "VARCHAR"),
		columnSpec("def", "App", "protected", "x", "VARCHAR"),
		columnSpec("def", "App", "protected", "ssn", "VARCHAR"),
		columnSpec("def", "App", "a", "x", "VARCHAR"),
		columnSpec("def", "App", "a", "ssn", "VARCHAR"),
		columnSpec("def", "App", "b", "y", "VARCHAR"),
		columnSpec("def", "App", "b", "ssn", "VARCHAR"),
	}
	ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"App"}}
	const ssnKey = "def.App.users.ssn"

	cases := []struct{ name, sql string }{
		{"UPDATE SET scalar-subquery via CTE decoy",
			"WITH protected AS (SELECT ssn AS x FROM users) UPDATE sink SET data = (SELECT x FROM protected LIMIT 1) WHERE sink.id = 1"},
		{"UPDATE FROM CTE decoy",
			"WITH protected AS (SELECT ssn AS x FROM users) UPDATE sink SET data = protected.x FROM protected WHERE sink.id = 1"},
		{"DELETE USING CTE decoy",
			"WITH protected AS (SELECT ssn AS x FROM users) DELETE sink FROM sink JOIN protected WHERE sink.data = protected.x"},
		{"chained CTE decoy (2 hops)",
			"WITH a AS (SELECT ssn AS x FROM users), b AS (SELECT x AS y FROM a) UPDATE sink SET data = (SELECT y FROM b LIMIT 1) WHERE sink.id = 1"},
		{"recursive CTE decoy",
			"WITH RECURSIVE protected AS (SELECT ssn FROM users UNION ALL SELECT ssn FROM protected) UPDATE sink SET data = (SELECT ssn FROM protected LIMIT 1) WHERE sink.id = 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyzeProbe(t, &pb.AnalyzeRequest{
				Sql:          tc.sql,
				EngineConfig: &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0)},
				Namespace:    ns, Catalog: cols,
			})
			caught := !res.Resolved
			for _, refs := range res.References {
				for _, c := range refs {
					if c == ssnKey {
						caught = true
					}
				}
			}
			for _, o := range res.Origins {
				for _, c := range o.Origins {
					if c == ssnKey {
						caught = true
					}
				}
			}
			if !caught {
				t.Fatalf("LEAK — %s bound to a physical decoy, %s never surfaced:\n  sql=%s\n  references=%v",
					tc.name, ssnKey, tc.sql, res.References)
			}
		})
	}
}
