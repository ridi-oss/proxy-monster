package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// TestColumnFirstCanonical locks in PG column-first resolution (chain-walked) against the
// docs/relation-model.md canonical PoCs + variants — the column-first leak family:
// a bare name PG binds column-first to an outer/target protected column, or to a relation-valued
// column, was mis-bound to a same-named decoy alias and streamed cleartext. Every case reads
// users.ssn, so the probe MUST catch it (DENY via references, or fail-closed unresolved). A resolved
// case with users.ssn nowhere is a leak.
func TestColumnFirstCanonical(t *testing.T) {
	cases := []struct{ id, sql string }{
		// canonical PoCs
		{"#1 write correlated (SELECT ssn)", "UPDATE users u SET name=(SELECT ssn) FROM orders ssn WHERE u.id=ssn.user_id"},
		{"#2 write subquery-own-FROM", "UPDATE users u SET name=(SELECT ssn FROM orders ssn LIMIT 1) WHERE u.id=1"},
		{"#3 write jsonb-of-target-row", "UPDATE users u SET name=(SELECT to_jsonb(u)::text) FROM orders ssn WHERE u.id=ssn.user_id"},
		{"#4 write decoy-alias vs relation-valued", "UPDATE sink SET data=((sub).ssn)::text FROM orders sub CROSS JOIN (SELECT users AS sub FROM users) d WHERE sink.id=1"},
		{"#5 read correlated scalar-subquery", "SELECT (SELECT ssn FROM orders ssn LIMIT 1) AS x FROM users u"},
		// variants
		{"read decoy Dot (u).ssn with alias", "SELECT (sub).ssn AS x FROM (SELECT users AS sub FROM users) d, orders sub"},
		{"read correlated in WHERE", "SELECT u.id FROM users u WHERE u.id = (SELECT ssn FROM orders ssn LIMIT 1)::bigint"},
		{"write decoy in RETURNING", "UPDATE sink SET data='x' FROM orders sub CROSS JOIN (SELECT users AS sub FROM users) d WHERE sink.id=1 RETURNING (sub).ssn"},
		// quoted identifiers (case-sensitive PG): resolution must match AS-IS, not lowercase
		{"quoted relation-valued", `SELECT (d."sub").ssn AS x FROM (SELECT users AS "sub" FROM users) d`},
		{"quoted decoy vs alias", `SELECT ("Sub").ssn AS x FROM (SELECT users AS "Sub" FROM users) d, orders "Sub"`},
		// write-side conservation (docs/relation-model.md): a protected read in ANY orphaned write clause
		// — SET / RETURNING / VALUES / MERGE-action / ON CONFLICT — across ALL roots, not just UPDATE SET
		{"MERGE SET bare-correlated", "MERGE INTO users u USING orders ssn ON u.id=ssn.user_id WHEN MATCHED THEN UPDATE SET name=(SELECT ssn)"},
		{"MERGE SET whole-row", "MERGE INTO users u USING orders o ON u.id=o.user_id WHEN MATCHED THEN UPDATE SET name=(SELECT to_jsonb(u)::text)"},
		{"ON CONFLICT SET whole-row", "INSERT INTO users (id,name) VALUES (1,'y') ON CONFLICT (id) DO UPDATE SET name=(SELECT to_jsonb(u)::text FROM users u WHERE u.id=excluded.id)"},
		{"DELETE RETURNING correlated", "DELETE FROM users u USING orders ssn WHERE u.id=ssn.user_id RETURNING u.id,(SELECT ssn)"},
		{"UPDATE RETURNING correlated", "UPDATE users u SET name='x' FROM orders ssn WHERE u.id=ssn.user_id RETURNING (SELECT ssn)"},
		{"INSERT VALUES subquery decoy", "INSERT INTO sink (id,data) VALUES (1,(SELECT ssn FROM users, orders ssn LIMIT 1))"},
		{"DELETE RETURNING via USING", "DELETE FROM sink USING users u, orders ssn WHERE sink.id=u.id RETURNING (SELECT ssn)"},
		// composite field access on a scalar-subquery-returning-a-row base (no decoy needed)
		{"read subquery-base Dot", "SELECT (SELECT u FROM users u LIMIT 1).ssn AS x"},
		{"UPDATE SET subquery-base Dot", "UPDATE sink SET data=(SELECT u FROM users u LIMIT 1).ssn WHERE sink.id=1"},
		{"DELETE RETURNING subquery-base", "DELETE FROM sink u WHERE u.id=1 RETURNING (SELECT u2 FROM users u2 LIMIT 1).ssn"},
		// RETURNING on a SELECT-bodied write (outside the payload SELECT) must still be swept
		{"INSERT…SELECT RETURNING correlated", "INSERT INTO sink (id,data) SELECT u.id,'x' FROM users u RETURNING id,(SELECT ssn FROM users, orders ssn LIMIT 1)"},
		{"INSERT…SELECT RETURNING subquery-base", "INSERT INTO sink (id,data) SELECT 100,'x' RETURNING (SELECT u FROM users u LIMIT 1).ssn AS leaked"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			res := analyzeProbe(t, &pb.AnalyzeRequest{Sql: tc.sql, EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES}, Namespace: canonicalPostgresNamespace, Catalog: canonicalPostgresCatalog})
			caught := !res.Resolved
			for _, cols := range res.References {
				for _, c := range cols {
					if c == canonicalUsersSSNKey {
						caught = true
					}
				}
			}
			for _, o := range res.Origins {
				for _, c := range o.Origins {
					if c == canonicalUsersSSNKey {
						caught = true
					}
				}
			}
			if !caught {
				t.Fatalf("LEAK — users.ssn never surfaced (probe would ALLOW):\n  sql=%s\n  references=%v", tc.sql, res.References)
			}
		})
	}
}
