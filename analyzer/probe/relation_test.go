package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func runProbe(t *testing.T, sql string) *ProbeResult {
	t.Helper()
	return analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          sql,
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    canonicalPostgresNamespace,
		Catalog:      canonicalPostgresCatalog,
	})
}

func ssnInRefs(res *ProbeResult) bool {
	for _, cols := range res.References {
		for _, c := range cols {
			if c == canonicalUsersSSNKey {
				return true
			}
		}
	}
	return false
}

// TestRelationValuedMustDeny: a protected column reached through a whole-row value, a relation-valued
// column, or a nested composite must be caught. The read cases may fail closed unresolved or surface the
// protected reference; the write-source regressions must resolve and surface it via native DML scope
// resolution.
func TestRelationValuedMustDeny(t *testing.T) {
	cases := []struct {
		name        string
		sql         string
		mustResolve bool
	}{
		{"composite (u).ssn", "SELECT (u).ssn AS r FROM users u", false},
		{"whole-row to_jsonb(u)", "SELECT to_jsonb(u) AS r FROM users u", false},
		{"relation-valued (d.sub).ssn", "SELECT (d.sub).ssn AS r FROM (SELECT users AS sub FROM users) d", false},
		{"nested write ((region).sub).ssn",
			"UPDATE sink SET data = ((region).sub).ssn FROM (SELECT id, users AS sub FROM users) region WHERE sink.id = region.id", true},
		{"RETURNING ((region).sub).ssn",
			"UPDATE sink SET data='x' FROM (SELECT id, users AS sub FROM users) region WHERE sink.id=region.id RETURNING ((region).sub).ssn", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runProbe(t, tc.sql)
			if tc.mustResolve {
				if !res.Resolved {
					t.Fatalf("write relation regression must resolve, got %s: %s", stageString(res.FailedStage), res.Detail)
				}
				if !ssnInRefs(res) {
					t.Fatalf("LEAK: resolved write omitted %s from references: %v", canonicalUsersSSNKey, res.References)
				}
				return
			}

			denied := !res.Resolved || ssnInRefs(res)
			mechanism := "references"
			if !res.Resolved {
				mechanism = "unresolved(" + stageString(res.FailedStage) + ": " + res.Detail + ")"
			}
			t.Logf("resolved=%v ssnInRefs=%v via=%s", res.Resolved, ssnInRefs(res), mechanism)
			if !denied {
				t.Fatalf("LEAK: not denied. resolved=%v references=%v", res.Resolved, res.References)
			}
		})
	}
}

// TestRelationValuedOverDeny documents the current (safe) over-approximation to fix in the precision
// pass: a relation-valued column DEFINITION (`users AS sub`) is swept as a whole-row read even when
// only a non-PII field is later used, so `(d.sub).id` currently denies. Not a leak — an over-deny.
func TestRelationValuedOverDeny(t *testing.T) {
	res := runProbe(t, "SELECT (d.sub).id AS r FROM (SELECT users AS sub FROM users) d")
	t.Logf("(d.sub).id: resolved=%v ssnInRefs=%v references=%v  [known over-deny]",
		res.Resolved, ssnInRefs(res), res.References)
}
