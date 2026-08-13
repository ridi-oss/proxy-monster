package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// TestRelationRedTeam adversarially sweeps whole-row / composite / relation-valued shapes. Each case
// touches the protected column users.ssn, so the probe MUST catch it — DENY via unresolved, DENY via
// references, or MASK via an ssn origin. A case that resolves but shows ssn NOWHERE is BLIND = a
// candidate cleartext leak (cross-checked against live PG separately).
func TestRelationRedTeam(t *testing.T) {
	cases := []struct{ id, sql string }{
		{"A composite (u).ssn", "SELECT (u).ssn AS r FROM users u"},
		{"B relvalued (d.sub).ssn", "SELECT (d.sub).ssn AS r FROM (SELECT users AS sub FROM users) d"},
		{"C relvalued WHOLE to_jsonb(d.sub)", "SELECT to_jsonb(d.sub) AS r FROM (SELECT users AS sub FROM users) d"},
		{"D relvalued bare output d.sub", "SELECT d.sub AS r FROM (SELECT users AS sub FROM users) d"},
		{"E whole-row to_jsonb(u)", "SELECT to_jsonb(u) AS r FROM users u"},
		{"F bare whole-row output u", "SELECT u AS r FROM users u"},
		{"G CTE relvalued (d.sub).ssn", "WITH d AS (SELECT users AS sub FROM users) SELECT (d.sub).ssn AS r FROM d"},
		{"H CTE relvalued WHOLE to_jsonb(d.sub)", "WITH d AS (SELECT users AS sub FROM users) SELECT to_jsonb(d.sub) AS r FROM d"},
		{"I LATERAL relvalued (l.sub).ssn", "SELECT (l.sub).ssn AS r FROM users u, LATERAL (SELECT u AS sub) l"},
		{"J LATERAL relvalued WHOLE to_jsonb(l.sub)", "SELECT to_jsonb(l.sub) AS r FROM users u, LATERAL (SELECT u AS sub) l"},
		{"K set-op relvalued (x.sub).ssn", "SELECT (x.sub).ssn AS r FROM (SELECT users AS sub FROM users UNION ALL SELECT users FROM users) x"},
		{"L correlated composite", "SELECT (SELECT (u2).ssn FROM users u2 WHERE u2.id=u.id) AS r FROM users u"},
		{"N 2-hop relvalued (r.a).ssn", "SELECT (r.a).ssn AS r FROM (SELECT sub AS a FROM (SELECT users AS sub FROM users) i) r"},
		{"P whole-row agg json_agg(u)", "SELECT json_agg(u) AS r FROM users u"},
		{"Q whole-row to_json(u.*)", "SELECT to_json(u.*) AS r FROM users u"},
		{"R relvalued row_to_json(d.sub)", "SELECT row_to_json(d.sub) AS r FROM (SELECT users AS sub FROM users) d"},
		{"O write to_jsonb(CTE row)", "WITH uid AS (SELECT id, ssn FROM users) UPDATE sink SET data = to_jsonb(uid)::text FROM uid WHERE sink.id = uid.id"},
		{"S MERGE relvalued (src.sub).ssn", "MERGE INTO sink s USING (SELECT id, users AS sub FROM users) src ON s.id = src.id WHEN MATCHED THEN UPDATE SET data = (src.sub).ssn"},
		{"T write (u).ssn in SET scalar-subq", "UPDATE sink SET data = (SELECT (u).ssn FROM users u WHERE u.id = sink.id)"},
		{"U collision relvalued named 'name'", "SELECT (d.name).ssn AS r FROM (SELECT users AS name FROM users) d"},
		{"W write RETURNING to_jsonb(u)", "UPDATE users u SET name = 'x' RETURNING to_jsonb(u)"},
		{"X insert-select whole-row", "INSERT INTO sink (id, data) SELECT id, to_jsonb(u)::text FROM users u"},
	}
	var blind []string
	for _, tc := range cases {
		res := analyzeProbe(t, &pb.AnalyzeRequest{
			Sql: tc.sql, EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace: canonicalPostgresNamespace, Catalog: canonicalPostgresCatalog,
		})
		inRefs, inOrigins := false, false
		for _, cols := range res.References {
			for _, c := range cols {
				if c == canonicalUsersSSNKey {
					inRefs = true
				}
			}
		}
		for _, o := range res.Origins {
			for _, c := range o.Origins {
				if c == canonicalUsersSSNKey {
					inOrigins = true
				}
			}
		}
		verdict := "ALLOW — BLIND to ssn  <<< LEAK SUSPECT"
		switch {
		case !res.Resolved:
			verdict = "DENY (unresolved)"
		case inRefs:
			verdict = "DENY (ssn in references)"
		case inOrigins:
			verdict = "MASK/DENY (ssn in origins)"
		}
		t.Logf("%-40s %s", tc.id, verdict)
		if res.Resolved && !inRefs && !inOrigins {
			blind = append(blind, tc.id+"  ::  "+tc.sql)
		}
	}
	if len(blind) > 0 {
		t.Errorf("\n%d BLIND (candidate leaks — probe sees no ssn though the query reads it):\n  %s",
			len(blind), joinLines(blind))
	}
}

func joinLines(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "\n  "
		}
		out += s
	}
	return out
}
