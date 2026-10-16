package engines

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func TestOnlyTheCanonicalExcludedIsTheProposedRow(t *testing.T) {
	for sql, resolved := range map[string]bool{
		`INSERT INTO users AS "Excluded" (id, name) VALUES (1, 'y') ON CONFLICT (id) DO UPDATE SET name = excluded.name`: true,
		`INSERT INTO users (id, name) VALUES (1, 'y') ON CONFLICT (id) DO UPDATE SET name = "EXCLUDED".name`:             false,
	} {
		res := analyzeProbe(t, &pb.AnalyzeRequest{
			Sql: sql, EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES}, Namespace: canonicalPostgresNamespace, Catalog: snapshot(canonicalPostgresCatalog),
		})
		if res.Resolved != resolved {
			t.Errorf("%s: resolved=%v", sql, res.Resolved)
		}
	}
}
