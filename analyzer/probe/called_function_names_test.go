package probe

import (
	"slices"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func TestUnresolvedCallNamesAreCanonical(t *testing.T) {
	res := analyzeProbe(t, &pb.AnalyzeRequest{
		Sql:          `SELECT "PG_READ_FILE"('a'), PG_READ_FILE('b') FROM missing_table`,
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES}, Namespace: canonicalPostgresNamespace, Catalog: snapshot(canonicalPostgresCatalog),
	})
	if res.Resolved || !slices.Contains(res.Functions, "PG_READ_FILE") || !slices.Contains(res.Functions, "pg_read_file") {
		t.Fatalf("resolved=%v functions=%v", res.Resolved, res.Functions)
	}
}
