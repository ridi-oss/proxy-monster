package probe

import (
	"slices"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// Search-path entries are canonical names, never SQL text to fold again.
func TestSearchPathEntriesAreCanonicalNames(t *testing.T) {
	for _, c := range []struct {
		name   string
		config *pb.EngineConfig
		ns     *pb.Namespace
		cols   []*pb.Column
		want   string
	}{
		{"postgres quoted schema", &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			&pb.Namespace{Catalog: "acme", SearchPath: []string{"App"}},
			[]*pb.Column{pbColumn("App", "t", "secret", "TEXT"), pbColumn("app", "t", "secret", "TEXT")},
			"acme.App.t.secret"},
		{"postgres quoted database", &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			&pb.Namespace{Catalog: "Acme", SearchPath: []string{"public"}},
			[]*pb.Column{pbColumn("public", "t", "secret", "TEXT")},
			"Acme.public.t.secret"},
		{"athena database", &pb.EngineConfig{Engine: pb.Engine_ATHENA, Session: &pb.SessionObservation{Engine: &pb.SessionObservation_Athena{Athena: &pb.AthenaSqlContext{Workgroup: "primary"}}}},
			&pb.Namespace{Catalog: "awsdatacatalog", SearchPath: []string{"sales"}},
			[]*pb.Column{pbColumn("sales", "t", "secret", "string")},
			"awsdatacatalog.sales.t.secret"},
		{"mysql lower_case_table_names=0 schema", &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0)},
			&pb.Namespace{Catalog: "def", SearchPath: []string{"App"}},
			[]*pb.Column{pbColumn("App", "t", "secret", "TEXT"), pbColumn("app", "t", "secret", "TEXT")},
			"def.App.t.secret"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, col := range c.cols {
				col.Catalog = c.ns.Catalog
			}
			res := analyzeProbe(t, &pb.AnalyzeRequest{Sql: "SELECT secret FROM t", EngineConfig: c.config, Namespace: c.ns, Catalog: snapshot(c.cols)})
			var origins []string
			for _, o := range res.Origins {
				origins = append(origins, o.Origins...)
			}
			if !res.Resolved || !slices.Contains(origins, c.want) {
				t.Fatalf("resolved=%v origins=%v", res.Resolved, origins)
			}
		})
	}
}
