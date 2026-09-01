package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// AnalyzeStatement is the FFM entry point the JVM calls, and it owns the proto→internal decode that
// EmitFacts itself never sees: a malformed catalog or namespace must surface as an ERROR here rather
// than reaching the analyzer as an empty one, which would analyze against a catalog that isn't there
// and resolve nothing — the fail-OPEN direction. The tests named for it elsewhere drive Probe through
// a helper that reimplements this plumbing, so the decode boundary itself was never exercised.
func TestAnalyzeStatementDecodesCatalogAndNamespace(t *testing.T) {
	base := func() *pb.AnalyzeRequest {
		return &pb.AnalyzeRequest{
			Sql: "SELECT id FROM users",
			EngineConfig: &pb.EngineConfig{
				Engine: pb.Engine_MYSQL, EngineVersion: "8.0.44",
				MysqlLowerCaseTableNames: proto.Int32(0),
			},
			Namespace: &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}},
			Catalog: []*pb.ColumnSpec{
				columnSpec("def", "acme", "users", "id", "BIGINT"),
			},
		}
	}

	facts, err := AnalyzeStatement(base())
	if err != nil {
		t.Fatalf("a well-formed request must analyze: %v", err)
	}
	if !facts.GetResolved() {
		t.Fatalf("expected resolved, got %s: %s", stageString(facts.FailedStage), facts.GetDetail())
	}

	// A namespace with no search path cannot resolve an unqualified name; it must be refused at the
	// boundary, not silently analyzed under an empty one.
	noSearchPath := base()
	noSearchPath.Namespace = &pb.Namespace{Catalog: "def"}
	if _, err := AnalyzeStatement(noSearchPath); err == nil {
		t.Error("an empty search path must be refused at the decode boundary, got no error")
	}

	// A duplicate catalog column makes the mapping ambiguous — a lineage key could bind either row.
	dup := base()
	dup.Catalog = append(dup.Catalog, columnSpec("def", "acme", "users", "id", "BIGINT"))
	if _, err := AnalyzeStatement(dup); err == nil {
		t.Error("a duplicate catalog column must be refused at the decode boundary, got no error")
	}
}

// The FFM boundary is a cgo boundary: a panic crossing it crashes the host JVM. AnalyzeStatementSafe
// must therefore be TOTAL — every input yields a decodable StatementFacts, and a failure is expressed
// as resolved=false rather than an error or a panic.
func TestAnalyzeStatementSafeIsTotal(t *testing.T) {
	catalog := []*pb.ColumnSpec{columnSpec("def", "acme", "users", "id", "BIGINT")}
	engine := &pb.EngineConfig{
		Engine: pb.Engine_MYSQL, EngineVersion: "8.0.44",
		MysqlLowerCaseTableNames: proto.Int32(0),
	}
	namespace := &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}}

	encode := func(t *testing.T, req *pb.AnalyzeRequest) []byte {
		t.Helper()
		b, err := proto.Marshal(req)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	for _, tc := range []struct {
		name         string
		in           []byte
		wantResolved bool
	}{
		{"well-formed", encode(t, &pb.AnalyzeRequest{
			Sql: "SELECT id FROM users", EngineConfig: engine, Namespace: namespace, Catalog: catalog,
		}), true},
		// Not a valid proto at all — the decode itself fails.
		{"garbage bytes", []byte{0xff, 0xfe, 0xfd, 0x01, 0x02}, false},
		{"empty bytes", []byte{}, false},
		{"nil bytes", nil, false},
		// Decodes, but the request is unusable: no engine, no namespace, no catalog.
		{"empty request", encode(t, &pb.AnalyzeRequest{}), false},
		// Decodes and is well-formed, but the statement cannot be parsed.
		{"unparseable sql", encode(t, &pb.AnalyzeRequest{
			Sql: "SELECT FROM WHERE ((", EngineConfig: engine, Namespace: namespace, Catalog: catalog,
		}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := AnalyzeStatementSafe(tc.in)
			if len(out) == 0 && tc.wantResolved {
				t.Fatal("a resolvable request must return a non-empty encoding")
			}
			var facts pb.StatementFacts
			if err := proto.Unmarshal(out, &facts); err != nil {
				t.Fatalf("output must always be a decodable StatementFacts, got %v", err)
			}
			if got := facts.GetResolved(); got != tc.wantResolved {
				t.Errorf("resolved = %v, want %v (detail %q)", got, tc.wantResolved, facts.GetDetail())
			}
			if !tc.wantResolved && facts.GetDetail() == "" {
				t.Error("a fail-closed result must carry a detail explaining why")
			}
		})
	}
}
