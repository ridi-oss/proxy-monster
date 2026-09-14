package probe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ridi-oss/sqlglot-go/schema"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// expandedProbeCase is one in-scope corpus case bound to a single dialect.
type expandedProbeCase struct {
	name    string
	dialect string
	sql     string
	sch     *schema.Mapping
}

func goldenKey(dialect, name string) string { return dialect + "|" + name }

func parityNamespace(dialect string) NamespaceConfig {
	ns := NamespaceConfig{Catalog: "acme", SearchPath: []string{"public"}}
	if dialect == "mysql" {
		ns = NamespaceConfig{Catalog: "def", SearchPath: []string{"public"}}
	}
	ns.EngineCatalog = engineCatalogFromProto(testFunctionCatalog(dialect == "mysql", ns.SearchPath), ns.SearchPath)
	return ns
}

func parityEngineConfig(t *testing.T, dialect string) *pb.EngineConfig {
	t.Helper()
	switch dialect {
	case "mysql":
		return &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}
	case "postgres":
		return &pb.EngineConfig{Engine: pb.Engine_POSTGRES}
	default:
		t.Fatalf("unsupported dialect %q", dialect)
		return nil
	}
}

func qualifyParitySchema(flat *schema.Mapping, dialect string) *schema.Mapping {
	namespace := parityNamespace(dialect)
	root := schema.NewMapping()
	schemas := schema.NewMapping()
	schemas.Set(namespace.SearchPath[0], flat)
	root.Set(namespace.Catalog, schemas)
	return root
}

// inScopeProbeCases expands the parity corpus (skipping deferred cases) across the dialects
// each case applies to — the exact set TestProbeParity sends to the Python oracle and that the
// committed golden file records. Kept in lockstep with the TestProbeParity expansion.
func inScopeProbeCases() []expandedProbeCase {
	var out []expandedProbeCase
	for _, tc := range probeParityCases() {
		if tc.deferredReason != "" {
			continue
		}
		dialects := []string{"mysql", "postgres"}
		if tc.dialect != "" {
			dialects = []string{tc.dialect}
		}
		sch := tc.schema
		if sch == nil {
			sch = defaultProbeSchema()
		}
		for _, dialect := range dialects {
			out = append(out, expandedProbeCase{name: tc.name, dialect: dialect, sql: tc.sql, sch: sch})
		}
	}
	return out
}

// TestProbeGolden is the HERMETIC parity guard: it compares the Go probe against the committed
// golden ProbeResults (captured from the real Python sqlglot 30.12.0 probe.py) WITHOUT needing
// python3 or the pinned reference. TestProbeParity proves the goldens still match live Python
// (and regenerates them under PROBE_REGEN=1); this test guarantees the enforcement output can't
// regress in a python3-less CI. Together they close the "parity gate not hermetic" gap.
func TestProbeGolden(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	goldenPath := filepath.Join(filepath.Dir(file), "testdata", "golden.json")
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s (regenerate: PROBE_REGEN=1 go test ./probe/ -run TestProbeParity): %v", goldenPath, err)
	}
	var golden map[string]json.RawMessage
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}

	cases := inScopeProbeCases()
	if len(golden) != len(cases) {
		t.Fatalf("golden has %d entries, corpus has %d in-scope cases — regenerate with PROBE_REGEN=1", len(golden), len(cases))
	}

	exact := 0
	for _, tc := range cases {
		raw, ok := golden[goldenKey(tc.dialect, tc.name)]
		if !ok {
			t.Errorf("no golden entry for %s/%s — regenerate", tc.dialect, tc.name)
			continue
		}
		var want ProbeResult
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatalf("unmarshal golden %s/%s: %v", tc.dialect, tc.name, err)
		}
		got := Probe(tc.sql, parityEngineConfig(t, tc.dialect), qualifyParitySchema(tc.sch, tc.dialect), nil, parityNamespace(tc.dialect))
		ok2, _, diffs := compareProbeResults(want, got, tc.dialect)
		if !ok2 {
			t.Errorf("%s/%s golden mismatch (sql=%q):\n  %s", tc.dialect, tc.name, tc.sql, strings.Join(diffs, "\n  "))
			continue
		}
		exact++
	}
	t.Logf("hermetic golden parity = %d/%d", exact, len(cases))
}
