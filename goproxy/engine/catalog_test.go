package engine

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/protobuf/proto"
)

func TestQueryEngineCachesCatalogWithNamespace(t *testing.T) {
	decider := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	query := NewQueryEngine(decider)
	catalog := "one"
	probes := 0
	input := AuthzInput{ProbeNamespace: func() (NamespaceProbe, error) {
		probes++
		return NamespaceProbe{CurrentCatalog: catalog, Namespace: []string{"schema"}}, nil
	}}
	query.Authorize(input)
	catalog = "two"
	query.Authorize(input)
	if decider.lastReq.CurrentCatalog != "one" || probes != 1 {
		t.Fatal("catalog was not cached with namespace")
	}
	query.MarkNamespaceDirty()
	query.Authorize(input)
	if decider.lastReq.CurrentCatalog != "two" || probes != 2 {
		t.Fatal("dirty namespace did not refresh catalog")
	}
}

func TestRefetcherCatalogIdentity(t *testing.T) {
	for _, test := range []struct {
		name                string
		catalog             *string
		unchanged, rejected bool
	}{
		{"legacy inferred", nil, false, false},
		{"qualified full fetch", proto.String("def"), false, false},
		{"qualified unchanged", proto.String("def"), true, false},
		{"blank", proto.String(""), false, true},
		{"wrong catalog", proto.String("other"), false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			probes := 0
			var pushed *pb.SchemaFragmentPush
			refetcher := Refetcher{Catalog: "def", Db: refetchDb{}, BackendGeneration: 7,
				Probe: func(sql string, _ int) ([][]*string, error) {
					probes++
					if sql == "columns:schema" {
						return fragmentRows("schema"), nil
					}
					return [][]*string{{ptr("hash")}}, nil
				},
				Push: func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 8, nil },
			}
			command := &pb.Refetch{Schema: "schema", Catalog: test.catalog}
			if test.unchanged {
				command.IfHashDiffers = []byte("hash")
			}
			err := refetcher.Run(command)
			if test.rejected {
				if err == nil || probes != 0 || pushed != nil {
					t.Fatalf("invalid catalog touched target: err=%v, probes=%d, push=%v", err, probes, pushed)
				}
				return
			}
			if err != nil || pushed.GetCatalog() != "def" || pushed.GetBackendGeneration() != 7 || pushed.GetUnchanged() != test.unchanged {
				t.Fatalf("push = %v, error = %v", pushed, err)
			}
			if !test.unchanged && (len(pushed.Columns) != 1 || pushed.Columns[0].GetCatalog() != "def") {
				t.Fatalf("fragment columns = %v", pushed.Columns)
			}
		})
	}
}
