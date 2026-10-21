package sqldb

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func TestRefetcherCatalogIdentity(t *testing.T) {
	for _, test := range []struct {
		name                string
		catalog             string
		unchanged, rejected bool
	}{
		{"qualified full fetch", "def", false, false},
		{"qualified unchanged", "def", true, false},
		{"blank", "", false, true},
		{"wrong catalog", "other", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			probes := 0
			var pushed *pb.SchemaFragmentPush
			refetcher := Refetcher{Catalog: "def", Queries: refetchQueries, BackendGeneration: 7,
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
