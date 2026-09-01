package probe

import (
	"slices"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// A schema qualifier is emitted so the control plane can FETCH that schema when the connection does not
// hold it. MySQL under lower_case_table_names=1 stores information_schema lowercase, so a raw uppercase
// candidate matches zero rows: the fetch records an empty fragment as held, and the retry relays the
// statement unanalyzed — unmasked. The candidate must therefore carry the spelling the target DB stores.
func TestSchemaQualifierCandidatesFoldToTheStoredSpelling(t *testing.T) {
	mapping, err := schemaMappingFromProto([]*pb.ColumnSpec{
		columnSpec("def", "bom", "tb_user", "id", "BIGINT"),
	})
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}
	for _, tc := range []struct {
		lowerCaseTableNames int32
		want                string
	}{
		// Mode 0 is case-sensitive: the stored spelling IS the raw one, so folding would break the fetch.
		{0, "GOODS_STORE"},
		{1, "goods_store"},
		{2, "goods_store"},
	} {
		facts := EmitFacts(
			"SELECT id FROM GOODS_STORE.orders",
			&pb.EngineConfig{
				Engine:                   pb.Engine_MYSQL,
				EngineVersion:            "8.0.44",
				MysqlLowerCaseTableNames: proto.Int32(tc.lowerCaseTableNames),
			},
			mapping,
			NamespaceConfig{Catalog: "def", SearchPath: []string{"bom"}},
		)
		got := facts.GetSchemaQualifierCandidates()
		if !slices.Contains(got, tc.want) {
			t.Errorf("lower_case_table_names=%d: want candidate %q for the refetch, got %v",
				tc.lowerCaseTableNames, tc.want, got)
		}
	}
}
