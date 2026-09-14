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
	mapping, _, err := schemaMappingFromProto("def", []*pb.Column{
		pbColumn("bom", "tb_user", "id", "BIGINT"),
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
			nil,
			NamespaceConfig{Catalog: "def", SearchPath: []string{"bom"}},
		)
		got := facts.GetSchemaQualifierCandidates()
		if !slices.Contains(got, tc.want) {
			t.Errorf("lower_case_table_names=%d: want candidate %q for the refetch, got %v",
				tc.lowerCaseTableNames, tc.want, got)
		}
	}
}

// `SELECT app.get_ssn()` names no table, so the qualifier of the call is the only thing that can make the
// control plane fetch `app`; without it the statement stays unresolved on every retry.
func TestSchemaQualifierCandidatesIncludeFunctionQualifiers(t *testing.T) {
	mapping, _, err := schemaMappingFromProto("db", []*pb.Column{pbColumn("public", "users", "id", "integer")})
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}
	facts := EmitFacts(
		"SELECT app.get_ssn()",
		&pb.EngineConfig{Engine: pb.Engine_POSTGRES, EngineVersion: "16.4"},
		mapping,
		nil,
		NamespaceConfig{Catalog: "db", SearchPath: []string{"pg_catalog", "public"}, EngineCatalog: engineCatalogFromProto(&pb.FunctionCatalog{}, nil)},
	)
	if facts.GetResolved() {
		t.Fatalf("resolved with no inventory: %v", facts)
	}
	if !slices.Equal(facts.GetSchemaQualifierCandidates(), []string{"app"}) {
		t.Fatalf("candidates = %v, want [app]", facts.GetSchemaQualifierCandidates())
	}
}
