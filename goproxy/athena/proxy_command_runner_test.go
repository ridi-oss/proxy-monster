package athena

import (
	"errors"
	"io"
	"net/http"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func TestProxyCommandRunnerDispatch(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch request.Header.Get("X-Amz-Target") {
		case "AmazonAthena.GetPreparedStatement":
			_, _ = io.WriteString(w, `{"PreparedStatement":{"StatementName":"by_id","QueryStatement":"SELECT 1"}}`)
		case "AmazonAthena.ListTableMetadata":
			_, _ = io.WriteString(w, `{"TableMetadataList":[{"Name":"orders","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"id","Type":"int"}]}]}`)
		default:
			t.Errorf("unexpected call %s", request.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	var pushes []*pb.SchemaFragmentPush
	runner := &relay.ProxyCommandRunner{Catalog: target.catalogIdentity(), ConnectionID: []byte("conn"), BackendGeneration: 7, Inspector: target,
		Push: func(push *pb.SchemaFragmentPush) (uint64, error) { pushes = append(pushes, push); return 1, nil }}
	fetch := &pb.ProxyCommand{Command: &pb.ProxyCommand_FetchAthenaPreparedDefinition{
		FetchAthenaPreparedDefinition: &enginepb.FetchAthenaPreparedDefinition{Workgroup: "primary", Name: "by_id"}}}
	refetch := &pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Catalog: target.catalogIdentity(), Schema: "example"}}}

	snapshot := &spi.SessionSnapshot{SessionObservation: &enginepb.SessionObservation{
		Engine: &enginepb.SessionObservation_Athena{Athena: &enginepb.AthenaSqlContext{Workgroup: "primary"}}}}
	if err := runner.RunAll([]*pb.ProxyCommand{fetch, refetch}, snapshot); err != nil {
		t.Fatal(err)
	}
	if held := snapshot.GetAthena().GetPreparedDefinitions(); len(held) != 1 || held[0].GetQueryString() != "SELECT 1" {
		t.Fatalf("prepared definitions = %v", held)
	}
	if len(pushes) != 1 || string(pushes[0].GetConnectionId()) != "conn" || pushes[0].GetCatalog() != target.catalogIdentity() ||
		pushes[0].GetBackendGeneration() != 7 || len(pushes[0].GetColumns()) != 1 {
		t.Fatalf("pushes = %v", pushes)
	}

	for name, command := range map[string]*pb.ProxyCommand{
		"empty":   {},
		"unknown": {Command: &pb.ProxyCommand_CheckTargetError{CheckTargetError: &pb.CheckTargetError{}}},
	} {
		pushes = nil
		if err := runner.RunAll([]*pb.ProxyCommand{command, refetch}, snapshot); !errors.Is(err, relay.ErrUnknownCommand) || len(pushes) != 0 {
			t.Errorf("%s: err = %v, pushes = %d; want ErrUnknownCommand before any push", name, err, len(pushes))
		}
	}
}
