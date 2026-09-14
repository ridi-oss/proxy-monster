package athena

import (
	"context"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
)

func TestRunSessionSubmitsPollsReadsAndMasks(t *testing.T) {
	aws := newFakeAthena()
	target := testTarget(t, aws.handle)
	client := &flowClient{principal: "alice", verdict: maskVerdict(), completed: make(chan struct{}, 8)}
	session, err := target.NewRunSession(context.Background(), spi.RunSessionOptions{Client: client, Token: "login-alice", ConnectionID: []byte("0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.OnOpen(context.Background(), []*pb.Refetch{{Schema: "example", Catalog: proto.String("awsdatacatalog")}}); err != nil {
		t.Fatal(err)
	}
	result, err := session.ServeStatement("SELECT * FROM users WHERE n > 0", 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Denied || result.Decision == nil || result.Decision.Action != "MASK" {
		t.Fatalf("unexpected decision: %+v", result)
	}
	if len(result.Columns) != 2 || result.Columns[0] != "email" {
		t.Fatalf("columns = %v", result.Columns)
	}
	if len(result.Rows) != 1 || result.Rows[0][0] == nil || *result.Rows[0][0] != "####" || *result.Rows[0][1] != "1" {
		t.Fatalf("rows = %v (header must be dropped, email masked)", result.Rows)
	}
	var submitted map[string]any
	for i, op := range aws.ops {
		if op == "StartQueryExecution" {
			submitted = aws.requests[i]
		}
	}
	if submitted == nil || submitted["QueryString"] != "SELECT email, n FROM users WHERE n > (1)" || submitted["WorkGroup"] != "primary" {
		t.Fatalf("editor submission not admitted: %v", submitted)
	}
	if len(client.decisions) != 1 || client.decisions[0].AthenaContext.GetWorkgroup() != "primary" || client.decisions[0].AthenaContext.GetMaxRows() != 100 {
		t.Fatalf("editor decision lacks Athena scope: %+v", client.decisions)
	}
}
