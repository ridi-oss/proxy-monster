package cp

import (
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/protobuf/proto"
)

func TestRegisterPreservesConnectionInfoPresence(t *testing.T) {
	fake := &fakeControlPlane{}
	client := startFakeControlPlane(t, fake)
	for _, info := range []*pb.ConnectionInfo{nil, {}, {Endpoint: "proxy.example:6033", Properties: map[string]string{"database": "app"}}} {
		if err := client.Register(enginepb.Engine_MYSQL, "target", 3306, "app", nil, "", nil, false, info, nil); err != nil {
			t.Fatal(err)
		}
		fake.mu.Lock()
		got := fake.lastRegisterReq.ConnectionInfo
		fake.mu.Unlock()
		if !proto.Equal(got, info) {
			t.Fatalf("connection info = %v, want %v", got, info)
		}
	}
}

func TestRegisterSendsDescriptionPresence(t *testing.T) {
	fake := &fakeControlPlane{}
	client := startFakeControlPlane(t, fake)
	empty, set := "", "Orders and payments"
	for _, description := range []*string{nil, &empty, &set} {
		if err := client.Register(enginepb.Engine_MYSQL, "target", 3306, "app", nil, "", nil, false, nil, description); err != nil {
			t.Fatal(err)
		}
		fake.mu.Lock()
		got := fake.lastRegisterReq
		fake.mu.Unlock()
		if got.Description != nil != (description != nil) || (description != nil && got.GetDescription() != *description) {
			t.Fatalf("description = %v, want %v", got.Description, description)
		}
	}
}
