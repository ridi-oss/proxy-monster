package cp

import (
	"context"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type authorizationServer struct {
	pb.UnimplementedControlPlaneServer
	authorize func(context.Context, *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error)
}

func (s authorizationServer) AuthorizeRequest(ctx context.Context, request *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
	return s.authorize(ctx, request)
}

func TestAuthorizeRequestPreservesQualifiedContext(t *testing.T) {
	requests := []*pb.RequestAuthorization{
		{Operation: &pb.RequestAuthorization_ReadCatalog{ReadCatalog: &pb.ReadCatalog{Namespace: &enginepb.ObjectRef{Catalog: "catalog", Schema: "schema"}}}},
		{Operation: &pb.RequestAuthorization_ReadTableMetadata{ReadTableMetadata: &pb.ReadTableMetadata{Table: &enginepb.ObjectRef{Catalog: "catalog", Schema: "schema", Table: "orders"}}}},
	}
	for _, request := range requests {
		request.Token, request.DatasourceName, request.ClientAddr = "token", "other", "192.0.2.4"
		for _, allowed := range []bool{false, true} {
			principal := ""
			if allowed {
				principal = "reader@example.com"
			}
			observed := make(chan *pb.RequestAuthorization, 1)
			secrets := make(chan string, 1)
			client := startControlPlane(t, authorizationServer{authorize: func(ctx context.Context, got *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
				observed <- got
				secrets <- metaValue(ctx)
				return &pb.RequestAuthorizationResult{Allowed: allowed, DenyReason: "reason", EffectiveRoles: []string{"reader"}, Principal: principal}, nil
			}})
			response, err := client.AuthorizeRequest(context.Background(), request)
			if err != nil || response.GetAllowed() != allowed || response.GetDenyReason() != "reason" || len(response.GetEffectiveRoles()) != 1 || response.GetPrincipal() != principal {
				t.Fatalf("authorization = %v, %v", response, err)
			}
			want := proto.Clone(request).(*pb.RequestAuthorization)
			want.DatasourceName = "ds-1"
			if got := <-observed; !proto.Equal(got, want) {
				t.Fatalf("request = %v, want %v", got, want)
			}
			if <-secrets != "secret-abc" || request.DatasourceName != "other" {
				t.Fatal("transport secret was lost or caller input was mutated")
			}
		}
	}
}

func TestAuthorizeRequestFailsClosedOnTransportError(t *testing.T) {
	client := startControlPlane(t, authorizationServer{authorize: func(context.Context, *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
		return nil, status.Error(codes.Unauthenticated, "expired token")
	}})
	if response, err := client.AuthorizeRequest(context.Background(), &pb.RequestAuthorization{Operation: &pb.RequestAuthorization_ReadCatalog{ReadCatalog: &pb.ReadCatalog{Namespace: &enginepb.ObjectRef{Catalog: "catalog", Schema: "schema"}}}}); response != nil || err == nil {
		t.Fatalf("authorization = %v, %v", response, err)
	}
	if _, err := client.AuthorizeRequest(context.Background(), nil); err == nil {
		t.Fatal("nil authorization request was accepted")
	}
}
