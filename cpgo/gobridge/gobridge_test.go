package gobridge

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestOnlyCallsCarryingTheInternalTokenReachAService(t *testing.T) {
	s, err := Listen(0, "secret")
	if err != nil {
		t.Fatal(err)
	}
	healthpb.RegisterHealthServer(s.GRPC(), health.NewServer())
	served := make(chan error, 1)
	s.Serve(served)
	defer s.Close()

	addr := strings.TrimPrefix(s.Env(), AddrEnv+"=")
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("listening on %s, want loopback", addr)
	}
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	check := func(token string) codes.Code {
		ctx := context.Background()
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, TokenKey, token)
		}
		_, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
		return status.Code(err)
	}
	for _, token := range []string{"", "wrong"} {
		if code := check(token); code != codes.Unauthenticated {
			t.Fatalf("token %q: %v", token, code)
		}
	}
	if code := check("secret"); code != codes.OK {
		t.Fatalf("with the token: %v", code)
	}
}
