package workload_test

import (
	"context"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	bridgepb "github.com/ridi-oss/proxy-monster/cpgo/gobridge/pb"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/workload"
)

func bridgeError(t *testing.T, err error) (codes.Code, string, map[string]string) {
	t.Helper()
	st, _ := grpcstatus.FromError(err)
	params := map[string]string{}
	for _, d := range st.Details() {
		if e, ok := d.(*bridgepb.WorkloadBindingError); ok {
			for _, p := range e.GetParams() {
				params[p.GetKey()] = p.GetValue()
			}
			return st.Code(), e.GetCode(), params
		}
	}
	return st.Code(), "", params
}

func TestBridgeServiceWritesBindingsAsTheMCPCaller(t *testing.T) {
	ai := newAWSIssuer(t)
	e := routetest.SetupConfig(t, routetest.Config{Workload: workload.NewVerifier([]workload.Issuer{ai.issuer()}, http.DefaultClient)})
	ctx := context.Background()
	s := workload.NewBridgeService([]workload.Issuer{ai.issuer()})
	if _, err := s.ListBindings(ctx, &bridgepb.ListBindingsRequest{}); grpcstatus.Code(err) != codes.Unavailable {
		t.Fatalf("before the pool: %v", err)
	}
	s.Ready(e.St.Pool)
	caller := &bridgepb.BindingCaller{Principal: "admin@example.com", ClientAddr: "198.51.100.7"}
	input := &bridgepb.WorkloadBindingInput{Name: "tf-pmon", Issuer: "aws-prod", Subject: role, Purposes: []string{"mcp"},
		McpScopes: []string{"mcp:read"}, Conditions: map[string]*bridgepb.ConditionValues{"aws_account": {Values: []string{"111122223333"}}}}
	created, err := s.CreateBinding(ctx, &bridgepb.WriteBindingRequest{Caller: caller, Binding: input})
	if err != nil || created.GetPrincipal() != "svc:tf-pmon" || created.GetTtlSeconds() != 900 || !created.GetEnabled() ||
		created.GetConditions()["aws_account"].GetValues()[0] != "111122223333" || created.GetCreatedAt() == "" {
		t.Fatalf("create %v %v", created, err)
	}
	_, err = s.CreateBinding(ctx, &bridgepb.WriteBindingRequest{Caller: caller, Binding: input})
	if c, code, p := bridgeError(t, err); c != codes.FailedPrecondition || code != "common.already_exists" || p["name"] != "tf-pmon" {
		t.Errorf("duplicate %v %s %v", c, code, p)
	}
	bad := proto.Clone(input).(*bridgepb.WorkloadBindingInput)
	bad.McpScopes = nil
	_, err = s.CreateBinding(ctx, &bridgepb.WriteBindingRequest{Caller: caller, Binding: bad})
	if _, code, p := bridgeError(t, err); code != "common.invalid_value" || p["field"] != "mcpScopes" {
		t.Errorf("invalid %s %v", code, p)
	}

	h := &harness{t: t, e: e}
	h.exchange(ai.token(t, role, nil), "mcp", "", http.StatusOK)
	disabled := proto.Clone(input).(*bridgepb.WorkloadBindingInput)
	off := false
	disabled.Enabled = &off
	updated, err := s.UpdateBinding(ctx, &bridgepb.WriteBindingRequest{Caller: caller, Binding: disabled})
	if err != nil || updated.GetEnabled() || updated.GetId() != created.GetId() {
		t.Fatalf("update %v %v", updated, err)
	}
	if n := e.Count(t, `SELECT count(*) FROM proxy_token WHERE workload_binding_id IS NOT NULL AND revoked_at IS NULL`); n != 0 {
		t.Errorf("disable left %d live tokens", n)
	}
	missing := proto.Clone(input).(*bridgepb.WorkloadBindingInput)
	missing.Name = "nope"
	_, err = s.UpdateBinding(ctx, &bridgepb.WriteBindingRequest{Caller: caller, Binding: missing})
	if _, code, p := bridgeError(t, err); code != "common.not_found" || p["resource"] != "workload_binding" {
		t.Errorf("missing %s %v", code, p)
	}
	listed, err := s.ListBindings(ctx, &bridgepb.ListBindingsRequest{})
	if err != nil || len(listed.GetBindings()) != 1 || listed.GetBindings()[0].GetName() != "tf-pmon" {
		t.Fatalf("list %v %v", listed, err)
	}
	if _, err := s.DeleteBinding(ctx, &bridgepb.DeleteBindingRequest{Caller: caller, Name: "tf-pmon"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.DeleteBinding(ctx, &bridgepb.DeleteBindingRequest{Caller: caller, Name: "tf-pmon"})
	if _, code, _ := bridgeError(t, err); code != "common.not_found" {
		t.Errorf("second delete %s", code)
	}
	if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'admin.identity' AND principal = 'admin@example.com'
		AND channel = 'mcp' AND client_addr = '198.51.100.7' AND resource = 'WorkloadBinding::"tf-pmon"'`); n != 3 {
		t.Errorf("%d mcp audit rows", n)
	}
	routetest.VerifyChain(t, e)
}
