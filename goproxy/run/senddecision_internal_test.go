package run

import (
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

type captureStream struct{ sent []*pb.ProxyRunMsg }

func (c *captureStream) Send(m *pb.ProxyRunMsg) error     { c.sent = append(c.sent, m); return nil }
func (c *captureStream) Recv() (*pb.ControlRunMsg, error) { return nil, nil }
func (c *captureStream) CloseSend() error                 { return nil }

// The result-view drift gate depends on the decision's fingerprint reaching the control-plane on the return
// leg. sendDecision must forward engine.Decision.ResultFingerprint onto RunDecision unchanged, or a stored
// result would carry no fingerprint and fail closed at view. Guards the forward at runner.go.
func TestSendDecisionForwardsResultFingerprint(t *testing.T) {
	fp := []*enginepb.RequireResultReadGrant{
		{Resource: &enginepb.RequireResultReadGrant_Function{Function: &enginepb.FunctionResource{Name: "now"}}},
	}
	s := &captureStream{}
	if !sendDecision(s, &engine.Decision{Action: "ALLOW", ResultFingerprint: fp}) {
		t.Fatal("sendDecision returned false")
	}
	got := s.sent[0].GetDecision().GetResultFingerprint()
	if len(got) != 1 || got[0].GetFunction().GetName() != "now" {
		t.Fatalf("RunDecision.result_fingerprint not forwarded from the decision: %+v", got)
	}
}
