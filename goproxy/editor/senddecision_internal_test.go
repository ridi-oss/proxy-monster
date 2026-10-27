package editor

import (
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

type captureStream struct{ sent []*pb.ProxyEditorMsg }

func (c *captureStream) Send(m *pb.ProxyEditorMsg) error { c.sent = append(c.sent, m); return nil }
func (c *captureStream) Recv() (*pb.CpEditorMsg, error)  { return nil, nil }
func (c *captureStream) CloseSend() error                { return nil }

func TestSendDecisionEchoesResultRequirements(t *testing.T) {
	requirements := &pb.ResultRequirements{TempTables: []*enginepb.ObjectRef{{Table: "scratch"}}}
	s := &captureStream{}
	if !sendDecision(s, &spi.Decision{Action: "ALLOW", ResultRequirements: requirements}) {
		t.Fatal("sendDecision returned false")
	}
	if got := s.sent[0].GetDecision().GetResultRequirements(); got != requirements {
		t.Fatalf("EditorDecision.result_requirements = %+v, want %+v", got, requirements)
	}
}
