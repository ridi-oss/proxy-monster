package proxymonsterv1

import (
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

func TestNativeProtocolFieldNumbers(t *testing.T) {
	decision := new(DecisionRequest).ProtoReflect().Descriptor().Fields()
	if decision.ByName("current_catalog").Number() != 12 || decision.ByName("session").Number() != 14 {
		t.Fatal("decision namespace and session field numbers changed")
	}
	session := new(analyzerpb.SessionObservation).ProtoReflect().Descriptor().Fields()
	if session.ByName("athena").Number() != 3 {
		t.Fatal("session Athena scope field number changed")
	}
}

func TestAthenaScopeSharesAnalyzerTypeAndPreservesParameterOrder(t *testing.T) {
	context := &analyzerpb.AthenaSqlContext{
		Workgroup:           "reports",
		ExecutionParameters: []string{"'second'", "'first'"},
		PreparedDefinitions: []*analyzerpb.AthenaPreparedDefinition{{
			Workgroup: "reports", Name: "lookup", QueryString: "SELECT email FROM users WHERE id = ?",
		}},
	}
	request := &DecisionRequest{Session: &analyzerpb.SessionObservation{Engine: &analyzerpb.SessionObservation_Athena{Athena: context}}}
	encoded, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(DecisionRequest)
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	analysis := &analyzerpb.AnalyzeRequest{EngineConfig: &analyzerpb.EngineConfig{Session: decoded.GetSession()}}
	if !proto.Equal(analysis.GetEngineConfig().GetSession().GetAthena(), context) {
		t.Fatalf("scope changed across decision/analyzer boundary: %v", analysis.GetEngineConfig().GetSession().GetAthena())
	}
}

func TestAthenaSubmissionEmptyParametersRemainPresent(t *testing.T) {
	verdict := &Verdict{RewrittenSql: proto.String("SELECT email FROM users"), Submission: &analyzerpb.Submission{Engine: &analyzerpb.Submission_Athena{Athena: &analyzerpb.AthenaSubmission{}}}}
	encoded, err := proto.Marshal(verdict)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(Verdict)
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetSubmission().GetAthena() == nil || len(decoded.GetSubmission().GetAthena().GetExecutionParameters()) != 0 {
		t.Fatalf("replacement with empty parameters lost presence: %v", decoded)
	}
	if new(Verdict).GetSubmission() != nil || new(DecisionRequest).GetSession().GetAthena() != nil {
		t.Fatal("absent Athena fields must remain absent")
	}
}

func TestAthenaPreparedDefinitionCommandHasItsOwnArm(t *testing.T) {
	command := &ProxyCommand{Command: &ProxyCommand_FetchAthenaPreparedDefinition{
		FetchAthenaPreparedDefinition: &analyzerpb.FetchAthenaPreparedDefinition{Workgroup: "reports", Name: "lookup"},
	}}
	encoded, err := proto.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(ProxyCommand)
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetRefetch() != nil || !proto.Equal(decoded, command) {
		t.Fatalf("prepared observation command changed arm: %v", decoded)
	}
}
