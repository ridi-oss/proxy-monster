package proxymonsterv1

import (
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

func TestNativeProtocolFieldNumbers(t *testing.T) {
	decision := new(DecisionRequest).ProtoReflect().Descriptor().Fields()
	if decision.ByName("current_catalog").Number() != 12 || decision.ByName("athena").Number() != 13 {
		t.Fatal("decision namespace and Athena scope field numbers changed")
	}
	config := new(analyzerpb.EngineConfig).ProtoReflect().Descriptor().Fields()
	if config.ByName("athena").Number() != 9 {
		t.Fatal("analyzer Athena scope field number changed")
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
	request := &DecisionRequest{Athena: context}
	encoded, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(DecisionRequest)
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	analysis := &analyzerpb.AnalyzeRequest{EngineConfig: &analyzerpb.EngineConfig{Athena: decoded.GetAthena()}}
	if !proto.Equal(analysis.GetEngineConfig().GetAthena(), context) {
		t.Fatalf("scope changed across decision/analyzer boundary: %v", analysis.GetEngineConfig().GetAthena())
	}
}

func TestAthenaSubmissionEmptyParametersRemainPresent(t *testing.T) {
	verdict := &Verdict{RewrittenSql: proto.String("SELECT email FROM users"), AthenaSubmission: &analyzerpb.AthenaSubmission{}}
	encoded, err := proto.Marshal(verdict)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(Verdict)
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetAthenaSubmission() == nil || len(decoded.GetAthenaSubmission().GetExecutionParameters()) != 0 {
		t.Fatalf("replacement with empty parameters lost presence: %v", decoded)
	}
	if decoded.RewrittenSql != nil {
		t.Fatal("native submission unexpectedly populated relational rewritten_sql")
	}
	if new(Verdict).GetAthenaSubmission() != nil || new(DecisionRequest).GetAthena() != nil {
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
