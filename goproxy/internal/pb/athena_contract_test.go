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
		Workgroup: "reports",
		Httpdb:    &analyzerpb.HttpDbSqlContext{Parameters: []*analyzerpb.HttpDbParameter{{Value: "'second'"}, {Value: "'first'"}}},
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

func TestNativeResultInstructionsReferenceOriginalContext(t *testing.T) {
	instructions := &analyzerpb.HttpDbInstructions{
		Action:   analyzerpb.HttpDbInstruction_HTTP_DB_INSTRUCTION_APPLY_ORIGINAL_CONTEXT,
		Contexts: []*analyzerpb.HttpDbContextRef{{ResourceId: "execution-123", ContextId: "context-456"}},
	}
	response := &RequestAuthorizationResult{Allowed: true, HttpDbInstructions: instructions}
	encoded, err := proto.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(RequestAuthorizationResult)
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	got := decoded.GetHttpDbInstructions()
	if !proto.Equal(got, instructions) {
		t.Fatalf("native result instructions changed: %v", got)
	}
	if new(analyzerpb.HttpDbInstructions).GetAction() != analyzerpb.HttpDbInstruction_HTTP_DB_INSTRUCTION_UNSPECIFIED {
		t.Fatal("an absent native instruction must not imply response release")
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
