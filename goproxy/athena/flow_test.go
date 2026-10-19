package athena

import (
	"google.golang.org/protobuf/proto"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func flowServer(t *testing.T, principal string, verdict *pb.Verdict) (*nativeServer, *flowClient, *fakeAthena) {
	t.Helper()
	aws := newFakeAthena()
	target := testTarget(t, aws.handle)
	client := &flowClient{principal: principal, verdict: verdict, completed: make(chan struct{}, 8)}
	server := &nativeServer{target: target, client: client}
	return server, client, aws
}

func serve(server *nativeServer, principal, operation, body string) *httptest.ResponseRecorder {
	request := nativeTestRequest(operation, body)
	request.Header.Set("Authorization", "Bearer login-"+principal)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func TestSubmissionIsDecidedRewrittenAndMaskedOnRead(t *testing.T) {
	server, client, aws := flowServer(t, "alice", maskVerdict())
	response := serve(server, "alice", "StartQueryExecution", `{"QueryString":"SELECT * FROM users WHERE n > ?","ExecutionParameters":["1"],"ClientRequestToken":"token-1","WorkGroup":"primary"}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "exec-0001") {
		t.Fatalf("submission failed: %d %s", response.Code, response.Body.String())
	}
	if len(client.decisions) != 1 || client.decisions[0].GetSession().GetAthena().GetWorkgroup() != "primary" || client.decisions[0].GetSession().GetAthena().GetMaxRows() != 0 || len(client.decisions[0].GetSession().GetAthena().GetExecutionParameters()) != 1 || client.decisions[0].CurrentCatalog != "awsdatacatalog" {
		t.Fatalf("decision request lacks Athena scope: %+v", client.decisions)
	}
	if len(client.pushes) != 1 || client.pushes[0].Schema != "example" || len(client.pushes[0].Columns) != 1 {
		t.Fatalf("on-open catalog not answered from Glue: %+v", client.pushes)
	}
	submitted := aws.lastRequest("StartQueryExecution")
	if submitted["QueryString"] != "SELECT email, n FROM users WHERE n > (1)" || submitted["ExecutionParameters"] != nil || submitted["ClientRequestToken"] == "token-1" {
		t.Fatalf("submission not replaced: %v", submitted)
	}
	if context, _ := submitted["QueryExecutionContext"].(map[string]any); submitted["WorkGroup"] != "primary" || context["Catalog"] != "AwsDataCatalog" || context["Database"] != "example" {
		t.Fatalf("submission left AWS to pick the scope: %v", submitted)
	}
	if completions := client.awaitCompletion(t); len(completions) != 1 || completions[0].Status != "ok" || completions[0].DecisionID != 7 || len(client.closed) != 1 {
		t.Fatalf("completion or connection close missing: %+v %v", completions, client.closed)
	}

	response = serve(server, "alice", "GetQueryResults", `{"QueryExecutionId":"exec-0001"}`)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "a@example.test") || !strings.Contains(response.Body.String(), "####") {
		t.Fatalf("result page not masked: %d %s", response.Code, response.Body.String())
	}
	response = serve(server, "alice", "GetQueryExecution", `{"QueryExecutionId":"exec-0001"}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "SUCCEEDED") || strings.Contains(response.Body.String(), "a@example.test") || !strings.Contains(response.Body.String(), engine.RedactedDiagnosticMessage) {
		t.Fatalf("status not released with redacted diagnostics: %d %s", response.Code, response.Body.String())
	}
	response = serve(server, "alice", "ListQueryExecutions", `{}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "exec-0001") {
		t.Fatalf("own history not released: %d %s", response.Code, response.Body.String())
	}
	bob := &flowClient{principal: "bob", verdict: maskVerdict(), completed: make(chan struct{}, 8)}
	server.client = bob
	response = serve(server, "bob", "GetQueryResults", `{"QueryExecutionId":"exec-0001"}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("another principal read alice's execution: %d %s", response.Code, response.Body.String())
	}
	response = serve(server, "bob", "GetQueryResults", `{"QueryExecutionId":"exec-unknown"}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("unknown execution served: %d %s", response.Code, response.Body.String())
	}
	response = serve(server, "bob", "ListQueryExecutions", `{"NextToken":"page-2"}`)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "exec-0001") || !strings.Contains(response.Body.String(), `"QueryExecutionIds":[]`) || !strings.Contains(response.Body.String(), "page-2") {
		t.Fatalf("another principal saw alice's history or lost the page token: %d %s", response.Code, response.Body.String())
	}
}

func TestSubmissionScopeCannotBeWidenedOrReused(t *testing.T) {
	server, _, aws := flowServer(t, "alice", maskVerdict())
	response := serve(server, "alice", "StartQueryExecution", `{"QueryString":"SELECT * FROM users WHERE n > ?","ExecutionParameters":["1"],"ResultReuseConfiguration":{"ResultReuseByAgeConfiguration":{"Enabled":true}}}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("result reuse accepted: %d %s", response.Code, response.Body.String())
	}
	for _, op := range aws.ops {
		if op == "StartQueryExecution" {
			t.Fatal("reused submission reached AWS")
		}
	}
}

func TestReplayWithoutContextNeverBindsTheCurrentPlan(t *testing.T) {
	server, _, aws := flowServer(t, "alice", maskVerdict())
	body := `{"QueryString":"SELECT * FROM users WHERE n > ?","ExecutionParameters":["1"],"ClientRequestToken":"stable"}`
	if response := serve(server, "alice", "StartQueryExecution", body); response.Code != http.StatusOK {
		t.Fatalf("first submission failed: %d %s", response.Code, response.Body.String())
	}
	// The proxy loses its contexts; AWS still replays exec-0001 for the token, submitted long ago.
	server.target.contexts, _ = OpenContextCache(":memory:", 10)
	aws.mu.Lock()
	aws.submitted["exec-0001"] = time.Now().Add(-time.Hour)
	aws.mu.Unlock()
	if response := serve(server, "alice", "StartQueryExecution", body); response.Code != http.StatusConflict {
		t.Fatalf("replayed execution bound to a fresh plan: %d %s", response.Code, response.Body.String())
	}
	if response := serve(server, "alice", "GetQueryResults", `{"QueryExecutionId":"exec-0001"}`); response.Code != http.StatusConflict {
		t.Fatalf("results released without the original context: %d %s", response.Code, response.Body.String())
	}
}

func TestFailedSubmissionRedactsDiagnostics(t *testing.T) {
	server, _, aws := flowServer(t, "alice", maskVerdict())
	aws.failSubmission = `{"__type":"InvalidRequestException","Message":"value a@example.test is not a bigint","AthenaErrorCode":"INVALID_INPUT"}`
	response := serve(server, "alice", "StartQueryExecution", `{"QueryString":"SELECT * FROM users WHERE n > ?","ExecutionParameters":["1"]}`)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "a@example.test") || !strings.Contains(response.Body.String(), "INVALID_INPUT") {
		t.Fatalf("submission failure leaked diagnostics: %d %s", response.Code, response.Body.String())
	}
}

func TestDeniedStatementNeverReachesAWS(t *testing.T) {
	server, client, aws := flowServer(t, "alice", &pb.Verdict{Decision: pb.EnfAction_DENY, DenyReason: "no access to datasource", DecisionId: 3})
	response := serve(server, "alice", "StartQueryExecution", `{"QueryString":"SELECT secret FROM users"}`)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "no access to datasource") {
		t.Fatalf("deny not surfaced: %d %s", response.Code, response.Body.String())
	}
	for _, op := range aws.ops {
		if op == "StartQueryExecution" {
			t.Fatal("denied statement reached AWS")
		}
	}
	client.mu.Lock()
	completions := len(client.completions)
	client.mu.Unlock()
	if completions != 0 || len(client.closed) != 1 {
		t.Fatalf("denied submission reported a completion or leaked its connection: %d %v", completions, client.closed)
	}
}

func TestStableTokenReplayKeepsTheOriginalContext(t *testing.T) {
	server, client, aws := flowServer(t, "alice", maskVerdict())
	body := `{"QueryString":"SELECT * FROM users WHERE n > ?","ExecutionParameters":["1"],"ClientRequestToken":"stable"}`
	if response := serve(server, "alice", "StartQueryExecution", body); response.Code != http.StatusOK {
		t.Fatalf("first submission failed: %d %s", response.Code, response.Body.String())
	}
	if response := serve(server, "alice", "StartQueryExecution", body); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "exec-0001") {
		t.Fatalf("identical retry not accepted: %d %s", response.Code, response.Body.String())
	}
	reordered := `{"ClientRequestToken":"stable", "ExecutionParameters":["1"],"QueryString":"SELECT * FROM users WHERE n > ?"}`
	if response := serve(server, "alice", "StartQueryExecution", reordered); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "exec-0001") {
		t.Fatalf("reordered retry not accepted: %d %s", response.Code, response.Body.String())
	}
	// A later, looser decision does not replace the plan the execution was admitted under.
	client.verdict = &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 9, RewrittenSql: proto.String("SELECT email, n FROM users WHERE n > (1)"), Submission: &enginepb.Submission{Engine: &enginepb.Submission_Athena{Athena: &enginepb.AthenaSubmission{}}}}
	if response := serve(server, "alice", "StartQueryExecution", body); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "exec-0001") {
		t.Fatalf("replay under a later admission rejected: %d %s", response.Code, response.Body.String())
	}
	response := serve(server, "alice", "GetQueryResults", `{"QueryExecutionId":"exec-0001"}`)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "a@example.test") {
		t.Fatalf("original mask plan not applied after replay: %d %s", response.Code, response.Body.String())
	}
	// A different submission under the same token is a different request; its admission must not be
	// attached to the execution AWS replays.
	client.verdict = &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 11, RewrittenSql: proto.String("SELECT n FROM users"), Submission: &enginepb.Submission{Engine: &enginepb.Submission_Athena{Athena: &enginepb.AthenaSubmission{}}}}
	if response := serve(server, "alice", "StartQueryExecution", `{"QueryString":"SELECT n FROM users","ClientRequestToken":"stable"}`); response.Code != http.StatusConflict {
		t.Fatalf("replayed execution bound to a different submission: %d %s", response.Code, response.Body.String())
	}
	if len(aws.tokens) != 1 {
		t.Fatalf("upstream token not namespaced stably: %v", aws.tokens)
	}
}

func TestCatalogChangingSubmissionRefreshesTheCatalogWhenAthenaFinishes(t *testing.T) {
	verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 5, AfterStatement: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: "example", Catalog: "awsdatacatalog"}}}}}
	server, client, _ := flowServer(t, "alice", verdict)
	if response := serve(server, "alice", "StartQueryExecution", `{"QueryString":"ALTER TABLE users ADD COLUMNS (phone string)"}`); response.Code != http.StatusOK {
		t.Fatalf("submission failed: %d %s", response.Code, response.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		client.mu.Lock()
		pushes, closed := len(client.pushes), len(client.closed)
		client.mu.Unlock()
		if pushes == 2 && closed == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after-statement refetch did not run before the session closed: pushes %d closed %d", pushes, closed)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAllowedExecutionReleasesRowsUnchanged(t *testing.T) {
	server, _, _ := flowServer(t, "alice", &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 5})
	if response := serve(server, "alice", "StartQueryExecution", `{"QueryString":"SELECT email, n FROM users"}`); response.Code != http.StatusOK {
		t.Fatalf("submission failed: %d %s", response.Code, response.Body.String())
	}
	response := serve(server, "alice", "GetQueryResults", `{"QueryExecutionId":"exec-0001"}`)
	if response.Code != http.StatusOK || response.Body.String() != resultPage {
		t.Fatalf("allowed page altered: %d %s", response.Code, response.Body.String())
	}
}
