package athena

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
)

// flowClient plays the control plane for one principal: it admits SQL through Decide, binds executions to
// the cached contexts the proxy presents, and records what it was asked.
type flowClient struct {
	spi.EnforcementClient
	mu          sync.Mutex
	principal   string
	verdict     *pb.Verdict
	decisions   []*pb.DecisionRequest
	pushes      []*pb.SchemaFragmentPush
	completions []engine.CompletionReport
	completed   chan struct{}
	closed      [][]byte
	descriptors []*enginepb.AthenaNativeDescriptor
}

// awaitCompletion waits for the asynchronous completion report and returns the reports so far.
func (c *flowClient) awaitCompletion(t *testing.T) []engine.CompletionReport {
	t.Helper()
	select {
	case <-c.completed:
	case <-time.After(5 * time.Second):
		t.Fatal("no completion report")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]engine.CompletionReport(nil), c.completions...)
}

func (c *flowClient) AuthorizeRequest(_ context.Context, request *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
	var descriptor enginepb.AthenaNativeDescriptor
	if err := proto.Unmarshal(request.GetNative().GetDescriptorPayload(), &descriptor); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.descriptors = append(c.descriptors, &descriptor)
	c.mu.Unlock()
	if request.Token != "login-"+c.principal {
		return &pb.RequestAuthorizationResult{DenyReason: "native.not_authorized"}, nil
	}
	var body map[string]any
	_ = json.Unmarshal(descriptor.Body, &body)
	response := descriptor.Phase == enginepb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE
	instructions := &enginepb.AthenaNativeInstructions{Version: 1}
	switch descriptor.Operation {
	case "StartQueryExecution":
		if response {
			return &pb.RequestAuthorizationResult{DenyReason: "native.not_authorized"}, nil
		}
		instructions.Action = enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_REQUIRE_SQL_ADMISSION
	case "GetQueryResults", "GetQueryExecution", "StopQueryExecution":
		id, _ := body["QueryExecutionId"].(string)
		var owned *enginepb.AthenaCachedContext
		for _, ctx := range descriptor.CachedContexts {
			if ctx.ResourceId == id && ctx.Owner == c.principal && string(ctx.TargetBinding) == string(descriptor.Target.TargetBinding) {
				owned = ctx
			}
		}
		if owned == nil {
			return &pb.RequestAuthorizationResult{DenyReason: "native.context_unavailable"}, nil
		}
		for _, observation := range descriptor.Observations {
			if observation.Kind == "query-execution" && observation.Id != id {
				return &pb.RequestAuthorizationResult{DenyReason: "native.context_unavailable"}, nil
			}
		}
		if response {
			instructions.Action = enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
			instructions.Contexts = []*enginepb.AthenaContextRef{{ResourceId: owned.ResourceId, ContextId: owned.ContextId}}
		} else {
			instructions.Action = enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
		}
	case "ListQueryExecutions":
		instructions.Action = enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
		if response {
			instructions.Action = enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
			for _, ctx := range descriptor.CachedContexts {
				if ctx.Owner == c.principal {
					instructions.Contexts = append(instructions.Contexts, &enginepb.AthenaContextRef{ResourceId: ctx.ResourceId, ContextId: ctx.ContextId})
				}
			}
		}
	default:
		instructions.Action = enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
		if response {
			instructions.Action = enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA
		}
	}
	payload, err := proto.Marshal(instructions)
	if err != nil {
		return nil, err
	}
	return &pb.RequestAuthorizationResult{Allowed: true, Principal: c.principal, ProviderInstructions: payload}, nil
}

func (c *flowClient) ValidateToken(token, _ string) (spi.Identity, error) {
	if token != "login-"+c.principal {
		return spi.Identity{}, ErrUnauthorized
	}
	return spi.Identity{Principal: c.principal, ConnectionID: []byte("0123456789abcdef"), OnOpen: []*pb.Refetch{{Schema: "example", Catalog: proto.String("awsdatacatalog")}}}, nil
}

func (c *flowClient) Decide(request engine.DecideRequest) engine.DecisionOutcome {
	wire := &pb.DecisionRequest{Sql: request.SQL, SearchPath: request.Namespace, CurrentCatalog: proto.String(request.CurrentCatalog), AthenaContext: request.AthenaContext}
	c.mu.Lock()
	c.decisions = append(c.decisions, wire)
	verdict := c.verdict
	c.mu.Unlock()
	if request.AthenaContext == nil || request.AthenaContext.Workgroup == "" {
		return engine.DecisionOutcome{Err: "missing athena context"}
	}
	_, decision := decisionFromWireForTest(verdict)
	return engine.DecisionOutcome{Decision: decision}
}

func (c *flowClient) PushSchemaFragment(push *pb.SchemaFragmentPush) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pushes = append(c.pushes, push)
	return uint64(len(c.pushes)), nil
}

func (c *flowClient) ReportCompletion(report engine.CompletionReport) {
	c.mu.Lock()
	c.completions = append(c.completions, report)
	c.mu.Unlock()
	c.completed <- struct{}{}
}

func (c *flowClient) CloseConnection(id []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = append(c.closed, id)
	return nil
}

// decisionFromWireForTest mirrors the cp client's verdict mapping for the fields this package consumes.
func decisionFromWireForTest(v *pb.Verdict) (any, *engine.Decision) {
	decision := &engine.Decision{Action: engine.EnfActionName(v.GetDecision()), DecisionID: v.GetDecisionId(), DenyReason: v.GetDenyReason(), Masks: v.GetMasks(), SanitizeDiagnostics: v.GetSanitizeDiagnostics()}
	for _, command := range v.GetAfterStatement() {
		if refetch := command.GetRefetch(); refetch != nil {
			decision.AfterStatement = append(decision.AfterStatement, refetch)
		}
	}
	if v.AthenaSubmission != nil {
		decision.AthenaSubmission = v.AthenaSubmission
		query := v.AthenaSubmission.QueryString
		decision.RewrittenSQL = &query
	} else if v.RewrittenSql != nil {
		decision.RewrittenSQL = v.RewrittenSql
	}
	return nil, decision
}

const resultPage = `{"ResultSet":{"ResultSetMetadata":{"ColumnInfo":[{"Name":"email","Type":"varchar"},{"Name":"n","Type":"bigint"}]},"Rows":[{"Data":[{"VarCharValue":"email"},{"VarCharValue":"n"}]},{"Data":[{"VarCharValue":"a@example.test"},{"VarCharValue":"1"}]}]},"UpdateCount":0}`

type fakeAthena struct {
	mu        sync.Mutex
	requests  []map[string]any
	ops       []string
	tokens    map[string]string
	submitted map[string]time.Time
	nextID    int
	// failSubmission, when set, is the error body StartQueryExecution returns.
	failSubmission string
}

func (f *fakeAthena) lastRequest(operation string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.ops) - 1; i >= 0; i-- {
		if f.ops[i] == operation {
			return f.requests[i]
		}
	}
	return nil
}

func newFakeAthena() *fakeAthena {
	return &fakeAthena{tokens: map[string]string{}, submitted: map[string]time.Time{}}
}

func (f *fakeAthena) handle(w http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	var input map[string]any
	_ = json.Unmarshal(body, &input)
	operation := strings.TrimPrefix(request.Header.Get("X-Amz-Target"), "AmazonAthena.")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, input)
	f.ops = append(f.ops, operation)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch operation {
	case "StartQueryExecution":
		if f.failSubmission != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, f.failSubmission)
			return
		}
		token, _ := input["ClientRequestToken"].(string)
		if id, replay := f.tokens[token]; replay && token != "" {
			_, _ = io.WriteString(w, `{"QueryExecutionId":"`+id+`"}`)
			return
		}
		f.nextID++
		id := "exec-" + strings.Repeat("0", 3) + string(rune('0'+f.nextID))
		if token != "" {
			f.tokens[token] = id
		}
		f.submitted[id] = time.Now()
		_, _ = io.WriteString(w, `{"QueryExecutionId":"`+id+`"}`)
	case "GetQueryResults":
		_, _ = io.WriteString(w, resultPage)
	case "GetQueryExecution":
		id, _ := input["QueryExecutionId"].(string)
		submitted := f.submitted[id]
		if submitted.IsZero() {
			submitted = time.Now()
		}
		_, _ = io.WriteString(w, `{"QueryExecution":{"QueryExecutionId":"`+id+`","StatementType":"DML","Status":{"State":"SUCCEEDED","SubmissionDateTime":`+strconv.FormatInt(submitted.Unix(), 10)+`,"StateChangeReason":"row a@example.test failed"},"WorkGroup":"primary"}}`)
	case "ListQueryExecutions":
		ids := make([]string, 0, f.nextID)
		for i := 1; i <= f.nextID; i++ {
			ids = append(ids, "exec-000"+strconv.Itoa(i))
		}
		encoded, _ := json.Marshal(ids)
		next, _ := input["NextToken"].(string)
		nextJSON, _ := json.Marshal(next)
		_, _ = io.WriteString(w, `{"QueryExecutionIds":`+string(encoded)+`,"NextToken":`+string(nextJSON)+`}`)
	case "ListTableMetadata":
		_, _ = io.WriteString(w, `{"TableMetadataList":[{"Name":"users","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]}]}`)
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"__type":"InvalidRequestException","Message":"unexpected `+operation+`"}`)
	}
}

func flowServer(t *testing.T, principal string, verdict *pb.Verdict) (*nativeServer, *flowClient, *fakeAthena) {
	t.Helper()
	aws := newFakeAthena()
	target := testTarget(t, aws.handle)
	client := &flowClient{principal: principal, verdict: verdict, completed: make(chan struct{}, 8)}
	server := &nativeServer{target: target, options: spi.NativeServerOptions{DatasourceName: "athena-dev", Client: client}}
	return server, client, aws
}

func serve(server *nativeServer, principal, operation, body string) *httptest.ResponseRecorder {
	request := nativeTestRequest(operation, body)
	request.Header.Set("Authorization", "Bearer login-"+principal)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func maskVerdict() *pb.Verdict {
	return &pb.Verdict{Decision: pb.EnfAction_MASK, DecisionId: 7, Masks: []*pb.ColumnMask{{Column: "email", Kind: "FIXED", Ordinal: proto.Int32(0)}}, SanitizeDiagnostics: true,
		AthenaSubmission: &enginepb.AthenaSubmission{QueryString: "SELECT email, n FROM users WHERE n > (1)"}}
}

func TestSubmissionIsDecidedRewrittenAndMaskedOnRead(t *testing.T) {
	server, client, aws := flowServer(t, "alice", maskVerdict())
	response := serve(server, "alice", "StartQueryExecution", `{"QueryString":"SELECT * FROM users WHERE n > ?","ExecutionParameters":["1"],"ClientRequestToken":"token-1","WorkGroup":"primary"}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "exec-0001") {
		t.Fatalf("submission failed: %d %s", response.Code, response.Body.String())
	}
	if len(client.decisions) != 1 || client.decisions[0].AthenaContext.Workgroup != "primary" || client.decisions[0].AthenaContext.MaxRows != 0 || len(client.decisions[0].AthenaContext.ExecutionParameters) != 1 || client.decisions[0].CurrentCatalog == nil || *client.decisions[0].CurrentCatalog != "awsdatacatalog" {
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
	server.options.Client = bob
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
	client.verdict = &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 9, AthenaSubmission: &enginepb.AthenaSubmission{QueryString: "SELECT email, n FROM users WHERE n > (1)"}}
	if response := serve(server, "alice", "StartQueryExecution", body); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "exec-0001") {
		t.Fatalf("replay under a later admission rejected: %d %s", response.Code, response.Body.String())
	}
	response := serve(server, "alice", "GetQueryResults", `{"QueryExecutionId":"exec-0001"}`)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "a@example.test") {
		t.Fatalf("original mask plan not applied after replay: %d %s", response.Code, response.Body.String())
	}
	// A different submission under the same token is a different request; its admission must not be
	// attached to the execution AWS replays.
	client.verdict = &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 11, AthenaSubmission: &enginepb.AthenaSubmission{QueryString: "SELECT n FROM users"}}
	if response := serve(server, "alice", "StartQueryExecution", `{"QueryString":"SELECT n FROM users","ClientRequestToken":"stable"}`); response.Code != http.StatusConflict {
		t.Fatalf("replayed execution bound to a different submission: %d %s", response.Code, response.Body.String())
	}
	if len(aws.tokens) != 1 {
		t.Fatalf("upstream token not namespaced stably: %v", aws.tokens)
	}
}

func TestCatalogChangingSubmissionRefreshesTheCatalogWhenAthenaFinishes(t *testing.T) {
	verdict := &pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 5, AfterStatement: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: "example", Catalog: proto.String("awsdatacatalog")}}}}}
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
