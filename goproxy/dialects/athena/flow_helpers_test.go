package athena

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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
	descriptor := *request.GetAthena()
	c.mu.Lock()
	c.descriptors = append(c.descriptors, &descriptor)
	c.mu.Unlock()
	if request.Token != "login-"+c.principal {
		return &pb.RequestAuthorizationResult{DenyReason: "native.not_authorized"}, nil
	}
	var body map[string]any
	_ = json.Unmarshal(descriptor.Body, &body)
	response := descriptor.Phase == enginepb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE
	instructions := &enginepb.AthenaNativeInstructions{}
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
	return &pb.RequestAuthorizationResult{Allowed: true, Principal: c.principal, Instructions: &pb.RequestAuthorizationResult_Athena{Athena: instructions}}, nil
}

func (c *flowClient) ValidateToken(token, _ string) (spi.Identity, error) {
	if token != "login-"+c.principal {
		return spi.Identity{}, ErrUnauthorized
	}
	return spi.Identity{Principal: c.principal, ConnectionID: []byte("0123456789abcdef"), OnOpen: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: "example", Catalog: "awsdatacatalog"}}}}}, nil
}

func (c *flowClient) Decide(request engine.DecideRequest) engine.DecisionOutcome {
	wire := &pb.DecisionRequest{Sql: request.SQL, SearchPath: request.Session.Namespace, CurrentCatalog: request.Session.CurrentCatalog, Session: request.Session.SessionObservation}
	c.mu.Lock()
	c.decisions = append(c.decisions, wire)
	verdict := c.verdict
	c.mu.Unlock()
	if request.Session.GetAthena().GetWorkgroup() == "" {
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
	decision := &engine.Decision{Action: engine.EnfActionName(v.GetDecision()), DecisionID: v.GetDecisionId(), DenyReason: v.GetDenyReason(), Masks: v.GetMasks(), SanitizeDiagnostics: v.GetSanitizeDiagnostics(), MaxRows: v.GetMaxRows(), MaxBytes: v.GetMaxBytes()}
	decision.AfterStatement = v.GetAfterStatement()
	decision.RewrittenSQL = v.RewrittenSql
	decision.Submission = v.Submission
	return nil, decision
}

const resultPage = `{"ResultSet":{"ResultSetMetadata":{"ColumnInfo":[{"Name":"email","Type":"varchar"},{"Name":"n","Type":"bigint"}]},"Rows":[{"Data":[{"VarCharValue":"email"},{"VarCharValue":"n"}]},{"Data":[{"VarCharValue":"a@example.test"},{"VarCharValue":"1"}]}]},"UpdateCount":0}`

type fakeAthena struct {
	resultPage string
	mu         sync.Mutex
	requests   []map[string]any
	ops        []string
	tokens     map[string]string
	submitted  map[string]time.Time
	nextID     int
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
		page := resultPage
		if f.resultPage != "" {
			page = f.resultPage
		}
		_, _ = io.WriteString(w, page)
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

func maskVerdict() *pb.Verdict {
	return &pb.Verdict{Decision: pb.EnfAction_MASK, DecisionId: 7, Masks: []*pb.ColumnMask{{Column: "email", Kind: "FIXED", Ordinal: proto.Int32(0)}}, SanitizeDiagnostics: true,
		RewrittenSql: proto.String("SELECT email, n FROM users WHERE n > (1)"), Submission: &enginepb.Submission{Engine: &enginepb.Submission_Athena{Athena: &enginepb.AthenaSubmission{}}}}
}
