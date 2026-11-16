package bigquery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
)

// flowClient plays the control plane for one principal: it admits SQL through Decide and binds jobs to the
// cached contexts the proxy presents.
type flowClient struct {
	spi.ControlPlane
	mu          sync.Mutex
	principal   string
	verdict     *pb.Verdict
	decisions   []*pb.DecisionRequest
	descriptors []*pb.HttpDbRequest
	completed   chan struct{}
}

func (*flowClient) DatasourceName() string { return "bq-dev" }

// jobOf is the job id a descriptor's path names, as the control plane spells it.
func jobOf(d *pb.HttpDbRequest) string {
	parts := strings.Split(strings.TrimPrefix(d.Path, apiPrefix), "/")
	location := "us"
	if query, _ := url.ParseQuery(d.RawQuery); query.Get("location") != "" {
		location = strings.ToLower(query.Get("location"))
	}
	return parts[1] + "/" + location + "/" + parts[3]
}

func (c *flowClient) AuthorizeRequest(_ context.Context, request *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
	descriptor := request.GetHttpDb()
	c.mu.Lock()
	c.descriptors = append(c.descriptors, descriptor)
	c.mu.Unlock()
	denied := &pb.RequestAuthorizationResult{DenyReason: "native.not_authorized"}
	if request.Token != "login-"+c.principal || descriptor.GetBigquery().GetProject() != "proj-a" || descriptor.Operation == "" {
		return denied, nil
	}
	response := descriptor.Phase == enginepb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_RESPONSE
	instructions := &enginepb.HttpDbInstructions{Action: enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_FORWARD_REQUEST}
	owned := func(id string) *enginepb.HttpDbCachedContext {
		for _, ctx := range descriptor.CachedContexts {
			if ctx.ResourceId == id && ctx.Owner == c.principal && bytes.Equal(ctx.TargetBinding, descriptor.TargetBinding) {
				return ctx
			}
		}
		return nil
	}
	switch descriptor.Operation {
	case "jobs.query", "jobs.insert":
		if response {
			return denied, nil
		}
		instructions.Action = enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_REQUIRE_SQL_ADMISSION
	case "jobs.get", "jobs.getQueryResults", "jobs.cancel", "jobs.delete":
		id := jobOf(descriptor)
		ctx := owned(id)
		if ctx == nil {
			return &pb.RequestAuthorizationResult{DenyReason: "native.context_unavailable"}, nil
		}
		for _, observation := range descriptor.Observations {
			if observation.Id != id {
				return &pb.RequestAuthorizationResult{DenyReason: "native.context_unavailable"}, nil
			}
		}
		if response {
			instructions.Action = enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
			instructions.Contexts = []*enginepb.HttpDbContextRef{{ResourceId: ctx.ResourceId, ContextId: ctx.ContextId}}
		}
	case "jobs.list":
		if response {
			instructions.Action = enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
			for _, observation := range descriptor.Observations {
				if ctx := owned(observation.Id); ctx != nil {
					instructions.Contexts = append(instructions.Contexts, &enginepb.HttpDbContextRef{ResourceId: ctx.ResourceId, ContextId: ctx.ContextId})
				}
			}
		}
	default:
		if response {
			instructions.Action = enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_RELEASE_METADATA
		}
	}
	return &pb.RequestAuthorizationResult{Allowed: true, Principal: c.principal, HttpDbInstructions: instructions}, nil
}

func (c *flowClient) OpenConnection(token, _ string, _ pb.ConnectionDoor) (spi.Identity, error) {
	if token != "login-"+c.principal {
		return spi.Identity{}, httpdb.ErrUnauthorized
	}
	return spi.Identity{Principal: c.principal, ConnectionID: []byte("0123456789abcdef"), OnOpen: []*pb.ProxyCommand{{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: "sales", Catalog: "proj-a"}}}}}, nil
}

func (c *flowClient) Decide(request spi.DecideRequest) spi.DecisionOutcome {
	wire := &pb.DecisionRequest{Sql: request.SQL, SearchPath: request.Snapshot.Namespace, CurrentCatalog: request.Snapshot.CurrentCatalog, Session: request.Snapshot.SessionObservation}
	c.mu.Lock()
	c.decisions = append(c.decisions, wire)
	v := c.verdict
	c.mu.Unlock()
	if request.Snapshot.SessionObservation.GetBigquery().GetProject() == "" {
		return spi.DecisionOutcome{Err: "missing BigQuery context"}
	}
	return spi.DecisionOutcome{Decision: &spi.Decision{Action: relay.EnfActionName(v.GetDecision()), DecisionID: v.GetDecisionId(), DenyReason: v.GetDenyReason(),
		Masks: v.GetMasks(), SanitizeDiagnostics: v.GetSanitizeDiagnostics(), RewrittenSQL: v.RewrittenSql, AfterStatement: v.GetAfterStatement()}}
}

func (c *flowClient) PushSchemaFragment(*pb.SchemaFragmentPush) (uint64, error) { return 1, nil }
func (c *flowClient) ReportCompletion(spi.CompletionReport)                     { c.completed <- struct{}{} }
func (c *flowClient) CloseConnection([]byte) error                              { return nil }

type fakeInspector struct{}

func (fakeInspector) InspectSchema(string, []byte) (*pb.SchemaFragmentPush, error) {
	return &pb.SchemaFragmentPush{ContentHash: []byte("h"), Columns: []*enginepb.Column{{Catalog: "proj-a", Schema: "sales", Table: "users", Column: "email"}}}, nil
}
func (fakeInspector) RunCommand(*pb.ProxyCommand, *spi.SessionSnapshot) error {
	return relay.ErrUnknownCommand
}

const (
	schemaJSON = `{"fields":[{"name":"email","type":"STRING","mode":"NULLABLE"},{"name":"n","type":"INTEGER","mode":"NULLABLE"}]}`
	rowsJSON   = `[{"f":[{"v":"a@example.test"},{"v":"1"}]},{"f":[{"v":null},{"v":"2"}]}]`
)

type recorded struct {
	method, path, query string
	header              http.Header
	body                map[string]any
}

// fakeBigQuery answers jobs.query, jobs.insert, getQueryResults, jobs.get and jobs.list for project proj-a.
type fakeBigQuery struct {
	mu         sync.Mutex
	requests   []recorded
	requestIDs map[string]string
	created    map[string]time.Time
	jobs       []string
}

func newFakeBigQuery() *fakeBigQuery {
	return &fakeBigQuery{requestIDs: map[string]string{}, created: map[string]time.Time{}}
}

func (f *fakeBigQuery) last(method, path string) *recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.requests) - 1; i >= 0; i-- {
		if f.requests[i].method == method && f.requests[i].path == path {
			return &f.requests[i]
		}
	}
	return nil
}

func reference(job string) string {
	return `{"projectId":"proj-a","jobId":"` + job + `","location":"US"}`
}

func (f *fakeBigQuery) handle(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if r.Header.Get("Authorization") != "Bearer upstream-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/bigquery/v2/projects/proj-a")
	switch {
	case r.Method == http.MethodPost && path == "/queries":
		requestID, _ := body["requestId"].(string)
		job, replay := f.requestIDs[requestID]
		if !replay || requestID == "" {
			job = fmt.Sprintf("job_%d", len(f.jobs)+1)
			f.jobs = append(f.jobs, job)
			f.created[job] = time.Now()
			f.requestIDs[requestID] = job
		}
		_, _ = io.WriteString(w, `{"kind":"bigquery#queryResponse","schema":`+schemaJSON+`,"jobReference":`+reference(job)+`,"totalRows":"2","rows":`+rowsJSON+`,"jobComplete":true,"errors":[{"reason":"x","message":"warning near a@example.test"}]}`)
	case r.Method == http.MethodPost && path == "/jobs":
		job, _ := body["jobReference"].(map[string]any)["jobId"].(string)
		f.jobs = append(f.jobs, job)
		f.created[job] = time.Now()
		_, _ = io.WriteString(w, `{"kind":"bigquery#job","jobReference":`+reference(job)+`,"status":{"state":"RUNNING"}}`)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/queries/"):
		job := strings.TrimPrefix(path, "/queries/")
		_, _ = io.WriteString(w, `{"kind":"bigquery#getQueryResultsResponse","schema":`+schemaJSON+`,"jobReference":`+reference(job)+`,"totalRows":"2","rows":`+rowsJSON+`,"jobComplete":true}`)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/jobs/"):
		job := strings.TrimPrefix(path, "/jobs/")
		created := f.created[job]
		if created.IsZero() {
			created = time.Now()
		}
		_, _ = io.WriteString(w, `{"kind":"bigquery#job","jobReference":`+reference(job)+`,"statistics":{"creationTime":"`+strconv.FormatInt(created.UnixMilli(), 10)+`"},"status":{"state":"DONE","errorResult":{"reason":"invalidQuery","message":"bad value a@example.test"}}}`)
	case r.Method == http.MethodGet && path == "/jobs":
		entries := make([]string, 0, len(f.jobs))
		for _, job := range f.jobs {
			entries = append(entries, `{"id":"proj-a:US.`+job+`","jobReference":`+reference(job)+`,"state":"DONE","errorResult":{"message":"bad value a@example.test"}}`)
		}
		_, _ = io.WriteString(w, `{"kind":"bigquery#jobList","jobs":[`+strings.Join(entries, ",")+`],"nextPageToken":"page-2"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":{"code":404,"message":"unexpected `+r.Method+` `+r.URL.Path+`"}}`)
	}
}

func testTarget(t *testing.T, handler http.HandlerFunc) *target {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	cfg := settings{project: "proj-a", location: "US", dataset: "sales", endpoint: server.URL, contextPath: ":memory:"}
	target, err := newTarget(cfg, func(context.Context) (string, error) { return "upstream-token", nil }, "proxy@proj-a.iam.gserviceaccount.com", server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	target.inspector = fakeInspector{}
	return target
}

func flowServer(t *testing.T, principal string, verdict *pb.Verdict) (*httpdb.Server, *flowClient, *fakeBigQuery) {
	t.Helper()
	upstream := newFakeBigQuery()
	client := &flowClient{principal: principal, verdict: verdict, completed: make(chan struct{}, 8)}
	return newServer(testTarget(t, upstream.handle), spi.Listen{}, client, nil), client, upstream
}

func serve(server *httpdb.Server, principal, method, target, body string, headers ...string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://proxy.example"+target, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer login-"+principal)
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Set(headers[i], headers[i+1])
	}
	request.RemoteAddr = "192.0.2.25:1234"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func maskVerdict() *pb.Verdict {
	return &pb.Verdict{Decision: pb.EnfAction_MASK, DecisionId: 7, Masks: []*pb.ColumnMask{{Column: "email", Kind: "FIXED", Ordinal: proto.Int32(0)}}, SanitizeDiagnostics: true,
		RewrittenSql: proto.String("SELECT email, n FROM `proj-a`.sales.users WHERE n > CAST('7' AS INT64)")}
}
