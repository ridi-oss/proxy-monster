package bigquery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	resultTable   = "projects/proj-a/datasets/_anon/tables/anon_job_1"
	storageSchema = `{"fields":[{"name":"email","type":"STRING","mode":"NULLABLE"},{"name":"n","type":"INTEGER","mode":"NULLABLE"},{"name":"phone","type":"STRING","mode":"NULLABLE"}]}`
)

// resultSchema is the result table's schema; a session over selected fields keeps this order, as BigQuery does.
var resultSchema = arrow.NewSchema([]arrow.Field{
	{Name: "email", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "n", Type: arrow.PrimitiveTypes.Int64, Nullable: true},
	{Name: "phone", Type: arrow.BinaryTypes.String, Nullable: true},
}, nil)

// resultRows are the result table's rows; stream 0 holds both, its split children 0a and 0b one each.
var resultRows = []struct {
	email string
	n     int64
	phone string
}{{"a@example.test", 1, "010-1234-5678"}, {"b@example.test", 2, "010-8765-4321"}}

// storageVerdict masks email (ordinal 0) and phone (ordinal 2).
func storageVerdict() *pb.Verdict {
	return &pb.Verdict{Decision: pb.EnfAction_MASK, DecisionId: 9, Masks: []*pb.ColumnMask{
		{Column: "email", Kind: "FIXED", Ordinal: proto.Int32(0)}, {Column: "phone", Kind: "LAST_N", Ordinal: proto.Int32(2)}}}
}

// jobResponse is a jobs.get body for a query job of statement type that wrote table.
func jobResponse(job, statement, state, table string, failed bool) string {
	project, dataset, id, _ := tableName(table)
	body := `{"kind":"bigquery#job","jobReference":` + reference(job) + `,"statistics":{"query":{"statementType":"` + statement + `"}},` +
		`"configuration":{"query":{"query":"SELECT 1","destinationTable":{"projectId":"` + project + `","datasetId":"` + dataset + `","tableId":"` + id + `"}}},`
	if failed {
		return body + `"status":{"state":"` + state + `","errorResult":{"message":"failed"}}}`
	}
	return body + `"status":{"state":"` + state + `"}}`
}

// fakeStorage is the Storage Read API over resultSchema and resultRows: one stream per session, split in two.
type fakeStorage struct {
	storagepb.UnimplementedBigQueryReadServer
	t        *testing.T
	mu       sync.Mutex
	sessions []*storagepb.CreateReadSessionRequest
	routes   []string
}

func (f *fakeStorage) route(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = append(f.routes, metadata.ValueFromIncomingContext(ctx, "x-goog-request-params")...)
}

func (f *fakeStorage) schema() *arrow.Schema {
	f.mu.Lock()
	defer f.mu.Unlock()
	selected := map[string]bool{}
	for _, name := range f.sessions[len(f.sessions)-1].GetReadSession().GetReadOptions().GetSelectedFields() {
		selected[strings.ToLower(name)] = true
	}
	if len(selected) == 0 {
		return resultSchema
	}
	fields := []arrow.Field{}
	for _, field := range resultSchema.Fields() {
		if selected[field.Name] {
			fields = append(fields, field)
		}
	}
	return arrow.NewSchema(fields, nil)
}

func (f *fakeStorage) CreateReadSession(ctx context.Context, request *storagepb.CreateReadSessionRequest) (*storagepb.ReadSession, error) {
	f.route(ctx)
	f.mu.Lock()
	f.sessions = append(f.sessions, request)
	f.mu.Unlock()
	schemaBytes, _ := serializedArrow(f.t, f.schema(), false, func(*array.RecordBuilder) {})
	f.mu.Lock()
	name := fmt.Sprintf("projects/proj-a/locations/us/sessions/s%d", len(f.sessions))
	f.mu.Unlock()
	return &storagepb.ReadSession{Name: name, Table: request.ReadSession.Table, DataFormat: storagepb.DataFormat_ARROW,
		Schema:  &storagepb.ReadSession_ArrowSchema{ArrowSchema: &storagepb.ArrowSchema{SerializedSchema: schemaBytes}},
		Streams: []*storagepb.ReadStream{{Name: name + "/streams/0"}}}, nil
}

func (f *fakeStorage) ReadRows(request *storagepb.ReadRowsRequest, stream storagepb.BigQueryRead_ReadRowsServer) error {
	f.route(stream.Context())
	rows := map[string][]int{"0": {0, 1}, "0a": {0}, "0b": {1}}[request.ReadStream[strings.LastIndex(request.ReadStream, "/")+1:]]
	if rows == nil || request.Offset > int64(len(rows)) {
		return status.Error(codes.NotFound, "no such stream")
	}
	rows = rows[request.Offset:]
	schema := f.schema()
	schemaBytes, batch := serializedArrow(f.t, schema, true, func(b *array.RecordBuilder) {
		for i, field := range schema.Fields() {
			for _, row := range rows {
				switch field.Name {
				case "email":
					b.Field(i).(*array.StringBuilder).Append(resultRows[row].email)
				case "n":
					b.Field(i).(*array.Int64Builder).Append(resultRows[row].n)
				case "phone":
					b.Field(i).(*array.StringBuilder).Append(resultRows[row].phone)
				}
			}
		}
	})
	return stream.Send(&storagepb.ReadRowsResponse{RowCount: int64(len(rows)), Schema: &storagepb.ReadRowsResponse_ArrowSchema{ArrowSchema: &storagepb.ArrowSchema{SerializedSchema: schemaBytes}},
		Rows: &storagepb.ReadRowsResponse_ArrowRecordBatch{ArrowRecordBatch: &storagepb.ArrowRecordBatch{SerializedRecordBatch: batch, RowCount: int64(len(rows))}}})
}

func (f *fakeStorage) SplitReadStream(ctx context.Context, request *storagepb.SplitReadStreamRequest) (*storagepb.SplitReadStreamResponse, error) {
	f.route(ctx)
	return &storagepb.SplitReadStreamResponse{PrimaryStream: &storagepb.ReadStream{Name: request.Name + "a"}, RemainderStream: &storagepb.ReadStream{Name: request.Name + "b"}}, nil
}

type storageFlow struct {
	target  *target
	rest    *httpdb.Server
	storage *fakeStorage
	client  storagepb.BigQueryReadClient
	mu      sync.Mutex
	jobs    map[string]string
}

// newStorageFlow serves the proxy's REST and gRPC calls over HTTPS with HTTP/2, BigQuery and the Storage API
// faked behind it. jobs.get answers from jobs; every table has storageSchema.
func newStorageFlow(t *testing.T, principal string, verdict *pb.Verdict) *storageFlow {
	t.Helper()
	flow := &storageFlow{storage: &fakeStorage{t: t}, jobs: map[string]string{}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := grpc.NewServer()
	storagepb.RegisterBigQueryReadServer(upstreamServer, flow.storage)
	go func() { _ = upstreamServer.Serve(listener) }()
	t.Cleanup(upstreamServer.Stop)
	upstream := newFakeBigQuery()
	flow.target = testTarget(t, func(w http.ResponseWriter, r *http.Request) {
		flow.mu.Lock()
		job, known := flow.jobs[strings.TrimPrefix(r.URL.Path, "/bigquery/v2/projects/proj-a/jobs/")]
		flow.mu.Unlock()
		switch {
		case known:
			_, _ = io.WriteString(w, job)
		case strings.Contains(r.URL.Path, "/tables/"):
			_, _ = io.WriteString(w, `{"kind":"bigquery#table","schema":`+storageSchema+`}`)
		default:
			upstream.handle(w, r)
		}
	})
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	flow.target.storage, flow.target.storageConn = storagepb.NewBigQueryReadClient(conn), conn
	flow.rest = newServer(flow.target, spi.Listen{}, &flowClient{principal: principal, verdict: verdict, completed: make(chan struct{}, 8)}, nil)
	proxy := httptest.NewUnstartedServer(flow.rest)
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	roots := x509.NewCertPool()
	roots.AddCert(proxy.Certificate())
	clientConn, err := grpc.NewClient(proxy.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	flow.client = storagepb.NewBigQueryReadClient(clientConn)
	return flow
}

// runJob submits job as principal, then reads it as the Python client does, which tells the proxy the table
// jobs.get reports: a finished SELECT writing its anonymous result table unless jobBody says otherwise.
func (f *storageFlow) runJob(t *testing.T, principal, job, jobBody string) {
	t.Helper()
	if jobBody == "" {
		jobBody = jobResponse(job, "SELECT", "DONE", "projects/proj-a/datasets/_anon/tables/anon_"+job, false)
	}
	insert := `{"jobReference":{"jobId":"` + job + `"},"configuration":{"query":{"query":"SELECT email, n, phone FROM users","useLegacySql":false}}}`
	if response := serve(f.rest, principal, http.MethodPost, "/bigquery/v2/projects/proj-a/jobs", insert); response.Code != http.StatusOK {
		t.Fatalf("jobs.insert: %d %s", response.Code, response.Body)
	}
	f.mu.Lock()
	f.jobs[job] = jobBody
	f.mu.Unlock()
	if response := serve(f.rest, principal, http.MethodGet, "/bigquery/v2/projects/proj-a/jobs/"+job+"?location=US&projection=full", ""); response.Code != http.StatusOK {
		t.Fatalf("jobs.get: %d %s", response.Code, response.Body)
	}
}

func as(principal string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer login-"+principal)
}

func sessionRequest(change func(*storagepb.CreateReadSessionRequest)) *storagepb.CreateReadSessionRequest {
	request := &storagepb.CreateReadSessionRequest{Parent: "projects/proj-a", MaxStreamCount: 1,
		ReadSession: &storagepb.ReadSession{Table: resultTable, DataFormat: storagepb.DataFormat_ARROW, ReadOptions: &storagepb.ReadSession_TableReadOptions{
			OutputFormatSerializationOptions: &storagepb.ReadSession_TableReadOptions_ArrowSerializationOptions{ArrowSerializationOptions: &storagepb.ArrowSerializationOptions{
				BufferCompression: storagepb.ArrowSerializationOptions_LZ4_FRAME}}}}}
	if change != nil {
		change(request)
	}
	return request
}

func readStream(ctx context.Context, client storagepb.BigQueryReadClient, name string, offset int64) (*storagepb.ReadRowsResponse, error) {
	stream, err := client.ReadRows(ctx, &storagepb.ReadRowsRequest{ReadStream: name, Offset: offset})
	if err != nil {
		return nil, err
	}
	response, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	if _, err := stream.Recv(); err != io.EOF {
		return nil, fmt.Errorf("more than one response: %v", err)
	}
	return response, nil
}

// readRows reads one stream and decodes it under the session's schema, which the stream must repeat.
func readRows(t *testing.T, client storagepb.BigQueryReadClient, session *storagepb.ReadSession, name string, offset int64) arrow.RecordBatch {
	t.Helper()
	response, err := readStream(as("alice"), client, name, offset)
	if err != nil {
		t.Fatalf("ReadRows %s: %v", name, err)
	}
	if !bytes.Equal(response.GetArrowSchema().GetSerializedSchema(), session.GetArrowSchema().GetSerializedSchema()) {
		t.Fatal("stream schema differs from the session's")
	}
	return readBatch(t, session.GetArrowSchema().GetSerializedSchema(), response.GetArrowRecordBatch().GetSerializedRecordBatch())
}

func columnText(batch arrow.RecordBatch, column int) []string {
	values := batch.Column(column).(*array.String)
	out := make([]string, values.Len())
	for i := range out {
		out[i] = values.Value(i)
	}
	return out
}

func TestStorageReadOfOwnResultIsMasked(t *testing.T) {
	flow := newStorageFlow(t, "alice", storageVerdict())
	flow.runJob(t, "alice", "job_1", "")
	session, err := flow.client.CreateReadSession(as("alice"), sessionRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	batch := readRows(t, flow.client, session, session.Streams[0].Name, 0)
	if email, n, phone := columnText(batch, 0), batch.Column(1).(*array.Int64), columnText(batch, 2); email[0] != "####" || email[1] != "####" ||
		n.Value(0) != 1 || n.Value(1) != 2 || phone[0] != "*********5678" || phone[1] != "*********4321" {
		t.Fatalf("rows: %v", batch)
	}
	if batch := readRows(t, flow.client, session, session.Streams[0].Name, 1); batch.NumRows() != 1 || batch.Column(1).(*array.Int64).Value(0) != 2 {
		t.Fatalf("offset 1: %v", batch)
	}
	split, err := flow.client.SplitReadStream(as("alice"), &storagepb.SplitReadStreamRequest{Name: session.Streams[0].Name, Fraction: 0.5})
	if err != nil {
		t.Fatal(err)
	}
	child := readRows(t, flow.client, session, split.GetRemainderStream().GetName(), 0)
	if child.NumRows() != 1 || columnText(child, 0)[0] != "####" || child.Column(1).(*array.Int64).Value(0) != 2 || columnText(child, 2)[0] != "*********4321" {
		t.Fatalf("split child: %v", child)
	}
	flow.storage.mu.Lock()
	sent, routes := flow.storage.sessions[0], flow.storage.routes
	flow.storage.mu.Unlock()
	if sent.ReadSession.Table != resultTable || sent.ReadSession.ReadOptions.GetArrowSerializationOptions().GetBufferCompression() != storagepb.ArrowSerializationOptions_LZ4_FRAME {
		t.Fatalf("upstream session request: %v", sent)
	}
	if len(routes) != 5 || !strings.HasPrefix(routes[0], "read_session.table=projects%2Fproj-a") || !strings.HasPrefix(routes[1], "read_stream=") || !strings.HasPrefix(routes[3], "name=") {
		t.Fatalf("routing headers: %v", routes)
	}
}

func TestStorageSessionWithoutReadOptionsReadsWholeRows(t *testing.T) {
	flow := newStorageFlow(t, "alice", storageVerdict())
	flow.runJob(t, "alice", "job_1", "")
	session, err := flow.client.CreateReadSession(as("alice"), sessionRequest(func(r *storagepb.CreateReadSessionRequest) { r.ReadSession.ReadOptions = nil }))
	if err != nil {
		t.Fatal(err)
	}
	if batch := readRows(t, flow.client, session, session.Streams[0].Name, 0); batch.NumCols() != 3 || columnText(batch, 0)[0] != "####" {
		t.Fatalf("rows: %v", batch)
	}
}

func TestStorageSelectedFieldsMapMasksByName(t *testing.T) {
	flow := newStorageFlow(t, "alice", storageVerdict())
	flow.runJob(t, "alice", "job_1", "")
	session, err := flow.client.CreateReadSession(as("alice"), sessionRequest(func(r *storagepb.CreateReadSessionRequest) {
		r.ReadSession.ReadOptions.SelectedFields = []string{"PHONE", "n"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	batch := readRows(t, flow.client, session, session.Streams[0].Name, 0)
	if batch.NumCols() != 2 || batch.Schema().Field(0).Name != "n" || batch.Column(0).(*array.Int64).Value(0) != 1 || columnText(batch, 1)[0] != "*********5678" {
		t.Fatalf("subset rows: %v", batch)
	}
}

func TestStorageReadsBeyondOwnResultsAreDenied(t *testing.T) {
	flow := newStorageFlow(t, "alice", storageVerdict())
	flow.runJob(t, "alice", "job_1", "")
	flow.runJob(t, "alice", "job_insert", jobResponse("job_insert", "INSERT", "DONE", "projects/proj-a/datasets/sales/tables/users", false))
	flow.runJob(t, "alice", "job_running", jobResponse("job_running", "SELECT", "RUNNING", "projects/proj-a/datasets/_anon/tables/anon_job_running", false))
	flow.runJob(t, "alice", "job_failed", jobResponse("job_failed", "SELECT", "DONE", "projects/proj-a/datasets/_anon/tables/anon_job_failed", true))
	flow.target.destinations.note("projects/proj-a/datasets/sales/tables/orders", "proj-a/us/job_1")
	table := func(name string) func(*storagepb.CreateReadSessionRequest) {
		return func(r *storagepb.CreateReadSessionRequest) { r.ReadSession.Table = name }
	}
	compression := storagepb.ReadSession_TableReadOptions_RESPONSE_COMPRESSION_CODEC_LZ4
	for name, tc := range map[string]struct {
		ctx    context.Context
		change func(*storagepb.CreateReadSessionRequest)
		code   codes.Code
	}{
		"a table no query wrote":        {as("alice"), table("projects/proj-a/datasets/sales/tables/customers"), codes.FailedPrecondition},
		"a table its job did not write": {as("alice"), table("projects/proj-a/datasets/sales/tables/orders"), codes.FailedPrecondition},
		"the table a DML job wrote":     {as("alice"), table("projects/proj-a/datasets/sales/tables/users"), codes.FailedPrecondition},
		"a running job's result":        {as("alice"), table("projects/proj-a/datasets/_anon/tables/anon_job_running"), codes.FailedPrecondition},
		"a failed job's result":         {as("alice"), table("projects/proj-a/datasets/_anon/tables/anon_job_failed"), codes.FailedPrecondition},
		"a row restriction":             {as("alice"), func(r *storagepb.CreateReadSessionRequest) { r.ReadSession.ReadOptions.RowRestriction = "n > 1" }, codes.PermissionDenied},
		"sampling":                      {as("alice"), func(r *storagepb.CreateReadSessionRequest) { r.ReadSession.ReadOptions.SamplePercentage = proto.Float64(50) }, codes.PermissionDenied},
		"response compression":          {as("alice"), func(r *storagepb.CreateReadSessionRequest) { r.ReadSession.ReadOptions.ResponseCompressionCodec = &compression }, codes.PermissionDenied},
		"avro": {as("alice"), func(r *storagepb.CreateReadSessionRequest) {
			r.ReadSession.DataFormat, r.ReadSession.ReadOptions.OutputFormatSerializationOptions = storagepb.DataFormat_AVRO, nil
		}, codes.PermissionDenied},
		"no data format": {as("alice"), func(r *storagepb.CreateReadSessionRequest) {
			r.ReadSession.DataFormat = storagepb.DataFormat_DATA_FORMAT_UNSPECIFIED
		}, codes.PermissionDenied},
		"a snapshot": {as("alice"), func(r *storagepb.CreateReadSessionRequest) {
			r.ReadSession.TableModifiers = &storagepb.ReadSession_TableModifiers{}
		}, codes.PermissionDenied},
		"another billing project": {as("alice"), func(r *storagepb.CreateReadSessionRequest) { r.Parent = "projects/proj-b" }, codes.PermissionDenied},
		"a nested field path": {as("alice"), func(r *storagepb.CreateReadSessionRequest) {
			r.ReadSession.ReadOptions.SelectedFields = []string{"email.x"}
		}, codes.PermissionDenied},
		"an unknown credential": {as("bob"), nil, codes.PermissionDenied},
		"no credential":         {context.Background(), nil, codes.Unauthenticated},
	} {
		if _, err := flow.client.CreateReadSession(tc.ctx, sessionRequest(tc.change)); status.Code(err) != tc.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(flow.storage.sessions) != 0 {
		t.Fatalf("denied sessions reached the Storage API: %v", flow.storage.sessions)
	}
}

// impostorClient is a control plane that authenticates any token as principal and grants the result read on
// whatever context the proxy presents, whoever owns it; a non-empty contextID replaces the granted context's id.
type impostorClient struct {
	*flowClient
	principal string
	contextID string
}

func (c impostorClient) AuthorizeRequest(ctx context.Context, request *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
	request = proto.Clone(request).(*pb.RequestAuthorization)
	request.Token = "login-" + c.flowClient.principal
	result, err := c.flowClient.AuthorizeRequest(ctx, request)
	if result != nil && result.Allowed {
		result.Principal = c.principal
		for _, ref := range result.GetHttpDbInstructions().GetContexts() {
			if c.contextID != "" {
				ref.ContextId = c.contextID
			}
		}
	}
	return result, err
}

func TestStorageRefusesAContextOwnedByAnother(t *testing.T) {
	flow := newStorageFlow(t, "alice", storageVerdict())
	flow.runJob(t, "alice", "job_1", "")
	session, err := flow.client.CreateReadSession(as("alice"), sessionRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	alice := flow.rest.Client.(*flowClient)
	flow.rest.Client = impostorClient{flowClient: alice, principal: "bob"}
	if _, err := flow.client.CreateReadSession(as("bob"), sessionRequest(nil)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("bob opened alice's result: %v", err)
	}
	if _, err := readStream(as("bob"), flow.client, session.Streams[0].Name, 0); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("bob read alice's stream: %v", err)
	}
	if _, err := flow.client.SplitReadStream(as("bob"), &storagepb.SplitReadStreamRequest{Name: session.Streams[0].Name}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("bob split alice's stream: %v", err)
	}
	flow.rest.Client = impostorClient{flowClient: alice, principal: "alice", contextID: "another-context"}
	if _, err := flow.client.CreateReadSession(as("alice"), sessionRequest(nil)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("result opened under a context the proxy did not present: %v", err)
	}
	flow.rest.Client = alice
	if _, err := readStream(as("alice"), flow.client, "projects/proj-a/locations/us/sessions/other/streams/0", 0); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unknown session read: %v", err)
	}
}

func TestStorageStreamsNeedTheSessionsContext(t *testing.T) {
	flow := newStorageFlow(t, "alice", storageVerdict())
	flow.runJob(t, "alice", "job_1", "")
	session, err := flow.client.CreateReadSession(as("alice"), sessionRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	contexts, err := httpdb.OpenContextCache(":memory:", contextFormat, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = contexts.Close() })
	decision := &spi.Decision{Action: relay.EnfActionName(pb.EnfAction_MASK), Masks: storageVerdict().Masks}
	record, err := httpdb.NewContext("proj-a/us/job_1", "alice", flow.rest.TargetBinding, decision, nil, nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := contexts.Associate("bq-dev", record); err != nil {
		t.Fatal(err)
	}
	flow.rest.Contexts = contexts
	if _, err := readStream(as("alice"), flow.client, session.Streams[0].Name, 0); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stream read under another context: %v", err)
	}
}

func TestResultReadIsOnlyForResultPages(t *testing.T) {
	flow := newStorageFlow(t, "alice", storageVerdict())
	flow.runJob(t, "alice", "job_1", "")
	request := httptest.NewRequest(http.MethodGet, "/bigquery/v2/projects/proj-a/jobs/job_1?location=us", nil)
	observed := &pb.HttpDbObservation{Source: pb.HttpDbObservationSource_HTTP_DB_OBSERVATION_SOURCE_UPSTREAM_RESPONSE, Kind: "job", Id: "proj-a/us/job_1"}
	if _, err := flow.rest.AuthorizeResultRead(context.Background(), "login-alice", "192.0.2.25", request, observed); !errors.Is(err, httpdb.ErrUnauthorized) {
		t.Fatalf("jobs.get admitted as a result read: %v", err)
	}
}

func TestDestinationsKeepNewestJobsPerTable(t *testing.T) {
	var d destinations
	for _, job := range []string{"j1", "j2", "j3", "j4", "j5", "j2"} {
		d.note("t", job)
	}
	if jobs := d.jobs("t"); len(jobs) != maxJobsPerTable || jobs[0] != "j2" || jobs[1] != "j5" {
		t.Fatalf("jobs: %v", jobs)
	}
	if len(d.jobs("other")) != 0 {
		t.Fatal("unknown table has jobs")
	}
}
