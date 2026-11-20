package bigquery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	// maxStorageMessage covers the Storage API's largest ReadRows response, 128 MiB.
	maxStorageMessage = 160 << 20
	maxReadSessions   = 10000
	// sessionLifetime is how long the Storage API keeps a read session.
	sessionLifetime = 6 * time.Hour
)

// storageServer serves the BigQuery Storage Read API for query results only: a read session is created
// only on the destination table of the caller's own query job, in Arrow, and every batch it streams is
// masked under that job's context.
type storageServer struct {
	storagepb.UnimplementedBigQueryReadServer
	target *target
	rest   *httpdb.Server

	mu       sync.Mutex
	sessions map[string]*readSession
}

// readSession is a session this proxy created: the job whose result it reads, the context that read was
// admitted under (its owner is the session's creator), and its masks.
type readSession struct {
	job       string
	contextID string
	sanitize  bool
	masker    *arrowMasker
	expires   time.Time
}

func newStorageServer(t *target, rest *httpdb.Server) *grpc.Server {
	server := grpc.NewServer()
	storagepb.RegisterBigQueryReadServer(server, &storageServer{target: t, rest: rest, sessions: map[string]*readSession{}})
	return server
}

func (s *storageServer) CreateReadSession(ctx context.Context, request *storagepb.CreateReadSessionRequest) (*storagepb.ReadSession, error) {
	token, clientAddr, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	upstream, table, err := s.target.readSessionRequest(request)
	if err != nil {
		return nil, err
	}
	read, job, err := s.authorizeTable(ctx, token, clientAddr, table)
	if err != nil {
		return nil, storageError(err)
	}
	ordinals, kinds, err := s.target.resultColumns(ctx, table, read)
	if err != nil {
		return nil, storageError(err)
	}
	if err := checkSelectedFields(upstream.ReadSession.ReadOptions.GetSelectedFields(), ordinals); err != nil {
		return nil, err
	}
	session, err := s.target.storage.CreateReadSession(routed(ctx, "read_session.table", table), upstream)
	if err != nil {
		return nil, upstreamStatus(err, read.Verdict.SanitizeDiagnostics)
	}
	masker, err := sessionMasker(session, ordinals, kinds)
	if err != nil {
		return nil, storageError(err)
	}
	session.Schema = &storagepb.ReadSession_ArrowSchema{ArrowSchema: &storagepb.ArrowSchema{SerializedSchema: masker.schema}}
	expires := time.Now().Add(sessionLifetime)
	if session.ExpireTime != nil && session.ExpireTime.AsTime().Before(expires) {
		expires = session.ExpireTime.AsTime()
	}
	err = s.remember(session.Name, &readSession{job: job, contextID: read.Context.ContextId,
		sanitize: read.Verdict.SanitizeDiagnostics, masker: masker, expires: expires})
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (s *storageServer) ReadRows(request *storagepb.ReadRowsRequest, stream storagepb.BigQueryRead_ReadRowsServer) error {
	ctx := stream.Context()
	session, err := s.reauthorize(ctx, request.GetReadStream())
	if err != nil {
		return err
	}
	upstream, err := s.target.storage.ReadRows(routed(ctx, "read_stream", request.GetReadStream()),
		&storagepb.ReadRowsRequest{ReadStream: request.GetReadStream(), Offset: request.GetOffset()})
	if err != nil {
		return upstreamStatus(err, session.sanitize)
	}
	for {
		response, err := upstream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return upstreamStatus(err, session.sanitize)
		}
		if err := session.mask(response); err != nil {
			return storageError(err)
		}
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

func (s *storageServer) SplitReadStream(ctx context.Context, request *storagepb.SplitReadStreamRequest) (*storagepb.SplitReadStreamResponse, error) {
	session, err := s.reauthorize(ctx, request.GetName())
	if err != nil {
		return nil, err
	}
	response, err := s.target.storage.SplitReadStream(routed(ctx, "name", request.GetName()),
		&storagepb.SplitReadStreamRequest{Name: request.GetName(), Fraction: request.GetFraction()})
	if err != nil {
		return nil, upstreamStatus(err, session.sanitize)
	}
	prefix := sessionOf(request.GetName()) + "/streams/"
	for _, stream := range []*storagepb.ReadStream{response.GetPrimaryStream(), response.GetRemainderStream()} {
		if stream != nil && !strings.HasPrefix(stream.GetName(), prefix) {
			return nil, storageError(httpdb.ErrResultShape)
		}
	}
	return response, nil
}

// readSessionRequest is the request sent upstream for a client's CreateReadSession, and the table it reads.
// Only an Arrow read of whole rows, billed to the target project, is accepted.
func (t *target) readSessionRequest(request *storagepb.CreateReadSessionRequest) (*storagepb.CreateReadSessionRequest, string, error) {
	session := request.GetReadSession()
	if request.GetParent() != "projects/"+t.project || session == nil {
		return nil, "", denied("bigquery.storage_scope_violation")
	}
	if _, _, _, ok := tableName(session.GetTable()); !ok {
		return nil, "", status.Error(codes.InvalidArgument, "bigquery.invalid_table")
	}
	options := session.GetReadOptions()
	if session.GetDataFormat() != storagepb.DataFormat_ARROW || session.GetTableModifiers() != nil || options.GetRowRestriction() != "" ||
		options != nil && options.SamplePercentage != nil || options.GetAvroSerializationOptions() != nil ||
		options.GetResponseCompressionCodec() != storagepb.ReadSession_TableReadOptions_RESPONSE_COMPRESSION_CODEC_UNSPECIFIED {
		return nil, "", denied("bigquery.storage_read_denied")
	}
	readOptions := &storagepb.ReadSession_TableReadOptions{SelectedFields: options.GetSelectedFields()}
	if arrow := options.GetArrowSerializationOptions(); arrow != nil {
		readOptions.OutputFormatSerializationOptions = &storagepb.ReadSession_TableReadOptions_ArrowSerializationOptions{ArrowSerializationOptions: arrow}
	}
	return &storagepb.CreateReadSessionRequest{
		Parent: request.GetParent(), MaxStreamCount: request.GetMaxStreamCount(), PreferredMinStreamCount: request.GetPreferredMinStreamCount(),
		ReadSession: &storagepb.ReadSession{Table: session.GetTable(), DataFormat: storagepb.DataFormat_ARROW, ReadOptions: readOptions, TraceId: session.GetTraceId()},
	}, session.GetTable(), nil
}

// tableName splits "projects/<p>/datasets/<d>/tables/<t>".
func tableName(name string) (project, dataset, table string, ok bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "datasets" || parts[4] != "tables" || slices.Contains(parts, "") {
		return "", "", "", false
	}
	return parts[1], parts[3], parts[5], true
}

// authorizeTable finds the caller's query job whose result table is table, newest first, and returns the
// read the control plane admitted on it. The job's destination is confirmed upstream, so the index of
// destinations is only a hint.
func (s *storageServer) authorizeTable(ctx context.Context, token, clientAddr, table string) (httpdb.ResultRead, string, error) {
	err := httpdb.ErrOriginalContextUnavailable
	for _, job := range s.target.destinations.jobs(table) {
		var read httpdb.ResultRead
		read, err = s.authorizeJob(ctx, token, clientAddr, job)
		if err != nil {
			continue
		}
		var state *jobStatus
		if state, err = s.target.getJob(ctx, job); err != nil {
			continue
		}
		// A DML, DDL or script job names the table it wrote as its destination, which is not a result.
		if state.destination() != table || state.Statistics.Query.StatementType != "SELECT" || state.Status.State != "DONE" || state.Status.ErrorResult != nil {
			err = httpdb.ErrOriginalContextUnavailable
			continue
		}
		return read, job, nil
	}
	return httpdb.ResultRead{}, "", err
}

// authorizeJob asks the control plane whether the caller may read job's result, as jobs.getQueryResults.
func (s *storageServer) authorizeJob(ctx context.Context, token, clientAddr, job string) (httpdb.ResultRead, error) {
	parts := strings.SplitN(job, "/", 3)
	if len(parts) != 3 {
		return httpdb.ResultRead{}, httpdb.ErrOriginalContextUnavailable
	}
	path := apiPrefix + projectPath(parts[0]) + "/queries/" + url.PathEscape(parts[2]) + "?location=" + url.QueryEscape(parts[1])
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return httpdb.ResultRead{}, err
	}
	observed := &pb.HttpDbObservation{Source: pb.HttpDbObservationSource_HTTP_DB_OBSERVATION_SOURCE_UPSTREAM_RESPONSE, Kind: "job", Id: job}
	return s.rest.AuthorizeResultRead(ctx, token, clientAddr, request, observed)
}

// resultColumns reads the result table's columns, by lowercased name to ordinal, and the mask kind of each
// masked ordinal. A masked column must be a scalar.
func (t *target) resultColumns(ctx context.Context, table string, read httpdb.ResultRead) (map[string]int, map[int]string, error) {
	project, dataset, id, _ := tableName(table)
	var resource struct {
		Schema struct {
			Fields []tableField `json:"fields"`
		} `json:"schema"`
	}
	path := projectPath(project) + "/datasets/" + url.PathEscape(dataset) + "/tables/" + url.PathEscape(id)
	if err := t.call(ctx, http.MethodGet, path, nil, nil, &resource); err != nil {
		return nil, nil, err
	}
	fields := resource.Schema.Fields
	if err := httpdb.CheckWidth(expectedWidth(read), len(fields)); err != nil {
		return nil, nil, err
	}
	binding := relay.BindMasks(read.Verdict.Masks, len(fields))
	if !binding.AllBound() {
		return nil, nil, relay.ErrMaskUnbound
	}
	ordinals := make(map[string]int, len(fields))
	for i, field := range fields {
		name := strings.ToLower(field.Name)
		if _, duplicate := ordinals[name]; duplicate || name == "" {
			return nil, nil, httpdb.ErrResultShape
		}
		ordinals[name] = i
	}
	for ordinal := range binding.ByIndex {
		field := fields[ordinal]
		if field.Type == "" || field.Type == "RECORD" || field.Type == "STRUCT" || field.Mode == "REPEATED" {
			return nil, nil, httpdb.ErrResultShape
		}
	}
	return ordinals, binding.ByIndex, nil
}

func expectedWidth(read httpdb.ResultRead) *int32 {
	if read.Context.ExpectedWidth == nil {
		return nil
	}
	width := int32(*read.Context.ExpectedWidth)
	return &width
}

// checkSelectedFields allows a subset of the result's columns in any order; a nested path is refused.
func checkSelectedFields(selected []string, ordinals map[string]int) error {
	seen := map[string]bool{}
	for _, name := range selected {
		name = strings.ToLower(name)
		if _, ok := ordinals[name]; !ok || seen[name] {
			return denied("bigquery.storage_read_denied")
		}
		seen[name] = true
	}
	return nil
}

// sessionMasker maps the session's Arrow fields to the result's columns by name and plans their masks.
func sessionMasker(session *storagepb.ReadSession, ordinals map[string]int, byOrdinal map[int]string) (*arrowMasker, error) {
	if session.GetDataFormat() != storagepb.DataFormat_ARROW || session.GetArrowSchema() == nil || session.GetName() == "" {
		return nil, httpdb.ErrResultShape
	}
	for _, stream := range session.GetStreams() {
		if !strings.HasPrefix(stream.GetName(), session.GetName()+"/streams/") {
			return nil, httpdb.ErrResultShape
		}
	}
	serialized := session.GetArrowSchema().GetSerializedSchema()
	reader, err := ipc.NewReader(bytes.NewReader(serialized))
	if err != nil {
		return nil, httpdb.ErrResultShape
	}
	schema := reader.Schema()
	reader.Release()
	kinds := map[int]string{}
	for i, field := range schema.Fields() {
		ordinal, ok := ordinals[strings.ToLower(field.Name)]
		if !ok {
			return nil, httpdb.ErrResultShape
		}
		if kind, masked := byOrdinal[ordinal]; masked {
			kinds[i] = kind
		}
	}
	return newArrowMasker(serialized, kinds)
}

// mask rewrites one ReadRows response under the session's masks; an Avro response fails closed.
func (r *readSession) mask(response *storagepb.ReadRowsResponse) error {
	if response.GetAvroRows() != nil || response.GetAvroSchema() != nil {
		return httpdb.ErrResultShape
	}
	if response.GetArrowSchema() != nil {
		response.Schema = &storagepb.ReadRowsResponse_ArrowSchema{ArrowSchema: &storagepb.ArrowSchema{SerializedSchema: r.masker.schema}}
	}
	if batch := response.GetArrowRecordBatch(); batch != nil {
		masked, err := r.masker.maskBatch(batch.GetSerializedRecordBatch())
		if err != nil {
			return err
		}
		batch.SerializedRecordBatch = masked
	}
	return nil
}

func (s *storageServer) remember(name string, session *readSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, existing := range s.sessions {
		if !existing.expires.After(now) {
			delete(s.sessions, key)
		}
	}
	if _, exists := s.sessions[name]; exists {
		return storageError(httpdb.ErrResultShape)
	}
	if len(s.sessions) >= maxReadSessions {
		return status.Error(codes.ResourceExhausted, "bigquery.storage_sessions_exhausted")
	}
	s.sessions[name] = session
	return nil
}

// reauthorize admits a call on one of a session's streams for the caller who created the session, asking
// the control plane again about the job it reads.
func (s *storageServer) reauthorize(ctx context.Context, stream string) (*readSession, error) {
	token, clientAddr, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	session := s.sessions[sessionOf(stream)]
	s.mu.Unlock()
	if session == nil || !strings.HasPrefix(stream, sessionOf(stream)+"/streams/") || !session.expires.After(time.Now()) {
		return nil, storageError(httpdb.ErrOriginalContextUnavailable)
	}
	read, err := s.authorizeJob(ctx, token, clientAddr, session.job)
	if err != nil {
		return nil, storageError(err)
	}
	if read.Context.ContextId != session.contextID {
		return nil, storageError(httpdb.ErrOriginalContextUnavailable)
	}
	return session, nil
}

// sessionOf is the session a stream name belongs to: ".../sessions/s1/streams/0" is ".../sessions/s1".
func sessionOf(stream string) string {
	session, _, _ := strings.Cut(stream, "/streams/")
	return session
}

// caller is the call's proxy-monster bearer token and client address.
func caller(ctx context.Context) (string, string, error) {
	values := metadata.ValueFromIncomingContext(ctx, "authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", "", status.Error(codes.Unauthenticated, "bigquery.authentication_required")
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", "", status.Error(codes.Unauthenticated, "bigquery.authentication_required")
	}
	client, ok := peer.FromContext(ctx)
	if !ok || client.Addr == nil {
		return "", "", status.Error(codes.InvalidArgument, "bigquery.invalid_client_address")
	}
	host, _, err := net.SplitHostPort(client.Addr.String())
	if err != nil {
		return "", "", status.Error(codes.InvalidArgument, "bigquery.invalid_client_address")
	}
	return token, host, nil
}

// routed adds the routing header the Storage API needs, such as read_stream=<name>.
func routed(ctx context.Context, field, value string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("x-goog-request-params", field+"="+url.QueryEscape(value)))
}

func denied(code string) error { return status.Error(codes.PermissionDenied, code) }

// storageError reports a proxy failure with the same codes as the REST side.
func storageError(err error) error {
	if _, ok := status.FromError(err); ok {
		return err
	}
	switch {
	case errors.Is(err, httpdb.ErrUnauthorized):
		return denied("bigquery.request_denied")
	case errors.Is(err, httpdb.ErrOriginalContextUnavailable):
		return status.Error(codes.FailedPrecondition, "bigquery.original_context_unavailable")
	case errors.Is(err, httpdb.ErrResultShape), errors.Is(err, relay.ErrMaskUnbound), errors.Is(err, errBatchShape):
		return status.Error(codes.FailedPrecondition, "bigquery.result_unenforceable")
	}
	return status.Error(codes.Unavailable, "bigquery.storage_unavailable")
}

// upstreamStatus relays an upstream failure's code; its message may echo stored values.
func upstreamStatus(err error, sanitize bool) error {
	upstream, ok := status.FromError(err)
	if !ok {
		return status.Error(codes.Unavailable, "bigquery.storage_unavailable")
	}
	if sanitize {
		return status.Error(upstream.Code(), relay.RedactedDiagnosticMessage)
	}
	return status.Error(upstream.Code(), upstream.Message())
}

// destinations remembers the jobs that wrote each result table, newest last, from the job resources the
// proxy relays; a table can have several when BigQuery answers a query from its cache.
type destinations struct {
	mu     sync.Mutex
	tables map[string][]string
	order  []string
}

const (
	maxDestinationTables = 10000
	maxJobsPerTable      = 4
)

func (d *destinations) note(table, job string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tables == nil {
		d.tables = map[string][]string{}
	}
	jobs, known := d.tables[table]
	if !known {
		if len(d.order) >= maxDestinationTables {
			delete(d.tables, d.order[0])
			d.order = d.order[1:]
		}
		d.order = append(d.order, table)
	}
	jobs = append(slices.DeleteFunc(jobs, func(j string) bool { return j == job }), job)
	if len(jobs) > maxJobsPerTable {
		jobs = jobs[len(jobs)-maxJobsPerTable:]
	}
	d.tables[table] = jobs
}

// jobs lists the jobs known to have written table, newest first.
func (d *destinations) jobs(table string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	jobs := slices.Clone(d.tables[table])
	slices.Reverse(jobs)
	return jobs
}

// noteDestinations records the result table of each query job a response describes.
func (t *target) noteDestinations(body []byte) {
	if !bytes.Contains(body, []byte(`"destinationTable"`)) {
		return
	}
	var response struct {
		jobResource
		Jobs []jobResource `json:"jobs"`
	}
	if json.Unmarshal(body, &response) != nil {
		return
	}
	for _, job := range append(response.Jobs, response.jobResource) {
		if id, err := job.JobReference.id(); err == nil && job.destination() != "" {
			t.destinations.note(job.destination(), id)
		}
	}
}
