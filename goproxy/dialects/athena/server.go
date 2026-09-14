package athena

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var errAuthorizationUnavailable = errors.New("athena: request authorization is unavailable")

type nativeServer struct {
	target  *target
	options spi.NativeServerOptions
	mu      sync.Mutex
	server  *http.Server
	stopped bool
	buffers chan struct{}
}

func (s *nativeServer) Start() error {
	if s.options.Client == nil || s.options.TLSProvider == nil {
		return ErrUnauthorized
	}
	tlsConfig, err := s.options.TLSProvider()
	if err != nil {
		return err
	}
	if tlsConfig == nil {
		return errors.New("athena: TLS is required")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.options.Port))
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		_ = listener.Close()
		return nil
	}
	s.buffers = make(chan struct{}, 8)
	s.server = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 64 << 10}
	server := s.server
	s.mu.Unlock()
	err = server.Serve(tls.NewListener(listener, tlsConfig.Clone()))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *nativeServer) Shutdown() {
	s.mu.Lock()
	s.stopped = true
	server := s.server
	s.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
}

func (s *nativeServer) Drain(ctx context.Context) {
	s.mu.Lock()
	s.stopped = true
	server := s.server
	s.mu.Unlock()
	if server != nil {
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
		}
	}
}

// nativeRequest is one authenticated Athena call as it moves through request authorization, forwarding,
// and response authorization.
type nativeRequest struct {
	server      *nativeServer
	request     *http.Request
	token       string
	clientAddr  string
	operation   string
	principal   string
	requestBody []byte
	// SQL submission state, set only for StartQueryExecution.
	session   *enforcementSession
	decision  *engine.Decision
	submitted []byte
	tokened   bool
	started   time.Time
	// Cached contexts the request phase found for the referenced executions.
	contexts  map[string]*enginepb.AthenaCachedContext
	firstPage bool
}

func (s *nativeServer) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if s.buffers != nil {
		select {
		case s.buffers <- struct{}{}:
			defer func() { <-s.buffers }()
		case <-request.Context().Done():
			return
		}
	}
	if s.options.Client == nil {
		nativeError(w, http.StatusServiceUnavailable, "athena.authorization_unavailable")
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != "/" || request.URL.RawQuery != "" {
		nativeError(w, http.StatusBadRequest, "athena.unsupported_transport")
		return
	}
	if len(request.Header.Values("Authorization")) != 1 || !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
		nativeError(w, http.StatusForbidden, "athena.authentication_required")
		return
	}
	token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		nativeError(w, http.StatusForbidden, "athena.authentication_required")
		return
	}
	operation, valid := strings.CutPrefix(request.Header.Get("X-Amz-Target"), "AmazonAthena.")
	if !valid || operation == "" {
		nativeError(w, http.StatusBadRequest, "athena.invalid_operation")
		return
	}
	clientAddr, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		nativeError(w, http.StatusBadRequest, "athena.invalid_client_address")
		return
	}
	call := &nativeRequest{server: s, request: request, token: token, clientAddr: clientAddr, operation: operation, contexts: map[string]*enginepb.AthenaCachedContext{}}
	defer call.release()
	forwarder, err := NewForwarder(ForwardOptions{
		Endpoint: s.target.endpoint, MaxBodyBytes: defaultRequestLimit, Sign: s.target.sign, Transport: s.target.transport,
		Authorize: call.authorizeRequest,
	})
	if err != nil {
		nativeError(w, http.StatusServiceUnavailable, "athena.forwarding_unavailable")
		return
	}
	response, err := forwarder.Forward(request)
	if err != nil {
		call.fail(w, err)
		return
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		call.complete("error")
		nativeError(w, http.StatusBadGateway, "athena.unsupported_response_encoding")
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, defaultResponseLimit+1))
	if err != nil || len(body) > defaultResponseLimit {
		call.complete("error")
		nativeError(w, http.StatusBadGateway, "athena.response_too_large")
		return
	}
	body, err = call.authorizeResponse(response.StatusCode, body)
	if err != nil {
		call.fail(w, err)
		return
	}
	for name, values := range response.Header {
		if stripResponseHeader(name) {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(body)
}

// authorizeRequest runs the REQUEST phase: the control plane admits the operation, then a SQL submission is
// decided and rewritten before it may leave.
func (c *nativeRequest) authorizeRequest(ctx context.Context, incoming *http.Request, envelope *Envelope) (*Envelope, error) {
	c.requestBody = envelope.Bytes()
	if err := c.lookupContexts(envelope); err != nil {
		return nil, err
	}
	descriptor := c.descriptor(enginepb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_REQUEST, nil)
	result, instructions, err := c.server.authorize(ctx, c.token, c.clientAddr, descriptor)
	if err != nil {
		return nil, err
	}
	c.principal = result.Principal
	if c.principal == "" {
		return nil, ErrUnauthorized
	}
	switch instructions.Action {
	case enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST:
		if c.operation == "StartQueryExecution" || c.operation == "GetQueryResultsStream" {
			return nil, ErrUnauthorized
		}
		return envelope, nil
	case enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_REQUIRE_SQL_ADMISSION:
		if c.operation != "StartQueryExecution" {
			return nil, ErrUnauthorized
		}
		return c.admitSubmission(envelope)
	default:
		return nil, ErrUnauthorized
	}
}

// lookupContexts attaches the cached context of every execution the body names, so the control plane can
// judge ownership; an unknown execution is simply absent and the control plane fails it closed.
func (c *nativeRequest) lookupContexts(envelope *Envelope) error {
	ids, err := referencedExecutions(envelope)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := c.attachContext(id); err != nil {
			return err
		}
	}
	c.firstPage = envelope.Field("NextToken") == nil
	return nil
}

func (c *nativeRequest) attachContext(id string) error {
	if _, found := c.contexts[id]; found {
		return nil
	}
	record, err := c.server.target.contexts.Find(c.server.options.DatasourceName, id)
	if errors.Is(err, ErrOriginalContextUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	c.contexts[id] = record
	return nil
}

func referencedExecutions(envelope *Envelope) ([]string, error) {
	var ids []string
	if raw := envelope.Field("QueryExecutionId"); raw != nil {
		var id string
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, errors.New("athena: QueryExecutionId must be a string")
		}
		ids = append(ids, id)
	}
	if raw := envelope.Field("QueryExecutionIds"); raw != nil {
		var batch []string
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, errors.New("athena: QueryExecutionIds must be strings")
		}
		ids = append(ids, batch...)
	}
	return ids, nil
}

// admitSubmission decides the actual SQL and parameters, then replaces them with the admitted submission.
func (c *nativeRequest) admitSubmission(envelope *Envelope) (*Envelope, error) {
	scope, err := readSubmission(envelope, c.server.target.config)
	if err != nil {
		return nil, err
	}
	// The control plane pinned the scope: any other workgroup or database was already a scope violation.
	identity, err := c.server.options.Client.ValidateToken(c.token, c.clientAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if identity.Principal != c.principal {
		return nil, ErrUnauthorized
	}
	session, err := c.server.target.newEnforcementSession(c.server.options.Client, c.token, identity.ConnectionID)
	if err != nil {
		return nil, err
	}
	c.session = session
	if err := session.onOpen(identity.OnOpen); err != nil {
		return nil, err
	}
	c.started = time.Now()
	verdict := session.authorize(scope.query, c.clientAddr, scope.parameters, 0)
	switch v := verdict.(type) {
	case engine.Fail:
		return nil, engine.FailError{Message: v.Message}
	case engine.Deny:
		// A DENY relays nothing: the control plane already failed its task inline, so no completion follows.
		return nil, &denied{reason: v.Decision.DenyReason}
	case engine.Proceed:
		c.decision = v.Decision
	default:
		return nil, engine.FailError{Message: fmt.Sprintf("unexpected authorization verdict %T", verdict)}
	}
	query, parameters := submittedQuery(scope.query, scope.parameters, c.decision)
	if c.decision.RewrittenSQL != nil && c.decision.AthenaSubmission == nil {
		query = *c.decision.RewrittenSQL
	}
	admitted, err := applySubmission(envelope, &enginepb.AthenaSubmission{QueryString: query, ExecutionParameters: parameters})
	if err != nil {
		return nil, err
	}
	if admitted, err = pinScope(admitted, c.server.target.config); err != nil {
		return nil, err
	}
	c.tokened = scope.token != ""
	if scope.token != "" {
		admitted, err = admitted.WithField("ClientRequestToken", namespacedToken(c.server.options.DatasourceName, c.principal, scope.token))
		if err != nil {
			return nil, err
		}
	}
	c.submitted = admitted.Bytes()
	return admitted, nil
}

// authorizeResponse runs the RESPONSE phase and applies the resulting instruction to the body.
func (c *nativeRequest) authorizeResponse(status int, body []byte) ([]byte, error) {
	if c.operation == "StartQueryExecution" {
		return c.associate(status, body)
	}
	observations, err := c.observe(status, body)
	if err != nil {
		return nil, err
	}
	for _, observation := range observations {
		if err := c.attachContext(observation.Id); err != nil {
			return nil, err
		}
	}
	descriptor := c.descriptor(enginepb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE, observations)
	result, instructions, err := c.server.authorize(c.request.Context(), c.token, c.clientAddr, descriptor)
	if err != nil {
		return nil, err
	}
	if result.Principal != c.principal {
		return nil, ErrUnauthorized
	}
	switch instructions.Action {
	case enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA:
		if c.operation == "GetQueryResults" || c.operation == "GetQueryResultsStream" {
			return nil, ErrUnauthorized
		}
		return body, nil
	case enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT:
		return c.applyContexts(status, body, instructions.Contexts)
	default:
		return nil, ErrUnauthorized
	}
}

// observe reports AWS-returned execution identities so the control plane can bind them to cached contexts.
func (c *nativeRequest) observe(status int, body []byte) ([]*enginepb.AthenaResourceObservation, error) {
	if status != http.StatusOK {
		return nil, nil
	}
	envelope, err := DecodeEnvelope(body)
	if err != nil {
		return nil, ErrResultShape
	}
	var observations []*enginepb.AthenaResourceObservation
	observe := func(raw json.RawMessage) error {
		if raw == nil {
			return nil
		}
		execution, err := DecodeEnvelope(raw)
		if err != nil {
			return ErrResultShape
		}
		if execution.Field("QueryExecutionId") == nil {
			return nil
		}
		var id string
		if err := json.Unmarshal(execution.Field("QueryExecutionId"), &id); err != nil || id == "" {
			return ErrResultShape
		}
		observation := &enginepb.AthenaResourceObservation{Source: enginepb.AthenaObservationSource_ATHENA_OBSERVATION_SOURCE_AWS_RESPONSE, Kind: "query-execution", Id: id}
		if raw := execution.Field("WorkGroup"); raw != nil {
			_ = json.Unmarshal(raw, &observation.Workgroup)
		}
		observations = append(observations, observation)
		return nil
	}
	if err := observe(envelope.Field("QueryExecution")); err != nil {
		return nil, err
	}
	if raw := envelope.Field("QueryExecutions"); raw != nil {
		var executions []json.RawMessage
		if err := json.Unmarshal(raw, &executions); err != nil {
			return nil, ErrResultShape
		}
		for _, execution := range executions {
			if err := observe(execution); err != nil {
				return nil, err
			}
		}
	}
	if raw := envelope.Field("QueryExecutionIds"); raw != nil {
		var ids []string
		if err := json.Unmarshal(raw, &ids); err != nil {
			return nil, ErrResultShape
		}
		for _, id := range ids {
			observations = append(observations, &enginepb.AthenaResourceObservation{Source: enginepb.AthenaObservationSource_ATHENA_OBSERVATION_SOURCE_AWS_RESPONSE, Kind: "query-execution", Id: id})
		}
	}
	return observations, nil
}

// associate binds the execution AWS returned to the decision it was submitted under. A stable-token retry
// AWS matched to an existing execution binds only when that execution's context is already the same one.
func (c *nativeRequest) associate(status int, body []byte) ([]byte, error) {
	if c.decision == nil || c.session == nil {
		return nil, ErrUnauthorized
	}
	if status != http.StatusOK {
		sanitize := c.decision.SanitizeDiagnostics
		c.complete("error")
		if sanitize {
			return redactDiagnostics(body)
		}
		return body, nil
	}
	id, err := executionID(body)
	if err != nil {
		c.complete("error")
		return nil, ErrResultShape
	}
	record, err := newCachedContext(id, c.principal, c.server.target.binding, c.decision, nil, requestBinding(c.submitted), time.Now())
	if err != nil {
		c.complete("error")
		return nil, err
	}
	// A stable token can replay an execution this proxy no longer has a context for (cache loss); the
	// current decision must not become that old result's plan, so only a fresh execution binds.
	if _, findErr := c.server.target.contexts.Find(c.server.options.DatasourceName, id); c.tokened && errors.Is(findErr, ErrOriginalContextUnavailable) {
		fresh, err := c.server.target.submittedAfter(c.request.Context(), id, c.started.Add(-replayTolerance))
		if err != nil || !fresh {
			c.complete("error")
			return nil, ErrOriginalContextUnavailable
		}
	}
	err = c.server.target.contexts.Associate(c.server.options.DatasourceName, record)
	if errors.Is(err, ErrContextConflict) {
		existing, findErr := c.server.target.contexts.Find(c.server.options.DatasourceName, id)
		if findErr != nil || existing.Owner != c.principal || !bytes.Equal(existing.RequestBinding, record.RequestBinding) {
			c.complete("error")
			return nil, ErrOriginalContextUnavailable
		}
		err = nil
	}
	if err != nil {
		c.complete("error")
		return nil, err
	}
	c.settle(id)
	return body, nil
}

// settle reports the accepted submission and, for a catalog-changing statement, keeps the enforcement session
// until the execution finishes so its after-statement refetches run; Athena executes asynchronously and a
// client need not poll.
func (c *nativeRequest) settle(id string) {
	decision, session := c.decision, c.session
	c.complete("ok")
	if len(decision.AfterStatement) == 0 {
		return
	}
	c.session = nil
	go func() {
		defer session.close(c.server.options.Client)
		ctx, cancel := context.WithTimeout(context.Background(), afterStatementTimeout)
		defer cancel()
		if _, err := c.server.target.awaitExecution(ctx, id); err != nil {
			return
		}
		if err := session.refetcher.RunAll(decision.AfterStatement); err != nil {
			slog.Warn("athena: catalog refresh after statement failed", "execution_id", id, "error", err)
		}
	}()
}

// applyContexts enforces the admitted instructions on a result page or releases a status response.
func (c *nativeRequest) applyContexts(status int, body []byte, refs []*enginepb.AthenaContextRef) ([]byte, error) {
	if status != http.StatusOK {
		if c.sanitizeDiagnostics(nil) {
			return redactDiagnostics(body)
		}
		return body, nil
	}
	if len(refs) == 0 && c.operation != "ListQueryExecutions" {
		return nil, ErrOriginalContextUnavailable
	}
	for _, ref := range refs {
		record, found := c.contexts[ref.GetResourceId()]
		if !found || record.ContextId != ref.GetContextId() || record.Owner != c.principal || !bytes.Equal(record.TargetBinding, c.server.target.binding) {
			return nil, ErrOriginalContextUnavailable
		}
	}
	if c.operation == "ListQueryExecutions" {
		return filterExecutionIDs(body, refs)
	}
	if c.operation != "GetQueryResults" {
		if c.sanitizeDiagnostics(refs) {
			return redactDiagnostics(body)
		}
		return body, nil
	}
	if len(refs) != 1 {
		return nil, ErrOriginalContextUnavailable
	}
	record := c.contexts[refs[0].GetResourceId()]
	verdict, err := cachedVerdict(record)
	if err != nil {
		return nil, err
	}
	envelope, err := DecodeEnvelope(body)
	if err != nil {
		return nil, ErrResultShape
	}
	if envelope.Field("ResultSet") == nil {
		return nil, ErrResultShape
	}
	if verdict.Decision == pb.EnfAction_ALLOW {
		return body, nil
	}
	masked, digest, err := MaskResultPage(body, verdict.Masks, expectedWidth(record), record.MetadataDigest, c.firstPage)
	if err != nil {
		return nil, err
	}
	if len(record.MetadataDigest) == 0 {
		bound := proto.Clone(record).(*enginepb.AthenaCachedContext)
		bound.MetadataDigest = digest
		if err := c.server.target.contexts.Rebind(c.server.options.DatasourceName, record, bound); err != nil {
			return nil, err
		}
	}
	return masked, nil
}

// filterExecutionIDs keeps only the referenced executions in a listing, in AWS order; the page token passes
// through so the client keeps paging.
func filterExecutionIDs(body []byte, refs []*enginepb.AthenaContextRef) ([]byte, error) {
	envelope, err := DecodeEnvelope(body)
	if err != nil {
		return nil, ErrResultShape
	}
	var ids []string
	if raw := envelope.Field("QueryExecutionIds"); raw != nil {
		if err := json.Unmarshal(raw, &ids); err != nil {
			return nil, ErrResultShape
		}
	}
	owned := make(map[string]bool, len(refs))
	for _, ref := range refs {
		owned[ref.GetResourceId()] = true
	}
	kept := make([]string, 0, len(refs))
	for _, id := range ids {
		if owned[id] {
			kept = append(kept, id)
		}
	}
	filtered, err := envelope.WithField("QueryExecutionIds", kept)
	if err != nil {
		return nil, ErrResultShape
	}
	return filtered.Bytes(), nil
}

// sanitizeDiagnostics reports whether any context this call touches (the referenced ones, else every one
// the request named) was admitted with diagnostic redaction; an undecodable context redacts too.
func (c *nativeRequest) sanitizeDiagnostics(refs []*enginepb.AthenaContextRef) bool {
	records := make([]*enginepb.AthenaCachedContext, 0, len(c.contexts))
	if refs == nil {
		for _, record := range c.contexts {
			records = append(records, record)
		}
	}
	for _, ref := range refs {
		if record, found := c.contexts[ref.GetResourceId()]; found {
			records = append(records, record)
		}
	}
	for _, record := range records {
		verdict, err := cachedVerdict(record)
		if err != nil || verdict.SanitizeDiagnostics {
			return true
		}
	}
	return false
}

func expectedWidth(record *enginepb.AthenaCachedContext) *int32 {
	if record.ExpectedWidth == nil {
		return nil
	}
	width := int32(*record.ExpectedWidth)
	return &width
}

func (c *nativeRequest) descriptor(phase enginepb.NativeAuthorizationPhase, observations []*enginepb.AthenaResourceObservation) *enginepb.AthenaNativeDescriptor {
	descriptor := nativeDescriptor(c.request, c.operation, c.requestBody, phase)
	descriptor.Observations = observations
	for _, record := range c.contexts {
		descriptor.CachedContexts = append(descriptor.CachedContexts, record)
	}
	return descriptor
}

// denied carries the control plane's SQL deny reason to the client as a native error.
type denied struct{ reason string }

func (d *denied) Error() string { return "athena: statement denied: " + d.reason }

func (c *nativeRequest) fail(w http.ResponseWriter, err error) {
	var deny *denied
	var fail engine.FailError
	code, status := "athena.forwarding_failed", http.StatusBadGateway
	switch {
	case errors.As(err, &deny):
		nativeStatementError(w, deny.reason)
		return
	case errors.As(err, &fail):
		c.complete("error")
		code, status = "athena.decision_failed", http.StatusServiceUnavailable
	case errors.Is(err, ErrUnauthorized):
		code, status = "athena.request_denied", http.StatusForbidden
	case errors.Is(err, errAuthorizationUnavailable):
		code, status = "athena.authorization_unavailable", http.StatusServiceUnavailable
	case errors.Is(err, ErrOriginalContextUnavailable):
		code, status = "athena.original_context_unavailable", http.StatusConflict
	case errors.Is(err, ErrBodyTooLarge):
		code, status = "athena.request_too_large", http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrResultShape), errors.Is(err, engine.ErrMaskUnbound):
		code, status = "athena.result_unenforceable", http.StatusBadGateway
	}
	if c.decision != nil && c.operation == "StartQueryExecution" {
		c.complete("error")
	}
	nativeError(w, status, code)
}

// complete reports a submission's outcome once; later calls are no-ops.
func (c *nativeRequest) complete(status string) {
	if c.decision == nil || c.session == nil {
		return
	}
	completion(c.server.options.Client, c.decision, status, c.started)
	c.decision = nil
}

func (c *nativeRequest) release() {
	if c.session != nil {
		c.session.close(c.server.options.Client)
		c.session = nil
	}
}

func (s *nativeServer) authorize(ctx context.Context, token, clientAddr string, descriptor *enginepb.AthenaNativeDescriptor) (*pb.RequestAuthorizationResult, *enginepb.AthenaNativeInstructions, error) {
	descriptor.Target = &enginepb.AthenaTarget{Region: s.target.config.region, DefaultWorkgroup: s.target.config.workgroup, DefaultCatalog: s.target.config.catalog, DefaultDatabase: s.target.config.database, Endpoint: s.target.endpoint, TargetBinding: s.target.binding}
	if proto.Size(descriptor) > 1<<20 {
		return nil, nil, ErrBodyTooLarge
	}
	body, err := proto.Marshal(descriptor)
	if err != nil {
		return nil, nil, err
	}
	result, err := s.options.Client.AuthorizeRequest(ctx, &pb.RequestAuthorization{
		Token: token, ClientAddr: clientAddr,
		Operation: &pb.RequestAuthorization_Native{Native: &pb.NativeRequestAuthorization{DescriptorVersion: 1, DescriptorPayload: body}},
	})
	if err != nil {
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound, codes.FailedPrecondition, codes.InvalidArgument:
				return nil, nil, fmt.Errorf("%w: %s", ErrUnauthorized, st.Message())
			}
		}
		return nil, nil, fmt.Errorf("%w: %v", errAuthorizationUnavailable, err)
	}
	if result != nil && !result.Allowed && result.DenyReason == "native.context_unavailable" {
		return nil, nil, ErrOriginalContextUnavailable
	}
	if result == nil || !result.Allowed || len(result.ProviderInstructions) == 0 || len(result.ProviderInstructions) > 1<<20 {
		return nil, nil, ErrUnauthorized
	}
	var instructions enginepb.AthenaNativeInstructions
	if proto.Unmarshal(result.ProviderInstructions, &instructions) != nil || instructions.Version != 1 || len(instructions.ProtoReflect().GetUnknown()) != 0 {
		return nil, nil, ErrUnauthorized
	}
	switch descriptor.Phase {
	case enginepb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_REQUEST:
		if instructions.Action != enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST &&
			instructions.Action != enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_REQUIRE_SQL_ADMISSION {
			return nil, nil, ErrUnauthorized
		}
	case enginepb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE:
		if instructions.Action != enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA &&
			instructions.Action != enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT {
			return nil, nil, ErrUnauthorized
		}
	default:
		return nil, nil, ErrUnauthorized
	}
	return result, &instructions, nil
}

func nativeDescriptor(request *http.Request, operation string, body []byte, phase enginepb.NativeAuthorizationPhase) *enginepb.AthenaNativeDescriptor {
	descriptor := &enginepb.AthenaNativeDescriptor{Service: "athena", Operation: operation, Method: request.Method, Path: request.URL.Path, RawQuery: request.URL.RawQuery, Body: body, Phase: phase}
	for name, values := range upstreamHeaders(request.Header) {
		descriptor.FunctionalHeaders = append(descriptor.FunctionalHeaders, &enginepb.NativeHeader{Name: name, Values: values})
	}
	return descriptor
}

func stripResponseHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "set-cookie":
		return true
	}
	return false
}

func nativeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": "AccessDeniedException", "Message": code})
}

// nativeStatementError renders a SQL deny the way Athena reports a rejected statement, so clients surface the
// reason instead of retrying.
func nativeStatementError(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": "InvalidRequestException", "AthenaErrorCode": "PROXY_MONSTER_DENIED", "Message": "proxy-monster denied this statement: " + reason})
}

var _ spi.WireServer = (*nativeServer)(nil)
