package httpdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
)

// replayTolerance bounds how far before the admission an execution may have been submitted and still count
// as the one this request created (analysis time plus clock skew).
const replayTolerance = 2 * time.Minute

// afterStatementTimeout bounds how long a catalog-changing execution is awaited before its refetches are given up.
const afterStatementTimeout = 15 * time.Minute

// call is one authenticated call as it moves through request authorization, forwarding, and response
// authorization.
type call struct {
	server      *Server
	request     *http.Request
	token       string
	clientAddr  string
	operation   Operation
	principal   string
	requestBody []byte
	// SQL submission state, set only for a submission.
	authz         *spi.Authorizer
	commandRunner *relay.ProxyCommandRunner
	decision      *spi.Decision
	submitted     []byte
	tokened       bool
	started       time.Time
	// Cached contexts the request phase found for the referenced resources.
	contexts  map[string]*enginepb.HttpDbCachedContext
	firstPage bool
}

// authorizeRequest runs the REQUEST phase: the control plane admits the operation, then a SQL submission is
// decided and rewritten before it may leave.
func (c *call) authorizeRequest(ctx context.Context, _ *http.Request, body []byte) ([]byte, error) {
	c.requestBody = bytes.Clone(body)
	if err := c.lookupContexts(body); err != nil {
		return nil, err
	}
	result, instructions, err := c.server.authorize(ctx, c.token, c.clientAddr, c.describe(enginepb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_REQUEST, nil))
	if err != nil {
		return nil, err
	}
	c.principal = result.Principal
	if c.principal == "" {
		return nil, ErrUnauthorized
	}
	switch instructions.Action {
	case enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_FORWARD_REQUEST:
		if c.operation.Kind == KindSubmission || c.operation.Kind == KindRefused {
			return nil, ErrUnauthorized
		}
		return body, nil
	case enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_REQUIRE_SQL_ADMISSION:
		if c.operation.Kind != KindSubmission {
			return nil, ErrUnauthorized
		}
		return c.admitSubmission(body)
	default:
		return nil, ErrUnauthorized
	}
}

// lookupContexts attaches the cached context of every resource the request names, so the control plane can
// judge ownership; an unknown resource is simply absent and the control plane fails it closed.
func (c *call) lookupContexts(body []byte) error {
	ids, firstPage, err := c.server.Engine.References(c.request, body)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := c.attachContext(id); err != nil {
			return err
		}
	}
	c.firstPage = firstPage
	return nil
}

func (c *call) attachContext(id string) error {
	if _, found := c.contexts[id]; found {
		return nil
	}
	record, err := c.server.Contexts.Find(c.server.datasourceName(), id)
	if errors.Is(err, ErrOriginalContextUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	c.contexts[id] = record
	return nil
}

// admitSubmission decides the actual SQL and parameters, then replaces them with the admitted submission.
func (c *call) admitSubmission(body []byte) ([]byte, error) {
	engine := c.server.Engine
	submission, err := engine.ReadSubmission(body)
	if err != nil {
		return nil, err
	}
	authz, identity, err := spi.Authenticate(c.server.Client, c.token, c.clientAddr, pb.ConnectionDoor_CONNECTION_DOOR_WIRE)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if identity.Principal != c.principal {
		authz.Close()
		return nil, ErrUnauthorized
	}
	commandRunner, err := engine.NewProxyCommandRunner(authz)
	if err != nil {
		authz.Close()
		return nil, err
	}
	c.authz, c.commandRunner = authz, commandRunner
	if err := commandRunner.RunAll(identity.OnOpen, nil); err != nil {
		return nil, err
	}
	c.started = time.Now()
	verdict := engine.Authorize(authz, commandRunner, submission.Query, submission.Parameters)
	switch v := verdict.(type) {
	case spi.Fail:
		return nil, relay.FailError{Message: v.Message}
	case spi.Deny:
		// A DENY relays nothing: the control plane already failed its task inline, so no completion follows.
		return nil, &denied{reason: v.Decision.DenyReason}
	case spi.Proceed:
		c.decision = v.Decision
	default:
		return nil, relay.FailError{Message: fmt.Sprintf("unexpected authorization verdict %T", verdict)}
	}
	admitted := Submission{}
	admitted.Query, admitted.Parameters = SubmittedQuery(submission.Query, submission.Parameters, c.decision)
	if submission.Token != "" {
		admitted.Token = namespacedToken(c.server.datasourceName(), c.principal, submission.Token)
	}
	written, err := engine.WriteSubmission(body, admitted)
	if err != nil {
		return nil, err
	}
	c.tokened = submission.Token != ""
	c.submitted = bytes.Clone(written)
	return written, nil
}

// authorizeResponse runs the RESPONSE phase and applies the resulting instruction to the body.
func (c *call) authorizeResponse(status int, body []byte) ([]byte, error) {
	if c.operation.Kind == KindSubmission {
		return c.associate(status, body)
	}
	var observations []*pb.HttpDbObservation
	if status == http.StatusOK {
		var err error
		if observations, err = c.server.Engine.Observe(body); err != nil {
			return nil, err
		}
	}
	for _, observation := range observations {
		if err := c.attachContext(observation.Id); err != nil {
			return nil, err
		}
	}
	result, instructions, err := c.server.authorize(c.request.Context(), c.token, c.clientAddr, c.describe(enginepb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_RESPONSE, observations))
	if err != nil {
		return nil, err
	}
	if result.Principal != c.principal {
		return nil, ErrUnauthorized
	}
	switch instructions.Action {
	case enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_RELEASE_METADATA:
		if c.operation.Kind == KindResultPage || c.operation.Kind == KindRefused {
			return nil, ErrUnauthorized
		}
		return body, nil
	case enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_APPLY_ORIGINAL_CONTEXT:
		return c.applyContexts(status, body, instructions.Contexts)
	default:
		return nil, ErrUnauthorized
	}
}

// associate binds the resource the target returned to the decision it was submitted under. A stable-token
// retry the target matched to an existing resource binds only when that resource's context is already the
// same one.
func (c *call) associate(status int, body []byte) ([]byte, error) {
	if c.decision == nil || c.authz == nil {
		return nil, ErrUnauthorized
	}
	if status != http.StatusOK {
		sanitize := c.decision.SanitizeDiagnostics
		c.complete("error")
		if sanitize {
			return RedactDiagnostics(body, c.server.DiagnosticKeys)
		}
		return body, nil
	}
	id, err := c.server.Engine.CreatedResource(body)
	if err != nil {
		c.complete("error")
		return nil, ErrResultShape
	}
	contexts, datasource := c.server.Contexts, c.server.datasourceName()
	record, err := NewContext(id, c.principal, c.server.TargetBinding, c.decision, nil, requestBinding(c.submitted), time.Now().Add(c.server.ContextLifetime))
	if err != nil {
		c.complete("error")
		return nil, err
	}
	// A stable token can replay an execution this proxy no longer has a context for (cache loss); the
	// current decision must not become that old result's plan, so only a fresh execution binds.
	if _, findErr := contexts.Find(datasource, id); c.tokened && errors.Is(findErr, ErrOriginalContextUnavailable) {
		fresh, err := c.server.Engine.SubmittedAfter(c.request.Context(), id, c.started.Add(-replayTolerance))
		if err != nil || !fresh {
			c.complete("error")
			return nil, ErrOriginalContextUnavailable
		}
	}
	err = contexts.Associate(datasource, record)
	if errors.Is(err, ErrContextConflict) {
		existing, findErr := contexts.Find(datasource, id)
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

// settle reports the accepted submission and, for a catalog-changing statement, keeps the connection
// until the execution finishes so its after-statement refetches run; the target executes asynchronously
// and a client need not poll.
func (c *call) settle(id string) {
	decision, authz, commandRunner := c.decision, c.authz, c.commandRunner
	c.complete("ok")
	if len(decision.AfterStatement) == 0 {
		return
	}
	c.authz, c.commandRunner = nil, nil
	go func() {
		defer authz.Close()
		ctx, cancel := context.WithTimeout(context.Background(), afterStatementTimeout)
		defer cancel()
		if err := c.server.Engine.AwaitExecution(ctx, id); err != nil {
			return
		}
		if err := commandRunner.RunAll(decision.AfterStatement, nil); err != nil {
			slog.Warn(c.server.Name+": catalog refresh after statement failed", "execution_id", id, "error", err)
		}
	}()
}

// applyContexts enforces the admitted instructions on a result page or releases a status response.
func (c *call) applyContexts(status int, body []byte, refs []*enginepb.HttpDbContextRef) ([]byte, error) {
	if status != http.StatusOK {
		if c.sanitizeDiagnostics(nil) {
			return RedactDiagnostics(body, c.server.DiagnosticKeys)
		}
		return body, nil
	}
	if len(refs) == 0 && c.operation.Kind != KindListing {
		return nil, ErrOriginalContextUnavailable
	}
	for _, ref := range refs {
		record, found := c.contexts[ref.GetResourceId()]
		if !found || record.ContextId != ref.GetContextId() || record.Owner != c.principal || !bytes.Equal(record.TargetBinding, c.server.TargetBinding) {
			return nil, ErrOriginalContextUnavailable
		}
	}
	if c.operation.Kind == KindListing {
		owned := make(map[string]bool, len(refs))
		for _, ref := range refs {
			owned[ref.GetResourceId()] = true
		}
		return c.server.Engine.FilterListing(body, owned)
	}
	if c.operation.Kind != KindResultPage {
		if c.sanitizeDiagnostics(refs) {
			return RedactDiagnostics(body, c.server.DiagnosticKeys)
		}
		return body, nil
	}
	if len(refs) != 1 {
		return nil, ErrOriginalContextUnavailable
	}
	record := c.contexts[refs[0].GetResourceId()]
	verdict, err := ContextVerdict(record)
	if err != nil {
		return nil, err
	}
	masked, digest, err := c.server.Engine.MaskResult(body, verdict, expectedWidth(record), record.MetadataDigest, c.firstPage)
	if err != nil {
		return nil, err
	}
	if digest != nil && len(record.MetadataDigest) == 0 {
		bound := proto.Clone(record).(*enginepb.HttpDbCachedContext)
		bound.MetadataDigest = digest
		if err := c.server.Contexts.Rebind(c.server.datasourceName(), record, bound); err != nil {
			return nil, err
		}
	}
	return masked, nil
}

// sanitizeDiagnostics reports whether any context this call touches (the referenced ones, else every one
// the request named) was admitted with diagnostic redaction; an undecodable context redacts too.
func (c *call) sanitizeDiagnostics(refs []*enginepb.HttpDbContextRef) bool {
	records := make([]*enginepb.HttpDbCachedContext, 0, len(c.contexts))
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
		verdict, err := ContextVerdict(record)
		if err != nil || verdict.SanitizeDiagnostics {
			return true
		}
	}
	return false
}

func expectedWidth(record *enginepb.HttpDbCachedContext) *int32 {
	if record.ExpectedWidth == nil {
		return nil
	}
	width := int32(*record.ExpectedWidth)
	return &width
}

// describe is the control plane's view of this call in one phase.
func (c *call) describe(phase enginepb.HttpDbAuthorizationPhase, observations []*pb.HttpDbObservation) *pb.HttpDbRequest {
	r := c.request
	d := &pb.HttpDbRequest{
		Service: c.server.Name, Operation: c.operation.Name, Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
		Body: c.requestBody, Phase: phase, Observations: observations, TargetBinding: c.server.TargetBinding,
	}
	for name, values := range upstreamHeaders(r.Header) {
		d.FunctionalHeaders = append(d.FunctionalHeaders, &enginepb.HttpDbHeader{Name: name, Values: values})
	}
	for _, record := range c.contexts {
		d.CachedContexts = append(d.CachedContexts, record)
	}
	c.server.Engine.SetTarget(d)
	return d
}

// denied carries the control plane's SQL deny reason to the client in the engine's error format.
type denied struct{ reason string }

func (d *denied) Error() string { return "httpdb: statement denied: " + d.reason }

func (c *call) fail(w http.ResponseWriter, err error) {
	var deny *denied
	var fail relay.FailError
	code, status := "forwarding_failed", http.StatusBadGateway
	switch {
	case errors.As(err, &deny):
		c.server.Engine.WriteDenied(w, deny.reason)
		return
	case errors.As(err, &fail):
		c.complete("error")
		code, status = "decision_failed", http.StatusServiceUnavailable
	case errors.Is(err, ErrUnauthorized):
		code, status = "request_denied", http.StatusForbidden
	case errors.Is(err, errAuthorizationUnavailable):
		code, status = "authorization_unavailable", http.StatusServiceUnavailable
	case errors.Is(err, ErrOriginalContextUnavailable):
		code, status = "original_context_unavailable", http.StatusConflict
	case errors.Is(err, ErrBodyTooLarge):
		code, status = "request_too_large", http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrResultShape), errors.Is(err, relay.ErrMaskUnbound):
		code, status = "result_unenforceable", http.StatusBadGateway
	}
	if c.decision != nil && c.operation.Kind == KindSubmission {
		c.complete("error")
	}
	c.server.writeError(w, status, code)
}

// complete reports a submission's outcome once; an accepted submission is the execution boundary, rows unknown.
func (c *call) complete(status string) {
	if c.decision == nil || c.authz == nil {
		return
	}
	relay.EmitCompletion(c.server.Client, c.decision, spi.RelayStats{}, status, c.started)
	c.decision = nil
}

func (c *call) release() {
	if c.authz != nil {
		c.authz.Close()
		c.authz, c.commandRunner = nil, nil
	}
}
