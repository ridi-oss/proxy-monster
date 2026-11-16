package httpdb

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/listen"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	ErrUnsupportedTransport     = errors.New("httpdb: unsupported transport")
	errAuthorizationUnavailable = errors.New("httpdb: request authorization is unavailable")
)

// Kind is what an operation does, which decides the instructions it may run under.
type Kind int

const (
	// KindRefused is refused whatever the control plane answers; an unclassified operation is refused.
	KindRefused Kind = iota
	// KindMetadata is forwarded and released under the control plane's instructions.
	KindMetadata
	// KindSubmission carries SQL: it is forwarded only after Decide admits it.
	KindSubmission
	// KindResultPage is never released as metadata: its rows are masked under the stored context.
	KindResultPage
	// KindListing releases only the resources the caller owns.
	KindListing
)

type Operation struct {
	Name string
	Kind Kind
	// InlineResult marks a submission whose accepted response carries its first result page.
	InlineResult bool
}

// Submission is the SQL a submission body carries, and the client's idempotency token.
type Submission struct {
	Query      string
	Parameters []string
	Token      string
	// Session is the SQL context the body carries for Decide, for an engine that reads one from it.
	Session *enginepb.SessionObservation
}

// Engine is one HTTP-API target database: its wire format, its control-plane target, and its SQL path.
type Engine interface {
	// Operation names a call; ErrUnsupportedTransport refuses it before authentication.
	Operation(*http.Request) (Operation, error)
	// References lists the resources a request names, and whether it asks for a result's first page.
	References(r *http.Request, body []byte) (ids []string, firstPage bool, err error)
	// SetTarget sets the request's engine target arm.
	SetTarget(*pb.HttpDbRequest)
	ReadSubmission(body []byte) (Submission, error)
	// WriteSubmission returns body carrying the admitted SQL and, when non-empty, the upstream token.
	WriteSubmission(body []byte, admitted Submission) ([]byte, error)
	// CreatedResource is the id of the resource an accepted submission's response names.
	CreatedResource(body []byte) (string, error)
	Observe(body []byte) ([]*pb.HttpDbObservation, error)
	FilterListing(body []byte, owned map[string]bool) ([]byte, error)
	// MaskResult checks a result page's shape and masks it; digest is nil when the verdict masks nothing.
	MaskResult(body []byte, verdict *pb.Verdict, expectedWidth *int32, metadataDigest []byte, firstPage bool) (masked, digest []byte, err error)
	Decider
	// SubmittedAfter reports whether the target records the resource as submitted at or after instant.
	SubmittedAfter(ctx context.Context, id string, instant time.Time) (bool, error)
	// AwaitExecution returns once the resource's execution is terminal.
	AwaitExecution(ctx context.Context, id string) error
	WriteError(w http.ResponseWriter, status int, code string)
	WriteDenied(w http.ResponseWriter, reason string)
}

// Server serves one HTTP-API target over TLS. Every call authenticates the bearer credential as a
// proxy-monster token, asks the control plane (AuthorizeRequest) what to do with the operation in the
// request phase and again in the response phase, submits SQL through Decide, and applies the cached
// enforcement context to result and status reads.
type Server struct {
	Engine Engine
	// Name is the descriptor's service and namespaces error codes, as in "athena.request_denied".
	Name            string
	Listen          spi.Listen
	Client          spi.ControlPlane
	TLSProvider     func() (*tls.Config, error)
	Contexts        *EnforcementContextCache
	TargetBinding   []byte
	ContextLifetime time.Duration
	// Forward is where calls go; its Authorize is set per call.
	Forward        ForwardOptions
	ResponseLimit  int64
	DiagnosticKeys []string

	mu      sync.Mutex
	server  *http.Server
	stopped bool
	buffers chan struct{}
}

func (s *Server) Start() error {
	if s.Client == nil || s.TLSProvider == nil {
		return ErrUnauthorized
	}
	tlsConfig, err := s.TLSProvider()
	if err != nil {
		return err
	}
	if tlsConfig == nil {
		return errors.New("httpdb: TLS is required")
	}
	listener, err := listen.Open(s.Listen)
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

func (s *Server) Shutdown() {
	s.mu.Lock()
	s.stopped = true
	server := s.server
	s.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
}

func (s *Server) Drain(ctx context.Context) {
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

func (s *Server) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if s.buffers != nil {
		select {
		case s.buffers <- struct{}{}:
			defer func() { <-s.buffers }()
		case <-request.Context().Done():
			return
		}
	}
	if s.Client == nil {
		s.writeError(w, http.StatusServiceUnavailable, "authorization_unavailable")
		return
	}
	operation, operationErr := s.Engine.Operation(request)
	if errors.Is(operationErr, ErrUnsupportedTransport) {
		s.writeError(w, http.StatusBadRequest, "unsupported_transport")
		return
	}
	if len(request.Header.Values("Authorization")) != 1 || !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
		s.writeError(w, http.StatusForbidden, "authentication_required")
		return
	}
	token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		s.writeError(w, http.StatusForbidden, "authentication_required")
		return
	}
	if operationErr != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_operation")
		return
	}
	clientAddr, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_client_address")
		return
	}
	c := &call{server: s, request: request, token: token, clientAddr: clientAddr, operation: operation, contexts: map[string]*enginepb.HttpDbCachedContext{}}
	defer c.release()
	options := s.Forward
	options.Authorize = c.authorizeRequest
	forwarder, err := NewForwarder(options)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "forwarding_unavailable")
		return
	}
	response, err := forwarder.Forward(request)
	if err != nil {
		c.fail(w, err)
		return
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		c.complete("error")
		s.writeError(w, http.StatusBadGateway, "unsupported_response_encoding")
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, s.ResponseLimit+1))
	if err != nil || int64(len(body)) > s.ResponseLimit {
		c.complete("error")
		s.writeError(w, http.StatusBadGateway, "response_too_large")
		return
	}
	body, err = c.authorizeResponse(response.StatusCode, body)
	if err != nil {
		c.fail(w, err)
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

func (s *Server) writeError(w http.ResponseWriter, status int, code string) {
	s.Engine.WriteError(w, status, s.Name+"."+code)
}

func (s *Server) authorize(ctx context.Context, token, clientAddr string, descriptor *pb.HttpDbRequest) (*pb.RequestAuthorizationResult, *enginepb.HttpDbInstructions, error) {
	if proto.Size(descriptor) > 1<<20 {
		return nil, nil, ErrBodyTooLarge
	}
	request := &pb.RequestAuthorization{Token: token, ClientAddr: clientAddr, Operation: &pb.RequestAuthorization_HttpDb{HttpDb: descriptor}}
	result, err := s.Client.AuthorizeRequest(ctx, request)
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
	if result == nil || !result.Allowed || result.GetHttpDbInstructions() == nil {
		return nil, nil, ErrUnauthorized
	}
	instructions := *result.GetHttpDbInstructions()
	switch descriptor.Phase {
	case enginepb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_REQUEST:
		if instructions.Action != enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_FORWARD_REQUEST &&
			instructions.Action != enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_REQUIRE_SQL_ADMISSION {
			return nil, nil, ErrUnauthorized
		}
	case enginepb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_RESPONSE:
		if instructions.Action != enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_RELEASE_METADATA &&
			instructions.Action != enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_APPLY_ORIGINAL_CONTEXT {
			return nil, nil, ErrUnauthorized
		}
	default:
		return nil, nil, ErrUnauthorized
	}
	return result, &instructions, nil
}

func stripResponseHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "set-cookie":
		return true
	}
	return false
}

var _ spi.WireServer = (*Server)(nil)

// datasourceName keys the enforcement-context cache; the control-plane client is bound to exactly one
// datasource, so the name is read from it rather than configured twice.
func (s *Server) datasourceName() string {
	if named, ok := s.Client.(interface{ DatasourceName() string }); ok {
		return named.DatasourceName()
	}
	return ""
}
