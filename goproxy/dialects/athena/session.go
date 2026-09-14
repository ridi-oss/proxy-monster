package athena

import (
	"context"
	"errors"
	"fmt"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// enforcementSession is one control-plane connection: the catalog commands it must answer and the decision
// it obtains for a statement. The native server opens one per submission; the editor holds one per run.
type enforcementSession struct {
	target       *target
	client       spi.SessionClient
	token        string
	connectionID []byte
	engine       *engine.QueryEngine
	refetcher    *refetcher
}

func (t *target) newEnforcementSession(client spi.SessionClient, token string, connectionID []byte) (*enforcementSession, error) {
	refetcher, err := t.newRefetcher(connectionID, client.PushSchemaFragment)
	if err != nil {
		return nil, err
	}
	return &enforcementSession{target: t, client: client, token: token, connectionID: append([]byte(nil), connectionID...), engine: engine.NewQueryEngine(client), refetcher: refetcher}, nil
}

func (s *enforcementSession) onOpen(commands []*pb.Refetch) error {
	return s.refetcher.RunAll(commands)
}

// authorize obtains the control plane's verdict for one statement in the target's fixed scope.
func (s *enforcementSession) authorize(sql, clientAddr string, parameters []string, maxRows int) engine.Verdict {
	return s.engine.Authorize(engine.AuthzInput{
		SQL: sql, Token: s.token, ClientAddr: clientAddr, ConnectionID: s.connectionID,
		ProbeNamespace: func() (engine.NamespaceProbe, error) {
			return engine.NamespaceProbe{CurrentCatalog: s.target.catalogIdentity(), Namespace: []string{s.target.config.database}}, nil
		},
		RunCommands:                   s.refetcher.RunAll,
		AthenaContext:                 &enginepb.AthenaSqlContext{Workgroup: s.target.config.workgroup, ExecutionParameters: parameters, MaxRows: uint32(max(maxRows, 0))},
		FetchAthenaPreparedDefinition: s.target.fetchPreparedDefinition,
	})
}

// submittedQuery is the text and parameters the proxy sends: the admitted submission when the control plane
// replaced them, else the client's own.
func submittedQuery(sql string, parameters []string, decision *engine.Decision) (string, []string) {
	if decision != nil && decision.AthenaSubmission != nil {
		return decision.AthenaSubmission.GetQueryString(), decision.AthenaSubmission.GetExecutionParameters()
	}
	return sql, parameters
}

func (s *enforcementSession) close(client interface{ CloseConnection([]byte) error }) {
	if client != nil {
		_ = client.CloseConnection(s.connectionID)
	}
}

// completion reports the wire task's outcome; Athena executes asynchronously, so an accepted submission is
// the proxy's execution boundary and row volume is unknown.
func completion(reporter engine.CompletionReporter, decision *engine.Decision, status string, start time.Time) {
	engine.EmitCompletion(reporter, decision, engine.RelayStats{}, status, start)
}

var errRunCanceled = errors.New("athena: query execution was canceled")

func describeFailure(reason string) error {
	if reason == "" {
		reason = "query execution failed"
	}
	return engine.TargetDbError{Message: reason, Redacted: engine.RedactedDiagnosticMessage}
}

func withDeadline(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

func verdictError(verdict engine.Verdict) error {
	switch v := verdict.(type) {
	case engine.Fail:
		return engine.FailError{Message: v.Message}
	case engine.Deny:
		return nil
	case engine.Proceed:
		return nil
	default:
		return engine.FailError{Message: fmt.Sprintf("unexpected authorization verdict %T", verdict)}
	}
}
