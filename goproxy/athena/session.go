package athena

import (
	"context"
	"errors"
	"fmt"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// enforcementSession is one control-plane connection: the catalog commands it must answer and the decision
// it obtains for a statement. The native server opens one per submission; the editor holds one per run.
type enforcementSession struct {
	target       *target
	client       spi.ControlPlane
	token        string
	connectionID []byte
	engine       *spi.QueryEngine
	refetcher    *refetcher
}

func (t *target) newEnforcementSession(client spi.ControlPlane, token string, connectionID []byte) (*enforcementSession, error) {
	refetcher, err := t.newRefetcher(connectionID, client.PushSchemaFragment)
	if err != nil {
		return nil, err
	}
	return &enforcementSession{target: t, client: client, token: token, connectionID: append([]byte(nil), connectionID...), engine: spi.NewQueryEngine(client), refetcher: refetcher}, nil
}

func (s *enforcementSession) onOpen(commands []*pb.ProxyCommand) error {
	return s.refetcher.RunAll(commands, nil)
}

// authorize obtains the control plane's verdict for one statement in the target's fixed scope.
func (s *enforcementSession) authorize(sql, clientAddr string, parameters []string, maxRows int) spi.Verdict {
	return s.engine.Authorize(spi.AuthzInput{
		SQL: sql, Token: s.token, ClientAddr: clientAddr, ConnectionID: s.connectionID,
		ProbeSession: func() (spi.SessionObservation, error) {
			return spi.SessionObservation{
				CurrentCatalog: s.target.catalogIdentity(), Namespace: []string{s.target.config.database},
				SessionObservation: &enginepb.SessionObservation{Engine: &enginepb.SessionObservation_Athena{Athena: &enginepb.AthenaSqlContext{Workgroup: s.target.config.workgroup, ExecutionParameters: parameters, MaxRows: uint32(max(maxRows, 0))}}},
			}, nil
		},
		RunCommands: s.refetcher.RunAll,
	})
}

// submittedQuery is the text and parameters the proxy sends: the control plane's rewrite and the parameter
// list that goes with it when present, else the client's own.
func submittedQuery(sql string, parameters []string, decision *spi.Decision) (string, []string) {
	if decision != nil && decision.RewrittenSQL != nil {
		sql = *decision.RewrittenSQL
	}
	if decision != nil && decision.Submission.GetAthena() != nil {
		parameters = decision.Submission.GetAthena().GetExecutionParameters()
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
func completion(reporter spi.ControlPlane, decision *spi.Decision, status string, start time.Time) {
	relay.EmitCompletion(reporter, decision, spi.RelayStats{}, status, start)
}

var errRunCanceled = errors.New("athena: query execution was canceled")

func describeFailure(reason string) error {
	if reason == "" {
		reason = "query execution failed"
	}
	return relay.TargetDbError{Message: reason, Redacted: relay.RedactedDiagnosticMessage}
}

func withDeadline(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

func verdictError(verdict spi.Verdict) error {
	switch v := verdict.(type) {
	case spi.Fail:
		return relay.FailError{Message: v.Message}
	case spi.Deny:
		return nil
	case spi.Proceed:
		return nil
	default:
		return relay.FailError{Message: fmt.Sprintf("unexpected authorization verdict %T", verdict)}
	}
}
