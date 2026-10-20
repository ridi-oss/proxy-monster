package athena

import (
	"context"
	"errors"
	"fmt"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// authorize obtains the control plane's verdict for one statement in the target's fixed scope.
func (t *target) authorize(authz *spi.Authorizer, refetcher *refetcher, sql string, parameters []string, maxRows int) spi.Verdict {
	return authz.Authorize(spi.AuthzInput{
		SQL: sql,
		ProbeSession: func() (spi.SessionObservation, error) {
			return spi.SessionObservation{
				CurrentCatalog: t.catalogIdentity(), Namespace: []string{t.config.database},
				SessionObservation: &enginepb.SessionObservation{Engine: &enginepb.SessionObservation_Athena{Athena: &enginepb.AthenaSqlContext{Workgroup: t.config.workgroup, ExecutionParameters: parameters, MaxRows: uint32(max(maxRows, 0))}}},
			}, nil
		},
		RunCommands: refetcher.RunAll,
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
