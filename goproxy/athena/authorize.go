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
func (t *target) authorize(authz *spi.Authorizer, commandRunner *relay.ProxyCommandRunner, sql string, parameters []string, maxRows int) spi.Verdict {
	// The snapshot carries this request's parameters and row cap, so a cached one would be stale.
	authz.MarkNamespaceDirty()
	return authz.Authorize(spi.AuthzInput{
		SQL: sql,
		ProbeSession: func() (spi.SessionSnapshot, error) {
			return spi.SessionSnapshot{
				CurrentCatalog: t.catalogIdentity(), Namespace: []string{t.databaseIdentity()},
				SessionObservation: &enginepb.SessionObservation{Engine: &enginepb.SessionObservation_Athena{Athena: &enginepb.AthenaSqlContext{Workgroup: t.settings.workgroup, Httpdb: sqlContext(parameters, maxRows)}}},
			}, nil
		},
		Commands: commandRunner,
	})
}

func sqlContext(parameters []string, maxRows int) *enginepb.HttpDbSqlContext {
	out := &enginepb.HttpDbSqlContext{MaxRows: uint32(max(maxRows, 0))}
	for _, value := range parameters {
		out.Parameters = append(out.Parameters, &enginepb.HttpDbParameter{Value: value})
	}
	return out
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
