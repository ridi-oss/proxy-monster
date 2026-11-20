package athena

import (
	"errors"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// authorize obtains the control plane's verdict for one statement in the target's fixed scope.
func (t *target) authorize(authz *spi.Authorizer, commandRunner *relay.ProxyCommandRunner, sql string, session *enginepb.SessionObservation) spi.Verdict {
	// The snapshot carries this request's parameters and row cap, so a cached one would be stale.
	authz.MarkNamespaceDirty()
	return authz.Authorize(spi.AuthzInput{
		SQL: sql,
		ProbeSession: func() (spi.SessionSnapshot, error) {
			if session.GetAthena() == nil {
				return spi.SessionSnapshot{}, errors.New("athena: submission has no SQL context")
			}
			return spi.SessionSnapshot{CurrentCatalog: t.catalogIdentity(), Namespace: []string{t.databaseIdentity()}, SessionObservation: session}, nil
		},
		Commands: commandRunner,
	})
}

// session is the SQL context Decide sees for a statement with these parameters and row cap.
func (t *target) session(parameters []string, maxRows int) *enginepb.SessionObservation {
	sql := &enginepb.HttpDbSqlContext{MaxRows: uint32(max(maxRows, 0))}
	for _, value := range parameters {
		sql.Parameters = append(sql.Parameters, &enginepb.HttpDbParameter{Value: value})
	}
	return &enginepb.SessionObservation{Engine: &enginepb.SessionObservation_Athena{Athena: &enginepb.AthenaSqlContext{Workgroup: t.settings.workgroup, Httpdb: sql}}}
}

var errRunCanceled = errors.New("athena: query execution was canceled")

func describeFailure(reason string) error {
	if reason == "" {
		reason = "query execution failed"
	}
	return relay.TargetDbError{Message: reason, Redacted: relay.RedactedDiagnosticMessage}
}
