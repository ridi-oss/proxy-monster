package relay

import (
	"fmt"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// FailError is a mechanical authorization failure that has no control-plane decision to report.
type FailError struct{ Message string }

func (e FailError) Error() string { return e.Message }

// TargetDbError marks an error as the target DB's own ERR response for the executed statement. It is the
// ONLY error provenance the control-plane may surface as a query's error detail; every proxy/decode/decision/
// mask-binding failure stays unwrapped and generic. A run result is stored and re-gated per viewer, so it
// carries BOTH forms: [Message] is the raw target-DB text (released to a viewer who reads unmasked) and
// [Redacted] is the diagnostic-redacted symbol (released to a viewer whose context masks). See
// docs/diagnostic-redaction.md.
type TargetDbError struct {
	Message  string
	Redacted string
}

func (e TargetDbError) Error() string { return e.Message }

// ServeStatement authorizes, executes, and conditionally runs after-statement refetch commands.
func ServeStatement(
	authz *spi.Authorizer,
	in spi.AuthzInput,
	commandRunner spi.ProxyCommandRunner,
	guard spi.ExecGuard,
	run func(toSend string, masks []*pb.ColumnMask, dec *spi.Decision) (clean bool, err error),
) (dec *spi.Decision, denied bool, err error) {
	verdict := authz.Authorize(in)
	var proceed spi.Proceed
	switch verdict := verdict.(type) {
	case spi.Fail:
		return nil, false, FailError{Message: verdict.Message}
	case spi.Deny:
		return verdict.Decision, true, nil
	case spi.Proceed:
		proceed = verdict
		dec = verdict.Decision
	default:
		return nil, false, FailError{Message: fmt.Sprintf("unexpected authorization verdict %T", verdict)}
	}

	toSend := in.SQL
	if proceed.RewrittenSQL != nil {
		toSend = *proceed.RewrittenSQL
	}
	var clean bool
	exec := func() error {
		var runErr error
		clean, runErr = run(toSend, proceed.Masks, dec)
		return runErr
	}
	if guard != nil {
		err = guard(exec)
	} else {
		err = exec()
	}
	if err != nil {
		return dec, false, err
	}
	if clean && dec != nil && len(dec.AfterStatement) > 0 {
		if commandRunner == nil {
			return dec, false, fmt.Errorf("after-statement command runner is nil")
		}
		if err := commandRunner.RunAll(dec.AfterStatement, nil); err != nil {
			return dec, false, err
		}
	}
	return dec, false, nil
}
