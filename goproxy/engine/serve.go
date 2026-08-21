package engine

import (
	"fmt"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// StatementResult is the protocol-neutral result of serving one authorized statement.
type StatementResult struct {
	Decision     *Decision
	Denied       bool
	Columns      []string
	Rows         [][]*string
	RowsAffected int
}

// ExecGuard optionally wraps only target-DB execution. Authorization and catalog probes run outside it.
type ExecGuard func(exec func() error) error

// FailError is a mechanical authorization failure that has no control-plane decision to report.
type FailError struct{ Message string }

func (e FailError) Error() string { return e.Message }

// ServeStatement authorizes, executes, and conditionally runs after-statement refetch commands.
func ServeStatement(
	qe *QueryEngine,
	in AuthzInput,
	ref *Refetcher,
	guard ExecGuard,
	run func(toSend string, masks []*pb.ColumnMask) (clean bool, err error),
) (dec *Decision, denied bool, err error) {
	verdict := qe.Authorize(in)
	var proceed Proceed
	switch verdict := verdict.(type) {
	case Fail:
		return nil, false, FailError{Message: verdict.Message}
	case Deny:
		return verdict.Decision, true, nil
	case Proceed:
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
		clean, runErr = run(toSend, proceed.Masks)
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
		if ref == nil {
			return dec, false, fmt.Errorf("after-statement refetcher is nil")
		}
		if err := ref.RunAll(dec.AfterStatement); err != nil {
			return dec, false, err
		}
	}
	return dec, false, nil
}
