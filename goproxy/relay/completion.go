package relay

import (
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// Completion statuses reported after a statement's result is relayed. A clean result is StatusOK; a
// target-DB error or a relay/transport fault carrying only the rows relayed before it is StatusError.
// StatusCanceled is accepted by the control plane and reserved for a future explicit-cancel signal — the
// blocking wire relay has no distinct cancel event today, so a canceled query surfaces as StatusError.
const (
	StatusOK       = "ok"
	StatusError    = "error"
	StatusCanceled = "canceled"
)

// RowBudget bounds an in-memory result collection (the run channel's paged reads) the way [RelayStats]
// plus a [Decision] bounds a wire relay. A zero MaxRows/MaxBytes is uncapped on that dimension.
type RowBudget struct {
	MaxRows  int
	MaxBytes int64
	bytes    int64
	// Overflowed is set once a row was left out; ByteCapped distinguishes the byte bound from the row one,
	// since only the byte bound is the verdict's alone (a row bound may be the caller's own page size).
	Overflowed, ByteCapped bool
}

// Admit reports whether a row of [rowBytes] fits, given [collected] rows already taken, and charges it to
// the budget when it does. Overflow LATCHES: once a row is refused every later one is too, even a narrow
// one that would still fit, so the collected rows are the result's contiguous prefix rather than whichever
// of its rows happened to be small.
func (b *RowBudget) Admit(collected int, rowBytes int64) bool {
	switch {
	case b.Overflowed:
	case b.MaxRows > 0 && collected >= b.MaxRows:
		b.Overflowed = true
	case b.MaxBytes > 0 && rowBytes > b.MaxBytes-b.bytes:
		b.Overflowed, b.ByteCapped = true, true
	default:
		b.bytes += rowBytes
		return true
	}
	return false
}

// CapTruncated reports whether the VERDICT's cap, not the caller's [clientRows] page size, is why this
// budget left rows out.
func (b *RowBudget) CapTruncated(dec *spi.Decision, clientRows int) bool {
	return b.Overflowed && (b.ByteCapped || dec.CapBinds(clientRows))
}

// RelayStatus reduces a relay's terminal condition to the completion status vocabulary. clean reports
// whether the result set terminated normally (a target-DB OK/EOF, not a target-DB error); err is any transport
// or protocol fault that tore the relay down. Anything that is not a clean, error-free completion is an
// error — the partial counts gathered before the fault still travel with it.
func RelayStatus(clean bool, err error) string {
	if err == nil && clean {
		return StatusOK
	}
	return StatusError
}

// EmitCompletion fires a post-relay completion report on its own goroutine and returns a channel that closes
// when the report has been sent (or given up on). It never blocks the caller and never surfaces an error: a
// lost completion degrades the audit volume signal, not the client session. The returned channel is what
// lets the SAME connection's next Decide see this statement's volume (QueryEngine.AwaitCompletion): a
// sequential dump script must not outrun its own budget. No report is sent for a statement that was never
// relayed (dec nil) or whose decision carries no audit id (DecisionID 0, a fail-closed path); the channel is
// then already closed.
func EmitCompletion(reporter interface{ ReportCompletion(spi.CompletionReport) }, dec *spi.Decision, stats spi.RelayStats, status string, start time.Time) <-chan struct{} {
	done := make(chan struct{})
	if reporter == nil || dec == nil || dec.DecisionID == 0 {
		close(done)
		return done
	}
	report := spi.CompletionReport{
		DecisionID:    dec.DecisionID,
		RowsReturned:  stats.Rows,
		BytesReturned: stats.Bytes,
		Status:        status,
		DurationMs:    time.Since(start).Milliseconds(),
	}
	go func() {
		defer close(done)
		reporter.ReportCompletion(report)
	}()
	return done
}
