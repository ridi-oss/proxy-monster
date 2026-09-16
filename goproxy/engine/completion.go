package engine

import (
	"time"
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

// RelayStats is the post-relay result-volume tally for one statement: the number of data rows that reached
// the client and the byte size of that row data. Rows catch "many records"; bytes catch "few wide rows /
// big blob". It is audit signal for the mass-export rule, never an enforcement input.
type RelayStats struct {
	Rows  int64
	Bytes int64
}

// CompletionReport is the proxy's post-relay result-volume signal for one statement, correlated to its
// decision by DecisionID (the audit id the Decide response carried). It mirrors the proto CompletionReport.
type CompletionReport struct {
	DecisionID    int64
	RowsReturned  int64
	BytesReturned int64
	Status        string
	DurationMs    int64
}

// CompletionReporter emits a best-effort post-relay completion report to the control plane. The native-wire
// gRPC client implements it; tests inject a fake. The implementation is expected to be self-contained
// best-effort — it logs its own failures and never returns an error, because a lost completion only
// degrades the audit monitor's volume signal and must never affect the client session.
type CompletionReporter interface {
	ReportCompletion(CompletionReport)
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

// EmitCompletion fires a best-effort post-relay completion report and returns immediately. It NEVER blocks
// the caller — the report goes on its own goroutine, off the client session's critical path — and NEVER
// surfaces an error, because a completion is an audit-only signal. No report is sent for a statement that
// was never relayed to the client (dec is nil) or whose decision carries no audit id (DecisionID 0 — a
// decision the control plane did not record, e.g. a fail-closed path); a DENY relays nothing and so is
// never reached here. duration is measured from start to now.
func EmitCompletion(reporter CompletionReporter, dec *Decision, stats RelayStats, status string, start time.Time) {
	if reporter == nil || dec == nil || dec.DecisionID == 0 {
		return
	}
	report := CompletionReport{
		DecisionID:    dec.DecisionID,
		RowsReturned:  stats.Rows,
		BytesReturned: stats.Bytes,
		Status:        status,
		DurationMs:    time.Since(start).Milliseconds(),
	}
	go reporter.ReportCompletion(report)
}
