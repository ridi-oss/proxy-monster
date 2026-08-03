package config

// DialTimeoutMS is `internal const val DIAL_TIMEOUT_MS = 120_000L` at RunExec.kt:42.
//
// The value is measured, not chosen: 07-tasks-approvals-results.md's timing table records "measured
// cold opens took ~26s; 10s failed them outright".
//
// TODO(A7): the constant BELONGS to A7 and has three consumers — RunExec itself, Main.kt:20
// (RunStreamTimeoutMS below, A1) and TableDetailExec.kt:91 (A5). 99-reconciliation-report.md closes A1
// Q5 with "in Go it needs a shared package, not a per-area copy", so when A7 lands, move it there and
// leave this as an alias. It is hosted here meanwhile because A1 is the first area ported and
// RunStreamTimeoutMS cannot be written without it.
const DialTimeoutMS int64 = 120_000

// RunStreamTimeoutMS is `runStreamTimeoutMs(queryExchangeTimeoutMs)` at Main.kt:19-20 — a top-level
// A1 function, and one of the four derived values in 01-bootstrap.md §1.
//
// How long one proxy-dialed run stream may live. The stream is OPENED BEFORE the proxy reports ready,
// so its lifetime has to cover the dial as well as the exchange that follows. Leave the dial out and
// the cap falls short of the work it wraps once PM_QUERY_TIMEOUT is large: the stream then dies under
// a statement that is still legitimately running, and the caller sees a stream-closed error rather
// than the timeout it actually is.
//
// ⚠️ The argument is queryExchangeTimeoutMs — MILLISECONDS, i.e. Config.QueryExchangeTimeoutMS(), not
// QueryTimeoutSeconds. 99-reconciliation-report.md flags 01-bootstrap.md §1's `q` as ambiguous on
// exactly this point, and 10-grpc.md:261 expands it correctly.
func RunStreamTimeoutMS(queryExchangeTimeoutMs int64) int64 {
	return max(15*60_000, DialTimeoutMS+queryExchangeTimeoutMs+30_000)
}
