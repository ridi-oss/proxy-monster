package approval

import (
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// ---------------------------------------------------------------------------------------------
// The RunExecService seam — 07-tasks-approvals-results.md §7 (RunExec.kt, 655 LOC).
//
// The SERVICE is internal/runexec. Its CONTRACT — the five exception kinds, the two input shapes and
// the interface — is declared in internal/query (query/runexec.go) and ALIASED here.
//
// 🔒 THESE ARE ALIASES, NOT COPIES, AND THAT IS LOAD-BEARING. `errors.Is` compares identity: a second
// `errors.New("no proxy is attached…")` in this package would be a different value, every
// `errors.Is(err, ErrNoProxyAttached)` below would answer false, and each of the four status mappings
// would silently degrade to 500 `common.fallback` — a control plane reporting an internal fault for a
// condition that has a real wire code. The reason the declaration lives over there rather than here is
// the type graph, not ownership: A6's `POST /api/datasources/{id}/query` is the transport's other HTTP
// consumer and internal/query cannot import this package (this package imports it).
// ---------------------------------------------------------------------------------------------

// The five `sealed class RunExecException` subclasses, as this package's routes switch on them.
//
// 🔒 INV-A7-34 — [ErrNoProxyAttached] and [ErrProxyStreamWedged] MUST stay distinct, and both are
// 503; see query.ErrNoProxyAttached for why.
var (
	ErrNoProxyAttached        = query.ErrNoProxyAttached
	ErrProxyStreamWedged      = query.ErrProxyStreamWedged
	ErrProxyRunTimeout        = query.ErrProxyRunTimeout
	ErrRunCanceledBeforeStart = query.ErrRunCanceledBeforeStart
)

// ProxyRunError is `class ProxyRunException(message)`; its Message reaches the wire as
// `query.failed{detail}`.
type ProxyRunError = query.ProxyRunError

// RunInput is `RunExecService.run(...)`'s parameter list (RunExec.kt:258-270).
type RunInput = query.RunInput

// SessionRunInput is `runOnSession(...)`'s parameter list (RunExec.kt:431-439).
type SessionRunInput = query.SessionRunInput

// RunExec is the CP-driven run transport as these routes consume it.
type RunExec = query.RunExec
