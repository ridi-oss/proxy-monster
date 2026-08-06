package query

import (
	"context"
	"errors"

	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
)

// ---------------------------------------------------------------------------------------------
// The RunExecService CONTRACT — 07-tasks-approvals-results.md §7 (RunExec.kt, 655 LOC).
//
// The SERVICE is internal/runexec. Only its contract lives here, and the reason is the type graph
// rather than ownership: the transport's answer IS a [QueryResponse], which this package owns
// (06-query-decision.md §2), and A6's own `POST /api/datasources/{id}/query` is one of its two HTTP
// consumers. internal/approval is the other, and it aliases every name below (approval/runexec.go) so
// there is exactly ONE set of sentinel values — `errors.Is` compares identity, so a second copy of
// ErrNoProxyAttached in a second package would silently degrade every status mapping to 500.
//
// internal/runexec cannot host them: it imports internal/core, which imports this package.
// ---------------------------------------------------------------------------------------------

// The five `sealed class RunExecException` subclasses (RunExec.kt:150-168), as Go sentinels.
//
// 🔒 INV-A7-34 — [ErrNoProxyAttached] and [ErrProxyStreamWedged] MUST stay distinct, and both are
// 503. Nothing is missing in the wedged case: a live stream is unusable and has been dropped so the
// proxy's own reconnect can replace it. Retrying after that reconnect is the fix; hunting an absent
// proxy is not. Collapsing them into one code loses the only signal that tells an operator which.
//
// [ErrRunCanceledBeforeStart] is NOT a failure: 🔒 the async bodies map it to a nil failure code, so
// a cancel that vetoed the send before it left the control plane leaves the task's terminal state to
// the cancel path rather than overwriting it with FAILED.
var (
	ErrNoProxyAttached        = errors.New("no proxy is attached to this datasource")
	ErrProxyStreamWedged      = errors.New("the proxy's event stream would not accept the request")
	ErrProxyRunTimeout        = errors.New("the proxy run channel timed out")
	ErrRunCanceledBeforeStart = errors.New("the run was canceled before it started")
)

// ProxyRunError is `class ProxyRunException(message)` — a run that reached the proxy and failed
// there. Its MESSAGE reaches the wire as `query.failed{detail}`, which is why it carries one rather
// than being a bare sentinel.
type ProxyRunError struct {
	Message string
	// Cause is Kotlin's second constructor argument. It is unwrapped so `errors.Is` still sees a
	// wrapped context cancellation, and so a store failure underneath keeps its own identity.
	Cause error
}

func (e *ProxyRunError) Error() string { return e.Message }

// Unwrap exposes [ProxyRunError.Cause] to errors.Is/errors.As.
func (e *ProxyRunError) Unwrap() error { return e.Cause }

// NewProxyRunError is `ProxyRunException(message, cause)`.
func NewProxyRunError(message string, cause error) *ProxyRunError {
	return &ProxyRunError{Message: message, Cause: cause}
}

// RunInput is `RunExecService.run(...)`'s parameter list (RunExec.kt:258-270). Kotlin gives six of
// the eleven defaults; the struct spells them out as zero values.
type RunInput struct {
	Principal  string
	Datasource datasource.Datasource
	SQL        string
	MaxRows    int
	// ApproverExec picks the minted token's kind: APPROVER_EXEC when true, else EDITOR.
	ApproverExec bool
	// AssumeRoles is R.
	//
	// 🔒 INV-A7-1 — R ALONE, never a union with the executor's own roles. The CP mints it onto the
	// ephemeral token (CP authority, never proxy-asserted) and the gRPC Decide handler forwards it as
	// decideQuery's providedRoles, which REPLACES server role resolution.
	AssumeRoles []string
	RequesterIP *string
	TaskID      *int64
	// Preflight is the in-gate DB status re-check (INV-A7-35): it runs while the cancel gate is held,
	// so a cancel is strictly ordered relative to the send.
	Preflight         func() bool
	ExchangeTimeoutMs int64
	// DialTimeoutMs is `dialTimeoutMs: Long = DIAL_TIMEOUT_MS` — the eleventh parameter, present
	// because GrpcRunExecDbTest's dial-timeout case injects a short bound rather than waiting out the
	// production two minutes. Zero means config.DialTimeoutMS.
	DialTimeoutMs int64
}

// SessionRunInput is `runOnSession(...)`'s parameter list (RunExec.kt:431-439).
type SessionRunInput struct {
	SessionID         string
	Principal         string
	SQL               string
	MaxRows           int
	RequesterIP       *string
	TaskID            *int64
	Preflight         func() bool
	ExchangeTimeoutMs int64
}

// RunExec is the CP-driven run transport as its consumers see it. *runexec.Service satisfies it.
//
// 🔒 The two owner-scoped lookups are load-bearing, not convenience: `SessionDatasourceName` and
// `CloseSessionOwnedBy` both answer "not found" for an unknown OR a not-owned id, so a leaked session
// id reveals nothing and cannot tear down another principal's held connection.
type RunExec interface {
	// Run is the one-shot path: mint, dial, send, collect, clean up.
	Run(ctx context.Context, in RunInput) (QueryResponse, error)
	// OpenSession dials one persistent editor stream = one backend connection.
	OpenSession(ctx context.Context, principal string, ds datasource.Datasource, requesterIP *string) (string, error)
	// RunOnSession runs one statement on a held session. 🔒 INV-A7-38 — enforcement stays
	// PER-STATEMENT: a held connection is a data-plane fact, not an authz relaxation.
	RunOnSession(ctx context.Context, in SessionRunInput) (QueryResponse, error)
	// SessionDatasourceName is owner-scoped; ok=false for unknown or not-owned.
	SessionDatasourceName(sessionID, principal string) (string, bool)
	// CloseSessionOwnedBy is owner-scoped; false for unknown or not-owned. Idempotent.
	CloseSessionOwnedBy(sessionID, principal string) bool
	// CancelActiveRun reports whether a run was registered. 🔒 INV-A7-35 — the implementation must
	// SEND under the same lock that sets `canceled`, or a cancel can reorder ahead of the query and
	// be dropped by an idle proxy, letting a just-canceled query run anyway.
	CancelActiveRun(ctx context.Context, taskID int64) bool
}
