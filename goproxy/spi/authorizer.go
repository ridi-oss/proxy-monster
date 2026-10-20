package spi

import (
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// ---- The verdict the engine hands back to the protocol ----

// Verdict is the control plane's decision reduced to what the dumb protocol must do.
type Verdict interface{ isVerdict() }

// Deny: send a wire error (Decision.DenyReason); the statement is not forwarded.
type Deny struct{ Decision *Decision }

// Proceed: forward SQL (RewrittenSQL if non-nil, else the client's original). When Masks is non-empty
// the protocol MUST mask those result columns via NewRowMasker; a mask that fails to bind is a
// mechanical failure and the protocol fails closed.
type Proceed struct {
	Decision     *Decision
	RewrittenSQL *string
	Masks        []*pb.ColumnMask
}

// Fail: a mechanical impossibility (control plane unreachable, a probe failed, ...) — fail closed.
type Fail struct{ Message string }

func (Deny) isVerdict()    {}
func (Proceed) isVerdict() {}
func (Fail) isVerdict()    {}

// ---- The engine ----

// QueryEngine runs one connection's relay. It holds ONLY a namespace cache (invalidated by protocol
// signals via MarkNamespaceDirty, never by inspecting SQL). It is created with an injected DecisionClient and
// never touches sockets — the protocol supplies probe I/O via callbacks.
type QueryEngine struct {
	client       DecisionClient
	session      SessionObservation
	nsDirty      bool
	sanitizeDiag bool
	// The previous statement's in-flight completion report; Authorize waits for it so the control plane's
	// budget read includes this connection's own last relay.
	pendingCompletion <-chan struct{}
}

// NewQueryEngine creates the per-connection engine. The namespace starts dirty so the first query
// probes it.
func NewQueryEngine(client DecisionClient) *QueryEngine {
	return &QueryEngine{client: client, nsDirty: true}
}

// MarkNamespaceDirty invalidates the cached namespace. The protocol calls this when an authoritative
// target DB signal says the namespace may have changed but does not include its new value, never by
// classifying SQL text.
func (e *QueryEngine) MarkNamespaceDirty() { e.nsDirty = true }

// AwaitCompletion makes the next Authorize wait until done closes (the statement's completion report has
// been delivered or abandoned), bounded by completionWait.
func (e *QueryEngine) AwaitCompletion(done <-chan struct{}) { e.pendingCompletion = done }

// completionWait bounds how long a Decide waits for the previous statement's completion report. The
// reporter's own RPC deadline is shorter, so this only guards a reporter that hangs.
const completionWait = 35 * time.Second

// SanitizeDiagnostics reports whether the CURRENT statement's target-DB diagnostics must be redacted
// — the value from the most recent decision, so the protocol can gate each target-DB error/notice forward on
// it. Per-decision, not latched (the control plane decides it fresh each Decide). See
// docs/diagnostic-redaction.md.
func (e *QueryEngine) SanitizeDiagnostics() bool { return e.sanitizeDiag }

// SetNamespace replaces the cached namespace from an authoritative target DB protocol signal. It copies
// namespace so a caller cannot mutate the authorization context after the signal is consumed.
func (e *QueryEngine) SetNamespace(namespace []string) {
	e.session.Namespace = append([]string{}, namespace...)
	e.nsDirty = false
}

// AuthzInput is one statement to authorize plus the probe callbacks the protocol wires up. The protocol
// runs its Db's probe SQL on the target DB and parses the result. The engine calls ProbeSession only when
// its cache is dirty, and ProbeTempColumns only when the protocol supplies it (the PG temp overlay).
type AuthzInput struct {
	SQL              string
	Token            string
	ClientAddr       string
	ConnectionID     []byte
	ProbeSession     func() (SessionObservation, error)
	ProbeTempColumns func() ([]TempColumn, error)
	RunCommands      func([]*pb.ProxyCommand, *SessionObservation) error
	CheckTargetError func(sql string) (*TargetError, error)
}

// Authorize gathers namespace context (cached unless dirty), gathers session-temp columns when the
// protocol supplies a probe, calls the control plane's Decide, and returns the verdict for the protocol to
// apply. It makes no enforcement decision of its own; the only local outcomes are fail-closed (Fail) on
// a mechanical impossibility and the reduction of the control plane's Action to Deny/Proceed.
func (e *QueryEngine) Authorize(in AuthzInput) Verdict {
	if e.pendingCompletion != nil {
		select {
		case <-e.pendingCompletion:
		case <-time.After(completionWait):
		}
		e.pendingCompletion = nil
	}
	if e.nsDirty || e.session.Namespace == nil {
		session, err := in.ProbeSession()
		if err != nil {
			return Fail{Message: "namespace probe failed: " + err.Error()}
		}
		e.session = session.Clone()
		e.nsDirty = false
	}

	var temps []TempColumn
	if in.ProbeTempColumns != nil {
		// Best-effort: on failure none are overlaid, so a temp read resolves fail-closed at the CP.
		if t, err := in.ProbeTempColumns(); err == nil {
			temps = t
		}
	}

	out := e.client.Decide(DecideRequest{
		Session:          e.session.Clone(),
		Token:            in.Token,
		SQL:              in.SQL,
		ClientAddr:       in.ClientAddr,
		TempColumns:      temps,
		ConnectionID:     in.ConnectionID,
		RunCommands:      in.RunCommands,
		CheckTargetError: in.CheckTargetError,
	})
	if out.IsErr() {
		return Fail{Message: out.Err}
	}
	// Per-decision, NOT latched: an ALLOW whose leak set is fully readable relays raw even right after a
	// MASK (docs/diagnostic-redaction.md).
	e.sanitizeDiag = out.Decision.SanitizeDiagnostics
	if out.Decision.ForwardTargetError {
		if out.TargetError == nil {
			return Fail{Message: "control plane asked to forward a target error the proxy did not observe"}
		}
		// A Deny, so a path that does not forward target errors still refuses the statement.
		out.Decision.TargetError = out.TargetError
		return Deny{Decision: out.Decision}
	}
	switch out.Decision.Action {
	case "ALLOW":
		return Proceed{Decision: out.Decision, RewrittenSQL: out.Decision.RewrittenSQL}
	case "MASK":
		return Proceed{Decision: out.Decision, RewrittenSQL: out.Decision.RewrittenSQL, Masks: out.Decision.Masks}
	default:
		// DENY and any unexpected Action: fail closed with an error the protocol renders.
		return Deny{Decision: out.Decision}
	}
}
