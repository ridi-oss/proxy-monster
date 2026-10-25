package spi

import (
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// ---- The verdict the Authorizer hands back to the protocol ----

// Verdict is the control plane's decision reduced to what the dumb protocol must do.
type Verdict interface{ isVerdict() }

// Deny: send a wire error (Decision.DenyReason); the statement is not forwarded.
type Deny struct{ Decision *Decision }

// Proceed: forward SQL (RewrittenSQL if non-nil, else the client's original). When Masks is non-empty
// the protocol MUST mask those result columns via relay.NewRowMasker; a mask that fails to bind is a
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

// ---- The Authorizer ----

// Authorizer runs one connection's relay. It holds ONLY a namespace cache (invalidated by protocol
// signals via MarkNamespaceDirty, never by inspecting SQL). It never touches sockets; the protocol supplies
// probe I/O via callbacks.
type Authorizer struct {
	client       ControlPlane
	token        string
	clientAddr   string
	connectionID []byte
	snapshot     SessionSnapshot
	nsDirty      bool
	sanitizeDiag bool
	// The previous statement's in-flight completion report; Authorize waits for it so the control plane's
	// budget read includes this connection's own last relay.
	pendingCompletion <-chan struct{}
}

// NewAuthorizer creates the Authorizer for one connection. The namespace starts dirty so the first query
// probes it.
func NewAuthorizer(client ControlPlane, token string, connectionID []byte) *Authorizer {
	return &Authorizer{client: client, token: token, connectionID: append([]byte(nil), connectionID...), nsDirty: true}
}

// Authenticate validates a wire client's token and opens the Authorizer for the connection it opened. The
// caller closes the connection with Close.
func Authenticate(client ControlPlane, token, clientAddr string) (*Authorizer, Identity, error) {
	identity, err := client.ValidateToken(token, clientAddr)
	if err != nil {
		return nil, Identity{}, err
	}
	authz := NewAuthorizer(client, token, identity.ConnectionID)
	authz.clientAddr = clientAddr
	return authz, identity, nil
}

// Close ends the connection on the control plane.
func (a *Authorizer) Close() error { return a.client.CloseConnection(a.connectionID) }

func (a *Authorizer) ConnectionID() []byte { return a.connectionID }

func (a *Authorizer) Client() ControlPlane { return a.client }

// MarkNamespaceDirty invalidates the cached namespace. The protocol calls this when an authoritative
// target DB signal says the namespace may have changed but does not include its new value, never by
// classifying SQL text.
func (a *Authorizer) MarkNamespaceDirty() { a.nsDirty = true }

// AwaitCompletion makes the next Authorize wait until done closes (the statement's completion report has
// been delivered or abandoned), bounded by completionWait.
func (a *Authorizer) AwaitCompletion(done <-chan struct{}) { a.pendingCompletion = done }

// completionWait bounds how long a Decide waits for the previous statement's completion report. The
// reporter's own RPC deadline is shorter, so this only guards a reporter that hangs.
const completionWait = 35 * time.Second

// SanitizeDiagnostics reports whether the CURRENT statement's target-DB diagnostics must be redacted
// — the value from the most recent decision, so the protocol can gate each target-DB error/notice forward on
// it. Per-decision, not latched (the control plane decides it fresh each Decide). See
// docs/diagnostic-redaction.md.
func (a *Authorizer) SanitizeDiagnostics() bool { return a.sanitizeDiag }

// Snapshot is the session snapshot the last decision was made under.
func (a *Authorizer) Snapshot() SessionSnapshot { return a.snapshot.Clone() }

// SetSnapshot replaces the cached snapshot with one the protocol probed itself (Postgres Bind); the cache is
// clean after it. It copies snapshot so the caller cannot mutate the authorization context afterwards.
func (a *Authorizer) SetSnapshot(snapshot SessionSnapshot) {
	a.snapshot = snapshot.Clone()
	a.nsDirty = false
}

// AuthzInput is one statement to authorize plus the probe callbacks the protocol wires up. The protocol
// runs its probe SQL on the target DB and parses the result. The Authorizer calls ProbeSession only when
// its cache is dirty, and ProbeTempColumns only when the protocol supplies it (the PG temp overlay).
type AuthzInput struct {
	SQL              string
	ProbeSession     func() (SessionSnapshot, error)
	ProbeTempColumns func() ([]TempColumn, error)
	Commands         ProxyCommandRunner
	CheckTargetError func(sql string) (*TargetError, error)
}

// Authorize gathers namespace context (cached unless dirty), gathers session-temp columns when the
// protocol supplies a probe, calls the control plane's Decide, and returns the verdict for the protocol to
// apply. It makes no enforcement decision of its own; the only local outcomes are fail-closed (Fail) on
// a mechanical impossibility and the reduction of the control plane's Action to Deny/Proceed.
func (a *Authorizer) Authorize(in AuthzInput) Verdict {
	if a.pendingCompletion != nil {
		select {
		case <-a.pendingCompletion:
		case <-time.After(completionWait):
		}
		a.pendingCompletion = nil
	}
	if a.nsDirty || a.snapshot.Namespace == nil {
		snapshot, err := in.ProbeSession()
		if err != nil {
			return Fail{Message: "namespace probe failed: " + err.Error()}
		}
		a.snapshot = snapshot.Clone()
		a.nsDirty = false
	}

	var temps []TempColumn
	if in.ProbeTempColumns != nil {
		// Best-effort: on failure none are overlaid, so a temp read resolves fail-closed at the CP.
		if t, err := in.ProbeTempColumns(); err == nil {
			temps = t
		}
	}

	out := a.client.Decide(DecideRequest{
		Snapshot:         a.snapshot.Clone(),
		Token:            a.token,
		SQL:              in.SQL,
		ClientAddr:       a.clientAddr,
		TempColumns:      temps,
		ConnectionID:     a.connectionID,
		Commands:         in.Commands,
		CheckTargetError: in.CheckTargetError,
	})
	if out.IsErr() {
		return Fail{Message: out.Err}
	}
	// Per-decision, NOT latched: an ALLOW whose leak set is fully readable relays raw even right after a
	// MASK (docs/diagnostic-redaction.md).
	a.sanitizeDiag = out.Decision.SanitizeDiagnostics
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
