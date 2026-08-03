package types

import (
	"encoding/json"
	"fmt"
)

// Decision is the outcome of the enforcement triad (DESIGN.md).
//
// 01-bootstrap.md §3: ALLOW | MASK | DENY | ERROR. ERROR is the internal-failure case — the proxy
// could not reach a verdict — and is DISTINCT from the fail-closed DENY. Do not collapse them: a
// caller that treats ERROR as DENY loses the "we never got an answer" signal the audit trail and the
// proxy's own retry logic depend on.
//
// # Why a string type and not an int enum
//
// Kotlin's `enum class Decision` is a closed set: there is no unset Decision, and kotlinx serializes
// it by NAME (auditmon/canon encodes `decision.name` into the hash preimage, 08-audit.md §2). Go has
// no closed sets, so the zero value has to be *something*. An int enum would make the zero value
// ALLOW — an unset field silently reading as a permit, i.e. fail-OPEN on the one field the whole
// system is about. A string type makes the zero value "" instead: not a valid Decision, rejected by
// IsValid and by UnmarshalJSON, and obviously wrong in a log. Fail-closed beats ordinal fidelity.
// This also makes handing an AuditEvent to auditmon/canon a direct assignment — canon.AuditEvent's
// Decision field is a plain string (auditmon/canon/canonical.go).
type Decision string

// The four decisions, spelled exactly as they go on the wire and into the canonical hash preimage.
const (
	// DecisionAllow — the statement is permitted unmodified.
	DecisionAllow Decision = "ALLOW"
	// DecisionMask — permitted, with named columns masked on the result stream.
	DecisionMask Decision = "MASK"
	// DecisionDeny — refused. This is the fail-closed verdict: a real answer, reached deliberately.
	DecisionDeny Decision = "DENY"
	// DecisionError — no verdict could be reached (internal failure). NOT the same as DecisionDeny.
	DecisionError Decision = "ERROR"
)

// DecisionValues returns the four decisions in Kotlin declaration order — the analogue of
// Decision.values(). It returns a fresh slice on every call so a caller cannot mutate the set.
func DecisionValues() []Decision {
	return []Decision{DecisionAllow, DecisionMask, DecisionDeny, DecisionError}
}

// IsValid reports whether d is one of the four declared decisions. The zero Decision ("") is not.
func (d Decision) IsValid() bool {
	switch d {
	case DecisionAllow, DecisionMask, DecisionDeny, DecisionError:
		return true
	default:
		return false
	}
}

// String returns the wire/hash name. Note it returns the raw value even when invalid, so a bad value
// is visible in a log rather than being laundered into something plausible.
func (d Decision) String() string { return string(d) }

// ParseDecision is the analogue of Kotlin's Decision.valueOf: exact-match only, and an unknown name
// is an error rather than a fallback. Matching is case-SENSITIVE, as valueOf is.
func ParseDecision(s string) (Decision, error) {
	d := Decision(s)
	if !d.IsValid() {
		return "", fmt.Errorf("types: %q is not a Decision (want one of ALLOW, MASK, DENY, ERROR)", s)
	}
	return d, nil
}

// UnmarshalJSON rejects any name outside the four.
//
// This exists because Go would otherwise accept anything. kotlinx.serialization's enum decoder throws
// SerializationException on an unknown name, so a proxy posting decision:"PERMIT" is REFUSED today —
// the event never reaches the store. A plain `type Decision string` would accept it and persist an
// unenforceable verdict, which is a behaviour change on a security path, not a Go nicety.
//
// On the status the caller sees: App.kt:675 calls call.receive<AuditEvent>() with no try/catch, so
// the SerializationException propagates to the StatusPages catch-all (App.kt:452-462), which answers
// 500 common.fallback for any Throwable outside /oauth/ — NOT 400. Both files read this session. That
// is a defect (a malformed request body reported as a server error) and the PORT POLICY says
// REPRODUCE: the Go ingest route must let a decode error propagate to the 500 catch-all rather than
// "improving" it to a 400.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("types: Decision must be a JSON string: %w", err)
	}
	parsed, err := ParseDecision(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
