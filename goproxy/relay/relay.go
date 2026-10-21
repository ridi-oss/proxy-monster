// Package relay is what every wire protocol shares around spi.Authorizer: serving a statement under its verdict,
// masking result rows, and reporting the completion.
package relay

import (
	"errors"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// ---- Mechanical masking: render the control plane's chosen masks onto result rows ----

// ErrMaskUnbound reports that a control-plane-selected mask cannot be applied to the live result shape.
var ErrMaskUnbound = errors.New("required mask could not be bound to a result column")

// MaskBinding is masks keyed by result-column index plus any that could not bind (out of range or an
// absent proto ordinal). The mask type is the proto ColumnMask (pb.ColumnMask) used AS the data class.
type MaskBinding struct {
	ByIndex map[int]string
	Unbound []*pb.ColumnMask
}

// AllBound reports whether every mask bound to a live result column.
func (b MaskBinding) AllBound() bool { return len(b.Unbound) == 0 }

// RowMasker renders the control plane's masks onto decoded result rows. It is mechanical, not a
// decision: the control plane chose the columns and kinds; the proxy only renders them.
type RowMasker struct {
	byIndex map[int]string
}

// NewRowMasker binds masks to a result set of columnCount columns. It returns nil when any mask is
// out of range — the caller MUST then fail closed, because a mask the proxy cannot bind means the
// intended column would otherwise reach the client unmasked.
func NewRowMasker(masks []*pb.ColumnMask, columnCount int) *RowMasker {
	binding := BindMasks(masks, columnCount)
	if !binding.AllBound() {
		return nil
	}
	return &RowMasker{byIndex: binding.ByIndex}
}

// Apply returns a copy of values with the bound columns masked.
func (m *RowMasker) Apply(values []*string) []*string {
	masked := append([]*string(nil), values...)
	for index, kind := range m.byIndex {
		if index >= 0 && index < len(masked) {
			masked[index] = applyMaskKind(masked[index], kind)
		}
	}
	return masked
}

// ---- Control-plane decision (the control-plane client maps the wire enum to a string Action + fail-closes) ----

// RedactedDiagnosticMessage is the single generic string that replaces every target-DB diagnostic message on
// a diagnostic-redacted connection. It carries no stored value; the proxy keeps only the
// machine-readable code + severity beside it. See docs/diagnostic-redaction.md.
const RedactedDiagnosticMessage = "target-DB diagnostic details are redacted on this connection (proxy-monster)"

// EnfActionName reduces a proto EnfAction to Decision.Action's string vocabulary, fail-closed: any
// value that is not ALLOW or MASK — including ENF_ACTION_UNSPECIFIED and the generated UNRECOGNIZED —
// becomes "DENY", so an unknown verdict never falls open.
func EnfActionName(a pb.EnfAction) string {
	switch a {
	case pb.EnfAction_ALLOW:
		return "ALLOW"
	case pb.EnfAction_MASK:
		return "MASK"
	default:
		return "DENY"
	}
}

// ParseEnfActionName is the inverse of EnfActionName, fail-closed to DENY on any string that is not
// "ALLOW" or "MASK".
func ParseEnfActionName(s string) pb.EnfAction {
	switch s {
	case "ALLOW":
		return pb.EnfAction_ALLOW
	case "MASK":
		return pb.EnfAction_MASK
	default:
		return pb.EnfAction_DENY
	}
}
