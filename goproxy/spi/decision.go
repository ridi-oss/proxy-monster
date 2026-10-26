package spi

import (
	"fmt"
	"math"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/protobuf/proto"
)

// StatementResult is the protocol-neutral result of serving one authorized statement.
type StatementResult struct {
	Decision     *Decision
	Denied       bool
	Columns      []string
	Rows         [][]*string
	RowsAffected int
	// The verdict's result cap, not the caller's page size, ended this result.
	TruncatedByCap bool
}

// ExecGuard optionally wraps only target-DB execution. Authorization and catalog probes run outside it.
type ExecGuard func(exec func() error) error

// RelayStats is the running result-volume tally for one statement: the number of data rows that reached
// the client and the byte size of that row data. Rows catch "many records"; bytes catch "few wide rows /
// big blob". It is both the audit signal for the mass-export rule and — as the relay accumulates it — what
// the verdict's result caps are measured against ([Decision.CapExceeded]).
type RelayStats struct {
	Rows  int64
	Bytes int64
}

func (s RelayStats) Plus(other RelayStats) RelayStats {
	return RelayStats{Rows: s.Rows + other.Rows, Bytes: s.Bytes + other.Bytes}
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

// Decision is the control plane's enforcement verdict for one statement. Mirrors WireDecision in
// controlplane.proto. Masks and AfterStatement are the proto types (pb.ColumnMask / pb.ProxyCommand) used
// AS the data classes; a ProxyCommand is run mechanically by the dialect's command runner (a Refetch is a
// conditional refresh of one connection-local schema fragment).
type Decision struct {
	Action              string // "ALLOW" | "MASK" | "DENY" (mapped by NAME; unknown -> DENY, fail closed)
	DecisionID          int64
	DenyReason          string
	DenyCode            string // a stable code for DenyReason ("rate_spent"), or empty
	Masks               []*pb.ColumnMask
	EffectiveRoles      []string
	RewrittenSQL        *string // nil == relay the client's original SQL verbatim (no * expansion)
	UnmaskablePermitted bool
	AfterStatement      []*pb.ProxyCommand
	Generation          uint64
	// SanitizeDiagnostics is the control plane's per-decision diagnostic-redaction flag. When set,
	// the proxy strips this statement's target-DB error/notice messages down to code + severity. See
	// docs/diagnostic-redaction.md.
	SanitizeDiagnostics bool
	// ForwardTargetError: send the client TargetError (redacted) and run nothing.
	ForwardTargetError bool
	TargetError        *TargetError
	// MaxRows / MaxBytes are the result caps the control plane resolved from the statement's Cedar permits
	// (Verdict.max_rows / max_bytes); 0 = uncapped. See docs/result-caps.md.
	MaxRows  int64
	MaxBytes int64
	// Submission is the engine-specific companion to RewrittenSQL (analyzer.proto Submission); the dialect
	// reads its own arm. nil = the text is the whole submission.
	Submission *enginepb.Submission
	// ResultRequirements is echoed on RunDecision for the control plane; the proxy does not read it.
	ResultRequirements *pb.ResultRequirements
}

// PageRows is the row count a paging caller should ask the target DB for: its own page size narrowed by the
// verdict cap. A zero on either side means that side sets no bound.
func (d *Decision) PageRows(clientRows int) int {
	if d == nil || d.MaxRows <= 0 {
		return clientRows
	}
	capRows := int(min(d.MaxRows, int64(math.MaxInt)))
	if clientRows <= 0 {
		return capRows
	}
	return min(clientRows, capRows)
}

// CapBinds reports whether the verdict cap — not the caller's page size — is what ended a result of
// [clientRows] page size. A result the client's own paging cut short is a plain page end, not a cap hit.
func (d *Decision) CapBinds(clientRows int) bool {
	return d != nil && d.MaxRows > 0 && (clientRows <= 0 || d.MaxRows <= int64(clientRows))
}

// CapExceeded is the client-facing terminator text when relaying one more row of [rowBytes] would cross
// this decision's caps, or "" when it fits. Both wire relays build their engine-specific error around this
// one string, so a MySQL 1317 and a PostgreSQL 57014 say the same thing.
func (d *Decision) CapExceeded(relayed RelayStats, rowBytes int64) string {
	switch {
	case d == nil:
		return ""
	case d.MaxRows > 0 && relayed.Rows >= d.MaxRows:
		return fmt.Sprintf("proxy-monster: result exceeds the row cap (%d rows); request unbounded access", d.MaxRows)
	case d.MaxBytes > 0 && rowBytes > d.MaxBytes-relayed.Bytes:
		return fmt.Sprintf("proxy-monster: result exceeds the byte cap (%d bytes); request unbounded access", d.MaxBytes)
	default:
		return ""
	}
}

// DecisionOutcome is the result of a Decide call: Ok(decision) or an Err message (fail closed).
type DecisionOutcome struct {
	Decision    *Decision
	Err         string // non-empty == the control-plane call failed / was unreachable; caller fails closed
	TargetError *TargetError
}

// TargetError is the target's answer to preparing a statement: its error code and the protocol's own
// error message, which the protocol forwards as-is.
type TargetError struct {
	Code    string
	Message any
}

// IsErr reports whether the Decide call failed.
func (o DecisionOutcome) IsErr() bool { return o.Decision == nil }

// TempColumn is one column of a session-temp table on the connection — context the proxy sends so the
// control plane resolves a bare name to the connection's temp. Mirrors proto TempColumn.
type TempColumn struct {
	Catalog string
	Schema  string
	Table   string
	Column  string
	SqlType string
	Ordinal int
}

// DecideRequest is the complete per-query control-plane request plus the callback used to satisfy
// before_decide commands on the held target-DB connection.
type DecideRequest struct {
	Snapshot     SessionSnapshot
	Token        string
	SQL          string
	ClientAddr   string
	TempColumns  []TempColumn
	ConnectionID []byte
	// Commands runs one before-decide round on the held target connection and may extend Session with what
	// it fetched.
	Commands ProxyCommandRunner
	// CheckTargetError prepares sql on the target without executing it; nil means the statement prepared.
	CheckTargetError func(sql string) (*TargetError, error)
}

// ProxyCommandRunner runs the ProxyCommands the control plane attaches to a decision or a connection open on the
// held target connection: Refetch, and Athena's FetchAthenaPreparedDefinition, which adds to session.
type ProxyCommandRunner interface {
	RunAll(commands []*pb.ProxyCommand, snapshot *SessionSnapshot) error
}

// SessionSnapshot is what the pre-statement probe returned: the connection's current catalog and
// effective namespace plus the session facts the wire carries as-is. The Authorizer caches it as one value and
// the decision carries it whole, so every fact reaches the control plane from the same probe.
type SessionSnapshot struct {
	CurrentCatalog string
	Namespace      []string
	*enginepb.SessionObservation
}

// Clone copies the observation so a cached snapshot cannot be mutated through shared state.
func (o SessionSnapshot) Clone() SessionSnapshot {
	o.Namespace = append([]string{}, o.Namespace...)
	if o.SessionObservation != nil {
		o.SessionObservation = proto.Clone(o.SessionObservation).(*enginepb.SessionObservation)
	}
	return o
}
