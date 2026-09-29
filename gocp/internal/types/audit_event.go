package types

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultAuditKind is AuditEvent.kind's Kotlin default. Kept as a named constant because it is
// applied in two places (NewAuditEvent and UnmarshalJSON) and because getting it wrong is silent:
// `kind` is field 1 of the canonical hash preimage (08-audit.md §2), so an event that decodes with
// kind "" instead of "decision" hashes differently and fails auditmon's chain verification later,
// with nothing at ingest time to point at the cause.
const DefaultAuditKind = "decision"

// AuditEvent is one tamper-evident audit event.
//
// 🔒 01-bootstrap.md §3: the wire contract shared by the proxy (emitting to /api/ingest/decision),
// the web UI (reading it back) AND auditmon (re-verifying the hash chain). Field names and order are
// FROZEN — auditmon/canon encodes 22 business columns in a fixed order (08-audit.md §2), so a rename
// or a reorder here breaks chain verification silently instead of failing a build.
//
// The struct field order below is the table order in 01-bootstrap.md §3, which is also the JSON
// emission order (encoding/json emits in declaration order) — TestAuditEventMarshalFullyPopulated
// asserts the whole byte string, so a reorder fails a test rather than reaching production.
//
// Note the 23 JSON fields are not the same set as canon's 22 canonical fields: `id` is field 23 on
// the wire but is hashed separately (as u64be, before the field block) and `ts` is replaced by
// `tsMicros`. Do not derive one list from the other.
//
// # Nullability (INV-A1-4)
//
// Kotlin `T?` with a null default becomes *T + omitempty, so an unset field is ABSENT from the JSON,
// never null (explicitNulls = false). Kotlin non-null fields — including `latencyMs: Long = 0` and
// `kind: String = "decision"` — carry NO omitempty, so their defaults are always emitted
// (encodeDefaults = true). The five List<String> fields carry no omitempty either and are normalised
// to [] by MarshalJSON, because Go's nil slice marshals as null and Kotlin's emptyList() marshals as
// [] — the UI relies on the arrays being present.
type AuditEvent struct {
	// ID is server-assigned; proxy ingest leaves it null. Application-allocated, not a sequence
	// (INV-A8-1).
	ID *int64 `json:"id,omitempty"`
	// TS is an ISO-8601 instant; the server fills it when null (INV-A8-3). Held as a string, not a
	// time.Time, because the Kotlin round-trips it through Java's variable-precision
	// Instant.toString() and that formatting is wire-visible (08-audit.md §1, Q2).
	TS                 *string  `json:"ts,omitempty"`
	Principal          string   `json:"principal"`
	Roles              []string `json:"roles"`
	Datasource         string   `json:"datasource"`
	ClientAddr         *string  `json:"clientAddr,omitempty"`
	Statement          string   `json:"statement"`
	Decision           Decision `json:"decision"`
	FailedStage        *string  `json:"failedStage,omitempty"` // parse|validate|convert|lineage
	EffectiveNamespace []string `json:"effectiveNamespace"`
	MaskedColumns      []string `json:"maskedColumns"`
	PIITouched         []string `json:"piiTouched"`
	LatencyMs          int64    `json:"latencyMs"`
	Detail             *string  `json:"detail,omitempty"`
	// Channel is which surface/phase the decision came from
	// (wire|editor|workflow-executor|workflow-viewer); ContextTags are the derived context.tags it
	// earned. Both optional because proxy ingest may leave them unset.
	Channel     *string  `json:"channel,omitempty"`
	ContextTags []string `json:"contextTags"`
	// AuthzAction/AuthzResource/Outcome are set by management decisions, which attach the exact
	// Cedar action and resource plus a mutation outcome. Optional for the query/wire audit contract.
	// ⚠️ These two map to columns `action`/`resource`, not to columns of the same name
	// (08-audit.md §1) — a trap for whoever writes the store.
	AuthzAction   *string `json:"authzAction,omitempty"`
	AuthzResource *string `json:"authzResource,omitempty"`
	Outcome       *string `json:"outcome,omitempty"`
	Kind          string  `json:"kind"`
	RowsReturned  *int64  `json:"rowsReturned,omitempty"`
	BytesReturned *int64  `json:"bytesReturned,omitempty"`
	DecisionID    *int64  `json:"decisionId,omitempty"`
}

// NewAuditEvent is the analogue of Kotlin's primary constructor: the four fields with no default are
// required arguments, and every other field is materialised at its declared default (empty lists,
// latencyMs 0, kind "decision", the rest absent).
//
// It exists because Go's zero value is NOT Kotlin's default value — AuditEvent{} has nil lists and an
// empty kind, neither of which any Kotlin AuditEvent can have. Construct events through this, not
// through a bare struct literal, and the defaults come out right by construction rather than by
// review.
func NewAuditEvent(principal, datasource, statement string, decision Decision) AuditEvent {
	return AuditEvent{
		Principal:          principal,
		Roles:              []string{},
		Datasource:         datasource,
		Statement:          statement,
		Decision:           decision,
		EffectiveNamespace: []string{},
		MaskedColumns:      []string{},
		PIITouched:         []string{},
		ContextTags:        []string{},
		Kind:               DefaultAuditKind,
	}
}

// auditEventJSON strips AuditEvent's own marshal/unmarshal methods so the reflection-based codec can
// be reused inside them without recursing. Field methods on named field types (Decision) survive the
// conversion, so Decision.UnmarshalJSON still validates.
type auditEventJSON AuditEvent

// MarshalJSON reproduces the two INV-A1-4 rules structurally rather than by discipline: the five
// List<String> fields are emitted as [] when nil, and pointer fields are omitted rather than nulled
// (that part is just the struct tags).
//
// Normalising nil→[] here rather than relying on every construction site is not a design improvement
// over the Kotlin — a nil slice is a Go artifact with no Kotlin counterpart, so removing it is
// REPRODUCING emptyList(), not fixing anything. `kind` is deliberately NOT defaulted here: Kotlin can
// legitimately construct AuditEvent(kind = ""), so forcing it at the marshal boundary would make a
// representable state unrepresentable. NewAuditEvent is where the default belongs.
func (e AuditEvent) MarshalJSON() ([]byte, error) {
	v := auditEventJSON(e)
	emptyIfNil(&v.Roles)
	emptyIfNil(&v.EffectiveNamespace)
	emptyIfNil(&v.MaskedColumns)
	emptyIfNil(&v.PIITouched)
	emptyIfNil(&v.ContextTags)
	// Encode without HTML escaping so MarshalWire's raw bytes survive. When the caller is a plain
	// json.Marshal instead, its compact(escapeHTML=true) pass re-escapes this output — so the default
	// path still behaves exactly like stdlib. See MarshalWire.
	return marshalJSON(v, false)
}

// UnmarshalJSON reproduces kotlinx's decoding behaviour, which differs from Go's default in three
// ways that are all observable on /api/ingest/decision:
//
//   - Required fields. principal, datasource, statement and decision have no Kotlin default, so a
//     body missing any of them raises MissingFieldException and the event is refused. Go would
//     silently zero-fill and store an event attributed to principal "". Missing fields are collected
//     and reported together, as kotlinx does.
//     ⚠️ The status that reaches the caller is 500 common.fallback, not 400: App.kt:675 calls
//     call.receive<AuditEvent>() bare, so the exception lands in the StatusPages catch-all
//     (App.kt:452-462). REPRODUCE that — do not "fix" the ingest route to a 400.
//   - Defaulted fields. kind absent means "decision" (see DefaultAuditKind), and the five list fields
//     absent mean emptyList(). Left to Go they would be "" and nil.
//   - Unknown keys are ignored (ignoreUnknownKeys = true) — that one is already Go's default, so
//     there is nothing to do, and nothing to add either: a DisallowUnknownFields decoder here would
//     be a behaviour change.
func (e *AuditEvent) UnmarshalJSON(data []byte) error {
	// The four required fields are shadowed as pointers so absent is distinguishable from zero. The
	// outer (depth-0) fields win over the embedded (depth-1) ones under encoding/json's conflict
	// rules, so each JSON key is decoded exactly once, into the pointer.
	var raw struct {
		auditEventJSON
		Principal  *string   `json:"principal"`
		Datasource *string   `json:"datasource"`
		Statement  *string   `json:"statement"`
		Decision   *Decision `json:"decision"`
		Kind       *string   `json:"kind"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var missing []string
	if raw.Principal == nil {
		missing = append(missing, "principal")
	}
	if raw.Datasource == nil {
		missing = append(missing, "datasource")
	}
	if raw.Statement == nil {
		missing = append(missing, "statement")
	}
	if raw.Decision == nil {
		missing = append(missing, "decision")
	}
	if len(missing) > 0 {
		return fmt.Errorf("types: AuditEvent is missing required field(s) [%s]", strings.Join(missing, ", "))
	}

	ev := AuditEvent(raw.auditEventJSON)
	ev.Principal = *raw.Principal
	ev.Datasource = *raw.Datasource
	ev.Statement = *raw.Statement
	ev.Decision = *raw.Decision
	ev.Kind = DefaultAuditKind
	if raw.Kind != nil {
		ev.Kind = *raw.Kind
	}
	emptyIfNil(&ev.Roles)
	emptyIfNil(&ev.EffectiveNamespace)
	emptyIfNil(&ev.MaskedColumns)
	emptyIfNil(&ev.PIITouched)
	emptyIfNil(&ev.ContextTags)

	*e = ev
	return nil
}

// emptyIfNil replaces a nil slice with an empty one so it marshals as [] and never null (INV-A1-4).
func emptyIfNil(s *[]string) {
	if *s == nil {
		*s = []string{}
	}
}
