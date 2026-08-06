package access

import (
	"bytes"
	"encoding/json"
	"errors"
)

// AccessRequest is the wire contract for /api/access-requests**, /api/approvals** and the task
// surfaces — 24 fields (Access.kt:31-48; 06-query-decision.md §5).
//
// One table carries three task origins and two kinds; the DTO carries all of it flat:
//
//   - kind ROLE   — a time-boxed elevation request. `roleId` is required.
//   - kind QUERY  — "run this statement under role R, once". `datasourceId` is required, and
//     `creatorKind` (WORKFLOW | EDITOR | WIRE) says which surface opened it (INV-A6-17).
//
// `sql`, `sqlHash` and `executedBy` are correlated subqueries over `query_result` in reqSelect, each
// `ORDER BY qr.id LIMIT 1` — i.e. the EARLIEST child. A WIRE task has no child, so all three read
// null. Note the asymmetry with A7's [result.Store.AccessFor], which reads the LATEST child: the two
// answer different questions and QueryResultStoreDbTest case 7 pins the difference.
//
// Every timestamp is a Java Instant.toString() string (internal/instant). INV-A1-4: optional fields
// are *T + omitempty, so an unset one is ABSENT rather than null; `executeAs` is a non-null
// `List<String> = emptyList()` and is normalised to [] by MarshalJSON.
type AccessRequest struct {
	ID                   int64   `json:"id"`
	Principal            string  `json:"principal"`
	RoleID               *int64  `json:"roleId,omitempty"`
	RoleName             *string `json:"roleName,omitempty"`
	DatasourceID         *int64  `json:"datasourceId,omitempty"`
	DatasourceName       *string `json:"datasourceName,omitempty"`
	Reason               *string `json:"reason,omitempty"`
	RequestedDurationSec int64   `json:"requestedDurationSec"`
	Status               string  `json:"status"`
	DecidedBy            *string `json:"decidedBy,omitempty"`
	ExecutedBy           *string `json:"executedBy,omitempty"`
	DecidedAt            *string `json:"decidedAt,omitempty"`
	RejectionReason      *string `json:"rejectionReason,omitempty"`
	CreatedAt            string  `json:"createdAt"`
	Kind                 string  `json:"kind"`
	SQL                  *string `json:"sql,omitempty"`
	SQLHash              *string `json:"sqlHash,omitempty"`
	DenyReason           *string `json:"denyReason,omitempty"`
	SourceDecisionID     *int64  `json:"sourceDecisionId,omitempty"`
	Title                *string `json:"title,omitempty"`
	EvaluatedDecision    *string `json:"evaluatedDecision,omitempty"`
	ApprovedAt           *string `json:"approvedAt,omitempty"`
	ExecutingAt          *string `json:"executingAt,omitempty"`
	// ExecutedAt is terminal-success only. An in-flight or failed task keeps this null.
	ExecutedAt  *string  `json:"executedAt,omitempty"`
	ExecuteAs   []string `json:"executeAs"`
	CreatorKind *string  `json:"creatorKind,omitempty"`
}

type accessRequestJSON AccessRequest

// MarshalJSON normalises the nil `executeAs` slice to [] (INV-A1-4 rule 2) and encodes without
// encoding/json's HTML escaping, which kotlinx does not perform — `sql` is raw SQL, so `WHERE a < 5`
// would otherwise come out escaped inside an otherwise-unescaped response body.
func (r AccessRequest) MarshalJSON() ([]byte, error) {
	v := accessRequestJSON(r)
	if v.ExecuteAs == nil {
		v.ExecuteAs = []string{}
	}
	return marshalNoEscape(v)
}

// DefaultKind is `AccessRequest.kind = "ROLE"` — the Kotlin default for a row read back without one.
// The column itself defaults to 'ROLE' too (V5__tasks.sql).
const DefaultKind = "ROLE"

// DefaultRequestedDurationSec is the 3600 that appears as a Kotlin default in five places:
// AccessRequestInput, createQueryRequest's parameter, and hardcoded in createEditorTask and
// createWireTask (Q6 asks whether it is inert for QUERY tasks — it is carried either way).
const DefaultRequestedDurationSec int64 = 3600

// AccessRequestInput is POST /api/access-requests' body (Access.kt:51-54).
//
// ⚠️ RequestedDurationSec is *int64, not int64: Kotlin's default is 3600 and Go's zero value is 0, so
// a plain int64 would silently write 0 into a column the ROLE path reads as the approver's window
// ceiling. nil means "the caller did not say", which is what [Store.CreateRequest] resolves to 3600.
type AccessRequestInput struct {
	RoleID               int64   `json:"roleId"`
	DatasourceID         *int64  `json:"datasourceId,omitempty"`
	Reason               *string `json:"reason,omitempty"`
	RequestedDurationSec *int64  `json:"requestedDurationSec,omitempty"`
}

// Duration resolves the input's window to the Kotlin default when the caller omitted it.
func (i AccessRequestInput) Duration() int64 {
	if i.RequestedDurationSec == nil {
		return DefaultRequestedDurationSec
	}
	return *i.RequestedDurationSec
}

// AccessGrant is a granted role, live until it expires or is revoked (Access.kt:57-61). The grant
// widens the role globally for its window: RoleResolver.resolve reads only principal + role + window,
// so there is no separate elevation path in the decision engine.
type AccessGrant struct {
	ID        int64   `json:"id"`
	Principal string  `json:"principal"`
	RoleID    int64   `json:"roleId"`
	RoleName  string  `json:"roleName"`
	GrantedBy *string `json:"grantedBy,omitempty"`
	GrantedAt string  `json:"grantedAt"`
	ExpiresAt *string `json:"expiresAt,omitempty"`
	RevokedAt *string `json:"revokedAt,omitempty"`
}

// ApproveInput is POST /api/access-requests/{id}/approve's body. A null durationSec means "the window
// the requester asked for".
type ApproveInput struct {
	DurationSec *int64 `json:"durationSec,omitempty"`
}

// RejectInput is POST /api/access-requests/{id}/reject's body.
type RejectInput struct {
	Reason string `json:"reason"`
}

// ErrDuplicatePendingQueryRequest is the port of
// `class DuplicatePendingQueryRequestException : RuntimeException("a pending query request already
// exists for this decision")`.
//
// 🔒 INV-A6-21 — it is raised by the partial-index upsert returning NO row, never by a preceding read.
// A read-then-insert would race; the unique index
// `(source_decision_id) WHERE kind='QUERY' AND status='PENDING' AND source_decision_id IS NOT NULL`
// plus `ON CONFLICT … DO NOTHING RETURNING id` is what makes "one pending request per denied
// decision" atomic.
var ErrDuplicatePendingQueryRequest = errors.New("a pending query request already exists for this decision")

// CreateQueryRequestInput carries createQueryRequest's ten parameters (Access.kt:112-127). Kotlin
// passes them as named arguments with defaults on the last two; Go has neither, so they become a
// struct and the two defaults are resolved by [Store.CreateQueryRequest].
type CreateQueryRequestInput struct {
	Principal    string
	DatasourceID int64
	SQL          string
	DenyReason   *string
	// SourceDecisionID links the task to the denied decision that spawned it. NULL rows are exempt
	// from the pending-per-decision unique index, so a request with no source can never conflict.
	SourceDecisionID  *int64
	Reason            *string
	Title             *string
	EvaluatedDecision *string
	// RoleID is the elevation role R the requester picked (role discovery). NULL = a legacy request
	// with no elevation role (the approver runs as themselves). The FK to app_role validates R.
	RoleID *int64
	// RequestedDurationSec is carried on the shared access_request row and is not consumed by the
	// query-approval flow; it is kept for the column the ROLE-elevation path needs. nil = 3600.
	RequestedDurationSec *int64
}

func (i CreateQueryRequestInput) duration() int64 {
	if i.RequestedDurationSec == nil {
		return DefaultRequestedDurationSec
	}
	return *i.RequestedDurationSec
}

// marshalNoEscape encodes without HTML escaping — see internal/result's copy for why this is
// duplicated rather than imported from internal/types.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
