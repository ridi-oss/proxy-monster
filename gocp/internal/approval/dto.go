package approval

import (
	"encoding/json"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---- POST /api/approvals -----------------------------------------------------------------------

// DefaultRequestedDurationSec is `CreateApprovalInput.requestedDurationSec = 3600`
// (Approvals.kt:40). It is carried on the shared access_request row and is NOT consumed by the
// query-approval flow — a QUERY approval is executed under R by an approver, never re-run by the
// requester for a window — but the column is shared with the ROLE path, so the default is real.
const DefaultRequestedDurationSec int64 = 3600

// CreateApprovalInput is POST /api/approvals' body (Approvals.kt:28-41).
//
// ⚠️ Two Kotlin defaults have no encoding/json equivalent, so decode through [DecodeCreateApproval],
// never json.Unmarshal:
//
//   - `reason: String = ""` — harmless (Go's zero value is also ""), carried for symmetry;
//   - `requestedDurationSec: Long = 3600` — NOT harmless. Go's zero value is 0, and a plain
//     json.Unmarshal of a body that omits the field would write 0 into the shared duration column.
//
// Same shape internal/query's DecodeQueryRequest established for `maxRows`.
type CreateApprovalInput struct {
	SourceDecisionID *int64  `json:"sourceDecisionId,omitempty"`
	DatasourceID     *int64  `json:"datasourceId,omitempty"`
	SQL              *string `json:"sql,omitempty"`
	Title            *string `json:"title,omitempty"`
	Reason           string  `json:"reason"`
	// RoleID is the elevation role R the requester picked from role discovery. NULL = no elevation
	// role; execute-under-R keys off the stored `access_request.role_id`.
	RoleID               *int64 `json:"roleId,omitempty"`
	RequestedDurationSec int64  `json:"requestedDurationSec"`
}

// DecodeCreateApproval applies the `requestedDurationSec = 3600` default.
//
// ⚠️ An explicit `"requestedDurationSec": 0` is NOT the default in Kotlin (the field is present, so
// the default does not apply) but is indistinguishable from an absent field after unmarshalling into
// a plain int64. The divergence is unobservable on this route: the QUERY approval flow never reads
// the column back, and a 0-second window on the ROLE path is not reachable from here.
func DecodeCreateApproval(b []byte) (CreateApprovalInput, error) {
	in := CreateApprovalInput{RequestedDurationSec: DefaultRequestedDurationSec}
	if err := json.Unmarshal(b, &in); err != nil {
		return CreateApprovalInput{}, err
	}
	if in.RequestedDurationSec == 0 {
		in.RequestedDurationSec = DefaultRequestedDurationSec
	}
	return in, nil
}

// CreateApprovalResponse is the 201 body (Approvals.kt:46).
//
// `wouldAllow` is the COMPOSE-TIME preview verdict, not a promise: the from-denied branch always
// reports false, and the proactive branch reports whether the server-side EDITOR-channel analysis
// came back ALLOW.
type CreateApprovalResponse struct {
	Request    access.AccessRequest `json:"request"`
	WouldAllow bool                 `json:"wouldAllow"`
}

// ---- POST /api/approvals/discover-roles ---------------------------------------------------------

// DiscoverRolesRequest is the discovery body (Approvals.kt:44).
type DiscoverRolesRequest struct {
	DatasourceID int64  `json:"datasourceId"`
	SQL          string `json:"sql"`
}

// RoleOption is one offered elevation role (Approvals.kt:62). UnmasksColumns are the columns Q
// returns UNMASKED under this role that the requester's own roles MASK — the "returns more" signal
// that ranks it.
type RoleOption struct {
	RoleID         int64    `json:"roleId"`
	RoleName       string   `json:"roleName"`
	UnmasksColumns []string `json:"unmasksColumns"`
}

type roleOptionJSON RoleOption

// MarshalJSON normalises `unmasksColumns` to [] (INV-A1-4). A role offered because the baseline was
// DENIED legitimately unmasks nothing, so the empty case is reachable on every response.
func (o RoleOption) MarshalJSON() ([]byte, error) {
	v := roleOptionJSON(o)
	if v.UnmasksColumns == nil {
		v.UnmasksColumns = []string{}
	}
	return types.MarshalWire(v)
}

// DiscoverRolesResponse is the discovery result (Approvals.kt:65).
type DiscoverRolesResponse struct {
	BaselineAllowed bool         `json:"baselineAllowed"`
	Options         []RoleOption `json:"options"`
}

type discoverRolesResponseJSON DiscoverRolesResponse

// MarshalJSON normalises `options` to [] (INV-A1-4) — the commonest response on a well-scoped
// deployment is "nothing to offer", and the console renders `.length` on it.
func (r DiscoverRolesResponse) MarshalJSON() ([]byte, error) {
	v := discoverRolesResponseJSON(r)
	if v.Options == nil {
		v.Options = []RoleOption{}
	}
	return types.MarshalWire(v)
}

// ---- GET /api/approvals/{id} ---------------------------------------------------------------------

// ApprovalDetail is the detail body (Approvals.kt:116-123).
//
// 🔒 INV-A7-23 — `result` is REDACTED (rowCount cleared, columns emptied) when the caller cannot
// assume R. Both are cardinality/existence oracles the assume gate must close, so a caller with only
// `task.read` sees status/executor/timestamps/error and nothing about the result's shape.
type ApprovalDetail struct {
	Request access.AccessRequest `json:"request"`
	// CanDecide is `status == "PENDING" && isApprover`.
	CanDecide bool `json:"canDecide"`
	// Result is the LATEST child's metadata; absent when there is no child or no result store.
	Result *result.QueryResultMeta `json:"result,omitempty"`
	// CanExecute mirrors /execute's gates exactly, so a merely-eligible approver who did not approve
	// THIS task gets no Run affordance that would just 403.
	CanExecute bool `json:"canExecute"`
	CanCancel  bool `json:"canCancel"`
}

// ---- the result view ----------------------------------------------------------------------------

// QueryResultView is the decrypted rows plus their metadata (Approvals.kt:133-139).
//
// 🔒 INV-A7-4 — `decision` and `maskedColumns` describe the LIVE VIEW re-decision, not the execution
// that stored the bytes: the viewer's own context can narrow an execution's ALLOW to a MASK. Without
// them a console showing rows has nothing to label them with but a guess.
type QueryResultView struct {
	Meta          result.QueryResultMeta `json:"meta"`
	Columns       []string               `json:"columns"`
	Rows          [][]*string            `json:"rows"`
	Decision      types.Decision         `json:"decision"`
	MaskedColumns []string               `json:"maskedColumns"`
}

type queryResultViewJSON QueryResultView

// MarshalJSON normalises the three list fields to [] (INV-A1-4). `rows` is customer data, so this
// goes through types.MarshalWire for the same non-escaping reason internal/query's QueryResponse
// does — `WHERE a < 5` in a cell must not come back as `<`.
func (v QueryResultView) MarshalJSON() ([]byte, error) {
	out := queryResultViewJSON(v)
	if out.Columns == nil {
		out.Columns = []string{}
	}
	if out.Rows == nil {
		out.Rows = [][]*string{}
	}
	if out.MaskedColumns == nil {
		out.MaskedColumns = []string{}
	}
	return types.MarshalWire(out)
}

// ExecuteApprovalResponse is /execute's 202 ack (Approvals.kt:142). `decision` is only ever
// "EXECUTING" — completion is observed by polling the detail/result endpoints.
type ExecuteApprovalResponse struct {
	Decision string `json:"decision"`
}

// ---- the editor session surface (Query.kt:880-900) -----------------------------------------------

// OpenEditorSessionInput is POST /api/editor/sessions' body.
type OpenEditorSessionInput struct {
	DatasourceID int64 `json:"datasourceId"`
}

// EditorSessionOpened is its 200 body.
type EditorSessionOpened struct {
	SessionID string `json:"sessionId"`
}

// EditorSubmitResponse is the async submit ack: the born-APPROVED EDITOR task and its single result
// child (task:child 1:1). No rows inline.
type EditorSubmitResponse struct {
	TaskID  int64 `json:"taskId"`
	ChildID int64 `json:"childId"`
}

// EditorTaskStatus is the poll body: the parent task status plus its child result metadata. Rows stay
// behind /result.
type EditorTaskStatus struct {
	TaskID int64                   `json:"taskId"`
	Status string                  `json:"status"`
	Result *result.QueryResultMeta `json:"result,omitempty"`
}

// ---- the SSE stream (TaskCompletionHub.kt:14) ----------------------------------------------------

// TaskEvent is one task's terminal transition, pushed to the parties watching it. Status is the
// task's new state — EXECUTED, FAILED or CANCELLED.
type TaskEvent struct {
	TaskID int64  `json:"taskId"`
	Status string `json:"status"`
}
