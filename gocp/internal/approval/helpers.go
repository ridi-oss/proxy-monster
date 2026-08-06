package approval

import (
	"context"
	"slices"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// IsWorkflowApproval is `private val AccessRequest.isWorkflowApproval` (Approvals.kt:55-56):
// `kind == "QUERY" && creatorKind == "WORKFLOW"`.
//
// 🔒 INV-A7-5 — EVERY id-addressed approval route guards on this. EDITOR and WIRE tasks share the
// `access_request` table but are internal lifecycle records with null SQL and no approver, so they
// must never be listed, fetched, decided, executed or viewed through /api/approvals. The list/inbox
// feeds get the same filter from A6's `ListQueryRequests` (`creator_kind = 'WORKFLOW'`).
//
// Exported — unlike the Kotlin's `private` — because the SSE stream's push filter and internal/app's
// route sweep both need to state the same predicate, and a second copy is how the two drift.
func IsWorkflowApproval(req access.AccessRequest) bool {
	return req.Kind == "QUERY" && req.CreatorKind != nil && *req.CreatorKind == "WORKFLOW"
}

// ---- validateApprovalSource ----------------------------------------------------------------------

// SourceValidation is `enum class SourceValidation` (Approvals.kt:155).
//
// It is a string type, not an iota enum, for the reason internal/query's Channel gives: an iota zero
// value would silently read as the FIRST constant, and here that is OK — the permissive one. A string
// zero value is "", which matches no arm of the caller's switch.
type SourceValidation string

const (
	// SourceOK — the decision exists, is owned by the requester, and is a DENY.
	SourceOK SourceValidation = "OK"
	// SourceNotFound — absent, or owned by someone else. 🔒 A not-owned decision is NOT_FOUND rather
	// than a 403 so no caller can probe for another principal's decision ids.
	SourceNotFound SourceValidation = "NOT_FOUND"
	// SourceNotDeny — the requester's own decision, but it was not denied.
	SourceNotDeny SourceValidation = "NOT_DENY"
)

// ValidateApprovalSource is the fail-closed create-source check (Approvals.kt:158-163).
//
// ⚠️ F15 — it does NOT check `failedStage == "admission"`, and nothing else in the from-denied branch
// does either. `Query.kt:818-820` states that "the minting path must refuse rows with
// failed_stage='admission'", so either the guard was never implemented or it was lost. The PORT
// POLICY is REPRODUCE, so the gap is carried verbatim and pinned by
// TestAnAdmissionStageDenyIsAcceptedAsASourceF15 rather than silently closed here.
// 07-tasks-approvals-results.md §11 Q1 owns the decision.
func ValidateApprovalSource(decision *types.AuditEvent, requestingPrincipal string) SourceValidation {
	switch {
	case decision == nil || decision.Principal != requestingPrincipal:
		return SourceNotFound
	case decision.Decision != types.DecisionDeny:
		return SourceNotDeny
	default:
		return SourceOK
	}
}

// ---- validateProactiveCompose ---------------------------------------------------------------------

// ValidateProactiveCompose is the fail-closed proactive-compose input check (Approvals.kt:292-298).
// It returns the FIRST missing/blank field name in the order `datasourceId`, `sql`, `title`,
// `reason`, or "" when the input is valid.
//
// ⚠️ THE ORDER IS THE CONTRACT, not an implementation detail: the response is
// `common.field_required{fields: <name>}` and the console highlights that one field, so an
// incomplete form must name the same field the Kotlin names.
//
// "" rather than a *string for "valid": Kotlin returns `String?` and every field name is non-empty,
// so the empty string is unambiguous and spares every call site a nil check.
func ValidateProactiveCompose(datasourceID *int64, sql, title, reason *string) string {
	switch {
	case datasourceID == nil:
		return "datasourceId"
	case isNilOrBlank(sql):
		return "sql"
	case isNilOrBlank(title):
		return "title"
	case isNilOrBlank(reason):
		return "reason"
	default:
		return ""
	}
}

// isNilOrBlank is Kotlin's `String?.isNullOrBlank()`, over [engine.IsBlank] so the port has one
// definition of "blank".
func isNilOrBlank(s *string) bool { return s == nil || engine.IsBlank(*s) }

// ---- discoverRoles ----------------------------------------------------------------------------

// Role is the two fields [DiscoverRoles] reads off `policyStore.listRoles()`.
//
// It is a local struct rather than internal/policy's Role for the reason internal/query's doc.go
// gives for MaskFn: naming policy.Role here would make internal/approval import internal/policy, and
// the wiring's three-line conversion is cheaper than the coupling.
type Role struct {
	ID   int64
	Name string
}

// RoleLister is `policyStore.listRoles()` as discovery consumes it.
type RoleLister func(ctx context.Context) ([]Role, error)

// DecidePreview is discovery's `decide: (roles: Set<String>) -> DecisionContext` (Approvals.kt:100).
//
// It returns an error the Kotlin expresses by letting `decideQuery` throw: a store failure inside the
// preview is a 500, not a "role not offered".
type DecidePreview func(roles []string) (query.DecisionContext, error)

// DiscoverRoles is `fun discoverRoles(ownRoles, allRoles, decide)` (Approvals.kt:97-114).
//
//  1. `baseline = decide(ownRoles)`; note `baselineMasked` and whether the baseline DENIED.
//  2. For every role the requester does NOT already hold: `underR = decide({role.name})`.
//     DENY ⇒ skip. `unmasked = (baselineMasked − underR's masked columns).sorted()`.
//     Offer iff `baselineDenied || unmasked is non-empty` — R must return STRICTLY MORE; a role
//     returning exactly what the requester already sees is noise.
//
// 🔒 INV-A7-12 — PREVIEW PARITY: each candidate is previewed ALONE, never unioned with the
// requester's own roles, because execute-under-R runs with `assumeRoles = {R}` alone (INV-A7-1). If
// discovery previewed `ownRoles ∪ {R}`, a role that only reads more THROUGH a column ownRoles
// already unlocks — a masked-write-payload gate, or a role-scoped `unless`/`when` keyed off the
// union — could preview ALLOW and then DENY at execute, offering a role the requester cannot run.
// Only the baseline decision and the already-held filter stay keyed on the requester's own roles.
//
// ⚠️ INV-A7-13 — the parity is over the ROLE SET only; the channel/context axis is knowingly open.
// Discovery runs on the EDITOR channel in the REQUESTER's live HTTP context, whereas execute-under-R
// runs on WORKFLOW_EXECUTOR in the APPROVER's context — and the approver is not known at discovery
// time. A policy conditioned on `context.channel` or on a `requester_ip`-derived tag can therefore
// still make an offered R deny at execute, or hide an R that would in fact run. Discovery is a
// best-effort preview, not a promise of the execute verdict. Do NOT "fix" this by previewing on
// WORKFLOW_EXECUTOR: that changes behaviour without resolving the unknown-approver problem.
//
// `decide` MUST be side-effect-free — discovery is a dry-run and writes no audit row.
func DiscoverRoles(ownRoles []string, allRoles []Role, decide DecidePreview) (DiscoverRolesResponse, error) {
	baseline, err := decide(ownRoles)
	if err != nil {
		return DiscoverRolesResponse{}, err
	}
	baselineMasked := maskedColumnSet(baseline.Masks)
	baselineDenied := baseline.Action == pb.EnfAction_DENY

	held := make(map[string]bool, len(ownRoles))
	for _, r := range ownRoles {
		held[r] = true
	}

	options := []RoleOption{}
	for _, role := range allRoles {
		if held[role.Name] { // Kotlin's `filterNot { it.name in ownRoles }`
			continue
		}
		// 🔒 INV-A7-12 — R ALONE.
		underR, err := decide([]string{role.Name})
		if err != nil {
			return DiscoverRolesResponse{}, err
		}
		if underR.Action == pb.EnfAction_DENY {
			continue // R doesn't even let Q run → not an option
		}
		underRMasked := maskedColumnSet(underR.Masks)
		unmasked := make([]string, 0, len(baselineMasked))
		for column := range baselineMasked {
			if !underRMasked[column] {
				unmasked = append(unmasked, column)
			}
		}
		// Kotlin's `.sorted()`. It also makes the Go map's randomised iteration order irrelevant.
		slices.Sort(unmasked)
		if baselineDenied || len(unmasked) > 0 {
			options = append(options, RoleOption{RoleID: role.ID, RoleName: role.Name, UnmasksColumns: unmasked})
		}
	}
	return DiscoverRolesResponse{BaselineAllowed: !baselineDenied, Options: options}, nil
}

// maskedColumnSet is `ctx.masks.map { it.column }.toSet()`.
func maskedColumnSet(masks []*pb.ColumnMask) map[string]bool {
	out := make(map[string]bool, len(masks))
	for _, m := range masks {
		out[m.GetColumn()] = true
	}
	return out
}

// ---- decideResultView ---------------------------------------------------------------------------

// ResultViewDecision is `internal sealed class ResultViewDecision` (Approvals.kt:165-174), flattened
// into one struct because Go has no sealed classes and a two-type interface would make every call
// site a type switch over an interface only this package can implement.
//
// DeniedReason is the discriminant: non-nil ⇒ Denied, nil ⇒ Allowed. A bare bool would allow the
// nonsense state "denied with no reason", which is exactly the state the route logs.
type ResultViewDecision struct {
	// DeniedReason is English prose, logged and never put on the wire — the route answers
	// `approval.result_view_denied` (INV-A1-13).
	DeniedReason *string
	Columns      []string
	Rows         [][]*string
	// MaskedColumns are the columns THIS VIEW masked.
	//
	// 🔒 INV-A7-16 — named from the BOUND indices, not from `ctx.masks`. Binding is what actually
	// rewrote a cell, so a mask the decision asked for but could not bind can never be reported as
	// applied. (An unbound mask denies at gate 7, so the two agree today — reading the binding keeps
	// them agreeing if that ever changes.)
	MaskedColumns []string
}

// IsDenied reports whether the view was refused.
func (d ResultViewDecision) IsDenied() bool { return d.DeniedReason != nil }

func viewDenied(reason string) ResultViewDecision { return ResultViewDecision{DeniedReason: &reason} }

// The seven deny reasons, verbatim from Approvals.kt:205-241. They are constants so the two callers
// (approval view and editor view) and their tests cannot drift on the string.
const (
	denyNoChildSQL      = "saved result child has no SQL"
	denyNoExecuteAs     = "approval request has no execute-as roles"
	denyViewDecision    = "view decision denied"
	denyPassthrough     = "stored query result re-decided as passthrough"
	denyColumnDrift     = "stored result columns no longer match the live query decision"
	denyRowWidthDrift   = "stored result row width does not match its columns"
	denyUnboundViewMask = "required view mask could not be bound"
)

// ResultViewInput is `decideResultView`'s parameter list minus the store seams, which [Decider]
// holds. Kotlin passes fifteen positional arguments with two defaults; a named-field struct makes the
// call sites diffable against the source and answers "did anyone bind positionally" by construction.
type ResultViewInput struct {
	Viewer string
	Req    access.AccessRequest
	// ChildSQL is the statement of the SAME result child whose bytes are in Decrypted
	// (result.ResultAccess.SQL) — NOT the task's first-child `req.sql`, which diverges once a task
	// holds plural children. Re-deciding the released child's own statement keeps the masking verdict
	// bound to those bytes (INV-A7-9).
	ChildSQL      *string
	DS            datasource.Datasource
	Decrypted     result.DecryptedResult
	CallerContext authz.AuthzContext
	// Channel is WORKFLOW_VIEWER for an approval view and EDITOR for the editor view, so the editor's
	// re-decision matches how runOnSession enforced the run.
	Channel query.Channel
}

// DecideResultView re-evaluates a stored execute-under-R result for the ACTUAL viewer in their live
// HTTP context — `internal fun decideResultView` (Approvals.kt:186-256).
//
// The store holds R's execution-enforced output; this re-applies R's masks for the viewer's current
// context, narrowing further where it requires. 🔒 INV-A7-3 — it can only NARROW, never widen: the
// stored bytes are already R-enforced and nothing here reads anything else.
//
// # Every uncertainty is a deny — seven gates, in order
//
//  1. no child SQL
//  2. empty {R} (🔒 INV-A7-2 — no role to re-decide under, and there is no raw-snapshot side channel)
//  3. the live decideQuery under `providedRoles = {R}` returned DENY
//  4. the re-decision came back PASSTHROUGH (nothing to bind masks to)
//  5. 🔒 INV-A7-14 — OUTPUT-COLUMN DRIFT: size mismatch, or any positional mismatch compared
//     case-insensitively. This is A6 INV-A6-5's consumer: a `SELECT *` re-expansion between execute
//     and view would slide a mask onto the wrong stored column and leak a value.
//  6. row-width drift
//  7. a required mask could not be bound
//
// The error return is for a store/engine failure inside decideQuery — a 500, exactly as the Kotlin's
// throw is.
func (d *Decider) DecideResultView(ctx context.Context, in ResultViewInput) (ResultViewDecision, error) {
	// GATE 1.
	if in.ChildSQL == nil {
		return viewDenied(denyNoChildSQL), nil
	}
	// GATE 2 — INV-A7-2.
	roles := in.Req.ExecuteAs
	if len(roles) == 0 {
		return viewDenied(denyNoExecuteAs), nil
	}

	catalog, err := d.Datasources.Catalog(ctx, in.DS.ID)
	if err != nil {
		return ResultViewDecision{}, err
	}
	provided := roles
	decision, err := d.decide(ctx, query.DecideQueryInput{
		Principal:            in.Viewer,
		Datasource:           in.DS,
		SQL:                  *in.ChildSQL,
		Channel:              in.Channel,
		Catalog:              catalog,
		MaskFns:              d.MaskFns,
		UserGroups:           d.UserGroups,
		Roles:                d.Roles,
		Authz:                d.Authz,
		ProvidedRoles:        &provided,
		Context:              in.CallerContext,
		SystemClassification: d.SystemClassification,
	})
	if err != nil {
		return ResultViewDecision{}, err
	}

	// GATE 3. `ctx.denyReason ?: ctx.detail ?: "view decision denied"`.
	if decision.Action == pb.EnfAction_DENY {
		reason := denyViewDecision
		switch {
		case decision.DenyReason != nil:
			reason = *decision.DenyReason
		case decision.Detail != nil:
			reason = *decision.Detail
		}
		return viewDenied(reason), nil
	}
	// GATE 4.
	if decision.Passthrough {
		return viewDenied(denyPassthrough), nil
	}
	// GATE 5 — INV-A7-14. Positional AND case-insensitive.
	if len(decision.OutputColumns) != len(in.Decrypted.Columns) {
		return viewDenied(denyColumnDrift), nil
	}
	for i, decided := range decision.OutputColumns {
		if !strings.EqualFold(decided, in.Decrypted.Columns[i]) {
			return viewDenied(denyColumnDrift), nil
		}
	}
	// GATE 6.
	for _, row := range in.Decrypted.Rows {
		if len(row) != len(in.Decrypted.Columns) {
			return viewDenied(denyRowWidthDrift), nil
		}
	}
	// GATE 7.
	binding := engine.BindMasks(decision.Masks, len(in.Decrypted.Columns))
	if !binding.AllBound() {
		return viewDenied(denyUnboundViewMask), nil
	}

	rows := make([][]*string, 0, len(in.Decrypted.Rows))
	for _, row := range in.Decrypted.Rows {
		out := make([]*string, len(row))
		for index, value := range row {
			// 🔒 INV-A7-15 — the null check is on the KIND, never on the result. `Masking.apply`
			// returns NULL for a full redaction (kind NULL), so collapsing this to
			// `ApplyMaskKind(value, kind) ?: value` would fall a redacted-to-null cell back to the
			// CLEARTEXT value. Do not "simplify" it.
			kind, masked := binding.ByIndex[index]
			if !masked {
				out[index] = value
				continue
			}
			out[index] = engine.ApplyMaskKind(value, kind)
		}
		rows = append(rows, out)
	}

	// 🔒 INV-A7-16 — from the BOUND indices, sorted, mapped through the STORED column names.
	indices := make([]int, 0, len(binding.ByIndex))
	for index := range binding.ByIndex {
		indices = append(indices, index)
	}
	slices.Sort(indices)
	maskedColumns := make([]string, 0, len(indices))
	for _, index := range indices {
		maskedColumns = append(maskedColumns, in.Decrypted.Columns[index])
	}

	return ResultViewDecision{Columns: in.Decrypted.Columns, Rows: rows, MaskedColumns: maskedColumns}, nil
}
