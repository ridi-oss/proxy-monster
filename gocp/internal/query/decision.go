package query

import (
	"strings"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// DecisionContext is the verdict for a statement WITHOUT executing it: action + masks (output column
// → kind) + context. Port of the 18-field data class at Query.kt:123-164.
//
// 🔒 INV-A6-4 — [DecisionContext.ContextTags] is stamped on EVERY post-derivation decision — ALLOW,
// MASK, DENY (structural AND policy), and passthrough alike — so an audit row carries the attested
// tags whatever the outcome. The ONLY rows that legitimately leave it empty are the two
// pre-derivation early denies (step 4 admission-reject, step 5 deactivated principal), which return
// before any tag is derived.
//
// 🔒 INV-A6-5 — [DecisionContext.OutputColumns] is a DRIFT DETECTOR, not decoration. Approval
// live-result viewing compares it against the stored execute-enforced result to catch catalog drift
// between execute and view: a `SELECT *` re-expansion could otherwise slide a mask onto the wrong
// stored column and leak a value. A mismatch is DENY. (Consumed in A7.)
//
// 🔒 INV-A6-6 — [DecisionContext.UnmaskablePermitted] is a CAPABILITY GRANT, not permission to skip
// masking. A proxy may relay an unmaskable binary result unmasked iff this is true AND the proxy's
// own local feature capability says that relay path is supported. Two independent conditions; the
// control plane owns only one of them.
//
// ⚠️ ReferencedSchemas and SchemaCandidates are Kotlin `Set<String>` built with `buildSet` /
// `toSet()` / `LinkedHashSet` — i.e. INSERTION-ORDERED, deduplicated sets. They are `[]string` here,
// deduplicated in insertion order, because the order is what the Kotlin type promises and a Go map
// would randomise it.
type DecisionContext struct {
	// Action is ALLOW / MASK / DENY.
	Action pb.EnfAction
	// DenyReason is English prose on the wire (F13 — REPRODUCE, do not localise).
	DenyReason *string
	// Masks maps an output column to its mask kind and carries the ordinal.
	Masks []*pb.ColumnMask
	// PIITouched is the column keys whose classification tags contain "pii".
	PIITouched []string
	// EffectiveRoles is the role set the decision ran under.
	EffectiveRoles []string
	// FailedStage is one of: admission | policy | catalog | mask-binding | explain-masked |
	// deprovisioned — or the analyzer's own lowercased stage on the final ALLOW/MASK return.
	FailedStage *string
	// Detail is English prose on the wire (F13 — REPRODUCE, do not localise).
	Detail *string
	// Passthrough means relay verbatim, with no mask binding.
	Passthrough bool
	// Structural marks a NON-grant-overridable deny (INV-A6-13).
	Structural bool
	// RewrittenSQL is ALLOW/MASK only: the `*`-expanded SQL the proxy must send INSTEAD of the
	// client's, so backend column order matches the mask ordinals. Nil = send verbatim.
	RewrittenSQL *string
	// OutputColumns is the analyzer's ordered output names; empty for a passthrough. See INV-A6-5.
	OutputColumns []string
	// ContextTags are the derived tags this decision ran under. See INV-A6-4.
	ContextTags []string
	// UnmaskablePermitted is a MASK-only capability grant. See INV-A6-6.
	UnmaskablePermitted bool
	// SanitizeDiagnostics tells the proxy to strip backend diagnostics to code + severity.
	SanitizeDiagnostics bool
	// CatalogChanging is true when success may change persistent catalog structure.
	CatalogChanging bool
	// CatalogMiss is true when the deny may be caused by absent catalog rows → refetch + retry.
	CatalogMiss bool
	// ReferencedSchemas is the non-temp schemas resolved/touched.
	ReferencedSchemas []string
	// SchemaCandidates is the dotted-identifier candidates for the catalog-miss retry (INV-A6-14).
	SchemaCandidates []string
}

// The six failedStage values. 06-query-decision.md §2 enumerates exactly these; they are spelled out
// as constants so a typo is a compile error rather than an audit row nobody can filter on.
const (
	stageAdmission     = "admission"
	stagePolicy        = "policy"
	stageCatalog       = "catalog"
	stageMaskBinding   = "mask-binding"
	stageExplainMasked = "explain-masked"
	stageDeprovisioned = "deprovisioned"
)

// The deny message constants — Query.kt:723-732.
//
// ⚠️ F13. These are ENGLISH PROSE ON THE WIRE via `denyReason`/`detail`, which sits uneasily with A1
// INV-A1-13 (ApiError codes only). They reach the client as SQLSTATE messages on the wire path, but
// `QueryResponse.denyReason` IS a REST field. REPRODUCE — 06-query-decision.md §8 Q3 is the open
// question; localising here would be a fix during a port.
const (
	editorSessionStatementDeny = "session/transaction statements aren't supported in the SQL editor — it runs each query on a fresh connection"
	// MaskBindDeny is `internal` in the Kotlin (Query.kt:725): decideQuery never raises it — the
	// EnforcementHarness and A7's view gate do, when a required mask fails to bind to a result column.
	MaskBindDeny             = "required mask could not be bound to a result column"
	explainMaskDeny          = "cannot EXPLAIN a query whose columns are masked — request full access or run the query directly"
	systemFunctionDeny       = "dangerous system function is not allowed:"
	systemUtilityDeny        = "utility command is not allowed on this datasource:"
	deactivatedPrincipalDeny = "principal is deprovisioned (deactivated) — access denied"
	catalogConfigurationDeny = "fail-closed: invalid catalog or analyzer namespace configuration"
	wireTaskForbiddenDeny    = "automatic task approval is not permitted for this datasource"
)

// structuralDeny is a NON-grant-overridable deny — Query.kt:734-752.
//
// 🔒 INV-A6-13 — the structural/policy split drives approval eligibility. Structural DENY rows still
// get a decisionId and use the normal audit path, but *the minting path must refuse rows with
// failed_stage = 'admission'* (source comment at Query.kt:818-820). The UI may offer approval for
// those rows, so the refusal has to live server-side. Cross-checked when specifying A7.
//
// Kotlin defaults failedStage to "admission" and contextTags to emptyList(); Go has no default
// arguments, so both are passed explicitly at every one of the 14 call sites. That is deliberate —
// it makes the failedStage of each step readable straight off the call, which is what
// 06-query-decision.md §3's table is diffed against.
func structuralDeny(reason string, roles []string, failedStage string, contextTags []string) DecisionContext {
	return DecisionContext{
		Action:         pb.EnfAction_DENY,
		DenyReason:     strptr(reason),
		Masks:          nil,
		PIITouched:     nil,
		EffectiveRoles: roles,
		FailedStage:    strptr(failedStage),
		Detail:         strptr(reason),
		Passthrough:    false,
		Structural:     true,
		ContextTags:    contextTags,
	}
}

// policyDeny is a missing `datasource.connect` / `sql.<kind>` Cedar grant — the once-per-query gates
// ahead of the catalog/analyzer/column loop. Query.kt:760-777.
//
// Unlike [structuralDeny] this IS grant-overridable — a JIT grant could add a role that holds the
// missing action — and "policy" is a more honest audit failedStage than "admission" for a Cedar deny
// (docs/authz-model.md wants sql_kind + matched policy in the audit trail).
//
// Every policyDeny site runs AFTER context derivation, so callers always pass the request's derived
// tags (INV-A6-4).
func policyDeny(reason string, roles []string, contextTags []string) DecisionContext {
	return DecisionContext{
		Action:         pb.EnfAction_DENY,
		DenyReason:     strptr(reason),
		Masks:          nil,
		PIITouched:     nil,
		EffectiveRoles: roles,
		FailedStage:    strptr(stagePolicy),
		Detail:         strptr(reason),
		Passthrough:    false,
		Structural:     false,
		ContextTags:    contextTags,
	}
}

// passthroughAllow is an ALLOW that relays the client's statement verbatim, with no mask binding.
// Query.kt:801-816. failedStage is nil.
func passthroughAllow(roles []string, detail string, contextTags []string) DecisionContext {
	return DecisionContext{
		Action:         pb.EnfAction_ALLOW,
		DenyReason:     nil,
		Masks:          nil,
		PIITouched:     nil,
		EffectiveRoles: roles,
		FailedStage:    nil,
		Detail:         strptr(detail),
		Passthrough:    true,
		ContextTags:    contextTags,
	}
}

// WireTaskForbiddenDeny is the fail-closed override when a native-wire statement's self-approve is
// forbidden — the Cedar `task.request` or `task.approve` gate on the wire channel denied it, so no
// task is created and nothing relays. Query.kt:785-788.
//
// 🔒 It surfaces as an ORDINARY POLICY DENY (SQLSTATE 42501/1142), never a gRPC status, so the client
// sees the same shape as any other denied statement. failedStage is therefore "policy" and
// structural is false — a JIT grant could still open it.
//
// Exported because A10's wire decide path is its only caller; `internal` in the Kotlin.
func WireTaskForbiddenDeny(roles []string, contextTags []string) DecisionContext {
	return policyDeny(wireTaskForbiddenDeny, roles, contextTags)
}

// grantAction maps an analyzer GrantAction to the Cedar action the datasource gate asks for —
// Query.kt:790-799.
//
// SQL_SELECT / INSERT / UPDATE / DELETE / DDL map. UNSPECIFIED, RESULT_READ and any unrecognised
// value return ok=false, which step 15 turns into `policyDeny("statement kind 'other' is not
// permitted")`.
//
// ⚠️ Go shape: protobuf-go has no UNRECOGNIZED sentinel, so the default arm covers both it and any
// future/unknown enum number. Same reasoning as [KnownOrDeny].
func grantAction(a probepb.GrantAction) (authz.AuthzAction, bool) {
	switch a {
	case probepb.GrantAction_GRANT_ACTION_SQL_SELECT:
		return authz.ActionSQLSelect, true
	case probepb.GrantAction_GRANT_ACTION_SQL_INSERT:
		return authz.ActionSQLInsert, true
	case probepb.GrantAction_GRANT_ACTION_SQL_UPDATE:
		return authz.ActionSQLUpdate, true
	case probepb.GrantAction_GRANT_ACTION_SQL_DELETE:
		return authz.ActionSQLDelete, true
	case probepb.GrantAction_GRANT_ACTION_SQL_DDL:
		return authz.ActionSQLDDL, true
	default:
		// GRANT_ACTION_UNSPECIFIED, GRANT_ACTION_RESULT_READ, and anything unrecognised.
		return "", false
	}
}

// LeaksDiagnosticsOnAllow reports whether a datasource engine can leak a protected value through a
// diagnostic even for an ALLOW query — an error revealing data the statement never referenced.
// Port of `internal val Engine.leaksDiagnosticsOnAllow` (Query.kt:188-189).
//
// PostgreSQL can (the whole-row `DETAIL: Failing row contains (…)`); MySQL cannot (it echoes only the
// operated-on value, and any value-exposing read of a protected column is denied).
//
// 🔒 THE ONE PLACE THIS ENGINE FACT LIVES. [RedactsDiagnostics] branches on the CAPABILITY, never on
// the engine name. It stays in A6 and not in A5's engine.go — the reconciliation report settled that.
//
// ⚠️ LANGUAGE-FORCED DEVIATION: Kotlin states this as an extension property on the proto enum; Go
// cannot declare a method on a type from another package, so it is a package-level function. Kotlin
// extensions compile to static functions taking the receiver first, so this is the same shape.
func LeaksDiagnosticsOnAllow(e datasource.Engine) bool { return e == datasource.EnginePostgres }

// RedactsDiagnostics reports whether a decision's backend diagnostics must be stripped to code +
// severity. Port of `internal fun redactsDiagnostics` (Query.kt:176-179):
//
//	if (!engine.leaksDiagnosticsOnAllow && action == ALLOW) return false
//	return !mayReadUnmasked()
//
// 🔒 INV-A6-15 — redact IFF the diagnostic could carry a protected value (the verdict touches
// protected data, i.e. MASK/DENY, or the engine leaks even on an ALLOW) AND the principal is NOT a
// full-cleartext reader of the datasource. A full-cleartext reader is someone no diagnostic can leak
// a protected value to. Keyed on Cedar authz + engine capability, NEVER a datasource-tag check.
//
// mayReadUnmasked is a THUNK so the Cedar call is skipped when the diagnostic cannot leak anyway —
// that skip is asserted by DiagnosticsRedactionTest case 2 and is why the parameter is a function.
func RedactsDiagnostics(e datasource.Engine, action pb.EnfAction, mayReadUnmasked func() bool) bool {
	if !LeaksDiagnosticsOnAllow(e) && action == pb.EnfAction_ALLOW {
		return false
	}
	return !mayReadUnmasked()
}

// DecisionRecord builds the AuditEvent for a decision — Query.kt:823-844.
//
// 🔒 SHARED, and the sharing is the point. `internal` (not private) in the Kotlin because it is
// reused by the per-connection enforcing decide flow (`decideConnection`, A5) AND by the test-only
// `support/EnforcementHarness.kt`. That reuse is the ONLY reason the audit rows the enforcement
// suites assert on are the audit rows production writes: a harness that re-derived the record would
// prove the harness agrees with itself and nothing else. Every Go consumer calls THIS function —
// including internal/dbtest's EnforcementFixture.Run, which imports internal/query precisely so the
// harness and production cannot drift (see doc.go on why the store seams are structural).
//
// The EnfAction → Decision mapping is FAIL-CLOSED: ALLOW→ALLOW, MASK→MASK, and everything else —
// DENY plus the proto-only ENF_ACTION_UNSPECIFIED and any unrecognised number — → DENY.
func DecisionRecord(
	principal string,
	ds datasource.Datasource,
	sql string,
	clientAddr *string,
	ctx DecisionContext,
	latencyMs int64,
	effectiveNamespace []string,
	channel Channel,
) types.AuditEvent {
	ev := types.NewAuditEvent(principal, ds.Name, sql, decisionOf(ctx.Action))
	ev.Roles = ctx.EffectiveRoles
	ev.ClientAddr = clientAddr
	ev.FailedStage = ctx.FailedStage
	ev.MaskedColumns = maskedColumnNames(ctx.Masks)
	ev.PIITouched = ctx.PIITouched
	ev.LatencyMs = latencyMs
	ev.Detail = ctx.Detail
	ev.EffectiveNamespace = effectiveNamespace
	ev.Channel = strptr(channel.ContextValue())
	ev.ContextTags = ctx.ContextTags
	return ev
}

// decisionOf is decisionRecord's fail-closed EnfAction → Decision mapping (Query.kt:834-839).
func decisionOf(a pb.EnfAction) types.Decision {
	switch a {
	case pb.EnfAction_ALLOW:
		return types.DecisionAllow
	case pb.EnfAction_MASK:
		return types.DecisionMask
	default:
		return types.DecisionDeny
	}
}

// maskedColumnNames is `ctx.masks.map { it.column }`.
func maskedColumnNames(masks []*pb.ColumnMask) []string {
	out := make([]string, 0, len(masks))
	for _, m := range masks {
		out = append(out, m.GetColumn())
	}
	return out
}

// ParseRequesterIp is the wire path's counterpart of A12's `stripToBareIp`, for a proxy-supplied
// `client_addr` arriving as `/1.2.3.4:5432` or `/[::1]:5432`. Port of Query.kt:1230-1237.
//
// Strips a leading `/`, then: a leading `[` ⇒ take between `[` and `]`; exactly one `:` ⇒ take
// before it; else the bare value. Returns nil when nothing is parseable.
//
// ⚠️ DELIBERATELY LAXER than `stripToBareIp` — it parses Netty's always-well-formed
// `SocketAddress.toString()`, not attacker-adjacent header text. A residual non-IP survivor is
// dropped defensively at AuthzContext.ToCedarMap (A2 INV-A2-8). **Do not unify the two without
// re-checking that assumption** (A12 Q4).
func ParseRequesterIp(clientAddr *string) *string {
	if clientAddr == nil {
		return nil
	}
	a := strings.TrimPrefix(strings.TrimSpace(*clientAddr), "/")
	if a == "" {
		return nil
	}
	var out string
	switch {
	case strings.HasPrefix(a, "["):
		// [v6]:port. Kotlin's substringAfter('[').substringBefore(']') — both return the WHOLE
		// remainder when the delimiter is absent, so "[::1" yields "::1".
		out = substringBefore(substringAfter(a, "["), "]")
	case strings.Count(a, ":") == 1:
		out = substringBefore(a, ":") // v4:port
	default:
		out = a // bare v4/v6 (no port)
	}
	if out == "" {
		return nil
	}
	return &out
}

// substringBefore is Kotlin's String.substringBefore: the whole string when the delimiter is absent.
func substringBefore(s, delim string) string {
	if i := strings.Index(s, delim); i >= 0 {
		return s[:i]
	}
	return s
}

// substringAfter is Kotlin's String.substringAfter: the whole string when the delimiter is absent.
func substringAfter(s, delim string) string {
	if i := strings.Index(s, delim); i >= 0 {
		return s[i+len(delim):]
	}
	return s
}

// strptr is the `String` → `String?` lift the DecisionContext fields need. Kotlin's non-null String
// assigned into a nullable field is simply a non-null value, including the EMPTY string — so a blank
// `facts.detail` becomes a pointer to "", never nil. Getting that wrong would drop `detail` from the
// audit row entirely (omitempty on *string only skips nil).
func strptr(s string) *string { return &s }
