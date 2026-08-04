package authz

import "slices"

// AuthzAction is the Cedar action set (docs/authz-model.md), a port of Authz.kt:25-58's
// `enum class AuthzAction(val cedarId: String)`. The value IS the literal Cedar `Action::"..."` id —
// see schema.cedarschema. 02-authz.md §2 enumerates all 24 and every string here is a wire contract.
//
// Modelled as a string enum rather than an int enum with a lookup table: the Kotlin's ONLY observable
// property is cedarId, and making the constant equal to its own cedarId removes the class of bug
// where a reordering silently repoints an action.
type AuthzAction string

// The 24 actions. Order and grouping follow Authz.kt:26-57 exactly.
const (
	// Global admin surfaces, resource System.
	ActionAdminDatasources AuthzAction = "admin.datasources"
	ActionAdminPolicies    AuthzAction = "admin.policies"
	ActionAdminIdentity    AuthzAction = "admin.identity"

	// The task-approval decision, resource Request.
	ActionTaskApprove AuthzAction = "task.approve"

	// Task lifecycle actions replace code-side group-membership / ownership gates. TASK_REQUEST is
	// Datasource-scoped; TASK_READ gates METADATA; TASK_ASSUME gates result DATA; GRANT_REVOKE acts on
	// an AccessGrant. Executing under R remains the same R-scoped TASK_APPROVE authority.
	//
	// 02-authz.md §2: "TASK_READ gates metadata, TASK_ASSUME gates result data. Keep them distinct."
	ActionTaskRequest AuthzAction = "task.request"
	ActionTaskRead    AuthzAction = "task.read"
	ActionTaskAssume  AuthzAction = "task.assume"
	ActionTaskCancel  AuthzAction = "task.cancel"
	ActionTaskDelete  AuthzAction = "task.delete"
	ActionGrantRevoke AuthzAction = "grant.revoke"

	// Credential issuance + management, resource Token.
	ActionTokenMint   AuthzAction = "token.mint"
	ActionTokenList   AuthzAction = "token.list"
	ActionTokenRevoke AuthzAction = "token.revoke"

	// Audit reads, resource AuditRecord or AuditLog.
	ActionAuditRead AuthzAction = "audit.read"

	// Per-column/table/function/utility result visibility.
	ActionResultReadUnmasked AuthzAction = "result.read.unmasked"
	ActionResultReadMasked   AuthzAction = "result.read.masked"

	// The two once-per-query gates, resource Datasource.
	ActionDatasourceConnect AuthzAction = "datasource.connect"
	ActionSQLSelect         AuthzAction = "sql.select"
	ActionSQLInsert         AuthzAction = "sql.insert"
	ActionSQLUpdate         AuthzAction = "sql.update"
	ActionSQLDelete         AuthzAction = "sql.delete"
	ActionSQLDDL            AuthzAction = "sql.ddl"

	// INV-A2-1 — the two exception gates are NOT a hardcoded deny. A statement the analyzer cannot
	// reason about (analyzable=false) or whose result cannot be masked on the chosen path
	// (maskable=false, e.g. EXPLAIN-of-masked) asks its DATASOURCE for this exception instead of being
	// blanket-denied in code. Deny-by-default: no exception policy means DENY, so the production floor
	// is unchanged, but a permissive dev datasource can permit the relay. This is AGENTS.md:136-139's
	// "fail-closed through Cedar, not a hardcoded deny" — coverage gaps are security gaps.
	ActionSQLUnanalyzable AuthzAction = "sql.unanalyzable"
	ActionSQLUnmaskable   AuthzAction = "sql.unmaskable"
)

// CedarID is the literal Cedar Action id. Ported from the Kotlin property of the same name so call
// sites read the same; the identity function is deliberate (see the AuthzAction doc).
func (a AuthzAction) CedarID() string { return string(a) }

// allAuthzActions is the enumeration order of Authz.kt:26-57, used by the vocabulary test to assert
// the port carries all 24 with the exact cedarId strings 02-authz.md §2 tabulates.
var allAuthzActions = []AuthzAction{
	ActionAdminDatasources, ActionAdminPolicies, ActionAdminIdentity,
	ActionTaskApprove, ActionTaskRequest, ActionTaskRead, ActionTaskAssume,
	ActionTaskCancel, ActionTaskDelete, ActionGrantRevoke,
	ActionTokenMint, ActionTokenList, ActionTokenRevoke,
	ActionAuditRead,
	ActionResultReadUnmasked, ActionResultReadMasked,
	ActionDatasourceConnect,
	ActionSQLSelect, ActionSQLInsert, ActionSQLUpdate, ActionSQLDelete, ActionSQLDDL,
	ActionSQLUnanalyzable, ActionSQLUnmaskable,
}

// AllAuthzActions is `AuthzAction.entries` — the whole enum, in declaration order.
//
// 🔒 It exists because 🔒 INV-A11-1 (11-mcp-oauth-management.md:48) CANNOT BE IMPLEMENTED WITHOUT IT:
// `McpCapabilityRegistry.verify()` asserts `inScopeActions + excludedActions == AuthzAction.entries`,
// so that adding an action HERE fails MCP boot until someone classifies it as in-scope or explicitly
// deferred. Kotlin gets the enumeration free from `enum class`; Go does not, and a second hand-written
// copy of the 24 in internal/mcp would make that check assert only that the copy agrees with itself —
// exactly the silent failure the invariant exists to prevent.
//
// It returns a FRESH slice on every call so a caller cannot mutate the package's own list. That
// matters more than usual here: the one production caller iterates it to decide what is authorized.
func AllAuthzActions() []AuthzAction { return slices.Clone(allAuthzActions) }
