package mcp

import (
	"fmt"
	"slices"
	"sort"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
)

// ---------------------------------------------------------------------------------------------
// A11 §1 — `McpCapabilityRegistry.kt`: the one authoritative, complete MCPA tool/action/scope catalog.
// ---------------------------------------------------------------------------------------------

// Classification is `enum class CapabilityClassification { READ, WRITE }`.
//
// It decides three separate things and they are not interchangeable: which OAuth scope a tool needs,
// whether the tool goes through [MutationExecutor] (and therefore whether it is idempotency-keyed and
// transactionally audited), and — 🔒 INV-A11-14 — whether a SUCCESSFUL call writes an audit row.
type Classification string

const (
	// ClassificationRead is a tool that reads the control-plane store. Scope `mcp:read`, and a
	// successful call writes NO audit row.
	ClassificationRead Classification = "READ"
	// ClassificationWrite is a tool that mutates. Scope is its domain's write scope, and every call
	// writes an audit row — ALLOW, IDEMPOTENT_REPLAY or a failure outcome.
	ClassificationWrite Classification = "WRITE"
)

// The four MCPA scopes. Every READ tool takes [ScopeRead]; each WRITE tool takes its domain's.
//
// They are constants rather than literals because [Capability.RequiredScope] is compared against the
// token's scope set, echoed in the `mcp.insufficient_scope` error's `{scope}` param, emitted in the
// `WWW-Authenticate` challenge and advertised in `scopes_supported` — four wire surfaces off one
// string.
const (
	ScopeRead             = "mcp:read"
	ScopeDatasourcesWrite = "mcp:datasources:write"
	ScopePoliciesWrite    = "mcp:policies:write"
	ScopeIdentityWrite    = "mcp:identity:write"
)

// ToolAnnotations is `data class McpToolAnnotations(readOnlyHint, destructiveHint)`.
//
// Only two of the four MCP annotation hints are stored: `idempotentHint` and `openWorldHint` are
// DERIVED at advertisement time (see [Capability.Annotations]'s use in newServer) rather than
// declared, exactly as in the Kotlin.
type ToolAnnotations struct {
	ReadOnlyHint    bool
	DestructiveHint bool
}

// Capability is `data class McpCapability(toolName, action, resource = System, requiredScope,
// classification, annotations)`.
//
// ⚠️ `Resource` is `AuthzResource.System` for ALL 38 tools and the Kotlin declares it as a default
// parameter no call site overrides. It is kept as a field rather than folded into a constant because
// A11 §3's Q1 is precisely whether the two classification tools should carry their Datasource
// instead — the field is where that answer would land.
type Capability struct {
	ToolName       string
	Action         authz.AuthzAction
	Resource       authz.AuthzResource
	RequiredScope  string
	Classification Classification
	Annotations    ToolAnnotations
}

// InScopeActions is the three Cedar actions the MCP management surface exposes.
var InScopeActions = []authz.AuthzAction{
	authz.ActionAdminDatasources,
	authz.ActionAdminPolicies,
	authz.ActionAdminIdentity,
}

// ExcludedActions is the 21 Cedar actions explicitly DEFERRED from the MCP surface — task lifecycle,
// token, audit, result-read and every `sql.*` action, all of which are RUNTIME authorization (the
// approval / token / query routes) rather than management tools.
//
// 🔒 INV-A11-1 lives on this list being exhaustive with [InScopeActions]. The order below is
// McpCapabilityRegistry.kt:30-54's, TASK_APPROVE first, including its out-of-sequence position ahead
// of the comment that explains the rest.
var ExcludedActions = []authz.AuthzAction{
	authz.ActionTaskApprove,
	// Task lifecycle + token actions are runtime authorization (the approval / token routes), not
	// MCP-management tools — deferred like the other non-management actions below.
	authz.ActionTaskRequest,
	authz.ActionTaskRead,
	authz.ActionTaskAssume,
	authz.ActionTaskCancel,
	authz.ActionTaskDelete,
	authz.ActionGrantRevoke,
	authz.ActionTokenMint,
	authz.ActionTokenList,
	authz.ActionTokenRevoke,
	authz.ActionAuditRead,
	authz.ActionResultReadUnmasked,
	authz.ActionResultReadMasked,
	authz.ActionDatasourceConnect,
	authz.ActionSQLSelect,
	authz.ActionSQLInsert,
	authz.ActionSQLUpdate,
	authz.ActionSQLDelete,
	authz.ActionSQLDDL,
	authz.ActionSQLUnanalyzable,
	authz.ActionSQLUnmaskable,
}

// read is `private fun read(name, action)` — every READ tool takes `mcp:read` and is
// readOnly/non-destructive.
func read(name string, action authz.AuthzAction) Capability {
	return Capability{
		ToolName: name, Action: action, Resource: authz.ResourceSystem{},
		RequiredScope: ScopeRead, Classification: ClassificationRead,
		Annotations: ToolAnnotations{ReadOnlyHint: true, DestructiveHint: false},
	}
}

// write is `private fun write(name, action, scope, destructive = false)`.
func write(name string, action authz.AuthzAction, scope string, destructive bool) Capability {
	return Capability{
		ToolName: name, Action: action, Resource: authz.ResourceSystem{},
		RequiredScope: scope, Classification: ClassificationWrite,
		Annotations: ToolAnnotations{ReadOnlyHint: false, DestructiveHint: destructive},
	}
}

// Entries is the 38-tool catalog, in McpCapabilityRegistry.kt:66-109's order.
//
// ⚠️ THE ORDER IS WIRE-VISIBLE. `tools/list` advertises them in this order, so a reshuffle is a
// (harmless but real) change to what every client sees. The grouping is the Kotlin's: datasources,
// policies, roles+assignments, users+groups, mask functions.
//
// ⚠️ `list_roles` requires ADMIN_POLICIES here while A9's REST `GET /api/roles` is gated only
// `requireApi` — THE SAME DATA AT TWO AUTHORITY LEVELS, by transport. That is 00-INDEX.md F5 and it is
// REPRODUCED; do not "align" one to the other.
var Entries = []Capability{
	read("list_datasources", authz.ActionAdminDatasources),
	read("get_datasource_liveness", authz.ActionAdminDatasources),
	read("browse_catalog", authz.ActionAdminDatasources),
	read("get_table_detail", authz.ActionAdminDatasources),
	read("list_column_tags", authz.ActionAdminDatasources),
	write("set_column_classification", authz.ActionAdminDatasources, ScopeDatasourcesWrite, false),
	write("clear_column_classification", authz.ActionAdminDatasources, ScopeDatasourcesWrite, true),

	read("list_policies", authz.ActionAdminPolicies),
	read("get_policy", authz.ActionAdminPolicies),
	read("validate_policy", authz.ActionAdminPolicies),
	read("get_policy_schema", authz.ActionAdminPolicies),
	write("create_policy", authz.ActionAdminPolicies, ScopePoliciesWrite, false),
	write("update_policy", authz.ActionAdminPolicies, ScopePoliciesWrite, false),
	write("enable_policy", authz.ActionAdminPolicies, ScopePoliciesWrite, false),
	write("disable_policy", authz.ActionAdminPolicies, ScopePoliciesWrite, false),
	write("delete_policy", authz.ActionAdminPolicies, ScopePoliciesWrite, true),

	read("list_roles", authz.ActionAdminPolicies),
	write("create_role", authz.ActionAdminPolicies, ScopePoliciesWrite, false),
	write("update_role", authz.ActionAdminPolicies, ScopePoliciesWrite, false),
	write("delete_role", authz.ActionAdminPolicies, ScopePoliciesWrite, true),
	read("list_role_assignments", authz.ActionAdminIdentity),
	write("assign_role", authz.ActionAdminIdentity, ScopeIdentityWrite, false),
	write("unassign_role", authz.ActionAdminIdentity, ScopeIdentityWrite, true),

	read("list_users", authz.ActionAdminIdentity),
	write("create_user", authz.ActionAdminIdentity, ScopeIdentityWrite, false),
	write("update_user", authz.ActionAdminIdentity, ScopeIdentityWrite, false),
	write("deprovision_user", authz.ActionAdminIdentity, ScopeIdentityWrite, true),
	read("list_groups", authz.ActionAdminIdentity),
	write("create_group", authz.ActionAdminIdentity, ScopeIdentityWrite, false),
	write("update_group", authz.ActionAdminIdentity, ScopeIdentityWrite, false),
	write("delete_group", authz.ActionAdminIdentity, ScopeIdentityWrite, true),
	write("add_group_member", authz.ActionAdminIdentity, ScopeIdentityWrite, false),
	write("remove_group_member", authz.ActionAdminIdentity, ScopeIdentityWrite, true),
	write("set_group_roles", authz.ActionAdminIdentity, ScopeIdentityWrite, false),

	read("list_mask_fns", authz.ActionAdminPolicies),
	write("create_mask_fn", authz.ActionAdminPolicies, ScopePoliciesWrite, false),
	write("update_mask_fn", authz.ActionAdminPolicies, ScopePoliciesWrite, false),
	write("delete_mask_fn", authz.ActionAdminPolicies, ScopePoliciesWrite, true),
}

// ByName is `entries.associateBy(McpCapability::toolName)`.
//
// ⚠️ Kotlin's associateBy SILENTLY KEEPS THE LAST on a duplicate key, which is why `verify()` compares
// `entries.size == byName.size` rather than trusting the map. Go's map literal built in a loop does
// the same thing, so the same assertion is the same check. Do not replace it with a compile-time
// construction that would make the check tautological.
var ByName = buildByName()

func buildByName() map[string]Capability {
	m := make(map[string]Capability, len(Entries))
	for _, c := range Entries {
		m[c.ToolName] = c
	}
	return m
}

// SupportedScopes is `entries.map(McpCapability::requiredScope).toSortedSet()` — the distinct scopes,
// SORTED, which is what `scopes_supported` in the protected-resource metadata advertises. Sorted, not
// declaration-ordered: `toSortedSet()` is a TreeSet.
var SupportedScopes = buildSupportedScopes()

func buildSupportedScopes() []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, c := range Entries {
		if _, ok := seen[c.RequiredScope]; ok {
			continue
		}
		seen[c.RequiredScope] = struct{}{}
		out = append(out, c.RequiredScope)
	}
	sort.Strings(out)
	return out
}

// ApprovedToolNames is the frozen, reviewed tool surface.
//
// 🔒 INV-A11-2 — IT IS A HARDCODED DUPLICATE OF [Entries], DELIBERATELY. `verify()`'s last assertion
// is `byName.keys == approvedToolNames`, so adding a tool to Entries ALONE fails boot: the tool
// surface is a reviewed artifact and the duplication IS the review gate.
//
// 🔴 DO NOT "DRY" THIS AWAY. Deriving it from Entries would compile, pass every test, and delete the
// only mechanism that forces a human to look at a new MCP tool before it ships. The list below is
// McpCapabilityRegistry.kt:114-122 verbatim, in its own (declaration-following but independently
// written) order.
var ApprovedToolNames = []string{
	"list_datasources", "get_datasource_liveness", "browse_catalog", "get_table_detail", "list_column_tags",
	"set_column_classification", "clear_column_classification", "list_policies", "get_policy", "validate_policy",
	"get_policy_schema", "create_policy", "update_policy", "enable_policy", "disable_policy", "delete_policy",
	"list_roles", "create_role", "update_role", "delete_role", "list_role_assignments", "assign_role",
	"unassign_role", "list_users", "create_user", "update_user", "deprovision_user", "list_groups", "create_group",
	"update_group", "delete_group", "add_group_member", "remove_group_member", "set_group_roles", "list_mask_fns",
	"create_mask_fn", "update_mask_fn", "delete_mask_fn",
}

// Verify is `fun verify()` — SIX startup assertions, in McpCapabilityRegistry.kt:124-135's order.
//
// 🔒 INV-A11-1 — EVERY `AuthzAction` MUST BE EXPLICITLY IN-SCOPE OR EXPLICITLY DEFERRED. Adding a new
// action to A2's enum fails assertion 2 until someone classifies it. That is the mechanism that stops
// a new Cedar action from silently becoming un-exposed OR accidentally exposed, and it is why this is
// a real check and not a comment.
//
// 🔒 It ABORTS STARTUP. Kotlin's `check(...)` throws IllegalStateException out of `installMcp`, which
// is called from `Application.module()`, so a mismatch fails the boot. Go has no exceptions, so the
// error is RETURNED and [New] propagates it — internal/app must treat a non-nil error from [New] as
// fatal, exactly as it treats a failed migration. It is deliberately NOT an `init()` panic: that
// would fire in processes and test binaries that never install MCP, which is more than the Kotlin
// does, and the port reproduces placement as well as behaviour.
//
// The messages are the Kotlin's `check` lazy-message strings verbatim, because they are what an
// operator reads out of a crash log.
func Verify() error {
	inScope := setOf(InScopeActions)
	excluded := setOf(ExcludedActions)

	for _, a := range InScopeActions {
		if _, ok := excluded[a]; ok {
			return fmt.Errorf("MCP action classifications overlap")
		}
	}

	// `inScopeActions + excludedActions == AuthzAction.entries.toSet()`. Both directions matter and
	// only one of them is the invariant people remember: an action missing from BOTH lists is the
	// INV-A11-1 case (a new Cedar action nobody classified), while a name in a list that is not an
	// action is a typo that would otherwise silently narrow the union back to a passing size.
	classified := make(map[authz.AuthzAction]struct{}, len(inScope)+len(excluded))
	for a := range inScope {
		classified[a] = struct{}{}
	}
	for a := range excluded {
		classified[a] = struct{}{}
	}
	all := authz.AllAuthzActions()
	if len(classified) != len(all) {
		return fmt.Errorf("Every AuthzAction must be explicitly MCPA in-scope or deferred")
	}
	for _, a := range all {
		if _, ok := classified[a]; !ok {
			return fmt.Errorf("Every AuthzAction must be explicitly MCPA in-scope or deferred")
		}
	}

	for _, action := range InScopeActions {
		if !slices.ContainsFunc(Entries, func(c Capability) bool { return c.Action == action }) {
			return fmt.Errorf("Every in-scope MCPA action must have at least one tool")
		}
	}

	if len(Entries) != len(ByName) {
		return fmt.Errorf("MCP tool names must be unique")
	}

	for _, c := range Entries {
		if isBlank(c.RequiredScope) {
			return fmt.Errorf("Every MCP tool must declare exactly one scope")
		}
	}

	// `byName.keys == approvedToolNames` — SET equality, so a duplicate inside ApprovedToolNames or a
	// name present in one and not the other both fail.
	approved := map[string]struct{}{}
	for _, n := range ApprovedToolNames {
		approved[n] = struct{}{}
	}
	if len(approved) != len(ByName) {
		return fmt.Errorf("MCP tool catalog differs from the approved set")
	}
	for name := range ByName {
		if _, ok := approved[name]; !ok {
			return fmt.Errorf("MCP tool catalog differs from the approved set")
		}
	}
	return nil
}

func setOf(actions []authz.AuthzAction) map[authz.AuthzAction]struct{} {
	m := make(map[authz.AuthzAction]struct{}, len(actions))
	for _, a := range actions {
		m[a] = struct{}{}
	}
	return m
}
