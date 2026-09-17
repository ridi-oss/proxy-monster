package com.ridi.oss.proxymonster.controlplane.management

import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource

enum class CapabilityClassification { READ, WRITE }

/** SYSTEM: Cedar on the System resource up front. RESOURCE: a scope check up front; the shared service runs Cedar. */
enum class McpGate { SYSTEM, RESOURCE }

data class McpToolAnnotations(
    val readOnlyHint: Boolean,
    val destructiveHint: Boolean,
)

data class McpCapability(
    val toolName: String,
    val action: AuthzAction,
    val resource: AuthzResource = AuthzResource.System,
    val requiredScope: String,
    val classification: CapabilityClassification,
    val annotations: McpToolAnnotations,
    val gate: McpGate = McpGate.SYSTEM,
)

/** The one authoritative, complete MCPA tool/action/scope catalog. */
object McpCapabilityRegistry {
    val inScopeActions = setOf(
        AuthzAction.ADMIN_DATASOURCES,
        AuthzAction.ADMIN_POLICIES,
        AuthzAction.ADMIN_IDENTITY,
        AuthzAction.DATASOURCE_CONNECT,
        AuthzAction.TASK_REQUEST,
        AuthzAction.TASK_READ,
        AuthzAction.TASK_ASSUME,
        AuthzAction.TASK_CANCEL,
        AuthzAction.TASK_APPROVE,
    )

    val excludedActions = setOf(
        // Editor-tab cleanup, grants, tokens, audit browsing, and actions that are only ever checked inside
        // a query decision have no MCP tool.
        AuthzAction.TASK_DELETE,
        AuthzAction.GRANT_REVOKE,
        AuthzAction.TOKEN_MINT,
        AuthzAction.TOKEN_LIST,
        AuthzAction.TOKEN_REVOKE,
        AuthzAction.AUDIT_READ,
        AuthzAction.RESULT_READ_UNMASKED,
        AuthzAction.RESULT_READ_MASKED,
        AuthzAction.RESULT_CAP,
        AuthzAction.NATIVE_INVOKE,
        AuthzAction.EXCEPTION_UNANALYZABLE,
        AuthzAction.EXCEPTION_UNMASKABLE,
    )

    private fun read(name: String, action: AuthzAction) = McpCapability(
        name, action, requiredScope = "mcp:read", classification = CapabilityClassification.READ,
        annotations = McpToolAnnotations(readOnlyHint = true, destructiveHint = false),
    )

    private fun write(name: String, action: AuthzAction, scope: String, destructive: Boolean = false) = McpCapability(
        name, action, requiredScope = scope, classification = CapabilityClassification.WRITE,
        annotations = McpToolAnnotations(readOnlyHint = false, destructiveHint = destructive),
    )

    private fun task(name: String, action: AuthzAction, scope: String, write: Boolean, destructive: Boolean = false) =
        McpCapability(
            name, action, requiredScope = scope,
            classification = if (write) CapabilityClassification.WRITE else CapabilityClassification.READ,
            annotations = McpToolAnnotations(readOnlyHint = !write, destructiveHint = destructive),
            gate = McpGate.RESOURCE,
        )

    val entries: List<McpCapability> = listOf(
        read("list_datasources", AuthzAction.ADMIN_DATASOURCES),
        read("get_datasource_liveness", AuthzAction.ADMIN_DATASOURCES),
        read("browse_catalog", AuthzAction.ADMIN_DATASOURCES),
        read("get_table_detail", AuthzAction.ADMIN_DATASOURCES),
        read("list_column_tags", AuthzAction.ADMIN_DATASOURCES),
        write("set_column_classification", AuthzAction.ADMIN_DATASOURCES, "mcp:datasources:write"),
        write("set_column_classifications", AuthzAction.ADMIN_DATASOURCES, "mcp:datasources:write"),
        write("clear_column_classification", AuthzAction.ADMIN_DATASOURCES, "mcp:datasources:write", destructive = true),

        read("list_policies", AuthzAction.ADMIN_POLICIES),
        read("get_policy", AuthzAction.ADMIN_POLICIES),
        read("validate_policy", AuthzAction.ADMIN_POLICIES),
        read("get_policy_schema", AuthzAction.ADMIN_POLICIES),
        write("create_policy", AuthzAction.ADMIN_POLICIES, "mcp:policies:write"),
        write("update_policy", AuthzAction.ADMIN_POLICIES, "mcp:policies:write"),
        write("enable_policy", AuthzAction.ADMIN_POLICIES, "mcp:policies:write"),
        write("disable_policy", AuthzAction.ADMIN_POLICIES, "mcp:policies:write"),
        write("delete_policy", AuthzAction.ADMIN_POLICIES, "mcp:policies:write", destructive = true),

        read("list_roles", AuthzAction.ADMIN_POLICIES),
        write("create_role", AuthzAction.ADMIN_POLICIES, "mcp:policies:write"),
        write("update_role", AuthzAction.ADMIN_POLICIES, "mcp:policies:write"),
        write("delete_role", AuthzAction.ADMIN_POLICIES, "mcp:policies:write", destructive = true),
        read("list_role_assignments", AuthzAction.ADMIN_IDENTITY),
        write("assign_role", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write"),
        write("unassign_role", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write", destructive = true),

        read("list_users", AuthzAction.ADMIN_IDENTITY),
        write("create_user", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write"),
        write("update_user", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write"),
        write("deprovision_user", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write", destructive = true),
        read("list_groups", AuthzAction.ADMIN_IDENTITY),
        write("create_group", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write"),
        write("update_group", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write"),
        write("delete_group", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write", destructive = true),
        write("add_group_member", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write"),
        write("remove_group_member", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write", destructive = true),
        write("set_group_roles", AuthzAction.ADMIN_IDENTITY, "mcp:identity:write"),

        read("list_mask_fns", AuthzAction.ADMIN_POLICIES),
        write("create_mask_fn", AuthzAction.ADMIN_POLICIES, "mcp:policies:write"),
        write("update_mask_fn", AuthzAction.ADMIN_POLICIES, "mcp:policies:write"),
        write("delete_mask_fn", AuthzAction.ADMIN_POLICIES, "mcp:policies:write", destructive = true),

        task("list_connectable_datasources", AuthzAction.DATASOURCE_CONNECT, "mcp:query", write = false),
        task("describe_datasource", AuthzAction.DATASOURCE_CONNECT, "mcp:query", write = false),
        // Destructive because the SQL may be DML wherever Cedar allows it.
        task("run_query", AuthzAction.TASK_REQUEST, "mcp:query", write = true, destructive = true),
        task("get_query_result", AuthzAction.TASK_ASSUME, "mcp:query", write = false),
        task("get_query_status", AuthzAction.TASK_READ, "mcp:query", write = false),
        task("cancel_query", AuthzAction.TASK_CANCEL, "mcp:query", write = true),
        task("discover_roles", AuthzAction.TASK_REQUEST, "mcp:query", write = false),
        task("request_approval", AuthzAction.TASK_REQUEST, "mcp:query", write = true),
        task("list_my_approvals", AuthzAction.TASK_READ, "mcp:query", write = false),
        task("list_approval_inbox", AuthzAction.TASK_APPROVE, "mcp:query", write = false),
        task("get_approval", AuthzAction.TASK_READ, "mcp:query", write = false),
        task("approve_approval", AuthzAction.TASK_APPROVE, "mcp:approvals:write", write = true),
        task("reject_approval", AuthzAction.TASK_APPROVE, "mcp:approvals:write", write = true),
        task("execute_approval", AuthzAction.TASK_APPROVE, "mcp:approvals:write", write = true, destructive = true),
        task("get_approval_result", AuthzAction.TASK_ASSUME, "mcp:query", write = false),
        task("cancel_approval", AuthzAction.TASK_CANCEL, "mcp:query", write = true),
    )

    val byName = entries.associateBy(McpCapability::toolName)
    val supportedScopes = entries.map(McpCapability::requiredScope).toSortedSet()

    val approvedToolNames = setOf(
        "list_datasources", "get_datasource_liveness", "browse_catalog", "get_table_detail", "list_column_tags",
        "set_column_classification", "set_column_classifications", "clear_column_classification",
        "list_policies", "get_policy", "validate_policy",
        "get_policy_schema", "create_policy", "update_policy", "enable_policy", "disable_policy", "delete_policy",
        "list_roles", "create_role", "update_role", "delete_role", "list_role_assignments", "assign_role",
        "unassign_role", "list_users", "create_user", "update_user", "deprovision_user", "list_groups", "create_group",
        "update_group", "delete_group", "add_group_member", "remove_group_member", "set_group_roles", "list_mask_fns",
        "create_mask_fn", "update_mask_fn", "delete_mask_fn",
        "list_connectable_datasources", "describe_datasource", "run_query", "get_query_result", "get_query_status",
        "cancel_query", "discover_roles", "request_approval", "list_my_approvals", "list_approval_inbox", "get_approval",
        "approve_approval", "reject_approval", "execute_approval", "get_approval_result", "cancel_approval",
    )

    fun verify() {
        check(inScopeActions.intersect(excludedActions).isEmpty()) { "MCP action classifications overlap" }
        check(inScopeActions + excludedActions == AuthzAction.entries.toSet()) {
            "Every AuthzAction must be explicitly MCPA in-scope or deferred"
        }
        check(inScopeActions.all { action -> entries.any { it.action == action } }) {
            "Every in-scope MCPA action must have at least one tool"
        }
        check(entries.size == byName.size) { "MCP tool names must be unique" }
        check(entries.all { it.requiredScope.isNotBlank() }) { "Every MCP tool must declare exactly one scope" }
        check(byName.keys == approvedToolNames) { "MCP tool catalog differs from the approved set" }
    }
}
