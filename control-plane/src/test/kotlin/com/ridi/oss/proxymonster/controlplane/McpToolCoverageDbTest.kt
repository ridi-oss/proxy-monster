package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.RequireResultReadGrant
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.support.ALL_MCP_SCOPES
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.McpTokens
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.str
import com.ridi.oss.proxymonster.controlplane.support.withFakeProxy
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.proxyRunMsg
import com.ridi.oss.proxymonster.grpc.proxyTableDetailMsg
import com.ridi.oss.proxymonster.grpc.runDecision
import com.ridi.oss.proxymonster.grpc.runDone
import com.ridi.oss.proxymonster.grpc.runResultRows
import com.ridi.oss.proxymonster.grpc.runRow
import com.ridi.oss.proxymonster.grpc.runValue
import com.ridi.oss.proxymonster.grpc.tableDetailResult
import com.ridi.oss.proxymonster.probe.TableDetail
import com.ridi.oss.proxymonster.probe.TableDetailColumn
import com.ridi.oss.proxymonster.probe.TableMetadata
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import io.ktor.client.HttpClient
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Drives every registered MCP tool once, successfully, through the production module. The invocation map must
 * name exactly the registry's tools, so a tool added without a call here fails the test.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpToolCoverageDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private lateinit var server: GrpcServer
    private lateinit var rawChannel: ManagedChannel
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub

    private val sql = "SELECT id, ssn FROM users ORDER BY id"
    private val maskedRows = listOf(listOf("1", "*******4320"), listOf("2", "*******4321"))

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
        core = PerConnectionCatalogFixture(fx).core
        tokens = McpTokens(fx.dataSource)
        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        rawChannel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(rawChannel)
    }

    @AfterAll
    fun close() {
        rawChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
    }

    @Test
    fun `every MCP tool answers a successful call`() = testApplication {
        val client = installControlPlane(mcpTestConfig(resultKey = ByteArray(32)), core)
        val ds = fx.datasource
        val catalog = ds.effectiveCatalog
        val schema = ds.defaultSchemas.first()
        val requester = "cov-requester@example.com"
        val admin = "cov-admin@example.com"
        core.policyStore.createAssignment(RoleAssignmentInput(requester, role(ANALYST)))
        core.policyStore.createAssignment(RoleAssignmentInput(admin, role("system:admin")))
        val req = tokens.token(requester, ALL_MCP_SCOPES)
        val adm = tokens.token(admin, ALL_MCP_SCOPES)
        val editorFingerprint = fx.decide(sql, requester, Channel.EDITOR).resultFingerprint
        val executeFingerprint = fx.decide(sql, admin, Channel.WORKFLOW_EXECUTOR, providedRoles = setOf(ANALYST)).resultFingerprint
        val ownAudit = core.auditStore.insert(AuditEvent(principal = requester, datasource = ds.name, statement = "cov", decision = Decision.ALLOW))
        val cancelTask = core.accessStore.createEditorTask(requester, ds.id, listOf(sql), listOf(ANALYST), approver = requester)
        val deleteTask = core.accessStore.createEditorTask(requester, ds.id, listOf(sql), listOf(ANALYST), approver = requester)
        val jitRole = core.policyStore.createRole(RoleInput("cov-jit-role"))
        val rejectRequest = core.accessStore.createRequest(requester, AccessRequestInput(roleId = jitRole.id)).id

        var runTaskId = 0L
        var approvalId = 0L
        var rejectApprovalId = 0L
        var accessRequestId = 0L
        var grantId = 0L
        var tokenId = 0L
        val succeeded = linkedSetOf<String>()

        suspend fun HttpClient.ok(token: String, tool: String, args: JsonObject = JsonObject(emptyMap())): JsonObject {
            val result = mcpCall(token, tool, args)
            assertTrue(result["isError"]?.jsonPrimitive?.content != "true", "$tool: $result")
            val structured = result.getValue("structuredContent").jsonObject
            assertTrue("result" in structured, "$tool: $structured")
            succeeded += tool
            return structured
        }
        fun args(vararg pairs: Pair<String, Any>) = buildJsonObject {
            for ((k, v) in pairs) when (v) {
                is String -> put(k, v)
                is Number -> put(k, v)
                is Boolean -> put(k, v)
                is List<*> -> put(k, buildJsonArray { v.forEach { add(JsonPrimitive(it as String)) } })
                else -> error("unsupported $v")
            }
        }
        fun JsonObject.result() = getValue("result")
        fun JsonObject.id() = result().jsonObject.getValue("id").jsonPrimitive.long

        val invocations = LinkedHashMap<String, suspend () -> JsonObject>()
        fun on(tool: String, call: suspend () -> JsonObject) {
            check(invocations.put(tool, call) == null) { "duplicate $tool" }
        }

        // Datasources and classifications, on a throwaway datasource.
        on("list_datasources") { client.ok(adm, "list_datasources") }
        on("create_datasource") { client.ok(adm, "create_datasource", args("name" to "cov-ds", "engine" to "mysql", "dbName" to "app")) }
        on("update_datasource") { client.ok(adm, "update_datasource", args("datasource" to "cov-ds", "host" to "db.internal")) }
        on("get_datasource_liveness") { client.ok(adm, "get_datasource_liveness", args("datasource" to ds.name)) }
        on("browse_catalog") { client.ok(adm, "browse_catalog", args("datasource" to ds.name)) }
        on("get_table_detail") {
            client.ok(adm, "get_table_detail", args("datasource" to ds.name, "catalog" to catalog, "schema" to schema, "table" to "users"))
        }
        on("refresh_datasource") { client.ok(adm, "refresh_datasource", args("datasource" to "cov-ds")) }
        on("test_datasource") { client.ok(adm, "test_datasource", args("datasource" to "cov-ds")) }
        on("list_mask_fns") { client.ok(adm, "list_mask_fns") }
        on("create_mask_fn") { client.ok(adm, "create_mask_fn", args("name" to "cov-mask", "kind" to "FIXED")) }
        on("update_mask_fn") { client.ok(adm, "update_mask_fn", args("name" to "cov-mask", "kind" to "FIXED")) }
        on("set_column_classification") {
            client.ok(adm, "set_column_classification", args(
                "datasource" to "cov-ds", "catalog" to "def", "schema" to "app", "table" to "t", "column" to "a",
                "tags" to listOf("pii"), "maskFnName" to "cov-mask",
            ))
        }
        on("set_column_classifications") {
            client.ok(adm, "set_column_classifications", buildJsonObject {
                put("datasource", "cov-ds")
                put("columns", buildJsonArray {
                    add(buildJsonObject {
                        put("catalog", "def"); put("schema", "app"); put("table", "t"); put("column", "b")
                        put("tags", buildJsonArray { add(JsonPrimitive("pii")) })
                    })
                })
            })
        }
        on("list_column_tags") { client.ok(adm, "list_column_tags", args("datasource" to "cov-ds")) }
        on("clear_column_classification") {
            client.ok(adm, "clear_column_classification", args("datasource" to "cov-ds", "catalog" to "def", "schema" to "app", "table" to "t", "column" to "a"))
        }
        on("delete_datasource") { client.ok(adm, "delete_datasource", args("datasource" to "cov-ds")) }

        // Policies, roles, users and groups.
        val policySrc = """permit(principal in Role::"cov-role", action == Action::"admin.identity", resource);"""
        on("list_policies") { client.ok(adm, "list_policies") }
        on("validate_policy") { client.ok(adm, "validate_policy", args("cedarSrc" to policySrc)) }
        on("get_policy_schema") { client.ok(adm, "get_policy_schema") }
        on("list_roles") { client.ok(adm, "list_roles") }
        on("create_role") { client.ok(adm, "create_role", args("name" to "cov-role")) }
        on("update_role") { client.ok(adm, "update_role", args("name" to "cov-role", "description" to "coverage")) }
        on("create_policy") { client.ok(adm, "create_policy", args("name" to "cov-policy", "cedarSrc" to policySrc)) }
        on("get_policy") { client.ok(adm, "get_policy", args("name" to "cov-policy")) }
        on("update_policy") { client.ok(adm, "update_policy", args("name" to "cov-policy", "cedarSrc" to policySrc)) }
        on("disable_policy") { client.ok(adm, "disable_policy", args("name" to "cov-policy")) }
        on("enable_policy") { client.ok(adm, "enable_policy", args("name" to "cov-policy")) }
        on("delete_policy") { client.ok(adm, "delete_policy", args("name" to "cov-policy")) }
        on("list_users") { client.ok(adm, "list_users") }
        on("create_user") { client.ok(adm, "create_user", args("principal" to "cov-user@example.com")) }
        on("update_user") { client.ok(adm, "update_user", args("principal" to "cov-user@example.com", "displayName" to "Coverage")) }
        on("assign_role") { client.ok(adm, "assign_role", args("principal" to "cov-user@example.com", "roleName" to "cov-role")) }
        on("list_role_assignments") { client.ok(adm, "list_role_assignments", args("roleName" to "cov-role")) }
        on("unassign_role") { client.ok(adm, "unassign_role", args("principal" to "cov-user@example.com", "roleName" to "cov-role")) }
        on("list_groups") { client.ok(adm, "list_groups") }
        on("create_group") { client.ok(adm, "create_group", args("name" to "cov-group")) }
        on("update_group") { client.ok(adm, "update_group", args("name" to "cov-group", "description" to "coverage")) }
        on("add_group_member") { client.ok(adm, "add_group_member", args("groupName" to "cov-group", "principal" to "cov-user@example.com")) }
        on("list_group_members") { client.ok(adm, "list_group_members", args("groupName" to "cov-group")) }
        on("set_group_roles") { client.ok(adm, "set_group_roles", args("groupName" to "cov-group", "roleNames" to listOf("cov-role"))) }
        on("list_group_roles") { client.ok(adm, "list_group_roles", args("groupName" to "cov-group")) }
        on("remove_group_member") { client.ok(adm, "remove_group_member", args("groupName" to "cov-group", "principal" to "cov-user@example.com")) }
        on("delete_group") { client.ok(adm, "delete_group", args("name" to "cov-group")) }
        on("delete_role") { client.ok(adm, "delete_role", args("name" to "cov-role")) }
        on("deprovision_user") { client.ok(adm, "deprovision_user", args("principal" to "cov-user@example.com")) }
        on("delete_mask_fn") { client.ok(adm, "delete_mask_fn", args("name" to "cov-mask")) }
        on("reset_principal_rate") { client.ok(adm, "reset_principal_rate", args("principal" to requester, "reason" to "coverage")) }
        on("get_principal_rate") { client.ok(adm, "get_principal_rate", args("principal" to requester)) }

        // Queries and query approvals.
        on("list_connectable_datasources") { client.ok(req, "list_connectable_datasources") }
        on("describe_datasource") { client.ok(req, "describe_datasource", args("datasource" to ds.name)) }
        on("run_query") {
            client.ok(req, "run_query", args("datasource" to ds.name, "sql" to sql)).also {
                val run = it.result().jsonObject
                assertEquals("EXECUTED", run.str("status"), run.toString())
                runTaskId = run.getValue("taskId").jsonPrimitive.long
            }
        }
        on("get_query_status") { client.ok(req, "get_query_status", args("taskId" to runTaskId)) }
        on("get_query_result") { client.ok(req, "get_query_result", args("taskId" to runTaskId)) }
        on("cancel_query") { client.ok(req, "cancel_query", args("taskId" to cancelTask.id)) }
        on("list_query_history") { client.ok(req, "list_query_history") }
        on("clear_query_history") { client.ok(req, "clear_query_history") }
        on("delete_query_task") { client.ok(req, "delete_query_task", args("taskId" to deleteTask.id)) }
        on("discover_roles") { client.ok(req, "discover_roles", args("datasource" to ds.name, "sql" to sql)) }
        on("request_approval") {
            val proactive = args("datasource" to ds.name, "sql" to sql, "title" to "coverage", "roleName" to ANALYST, "reason" to "coverage")
            rejectApprovalId = client.ok(req, "request_approval", proactive).result().jsonObject.getValue("request").jsonObject
                .getValue("id").jsonPrimitive.long
            client.ok(req, "request_approval", proactive).also {
                approvalId = it.result().jsonObject.getValue("request").jsonObject.getValue("id").jsonPrimitive.long
            }
        }
        on("list_my_approvals") { client.ok(req, "list_my_approvals") }
        on("list_approval_inbox") { client.ok(adm, "list_approval_inbox") }
        on("get_approval") { client.ok(adm, "get_approval", args("id" to approvalId)) }
        on("reject_approval") { client.ok(adm, "reject_approval", args("id" to rejectApprovalId, "reason" to "coverage")) }
        on("approve_approval") { client.ok(adm, "approve_approval", args("id" to approvalId)) }
        on("execute_approval") {
            client.ok(adm, "execute_approval", args("id" to approvalId)).also {
                withTimeout(10_000) {
                    while (client.ok(req, "get_approval", args("id" to approvalId)).result().jsonObject
                            .getValue("request").jsonObject.str("status") != "EXECUTED"
                    ) {
                        delay(50)
                    }
                }
            }
        }
        on("get_approval_result") { client.ok(req, "get_approval_result", args("id" to approvalId)) }
        on("cancel_approval") { client.ok(req, "cancel_approval", args("id" to approvalId)) }

        // JIT access, rates, audit, permissions and tokens.
        on("get_my_permissions") { client.ok(req, "get_my_permissions") }
        on("get_pmon_guide") { client.ok(req, "get_pmon_guide") }
        on("get_usage_guide") { client.ok(req, "get_usage_guide") }
        on("get_admin_guide") { client.ok(req, "get_admin_guide") }
        on("request_access") {
            client.ok(req, "request_access", args("roleName" to jitRole.name, "reason" to "coverage")).also { accessRequestId = it.id() }
        }
        on("list_access_requests") { client.ok(req, "list_access_requests") }
        on("approve_access_request") { client.ok(adm, "approve_access_request", args("id" to accessRequestId)) }
        on("reject_access_request") { client.ok(adm, "reject_access_request", args("id" to rejectRequest, "reason" to "coverage")) }
        on("list_access_grants") {
            client.ok(req, "list_access_grants", args("active" to true)).also {
                grantId = it.result().jsonArray.single().jsonObject.getValue("id").jsonPrimitive.long
            }
        }
        on("revoke_access_grant") { client.ok(req, "revoke_access_grant", args("id" to grantId)) }
        on("reset_my_rate") { client.ok(req, "reset_my_rate", args("reason" to "coverage")) }
        on("list_audit") { client.ok(req, "list_audit") }
        on("get_audit_event") { client.ok(req, "get_audit_event", args("id" to ownAudit)) }
        on("mint_token") { client.ok(req, "mint_token", args("name" to "coverage")).also { tokenId = it.id() } }
        on("list_tokens") { client.ok(req, "list_tokens") }
        on("revoke_token") { client.ok(req, "revoke_token", args("id" to tokenId)) }

        assertEquals(McpCapabilityRegistry.byName.keys, invocations.keys)

        withFakeProxy(
            core, stub, ds.name,
            respond = { identity, _, _ ->
                if (identity?.kind == TokenKind.APPROVER_EXEC.name) {
                    masked(executeFingerprint, execution(admin, Channel.WORKFLOW_EXECUTOR))
                } else {
                    masked(editorFingerprint, execution(requester, Channel.EDITOR))
                }
            },
            tableDetail = { open ->
                val detail = TableDetail(
                    catalog = open.catalog, schema = open.schema, table = open.table,
                    columns = listOf(TableDetailColumn("id", "bigint", 1, false, null, null, 64, 0, true, true, null, null, null, null)),
                    indexes = emptyList(), foreignKeys = emptyList(), referencedBy = emptyList(),
                    metadata = TableMetadata("InnoDB", 2, null, null, null, null),
                )
                proxyTableDetailMsg { result = tableDetailResult { json = Json.encodeToString(detail) } }
            },
        ) {
            for ((tool, call) in invocations) assertNotNull(call(), tool)
        }
        assertEquals(McpCapabilityRegistry.byName.keys, succeeded)
    }

    private fun role(name: String) = assertNotNull(core.policyStore.getRoleByName(name)).id

    private fun execution(principal: String, channel: Channel): Long = core.auditStore.insert(
        AuditEvent(principal = principal, datasource = fx.datasource.name, statement = sql, decision = Decision.MASK, channel = channel.contextValue),
    )

    private fun masked(fingerprint: List<RequireResultReadGrant>, decisionId: Long): List<ProxyRunMsg> = listOf(
        proxyRunMsg {
            decision = runDecision {
                decision = EnfAction.MASK
                this.decisionId = decisionId
                maskedColumns += "ssn"
                resultFingerprint += fingerprint
            }
        },
        proxyRunMsg {
            resultRows = runResultRows {
                columns += listOf("id", "ssn")
                rows += maskedRows.map { row -> runRow { values += row.map { v -> runValue { value = v } } } }
            }
        },
        proxyRunMsg { done = runDone { rowsAffected = -1 } },
    )

    private companion object {
        const val ANALYST = "analyst"
    }
}
