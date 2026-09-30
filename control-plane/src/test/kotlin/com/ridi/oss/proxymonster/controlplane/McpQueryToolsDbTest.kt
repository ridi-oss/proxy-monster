package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.AuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.ConsumeAuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.OAuthAuthorizationStore
import com.ridi.oss.proxymonster.auth.pkceS256
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.grpc.CONTROL_PROTOCOL_VERSION
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.management.IdentityManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.management.McpGate
import com.ridi.oss.proxymonster.controlplane.management.PolicyManagementService
import com.ridi.oss.proxymonster.controlplane.mcp.installMcp
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.OpenRunChannel
import com.ridi.oss.proxymonster.grpc.decisionRequest
import com.ridi.oss.proxymonster.grpc.EnfAction as WireEnfAction
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.eventsRequest
import com.ridi.oss.proxymonster.grpc.proxyRunMsg
import com.ridi.oss.proxymonster.grpc.runDecision
import com.ridi.oss.proxymonster.grpc.runDone
import com.ridi.oss.proxymonster.grpc.runReady
import com.ridi.oss.proxymonster.grpc.runResultRows
import com.ridi.oss.proxymonster.grpc.runRow
import com.ridi.oss.proxymonster.grpc.runServing
import com.ridi.oss.proxymonster.grpc.runValue
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel as KChannel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Duration
import java.sql.DriverManager
import java.time.Instant
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The MCP query and approval tools end to end: OAuth scope ceiling, the shared services' Cedar gates on the
 * REST channels, masked results through a fake proxy over the real gRPC run path, and paged result views.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpQueryToolsDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var pcf: PerConnectionCatalogFixture
    private lateinit var core: ControlPlaneCore
    private lateinit var oauth: OAuthAuthorizationStore
    private lateinit var resultStore: QueryResultStore
    private lateinit var runExecService: RunExecService
    private lateinit var appScope: CoroutineScope
    private lateinit var server: GrpcServer
    private lateinit var rawChannel: ManagedChannel
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private var analystRoleId = 0L
    private val seq = AtomicInteger()

    private val sql = "SELECT id, ssn FROM users ORDER BY id"
    private val maskedRows = listOf(listOf("1", "*******4320"), listOf("2", "*******4321"), listOf("3", "*******4322"))

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
        pcf = PerConnectionCatalogFixture(fx)
        core = pcf.core
        oauth = OAuthAuthorizationStore(fx.dataSource)
        resultStore = QueryResultStore(fx.dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        runExecService = RunExecService(core)
        appScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        analystRoleId = fx.policyStore.listRoles().first { it.name == ANALYST }.id
        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        rawChannel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(rawChannel)
    }

    @AfterAll
    fun close() {
        appScope.cancel()
        rawChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
    }

    @Test
    fun `scope is a ceiling on every query and approval tool`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val principal = analyst("scope")
        val readOnly = token(principal, setOf("mcp:read"))
        val taskTools = McpCapabilityRegistry.entries.filter { it.gate == McpGate.RESOURCE }
        assertEquals(16, taskTools.size)
        for (tool in taskTools) {
            val response = client.rawCall(readOnly, tool.toolName)
            assertEquals(HttpStatusCode.Forbidden, response.status, tool.toolName)
            assertContains(assertNotNull(response.headers[HttpHeaders.WWWAuthenticate]), "scope=\"${tool.requiredScope}\"")
            assertEquals("mcp.insufficient_scope", structured(response.bodyAsText()).code(), tool.toolName)
        }
        val queryOnly = token(principal, setOf("mcp:query"))
        for (tool in listOf("approve_approval", "reject_approval", "execute_approval")) {
            val response = client.rawCall(queryOnly, tool, buildJsonObject { put("id", 1) })
            assertEquals(HttpStatusCode.Forbidden, response.status, tool)
            assertContains(assertNotNull(response.headers[HttpHeaders.WWWAuthenticate]), "scope=\"mcp:approvals:write\"")
        }
    }

    @Test
    fun `run_query returns the masked first page and get_query_result pages it`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val principal = analyst("run")
        val fingerprint = fx.decide(sql, principal, Channel.EDITOR).resultFingerprint
        val token = token(principal, setOf("mcp:query"))
        withFakeProxy({ _, _, _ -> maskedResult(fingerprint, executionDecision(principal, Channel.EDITOR)) }) {
            run {
                val run = client.call(token, "run_query", buildJsonObject {
                    put("datasource", fx.datasource.name)
                    put("sql", sql)
                }).ok().result()
                assertEquals("EXECUTED", run.str("status"))
                val page = run.getValue("page").jsonObject
                assertEquals(maskedRows, page.rows())
                assertEquals("MASK", page.str("decision"))
                val taskId = run.getValue("taskId").jsonPrimitive.long

                val second = client.call(token, "get_query_result", buildJsonObject {
                    put("taskId", taskId)
                    put("offset", 1)
                    put("limit", 1)
                }).ok().result()
                assertEquals(listOf(maskedRows[1]), second.rows())
                assertEquals(2, second.getValue("nextOffset").jsonPrimitive.int)
            }
        }
    }

    @Test
    fun `a denied run_query becomes an approval the approver runs and the requester reads masked`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val requester = analyst("requester")
        val approver = "mcp-approver-${seq.incrementAndGet()}@example.com"
        val outsider = "mcp-outsider-${seq.incrementAndGet()}@example.com"
        val policy = core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-approver-${seq.incrementAndGet()}",
                """permit(principal == User::"$approver", action in [Action::"task.approve", Action::"task.read"], resource);""",
            ),
            "test",
        )
        val executeFingerprint = fx.decide(sql, approver, Channel.WORKFLOW_EXECUTOR, providedRoles = setOf(ANALYST)).resultFingerprint
        val requesterToken = token(requester, setOf("mcp:query"))
        val approverToken = token(approver, setOf("mcp:query", "mcp:approvals:write"))
        try {
            withFakeProxy({ identity, statement, _ ->
                    if (identity?.kind == TokenKind.APPROVER_EXEC.name) {
                        maskedResult(executeFingerprint, executionDecision(approver))
                    } else {
                        val denied = core.auditStore.insert(
                            AuditEvent(
                                principal = requester, datasource = fx.datasource.name, statement = statement,
                                decision = Decision.DENY, detail = "ssn requires approval",
                            ),
                        )
                        listOf(proxyRunMsg { decision = runDecision { decision = WireEnfAction.DENY; decisionId = denied; denyReason = "ssn requires approval" } })
                    }
            }) {
                run {
                    val run = client.call(requesterToken, "run_query", buildJsonObject {
                        put("datasource", fx.datasource.name)
                        put("sql", sql)
                    }).ok().result()
                    assertEquals("FAILED", run.str("status"))
                    val decisionId = run.getValue("statements").jsonArray.single().jsonObject.getValue("decisionId").jsonPrimitive.long

                    val created = client.call(requesterToken, "request_approval", buildJsonObject {
                        put("decisionId", decisionId)
                        put("roleName", ANALYST)
                        put("reason", "support ticket")
                    }).ok().result()
                    val id = created.getValue("request").jsonObject.getValue("id").jsonPrimitive.long

                    val inbox = client.call(approverToken, "list_approval_inbox").ok().getValue("result").jsonArray
                    assertTrue(inbox.any { it.jsonObject.getValue("id").jsonPrimitive.long == id })
                    assertEquals("APPROVED", client.call(approverToken, "approve_approval", idArg(id)).ok().result().str("status"))
                    assertEquals("EXECUTING", client.call(approverToken, "execute_approval", idArg(id)).ok().result().str("decision"))

                    withTimeout(10_000) {
                        while (client.call(requesterToken, "get_approval", idArg(id)).ok().result()
                                .getValue("request").jsonObject.str("status") != "EXECUTED"
                        ) {
                            delay(50)
                        }
                    }
                    val view = client.call(requesterToken, "get_approval_result", idArg(id)).ok().result()
                    assertEquals(maskedRows, view.rows())
                    assertEquals("MASK", view.str("decision"))

                    val outsiderResult = client.call(token(outsider, setOf("mcp:query")), "get_approval_result", idArg(id))
                    assertEquals("common.not_found", outsiderResult.error())
                }
            }
        } finally {
            core.cedarPolicyStore.delete(policy.id)
        }
    }

    @Test
    fun `a requester cannot approve their own request even holding task approve`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val requester = analyst("self")
        val policy = core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-self-approve-${seq.incrementAndGet()}",
                """permit(principal == User::"$requester", action == Action::"task.approve", resource);""",
            ),
            "test",
        )
        try {
            val id = pendingRequest(requester, fx.datasource.id)
            val result = client.call(token(requester, setOf("mcp:query", "mcp:approvals:write")), "approve_approval", idArg(id))
            assertEquals("approval.not_approver", result.error())
            assertEquals("PENDING", core.accessStore.getRequest(id)?.status)
        } finally {
            core.cedarPolicyStore.delete(policy.id)
        }
    }

    @Test
    fun `a datasource-scoped approver sees and decides only that datasource's requests`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val n = seq.incrementAndGet()
        val dsA = core.datasourceStore.create(DatasourceInput("mcp-scope-a-$n", "mysql", "localhost", 3306, "app"))
        val dsB = core.datasourceStore.create(DatasourceInput("mcp-scope-b-$n", "mysql", "localhost", 3306, "app"))
        val requester = analyst("scoped-requester")
        val approver = "mcp-scoped-approver-$n@example.com"
        val policy = core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-scoped-approver-$n",
                """permit(principal == User::"$approver", action == Action::"task.approve", resource) when { resource in Datasource::"${dsA.name}" };""",
            ),
            "test",
        )
        try {
            val onA = pendingRequest(requester, dsA.id)
            val onB = pendingRequest(requester, dsB.id)
            val token = token(approver, setOf("mcp:query", "mcp:approvals:write"))
            val inbox = client.call(token, "list_approval_inbox").ok().getValue("result").jsonArray
                .map { it.jsonObject.getValue("id").jsonPrimitive.long }
            assertTrue(onA in inbox, "inbox $inbox")
            assertFalse(onB in inbox, "inbox $inbox")
            assertEquals("approval.not_approver", client.call(token, "approve_approval", idArg(onB)).error())
            assertEquals("APPROVED", client.call(token, "approve_approval", idArg(onA)).ok().result().str("status"))
        } finally {
            core.cedarPolicyStore.delete(policy.id)
        }
    }

    @Test
    fun `another principal's editor task is not found`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val owner = analyst("owner")
        val caller = analyst("caller")
        val task = core.accessStore.createEditorTask(owner, fx.datasource.id, listOf(sql), listOf(ANALYST), approver = owner)
        val result = client.call(token(caller, setOf("mcp:query")), "get_query_result", buildJsonObject { put("taskId", task.id) })
        assertEquals("common.not_found", result.error())
    }

    @Test
    fun `run_query without result storage fails closed`() = testApplication {
        application { installTestMcp(withStorage = false) }
        val client = createClient { expectSuccess = false }
        val principal = analyst("nostore")
        val result = client.call(token(principal, setOf("mcp:query")), "run_query", buildJsonObject {
            put("datasource", fx.datasource.name)
            put("sql", sql)
        })
        assertEquals("approval.result_storage_not_configured", result.error())
    }

    @Test
    fun `a paged approval result audits and charges only the released page`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val requester = analyst("paged")
        val approver = "mcp-paged-approver-${seq.incrementAndGet()}@example.com"
        val decisionId = core.auditStore.insert(
            AuditEvent(principal = approver, datasource = fx.datasource.name, statement = sql, decision = Decision.MASK),
        )
        val id = seedApprovalResult(requester, approver, decisionId)
        val window = Duration.ofHours(1)
        val before = core.auditStore.relayedVolume(requester, listOf(window), Instant.now()).getValue(window)

        val view = client.call(token(requester, setOf("mcp:query")), "get_approval_result", buildJsonObject {
            put("id", id)
            put("limit", 1)
        }).ok().result()
        assertEquals(listOf(maskedRows[0]), view.rows())
        assertEquals(1, view.getValue("nextOffset").jsonPrimitive.int)

        val after = core.auditStore.relayedVolume(requester, listOf(window), Instant.now()).getValue(window)
        assertEquals(1L, after.rows - before.rows)
        assertEquals(
            1L,
            scalar(
                "SELECT count(*) FROM audit_event WHERE principal=? AND statement LIKE ? AND channel='workflow-viewer'",
                requester, "approval #$id result-viewed-%",
            ),
        )
        assertEquals(
            1L,
            scalar(
                "SELECT rows_returned FROM audit_event WHERE kind='completion' AND principal=? AND decision_id=$decisionId",
                requester,
            ),
        )
    }

    @Test
    fun `run_query pages the last statement that returned rows, else the last with columns`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val principal = analyst("multi")
        val empty = "SELECT id FROM users WHERE id < 0"
        val maskedFingerprint = fx.decide(sql, principal, Channel.EDITOR).resultFingerprint
        val emptyFingerprint = fx.decide(empty, principal, Channel.EDITOR).resultFingerprint
        val token = token(principal, setOf("mcp:query"))
        withFakeProxy({ _, statement, _ ->
            if (statement.contains("id < 0")) {
                listOf(
                    proxyRunMsg {
                        decision = runDecision {
                            decision = WireEnfAction.ALLOW; decisionId = executionDecision(principal, Channel.EDITOR); resultFingerprint += emptyFingerprint
                        }
                    },
                    proxyRunMsg { resultRows = runResultRows { columns += "id" } },
                    proxyRunMsg { done = runDone { rowsAffected = -1 } },
                )
            } else {
                maskedResult(maskedFingerprint, executionDecision(principal, Channel.EDITOR))
            }
        }) {
            val batch = client.call(token, "run_query", buildJsonObject {
                put("datasource", fx.datasource.name)
                put("sql", "$sql; $empty")
            }).ok().result()
            assertEquals("EXECUTED", batch.str("status"))
            assertEquals(2, batch.getValue("statements").jsonArray.size)
            val page = batch.getValue("page").jsonObject
            assertEquals(0, page.getValue("meta").jsonObject.getValue("ordinal").jsonPrimitive.int)
            assertEquals(maskedRows, page.rows())

            val onlyEmpty = client.call(token, "run_query", buildJsonObject {
                put("datasource", fx.datasource.name)
                put("sql", empty)
            }).ok().result().getValue("page").jsonObject
            assertEquals(listOf("id"), onlyEmpty.getValue("columns").jsonArray.map { it.jsonPrimitive.content })
            assertEquals(emptyList(), onlyEmpty.rows())
        }
    }

    @Test
    fun `run_query keeps the taskId when the page view is denied`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val principal = analyst("pagedenied")
        val token = token(principal, setOf("mcp:query"))
        // No frozen fingerprint, so the live re-decision cannot bind the stored columns and denies the view.
        withFakeProxy({ _, _, _ -> maskedResult(emptyList(), executionDecision(principal, Channel.EDITOR)) }) {
            val run = client.call(token, "run_query", buildJsonObject {
                put("datasource", fx.datasource.name)
                put("sql", sql)
            }).ok().result()
            assertEquals("EXECUTED", run.str("status"))
            assertTrue(run.getValue("taskId").jsonPrimitive.long > 0)
            assertEquals("approval.result_view_denied", run.str("pageError"))
            assertNull(run["page"])
        }
    }

    @Test
    fun `a page past the end returns no rows and no nextOffset`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val requester = analyst("pastend")
        val approver = "mcp-pastend-approver-${seq.incrementAndGet()}@example.com"
        val decisionId = core.auditStore.insert(
            AuditEvent(principal = approver, datasource = fx.datasource.name, statement = sql, decision = Decision.MASK),
        )
        val id = seedApprovalResult(requester, approver, decisionId)
        val view = client.call(token(requester, setOf("mcp:query")), "get_approval_result", buildJsonObject {
            put("id", id)
            put("offset", Int.MAX_VALUE)
            put("limit", 1000)
        }).ok().result()
        assertEquals(emptyList(), view.rows())
        assertNull(view["nextOffset"])
    }

    @Test
    fun `request_approval checks source exclusivity before resolving any name`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val principal = analyst("probe")
        val token = token(principal, setOf("mcp:query"))
        for (args in listOf(
            buildJsonObject { put("decisionId", 1); put("datasource", "no-such-ds"); put("roleName", "no-such-role"); put("reason", "r") },
            buildJsonObject { put("decisionId", 1); put("sql", "select 1"); put("roleName", "no-such-role"); put("reason", "r") },
        )) {
            assertEquals("approval.exactly_one_source_required", client.call(token, "request_approval", args).error(), args.toString())
        }
        val policy = core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-no-request-${seq.incrementAndGet()}",
                """forbid(principal == User::"$principal", action == Action::"task.request", resource);""",
            ),
            "test",
        )
        try {
            val refused = client.call(token, "request_approval", buildJsonObject {
                put("datasource", fx.datasource.name); put("sql", sql); put("title", "t")
                put("roleName", "no-such-role"); put("reason", "r")
            })
            assertEquals("common.forbidden", refused.error())
        } finally {
            core.cedarPolicyStore.delete(policy.id)
        }
    }

    @Test
    fun `approval tools decide on workflow-viewer, never on mcp`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        for (channel in listOf("workflow-viewer", "mcp")) {
            val requester = analyst("viewer-requester")
            val approver = "mcp-viewer-approver-${seq.incrementAndGet()}@example.com"
            val policy = core.cedarPolicyStore.create(
                CedarPolicyInput(
                    "mcp-channel-approver-${seq.incrementAndGet()}",
                    """permit(principal == User::"$approver", action in [Action::"task.approve", Action::"task.read", Action::"task.assume", Action::"task.cancel"], resource) when { context has channel && context.channel == "$channel" };""",
                ),
                "test",
            )
            val executeFingerprint = fx.decide(sql, approver, Channel.WORKFLOW_EXECUTOR, providedRoles = setOf(ANALYST)).resultFingerprint
            val approverToken = token(approver, setOf("mcp:query", "mcp:approvals:write"))
            try {
                val id = pendingRequest(requester, fx.datasource.id)
                val inbox = client.call(approverToken, "list_approval_inbox").ok().getValue("result").jsonArray
                    .map { it.jsonObject.getValue("id").jsonPrimitive.long }
                if (channel == "mcp") {
                    assertFalse(id in inbox, "inbox $inbox")
                    assertEquals("approval.not_approver", client.call(approverToken, "approve_approval", idArg(id)).error())
                    assertEquals("common.not_found", client.call(approverToken, "get_approval", idArg(id)).error())
                    assertEquals("PENDING", core.accessStore.getRequest(id)?.status)
                    continue
                }
                assertTrue(id in inbox, "inbox $inbox")
                assertEquals("APPROVED", client.call(approverToken, "approve_approval", idArg(id)).ok().result().str("status"))
                assertEquals(
                    1L,
                    scalar(
                        "SELECT count(*) FROM audit_event WHERE kind='admin' AND channel='mcp' AND principal=? AND action=? AND resource=?",
                        approver, "task.approve", "AccessRequest::\"$id\"",
                    ),
                )
                withFakeProxy({ _, _, _ -> maskedResult(executeFingerprint, executionDecision(approver)) }) {
                    assertEquals("EXECUTING", client.call(approverToken, "execute_approval", idArg(id)).ok().result().str("decision"))
                    withTimeout(10_000) {
                        while (client.call(approverToken, "get_approval", idArg(id)).ok().result()
                                .getValue("request").jsonObject.str("status") != "EXECUTED"
                        ) {
                            delay(50)
                        }
                    }
                }
                assertEquals(maskedRows, client.call(approverToken, "get_approval_result", idArg(id)).ok().result().rows())
                assertEquals("EXECUTED", client.call(approverToken, "cancel_approval", idArg(id)).ok().result().str("status"))
            } finally {
                core.cedarPolicyStore.delete(policy.id)
            }
        }
    }

    @Test
    fun `run_query self-approves on the editor channel, never on mcp`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        for (channel in listOf("editor", "mcp")) {
            val principal = analyst("self-$channel")
            val policies = listOf(
                """permit(principal == User::"$principal", action == Action::"task.approve", resource) when { context has channel && context.channel == "$channel" };""",
                """forbid(principal == User::"$principal", action == Action::"task.approve", resource) unless { context has channel && context.channel == "$channel" };""",
            ).map { core.cedarPolicyStore.create(CedarPolicyInput("mcp-self-approve-channel-${seq.incrementAndGet()}", it), "test") }
            val fingerprint = fx.decide(sql, principal, Channel.EDITOR).resultFingerprint
            try {
                withFakeProxy({ _, _, _ -> maskedResult(fingerprint, executionDecision(principal, Channel.EDITOR)) }) {
                    val result = client.call(token(principal, setOf("mcp:query")), "run_query", buildJsonObject {
                        put("datasource", fx.datasource.name)
                        put("sql", sql)
                    })
                    if (channel == "editor") {
                        assertEquals("EXECUTED", result.ok().result().str("status"))
                    } else {
                        assertEquals("common.forbidden", result.error())
                        val params = result.getValue("structuredContent").jsonObject.getValue("params").jsonObject
                        assertEquals("task.request, task.approve", params.str("detail"))
                    }
                }
            } finally {
                policies.forEach { core.cedarPolicyStore.delete(it.id) }
            }
        }
    }

    @Test
    fun `run_query goes through the real Decide on the editor channel with the caller's IP`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val n = seq.incrementAndGet()
        val role = core.policyStore.createRole(RoleInput("mcp-ip-reader-$n"))
        val principal = "mcp-ip-$n@example.com"
        fx.policyStore.createAssignment(RoleAssignmentInput(principal, role.id))
        val schema = fx.datasource.defaultSchemas.first()
        val usersTable = "${fx.datasource.name}/${fx.datasource.engine.catalogName(fx.datasource.dbName)}/$schema/users"
        val policies = listOf(
            """permit(principal in Role::"${role.name}", action in [Action::"datasource.connect", Action::"stmt.cat.read"], resource in Datasource::"${fx.datasource.name}") when { context has channel && context.channel == "editor" && context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            """permit(principal in Role::"${role.name}", action == Action::"result.read.unmasked", resource in Table::"$usersTable") unless { resource in Tag::"pii" };""",
        ).map { core.cedarPolicyStore.create(CedarPolicyInput("mcp-ip-reader-$n-${seq.incrementAndGet()}", it), "test") }
        val verdicts = java.util.concurrent.CopyOnWriteArrayList<WireEnfAction>()
        val token = token(principal, setOf("mcp:query"))
        try {
            DriverManager.getConnection(fx.targetJdbcUrl, fx.targetUser, fx.targetPassword).use { target ->
                withFakeProxy({ _, statement, open ->
                    var response = stub.decide(decisionRequest {
                        this.token = open.ephemeralToken
                        datasourceName = fx.datasource.name
                        currentCatalog = fx.datasource.effectiveCatalog
                        connectionId = open.connectionId
                        this.sql = statement
                        searchPath.add(schema)
                    })
                    repeat(3) {
                        if (response.hasBeforeDecide()) {
                            response.beforeDecide.commandsList.forEach { pcf.pushFromTarget(target, open.connectionId, it.refetch.schema) }
                            response = stub.decide(decisionRequest {
                                this.token = open.ephemeralToken
                                datasourceName = fx.datasource.name
                                currentCatalog = fx.datasource.effectiveCatalog
                                connectionId = open.connectionId
                                this.sql = statement
                                searchPath.add(schema)
                            })
                        }
                    }
                    val verdict = response.verdict
                    verdicts += verdict.decision
                    if (verdict.decision == WireEnfAction.DENY) {
                        listOf(proxyRunMsg { decision = runDecision { decision = WireEnfAction.DENY; decisionId = verdict.decisionId; denyReason = verdict.denyReason } })
                    } else {
                        listOf(
                            proxyRunMsg {
                                decision = runDecision {
                                    decision = verdict.decision; decisionId = verdict.decisionId; resultFingerprint += verdict.resultFingerprintList
                                }
                            },
                            proxyRunMsg {
                                resultRows = runResultRows {
                                    columns += "id"
                                    rows += listOf("1", "2").map { v -> runRow { values += runValue { value = v } } }
                                }
                            },
                            proxyRunMsg { done = runDone { rowsAffected = -1 } },
                        )
                    }
                }) {
                    val args = buildJsonObject {
                        put("datasource", fx.datasource.name)
                        put("sql", "SELECT id FROM users ORDER BY id")
                    }
                    val allowed = client.call(token, "run_query", args, forwardedFor = "203.0.113.7").ok().result()
                    assertEquals("EXECUTED", allowed.str("status"))
                    assertEquals(listOf(listOf("1"), listOf("2")), allowed.getValue("page").jsonObject.rows())

                    val denied = client.call(token, "run_query", args, forwardedFor = "198.51.100.7").ok().result()
                    assertEquals("FAILED", denied.str("status"))
                    assertNotNull(denied.getValue("statements").jsonArray.single().jsonObject["decisionId"])
                }
            }
            assertEquals(listOf(WireEnfAction.ALLOW, WireEnfAction.DENY), verdicts.toList())
        } finally {
            policies.forEach { core.cedarPolicyStore.delete(it.id) }
        }
    }

    @Test
    fun `datasource discovery and task status tools`() = testApplication {
        application { installTestMcp() }
        val client = createClient { expectSuccess = false }
        val principal = analyst("smoke")
        val token = token(principal, setOf("mcp:query"))
        val hidden = core.datasourceStore.create(DatasourceInput("mcp-hidden-${seq.incrementAndGet()}", "mysql", "localhost", 3306, "app"))

        val listed = client.call(token, "list_connectable_datasources").ok().getValue("result").jsonArray.map { it.jsonObject }
        assertContains(listed.map { it.str("name") }, fx.datasource.name)
        assertFalse(hidden.name in listed.map { it.str("name") })
        assertTrue(listed.none { "host" in it || "port" in it }, listed.toString())

        val described = client.call(token, "describe_datasource", buildJsonObject { put("datasource", fx.datasource.name) })
        assertTrue(described.ok().getValue("result").jsonArray.isNotEmpty())
        assertEquals(
            "datasource.not_connectable",
            client.call(token, "describe_datasource", buildJsonObject { put("datasource", hidden.name) }).error(),
        )

        val options = client.call(token, "discover_roles", buildJsonObject {
            put("datasource", fx.datasource.name)
            put("sql", sql)
        }).ok().result().getValue("options").jsonArray.map { it.jsonObject.str("roleName") }
        assertContains(options, ANALYST)

        val task = core.accessStore.createEditorTask(principal, fx.datasource.id, listOf(sql), listOf(ANALYST), approver = principal)
        val taskArg = buildJsonObject { put("taskId", task.id) }
        assertEquals("APPROVED", client.call(token, "get_query_status", taskArg).ok().result().str("status"))
        assertEquals("APPROVED", client.call(token, "cancel_query", taskArg).ok().result().str("status"))
    }

    // ---- harness ------------------------------------------------------------------------------

    private fun Application.installTestMcp(withStorage: Boolean = true) {
        install(ContentNegotiation) { json(TEST_JSON) }
        val config = config(withStorage)
        val recorder = ManagementAuditRecorder(core.auditStore)
        val datasourceService = DatasourceManagementService(core.datasourceStore, core.proxyEventsHub, TableDetailService(core), recorder)
        val policyService = PolicyManagementService(core.cedarPolicyStore, core.policyStore, recorder)
        val identityService = IdentityManagementService(
            fx.dataSource, core.userGroupStore, core.policyStore, core.tokenStore, core.accessStore,
            PrincipalSessionStore(fx.dataSource, null), recorder,
        )
        val store = resultStore.takeIf { withStorage }
        val editorTasks = EditorTaskService(
            config, core.datasourceStore, core.accessStore, store, core.policyStore, core.userGroupStore,
            core.roleResolver, core.authz, runExecService, appScope, core.systemClassification, core.taskCompletionHub,
            core.auditStore,
        )
        val approvals = ApprovalService(
            config, core.accessStore, core.auditStore, core.datasourceStore, core.policyStore, core.userGroupStore,
            store, core.roleResolver, core.authz, runExecService, appScope, core.systemClassification,
            core.taskCompletionHub,
        )
        installMcp(config, core, datasourceService, policyService, identityService, editorTasks, approvals)
    }

    /** Answers every run the control plane opens on the fixture datasource with [respond]'s frames while [body] runs. */
    private suspend fun withFakeProxy(
        respond: suspend (WireIdentity?, String, OpenRunChannel) -> List<ProxyRunMsg>,
        body: suspend () -> Unit,
    ) = supervisorScope {
        val proxy = launch {
            stub.events(eventsRequest { datasourceName = fx.datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION })
                .collect { event ->
                    if (!event.hasOpenRunChannel()) return@collect
                    val open = event.openRunChannel
                    val identity = core.tokenStore.resolve(open.ephemeralToken)
                    launch {
                        val out = KChannel<ProxyRunMsg>(KChannel.UNLIMITED)
                        out.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
                        out.send(proxyRunMsg { serving = runServing {} })
                        stub.runExec(out.receiveAsFlow()).collect { control ->
                            when {
                                control.hasQuery() -> respond(identity, control.query.sql, open).forEach { out.send(it) }
                                control.hasClose() -> out.close()
                            }
                        }
                    }
                }
        }
        try {
            withTimeout(5_000) { while (fx.datasource.name !in core.proxyEventsHub.attached()) delay(20) }
            body()
        } finally {
            proxy.cancel()
            withTimeout(5_000) { while (fx.datasource.name in core.proxyEventsHub.attached()) delay(20) }
        }
    }

    private fun executionDecision(principal: String, channel: Channel = Channel.WORKFLOW_EXECUTOR): Long = core.auditStore.insert(
        AuditEvent(principal = principal, datasource = fx.datasource.name, statement = sql, decision = Decision.MASK, channel = channel.contextValue),
    )

    private fun maskedResult(fingerprint: List<com.ridi.oss.proxymonster.analyzer.pb.RequireResultReadGrant>, decisionId: Long) = listOf(
        proxyRunMsg {
            decision = runDecision {
                decision = WireEnfAction.MASK
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

    private fun analyst(label: String): String {
        val principal = "mcp-$label-${seq.incrementAndGet()}@example.com"
        fx.policyStore.createAssignment(RoleAssignmentInput(principal, analystRoleId))
        return principal
    }

    private fun pendingRequest(requester: String, datasourceId: Long): Long = core.accessStore.createQueryRequest(
        principal = requester, datasourceId = datasourceId, statements = listOf(sql), denyReason = null,
        sourceDecisionId = null, reason = "need it", title = "t", evaluatedDecision = "DENY", roleId = analystRoleId,
    ).id

    private fun seedApprovalResult(requester: String, approver: String, decisionId: Long): Long {
        val id = fx.dataSource.connection.use { c ->
            c.prepareStatement(
                "INSERT INTO access_request (principal, kind, datasource_id, role_id, execute_as, creator_kind, decided_by, status) " +
                    "VALUES (?, 'QUERY', ?, ?, ?::jsonb, 'WORKFLOW', ?, 'EXECUTED') RETURNING id",
            ).use { ps ->
                ps.setString(1, requester)
                ps.setLong(2, fx.datasource.id)
                ps.setLong(3, analystRoleId)
                ps.setString(4, "[\"$ANALYST\"]")
                ps.setString(5, approver)
                ps.executeQuery().use { rs -> check(rs.next()); rs.getLong(1) }
            }
        }
        fx.dataSource.connection.use { c ->
            c.prepareStatement("INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, ?, 'fixture')").use { ps ->
                ps.setLong(1, id); ps.setString(2, sql); ps.executeUpdate()
            }
        }
        assertNotNull(resultStore.startNextRun(id, approver))
        val fingerprint = fingerprintOf(fx.decide(sql, providedRoles = setOf(ANALYST)).resultFingerprint)
        assertNotNull(resultStore.completeRun(id, DecryptedResult(listOf("id", "ssn"), maskedRows, resultFingerprint = fingerprint), 3600, decisionId))
        return id
    }

    private fun idArg(id: Long) = buildJsonObject { put("id", id) }

    private suspend fun HttpClient.rawCall(
        token: String,
        tool: String,
        args: JsonObject = JsonObject(emptyMap()),
        forwardedFor: String? = null,
    ): HttpResponse =
        post("/mcp") {
            forwardedFor?.let { header("X-Forwarded-For", it) }
            header(HttpHeaders.Accept, "application/json, text/event-stream")
            contentType(ContentType.Application.Json)
            header("MCP-Protocol-Version", "2025-06-18")
            header(HttpHeaders.Authorization, "Bearer $token")
            setBody(
                buildJsonObject {
                    put("jsonrpc", "2.0")
                    put("id", seq.incrementAndGet())
                    put("method", "tools/call")
                    put("params", buildJsonObject { put("name", tool); put("arguments", args) })
                }.toString(),
            )
        }

    private suspend fun HttpClient.call(
        token: String,
        tool: String,
        args: JsonObject = JsonObject(emptyMap()),
        forwardedFor: String? = null,
    ): JsonObject =
        TEST_JSON.parseToJsonElement(rawCall(token, tool, args, forwardedFor).bodyAsText()).jsonObject.getValue("result").jsonObject

    private fun structured(body: String): JsonObject =
        TEST_JSON.parseToJsonElement(body).jsonObject.getValue("result").jsonObject.getValue("structuredContent").jsonObject

    private fun JsonObject.ok(): JsonObject {
        assertTrue(this["isError"]?.jsonPrimitive?.content != "true", toString())
        return getValue("structuredContent").jsonObject
    }

    private fun JsonObject.error(): String? {
        assertEquals("true", this["isError"]?.jsonPrimitive?.content, toString())
        return getValue("structuredContent").jsonObject.code()
    }

    private fun JsonObject.code(): String? = this["code"]?.jsonPrimitive?.content

    private fun JsonObject.result(): JsonObject = getValue("result").jsonObject

    private fun JsonObject.str(name: String): String? = (this[name] as? JsonPrimitive)?.content

    private fun JsonObject.rows(): List<List<String?>> = getValue("rows").jsonArray.map { row ->
        row.jsonArray.map { (it as? JsonPrimitive)?.takeUnless { p -> p.toString() == "null" }?.content }
    }

    private fun token(principal: String, scopes: Set<String>): String {
        val consent = oauth.rememberConsent(principal, CLIENT_ID, RESOURCE, scopes)
        val code = oauth.createAuthorizationCode(
            AuthorizationCodeInput(CLIENT_ID, principal, REDIRECT_URI, RESOURCE, scopes, CHALLENGE, consentId = consent.id),
        )
        return assertNotNull(
            oauth.consumeAuthorizationCode(
                ConsumeAuthorizationCodeInput(code, CLIENT_ID, REDIRECT_URI, RESOURCE, VERIFIER, 600, 3_600),
            ),
        ).accessToken
    }

    private fun scalar(query: String, vararg values: String): Long = fx.dataSource.connection.use { c ->
        c.prepareStatement(query).use { ps ->
            values.forEachIndexed { i, v -> ps.setString(i + 1, v) }
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    private fun config(withStorage: Boolean) = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = false,
        secretToken = null,
        sessionSecret = "mcp-query-tools-test-secret",
        oidc = null,
        resultKey = if (withStorage) ByteArray(32) else null,
        scimToken = null,
        sessionWindowSeconds = 3_600,
        idpRecheckIntervalSeconds = 600,
        devMarker = false,
        mcpResource = RESOURCE,
        trustedProxies = setOf("localhost"),
    )

    private companion object {
        const val ANALYST = "analyst"
        val TEST_JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        const val RESOURCE = "http://localhost/mcp"
        const val CLIENT_ID = "https://client.example/mcp.json"
        const val REDIRECT_URI = "http://127.0.0.1:43110/callback"
        val VERIFIER = "m".repeat(43)
        val CHALLENGE = pkceS256(VERIFIER)
    }
}
