package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.editorError

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.pushTestCatalog
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import com.ridi.oss.proxymonster.grpc.ResultRequirements
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Route-level regression coverage for assume-R result viewing: the encrypted store holds R's
 * execution-enforced output, while every GET /result re-decides under exactly R at workflow-viewer using
 * the viewer's live requester-IP-derived tags. The tests deliberately store raw PII (an executor that ran
 * where it could unmask) so a snapshot-as-is path fails the context, revocation, DENY, and catalog-drift
 * cases with observable cleartext.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalResultViewContextDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var resultStore: QueryResultStore
    private lateinit var editorExecService: EditorExecService
    // The request detail is served by cp-go; the result route stays on the in-process Kotlin routes.
    private lateinit var cpGo: CpGoStack
    private lateinit var config: Config
    private var roleId: Long = 0
    private var segregatedUnmaskPolicyId: Long = 0
    private var requesterUnmaskForbidPolicyId: Long = 0

    private val roleName = "pii-reader"
    private val executor = "approver@example.com"
    private val requester = "requester@example.com"
    private val approver = executor
    private val auditor = "auditor@example.com"
    private val admin = "admin@example.com"
    private val outsider = "outsider@example.com"
    private val rawSsn = "987-65-4320"
    private val maskedSsn = "*******4320"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        resultStore = QueryResultStore(fx.dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        editorExecService = EditorExecService(ControlPlaneCore(fx.dataSource))
        config = Config(
            httpPort = 0,
            dbUrl = "",
            dbUser = "",
            dbPassword = "",
            authDebug = false,
            secretToken = null,
            sessionSecret = "approval-result-view-test-secret",
            oidc = null,
            resultKey = null,
            scimToken = null,
            sessionWindowSeconds = 3600,
            idpRecheckIntervalSeconds = 600,
            devMarker = true,
            trustedProxies = setOf("localhost"),
        )
        val stackConfig = config.copy(sessionSecret = "approval-result-view-cp-go-secret-32", resultKey = ByteArray(32) { it.toByte() })
        cpGo = CpGoStack(stackConfig, ControlPlaneCore(fx.dataSource), fx.metaDatabase) {
            routing { testLoginRoute(PrincipalSessionStore(fx.dataSource, null), stackConfig) }
        }
        listOf(executor, requester, approver, auditor, admin, outsider).distinct().forEach { principal ->
            fx.userGroupStore.createUser(
                AppUserInput(principal = principal),
                fx.tokenStore,
                fx.accessStore,
                fx.daemonSessionStore,
            )
        }

        roleId = fx.policyStore.createRole(RoleInput(roleName)).id
        val auditorRole = fx.policyStore.listRoles().first { it.name == "system:auditor" }
        fx.policyStore.createAssignment(RoleAssignmentInput(auditor, auditorRole.id))
        val adminRole = fx.policyStore.listRoles().first { it.name == "system:admin" }
        fx.policyStore.createAssignment(RoleAssignmentInput(admin, adminRole.id))
        val usersTableEuid = "${fx.datasource.name}/${fx.datasource.dbName}/public/users"
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-segregated-tag",
                cedarSrc = """permit(
                    principal, action == Action::"context.tag::segregated", resource
                ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };""",
            ),
            updatedBy = "test-fixture",
        )
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-pii-reader-masked",
                cedarSrc = """permit(
                    principal in Role::"$roleName", action == Action::"result.read.masked", resource in Table::"$usersTableEuid"
                ) when { resource in Tag::"pii" };""",
            ),
            updatedBy = "test-fixture",
        )
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-pii-reader-unmasked-non-pii",
                cedarSrc = """permit(
                    principal in Role::"$roleName", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid"
                ) unless { resource in Tag::"pii" };""",
            ),
            updatedBy = "test-fixture",
        )
        segregatedUnmaskPolicyId = fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-pii-reader-unmasked-segregated",
                cedarSrc = """permit(
                    principal in Role::"$roleName", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid"
                ) when {
                    resource in Tag::"pii" && context has tags && context.tags.contains("segregated")
                };""",
            ),
            updatedBy = "test-fixture",
        ).id
        requesterUnmaskForbidPolicyId = fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-requester-unmask-forbid",
                cedarSrc = """forbid(
                    principal, action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid"
                ) when { principal == User::"$requester" && resource in Tag::"pii" };""",
                enabled = false,
            ),
            updatedBy = "test-fixture",
        ).id
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-pii-reader-connect-select",
                cedarSrc = """permit(
                    principal in Role::"$roleName",
                    action in [Action::"datasource.connect", Action::"stmt.cat.read", Action::"stmt.cat.metadata"],
                    resource in Datasource::"${fx.datasource.name}"
                );""",
            ),
            updatedBy = "test-fixture",
        )
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    private fun ApplicationTestBuilder.wire(): HttpClient {
        application { installRoutes() }
        return createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private fun Application.installRoutes() {
        val sessionStore = PrincipalSessionStore(fx.dataSource, null)
        attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(Sessions) {
            webSessionCookie(sessionStore, config.sessionSecret)
        }
        routing {
            post("/test/session/{principal}") {
                val deviceId = call.ensureDeviceCookie(secure = false)
                call.sessions.set(
                    WebSessionRef(
                        sessionStore.mintWeb(
                            requireNotNull(call.parameters["principal"]),
                            null,
                            config.webSessionAbsoluteSeconds,
                            config.webSessionIdleSeconds,
                            deviceId,
                        ),
                    ),
                )
                call.respond(HttpStatusCode.NoContent)
            }
            approvalRoutes(
                config,
                fx.accessStore,
                fx.auditStore,
                fx.datasourceStore,
                fx.policyStore,
                fx.userGroupStore,
                resultStore,
                fx.roleResolver,
                fx.authz,
                editorExecService,
            )
        }
    }

    private suspend fun HttpClient.login(principal: String) {
        assertEquals(HttpStatusCode.NoContent, post("/test/session/$principal").status)
    }

    private fun resetMutableAuthzState() {
        listOf(executor, requester, approver, auditor, admin, outsider).distinct().forEach { fx.userGroupStore.setUserActive(it, true) }
        assertNotNull(fx.cedarPolicyStore.setEnabled(segregatedUnmaskPolicyId, true, "test-fixture"))
        assertNotNull(fx.cedarPolicyStore.setEnabled(requesterUnmaskForbidPolicyId, false, "test-fixture"))
    }

    private fun seedResult(
        sql: String = "SELECT id, email, ssn FROM users",
        columns: List<String> = listOf("id", "email", "ssn"),
        rows: List<List<String?>> = listOf(listOf("1", "a@x", rawSsn)),
        truncatedByCap: Boolean = false,
        // What the execution stored for the view; null models a legacy result.
        resultRequirements: ResultRequirements = fx.decide(sql, channel = Channel.WORKFLOW_EXECUTOR, providedRoles = setOf(roleName)).resultRequirements!!,
        decisionId: Long? = executionDecision(sql),
        sourceDecisionId: Long? = null,
    ): Long {
        val reqId = fx.dataSource.connection.use { c ->
            c.prepareStatement(
                "INSERT INTO access_request (principal, kind, datasource_id, role_id, execute_as, creator_kind, decided_by, source_decision_id) VALUES (?, 'QUERY', ?, ?, ?::jsonb, 'WORKFLOW', ?, ?) RETURNING id",
            ).use { ps ->
                ps.setString(1, requester)
                ps.setLong(2, fx.datasource.id)
                ps.setLong(3, roleId)
                ps.setString(4, "[\"$roleName\"]")
                ps.setString(5, approver)
                ps.setObject(6, sourceDecisionId)
                ps.executeQuery().use { rs ->
                    check(rs.next())
                    rs.getLong(1)
                }
            }
        }
        fx.dataSource.connection.use { c -> c.prepareStatement("INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, ?, 'fixture')").use { ps -> ps.setLong(1, reqId); ps.setString(2, sql); ps.executeUpdate() } }
        assertNotNull(resultStore.startNextRun(reqId, executor))
        resultStore.recordRequirements(reqId, resultRequirements)
        assertNotNull(resultStore.completeRun(reqId, DecryptedResult(columns, rows, truncatedByCap = truncatedByCap), 3600, decisionId ?: executionDecision(sql)))
        // The FK's ON DELETE SET NULL can still leave a DONE row without its decision.
        if (decisionId == null) fx.dataSource.connection.use { c -> c.prepareStatement("UPDATE query_result SET decision_id = NULL WHERE task_id = ?").use { ps -> ps.setLong(1, reqId); ps.executeUpdate() } }
        return reqId
    }

    private fun executionDecision(sql: String, decision: Decision = Decision.ALLOW): Long = fx.auditStore.insert(
        AuditEvent(principal = executor, datasource = fx.datasource.name, statement = sql, decision = decision, channel = "workflow-executor"),
    )

    private fun seedFailedResult(rawText: String, redactedForm: String): Long {
        val reqId = fx.dataSource.connection.use { c ->
            c.prepareStatement(
                "INSERT INTO access_request (principal, kind, datasource_id, role_id, execute_as, creator_kind, decided_by) VALUES (?, 'QUERY', ?, ?, ?::jsonb, 'WORKFLOW', ?) RETURNING id",
            ).use { ps ->
                ps.setString(1, requester)
                ps.setLong(2, fx.datasource.id)
                ps.setLong(3, roleId)
                ps.setString(4, "[\"$roleName\"]")
                ps.setString(5, approver)
                ps.executeQuery().use { rs ->
                    check(rs.next())
                    rs.getLong(1)
                }
            }
        }
        fx.dataSource.connection.use { c ->
            c.prepareStatement("INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, 'SELECT id, email, ssn FROM users', 'fixture')").use { ps ->
                ps.setLong(1, reqId)
                ps.executeUpdate()
            }
        }
        assertNotNull(resultStore.startNextRun(reqId, executor))
        val requirements = fx.decide("SELECT id, email, ssn FROM users", channel = Channel.WORKFLOW_EXECUTOR, providedRoles = setOf(roleName)).resultRequirements!!
        resultStore.recordRequirements(reqId, requirements)
        assertNotNull(resultStore.failRun(reqId, "approval.query_failed", diagnostic = editorError { message = redactedForm; rawMessage = rawText; targetDbError = true }))
        return reqId
    }

    private fun ciphertext(requestId: Long): ByteArray = fx.dataSource.connection.use { c ->
        c.prepareStatement("SELECT ciphertext FROM query_result WHERE task_id = ?").use { ps ->
            ps.setLong(1, requestId)
            ps.executeQuery().use { rs ->
                check(rs.next())
                rs.getBytes(1)
            }
        }
    }

    /** The latest result-view event a [principal] earned on [requestId] (now a normal audit_event row). */
    private fun viewEvent(requestId: Long, principal: String): String? = fx.dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT statement FROM audit_event WHERE principal = ? AND statement LIKE ? ORDER BY id DESC LIMIT 1",
        ).use { ps ->
            ps.setString(1, principal)
            ps.setString(2, "approval #$requestId result-viewed-%")
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }
    }

    @Test
    fun `the same stored result masks off-segregated and unmasks in-context for approver and requester`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult()
        val storedBefore = ciphertext(id)
        val client = wire()
        client.login(executor)

        val executorMasked = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, executorMasked.status)
        assertEquals(maskedSsn, executorMasked.body<QueryResultView>().rows.single()[2])
        assertContentEquals(storedBefore, ciphertext(id), "view-time masking must not rewrite stored ciphertext")

        val executorRaw = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.OK, executorRaw.status)
        assertEquals(rawSsn, executorRaw.body<QueryResultView>().rows.single()[2])
        assertContentEquals(storedBefore, ciphertext(id), "the in-context view must read the same stored bytes")

        client.login(requester)
        val requesterMasked = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, requesterMasked.status)
        assertEquals(maskedSsn, requesterMasked.body<QueryResultView>().rows.single()[2])

        val requesterRaw = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.OK, requesterRaw.status)
        assertEquals(rawSsn, requesterRaw.body<QueryResultView>().rows.single()[2])
        assertContentEquals(storedBefore, ciphertext(id), "release and live requester views must not alter ciphertext")
        assertTrue(
            fx.auditStore.recent(100).filter { it.statement.startsWith("approval #$id ") }.all {
                it.kind == "approval_lifecycle"
            },
            "approval lifecycle audit events must carry their explicit kind",
        )
    }

    // A saved query whose derived output over the masked column redacts in full (kind NULL) must come back
    // BLANK on view — never falling back to the stored cleartext. Guards the Approvals.kt mask-application
    // fix (distinguish "no mask for this index" from "mask → null"); the other view tests use only LAST_N,
    // which never returns null, so they would pass even on the buggy `?: value` form. (docs/derived-masking.md)
    @Test
    fun `a NULL-kind redaction of a derived output blanks the cell on view, not the stored cleartext`() = testApplication {
        resetMutableAuthzState()
        // upper(ssn) is a provably-total transform of the masked ssn → redacted in full (kind NULL). For an
        // all-digit/dash SSN, upper(ssn) == ssn, so a `?: value` fallback would leak the raw SSN on view.
        val derivedCleartext = rawSsn.uppercase()
        val id = seedResult(
            sql = "SELECT id, upper(ssn) AS u FROM users",
            columns = listOf("id", "u"),
            rows = listOf(listOf("1", derivedCleartext)),
        )
        val client = wire()
        client.login(executor)
        val resp = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, resp.status)
        val row = resp.body<QueryResultView>().rows.single()
        assertEquals("1", row[0], "the non-sensitive id column is returned intact")
        assertNull(row[1], "a NULL-kind redaction must blank the derived cell, not fall back to the stored cleartext")
        assertFalse(derivedCleartext in row.filterNotNull(), "the cleartext derived value must not leak on view")
    }

    @Test
    fun `the live decision uses the viewer principal rather than the requester identity`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult()
        val client = wire()
        client.login(executor)
        assertNotNull(fx.cedarPolicyStore.setEnabled(requesterUnmaskForbidPolicyId, true, "test-fixture"))
        try {
            val response = client.get("/api/approvals/$id/result") {
                header("X-Forwarded-For", "100.100.5.5")
            }
            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals(
                rawSsn,
                response.body<QueryResultView>().rows.single()[2],
                "a requester-scoped forbid must not apply to the executing viewer",
            )
        } finally {
            fx.cedarPolicyStore.setEnabled(requesterUnmaskForbidPolicyId, false, "test-fixture")
        }
    }

    @Test
    fun `disabling the live unmask grant re-masks the next view without changing storage`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult()
        val storedBefore = ciphertext(id)
        val client = wire()
        client.login(executor)

        val raw = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.OK, raw.status)
        assertEquals(rawSsn, raw.body<QueryResultView>().rows.single()[2])

        assertNotNull(fx.cedarPolicyStore.setEnabled(segregatedUnmaskPolicyId, false, "test-fixture"))
        try {
            val remasked = client.get("/api/approvals/$id/result") {
                header("X-Forwarded-For", "100.100.5.5")
            }
            assertEquals(HttpStatusCode.OK, remasked.status)
            assertEquals(maskedSsn, remasked.body<QueryResultView>().rows.single()[2])
            assertContentEquals(storedBefore, ciphertext(id), "policy revocation must affect only the live response")
        } finally {
            fx.cedarPolicyStore.setEnabled(segregatedUnmaskPolicyId, true, "test-fixture")
        }
    }

    @Test
    fun `a stored-result view charges the viewer's relayed volume against the execution decision`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult(rows = listOf(listOf("1", "a@x", rawSsn), listOf("2", "b@x", rawSsn)))
        val decisionId = fx.auditStore.insert(
            AuditEvent(principal = executor, datasource = fx.datasource.name, statement = "SELECT id, email, ssn FROM users", decision = Decision.ALLOW, channel = "workflow-executor"),
        )
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE query_result SET decision_id = ? WHERE task_id = ?").use { ps -> ps.setLong(1, decisionId); ps.setLong(2, id); ps.executeUpdate() }
        }
        val client = wire()
        client.login(requester)
        val hour = java.time.Duration.ofHours(1)
        val before = fx.auditStore.relayedVolume(requester, fx.datasource.name, listOf(hour), java.time.Instant.now()).getValue(hour)
        val response = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, response.status)
        val released = response.body<QueryResultView>().rows
        assertEquals(2, released.size)
        val after = fx.auditStore.relayedVolume(requester, fx.datasource.name, listOf(hour), java.time.Instant.now()).getValue(hour)
        assertEquals(before.rows + 2, after.rows, "the viewer, not the executor, is charged the released rows")
        val releasedBytes = released.sumOf { row -> row.sumOf { it?.toByteArray(Charsets.UTF_8)?.size ?: 0 } }.toLong()
        assertEquals(before.bytes + releasedBytes, after.bytes, "bytes charged are the released (masked) cells")
        val charge = fx.auditStore.recent(50).first { it.kind == "completion" && it.principal == requester && it.decisionId == decisionId }
        assertEquals("workflow-viewer", charge.channel)
        assertTrue(
            fx.auditStore.recent(50).none { it.kind == "completion" && it.principal == executor && it.decisionId == decisionId },
            "the executor is not charged for someone else's view",
        )
    }

    @Test
    fun `a stored result with no execution decision is refused, audited, and not charged`() = testApplication {
        resetMutableAuthzState()
        val client = wire()
        client.login(requester)
        for (sourceDecisionId in listOf(null, executionDecision("SELECT id, email, ssn FROM users", Decision.DENY))) {
            val id = seedResult(decisionId = null, sourceDecisionId = sourceDecisionId)
            val hour = java.time.Duration.ofHours(1)
            val before = fx.auditStore.relayedVolume(requester, fx.datasource.name, listOf(hour), java.time.Instant.now()).getValue(hour)
            val completionsBefore = fx.auditStore.recent(200).count { it.kind == "completion" && it.principal == requester }
            val response = client.get("/api/approvals/$id/result") { header("X-Forwarded-For", "100.100.5.5") }
            assertEquals(HttpStatusCode.Forbidden, response.status)
            assertEquals("approval.result_view_denied", response.body<ApiError>().code)
            assertFalse(rawSsn in response.bodyAsText(), "no rows are returned")
            assertTrue(
                fx.auditStore.recent(50).any { it.principal == requester && it.statement == "approval #$id result-view-denied" },
                "the refusal is audited",
            )
            assertEquals(completionsBefore, fx.auditStore.recent(200).count { it.kind == "completion" && it.principal == requester })
            assertEquals(before, fx.auditStore.relayedVolume(requester, fx.datasource.name, listOf(hour), java.time.Instant.now()).getValue(hour))
            assertNull(viewEvent(id, requester), "a refused view earns no result-viewed event")
        }
    }

    @Test
    fun `a from-denied request's view charges the execution decision, not the source denial`() = testApplication {
        resetMutableAuthzState()
        val sql = "SELECT id, email, ssn FROM users"
        val sourceDecisionId = executionDecision(sql, Decision.DENY)
        val decisionId = executionDecision(sql)
        val id = seedResult(sql = sql, decisionId = decisionId, sourceDecisionId = sourceDecisionId)
        val client = wire()
        client.login(requester)
        assertEquals(HttpStatusCode.OK, client.get("/api/approvals/$id/result").status)
        val charges = fx.auditStore.recent(50).filter { it.kind == "completion" && it.principal == requester }
        assertTrue(charges.any { it.decisionId == decisionId }, "the view is charged against the execution decision")
        assertTrue(charges.none { it.decisionId == sourceDecisionId }, "the source DENY decision is never charged")
    }

    @Test
    fun `a deactivated executor is hidden before any live result decision`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult()
        val client = wire()
        client.login(executor)
        fx.userGroupStore.setUserActive(executor, false)
        try {
            val response = client.get("/api/approvals/$id/result") {
                header("X-Forwarded-For", "100.100.5.5")
            }
            assertEquals(HttpStatusCode.NotFound, response.status)
            assertFalse(response.bodyAsText().contains(rawSsn), "a deactivated viewer must receive no stored PII")
        } finally {
            fx.userGroupStore.setUserActive(executor, true)
        }
    }

    @Test
    fun `an outsider cannot assume the task role`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult()
        val client = wire()
        client.login(outsider)

        val response = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.NotFound, response.status)
        assertFalse(response.bodyAsText().contains(rawSsn), "the assume gate must return no stored PII")
    }

    @Test
    fun `a requester assumes R and reads their own result`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult()
        val client = wire()
        client.login(requester)

        val response = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(
            response.bodyAsText().contains(rawSsn),
            "task.assume admits the requester and the live exactly-R view decision applies the task role",
        )
    }

    @Test
    fun `a result run in the request's default schema reads back under that schema`() = testApplication {
        resetMutableAuthzState()
        fx.execOnTarget("CREATE SCHEMA IF NOT EXISTS sales")
        fx.execOnTarget("CREATE TABLE IF NOT EXISTS sales.ledger (id BIGINT, amount BIGINT)")
        fx.datasourceStore.pushTestCatalog(fx.datasource, fx.targetJdbcUrl, fx.targetUser, fx.targetPassword)
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-ledger",
                cedarSrc = """permit(
                    principal in Role::"$roleName", action == Action::"result.read.unmasked",
                    resource in Table::"${fx.datasource.name}/${fx.datasource.dbName}/sales/ledger"
                );""",
            ),
            updatedBy = "test-fixture",
        )
        val sql = "SELECT id, amount FROM ledger"
        val ran = decideQuery(
            executor, fx.datasource, sql, Channel.WORKFLOW_EXECUTOR, fx.datasourceStore.catalog(fx.datasource.id),
            fx.policyStore, fx.accessStore, fx.userGroupStore, fx.roleResolver, fx.authz,
            providedRoles = setOf(roleName), liveSearchPath = listOf("sales"),
        )
        val id = seedResult(sql = sql, columns = listOf("id", "amount"), rows = listOf(listOf("1", "4242")), resultRequirements = ran.resultRequirements!!)
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET source = 'github', repository = 'acme/shop', pr = 1, default_schema = 'sales' WHERE id = ?").use { ps -> ps.setLong(1, id); ps.executeUpdate() }
        }
        val client = wire()
        client.login(requester)

        val response = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertTrue(response.bodyAsText().contains("4242"))
    }

    @Test
    fun `approver and auditor assume R while admin sees metadata only`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult()
        val client = wire()

        for (principal in listOf(approver, auditor)) {
            client.login(principal)
            val response = client.get("/api/approvals/$id/result") { header("X-Forwarded-For", "100.100.5.5") }
            assertEquals(HttpStatusCode.OK, response.status, principal)
            assertEquals(rawSsn, response.body<QueryResultView>().rows.single()[2], principal)
        }
        // The approver's view is credited to the approver; the auditor is neither party and must NOT be
        // miscredited as the approver — its view is recorded as a neutral assumer event.
        assertEquals("approval #$id result-viewed-by-approver", viewEvent(id, approver))
        assertEquals("approval #$id result-viewed-by-assumer", viewEvent(id, auditor))

        // An assumer's metadata carries the result cardinality; the admin's must not (task.read is
        // metadata-only, and row count is a result-derived existence/cardinality oracle behind task.assume).
        // The requester holds both task.read (self-request seed) and task.assume (party seed), so their
        // GET /{id} returns the un-redacted meta.
        val console = cpGo.client()
        console.login(requester)
        assertNotNull(
            console.get("/api/approvals/$id").body<QueryRequestDetail>().result?.rowCount,
            "an assumer sees the result row count in metadata",
        )

        console.login(admin)
        val adminDetail = console.get("/api/approvals/$id")
        assertEquals(HttpStatusCode.OK, adminDetail.status, "admin may read metadata")
        val adminMeta = adminDetail.body<QueryRequestDetail>().result
        assertNotNull(adminMeta, "admin still sees execution status metadata")
        assertNull(adminMeta.rowCount, "admin (task.read only) must not learn the result row count")
        assertTrue(adminMeta.columns.isEmpty(), "admin (task.read only) must not learn the result column shape")
        // A new web session for the same principal ends the older one, so the admin signs in here last.
        client.login(admin)
        assertEquals(HttpStatusCode.NotFound, client.get("/api/approvals/$id/result").status, "admin may not assume R")
    }

    @Test
    fun `an authorized passthrough result is released to the viewer`() = testApplication {
        // A passthrough (SHOW / DESCRIBE / a session-config read) carries no column-masking model, so the view
        // has nothing to narrow. Once the live re-decision under {R} authorizes the statement, "authorized to
        // run" is "authorized to see" — the stored bytes are released as-is. The DENY branch is the boundary
        // (see the SET and ungranted-table cases below), not a blanket passthrough deny.
        resetMutableAuthzState()
        val value = "reporting, public"
        val id = seedResult(
            sql = "SHOW search_path",
            columns = listOf("search_path"),
            rows = listOf(listOf(value)),
        )
        val client = wire()
        client.login(executor)

        val response = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, response.status)
        val view = response.body<QueryResultView>()
        assertEquals(listOf("search_path"), view.columns)
        assertEquals(value, view.rows.single().single())
    }

    @Test
    fun `a passthrough that re-decides DENY is still refused without stored data`() = testApplication {
        // Dropping the blanket passthrough deny must not widen the DENY branch: a session statement re-decides
        // DENY on the workflow-viewer channel (each view runs on a fresh connection, no session to mutate), so
        // its stored bytes stay locked.
        resetMutableAuthzState()
        val sentinel = "LEAK-SENTINEL-SESSION"
        val id = seedResult(
            sql = "SET search_path TO reporting",
            columns = listOf("ok"),
            rows = listOf(listOf(sentinel)),
        )
        val client = wire()
        client.login(executor)

        val response = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        val responseBody = response.bodyAsText()
        assertEquals("approval.result_view_denied", Json.decodeFromString<ApiError>(responseBody).code)
        assertFalse(responseBody.contains(sentinel), "a denied passthrough must not release stored values")
    }

    @Test
    fun `a live DENY on an ungranted table returns 403 without stored sentinel data`() = testApplication {
        resetMutableAuthzState()
        val sentinel = "LEAK-SENTINEL-777"
        val id = seedResult(
            sql = "SELECT id, amount FROM orders",
            columns = listOf("id", "amount"),
            rows = listOf(listOf("1", sentinel)),
        )
        val client = wire()
        client.login(executor)

        val response = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        val responseBody = response.bodyAsText()
        assertEquals("approval.result_view_denied", Json.decodeFromString<ApiError>(responseBody).code)
        assertFalse(responseBody.contains(sentinel), "a denied live decision must not echo stored values")
    }

    @Test
    fun `output-column drift fails closed before any partially matched row is returned`() = testApplication {
        resetMutableAuthzState()
        val sentinel = "LEAK-SENTINEL-DRIFT"
        val id = seedResult(
            columns = listOf("id", "email"),
            rows = listOf(listOf("1", sentinel)),
        )
        val client = wire()
        client.login(executor)

        val response = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        val responseBody = response.bodyAsText()
        assertEquals("approval.result_view_denied", Json.decodeFromString<ApiError>(responseBody).code)
        assertFalse(responseBody.contains(sentinel), "catalog drift must not return a partially rebound row")
    }

    @Test
    fun `a FAILED run's target-DB detail is re-gated per viewer, never on the metadata poll`() = testApplication {
        resetMutableAuthzState()
        val raw = "ERROR: relation \"orders_missing\" does not exist"
        val redacted = "ERROR: 42P01 undefined_table"
        val id = seedFailedResult(raw, redacted)
        val client = wire()

        // The executor masks ssn here, so it gets the redacted form — the #228 leak closed end-to-end.
        client.login(executor)
        val viewed = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, viewed.status)
        val view = viewed.body<QueryResultView>()
        assertEquals(redacted, view.errorDetail, "a masking viewer gets the redacted form")
        assertFalse(view.errorDetail!!.contains("orders_missing"), "the raw target-DB text must not reach a masking viewer")
        assertTrue(view.rows.isEmpty(), "a FAILED view carries no rows")
        assertTrue(view.columns.isEmpty(), "a FAILED view carries no columns")

        // A task.read-only admin: no detail, and neither form on the metadata poll.
        client.login(admin)
        assertEquals(HttpStatusCode.NotFound, client.get("/api/approvals/$id/result").status, "admin may not assume R")
        val console = cpGo.client().also { it.login(admin) }
        val adminDetail = console.get("/api/approvals/$id")
        assertEquals(HttpStatusCode.OK, adminDetail.status, "admin may read metadata")
        assertFalse(
            adminDetail.bodyAsText().let { it.contains("orders_missing") || it.contains("undefined_table") },
            "no target-DB detail rides on the task.read metadata poll",
        )
        assertEquals("approval.query_failed", adminDetail.body<QueryRequestDetail>().result?.errorCode)
    }

    // The raw-release branch is covered in PresetPolicyDbTest (full reader → sanitizeDiagnostics=false).

    @Test
    fun `stored row-width drift fails closed instead of returning an unbound extra value`() = testApplication {
        resetMutableAuthzState()
        val sentinel = "LEAK-SENTINEL-EXTRA-CELL"
        val id = seedResult(rows = listOf(listOf("1", "a@x", rawSsn, sentinel)))
        val client = wire()
        client.login(executor)

        val response = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        val responseBody = response.bodyAsText()
        assertEquals("approval.result_view_denied", Json.decodeFromString<ApiError>(responseBody).code)
        assertFalse(responseBody.contains(sentinel), "an extra stored cell must never bypass ordinal masking")
    }

    // The view reads only what the run stored and the current classifications, so a table dropped after
    // execution does not change it: the classified column stays masked.
    @Test
    fun `a result over a table dropped after execution stays viewable and masked`() = testApplication {
        resetMutableAuthzState()
        val sql = "SELECT id, secret FROM archive"
        val tableEuid = "${fx.datasource.name}/${fx.datasource.dbName}/public/archive"
        fx.execOnTarget("CREATE TABLE archive (id BIGINT, secret VARCHAR(32))")
        fx.datasourceStore.pushTestCatalog(fx.datasource, fx.targetJdbcUrl, fx.targetUser, fx.targetPassword)
        fx.datasourceStore.upsertClassification(
            fx.datasource.id,
            ClassificationInput(schema = "public", table = "archive", column = "secret", tags = listOf("pii"), catalog = fx.datasource.dbName),
        )
        val policy = fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-archive-masked",
                cedarSrc = """permit(principal in Role::"$roleName", action == Action::"result.read.masked", resource in Table::"$tableEuid");""",
            ),
            updatedBy = "test-fixture",
        )
        try {
            val id = seedResult(sql = sql, columns = listOf("id", "secret"), rows = listOf(listOf("1", rawSsn)))
            fx.execOnTarget("DROP TABLE archive")
            fx.datasourceStore.pushTestCatalog(fx.datasource, fx.targetJdbcUrl, fx.targetUser, fx.targetPassword)
            assertTrue(fx.datasourceStore.catalog(fx.datasource.id).columns.none { it.table == "archive" })
            val client = wire()
            client.login(executor)

            val view = client.get("/api/approvals/$id/result").body<QueryResultView>()
            assertTrue("secret" in view.maskedColumns)
            assertFalse(view.rows.single()[1] == rawSsn, "the classified column of a dropped table stays masked")
        } finally {
            fx.cedarPolicyStore.delete(policy.id)
        }
    }

    // Each stored result's masks bind to its own output positions, however another result orders the same columns.
    @Test
    fun `each stored result masks the positions its own execution recorded`() = testApplication {
        resetMutableAuthzState()
        val ssnLast = seedResult()
        val ssnFirst = seedResult(
            sql = "SELECT ssn, id, email FROM users",
            columns = listOf("ssn", "id", "email"),
            rows = listOf(listOf(rawSsn, "1", "a@x")),
        )
        val client = wire()
        client.login(executor)

        assertEquals(listOf("1", "a@x", maskedSsn), client.get("/api/approvals/$ssnLast/result").body<QueryResultView>().rows.single())
        assertEquals(listOf(maskedSsn, "1", "a@x"), client.get("/api/approvals/$ssnFirst/result").body<QueryResultView>().rows.single())
    }

    // A column read only in a predicate is part of what a result stores, so classifying it later denies the view.
    @Test
    fun `a predicate column classified after execution denies the view`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult(
            sql = "SELECT id FROM users WHERE region = 'kr'",
            columns = listOf("id"),
            rows = listOf(listOf("1")),
        )
        val client = wire()
        client.login(executor)
        assertEquals(HttpStatusCode.OK, client.get("/api/approvals/$id/result").status)

        fx.datasourceStore.upsertClassification(
            fx.datasource.id,
            ClassificationInput(schema = "public", table = "users", column = "region", tags = listOf("pii"), catalog = fx.datasource.dbName),
        )
        try {
            assertEquals(HttpStatusCode.Forbidden, client.get("/api/approvals/$id/result").status)
        } finally {
            fx.datasourceStore.deleteClassification(fx.datasource.id, "public", "users", "region", fx.datasource.dbName)
        }
    }

    // The view decides under the task's live execute-as roles, so changing them changes the masks.
    @Test
    fun `a view under different execute-as roles gets those roles' masks`() = testApplication {
        resetMutableAuthzState()
        val maskedOnly = "pii-masked-reader"
        val maskedOnlyId = fx.policyStore.listRoles().firstOrNull { it.name == maskedOnly }?.id ?: fx.policyStore.createRole(RoleInput(maskedOnly)).id
        val usersTableEuid = "${fx.datasource.name}/${fx.datasource.dbName}/public/users"
        val policies = listOf(
            """permit(principal in Role::"$maskedOnly", action in [Action::"datasource.connect", Action::"stmt.cat.read"], resource in Datasource::"${fx.datasource.name}");""",
            """permit(principal in Role::"$maskedOnly", action == Action::"result.read.masked", resource in Table::"$usersTableEuid");""",
            """permit(principal in Role::"$maskedOnly", action == Action::"result.read.unmasked", resource in Table::"$usersTableEuid") unless { resource in Tag::"pii" };""",
        ).mapIndexed { index, cedarSrc ->
            fx.cedarPolicyStore.create(CedarPolicyInput(name = "approval-view-masked-only-$index", cedarSrc = cedarSrc), updatedBy = "test-fixture").id
        }
        try {
            val id = seedResult()
            val client = wire()
            client.login(executor)
            val asRole = client.get("/api/approvals/$id/result") { header("X-Forwarded-For", "100.100.5.5") }.body<QueryResultView>()
            assertEquals(rawSsn, asRole.rows.single()[2], "the stored role unmasks ssn on the segregated network")

            fx.dataSource.connection.use { c ->
                c.prepareStatement("UPDATE access_request SET role_id = ?, execute_as = ?::jsonb WHERE id = ?").use { ps ->
                    ps.setLong(1, maskedOnlyId)
                    ps.setString(2, "[\"$maskedOnly\"]")
                    ps.setLong(3, id)
                    ps.executeUpdate()
                }
            }
            val asMaskedOnly = client.get("/api/approvals/$id/result") { header("X-Forwarded-For", "100.100.5.5") }.body<QueryResultView>()
            assertEquals(maskedSsn, asMaskedOnly.rows.single()[2], "a masked-only role masks the same stored ssn")
            assertEquals(listOf("ssn"), asMaskedOnly.maskedColumns)
        } finally {
            policies.forEach { fx.cedarPolicyStore.delete(it) }
        }
    }

    // Masks bind by ordinal, not label: a stored label that differs from the analyzer's output name (an
    // unaliased `cast(id …)`) is masked and released, not denied.
    @Test
    fun `a result whose labels differ from the analyzer names is released, not falsely denied`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult(columns = listOf("c0", "c1", "c2"))
        val client = wire()
        client.login(executor)

        val response = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, response.status)
        val view = response.body<QueryResultView>()
        assertEquals(listOf("c0", "c1", "c2"), view.columns, "the stored labels are returned as-is")
        assertEquals(maskedSsn, view.rows.single()[2], "the ssn is still masked by ordinal, just not falsely denied")
    }

    // A legacy result stored no requirements, so there is nothing to decide its view from.
    @Test
    fun `a legacy result with no stored requirements fails closed`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult(rows = listOf(listOf("1", "a@x", rawSsn)), resultRequirements = ResultRequirements.getDefaultInstance())
        val client = wire()
        client.login(executor)

        val response = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        val responseBody = response.bodyAsText()
        assertEquals("approval.result_view_denied", Json.decodeFromString<ApiError>(responseBody).code)
        assertFalse(responseBody.contains(rawSsn), "a result with no requirements must not release stored PII")
    }

    // A legacy passthrough result (no stored requirements) fails closed rather than releasing raw.
    @Test
    fun `a legacy result that re-decides as passthrough fails closed`() = testApplication {
        resetMutableAuthzState()
        val sentinel = "LEAK-SENTINEL-LEGACY-PASSTHROUGH"
        val id = seedResult(
            sql = "SHOW search_path",
            columns = listOf("search_path"),
            rows = listOf(listOf(sentinel)),
            resultRequirements = ResultRequirements.getDefaultInstance(),
        )
        val client = wire()
        client.login(executor)

        val response = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        val responseBody = response.bodyAsText()
        assertEquals("approval.result_view_denied", Json.decodeFromString<ApiError>(responseBody).code)
        assertFalse(responseBody.contains(sentinel), "a legacy result must not release raw through a passthrough re-decision")
    }

    // The viewer's own result.cap rows cap the release: the stored rows outnumber the viewer's cap, so the
    // workflow-viewer re-decision truncates; a result.cap forbid releases every stored row.
    @Test
    fun `a capped viewer receives the first rows and an unbounded one the whole stored result`() = testApplication {
        resetMutableAuthzState()
        val storedRows = (1..12).map { listOf(it.toString(), "u$it@x", rawSsn) }
        val cap = 5
        val id = seedResult(rows = storedRows)
        val storedBefore = ciphertext(id)
        val client = wire()
        client.login(executor)
        val capped = fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-capped-viewer",
                cedarSrc = """@cap("$cap") permit(
                    principal in Role::"$roleName", action == Action::"result.cap", resource
                );""",
            ),
            updatedBy = "test-fixture",
        )
        try {
            val view = client.get("/api/approvals/$id/result").body<QueryResultView>()
            assertEquals(cap, view.rows.size)
            assertEquals(cap, view.truncatedAt)
            assertContentEquals(storedRows.take(cap).map { it.take(2) }, view.rows.map { it.take(2) })
        } finally {
            fx.cedarPolicyStore.delete(capped.id)
        }

        val unbounded = fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-view-unbounded-viewer",
                cedarSrc = """forbid(
                    principal in Role::"$roleName", action == Action::"result.cap", resource
                );""",
            ),
            updatedBy = "test-fixture",
        )
        try {
            val full = client.get("/api/approvals/$id/result").body<QueryResultView>()
            assertEquals(storedRows.size, full.rows.size)
            assertNull(full.truncatedAt)
        } finally {
            fx.cedarPolicyStore.delete(unbounded.id)
        }
        assertContentEquals(storedBefore, ciphertext(id), "truncating a view must not rewrite stored ciphertext")
    }

    @Test
    fun `a result the execution capped stays marked incomplete even when the view releases every stored row`() = testApplication {
        resetMutableAuthzState()
        val id = seedResult(truncatedByCap = true)
        val client = wire()
        client.login(executor)

        val view = client.get("/api/approvals/$id/result").body<QueryResultView>()
        assertEquals(1, view.rows.size)
        // The view released every stored row, so only the execution's own flag can report the cut.
        assertNull(view.truncatedAt)
        assertTrue(view.truncatedByCap)

        assertFalse(client.get("/api/approvals/${seedResult()}/result").body<QueryResultView>().truncatedByCap)
    }

}
