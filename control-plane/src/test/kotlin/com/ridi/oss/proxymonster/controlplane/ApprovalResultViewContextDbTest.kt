package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
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
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
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
    private lateinit var runExecService: RunExecService
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
    private val rawRrn = "900101-1234567"
    private val maskedRrn = "**********4567"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        resultStore = QueryResultStore(fx.dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        runExecService = RunExecService(ControlPlaneCore(fx.dataSource))
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
                    action in [Action::"datasource.connect", Action::"sql.select"],
                    resource in Datasource::"${fx.datasource.name}"
                );""",
            ),
            updatedBy = "test-fixture",
        )
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
                runExecService,
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
        sql: String = "SELECT id, email, rrn FROM users",
        columns: List<String> = listOf("id", "email", "rrn"),
        rows: List<List<String?>> = listOf(listOf("1", "a@x", rawRrn)),
    ): Long {
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
        fx.dataSource.connection.use { c -> c.prepareStatement("INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, ?, 'fixture')").use { ps -> ps.setLong(1, reqId); ps.setString(2, sql); ps.executeUpdate() } }
        assertNotNull(resultStore.startRun(reqId, executor))
        assertNotNull(resultStore.completeRun(reqId, DecryptedResult(columns, rows), 3600))
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
        assertEquals(maskedRrn, executorMasked.body<QueryResultView>().rows.single()[2])
        assertContentEquals(storedBefore, ciphertext(id), "view-time masking must not rewrite stored ciphertext")

        val executorRaw = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.OK, executorRaw.status)
        assertEquals(rawRrn, executorRaw.body<QueryResultView>().rows.single()[2])
        assertContentEquals(storedBefore, ciphertext(id), "the in-context view must read the same stored bytes")

        client.login(requester)
        val requesterMasked = client.get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, requesterMasked.status)
        assertEquals(maskedRrn, requesterMasked.body<QueryResultView>().rows.single()[2])

        val requesterRaw = client.get("/api/approvals/$id/result") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.OK, requesterRaw.status)
        assertEquals(rawRrn, requesterRaw.body<QueryResultView>().rows.single()[2])
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
        // upper(rrn) is a provably-total transform of the masked rrn → redacted in full (kind NULL). For an
        // all-digit/dash RRN, upper(rrn) == rrn, so a `?: value` fallback would leak the raw RRN on view.
        val derivedCleartext = rawRrn.uppercase()
        val id = seedResult(
            sql = "SELECT id, upper(rrn) AS u FROM users",
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
                rawRrn,
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
        assertEquals(rawRrn, raw.body<QueryResultView>().rows.single()[2])

        assertNotNull(fx.cedarPolicyStore.setEnabled(segregatedUnmaskPolicyId, false, "test-fixture"))
        try {
            val remasked = client.get("/api/approvals/$id/result") {
                header("X-Forwarded-For", "100.100.5.5")
            }
            assertEquals(HttpStatusCode.OK, remasked.status)
            assertEquals(maskedRrn, remasked.body<QueryResultView>().rows.single()[2])
            assertContentEquals(storedBefore, ciphertext(id), "policy revocation must affect only the live response")
        } finally {
            fx.cedarPolicyStore.setEnabled(segregatedUnmaskPolicyId, true, "test-fixture")
        }
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
            assertFalse(response.bodyAsText().contains(rawRrn), "a deactivated viewer must receive no stored PII")
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
        assertFalse(response.bodyAsText().contains(rawRrn), "the assume gate must return no stored PII")
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
            response.bodyAsText().contains(rawRrn),
            "task.assume admits the requester and the live exactly-R view decision applies the task role",
        )
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
            assertEquals(rawRrn, response.body<QueryResultView>().rows.single()[2], principal)
        }
        // The approver's view is credited to the approver; the auditor is neither party and must NOT be
        // miscredited as the approver — its view is recorded as a neutral assumer event.
        assertEquals("approval #$id result-viewed-by-approver", viewEvent(id, approver))
        assertEquals("approval #$id result-viewed-by-assumer", viewEvent(id, auditor))

        // An assumer's metadata carries the result cardinality; the admin's must not (task.read is
        // metadata-only, and row count is a result-derived existence/cardinality oracle behind task.assume).
        // The requester holds both task.read (self-request seed) and task.assume (party seed), so their
        // GET /{id} returns the un-redacted meta.
        client.login(requester)
        assertNotNull(
            client.get("/api/approvals/$id").body<ApprovalDetail>().result?.rowCount,
            "an assumer sees the result row count in metadata",
        )

        client.login(admin)
        val adminDetail = client.get("/api/approvals/$id")
        assertEquals(HttpStatusCode.OK, adminDetail.status, "admin may read metadata")
        val adminMeta = adminDetail.body<ApprovalDetail>().result
        assertNotNull(adminMeta, "admin still sees execution status metadata")
        assertNull(adminMeta.rowCount, "admin (task.read only) must not learn the result row count")
        assertTrue(adminMeta.columns.isEmpty(), "admin (task.read only) must not learn the result column shape")
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
    fun `stored row-width drift fails closed instead of returning an unbound extra value`() = testApplication {
        resetMutableAuthzState()
        val sentinel = "LEAK-SENTINEL-EXTRA-CELL"
        val id = seedResult(rows = listOf(listOf("1", "a@x", rawRrn, sentinel)))
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
}
