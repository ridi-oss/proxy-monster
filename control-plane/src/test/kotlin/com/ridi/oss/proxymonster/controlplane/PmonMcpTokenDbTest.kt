package com.ridi.oss.proxymonster.controlplane

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.TestClock
import com.ridi.oss.proxymonster.controlplane.support.errorCode
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.ok
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.pmonLogin
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.str
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.slf4j.LoggerFactory
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** `POST /auth/session/mcp-token`: a pmon session's renewal bearer traded for an MCP token with its scopes. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PmonMcpTokenDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private val clock = TestClock()
    private val config = mcpTestConfig().copy(elevatedScopeTtlSeconds = 1_800)
    private val seq = AtomicInteger()
    private lateinit var datasource: Datasource

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_pmon_mcp_token"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource, clock = clock)
        datasource = core.datasourceStore.create(DatasourceInput("pmon-mcp-ds", "postgres"))
    }

    private suspend fun HttpClient.exchange(renewalToken: String?): HttpResponse = post("/auth/session/mcp-token") {
        renewalToken?.let { header(HttpHeaders.Authorization, "Bearer $it") }
    }

    private suspend fun HttpClient.mint(renewalToken: String): PmonMcpTokenResponse {
        val res = exchange(renewalToken)
        assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())
        return MCP_TEST_JSON.decodeFromString(res.bodyAsText())
    }

    private fun refusal(res: HttpResponse, body: String) = res.status to MCP_TEST_JSON.decodeFromString<ApiError>(body).code

    @Test
    fun `a default login mints a working MCP token with exactly mcp read and query`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal()
        val login = client.pmonLogin(caller)
        val minted = client.mint(login.renewalToken)
        assertEquals("mcp:query mcp:read", minted.scope)
        assertEquals(minted.scope, tokenRow(minted.accessToken).scope)
        assertEquals(PMON_MCP_CLIENT_ID, tokenRow(minted.accessToken).clientId)

        client.mcpCall(minted.accessToken, "get_my_permissions").ok()
        client.mcpCall(minted.accessToken, "list_connectable_datasources").ok()
        val id = pendingRequest()
        assertEquals("mcp.insufficient_scope", client.mcpCall(minted.accessToken, "approve_approval", idArg(id)).errorCode())
    }

    @Test
    fun `elevated scopes work until their window ends, then only read and query remain`() = testApplication {
        val client = installControlPlane(config, core)
        val approver = admin()
        val login = client.pmonLogin(approver, listOf("mcp:read", "mcp:query", "mcp:approvals:write"))
        val elevatedUntil = Instant.parse(assertNotNull(login.elevatedUntil))

        val early = client.mint(login.renewalToken)
        assertEquals("mcp:approvals:write mcp:query mcp:read", early.scope)
        val approved = client.mcpCall(early.accessToken, "approve_approval", idArg(pendingRequest()))
        assertEquals("APPROVED", approved.okResult().jsonObject.str("status"))

        clock.now = elevatedUntil.plusSeconds(1)
        try {
            val late = client.mint(login.renewalToken)
            assertEquals("mcp:query mcp:read", late.scope)
            assertEquals("mcp.insufficient_scope", client.mcpCall(late.accessToken, "approve_approval", idArg(pendingRequest())).errorCode())
            val run = client.mcpCall(
                late.accessToken, "run_query",
                buildJsonObject { put("datasource", datasource.name); put("sql", "SELECT 1") },
            )
            assertNotEquals("mcp.insufficient_scope", run.errorCode(), run.toString())
            client.mcpCall(late.accessToken, "list_connectable_datasources").ok()
        } finally {
            clock.now = Instant.now()
        }
    }

    @Test
    fun `a token minted near the end of the window expires at the window's end`() = testApplication {
        val client = installControlPlane(config, core)
        val login = client.pmonLogin(principal(), listOf("mcp:query", "mcp:approvals:write"))
        val elevatedUntil = Instant.parse(assertNotNull(login.elevatedUntil))
        clock.now = elevatedUntil.minusSeconds(120)
        try {
            val minted = client.mint(login.renewalToken)
            assertEquals("mcp:approvals:write mcp:query", minted.scope)
            assertEquals(elevatedUntil, Instant.parse(minted.expiresAt))
            assertEquals(elevatedUntil, tokenRow(minted.accessToken).expiresAt)
        } finally {
            clock.now = Instant.now()
        }
        val fresh = client.mint(login.renewalToken)
        assertEquals(clock.now.plusSeconds(config.mcpAccessTtlSeconds), Instant.parse(fresh.expiresAt))
    }

    @Test
    fun `a login granted only elevated scopes has nothing left after the window`() = testApplication {
        val client = installControlPlane(config, core)
        val login = client.pmonLogin(principal(), listOf("mcp:approvals:write"))
        clock.now = Instant.parse(assertNotNull(login.elevatedUntil))
        try {
            val res = client.exchange(login.renewalToken)
            assertEquals(HttpStatusCode.Forbidden to "auth.scopes_expired", refusal(res, res.bodyAsText()))
        } finally {
            clock.now = Instant.now()
        }
    }

    @Test
    fun `an expired, ended, or deactivated session and a bad bearer are refused`() = testApplication {
        val client = installControlPlane(config, core)
        val unauthorized = HttpStatusCode.Unauthorized
        suspend fun refused(renewal: String?): Pair<HttpStatusCode, String> = client.exchange(renewal).let { refusal(it, it.bodyAsText()) }

        assertEquals(unauthorized to "auth.missing_renewal_token", refused(null))
        assertEquals(unauthorized to "common.unauthenticated", refused("pmr_not-a-session"))

        val expired = client.pmonLogin(principal())
        val session = assertNotNull(core.mcpSession(expired.renewalToken))
        clock.now = session.createdAt.plusSeconds(session.ttlSeconds)
        try {
            assertEquals(unauthorized to "auth.session_window_expired", refused(expired.renewalToken))
        } finally {
            clock.now = Instant.now()
        }

        val ended = client.pmonLogin(principal())
        PrincipalSessionStore(dataSource, null).let { store ->
            dataSource.connection.use { c -> store.closeDaemonWindow(assertNotNull(core.mcpSession(ended.renewalToken)).id, c) }
        }
        assertEquals(unauthorized to "auth.session_window_expired", refused(ended.renewalToken))

        val owner = principal()
        core.userGroupStore.createUser(AppUserInput(owner), core.tokenStore, core.accessStore, PrincipalSessionStore(dataSource, null))
        val deactivated = client.pmonLogin(owner)
        client.mint(deactivated.renewalToken)
        core.userGroupStore.setUserActive(owner, false)
        assertEquals(unauthorized to "auth.session_window_expired", refused(deactivated.renewalToken))
    }

    @Test
    fun `the mint is audited without the token, and no log line carries it`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal()
        val login = client.pmonLogin(caller)
        val root = LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME) as Logger
        val logs = ListAppender<ILoggingEvent>().also { it.start() }
        root.addAppender(logs)
        val minted = try {
            client.mint(login.renewalToken)
        } finally {
            root.detachAppender(logs)
        }
        assertEquals(
            1L,
            count(
                "SELECT count(*) FROM audit_event WHERE principal=? AND action=? AND channel='pmon' AND kind='auth'",
                caller, AuthAuditRecorder.ACTION_SESSION_MCP_TOKEN,
            ),
        )
        for (secret in listOf(minted.accessToken, login.renewalToken)) {
            assertEquals(
                0L,
                count("SELECT count(*) FROM audit_event WHERE statement LIKE ? OR detail LIKE ? OR resource LIKE ?", "%$secret%", "%$secret%", "%$secret%"),
            )
            assertTrue(logs.list.none { secret in it.formattedMessage }, "a secret reached a log line")
        }
    }

    private data class TokenRow(val scope: String, val clientId: String, val expiresAt: Instant)

    private fun tokenRow(token: String): TokenRow = dataSource.connection.use { c ->
        c.prepareStatement("SELECT scope, client_id, expires_at FROM proxy_token WHERE token_hash = ?").use { ps ->
            ps.setString(1, sha256Hex(token))
            ps.executeQuery().use { rs ->
                assertTrue(rs.next())
                TokenRow(rs.getString(1), rs.getString(2), rs.getTimestamp(3).toInstant())
            }
        }
    }

    private fun ControlPlaneCore.mcpSession(renewalToken: String) =
        PrincipalSessionStore(dataSource, null).getByRenewalTokenHash(sha256Hex(renewalToken))

    private fun count(sql: String, vararg args: String): Long = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps ->
            args.forEachIndexed { i, v -> ps.setString(i + 1, v) }
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    private fun idArg(id: Long) = buildJsonObject { put("id", id) }

    private fun pendingRequest(): Long = core.accessStore.createQueryRequest(
        principal = principal(), datasourceId = datasource.id, statements = listOf("SELECT 1"), denyReason = null,
        sourceDecisionId = null, reason = "need it", title = "t", evaluatedDecision = "DENY",
        roleId = assertNotNull(core.policyStore.getRoleByName("system:production-viewer")).id,
    ).id

    private fun admin(): String = principal().also {
        core.policyStore.createAssignment(RoleAssignmentInput(it, assertNotNull(core.policyStore.getRoleByName("system:admin")).id))
    }

    private fun principal() = "pmon-mcp-${seq.incrementAndGet()}@example.com"
}
