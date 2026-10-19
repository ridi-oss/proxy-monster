package com.ridi.oss.proxymonster.controlplane

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import com.ridi.oss.proxymonster.controlplane.support.PmonMcpTokenResponse
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.errorCode
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.ok
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.pmonLogin
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.str
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.slf4j.LoggerFactory
import java.sql.Timestamp
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** `POST /auth/session/mcp-token` on cp-go: a pmon session's renewal bearer traded for an MCP token with its scopes. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PmonMcpTokenDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var stack: CpGoStack
    private val config = mcpTestConfig().copy(elevatedScopeTtlSeconds = 1_800, mcpResource = "http://127.0.0.1/mcp")
    private val seq = AtomicInteger()
    private lateinit var datasource: Datasource

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_pmon_mcp_token")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        datasource = core.datasourceStore.create(DatasourceInput("pmon-mcp-ds", "postgres"))
        stack = CpGoStack(config, core, database) { routing { testLoginRoute(PrincipalSessionStore(dataSource, null), config) } }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
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
    fun `a default login mints a working MCP token with exactly mcp read and query`() = runBlocking<Unit> {
        val client = stack.client()
        val caller = principal()
        val login = client.pmonLogin(caller)
        val minted = client.mint(login.renewalToken)
        assertEquals("mcp:query mcp:read", minted.scope)
        assertEquals(minted.scope, tokenRow(minted.accessToken).scope)
        assertEquals("pmon", tokenRow(minted.accessToken).clientId)

        client.mcpCall(minted.accessToken, "get_my_permissions").ok()
        client.mcpCall(minted.accessToken, "list_connectable_datasources").ok()
        val id = pendingRequest()
        assertEquals("mcp.insufficient_scope", client.mcpCall(minted.accessToken, "approve_approval", approveArgs(id)).errorCode())
    }

    @Test
    fun `elevated scopes work until their window ends, then only read and query remain`() = runBlocking<Unit> {
        val client = stack.client()
        val approver = admin()
        val login = client.pmonLogin(approver, listOf("mcp:read", "mcp:query", "mcp:approvals:write"))
        assertNotNull(login.elevatedUntil)

        val early = client.mint(login.renewalToken)
        assertEquals("mcp:approvals:write mcp:query mcp:read", early.scope)
        val approved = client.mcpCall(early.accessToken, "approve_approval", approveArgs(pendingRequest()))
        assertEquals("APPROVED", approved.okResult().jsonObject.str("status"))

        setElevatedUntil(login.renewalToken, Instant.now().minusSeconds(1))
        val late = client.mint(login.renewalToken)
        assertEquals("mcp:query mcp:read", late.scope)
        assertEquals("mcp.insufficient_scope", client.mcpCall(late.accessToken, "approve_approval", approveArgs(pendingRequest())).errorCode())
        val run = client.mcpCall(
            late.accessToken, "run_query",
            buildJsonObject { put("datasource", datasource.name); put("sql", "SELECT 1") },
        )
        assertNotEquals("mcp.insufficient_scope", run.errorCode(), run.toString())
        client.mcpCall(late.accessToken, "list_connectable_datasources").ok()
    }

    @Test
    fun `a token minted near the end of the window expires at the window's end`() = runBlocking<Unit> {
        val client = stack.client()
        val login = client.pmonLogin(principal(), listOf("mcp:query", "mcp:approvals:write"))
        val granted = Instant.parse(assertNotNull(login.elevatedUntil))
        val elevatedUntil = Instant.now().plusSeconds(120).truncatedTo(ChronoUnit.MICROS)
        setElevatedUntil(login.renewalToken, elevatedUntil)
        val minted = client.mint(login.renewalToken)
        assertEquals("mcp:approvals:write mcp:query", minted.scope)
        assertEquals(elevatedUntil, Instant.parse(minted.expiresAt))
        assertEquals(elevatedUntil, tokenRow(minted.accessToken).expiresAt)

        setElevatedUntil(login.renewalToken, granted)
        val mintedAfter = Instant.now().truncatedTo(ChronoUnit.MICROS)
        val fresh = client.mint(login.renewalToken)
        val mintedBefore = Instant.now()
        val expires = Instant.parse(fresh.expiresAt)
        assertTrue(
            !expires.isBefore(mintedAfter.plusSeconds(config.mcpAccessTtlSeconds)) &&
                !expires.isAfter(mintedBefore.plusSeconds(config.mcpAccessTtlSeconds)),
            "expiresAt $expires is not the mint time + ${config.mcpAccessTtlSeconds}s",
        )
    }

    @Test
    fun `a login granted only elevated scopes has nothing left after the window`() = runBlocking<Unit> {
        val client = stack.client()
        val login = client.pmonLogin(principal(), listOf("mcp:approvals:write"))
        assertNotNull(login.elevatedUntil)
        setElevatedUntil(login.renewalToken, Instant.now())
        val res = client.exchange(login.renewalToken)
        assertEquals(HttpStatusCode.Forbidden to "auth.scopes_expired", refusal(res, res.bodyAsText()))
    }

    @Test
    fun `an expired, ended, or deactivated session and a bad bearer are refused`() = runBlocking<Unit> {
        val client = stack.client()
        val unauthorized = HttpStatusCode.Unauthorized
        suspend fun refused(renewal: String?): Pair<HttpStatusCode, String> = client.exchange(renewal).let { refusal(it, it.bodyAsText()) }

        assertEquals(unauthorized to "auth.missing_renewal_token", refused(null))
        assertEquals(unauthorized to "common.unauthenticated", refused("pmr_not-a-session"))

        val expired = client.pmonLogin(principal())
        updateDaemon(expired.renewalToken, "created_at = created_at - make_interval(secs => ttl_seconds)")
        assertEquals(unauthorized to "auth.session_window_expired", refused(expired.renewalToken))

        val ended = client.pmonLogin(principal())
        updateDaemon(ended.renewalToken, "liveness_status = 'INACTIVE', absolute_expires_at = now()")
        assertEquals(unauthorized to "auth.session_window_expired", refused(ended.renewalToken))

        val owner = principal()
        core.userGroupStore.createUser(AppUserInput(owner), core.tokenStore, core.accessStore, PrincipalSessionStore(dataSource, null))
        val deactivated = client.pmonLogin(owner)
        client.mint(deactivated.renewalToken)
        core.userGroupStore.setUserActive(owner, false)
        assertEquals(unauthorized to "auth.session_window_expired", refused(deactivated.renewalToken))
    }

    @Test
    fun `the mint is audited without the token, and no log line carries it`() = runBlocking<Unit> {
        val client = stack.client()
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
            assertFalse(secret in stack.logText(), "a secret reached a cp-go log line")
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

    private fun updateDaemon(renewalToken: String, set: String) = dataSource.connection.use { c ->
        c.prepareStatement("UPDATE principal_session SET $set WHERE kind = 'DAEMON' AND renewal_token_hash = ?").use { ps ->
            ps.setString(1, sha256Hex(renewalToken))
            assertEquals(1, ps.executeUpdate())
        }
    }

    private fun setElevatedUntil(renewalToken: String, at: Instant) = dataSource.connection.use { c ->
        c.prepareStatement("UPDATE principal_session SET elevated_until = ? WHERE kind = 'DAEMON' AND renewal_token_hash = ?").use { ps ->
            ps.setTimestamp(1, Timestamp.from(at))
            ps.setString(2, sha256Hex(renewalToken))
            assertEquals(1, ps.executeUpdate())
        }
    }

    private fun count(sql: String, vararg args: String): Long = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps ->
            args.forEachIndexed { i, v -> ps.setString(i + 1, v) }
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    private fun approveArgs(id: Long) = buildJsonObject { put("id", id); put("revision", 1) }

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
