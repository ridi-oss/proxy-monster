package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.DeviceStartResponse
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.deviceConfirm
import com.ridi.oss.proxymonster.controlplane.support.deviceStart
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.pmonLogin
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `pmon login --scopes`: the requested scopes travel start → approval page → daemon session, served by cp-go. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeviceLoginScopesCpGoTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var stack: CpGoStack
    private val config = mcpTestConfig().copy(elevatedScopeTtlSeconds = 1_800)
    private val seq = AtomicInteger()

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_device_scopes")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        stack = CpGoStack(config, core, database) { routing { testLoginRoute(PrincipalSessionStore(dataSource, null), config) } }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    private data class DaemonRow(val scopes: Set<String>, val elevatedUntil: Instant?)

    private fun daemonByRenewal(renewalToken: String): DaemonRow? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT scopes, elevated_until FROM principal_session WHERE kind = 'DAEMON' AND renewal_token_hash = ?").use { ps ->
            ps.setString(1, sha256Hex(renewalToken))
            ps.executeQuery().use { rs ->
                if (!rs.next()) null else DaemonRow(rs.getString(1).split(' ').toSet(), rs.getTimestamp(2)?.toInstant())
            }
        }
    }

    private fun loginScopes(handle: String): Set<String> = dataSource.connection.use { c ->
        c.prepareStatement("SELECT scopes FROM device_login WHERE handle = ?").use { ps ->
            ps.setString(1, handle)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getString(1).split(' ').toSet() }
        }
    }

    @Test
    fun `start stores the requested scopes on the pending login`() = runBlocking<Unit> {
        val client = stack.client()
        val res = client.deviceStart(listOf("mcp:read", "mcp:approvals:write"))
        assertEquals(HttpStatusCode.OK, res.status)
        val handle = MCP_TEST_JSON.decodeFromString<DeviceStartResponse>(res.bodyAsText()).handle
        assertEquals(setOf("mcp:read", "mcp:approvals:write"), loginScopes(handle))
    }

    @Test
    fun `an unknown or empty scope list is refused`() = runBlocking<Unit> {
        val client = stack.client()
        val unknown = client.deviceStart(listOf("mcp:read", "mcp:everything"))
        assertEquals(HttpStatusCode.BadRequest, unknown.status)
        assertEquals(ApiError("device.unknown_scope", mapOf("scope" to "mcp:everything")), MCP_TEST_JSON.decodeFromString(unknown.bodyAsText()))
        val empty = client.deviceStart(listOf(" "))
        assertEquals(HttpStatusCode.BadRequest, empty.status)
        assertEquals("device.no_scopes", MCP_TEST_JSON.decodeFromString<ApiError>(empty.bodyAsText()).code)
    }

    @Test
    fun `a login without scopes grants the default pair and no elevated window`() = runBlocking<Unit> {
        val client = stack.client()
        val result = client.pmonLogin(principal())
        assertEquals(listOf("mcp:query", "mcp:read"), result.scopes)
        assertNull(result.elevatedUntil)
        val session = assertNotNull(daemonByRenewal(result.renewalToken))
        assertEquals(setOf("mcp:query", "mcp:read"), session.scopes)
        assertNull(session.elevatedUntil)
    }

    @Test
    fun `the approval page sees the extra scopes and the approval starts their window`() = runBlocking<Unit> {
        val client = stack.client()
        val started = MCP_TEST_JSON.decodeFromString<DeviceStartResponse>(
            client.deviceStart(listOf("mcp:query", "mcp:approvals:write")).bodyAsText(),
        )
        client.login(principal())
        val ack = client.deviceConfirm(started.userCode)
        assertEquals(listOf("mcp:approvals:write", "mcp:query"), ack.scopes)
        assertEquals(1_800L, ack.elevatedTtlSeconds)

        val defaultAck = client.deviceConfirm(
            MCP_TEST_JSON.decodeFromString<DeviceStartResponse>(client.deviceStart(null).bodyAsText()).userCode,
        )
        assertNull(defaultAck.elevatedTtlSeconds)

        val approvedAfter = Instant.now().truncatedTo(ChronoUnit.MICROS)
        val result = client.pmonLogin(principal(), listOf("mcp:query", "mcp:approvals:write"))
        val approvedBefore = Instant.now()
        val until = Instant.parse(assertNotNull(result.elevatedUntil))
        assertTrue(
            !until.isBefore(approvedAfter.plusSeconds(1_800)) && !until.isAfter(approvedBefore.plusSeconds(1_800)),
            "elevatedUntil $until is not approval + 1800s",
        )
        assertEquals(listOf("mcp:approvals:write", "mcp:query"), result.scopes)
        val session = assertNotNull(daemonByRenewal(result.renewalToken))
        assertEquals(setOf("mcp:approvals:write", "mcp:query"), session.scopes)
        assertEquals(until, session.elevatedUntil)
    }

    private fun principal() = "pmon-scopes-${seq.incrementAndGet()}@example.com"
}
