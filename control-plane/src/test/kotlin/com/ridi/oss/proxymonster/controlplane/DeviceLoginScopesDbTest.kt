package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.TestClock
import com.ridi.oss.proxymonster.controlplane.support.deviceConfirm
import com.ridi.oss.proxymonster.controlplane.support.deviceStart
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.pmonLogin
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** `pmon login --scopes`: the requested scopes travel start → approval page → daemon session. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeviceLoginScopesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var sessions: PrincipalSessionStore
    private val clock = TestClock()
    private val config = mcpTestConfig().copy(elevatedScopeTtlSeconds = 1_800)
    private val seq = AtomicInteger()

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_device_scopes"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource, clock = clock)
        sessions = PrincipalSessionStore(dataSource, null)
    }

    @Test
    fun `start stores the requested scopes on the pending login`() = testApplication {
        val client = installControlPlane(config, core)
        val res = client.deviceStart(listOf("mcp:read", "mcp:approvals:write"))
        assertEquals(HttpStatusCode.OK, res.status)
        val handle = MCP_TEST_JSON.decodeFromString<DeviceStartResponse>(res.bodyAsText()).handle
        assertEquals(setOf("mcp:read", "mcp:approvals:write"), DeviceLoginStore(dataSource).get(handle)!!.scopes)
    }

    @Test
    fun `an unknown or empty scope list is refused`() = testApplication {
        val client = installControlPlane(config, core)
        val unknown = client.deviceStart(listOf("mcp:read", "mcp:everything"))
        assertEquals(HttpStatusCode.BadRequest, unknown.status)
        assertEquals(ApiError("device.unknown_scope", mapOf("scope" to "mcp:everything")), MCP_TEST_JSON.decodeFromString(unknown.bodyAsText()))
        val empty = client.deviceStart(listOf(" "))
        assertEquals(HttpStatusCode.BadRequest, empty.status)
        assertEquals("device.no_scopes", MCP_TEST_JSON.decodeFromString<ApiError>(empty.bodyAsText()).code)
    }

    @Test
    fun `a login without scopes grants the default pair and no elevated window`() = testApplication {
        val client = installControlPlane(config, core)
        val result = client.pmonLogin(principal())
        assertEquals(listOf("mcp:query", "mcp:read"), result.scopes)
        assertNull(result.elevatedUntil)
        val session = assertNotNull(sessions.getByRenewalTokenHash(sha256Hex(result.renewalToken)))
        assertEquals(setOf("mcp:query", "mcp:read"), session.scopes)
        assertNull(session.elevatedUntil)
    }

    @Test
    fun `the approval page sees the extra scopes and the approval starts their window`() = testApplication {
        val client = installControlPlane(config, core)
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

        val approvedAt = Instant.parse("2026-01-01T00:00:00Z").also { clock.now = it }
        val result = try {
            client.pmonLogin(principal(), listOf("mcp:query", "mcp:approvals:write"))
        } finally {
            clock.now = Instant.now()
        }
        val until = approvedAt.plusSeconds(1_800)
        assertEquals(listOf("mcp:approvals:write", "mcp:query"), result.scopes)
        assertEquals(until.toString(), result.elevatedUntil)
        val session = assertNotNull(sessions.getByRenewalTokenHash(sha256Hex(result.renewalToken)))
        assertEquals(setOf("mcp:approvals:write", "mcp:query"), session.scopes)
        assertEquals(until, session.elevatedUntil)
    }

    @Test
    fun `PM_ELEVATED_SCOPE_TTL defaults to an hour and is clamped like the OAuth TTLs`() {
        assertEquals(3_600L, Config.fromEnv { null }.elevatedScopeTtlSeconds)
        assertEquals(900L, Config.fromEnv { if (it == "PM_ELEVATED_SCOPE_TTL") "900" else null }.elevatedScopeTtlSeconds)
        assertEquals(60L, Config.fromEnv { if (it == "PM_ELEVATED_SCOPE_TTL") "5" else null }.elevatedScopeTtlSeconds)
    }

    private fun principal() = "pmon-scopes-${seq.incrementAndGet()}@example.com"
}
