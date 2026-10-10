package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpRaw
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.ok
import com.ridi.oss.proxymonster.controlplane.support.pmonLogin
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.validateTokenRequest
import io.grpc.Status
import io.grpc.StatusException
import io.ktor.client.HttpClient
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** `POST /auth/session/logout`: pmon ends its daemon session on the server, with every token it minted. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PmonLogoutDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var grpc: ControlPlaneGrpcService
    private lateinit var datasource: Datasource
    private val config = mcpTestConfig()
    private val seq = AtomicInteger()

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_pmon_logout"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        grpc = ControlPlaneGrpcService(core)
        datasource = core.datasourceStore.create(DatasourceInput("pmon-logout-ds", "postgres"))
    }

    private suspend fun HttpClient.bearerPost(path: String, renewalToken: String): HttpResponse = post(path) {
        header(HttpHeaders.Authorization, "Bearer $renewalToken")
    }

    private suspend fun HttpClient.mint(renewalToken: String): PmonMcpTokenResponse {
        val res = bearerPost("/auth/session/mcp-token", renewalToken)
        assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())
        return MCP_TEST_JSON.decodeFromString(res.bodyAsText())
    }

    private fun wireValid(token: String): Boolean = try {
        runBlocking { grpc.validateToken(validateTokenRequest { this.token = token; datasourceName = datasource.name; clientAddr = "127.0.0.1" }) }
        true
    } catch (e: StatusException) {
        assertEquals(Status.Code.UNAUTHENTICATED, e.status.code)
        false
    }

    @Test
    fun `logout refuses renew and the exchange, and revokes the login's wire and MCP tokens`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal()
        val login = client.pmonLogin(caller)
        val renewed = MCP_TEST_JSON.decodeFromString<RenewSessionResponse>(
            client.bearerPost("/auth/session/renew", login.renewalToken).bodyAsText(),
        )
        val mcp = client.mint(login.renewalToken)
        val other = client.pmonLogin(caller)
        val otherMcp = client.mint(other.renewalToken)
        assertEquals(true, wireValid(login.token))
        assertEquals(true, wireValid(renewed.token))
        client.mcpCall(mcp.accessToken, "get_my_permissions").ok()

        assertEquals(HttpStatusCode.NoContent, client.bearerPost("/auth/session/logout", login.renewalToken).status)

        assertEquals(HttpStatusCode.Unauthorized, client.bearerPost("/auth/session/renew", login.renewalToken).status)
        assertEquals(HttpStatusCode.Unauthorized, client.bearerPost("/auth/session/mcp-token", login.renewalToken).status)
        assertEquals(false, wireValid(login.token))
        assertEquals(false, wireValid(renewed.token))
        assertFailsWith<StatusException> { core.resolveRequestIdentity(login.token, null) }
        assertEquals(HttpStatusCode.Unauthorized, client.mcpRaw(mcp.accessToken, "get_my_permissions").status)

        assertEquals(true, wireValid(other.token), "another login of the same principal stays up")
        client.mcpCall(otherMcp.accessToken, "get_my_permissions").ok()
        client.mcpCall(client.mint(other.renewalToken).accessToken, "get_my_permissions").ok()
    }

    @Test
    fun `a replaced login keeps its open connections but opens no new one`() = testApplication {
        val client = installControlPlane(config, core)
        val login = client.pmonLogin(principal())
        // Datasource discovery accepts a bearer only while it resolves with retired tokens excluded.
        val discoverable = { core.tokenStore.resolve(login.token, allowRetired = false) != null }
        assertEquals(true, discoverable())
        val mcp = client.mint(login.renewalToken)

        assertEquals(HttpStatusCode.NoContent, client.bearerPost("/auth/session/logout?replaced=true", login.renewalToken).status)

        assertEquals(HttpStatusCode.Unauthorized, client.mcpRaw(mcp.accessToken, "get_my_permissions").status)

        assertEquals(HttpStatusCode.Unauthorized, client.bearerPost("/auth/session/renew", login.renewalToken).status)
        assertEquals(false, wireValid(login.token), "a new connection is refused")
        assertEquals(login.principal, core.resolveRequestIdentity(login.token, null).identity.principal, "an open connection's statements still run")
        assertEquals(false, discoverable(), "a retired token is refused as a fresh bearer")
    }

    @Test
    fun `revoking the pmon consent on the web ends the pmon login`() = testApplication {
        val client = installControlPlane(config, core)
        val login = client.pmonLogin(principal())
        val mcp = client.mint(login.renewalToken)
        val listed = MCP_TEST_JSON.parseToJsonElement(client.get("/oauth/consents").bodyAsText()).jsonObject
        val consent = listed["consents"]!!.jsonArray.map { it.jsonObject }.single { it["clientId"]!!.jsonPrimitive.content == PMON_MCP_CLIENT_ID }

        val revoke = client.delete("/oauth/consents/${consent["id"]!!.jsonPrimitive.content}") {
            header("X-PM-CSRF", listed["csrfToken"]!!.jsonPrimitive.content)
        }
        assertEquals(HttpStatusCode.NoContent, revoke.status)

        assertEquals(HttpStatusCode.Unauthorized, client.mcpRaw(mcp.accessToken, "get_my_permissions").status)
        assertEquals(HttpStatusCode.Unauthorized, client.bearerPost("/auth/session/mcp-token", login.renewalToken).status, "pmon cannot mint it back")
        assertEquals(false, wireValid(login.token))
    }

    @Test
    fun `logout is idempotent, reveals nothing, and is audited once without the token`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal()
        val login = client.pmonLogin(caller)
        repeat(2) { assertEquals(HttpStatusCode.NoContent, client.bearerPost("/auth/session/logout", login.renewalToken).status) }
        assertEquals(HttpStatusCode.NoContent, client.bearerPost("/auth/session/logout", "pmr_not-a-session").status)
        assertEquals(HttpStatusCode.Unauthorized, client.post("/auth/session/logout").status)

        assertEquals(
            1L,
            count(
                "SELECT count(*) FROM audit_event WHERE principal=? AND action=? AND channel='pmon' AND kind='auth'",
                caller, AuthAuditRecorder.ACTION_LOGOUT,
            ),
        )
        for (secret in listOf(login.renewalToken, login.token)) {
            assertEquals(0L, count("SELECT count(*) FROM audit_event WHERE statement LIKE ? OR detail LIKE ? OR resource LIKE ?", "%$secret%", "%$secret%", "%$secret%"))
        }
        assertFailsWith<StatusException> {
            runBlocking { grpc.validateToken(validateTokenRequest { token = login.token; datasourceName = datasource.name; clientAddr = "127.0.0.1" }) }
        }
    }

    private fun count(sql: String, vararg args: String): Long = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps ->
            args.forEachIndexed { i, v -> ps.setString(i + 1, v) }
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    private fun principal() = "pmon-logout-${seq.incrementAndGet()}@example.com"
}
