package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.OAuthAuthorizationStore
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpRaw
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.ok
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.seedDaemonSession
import com.ridi.oss.proxymonster.grpc.validateTokenRequest
import io.grpc.Status
import io.grpc.StatusException
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
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
import java.time.Instant
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PmonConsentRevokeDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var grpc: ControlPlaneGrpcService
    private lateinit var datasource: Datasource
    private val config = mcpTestConfig()

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_pmon_consent_revoke"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        grpc = ControlPlaneGrpcService(core)
        datasource = core.datasourceStore.create(DatasourceInput("pmon-consent-ds", "postgres"))
    }

    private fun wireValid(token: String): Boolean = try {
        runBlocking { grpc.validateToken(validateTokenRequest { this.token = token; datasourceName = datasource.name; clientAddr = "127.0.0.1" }) }
        true
    } catch (e: StatusException) {
        assertEquals(Status.Code.UNAUTHENTICATED, e.status.code)
        false
    }

    @Test
    fun `revoking the pmon consent on the web ends the pmon login`() = testApplication {
        val client = installControlPlane(config, core)
        val principal = "pmon-consent@example.com"
        val sessionId = dataSource.seedDaemonSession(principal)
        val (wire, mcp) = dataSource.connection.use { c ->
            core.tokenStore.issue(TokenKind.SESSION, principal, emptyList(), null, 3600, c, sessionId).token to
                OAuthAuthorizationStore(dataSource).issueAccessOnly(
                    c, principal, "pmon", config.mcpResource, PMON_DEFAULT_SCOPES, Instant.now().plusSeconds(600), sessionId,
                ).first
        }
        client.login(principal)
        assertEquals(true, wireValid(wire))
        client.mcpCall(mcp, "get_my_permissions").ok()

        val listed = MCP_TEST_JSON.parseToJsonElement(client.get("/oauth/consents").bodyAsText()).jsonObject
        val consent = listed["consents"]!!.jsonArray.map { it.jsonObject }.single { it["clientId"]!!.jsonPrimitive.content == "pmon" }
        val revoke = client.delete("/oauth/consents/${consent["id"]!!.jsonPrimitive.content}") {
            header("X-PM-CSRF", listed["csrfToken"]!!.jsonPrimitive.content)
        }
        assertEquals(HttpStatusCode.NoContent, revoke.status)

        assertEquals(HttpStatusCode.Unauthorized, client.mcpRaw(mcp, "get_my_permissions").status)
        assertEquals(false, wireValid(wire))
        val ended = dataSource.connection.use { c ->
            c.prepareStatement("SELECT ended_at FROM principal_session WHERE id = ?").use { ps ->
                ps.setLong(1, sessionId)
                ps.executeQuery().use { rs -> rs.next(); rs.getTimestamp(1) }
            }
        }
        assertNotNull(ended, "pmon cannot mint it back")
    }
}
