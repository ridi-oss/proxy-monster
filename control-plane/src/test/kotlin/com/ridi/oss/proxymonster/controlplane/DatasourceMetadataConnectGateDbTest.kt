package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import com.ridi.oss.proxymonster.grpc.Engine
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The `datasource.connect` gate on `GET /api/datasources/{id}/table-detail`, and the per-row decision the
 * list, `{id}` and `{id}/wire-cert` ask Kotlin for (those three are served by cp-go). `authDebug` is off —
 * with it on every gate short-circuits and this test would prove nothing.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DatasourceMetadataConnectGateDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var datasource: Datasource
    private lateinit var ungranted: Datasource

    private val connector = "connector@example.com"
    private val stranger = "stranger@example.com"

    private val chainPem =
        "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkTCB+wIJAKZ5Zm1kZm1kMA0GCSqGSIb3DQEBCwUAMBUxEzARBgNVBAMTCnBt\n" +
            "-----END CERTIFICATE-----\n"

    // Bound to ONE datasource by name, not a bare `resource`: an unconstrained permit would still admit a
    // gate that authorized the wrong datasource (or resolved the resource from the wrong place), so the
    // second datasource below is what proves the decision is keyed to the row being asked for.
    private val connectPermit = """permit(
        principal in Role::"connector",
        action == Action::"datasource.connect",
        resource == Datasource::"gated-ds"
    );"""

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_ds_metadata_gate"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)

        core.datasourceStore.register(
            name = "gated-ds", engine = Engine.MYSQL, host = "db", port = 3306, dbName = "app",
            tags = emptyList(), advertiseAddr = "proxy.example.com:6033",
            advertiseCertChain = chainPem, advertiseWireTls = true, description = "Gated orders DB",
        )
        datasource = core.datasourceStore.getByName("gated-ds")!!

        // A second datasource nobody is granted: the connector's permit names "gated-ds", so this one must
        // stay 403 for everyone. Without it the suite could not tell a per-datasource decision from a blanket
        // "is any connect policy enabled" check.
        core.datasourceStore.register(
            name = "other-ds", engine = Engine.MYSQL, host = "db2", port = 3306, dbName = "app",
            tags = emptyList(), advertiseAddr = "other.example.com:6033",
            advertiseCertChain = chainPem, advertiseWireTls = true,
        )
        ungranted = core.datasourceStore.getByName("other-ds")!!

        val role = core.policyStore.createRole(RoleInput("connector"))
        core.policyStore.createAssignment(RoleAssignmentInput(connector, role.id))
        for (p in listOf(connector, stranger)) {
            core.userGroupStore.createUser(
                AppUserInput(principal = p), core.tokenStore, core.accessStore,
                PrincipalSessionStore(dataSource, null),
            )
        }
        core.cedarPolicyStore.create(
            CedarPolicyInput(name = "ds-metadata-connect", cedarSrc = connectPermit), updatedBy = null,
        )

        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "ds-metadata-gate-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
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
        val sessionStore = PrincipalSessionStore(dataSource, null)
        attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(Sessions) { webSessionCookie(sessionStore, config.sessionSecret) }
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
            datasourceRoutes(
                config, core.authz, core.roleResolver, core.datasourceStore, core.proxyEventsHub,
                TableDetailService(core), core.tokenStore, core.userGroupStore,
            )
        }
    }

    /** The decision is keyed to the datasource asked for: the connector's permit names `gated-ds` only. */
    @Test
    fun `a connect grant on one datasource does not carry to another`() = testApplication {
        val client = wire()
        client.post("/test/session/$connector")
        assertEquals(
            HttpStatusCode.Forbidden,
            client.get("/api/datasources/${ungranted.id}/table-detail?catalog=def&schema=app&table=t").status,
        )
    }

    /**
     * cp-go's list keeps a row the caller may not connect to but strips its connection material; this is the
     * decision it asks per row, the same one `{id}` and `{id}/wire-cert` make.
     */
    @Test
    fun `the list's per-row decision matches the datasource row's`() {
        assertFalse(core.mayConnectById(stranger, null, datasource.id), "a stranger's row is stripped")
        assertTrue(core.mayConnectById(connector, null, datasource.id), "a connector's row keeps its material")
        assertFalse(core.mayConnectById(connector, null, Long.MAX_VALUE), "a missing datasource is never connectable")
    }

    @Test
    fun `table-detail is 401 unauthenticated`() = testApplication {
        val client = wire()
        val res = client.get("/api/datasources/${datasource.id}/table-detail?catalog=def&schema=app&table=t")
        assertEquals(HttpStatusCode.Unauthorized, res.status)
    }

    @Test
    fun `table-detail is 403 without datasource-connect`() = testApplication {
        val client = wire()
        client.post("/test/session/$stranger")
        val res = client.get("/api/datasources/${datasource.id}/table-detail?catalog=def&schema=app&table=t")
        assertEquals(
            HttpStatusCode.Forbidden, res.status,
            "table-detail overlays the same classifications {id}/catalog serves under datasource.connect",
        )
    }

    /**
     * The gate must clear for a granted caller. No proxy is attached here, so the route runs past
     * authorization and fails at dispatch — asserted as the exact 502 the no-proxy path maps to, not merely
     * "not 403": a 500 from any unrelated crash would satisfy the weaker claim and hide a broken gate.
     */
    @Test
    fun `a granted caller passes the table-detail gate and fails at proxy dispatch`() = testApplication {
        val client = wire()
        client.post("/test/session/$connector")
        val res = client.get("/api/datasources/${datasource.id}/table-detail?catalog=def&schema=app&table=t")
        assertEquals(HttpStatusCode.BadGateway, res.status, "expected the no-proxy dispatch failure past the gate")
        assertTrue(
            res.bodyAsText().contains("table_introspection_failed"),
            "expected datasource.table_introspection_failed, got: ${res.bodyAsText()}",
        )
    }
}
