package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.grpc.Engine
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The `datasource.connect` gate on `GET /api/datasources/{id}` and the list route that carries the same
 * fields, behind cp-go (support/CpGoStack.kt), which serves both. The row and the list carry the
 * `advertiseAddr`/`advertiseCertChain` that `{id}/wire-cert` releases only under `datasource.connect`, so a
 * gate on any one of them alone is bypassable through the others. `authDebug` is off — with it on every gate
 * short-circuits and this test would prove nothing.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DatasourceMetadataConnectGateCpGoTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var datasource: Datasource
    private lateinit var ungranted: Datasource
    private lateinit var stack: CpGoStack

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
        val database = SharedPostgres.freshDatabase("pm_ds_metadata_gate_cpgo")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)

        core.datasourceStore.register(
            name = "gated-ds", engine = Engine.MYSQL, host = "db", port = 3306, dbName = "app",
            tags = emptyList(), advertiseAddr = "proxy.example.com:6033",
            advertiseCertChain = chainPem, advertiseWireTls = true, description = "Gated orders DB",
        )
        datasource = core.datasourceStore.getByName("gated-ds")!!

        // A second datasource nobody is granted: the connector's permit names "gated-ds", so this one must
        // stay 403 for everyone.
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
        stack = CpGoStack(config, core, database) {
            routing { testLoginRoute(PrincipalSessionStore(dataSource, null), config) }
        }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    @Test
    fun `the datasource row is 401 unauthenticated`() = runBlocking {
        val client = stack.client()
        val res = client.get("/api/datasources/${datasource.id}")
        assertEquals(HttpStatusCode.Unauthorized, res.status)
        assertFalse(
            res.bodyAsText().contains("BEGIN CERTIFICATE"),
            "an unauthenticated response must not carry the advertised chain",
        )
    }

    /**
     * The decision is keyed to the datasource being asked for. The connector's permit names `gated-ds`, so
     * the SAME session must be admitted there and refused here — the assertion an unconstrained `resource`
     * permit could not make.
     */
    @Test
    fun `a connect grant on one datasource does not carry to another`() = runBlocking {
        val client = stack.client()
        client.post("/test/session/$connector")
        assertEquals(HttpStatusCode.OK, client.get("/api/datasources/${datasource.id}").status)
        assertEquals(
            HttpStatusCode.Forbidden, client.get("/api/datasources/${ungranted.id}").status,
            "the grant names one datasource; a gate keyed to anything coarser would admit both",
        )
        assertEquals(
            HttpStatusCode.Forbidden,
            client.get("/api/datasources/${ungranted.id}/table-detail?catalog=def&schema=app&table=t").status,
        )
    }

    /**
     * The Bearer path is why these routes use `requireApiOrBearer` rather than `requireApi`: pmon holds a
     * wire token, not a cookie. Swapping the helper back would leave every session test passing.
     */
    @Test
    fun `a wire-token Bearer caller is authorized by the same connect decision`() = runBlocking {
        val token = core.tokenStore.issue(
            TokenKind.USER, connector, roles = emptyList(), name = "gate-test", ttlSeconds = 300,
        )
        val client = stack.client()
        val granted = client.get("/api/datasources/${datasource.id}") {
            header(HttpHeaders.Authorization, "Bearer ${token.token}")
        }
        assertEquals(HttpStatusCode.OK, granted.status, "a wire token is a valid identity on this route")
        val refused = client.get("/api/datasources/${ungranted.id}") {
            header(HttpHeaders.Authorization, "Bearer ${token.token}")
        }
        assertEquals(
            HttpStatusCode.Forbidden, refused.status,
            "the Bearer path must run the same per-datasource decision, not skip it",
        )
    }

    @Test
    fun `the datasource row is 403 without datasource-connect, chain withheld`() = runBlocking {
        val client = stack.client()
        client.post("/test/session/$stranger")
        val res = client.get("/api/datasources/${datasource.id}")
        assertEquals(
            HttpStatusCode.Forbidden, res.status,
            "the row carries the same advertiseCertChain {id}/wire-cert gates on datasource.connect; " +
                "admitting it on a session alone makes that gate decorative",
        )
        assertFalse(res.bodyAsText().contains("BEGIN CERTIFICATE"), "a forbidden response must not carry the chain")
    }

    @Test
    fun `a granted caller reads the datasource row`() = runBlocking {
        val client = stack.client()
        client.post("/test/session/$connector")
        assertEquals(HttpStatusCode.OK, client.get("/api/datasources/${datasource.id}").status)
    }

    /**
     * The list is the alternate path to the same bytes: filtering it would break JIT-request compose (which
     * must show datasources you cannot yet connect to), so the row survives with its connection material
     * stripped. Without this the `{id}` gate above is bypassable by asking for the list instead.
     */
    @Test
    fun `the list keeps non-connectable rows but strips their connection material`() = runBlocking {
        val client = stack.client()
        client.post("/test/session/$stranger")
        val res = client.get("/api/datasources")
        assertEquals(HttpStatusCode.OK, res.status)
        val body = res.bodyAsText()
        assertTrue(body.contains("gated-ds"), "the datasource must stay visible so it can be requested")
        assertFalse(
            body.contains("BEGIN CERTIFICATE"),
            "the list must not answer what {id} and {id}/wire-cert refuse; got: $body",
        )
        assertFalse(body.contains("proxy.example.com"), "the advertised address is connection material too")
        assertFalse(body.contains("Gated orders DB"), "the description rides only on connectable rows")
    }

    @Test
    fun `the list keeps connection material for a connectable row`() = runBlocking {
        val client = stack.client()
        client.post("/test/session/$connector")
        val body = client.get("/api/datasources").bodyAsText()
        assertTrue(body.contains("BEGIN CERTIFICATE"), "a caller granted connect must still get the chain")
        assertTrue(body.contains("proxy.example.com"), "a caller granted connect must still get the address")
        assertTrue(body.contains("\"description\":\"Gated orders DB\""), body)
    }
}
