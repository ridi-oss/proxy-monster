package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.grpc.Engine
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
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
 * ROUTE-level coverage of `GET /api/datasources/{id}/wire-cert`, the download a direct client
 * (psql/mysql/DataGrip) points `sslrootcert` / `--ssl-ca` at.
 *
 * This route hands out trust material, so its gate is load-bearing in a way the happy path cannot show: the
 * bytes are useless to an attacker on their own, but the route also reveals WHICH datasources exist and which
 * address they answer on, and it previously resolved its principal as `userSession()?.principal ?: "debug-user"`
 * — an unauthenticated caller silently became `debug-user` and got whatever that identity could connect to.
 * Nothing in the response distinguishes the two cases, which is exactly why it needs a test rather than an
 * inspection.
 *
 * Pinned here: unauthenticated is 401 (never a debug-user fallback), an authenticated caller WITHOUT
 * `datasource.connect` is 403, a datasource whose proxy published no chain is 404 with a distinct code (not
 * "no such datasource"), and only a caller Cedar actually grants gets the PEM.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WireCertRouteDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private lateinit var withChain: Datasource
    private lateinit var noChain: Datasource
    private lateinit var cpGo: CpGoStack

    private val connector = "connector@example.com"
    private val stranger = "stranger@example.com"

    // A self-signed leaf is the ordinary self-hosted case: the proxy's own certificate IS the anchor.
    private val chainPem =
        "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkTCB+wIJAKZ5Zm1kZm1kMA0GCSqGSIb3DQEBCwUAMBUxEzARBgNVBAMTCnBt\n" +
            "LXRlc3QtY2EwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAVMRMwEQYD\n" +
            "VQQDEwpwbS10ZXN0LWNhMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL9pm1kZm1kZ\n" +
            "-----END CERTIFICATE-----\n"

    /** Only `connector` may connect to the two datasources; `stranger` is granted nothing. */
    private val connectPermit = """permit(
        principal in Role::"connector",
        action == Action::"datasource.connect",
        resource
    );"""

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_wire_cert_route")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)

        // Registered through the STORE's register(), the same path the proxy's gRPC Register drives, so the
        // presence/clear semantics of the chain are exercised rather than bypassed by a direct INSERT.
        core.datasourceStore.register(
            name = "cert-ds", engine = Engine.MYSQL, host = "db", port = 3306, dbName = "app",
            tags = emptyList(), advertiseAddr = "proxy.example.com:6033",
            advertiseCertChain = chainPem, advertiseWireTls = true,
        )
        withChain = core.datasourceStore.getByName("cert-ds")!!
        // A proxy serving TLS that publishes NOTHING (PM_TLS_NO_ADVERTISE): there is no file to hand out, but
        // this is emphatically not "no TLS" and not "no such datasource".
        core.datasourceStore.register(
            name = "public-ds", engine = Engine.MYSQL, host = "db2", port = 3306, dbName = "app",
            tags = emptyList(), advertiseAddr = "public.example.com:6033",
            advertiseCertChain = null, advertiseWireTls = true,
        )
        noChain = core.datasourceStore.getByName("public-ds")!!

        val role = core.policyStore.createRole(RoleInput("connector"))
        core.policyStore.createAssignment(RoleAssignmentInput(connector, role.id))
        for (p in listOf(connector, stranger)) {
            core.userGroupStore.createUser(
                AppUserInput(principal = p), core.tokenStore, core.accessStore,
                PrincipalSessionStore(dataSource, null),
            )
        }
        core.cedarPolicyStore.create(CedarPolicyInput(name = "wire-cert-connect", cedarSrc = connectPermit), updatedBy = null)

        // authDebug=false is the whole point: with it on, every gate short-circuits and this test proves nothing.
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "wire-cert-route-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(PrincipalSessionStore(dataSource, null), config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    @Suppress("UnusedReceiverParameter")
    private fun ApplicationTestBuilder.wire(): HttpClient = cpGo.client()

    @Test
    fun `an unauthenticated caller gets 401, never a debug-user fallback`() = testApplication {
        val client = wire()
        val res = client.get("/api/datasources/${withChain.id}/wire-cert")
        assertEquals(
            HttpStatusCode.Unauthorized, res.status,
            "no session and no bearer must be 401; resolving the principal as \"debug-user\" would hand the " +
                "advertised trust material and datasource inventory to an anonymous caller",
        )
        assertFalse(
            res.bodyAsText().contains("BEGIN CERTIFICATE"),
            "an unauthenticated response must not carry the certificate",
        )
    }

    @Test
    fun `an authenticated caller without datasource-connect gets 403`() = testApplication {
        val client = wire()
        client.post("/test/session/$stranger")
        val res = client.get("/api/datasources/${withChain.id}/wire-cert")
        assertEquals(
            HttpStatusCode.Forbidden, res.status,
            "a session alone is not authorization — the route must run the same datasource.connect decision " +
                "the console's list runs, or it advertises a connection the caller may not make",
        )
        assertFalse(res.bodyAsText().contains("BEGIN CERTIFICATE"), "a forbidden response must not carry the certificate")
    }

    @Test
    fun `a granted caller downloads the advertised chain as a PEM attachment`() = testApplication {
        val client = wire()
        client.post("/test/session/$connector")
        val res = client.get("/api/datasources/${withChain.id}/wire-cert")
        assertEquals(HttpStatusCode.OK, res.status)
        assertTrue(res.bodyAsText().contains("BEGIN CERTIFICATE"), "the granted caller must receive the chain")
        // Filename from the id, not the name: a datasource name is barely constrained, so a quote or CRLF in
        // one would be header injection in Content-Disposition.
        assertEquals(
            "attachment; filename=\"datasource-${withChain.id}-wire-cert.pem\"",
            res.headers[HttpHeaders.ContentDisposition],
        )
    }

    @Test
    fun `a datasource whose proxy published no chain is 404 with its own code`() = testApplication {
        val client = wire()
        client.post("/test/session/$connector")
        val res = client.get("/api/datasources/${noChain.id}/wire-cert")
        assertEquals(HttpStatusCode.NotFound, res.status)
        // Distinct from common.not_found so the console can say "this proxy publishes no certificate" instead
        // of "no such datasource" — the two are different operator problems, and this datasource DOES serve TLS.
        assertTrue(
            res.bodyAsText().contains("no_wire_cert"),
            "expected the datasource.no_wire_cert code, got: ${res.bodyAsText()}",
        )
    }

    @Test
    fun `an unknown datasource id is 404 and is not confused with a missing chain`() = testApplication {
        val client = wire()
        client.post("/test/session/$connector")
        val res = client.get("/api/datasources/999999/wire-cert")
        assertEquals(HttpStatusCode.NotFound, res.status)
        assertFalse(
            res.bodyAsText().contains("no_wire_cert"),
            "a nonexistent datasource must not report the no-chain code: that would tell a caller the id " +
                "exists. Got: ${res.bodyAsText()}",
        )
    }
}
