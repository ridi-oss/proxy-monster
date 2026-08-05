package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_TOKEN_MINT
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_TOKEN_REVOKE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_WIRE_VALIDATE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.CHANNEL_WIRE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.PRINCIPAL_UNATTRIBUTED
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.auditChainHead
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import com.ridi.oss.proxymonster.grpc.validateTokenRequest
import io.grpc.Status
import io.grpc.StatusException
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.delete
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.response.respond
import io.ktor.server.routing.post as serverPost
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed coverage of the `kind="auth"` trail written by [AuthAuditRecorder], through the routes and
 * the gRPC service that own each chokepoint rather than a re-composition of their store calls — deleting
 * an emission in `Tokens.kt` or `ControlPlaneGrpcService.kt` has to fail here.
 *
 * The load-bearing assertion is the last one: a SUCCESSFUL wire-token validation writes NO row. That path
 * runs per connection and per query, and burying the rejected attempts under it would defeat the trail.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthAuditDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var grpc: ControlPlaneGrpcService
    private lateinit var authz: Authz
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var datasourceName: String

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_auth_audit"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        grpc = ControlPlaneGrpcService(core)
        val policyStore = CedarPolicyStore(dataSource)
        authz = Authz(CedarEngine(policyStore), policyStore, RoleSource { emptySet() })
        sessionStore = PrincipalSessionStore(dataSource, null)
        datasourceName = core.datasourceStore.create(DatasourceInput("auth-audit-ds", "postgres")).name
    }

    /** authDebug bypasses requireAuthz, so the routes under test decide nothing here — the point is who the
     *  audit row NAMES, and a signed-in caller is established through the same web-session cookie the app uses.
     *  The test host's socket peer is trusted as an edge so [CALLER_ADDR] resolves off `X-Forwarded-For`,
     *  which is how the recorder's client-address wiring is pinned to a known value. */
    private fun testConfig() = Config(
        httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
        sessionSecret = "auth-audit-test-secret-at-least-32-bytes", oidc = null, resultKey = null,
        scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        trustedProxies = setOf("localhost"),
    )

    private fun ApplicationTestBuilder.installTokenRoutes() {
        val config = testConfig()
        application {
            attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            // Mirrors the application-level fallback module() installs, so a route that throws answers 500
            // here the way it would in the running server instead of surfacing as a transport failure.
            install(StatusPages) { exception<Throwable> { call, _ -> call.respond(HttpStatusCode.InternalServerError) } }
            install(Sessions) { webSessionCookie(sessionStore, config.sessionSecret) }
            routing {
                serverPost("/test/login/{principal}") {
                    val principal = requireNotNull(call.parameters["principal"])
                    val deviceId = call.ensureDeviceCookie(secure = false)
                    call.sessions.set(
                        WebSessionRef(
                            sessionStore.mintWeb(
                                principal, null, config.webSessionAbsoluteSeconds, config.webSessionIdleSeconds, deviceId,
                            ),
                        ),
                    )
                    call.respond(HttpStatusCode.NoContent)
                }
                tokenRoutes(config, core.tokenStore, core.userGroupStore, authz, core.authAudit)
            }
        }
    }

    /** A cookie-jar client that presents [CALLER_ADDR] as its forwarded source on every request. */
    private fun ApplicationTestBuilder.callerClient() = createClient {
        expectSuccess = false
        install(HttpCookies)
        install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        install(DefaultRequest) { header("X-Forwarded-For", CALLER_ADDR) }
    }

    @Test
    fun `token mint and revoke are audited through their routes and name the caller`() = testApplication {
        installTokenRoutes()
        val client = callerClient()

        val owner = "token-owner@example.com"
        client.post("/test/login/$owner")
        val minted: IssuedToken = client.post("/api/tokens") {
            contentType(ContentType.Application.Json)
            setBody(CreateTokenInput(name = "audited"))
        }.body()
        assertEvent(owner, ACTION_TOKEN_MINT, auditEntity("Token", minted.id.toString()), "SUCCESS", "ALLOW")

        // An identity admin may revoke someone else's token (the token.revoke oversight seed). The row must
        // name the ADMIN who did it, not the owner it was done to — otherwise the trail frames the victim.
        val admin = "token-admin@example.com"
        val adminClient = callerClient()
        adminClient.post("/test/login/$admin")
        assertEquals(HttpStatusCode.NoContent, adminClient.delete("/api/tokens/${minted.id}").status)
        assertNotNull(core.tokenStore.get(minted.id)?.revokedAt)
        assertEvent(admin, ACTION_TOKEN_REVOKE, auditEntity("Token", minted.id.toString()), "SUCCESS", "ALLOW")
        assertEquals(
            0, count("SELECT count(*) FROM audit_event WHERE kind='auth' AND action='$ACTION_TOKEN_REVOKE' AND principal='$owner'"),
            "the token's owner did not perform this revocation and must not be named as its actor",
        )

        // A 404 revoke changes nothing, so it records nothing.
        val before = countAuth()
        assertEquals(HttpStatusCode.NotFound, adminClient.delete("/api/tokens/${minted.id}").status)
        assertEquals(before, countAuth(), "a revoke that changed no row must not write an event")

        assertEquals(
            0, count("SELECT count(*) FROM audit_event WHERE statement LIKE '%${minted.token}%' OR detail LIKE '%${minted.token}%'"),
            "a minted token's secret must never reach the audit trail",
        )
        verifyAuditChain(dataSource)
    }

    /**
     * Atomicity proven through the ROUTES, not a re-composition of their store calls: a route that committed
     * the credential change and then recorded it separately would satisfy every other assertion in this class
     * while leaving a rejected insert with a committed mutation behind it.
     */
    @Test
    fun `a rejected auth audit insert rolls the token route's own mutation back`() = testApplication {
        installTokenRoutes()
        val client = callerClient()
        val principal = "auth-audit-rollback@example.com"
        client.post("/test/login/$principal")

        val headBeforeMint = auditChainHead(dataSource)
        val tokensBefore = count("SELECT count(*) FROM proxy_token WHERE principal = '$principal'")
        rejectAction(ACTION_TOKEN_MINT)
        try {
            assertEquals(
                HttpStatusCode.InternalServerError,
                client.post("/api/tokens") {
                    contentType(ContentType.Application.Json)
                    setBody(CreateTokenInput(name = "rolled-back"))
                }.status,
            )
            assertEquals(
                tokensBefore, count("SELECT count(*) FROM proxy_token WHERE principal = '$principal'"),
                "a mint whose audit insert was rejected must leave no token behind",
            )
            assertHeadUnchanged(headBeforeMint)
        } finally {
            dropRejectTrigger()
        }

        val minted: IssuedToken = client.post("/api/tokens") {
            contentType(ContentType.Application.Json)
            setBody(CreateTokenInput(name = "revoke-rollback"))
        }.body()
        val headBeforeRevoke = auditChainHead(dataSource)
        rejectAction(ACTION_TOKEN_REVOKE)
        try {
            assertEquals(HttpStatusCode.InternalServerError, client.delete("/api/tokens/${minted.id}").status)
            assertNull(
                core.tokenStore.get(minted.id)?.revokedAt,
                "a revoke whose audit insert was rejected must leave the token usable",
            )
            assertHeadUnchanged(headBeforeRevoke)
        } finally {
            dropRejectTrigger()
        }
        verifyAuditChain(dataSource)
    }

    @Test
    fun `session wire-token mint is audited through its route and names the caller`() = testApplication {
        installTokenRoutes()
        val client = callerClient()

        val owner = "wire-token-owner@example.com"
        client.post("/test/login/$owner")
        val minted: IssuedToken = client.post("/api/wire-tokens") {
            contentType(ContentType.Application.Json)
            setBody(MintSessionTokenInput())
        }.body()
        assertEquals(TokenKind.SESSION.name, minted.kind)
        assertEvent(owner, ACTION_TOKEN_MINT, auditEntity("Token", minted.id.toString()), "SUCCESS", "ALLOW")

        assertEquals(
            0, count("SELECT count(*) FROM audit_event WHERE statement LIKE '%${minted.token}%' OR detail LIKE '%${minted.token}%'"),
            "a minted token's secret must never reach the audit trail",
        )
        verifyAuditChain(dataSource)
    }

    @Test
    fun `a rejected auth audit insert rolls the wire-token route's own mint back`() = testApplication {
        installTokenRoutes()
        val client = callerClient()
        val principal = "wire-audit-rollback@example.com"
        client.post("/test/login/$principal")

        val headBeforeMint = auditChainHead(dataSource)
        val tokensBefore = count("SELECT count(*) FROM proxy_token WHERE principal = '$principal'")
        rejectAction(ACTION_TOKEN_MINT)
        try {
            assertEquals(
                HttpStatusCode.InternalServerError,
                client.post("/api/wire-tokens") {
                    contentType(ContentType.Application.Json)
                    setBody(MintSessionTokenInput())
                }.status,
            )
            assertEquals(
                tokensBefore, count("SELECT count(*) FROM proxy_token WHERE principal = '$principal'"),
                "a mint whose audit insert was rejected must leave no token behind",
            )
            assertHeadUnchanged(headBeforeMint)
        } finally {
            dropRejectTrigger()
        }
        verifyAuditChain(dataSource)
    }

    @Test
    fun `validateToken audits failures but not successful validation`() {
        val before = countAuth()
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf("not-a-token"))
        assertEquals(before + 1, countAuth())
        // No client address: ValidateTokenRequest carries none (KNOWN_LIMITATIONS.md "Audit trail").
        assertEvent(
            PRINCIPAL_UNATTRIBUTED, ACTION_WIRE_VALIDATE, auditEntity("Token", "unresolved"), "FAILURE", "DENY",
            expectedRows = 1, clientAddr = null,
        )

        val revoked = core.tokenStore.issue(TokenKind.USER, "revoked@example.com", emptyList(), null, 3600)
        assertTrue(core.tokenStore.revoke(revoked.id, "revoked@example.com"))
        val afterUnknown = countAuth()
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf(revoked.token))
        assertEquals(afterUnknown + 1, countAuth())

        val expired = core.tokenStore.issue(TokenKind.USER, "expired@example.com", emptyList(), null, 3600)
        execute("UPDATE proxy_token SET expires_at = now() - interval '1 hour' WHERE id = ${expired.id}")
        val afterRevoked = countAuth()
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf(expired.token))
        assertEquals(afterRevoked + 1, countAuth())

        val deprovisionedPrincipal = "deprovisioned@example.com"
        core.userGroupStore.createUser(
            AppUserInput(deprovisionedPrincipal), core.tokenStore, core.accessStore, sessionStore,
        )
        val deprovisioned = core.tokenStore.issue(TokenKind.USER, deprovisionedPrincipal, emptyList(), null, 3600)
        core.userGroupStore.setUserActive(deprovisionedPrincipal, false)
        val afterExpired = countAuth()
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf(deprovisioned.token))
        assertEquals(afterExpired + 1, countAuth())
        assertEvent(
            deprovisionedPrincipal, ACTION_WIRE_VALIDATE, auditEntity("User", deprovisionedPrincipal), "FAILURE", "DENY",
            clientAddr = null,
        )

        // The presented credential is never itself recorded, on any of the failure paths above.
        assertEquals(
            0,
            count(
                """SELECT count(*) FROM audit_event
                   WHERE statement LIKE '%${revoked.token}%' OR detail LIKE '%${revoked.token}%'
                      OR statement LIKE '%${expired.token}%' OR detail LIKE '%${expired.token}%'""",
            ),
        )

        val valid = core.tokenStore.issue(TokenKind.USER, "valid@example.com", emptyList(), null, 3600)
        val beforeSuccess = countAuth()
        val identity = runBlocking {
            grpc.validateToken(validateTokenRequest { token = valid.token; datasourceName = this@AuthAuditDbTest.datasourceName })
        }
        assertEquals("valid@example.com", identity.principal)
        assertEquals(beforeSuccess, countAuth(), "successful wire validation must not emit auth audit rows")
        verifyAuditChain(dataSource)
    }

    /**
     * The wire-rejection audit is best-effort: a bad token has no state change to join, so an audit-insert
     * failure on this hot path must NOT turn UNAUTHENTICATED into INTERNAL — the regression this guards. A
     * reject-trigger on the wire-validate insert forces the insert to throw; the status must stay
     * UNAUTHENTICATED and the chain untouched.
     */
    @Test
    fun `a rejected wire-rejection audit still answers UNAUTHENTICATED, not INTERNAL`() {
        val headBefore = auditChainHead(dataSource)
        rejectAction(ACTION_WIRE_VALIDATE)
        try {
            assertEquals(
                Status.Code.UNAUTHENTICATED, statusOf("still-not-a-token"),
                "a failed rejection audit must not change the auth outcome",
            )
        } finally {
            dropRejectTrigger()
        }
        assertHeadUnchanged(headBefore)
        verifyAuditChain(dataSource)
    }

    private fun statusOf(token: String): Status.Code =
        assertFailsWith<StatusException> {
            runBlocking { grpc.validateToken(validateTokenRequest { this.token = token; datasourceName = this@AuthAuditDbTest.datasourceName }) }
        }.status.code

    /**
     * Assert the (principal, action, resource) triple identifies exactly [expectedRows] rows that read as
     * expected, [clientAddr] included: the recorder is the only thing carrying the caller's address onto the
     * row, so an unasserted address is a wire that can be cut without a test noticing.
     */
    private fun assertEvent(
        principal: String,
        action: String,
        resource: String,
        outcome: String,
        decision: String,
        expectedRows: Int = 1,
        channel: String = CHANNEL_WIRE,
        clientAddr: String? = CALLER_ADDR,
    ) {
        val rows = dataSource.connection.use { c ->
            c.prepareStatement(
                """SELECT action, resource, outcome, kind, channel, decision, datasource, client_addr
                   FROM audit_event WHERE principal=? AND action=? AND resource=? ORDER BY id""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.setString(2, action)
                ps.setString(3, resource)
                ps.executeQuery().use { rs -> buildList { while (rs.next()) add((1..8).map(rs::getString)) } }
            }
        }
        assertEquals(
            List(expectedRows) {
                listOf(action, resource, outcome, "auth", channel, decision, "control-plane", clientAddr)
            },
            rows,
        )
    }

    /** Make every `kind="auth"` insert for [action] fail, so a caller's transaction has to roll back with it. */
    private fun rejectAction(action: String) {
        execute(
            """CREATE OR REPLACE FUNCTION pm_test_reject_auth_audit() RETURNS trigger AS ${'$'}body${'$'}
               BEGIN RAISE EXCEPTION 'forced auth audit failure'; END
               ${'$'}body${'$'} LANGUAGE plpgsql""",
        )
        execute(
            """CREATE TRIGGER pm_test_reject_auth_audit BEFORE INSERT ON audit_event
               FOR EACH ROW WHEN (NEW.kind = 'auth' AND NEW.action = '$action')
               EXECUTE FUNCTION pm_test_reject_auth_audit()""",
        )
    }

    private fun dropRejectTrigger() {
        execute("DROP TRIGGER IF EXISTS pm_test_reject_auth_audit ON audit_event")
        execute("DROP FUNCTION IF EXISTS pm_test_reject_auth_audit()")
    }

    private fun assertHeadUnchanged(before: Pair<Long, ByteArray>) {
        val after = auditChainHead(dataSource)
        assertEquals(before.first, after.first)
        assertContentEquals(before.second, after.second)
    }

    private fun countAuth(): Int = count("SELECT count(*) FROM audit_event WHERE kind = 'auth'")

    private fun count(sql: String): Int = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps -> ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) } }
    }

    private fun execute(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    private companion object {
        /** The forwarded source address every HTTP request in this class presents — a documentation range,
         *  never a real host, and the value the audit rows must carry back. */
        const val CALLER_ADDR = "203.0.113.7"
    }
}
