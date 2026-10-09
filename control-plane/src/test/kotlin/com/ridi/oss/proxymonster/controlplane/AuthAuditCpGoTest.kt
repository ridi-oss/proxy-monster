package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_TOKEN_MINT
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_TOKEN_REVOKE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.CHANNEL_WIRE
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.auditChainHead
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.request.delete
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The `kind="auth"` rows the token routes write, driven through cp-go: deleting an emission or splitting it
 * off the route's own transaction has to fail here.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthAuditCpGoTest {
    @Serializable
    private data class CreateTokenInput(val name: String? = null, val ttlSeconds: Long? = null)

    @Serializable
    private data class MintSessionTokenInput(val ttlSeconds: Long? = null)

    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var stack: CpGoStack

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_auth_audit_cpgo")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        // token-admin holds system:admin so the seeded token.revoke oversight policy authorizes the cross-principal revoke.
        core.policyStore.createAssignment(
            RoleAssignmentInput("token-admin@example.com", core.policyStore.getRoleByName("system:admin")!!.id),
        )
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "auth-audit-test-secret-at-least-32-bytes", oidc = null, resultKey = null,
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        val sessions = PrincipalSessionStore(dataSource, null)
        stack = CpGoStack(config, core, database, extraEnv = mapOf("PM_TRUSTED_PROXIES" to "127.0.0.1")) {
            routing { testLoginRoute(sessions, config) }
        }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    /** A cookie-jar client that presents [CALLER_ADDR] as its forwarded source on every request. */
    private fun callerClient(): HttpClient = stack.client().config {
        install(DefaultRequest) { header("X-Forwarded-For", CALLER_ADDR) }
    }

    @Test
    fun `token mint and revoke are audited through their routes and name the caller`() = runBlocking<Unit> {
        val client = callerClient()

        val owner = "token-owner@example.com"
        client.post("/test/session/$owner")
        val minted: IssuedToken = client.post("/api/tokens") {
            contentType(ContentType.Application.Json)
            setBody(CreateTokenInput(name = "audited"))
        }.body()
        assertEvent(owner, ACTION_TOKEN_MINT, auditEntity("Token", minted.id.toString()), "SUCCESS", "ALLOW")

        // The row must name the ADMIN who revoked, not the owner it was done to.
        val admin = "token-admin@example.com"
        val adminClient = callerClient()
        adminClient.post("/test/session/$admin")
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

    @Test
    fun `a rejected auth audit insert rolls the token route's own mutation back`() = runBlocking<Unit> {
        val client = callerClient()
        val principal = "auth-audit-rollback@example.com"
        client.post("/test/session/$principal")

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
    fun `session wire-token mint is audited through its route and names the caller`() = runBlocking<Unit> {
        val client = callerClient()

        val owner = "wire-token-owner@example.com"
        client.post("/test/session/$owner")
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
    fun `a rejected auth audit insert rolls the wire-token route's own mint back`() = runBlocking<Unit> {
        val client = callerClient()
        val principal = "wire-audit-rollback@example.com"
        client.post("/test/session/$principal")

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

    /** The (principal, action, resource) triple identifies exactly [expectedRows] rows, caller address included. */
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
        const val CALLER_ADDR = "203.0.113.7"
    }
}
