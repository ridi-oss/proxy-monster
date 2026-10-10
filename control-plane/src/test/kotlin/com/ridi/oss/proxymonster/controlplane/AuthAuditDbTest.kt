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
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.auditChainHead
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import com.ridi.oss.proxymonster.grpc.validateTokenRequest
import io.grpc.Status
import io.grpc.StatusException
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed coverage of the `kind="auth"` trail written by [AuthAuditRecorder], through [TokenService] and
 * the gRPC service that own each chokepoint — deleting an emission in `TokenService.kt` or
 * `ControlPlaneGrpcService.kt` has to fail here.
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
        // token-admin@example.com holds system:admin so the seeded token.revoke oversight policy applies to
        // it — the cross-principal revoke below is the case under test, and it has to be authorized for real.
        // Everyone else resolves to no roles, so their own token.mint still comes from the token.self seed.
        authz = Authz(
            CedarEngine(policyStore),
            policyStore,
            RoleSource { principal -> if (principal == "token-admin@example.com") setOf("system:admin") else emptySet() },
        )
        sessionStore = PrincipalSessionStore(dataSource, null)
        datasourceName = core.datasourceStore.create(DatasourceInput("auth-audit-ds", "postgres")).name
    }

    private fun service() = TokenService(core.tokenStore, core.userGroupStore, authz, core.authAudit)

    private fun actor(principal: String) = AuditActor(principal, clientAddr = CALLER_ADDR, channel = CHANNEL_WIRE)

    private fun mintUser(principal: String, name: String) =
        service().mintUser(principal, CALLER_ADDR, emptyList(), actor(principal), name, null)

    private fun mintSession(principal: String) =
        core.tokenStore.dataSource.mintForActivePrincipalLocked(principal, core.userGroupStore) { c ->
            core.tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = core.tokenStore.sessionTtlSeconds, c).also {
                core.authAudit.success(c, actor(principal), ACTION_TOKEN_MINT, auditEntity("Token", it.id.toString()), "Minted SESSION wire token")
            }
        }

    @Test
    fun `token mint and revoke are audited and name the caller`() {
        val owner = "token-owner@example.com"
        val minted = mintUser(owner, "audited")
        assertEvent(owner, ACTION_TOKEN_MINT, auditEntity("Token", minted.id.toString()), "SUCCESS", "ALLOW")

        // An identity admin may revoke someone else's token (the token.revoke oversight seed). The row must
        // name the ADMIN who did it, not the owner it was done to — otherwise the trail frames the victim.
        val admin = "token-admin@example.com"
        assertTrue(service().revoke(admin, CALLER_ADDR, actor(admin), minted.id))
        assertNotNull(core.tokenStore.get(minted.id)?.revokedAt)
        assertEvent(admin, ACTION_TOKEN_REVOKE, auditEntity("Token", minted.id.toString()), "SUCCESS", "ALLOW")
        assertEquals(
            0, count("SELECT count(*) FROM audit_event WHERE kind='auth' AND action='$ACTION_TOKEN_REVOKE' AND principal='$owner'"),
            "the token's owner did not perform this revocation and must not be named as its actor",
        )

        // A not-found revoke changes nothing, so it records nothing.
        val before = countAuth()
        val again = assertFailsWith<TaskServiceException> { service().revoke(admin, CALLER_ADDR, actor(admin), minted.id) }
        assertEquals(HttpStatusCode.NotFound, again.status)
        assertEquals(before, countAuth(), "a revoke that changed no row must not write an event")

        assertEquals(
            0, count("SELECT count(*) FROM audit_event WHERE statement LIKE '%${minted.token}%' OR detail LIKE '%${minted.token}%'"),
            "a minted token's secret must never reach the audit trail",
        )
        verifyAuditChain(dataSource)
    }

    /** A service that committed the credential change and then recorded it separately would leave a rejected
     *  insert with a committed mutation behind it. */
    @Test
    fun `a rejected auth audit insert rolls the token service's own mutation back`() {
        val principal = "auth-audit-rollback@example.com"

        val headBeforeMint = auditChainHead(dataSource)
        val tokensBefore = count("SELECT count(*) FROM proxy_token WHERE principal = '$principal'")
        rejectAction(ACTION_TOKEN_MINT)
        try {
            assertFails { mintUser(principal, "rolled-back") }
            assertEquals(
                tokensBefore, count("SELECT count(*) FROM proxy_token WHERE principal = '$principal'"),
                "a mint whose audit insert was rejected must leave no token behind",
            )
            assertHeadUnchanged(headBeforeMint)
        } finally {
            dropRejectTrigger()
        }

        val minted = mintUser(principal, "revoke-rollback")
        val headBeforeRevoke = auditChainHead(dataSource)
        rejectAction(ACTION_TOKEN_REVOKE)
        try {
            assertFails { service().revoke(principal, CALLER_ADDR, actor(principal), minted.id) }
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
    fun `validateToken audits failures but not successful validation`() {
        val before = countAuth()
        assertEquals(Status.Code.UNAUTHENTICATED, statusOf("not-a-token"))
        assertEquals(before + 1, countAuth())
        // The wire caller address rides ValidateTokenRequest and lands on the row, raw as decide stores it.
        assertEvent(
            PRINCIPAL_UNATTRIBUTED, ACTION_WIRE_VALIDATE, auditEntity("Token", "unresolved"), "FAILURE", "DENY",
            expectedRows = 1,
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
            grpc.validateToken(validateTokenRequest { token = valid.token; datasourceName = this@AuthAuditDbTest.datasourceName; clientAddr = CALLER_ADDR })
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
            runBlocking { grpc.validateToken(validateTokenRequest { this.token = token; datasourceName = this@AuthAuditDbTest.datasourceName; clientAddr = CALLER_ADDR }) }
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
        /** The caller address every call in this class presents — a documentation range, never a real host. */
        const val CALLER_ADDR = "203.0.113.7"
    }
}
