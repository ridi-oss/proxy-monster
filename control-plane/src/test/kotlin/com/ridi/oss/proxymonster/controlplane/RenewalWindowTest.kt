package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import com.ridi.oss.proxymonster.controlplane.support.RenewSessionResponse
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.seedDaemonLogin
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `POST /auth/session/renew` on cp-go (docs/auth-model.md "Session renewal"): authentication is by the
 * `Authorization: Bearer <renewalToken>` header ONLY — a request-body principal would let anyone who knows an
 * email mint that principal a wire token. Renewal is refused once the window has closed, for a deprovisioned
 * principal, and for a liveness-INACTIVE session.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RenewalWindowTest {
    private lateinit var ds: DataSource
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var policyStore: PolicyStore
    private lateinit var stack: CpGoStack
    private lateinit var admin: HttpClient
    private val adminPrincipal = "renewal-admin@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_renewal_window")
        ds = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(ds).load().migrate()
        daemonSessionStore = PrincipalSessionStore(ds, null)
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        userGroupStore = UserGroupStore(ds)
        policyStore = PolicyStore(ds)
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "test-secret", oidc = null, resultKey = null,
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        policyStore.createAssignment(RoleAssignmentInput(adminPrincipal, assertNotNull(policyStore.getRoleByName("system:admin")).id))
        stack = CpGoStack(config, ControlPlaneCore(ds), database) { routing { testLoginRoute(daemonSessionStore, config) } }
        admin = stack.client()
        runBlocking { admin.login(adminPrincipal) }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    private fun createUser(principal: String) {
        userGroupStore.createUser(AppUserInput(principal = principal), tokenStore, accessStore, daemonSessionStore)
    }

    /** The console's user edit, served by cp-go; `active=false` is the authoritative credential teardown. */
    private suspend fun setActive(principal: String, active: Boolean) {
        val id = ds.connection.use { c ->
            c.prepareStatement("SELECT id FROM app_user WHERE principal = ?").use { ps ->
                ps.setString(1, principal)
                ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getLong(1) }
            }
        }
        val res = admin.put("/api/users/$id") {
            contentType(ContentType.Application.Json)
            setBody("""{"principal":"$principal","active":$active}""")
        }
        assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())
    }

    private suspend fun HttpClient.renew(secret: String) = post("/auth/session/renew") { header("Authorization", "Bearer $secret") }

    @Test
    fun `renew with the correct bearer secret inside the window mints a fresh token`() = runBlocking<Unit> {
        val client = stack.client()
        val principal = "within@example.com"
        val created = ds.seedDaemonLogin(principal, "dvc_within")

        val resp = client.renew(created.renewalToken)
        assertEquals(HttpStatusCode.OK, resp.status)
        val body = MCP_TEST_JSON.decodeFromString<RenewSessionResponse>(resp.bodyAsText())
        assertTrue(body.token.isNotBlank())
        assertNotNull(tokenStore.validate(body.token))
        val audit = ds.connection.use { c ->
            c.prepareStatement("SELECT outcome, channel FROM audit_event WHERE kind='auth' AND action=? AND principal=?").use { ps ->
                ps.setString(1, AuthAuditRecorder.ACTION_SESSION_RENEW)
                ps.setString(2, principal)
                ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getString(1) to rs.getString(2) }
            }
        }
        assertEquals("SUCCESS" to AuthAuditRecorder.CHANNEL_PMON, audit)
    }

    @Test
    fun `a principal-only JSON body with no bearer is refused — the unauthenticated-renewal attack`() = runBlocking<Unit> {
        val client = stack.client()
        val principal = "public-principal@example.com"
        ds.seedDaemonLogin(principal, "dvc_public")

        val resp = client.post("/auth/session/renew") {
            contentType(ContentType.Application.Json)
            setBody("""{"principal":"$principal"}""")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `a wrong or garbage bearer secret is refused`() = runBlocking<Unit> {
        val client = stack.client()
        ds.seedDaemonLogin("garbage-bearer@example.com", "dvc_garbage")

        assertEquals(HttpStatusCode.Unauthorized, client.renew("pmr_not-the-real-secret").status)
    }

    @Test
    fun `missing Authorization header entirely is refused`() = runBlocking<Unit> {
        val client = stack.client()

        val resp = client.post("/auth/session/renew") { }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `renew after the window closed is refused even with the correct secret`() = runBlocking<Unit> {
        val client = stack.client()
        val created = ds.seedDaemonLogin("after@example.com", "dvc_after")
        ds.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = ?").use { ps ->
                ps.setLong(1, created.id)
                ps.executeUpdate()
            }
        }

        assertEquals(HttpStatusCode.Unauthorized, client.renew(created.renewalToken).status)
    }

    @Test
    fun `renew for a deprovisioned principal is refused even inside the window`() = runBlocking<Unit> {
        val client = stack.client()
        val principal = "deprovisioned@example.com"
        createUser(principal)
        userGroupStore.setUserActive(principal, false)
        val created = ds.seedDaemonLogin(principal, "dvc_deprov")

        assertEquals(HttpStatusCode.Unauthorized, client.renew(created.renewalToken).status)
    }

    @Test
    fun `renew for a liveness-INACTIVE session is refused even inside the window`() = runBlocking<Unit> {
        val client = stack.client()
        val created = ds.seedDaemonLogin("inactive-liveness@example.com", "dvc_inactive")
        ds.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET liveness_status = 'INACTIVE', last_idp_check_at = now() WHERE id = ?").use { ps ->
                ps.setLong(1, created.id)
                ps.executeUpdate()
            }
        }

        assertEquals(HttpStatusCode.Unauthorized, client.renew(created.renewalToken).status)
    }

    @Test
    fun `authoritative principal deprovision refuses renewal on every sibling session`() = runBlocking<Unit> {
        val client = stack.client()
        val principal = "two-daemons@example.com"
        createUser(principal)
        ds.seedDaemonLogin(principal, "dvc_sibling_a")
        val sibling = ds.seedDaemonLogin(principal, "dvc_sibling_b")

        assertEquals(HttpStatusCode.OK, client.renew(sibling.renewalToken).status)

        setActive(principal, false)

        assertEquals(HttpStatusCode.Unauthorized, client.renew(sibling.renewalToken).status, "a sibling session must not survive the principal's deprovision")
    }

    @Test
    fun `a deprovision-then-reactivate cannot resurrect the old renewal secret (window stays closed)`() = runBlocking<Unit> {
        val client = stack.client()
        val principal = "resurrect@example.com"
        createUser(principal)
        val created = ds.seedDaemonLogin(principal, "dvc_resurrect")

        setActive(principal, false)
        assertEquals(HttpStatusCode.Unauthorized, client.renew(created.renewalToken).status, "renew is refused while deprovisioned")

        // Deprovision is durable because the window was closed, not merely paused behind the deactivated flag.
        setActive(principal, true)
        assertEquals(
            HttpStatusCode.Unauthorized, client.renew(created.renewalToken).status,
            "reactivation must not resurrect the pre-deprovision renewal secret",
        )
    }

    @Test
    fun `renew mints under the lock, so an immediately-following teardown sweeps up the just-minted token`() = runBlocking<Unit> {
        val client = stack.client()
        val principal = "mint-then-revoke@example.com"
        createUser(principal)
        val created = ds.seedDaemonLogin(principal, "dvc_mint_then_revoke")

        val resp = client.renew(created.renewalToken)
        assertEquals(HttpStatusCode.OK, resp.status)
        val minted = MCP_TEST_JSON.decodeFromString<RenewSessionResponse>(resp.bodyAsText())
        assertNotNull(tokenStore.validate(minted.token), "sanity: the freshly-minted token validates")

        setActive(principal, false)
        assertNull(tokenStore.validate(minted.token), "a teardown immediately following renew must revoke the just-minted token")

        assertEquals(HttpStatusCode.Unauthorized, client.renew(created.renewalToken).status, "renew after the teardown must be refused (closed window)")
    }

    @Test
    fun `a renew blocks behind a concurrent holder of the SAME principal's advisory lock, then observes its committed state`() = runBlocking<Unit> {
        val client = stack.client()
        val principal = "lock-interleave@example.com"
        val created = ds.seedDaemonLogin(principal, "dvc_lock_interleave")

        // A second connection holds the principal's lock mid-teardown; renew must wait for its commit.
        val holder = ds.connection
        holder.autoCommit = false
        holder.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
            ps.setString(1, principal); ps.executeQuery().use { it.next() }
        }
        holder.prepareStatement(
            "UPDATE principal_session SET liveness_status = 'INACTIVE', absolute_expires_at = now() WHERE id = ?",
        ).use { ps -> ps.setLong(1, created.id); ps.executeUpdate() }

        try {
            coroutineScope {
                val renewDeferred = async(Dispatchers.IO) { client.renew(created.renewalToken).status }
                delay(300)
                assertFalse(renewDeferred.isCompleted, "renew must block behind the held advisory lock, not race ahead of the holder")

                holder.commit()

                val status = withTimeout(5_000) { renewDeferred.await() }
                assertEquals(
                    HttpStatusCode.Unauthorized, status,
                    "once the lock releases, renew must observe the holder's committed INACTIVE state, not a stale pre-lock snapshot",
                )
            }
        } finally {
            holder.close()
        }
    }
}
