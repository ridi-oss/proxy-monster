package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
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
 * Route-level coverage of `POST /auth/session/renew` (docs/auth-model.md "Session renewal"):
 * authentication is by the `Authorization: Bearer <renewalToken>` header ONLY (no request-body
 * identity — that was the unauthenticated-renewal flaw: anyone who knew a principal's email could
 * mint them a fresh wire token). Also covers refusal (401) once the window has closed, for a
 * deprovisioned principal, and for a liveness-INACTIVE session — the deprovisioning invariant
 * holds on the renewal path, not just at initial login.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RenewalWindowTest {
    private lateinit var ds: DataSource
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var config: Config

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_renewal_window"))
        Flyway.configure().dataSource(ds).load().migrate()
        daemonSessionStore = PrincipalSessionStore(ds, null)
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        userGroupStore = UserGroupStore(ds)
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "test-secret", oidc = null, resultKey = null,
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
    }

    /** Stand up just the renewal route. IdP revalidation is timer-owned and absent from this request path. */
    private fun ApplicationTestBuilder.installRenewRoute() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            sessionRenewRoutes(config, daemonSessionStore, tokenStore, userGroupStore, AuthAuditRecorder(AuditStore(ds)))
        }
    }

    @Test
    fun `renew with the correct bearer secret inside the window mints a fresh token`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "within@example.com"
        val created = daemonSessionStore.create(principal, "dvc_within", null, windowSeconds = 3600, ttlSeconds = 900)

        val resp = client.post("/auth/session/renew") {
            header("Authorization", "Bearer ${created.renewalToken}")
        }
        assertEquals(HttpStatusCode.OK, resp.status)
        val body: RenewSessionResponse = resp.body()
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
    fun `a principal-only JSON body with no bearer is refused — the unauthenticated-renewal attack`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "public-principal@example.com"
        daemonSessionStore.create(principal, "dvc_public", null, windowSeconds = 3600, ttlSeconds = 900)

        // The vulnerable request shape: knowledge of the principal string alone.
        val resp = client.post("/auth/session/renew") {
            contentType(ContentType.Application.Json)
            setBody("""{"principal":"$principal"}""")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `a wrong or garbage bearer secret is refused`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "garbage-bearer@example.com"
        daemonSessionStore.create(principal, "dvc_garbage", null, windowSeconds = 3600, ttlSeconds = 900)

        val resp = client.post("/auth/session/renew") {
            header("Authorization", "Bearer pmr_not-the-real-secret")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `missing Authorization header entirely is refused`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }

        val resp = client.post("/auth/session/renew") { }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `renew after the window closed is refused even with the correct secret`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "after@example.com"
        val created = daemonSessionStore.create(principal, "dvc_after", null, windowSeconds = 3600, ttlSeconds = 900)
        ds.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = ?").use { ps ->
                ps.setLong(1, created.row.id)
                ps.executeUpdate()
            }
        }

        val resp = client.post("/auth/session/renew") {
            header("Authorization", "Bearer ${created.renewalToken}")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `renew for a deprovisioned principal is refused even inside the window`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "deprovisioned@example.com"
        userGroupStore.createUser(AppUserInput(principal = principal), tokenStore, accessStore, daemonSessionStore)
        userGroupStore.setUserActive(principal, false)
        val created = daemonSessionStore.create(principal, "dvc_deprov", null, windowSeconds = 3600, ttlSeconds = 900)

        val resp = client.post("/auth/session/renew") {
            header("Authorization", "Bearer ${created.renewalToken}")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `renew for a liveness-INACTIVE session is refused even inside the window`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "inactive-liveness@example.com"
        val created = daemonSessionStore.create(principal, "dvc_inactive", null, windowSeconds = 3600, ttlSeconds = 900)
        daemonSessionStore.markCheck(created.row.id, LIVENESS_INACTIVE)

        val resp = client.post("/auth/session/renew") {
            header("Authorization", "Bearer ${created.renewalToken}")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `authoritative principal deprovision refuses renewal on every sibling session`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "two-daemons@example.com"
        // Two live sessions for one principal. An authoritative directory or local-admin teardown
        // closes every renewal window; refresh-token invalid_grant remains deliberately per-session.
        daemonSessionStore.create(principal, "dvc_sibling_a", null, windowSeconds = 3600, ttlSeconds = 900)
        val sibling = daemonSessionStore.create(principal, "dvc_sibling_b", null, windowSeconds = 3600, ttlSeconds = 900)

        // Sanity: the sibling can renew before the deprovision.
        assertEquals(
            HttpStatusCode.OK,
            client.post("/auth/session/renew") { header("Authorization", "Bearer ${sibling.renewalToken}") }.status,
        )

        daemonSessionStore.deactivateAllForPrincipal(principal)

        val resp = client.post("/auth/session/renew") {
            header("Authorization", "Bearer ${sibling.renewalToken}")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status, "a sibling session must not survive the principal's deprovision")
    }

    @Test
    fun `a deprovision-then-reactivate cannot resurrect the old renewal secret (window stays closed)`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "resurrect@example.com"
        userGroupStore.createUser(AppUserInput(principal = principal), tokenStore, accessStore, daemonSessionStore)
        val created = daemonSessionStore.create(principal, "dvc_resurrect", null, windowSeconds = 3600, ttlSeconds = 900)

        // SCIM active=false: setUserActive(false) + revokeActiveCredentials (-> deactivateAllForPrincipal).
        userGroupStore.setUserActive(principal, false)
        daemonSessionStore.deactivateAllForPrincipal(principal)
        assertEquals(
            HttpStatusCode.Unauthorized,
            client.post("/auth/session/renew") { header("Authorization", "Bearer ${created.renewalToken}") }.status,
            "renew is refused while deprovisioned",
        )

        // SCIM active=true again (a reactivation inside the original window). The renewal secret must
        // NOT come back to life — the daemon must re-run device-auth. Deprovision is durable because
        // the session window was closed, not merely paused behind the isDeactivated flag.
        userGroupStore.setUserActive(principal, true)
        val resp = client.post("/auth/session/renew") {
            header("Authorization", "Bearer ${created.renewalToken}")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status, "reactivation must not resurrect the pre-deprovision renewal secret")
    }

    @Test
    fun `renew mints under the lock, so an immediately-following teardown sweeps up the just-minted token`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "mint-then-revoke@example.com"
        val created = daemonSessionStore.create(principal, "dvc_mint_then_revoke", null, windowSeconds = 3600, ttlSeconds = 900)

        val resp = client.post("/auth/session/renew") { header("Authorization", "Bearer ${created.renewalToken}") }
        assertEquals(HttpStatusCode.OK, resp.status)
        val minted: RenewSessionResponse = resp.body()
        assertNotNull(tokenStore.validate(minted.token), "sanity: the freshly-minted token validates")

        // Simulate teardown landing immediately after renew's mint committed. Mint and teardown use
        // the same principal lock, so a teardown run right after must sweep up the
        // just-minted token, not race ahead of/miss it.
        revokeActiveCredentials(principal, tokenStore, accessStore, daemonSessionStore)
        assertNull(tokenStore.validate(minted.token), "a teardown immediately following renew must revoke the just-minted token")

        // The window is now closed too — a second renew attempt on the SAME renewal secret is refused.
        val resp2 = client.post("/auth/session/renew") { header("Authorization", "Bearer ${created.renewalToken}") }
        assertEquals(HttpStatusCode.Unauthorized, resp2.status, "renew after the teardown must be refused (closed window)")
    }

    @Test
    fun `a renew blocks behind a concurrent holder of the SAME principal's advisory lock, then observes its committed state`() = testApplication {
        installRenewRoute()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }
        val principal = "lock-interleave@example.com"
        val created = daemonSessionStore.create(principal, "dvc_lock_interleave", null, windowSeconds = 3600, ttlSeconds = 900)

        // Hold the SAME per-principal advisory lock open on a second, independent connection —
        // standing in for a concurrent teardown mid-transaction. A renew attempted while it's held
        // must BLOCK (not race ahead and mint against state the holder is about to invalidate), and
        // only proceed once the holder releases the lock (by committing).
        val holder = ds.connection
        holder.autoCommit = false
        holder.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
            ps.setString(1, principal); ps.executeQuery().use { it.next() }
        }
        holder.prepareStatement(
            "UPDATE principal_session SET liveness_status = 'INACTIVE', absolute_expires_at = now() WHERE id = ?",
        ).use { ps -> ps.setLong(1, created.row.id); ps.executeUpdate() }

        try {
            coroutineScope {
                val renewDeferred = async(Dispatchers.IO) {
                    client.post("/auth/session/renew") { header("Authorization", "Bearer ${created.renewalToken}") }.status
                }
                // Give the renew request time to reach and block on the (still-held) advisory lock.
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

    @Test
    fun `revokeActiveCredentials itself blocks behind a concurrent holder of the SAME principal's advisory lock`() {
        // The OTHER half of the shared-lock contract: not just renew, but the TEARDOWN
        // (revokeActiveCredentials — the periodic sweep / SCIM deactivate path) must take the same
        // per-principal advisory lock, so a renew and a sweep for one principal can never interleave.
        // A broken teardown that dropped the advisory lock while still revoking sequentially would pass
        // the renew-side lock test above yet reopen the renew-vs-sweep race — so assert the teardown
        // BLOCKS while a concurrent holder of the same lock is mid-transaction, and only proceeds on release.
        val principal = "revoke-serializes@example.com"
        val token = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = 3600)

        val holder = ds.connection
        holder.autoCommit = false
        holder.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
            ps.setString(1, principal); ps.executeQuery().use { it.next() }
        }
        try {
            runBlocking {
                coroutineScope {
                    val revokeDeferred = async(Dispatchers.IO) {
                        revokeActiveCredentials(principal, tokenStore, accessStore, daemonSessionStore)
                    }
                    delay(300)
                    assertFalse(revokeDeferred.isCompleted, "revokeActiveCredentials must block behind the held advisory lock, not revoke ahead of the holder")
                    assertNull(tokenStore.get(token.id)!!.revokedAt, "the token must still be live while the teardown is blocked on the lock")

                    holder.commit() // release the advisory lock

                    val revoked = withTimeout(5_000) { revokeDeferred.await() }
                    assertTrue(revoked >= 1, "once the lock releases, the teardown proceeds and revokes at least the token")
                    assertNotNull(tokenStore.get(token.id)!!.revokedAt, "the token must be revoked after the teardown completes")
                }
            }
        } finally {
            holder.close()
        }
    }
}
