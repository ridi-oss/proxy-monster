package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
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
 * DB-backed lifecycle tests for [PrincipalSessionStore]: daemon round-trips, refresh-token
 * encryption at rest, the renewal-window boundary, and the liveness-sweep candidate set.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DaemonSessionStoreDbTest {
    private lateinit var ds: DataSource
    private lateinit var store: PrincipalSessionStore // PM_RESULT_KEY configured
    private lateinit var storeNoCrypto: PrincipalSessionStore // PM_RESULT_KEY unset

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_principal_session"))
        Flyway.configure().dataSource(ds).load().migrate()
        store = PrincipalSessionStore(ds, ResultCrypto(ByteArray(32) { it.toByte() }))
        storeNoCrypto = PrincipalSessionStore(ds, null)
    }

    @Test
    fun `create round-trips and encrypts the refresh token at rest`() {
        val row = store.create("alice@example.com", "dvc_1", "refresh-secret-abc", windowSeconds = 3600, ttlSeconds = 900).row
        assertEquals("alice@example.com", row.principal)
        assertEquals("dvc_1", row.handle)
        assertEquals(900L, row.ttlSeconds)
        assertEquals(LIVENESS_ACTIVE, row.livenessStatus)
        assertNotNull(row.refreshTokenEnc)
        assertEquals("refresh-secret-abc", store.decryptRefresh(row.refreshTokenEnc))

        // At rest, the ciphertext must NOT contain the plaintext refresh token.
        ds.connection.use { c ->
            c.prepareStatement("SELECT refresh_token_enc FROM principal_session WHERE id = ?").use { ps ->
                ps.setLong(1, row.id)
                ps.executeQuery().use { rs ->
                    rs.next()
                    val blob = rs.getBytes("refresh_token_enc").toString(Charsets.ISO_8859_1)
                    assertFalse(blob.contains("refresh-secret-abc"), "plaintext refresh token must not be stored at rest")
                }
            }
        }
    }

    @Test
    fun `no crypto configured means the refresh token is never persisted, not even plaintext`() {
        val row = storeNoCrypto.create("bob@example.com", "dvc_2", "should-never-be-stored", windowSeconds = 3600, ttlSeconds = 900).row
        assertNull(row.refreshTokenEnc)
        assertNull(storeNoCrypto.decryptRefresh(row.refreshTokenEnc))

        ds.connection.use { c ->
            c.prepareStatement("SELECT refresh_token_enc FROM principal_session WHERE id = ?").use { ps ->
                ps.setLong(1, row.id)
                ps.executeQuery().use { rs -> rs.next(); assertNull(rs.getBytes("refresh_token_enc")) }
            }
        }
    }

    @Test
    fun `no refresh token at all round-trips as null (device flow without offline_access)`() {
        val row = store.create("carol@example.com", "dvc_3", null, windowSeconds = 3600, ttlSeconds = 900).row
        assertNull(row.refreshTokenEnc)
        assertNull(store.decryptRefresh(row))
    }

    @Test
    fun `getByHandle finds the exact session`() {
        store.create("dave@example.com", "dvc_4", null, windowSeconds = 3600, ttlSeconds = 900)
        assertEquals("dave@example.com", store.getByHandle("dvc_4")!!.principal)
        assertNull(store.getByHandle("no-such-handle"))
    }

    @Test
    fun `getByPrincipal returns the most recent session`() {
        store.create("erin@example.com", "dvc_5a", null, windowSeconds = 3600, ttlSeconds = 900)
        val second = store.create("erin@example.com", "dvc_5b", null, windowSeconds = 3600, ttlSeconds = 900).row
        assertEquals(second.id, store.getByPrincipal("erin@example.com")!!.id)
    }

    @Test
    fun `withinWindow is true right after create and false once the window has passed`() {
        val row = store.create("frank@example.com", "dvc_6", null, windowSeconds = 3600, ttlSeconds = 900).row
        assertTrue(store.withinWindow("frank@example.com"))

        // Backdate the window directly — there's no real clock to fast-forward in a unit test.
        ds.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = ?").use { ps ->
                ps.setLong(1, row.id)
                ps.executeUpdate()
            }
        }
        assertFalse(store.withinWindow("frank@example.com"))
    }

    @Test
    fun `withinWindow is false, fail-closed, for a principal with no session at all`() {
        assertFalse(store.withinWindow("nobody@example.com"))
    }

    @Test
    fun `getByRenewalTokenHash resolves the session by the hashed bearer secret, and a wrong hash finds nothing`() {
        val created = store.create("nina@example.com", "dvc_14", null, windowSeconds = 3600, ttlSeconds = 900)
        assertTrue(created.renewalToken.startsWith("pmr_"))

        val expectedHash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(created.renewalToken.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val found = store.getByRenewalTokenHash(expectedHash)
        assertNotNull(found)
        assertEquals(created.row.id, found.id)
        assertEquals("nina@example.com", found.principal)

        assertNull(store.getByRenewalTokenHash("0".repeat(64)))
    }

    @Test
    fun `deactivateAllForPrincipal closes EVERY in-window session for the principal and marks them INACTIVE`() {
        // Two sessions for the same principal (two machines / re-logins) plus one for a bystander that
        // must be left untouched — the pull-deprovision-leaves-a-sibling regression.
        val a = store.create("oscar@example.com", "dvc_15a", null, windowSeconds = 3600, ttlSeconds = 900)
        val b = store.create("oscar@example.com", "dvc_15b", null, windowSeconds = 3600, ttlSeconds = 900)
        val bystander = store.create("peggy@example.com", "dvc_15c", null, windowSeconds = 3600, ttlSeconds = 900)
        assertTrue(store.withinWindow("oscar@example.com"))

        val closed = store.deactivateAllForPrincipal("oscar@example.com")
        assertEquals(2, closed, "both of the principal's in-window sessions must be closed, not just one")

        for (id in listOf(a.row.id, b.row.id)) {
            val updated = store.getById(id)!!
            assertEquals(LIVENESS_INACTIVE, updated.livenessStatus)
        }
        assertFalse(store.withinWindow("oscar@example.com"), "the principal has no in-window session left after deactivation")
        // A different principal's session is untouched.
        assertEquals(LIVENESS_ACTIVE, store.getById(bystander.row.id)!!.livenessStatus)
        assertTrue(store.withinWindow("peggy@example.com"))

        // Idempotent: a repeat call finds nothing still in-window to close.
        assertEquals(0, store.deactivateAllForPrincipal("oscar@example.com"))
    }

    @Test
    fun `daemon lookups stay isolated from web rows`() {
        val principal = "quinn@example.com"
        val daemon = store.create(principal, "dvc_web_guard", "daemon-refresh", windowSeconds = 3600, ttlSeconds = 900).row
        val webId = store.mintWeb(principal, "web-refresh", absoluteSeconds = 3600, idleSeconds = 900, deviceId = "daemon-test-device")

        assertEquals(daemon.id, store.getById(daemon.id)!!.id)
        assertNull(store.getById(webId), "a WEB row id must not resolve through the daemon mapper")
        val byPrincipal = store.getByPrincipal(principal)!!
        assertEquals(daemon.id, byPrincipal.id)
        assertEquals(900L, byPrincipal.ttlSeconds)
        assertTrue(store.withinWindow(principal))

        assertNotNull(store.resolveWeb(webId, "daemon-test-device"))

        store.endWeb(webId, ENDED_GROUP_REVOKED)
        assertEquals(ENDED_GROUP_REVOKED, store.webEndedReason(webId))

        val liveWeb = store.mintWeb(principal, "replacement-web-refresh", 3600, 900, "replacement-web-device")
        assertEquals(1, store.deactivateAllForPrincipal(principal), "daemon deactivation must touch only DAEMON rows")
        assertEquals(LIVENESS_INACTIVE, store.getById(daemon.id)!!.livenessStatus)
        assertNotNull(store.resolveWeb(liveWeb, "replacement-web-device"))
    }

    @Test
    fun `endAllWebForPrincipal ends only live web rows for one principal and is idempotent`() {
        val principal = "web-fanout@example.com"
        val endedBefore = store.mintWeb(principal, null, 3600, 900, "web-fanout-ended")
        store.endWeb(endedBefore, ENDED_SIGNED_OUT)
        val liveWeb = store.mintWeb(principal, null, 3600, 900, "web-fanout-live")
        val daemon = store.create(principal, "web-fanout-daemon", null, 3600, 900).row
        val bystander = store.mintWeb("web-fanout-bystander@example.com", null, 3600, 900, "web-fanout-bystander")

        val ended = ds.connection.use { c ->
            store.endAllWebForPrincipal(principal, ENDED_DEACTIVATED, c)
        }

        assertEquals(1, ended)
        assertEquals(ENDED_SIGNED_OUT, store.webEndedReason(endedBefore))
        assertEquals(ENDED_DEACTIVATED, store.webEndedReason(liveWeb))
        assertNull(store.resolveWeb(liveWeb, "web-fanout-live"))
        assertEquals(LIVENESS_ACTIVE, store.getById(daemon.id)!!.livenessStatus)
        assertNotNull(store.resolveWeb(bystander, "web-fanout-bystander"))
        assertEquals(0, ds.connection.use { c -> store.endAllWebForPrincipal(principal, ENDED_DEACTIVATED, c) })
    }

    @Test
    fun `withinWindow ignores a still-open WEB row once the daemon window has closed`() {
        val principal = "rita@example.com"
        val daemon = store.create(principal, "dvc_web_guard_2", null, windowSeconds = 3600, ttlSeconds = 900).row
        store.mintWeb(principal, null, absoluteSeconds = 3600, idleSeconds = 900, deviceId = "daemon-test-device") // in-window WEB row that must not rescue the daemon window
        ds.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = ?").use { ps ->
                ps.setLong(1, daemon.id)
                ps.executeUpdate()
            }
        }
        assertFalse(store.withinWindow(principal), "an in-window WEB row must not keep a closed daemon window open")
    }
}
