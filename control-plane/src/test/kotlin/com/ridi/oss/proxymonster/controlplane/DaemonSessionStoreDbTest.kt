package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.daemonLiveness
import com.ridi.oss.proxymonster.controlplane.support.daemonWithinWindow
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.seedDaemonSession
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

/** DB-backed tests for the daemon teardowns [PrincipalSessionStore] still runs, and their isolation from web rows. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DaemonSessionStoreDbTest {
    private lateinit var ds: DataSource
    private lateinit var store: PrincipalSessionStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_principal_session"))
        Flyway.configure().dataSource(ds).load().migrate()
        store = PrincipalSessionStore(ds, ResultCrypto(ByteArray(32) { it.toByte() }))
    }

    @Test
    fun `deactivateAllForPrincipal closes EVERY in-window session for the principal and marks them INACTIVE`() {
        // Two sessions for the same principal (two machines / re-logins) plus one for a bystander that
        // must be left untouched — the pull-deprovision-leaves-a-sibling regression.
        val a = ds.seedDaemonSession("oscar@example.com")
        val b = ds.seedDaemonSession("oscar@example.com")
        val bystander = ds.seedDaemonSession("peggy@example.com")
        assertTrue(ds.daemonWithinWindow("oscar@example.com"))

        val closed = store.deactivateAllForPrincipal("oscar@example.com")
        assertEquals(2, closed, "both of the principal's in-window sessions must be closed, not just one")

        for (id in listOf(a, b)) {
            assertEquals(LIVENESS_INACTIVE, ds.daemonLiveness(id))
        }
        assertFalse(ds.daemonWithinWindow("oscar@example.com"), "the principal has no in-window session left after deactivation")
        // A different principal's session is untouched.
        assertEquals(LIVENESS_ACTIVE, ds.daemonLiveness(bystander))
        assertTrue(ds.daemonWithinWindow("peggy@example.com"))

        // Idempotent: a repeat call finds nothing still in-window to close.
        assertEquals(0, store.deactivateAllForPrincipal("oscar@example.com"))
    }

    @Test
    fun `daemon deactivation stays isolated from web rows`() {
        val principal = "quinn@example.com"
        val daemon = ds.seedDaemonSession(principal)
        val webId = store.mintWeb(principal, "web-refresh", absoluteSeconds = 3600, idleSeconds = 900, deviceId = "daemon-test-device")
        assertTrue(ds.daemonWithinWindow(principal))

        assertNotNull(store.resolveWeb(webId, "daemon-test-device"))

        store.endWeb(webId, ENDED_GROUP_REVOKED)
        assertEquals(ENDED_GROUP_REVOKED, store.webEndedReason(webId))

        val liveWeb = store.mintWeb(principal, "replacement-web-refresh", 3600, 900, "replacement-web-device")
        assertEquals(1, store.deactivateAllForPrincipal(principal), "daemon deactivation must touch only DAEMON rows")
        assertEquals(LIVENESS_INACTIVE, ds.daemonLiveness(daemon))
        assertNotNull(store.resolveWeb(liveWeb, "replacement-web-device"))
    }

    @Test
    fun `endAllWebForPrincipal ends only live web rows for one principal and is idempotent`() {
        val principal = "web-fanout@example.com"
        val endedBefore = store.mintWeb(principal, null, 3600, 900, "web-fanout-ended")
        store.endWeb(endedBefore, ENDED_SIGNED_OUT)
        val liveWeb = store.mintWeb(principal, null, 3600, 900, "web-fanout-live")
        val daemon = ds.seedDaemonSession(principal)
        val bystander = store.mintWeb("web-fanout-bystander@example.com", null, 3600, 900, "web-fanout-bystander")

        val ended = ds.connection.use { c ->
            store.endAllWebForPrincipal(principal, ENDED_DEACTIVATED, c)
        }

        assertEquals(1, ended)
        assertEquals(ENDED_SIGNED_OUT, store.webEndedReason(endedBefore))
        assertEquals(ENDED_DEACTIVATED, store.webEndedReason(liveWeb))
        assertNull(store.resolveWeb(liveWeb, "web-fanout-live"))
        assertEquals(LIVENESS_ACTIVE, ds.daemonLiveness(daemon))
        assertNotNull(store.resolveWeb(bystander, "web-fanout-bystander"))
        assertEquals(0, ds.connection.use { c -> store.endAllWebForPrincipal(principal, ENDED_DEACTIVATED, c) })
    }
}
