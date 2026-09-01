package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Duration
import java.time.Instant
import javax.sql.DataSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PrincipalSessionStoreDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var store: PrincipalSessionStore
    private lateinit var noCryptoStore: PrincipalSessionStore
    private val key = ByteArray(32) { it.toByte() }

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_principal_session"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        store = PrincipalSessionStore(dataSource, ResultCrypto(key))
        noCryptoStore = PrincipalSessionStore(dataSource, null)
    }

    @Test
    fun `web session lifecycle separates validation from idle touch without moving the absolute cap`() {
        val before = Instant.now()
        val id = store.mintWeb(
            "web@example.com",
            "refresh-secret",
            absoluteSeconds = 7200,
            idleSeconds = 900,
            deviceId = "device-a",
        )
        val minted = snapshot(id)
        assertTrue(minted.absoluteExpiresAt.isAfter(before.plusSeconds(7190)))
        assertTrue(Duration.between(minted.createdAt, minted.absoluteExpiresAt).seconds in 7199..7201)
        assertTrue(Duration.between(minted.createdAt, minted.idleExpiresAt).seconds in 899..901)
        assertNull(minted.lastSeenAt)
        assertEquals("device-a", minted.deviceId)

        dataSource.connection.use { c ->
            c.prepareStatement(
                """SELECT kind, handle, ttl_seconds, renewal_token_hash, liveness_status, refresh_token_enc
                   FROM principal_session WHERE id = ?""",
            ).use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next())
                    assertEquals("WEB", rs.getString("kind"))
                    assertNull(rs.getString("handle"))
                    assertNull(rs.getObject("ttl_seconds"))
                    assertNull(rs.getString("renewal_token_hash"))
                    assertEquals(LIVENESS_ACTIVE, rs.getString("liveness_status"))
                    val encrypted = assertNotNull(rs.getBytes("refresh_token_enc"))
                    assertFalse(encrypted.contentEquals("refresh-secret".toByteArray()))
                    assertContentEquals("refresh-secret".toByteArray(), ResultCrypto(key).decrypt(encrypted))
                }
            }
        }

        val first = assertNotNull(store.resolveWeb(id, "device-a"))
        val afterFirst = snapshot(id)
        assertEquals("web@example.com", first.principal)
        assertEquals(minted.idleExpiresAt, first.idleExpiresAt)
        assertEquals(minted.idleExpiresAt, afterFirst.idleExpiresAt)
        assertEquals(minted.absoluteExpiresAt, first.absoluteExpiresAt)
        assertEquals(minted.absoluteExpiresAt, afterFirst.absoluteExpiresAt)
        assertNull(afterFirst.lastSeenAt)

        val second = assertNotNull(store.resolveWeb(id, "device-a"))
        val afterSecond = snapshot(id)
        assertEquals(minted.idleExpiresAt, second.idleExpiresAt)
        assertEquals(minted.idleExpiresAt, afterSecond.idleExpiresAt)
        assertNull(afterSecond.lastSeenAt)
        assertEquals(minted.absoluteExpiresAt, afterSecond.absoluteExpiresAt)

        val firstTouch = assertNotNull(store.touchWeb(id, "device-a"))
        val afterFirstTouch = snapshot(id)
        assertTrue(afterFirstTouch.idleExpiresAt.isAfter(minted.idleExpiresAt))
        assertEquals(afterFirstTouch.idleExpiresAt, firstTouch.idleExpiresAt)
        assertNotNull(afterFirstTouch.lastSeenAt)
        assertEquals(minted.absoluteExpiresAt, afterFirstTouch.absoluteExpiresAt)

        val throttledTouch = assertNotNull(store.touchWeb(id, "device-a"))
        val afterThrottledTouch = snapshot(id)
        assertEquals(afterFirstTouch.idleExpiresAt, throttledTouch.idleExpiresAt)
        assertEquals(afterFirstTouch.idleExpiresAt, afterThrottledTouch.idleExpiresAt)
        assertEquals(afterFirstTouch.lastSeenAt, afterThrottledTouch.lastSeenAt)

        dataSource.connection.use { c ->
            c.prepareStatement(
                """UPDATE principal_session
                   SET last_seen_at = now() - interval '3 minutes',
                       idle_expires_at = idle_expires_at - interval '3 minutes'
                   WHERE id = ?""",
            ).use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        val backdated = snapshot(id)
        val slid = assertNotNull(store.touchWeb(id, "device-a"))
        val afterSlide = snapshot(id)
        assertTrue(afterSlide.idleExpiresAt.isAfter(backdated.idleExpiresAt))
        assertEquals(afterSlide.idleExpiresAt, slid.idleExpiresAt)
        assertEquals(minted.absoluteExpiresAt, slid.absoluteExpiresAt)
        assertEquals(minted.absoluteExpiresAt, afterSlide.absoluteExpiresAt)

        assertTrue(store.endWeb(id, ENDED_SIGNED_OUT))
        assertNull(store.resolveWeb(id, "device-a"))
        assertFalse(store.endWeb(id, ENDED_SIGNED_OUT))
        val ended = snapshot(id)
        assertNotNull(ended.endedAt)
        assertEquals(ENDED_SIGNED_OUT, ended.endedReason)
        assertEquals(LIVENESS_INACTIVE, ended.livenessStatus)
    }

    @Test
    fun `newest web session displaces only same-principal web siblings`() {
        val principal = "displaced@example.com"
        val daemonA = store.create(principal, "displace-daemon-a", null, 7200, 600).row
        val daemonB = store.create(principal, "displace-daemon-b", null, 7200, 600).row
        val bystander = store.mintWeb(
            "bystander@example.com",
            null,
            absoluteSeconds = 7200,
            idleSeconds = 900,
            deviceId = "bystander-device",
        )
        val first = store.mintWeb(principal, null, 7200, 900, "first-device")
        val second = store.mintWeb(principal, null, 7200, 900, "second-device")

        val displaced = snapshot(first)
        assertNotNull(displaced.endedAt)
        assertEquals(ENDED_DISPLACED, displaced.endedReason)
        assertEquals(LIVENESS_INACTIVE, displaced.livenessStatus)
        assertNull(store.resolveWeb(first, "first-device"))
        assertEquals(principal, assertNotNull(store.resolveWeb(second, "second-device")).principal)
        assertEquals("bystander@example.com", assertNotNull(store.resolveWeb(bystander, "bystander-device")).principal)

        for (daemon in listOf(daemonA, daemonB)) {
            val unchanged = assertNotNull(store.getById(daemon.id))
            assertEquals(LIVENESS_ACTIVE, unchanged.livenessStatus)
            assertTrue(unchanged.sessionExpiresAt.isAfter(Instant.now()))
        }
        assertTrue(store.withinWindow(principal))
    }

    @Test
    fun `the session-end seam invokes the editor-cleanup callback on every ending path`() {
        // The onWebSessionEnded hook (App.kt wires it to drop a principal's saved editor results) must fire on
        // EVERY web-session ending: single logout (endWeb), newest-wins displacement (mintWeb), and the
        // deprovision / group-revocation bulk end (endAllWebForPrincipal) — not just endWeb in isolation.
        val ended = mutableListOf<String>()
        val hooked = PrincipalSessionStore(dataSource, ResultCrypto(key), onWebSessionEnded = { p, _ -> ended += p })

        val alice = "hook-alice@example.com"
        hooked.mintWeb(alice, null, 7200, 900, "device-1")
        assertTrue(ended.isEmpty(), "a first login displaces nothing → no cleanup fires")

        // Newest-wins: a second login for the same principal displaces the first → the seam fires once.
        hooked.mintWeb(alice, null, 7200, 900, "device-2")
        assertEquals(listOf(alice), ended, "newest-wins displacement routes through the cleanup seam")

        ended.clear()
        val survivor = liveWebId(alice)
        assertTrue(hooked.endWeb(survivor, ENDED_SIGNED_OUT))
        assertEquals(listOf(alice), ended, "explicit logout fires the seam")
        ended.clear()
        assertFalse(hooked.endWeb(survivor, ENDED_SIGNED_OUT), "an already-ended row transitions nothing")
        assertTrue(ended.isEmpty(), "a no-op end fires nothing")

        val bob = "hook-bob@example.com"
        hooked.mintWeb(bob, null, 7200, 900, "device-b1")
        ended.clear()
        assertEquals(1, hooked.endAllWebForPrincipal(bob, ENDED_DEACTIVATED))
        assertEquals(listOf(bob), ended, "deprovision / group-revocation bulk end routes through the cleanup seam")
        ended.clear()
        assertEquals(0, hooked.endAllWebForPrincipal(bob, ENDED_DEACTIVATED))
        assertTrue(ended.isEmpty(), "a no-op bulk end fires nothing")
    }

    @Test
    fun `deprovision-composed cleanup rolls back with an aborted teardown transaction`() {
        // Deprovision ends web sessions AND revokes tokens/grants in ONE transaction (revokeActiveCredentialsTx).
        // The editor-result cleanup must join THAT transaction — via the caller-supplied connection — so a later
        // statement that aborts the teardown reverts the deletion too. A separate auto-commit delete would
        // survive the rollback and orphan a still-live session's tabs. This wires the real App-side callback
        // (deleteEditorResultsForPrincipal on the passed connection) and drives it through inTx.
        val resultStore = QueryResultStore(dataSource, ResultCrypto(key))
        val accessStore = AccessStore(dataSource)
        val dsId = DatasourceStore(dataSource).create(
            DatasourceInput(name = "ds-teardown", engine = "postgres", host = "h", port = 5432, dbName = "d"),
        ).id
        val composed = PrincipalSessionStore(
            dataSource, ResultCrypto(key),
            onWebSessionEnded = { p, conn -> resultStore.deleteEditorResultsForPrincipal(p, conn) },
        )
        val principal = "teardown@example.com"
        composed.mintWeb(principal, null, 7200, 900, "device-t")
        val task = accessStore.createEditorTask(principal, dsId, listOf("select 1"), listOf("analyst"), principal)
        resultStore.startNextRun(task.id, principal)
        resultStore.completeRun(task.id, DecryptedResult(listOf("c"), listOf(listOf("1"))), 3600)
        assertEquals(1, editorChildCount(principal), "seeded one editor result child")

        // Teardown aborts AFTER ending the session + composing the delete → inTx rolls the whole thing back.
        val aborted = runCatching {
            dataSource.inTx { c ->
                composed.endAllWebForPrincipal(principal, ENDED_DEACTIVATED, c)
                throw IllegalStateException("simulate a later teardown statement failing")
            }
        }
        assertTrue(aborted.isFailure, "the teardown transaction aborted")
        assertEquals(1, editorChildCount(principal), "rolled-back teardown must NOT orphan a committed delete")
        assertEquals(1, liveWebRowCount(principal), "the session the rollback keeps alive still has its tabs")

        // Committed teardown drops both the session and its editor results atomically.
        dataSource.inTx { c -> composed.endAllWebForPrincipal(principal, ENDED_DEACTIVATED, c) }
        assertEquals(0, editorChildCount(principal), "a committed teardown removes the editor results")
        assertEquals(0, liveWebRowCount(principal), "and ends the session")
    }

    private fun editorChildCount(principal: String): Int = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT count(*) FROM query_result WHERE task_id IN " +
                "(SELECT id FROM access_request WHERE creator_kind = 'EDITOR' AND principal = ?)",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    @Test
    fun `device mismatch ends a live web row permanently without sliding idle`() {
        val id = store.mintWeb(
            "bound@example.com",
            null,
            absoluteSeconds = 7200,
            idleSeconds = 900,
            deviceId = "correct-device",
        )
        assertNotNull(store.resolveWeb(id, "correct-device"))
        dataSource.connection.use { c ->
            c.prepareStatement(
                """UPDATE principal_session
                   SET last_seen_at = now() - interval '3 minutes', idle_expires_at = now() + interval '5 minutes'
                   WHERE id = ?""",
            ).use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        val idleBeforeMismatch = snapshot(id).idleExpiresAt

        assertNull(store.resolveWeb(id, "wrong-device"))
        val mismatched = snapshot(id)
        assertEquals(idleBeforeMismatch, mismatched.idleExpiresAt, "a mismatched request must not extend the idle clock")
        assertEquals(ENDED_DEVICE_BIND_MISMATCH, mismatched.endedReason)
        assertEquals(LIVENESS_INACTIVE, mismatched.livenessStatus)
        assertNull(store.resolveWeb(id, "correct-device"), "a correctly-bound replay cannot resurrect an ended row")

        val legacy = store.mintWeb(
            "legacy-bound@example.com",
            null,
            absoluteSeconds = 7200,
            idleSeconds = 900,
            deviceId = "legacy-device",
        )
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET device_id = NULL WHERE id = ?").use { ps ->
                ps.setLong(1, legacy)
                ps.executeUpdate()
            }
        }
        assertNull(store.resolveWeb(legacy, "legacy-device"))
        assertEquals(ENDED_DEVICE_BIND_MISMATCH, snapshot(legacy).endedReason)

        // A live, correctly-bound row presented with NO device id (null) must be rejected and ended, not
        // resolved: a stolen pm_session replayed without a pm_did is exactly what device-binding defends
        // against, so an absent device can never be treated as a wildcard match.
        val absent = store.mintWeb(
            "absent-device@example.com",
            null,
            absoluteSeconds = 7200,
            idleSeconds = 900,
            deviceId = "present-device",
        )
        assertNull(store.resolveWeb(absent, null), "a live bound row presented with no device id must never resolve")
        assertEquals(ENDED_DEVICE_BIND_MISMATCH, snapshot(absent).endedReason)
    }

    @Test
    fun `resolve web requires both live clocks and excludes daemon rows`() {
        val daemon = store.create("daemon@example.com", "handle", null, 7200, 600)
        assertNull(store.resolveWeb(daemon.row.id, "device-a"))

        val idleExpired = store.mintWeb(
            "idle-expired@example.com",
            null,
            absoluteSeconds = 7200,
            idleSeconds = 900,
            deviceId = "idle-device",
        )
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = ?").use { ps ->
                ps.setLong(1, idleExpired)
                ps.executeUpdate()
            }
        }
        val expiredIdleDeadline = snapshot(idleExpired).idleExpiresAt
        assertNull(store.resolveWeb(idleExpired, "idle-device"))
        assertEquals(expiredIdleDeadline, snapshot(idleExpired).idleExpiresAt, "an expired idle clock must never slide back to life")

        val absoluteExpired = store.mintWeb(
            "absolute-expired@example.com",
            null,
            absoluteSeconds = 7200,
            idleSeconds = 900,
            deviceId = "absolute-device",
        )
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = ?").use { ps ->
                ps.setLong(1, absoluteExpired)
                ps.executeUpdate()
            }
        }
        val liveIdleDeadline = snapshot(absoluteExpired).idleExpiresAt
        assertNull(store.resolveWeb(absoluteExpired, "absolute-device"))
        assertEquals(liveIdleDeadline, snapshot(absoluteExpired).idleExpiresAt, "an expired absolute clock must never slide idle")
    }

    @Test
    fun `web ended reason is returned only for web rows`() {
        val webId = store.mintWeb(
            "reason@example.com",
            null,
            absoluteSeconds = 7200,
            idleSeconds = 900,
            deviceId = "reason-device",
        )
        assertTrue(store.endWeb(webId, ENDED_SIGNED_OUT))
        assertEquals(ENDED_SIGNED_OUT, store.webEndedReason(webId))

        val daemonId = store.create("reason-daemon@example.com", "reason-daemon", null, 7200, 600).row.id
        assertNull(store.webEndedReason(daemonId))
        assertNull(store.webEndedReason(-1))
    }

    @Test
    fun `web mint waits for the principal lock and leaves exactly one active web row`() {
        val principal = "serialized-mint@example.com"
        val first = store.mintWeb(principal, null, 7200, 900, "serialized-first")
        val holder = dataSource.connection
        holder.autoCommit = false
        holder.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { it.next() }
        }
        try {
            runBlocking {
                coroutineScope {
                    val deferred = async(Dispatchers.IO) {
                        store.mintWeb(principal, null, 7200, 900, "serialized-second")
                    }
                    delay(300)
                    assertFalse(deferred.isCompleted, "web mint must wait for the existing principal transaction")
                    // Keep holding the lock well past a second so a deadline frozen at transaction start
                    // (the now() bug) would be visibly short of full duration measured from completion.
                    delay(1_700)
                    holder.commit()
                    val second = withTimeout(5_000) { deferred.await() }
                    val completedAt = Instant.now()
                    // Snapshot the minted deadlines immediately after the blocked insert completes.
                    // The mint blocked ~2s on the principal lock; its deadlines must be full-duration from
                    // the real insert instant (clock_timestamp), not from the frozen transaction-start now()
                    // — otherwise the fresh session is minted with an already-shortened idle clock.
                    val minted = snapshot(second)
                    assertTrue(
                        minted.idleExpiresAt.isAfter(completedAt.plusSeconds(899)),
                        "idle deadline of a lock-delayed mint must be full-duration from the real insert time",
                    )
                    assertTrue(
                        minted.absoluteExpiresAt.isAfter(completedAt.plusSeconds(7199)),
                        "absolute deadline of a lock-delayed mint must be full-duration from the real insert time",
                    )
                    assertEquals(ENDED_DISPLACED, snapshot(first).endedReason)
                    assertNotNull(store.resolveWeb(second, "serialized-second"))
                }
            }
        } finally {
            holder.close()
        }

        val activeCount = dataSource.connection.use { c ->
            c.prepareStatement(
                """SELECT count(*) FROM principal_session
                   WHERE principal = ? AND kind = 'WEB' AND ended_at IS NULL""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
            }
        }
        assertEquals(1, activeCount)
    }

    @Test
    fun `web refresh token is omitted when encryption is unavailable`() {
        val noCrypto = noCryptoStore.mintWeb(
            "no-crypto@example.com",
            "must-not-persist",
            absoluteSeconds = 7200,
            idleSeconds = 900,
            deviceId = "device-no-crypto",
        )
        dataSource.connection.use { c ->
            c.prepareStatement("SELECT refresh_token_enc FROM principal_session WHERE id = ?").use { ps ->
                ps.setLong(1, noCrypto)
                ps.executeQuery().use { rs -> assertTrue(rs.next()); assertNull(rs.getBytes(1)) }
            }
        }
    }

    private fun liveWebId(principal: String): Long = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT id FROM principal_session WHERE principal = ? AND kind = 'WEB' AND ended_at IS NULL ORDER BY id DESC LIMIT 1",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    private fun webRowCount(principal: String): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM principal_session WHERE principal = ? AND kind = 'WEB'").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun liveWebRowCount(principal: String): Int = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT count(*) FROM principal_session WHERE principal = ? AND kind = 'WEB' AND ended_at IS NULL",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun snapshot(id: Long): WebSnapshot = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT created_at, absolute_expires_at, idle_expires_at, last_seen_at, device_id,
                      ended_at, ended_reason, liveness_status
               FROM principal_session WHERE id = ?""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                assertTrue(rs.next())
                WebSnapshot(
                    createdAt = rs.getTimestamp("created_at").toInstant(),
                    absoluteExpiresAt = rs.getTimestamp("absolute_expires_at").toInstant(),
                    idleExpiresAt = rs.getTimestamp("idle_expires_at").toInstant(),
                    lastSeenAt = rs.getTimestamp("last_seen_at")?.toInstant(),
                    deviceId = rs.getString("device_id"),
                    endedAt = rs.getTimestamp("ended_at")?.toInstant(),
                    endedReason = rs.getString("ended_reason"),
                    livenessStatus = rs.getString("liveness_status"),
                )
            }
        }
    }

    private data class WebSnapshot(
        val createdAt: Instant,
        val absoluteExpiresAt: Instant,
        val idleExpiresAt: Instant,
        val lastSeenAt: Instant?,
        val deviceId: String?,
        val endedAt: Instant?,
        val endedReason: String?,
        val livenessStatus: String,
    )
}
