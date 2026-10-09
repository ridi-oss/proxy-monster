package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.seedDaemonSession
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Instant
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PrincipalSessionStorageDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var store: PrincipalSessionStore
    private lateinit var serializer: JsonSessionSerializer<WebSessionRef>
    private lateinit var storage: PrincipalSessionStorage

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_principal_session_storage"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        store = PrincipalSessionStore(dataSource, null)
        serializer = jsonSessionSerializer()
        storage = PrincipalSessionStorage(store, serializer)
    }

    @Test
    fun `write links a web row and steals a reused key from its prior holder`() = runBlocking {
        val first = store.mintWeb("first-key@example.com", null, 7200, 900, "first-device")
        storage.write("tracker-key", serializer.serialize(WebSessionRef(first)))
        assertEquals(first, store.webIdBySessionKey("tracker-key"))

        val second = store.mintWeb("second-key@example.com", null, 7200, 900, "second-device")
        storage.write("tracker-key", serializer.serialize(WebSessionRef(second)))

        assertEquals(second, store.webIdBySessionKey("tracker-key"))
        assertNull(sessionKey(first))
        assertEquals("tracker-key", sessionKey(second))
    }

    @Test
    fun `read returns live ended and expired refs without changing idle state`() = runBlocking {
        val live = store.mintWeb("read-live@example.com", null, 7200, 900, "live-device")
        storage.write("live-key", serializer.serialize(WebSessionRef(live)))
        val before = webTimes(live)
        assertEquals(WebSessionRef(live), serializer.deserialize(storage.read("live-key")))
        assertEquals(before, webTimes(live))

        val ended = store.mintWeb("read-ended@example.com", null, 7200, 900, "ended-device")
        storage.write("ended-key", serializer.serialize(WebSessionRef(ended)))
        assertTrue(store.endWeb(ended, ENDED_DISPLACED))
        assertEquals(WebSessionRef(ended), serializer.deserialize(storage.read("ended-key")))

        val expired = store.mintWeb("read-expired@example.com", null, 7200, 900, "expired-device")
        storage.write("expired-key", serializer.serialize(WebSessionRef(expired)))
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = ?").use { ps ->
                ps.setLong(1, expired)
                ps.executeUpdate()
            }
        }
        assertEquals(WebSessionRef(expired), serializer.deserialize(storage.read("expired-key")))
        assertFailsWith<NoSuchElementException> { storage.read("unknown-key") }
        Unit
    }

    @Test
    fun `invalidate signs out only active rows and preserves an existing terminal reason`() = runBlocking {
        val active = store.mintWeb("invalidate-active@example.com", null, 7200, 900, "active-device")
        storage.write("active-key", serializer.serialize(WebSessionRef(active)))
        storage.invalidate("active-key")
        assertEquals(ENDED_SIGNED_OUT, store.webEndedReason(active))

        val displaced = store.mintWeb("invalidate-displaced@example.com", null, 7200, 900, "displaced-device")
        storage.write("displaced-key", serializer.serialize(WebSessionRef(displaced)))
        assertTrue(store.endWeb(displaced, ENDED_DISPLACED))
        storage.invalidate("displaced-key")
        assertEquals(ENDED_DISPLACED, store.webEndedReason(displaced))
    }

    @Test
    fun `daemon rows cannot be linked or reached through web session keys`() = runBlocking {
        val daemon = dataSource.seedDaemonSession("daemon-key@example.com", 7200, 60)
        storage.write("daemon-key", serializer.serialize(WebSessionRef(daemon)))

        assertNull(sessionKey(daemon))
        assertNull(store.webIdBySessionKey("daemon-key"))
        assertFailsWith<NoSuchElementException> { storage.read("daemon-key") }
        Unit
    }

    private fun sessionKey(id: Long): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT session_key FROM principal_session WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getString(1) }
        }
    }

    private fun webTimes(id: Long): Pair<Instant, Instant?> = dataSource.connection.use { c ->
        c.prepareStatement("SELECT idle_expires_at, last_seen_at FROM principal_session WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                assertTrue(rs.next())
                assertNotNull(rs.getTimestamp("idle_expires_at")).toInstant() to rs.getTimestamp("last_seen_at")?.toInstant()
            }
        }
    }
}
