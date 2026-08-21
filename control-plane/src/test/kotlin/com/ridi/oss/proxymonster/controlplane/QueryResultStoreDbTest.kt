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

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class QueryResultStoreDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var store: QueryResultStore
    private lateinit var accessStore: AccessStore
    private var datasourceId = 0L

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_qr"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        accessStore = AccessStore(dataSource)
        datasourceId = DatasourceStore(dataSource).create(
            DatasourceInput(name = "ds", engine = "postgres", host = "h", port = 5432, dbName = "d"),
        ).id
        store = QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
    }

    private fun newTask(requester: String = "alice@example.com"): Long = accessStore.createQueryRequest(
        principal = requester,
        datasourceId = datasourceId,
        sql = "select id, ssn from users",
        denyReason = null,
        sourceDecisionId = null,
        reason = "r",
        title = "t",
        evaluatedDecision = "MASK",
    ).id

    private fun result() = DecryptedResult(
        listOf("id", "ssn"),
        listOf(listOf("1", "PM_SECRET_900101"), listOf("2", "PM_SECRET_850202")),
    )

    @Test
    fun `child transitions from pending to running to done with encrypted rows`() {
        val id = newTask()
        val running = store.startRun(id, "bob@example.com")
        assertEquals("RUNNING", running?.status)
        assertEquals("bob@example.com", running?.executedBy)
        assertEquals("bob@example.com", accessStore.getRequest(id)?.executedBy)
        val done = store.completeRun(id, result(), 3600)
        assertEquals("DONE", done?.status)
        assertEquals(2, done?.rowCount)
        assertEquals(result(), store.accessFor(id)?.decrypted)
        assertNull(store.cancelRun(id), "cancel-after-DONE is an idempotent no-op")

        dataSource.connection.use { c ->
            c.prepareStatement("SELECT ciphertext FROM query_result WHERE task_id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next())
                    assertFalse(rs.getBytes(1).toString(Charsets.ISO_8859_1).contains("PM_SECRET_900101"))
                }
            }
        }
    }

    @Test
    fun `DML result stores rowsAffected as row_count, not the empty result-set size`() {
        val id = newTask()
        assertNotNull(store.startRun(id, "bob@example.com"))
        val done = store.completeRun(id, DecryptedResult(emptyList(), emptyList(), rowsAffected = 1), 3600)
        assertEquals("DONE", done?.status)
        assertEquals(1, done?.rowCount)
    }

    @Test
    fun `failed child stores a stable error code without ciphertext`() {
        val id = newTask()
        assertNotNull(store.startRun(id, "bob@example.com"))
        val failed = store.failRun(id, "approval.execute_denied")
        assertEquals("FAILED", failed?.status)
        assertEquals("approval.execute_denied", failed?.errorCode)
        assertNull(store.accessFor(id)?.decrypted)
    }

    private fun approve(id: Long) = dataSource.connection.use { c ->
        c.prepareStatement("UPDATE access_request SET status = 'APPROVED' WHERE id = ?").use { ps ->
            ps.setLong(1, id); ps.executeUpdate()
        }
    }

    @Test
    fun `claimAndStartRun atomically claims the parent and starts the child, closing the cancel window`() {
        val id = newTask().also { approve(it) }
        // While APPROVED there is no RUNNING child yet — a cancel would find nothing to cancel.
        assertNull(store.cancelRun(id), "no RUNNING child before the run starts")
        // One transaction: parent APPROVED→EXECUTING AND child NULL→RUNNING commit together, so a cancel can
        // never observe an EXECUTING parent without a RUNNING child (the window that let a canceled query run).
        val started = store.claimAndStartRun(id, "bob@example.com") { c -> accessStore.claimExecution(id, c) }
        assertEquals("RUNNING", started?.status)
        assertEquals("bob@example.com", started?.executedBy)
        assertEquals("EXECUTING", accessStore.getRequest(id)?.status)
        // Now that the parent is EXECUTING it ALWAYS has a RUNNING child a cancel catches.
        val cancelled = store.cancelRun(id) { c, _ -> assertTrue(accessStore.markCancelled(id, c)) }
        assertEquals("CANCELLED", cancelled?.status)
        assertEquals("CANCELLED", accessStore.getRequest(id)?.status)
    }

    @Test
    fun `claimAndStartRun is single-shot - a second claim on a non-APPROVED task loses`() {
        val id = newTask().also { approve(it) }
        assertNotNull(store.claimAndStartRun(id, "bob@example.com") { c -> accessStore.claimExecution(id, c) })
        // Parent is already EXECUTING → claimExecution returns false → the whole step is a null no-op.
        assertNull(store.claimAndStartRun(id, "carol@example.com") { c -> accessStore.claimExecution(id, c) })
        assertEquals("bob@example.com", store.meta(id)?.executedBy)
    }

    @Test
    fun `cancelRun atomically cancels the child and parent and wins late completion`() {
        val id = newTask()
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status = 'EXECUTING' WHERE id = ?").use { ps ->
                ps.setLong(1, id); ps.executeUpdate()
            }
        }
        assertNotNull(store.startRun(id, "bob@example.com"))
        val cancelled = store.cancelRun(id) { c, _ -> assertTrue(accessStore.markCancelled(id, c)) }
        assertEquals("CANCELLED", cancelled?.status)
        assertEquals("approval.canceled", cancelled?.errorCode)
        assertNotNull(cancelled?.expiresAt)
        assertEquals("CANCELLED", accessStore.getRequest(id)?.status)
        assertNull(store.completeRun(id, result(), 3600), "late completion must lose the child CAS")
        assertNull(store.cancelRun(id), "cancel-after-terminal is an idempotent no-op")
    }

    @Test
    fun `one task supports multiple children and latest metadata wins`() {
        val id = newTask()
        dataSource.connection.use { c ->
            c.prepareStatement("INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, 'select 2', 'second')").use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        assertEquals(2L, dataSource.connection.use { c ->
            c.prepareStatement("SELECT count(*) FROM query_result WHERE task_id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
        })
        assertNull(store.meta(id)?.status)
        assertNotNull(store.startRun(id, "bob@example.com"))
        assertEquals("FAILED", store.failRun(id, "approval.query_failed")?.status)
    }

    @Test
    fun `accessFor binds the released child's own sql to its ciphertext, not the first child's`() {
        // Regression: a task with plural children whose SQL differs. accessFor returns the LATEST child's
        // ciphertext, so it must also return that SAME child's sql — the view re-decides the released bytes
        // against their own statement, never the first child's (which would let a later child's PII be
        // released under an earlier child's non-PII verdict when the output labels happen to match).
        val id = newTask() // first child carries "select id, ssn from users"
        dataSource.connection.use { c ->
            c.prepareStatement(
                "INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, 'select ssn as v from users', 'second')",
            ).use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        assertNotNull(store.startRun(id, "bob@example.com")) // claims the latest NULL child (the second)
        val done = store.completeRun(id, DecryptedResult(listOf("v"), listOf(listOf("PM_SECRET_900101"))), 3600)
        assertEquals("DONE", done?.status)

        val access = store.accessFor(id)
        assertNotNull(access)
        assertEquals("select ssn as v from users", access?.sql, "accessFor.sql is the latest (released) child's own sql")
        assertEquals(listOf(listOf("PM_SECRET_900101")), access?.decrypted?.rows, "and its ciphertext is that same child's")
    }

    @Test
    fun `expiry purges the payload but keeps the child row and its sql for audit`() {
        val id = newTask()
        store.startRun(id, "bob@example.com")
        store.completeRun(id, result(), -1) // already expired
        assertTrue(store.purgeExpired() >= 1)

        // The child row survives: sql/sql_hash/status stay for durable audit + web preview, but the
        // decryptable payload (ciphertext, row_count, columns) is gone.
        dataSource.connection.use { c ->
            c.prepareStatement(
                "SELECT sql, sql_hash, status, ciphertext, row_count, columns FROM query_result WHERE task_id = ?",
            ).use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next())
                    assertEquals("select id, ssn from users", rs.getString("sql"))
                    assertNotNull(rs.getString("sql_hash"))
                    assertEquals("DONE", rs.getString("status"))
                    assertNull(rs.getBytes("ciphertext"))
                    rs.getInt("row_count"); assertTrue(rs.wasNull())
                    assertNull(rs.getString("columns"))
                }
            }
        }
        // A subsequent read finds the row DONE but with no decryptable payload — the /result route returns 410.
        val access = store.accessFor(id)
        assertEquals("DONE", access?.meta?.status)
        assertNull(access?.decrypted)
    }
}
