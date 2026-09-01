package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.runError

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
        statements = listOf("select id, ssn from users"),
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
        val running = store.startNextRun(id, "bob@example.com")
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
        assertNotNull(store.startNextRun(id, "bob@example.com"))
        val done = store.completeRun(id, DecryptedResult(emptyList(), emptyList(), rowsAffected = 1), 3600)
        assertEquals("DONE", done?.status)
        assertEquals(1, done?.rowCount)
    }

    @Test
    fun `failed child stores a stable error code without ciphertext`() {
        val id = newTask()
        assertNotNull(store.startNextRun(id, "bob@example.com"))
        val failed = store.failRun(id, "approval.execute_denied")
        assertEquals("FAILED", failed?.status)
        assertEquals("approval.execute_denied", failed?.errorCode)
        assertNull(store.accessFor(id)?.errorDetail, "no backend text unless a target-DB failure carried one")
        assertNull(store.accessFor(id)?.decrypted)
    }

    @Test
    fun `a target-DB failure stores the backend error text encrypted, released only via accessFor`() {
        val id = newTask()
        assertNotNull(store.startNextRun(id, "bob@example.com"))
        val diagnostic = runError { message = "ER_TABLE_EXISTS_ERROR"; rawMessage = "Table 'bom.test' already exists"; targetDbError = true }
        val failed = store.failRun(id, "approval.query_failed", diagnostic = diagnostic)
        assertEquals("FAILED", failed?.status)
        // The stable catalog code stays on metadata; both diagnostic forms move behind the task.assume gate,
        // released only through accessFor and decrypting back to the stored structure.
        assertEquals("approval.query_failed", failed?.errorCode)
        assertEquals(diagnostic, store.accessFor(id)?.errorDetail)

        // At rest error_detail holds AES-GCM ciphertext of the serialized struct, never the plaintext.
        dataSource.connection.use { c ->
            c.prepareStatement("SELECT error_detail FROM query_result WHERE task_id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next())
                    val raw = rs.getBytes("error_detail")
                    assertNotNull(raw)
                    val atRest = raw.toString(Charsets.ISO_8859_1)
                    assertFalse(atRest.contains("already exists"))
                    assertFalse(atRest.contains("ER_TABLE_EXISTS_ERROR"))
                }
            }
        }
    }

    @Test
    fun `error detail is off the metadata path and reachable only through accessFor`() {
        val id = newTask()
        assertNotNull(store.startNextRun(id, "bob@example.com"))
        val detail = "constraint users_email_key violated"
        store.failRun(id, "approval.query_failed", diagnostic = runError { message = "ER_DUP_ENTRY"; rawMessage = detail; targetDbError = true })
        // The metadata poll (task.read) carries the stable code but has no channel for the raw detail — the
        // field was removed from QueryResultMeta, so a metadata-only reader can never see it.
        val meta = store.meta(id)
        assertEquals("approval.query_failed", meta?.errorCode)
        // Reachable only via accessFor, which the /result routes gate on task.assume.
        assertEquals(detail, store.accessFor(id)?.errorDetail?.rawMessage)
    }

    @Test
    fun `expiry purges the encrypted error detail`() {
        val id = newTask()
        assertNotNull(store.startNextRun(id, "bob@example.com"))
        store.failRun(id, "approval.query_failed", diagnostic = runError { message = "ER_NO_SUCH_TABLE"; rawMessage = "relation missing does not exist"; targetDbError = true })
        // failRun stamps expires_at RESULT_RETENTION_SEC ahead; force the row past expiry so the sweep hits it.
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE query_result SET expires_at = now() - interval '1 second' WHERE task_id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        assertTrue(store.purgeExpired() >= 1)
        assertNull(store.accessFor(id)?.errorDetail, "expiry must NULL the encrypted detail like the row ciphertext")
        dataSource.connection.use { c ->
            c.prepareStatement("SELECT error_detail FROM query_result WHERE task_id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next())
                    rs.getBytes("error_detail"); assertTrue(rs.wasNull())
                }
            }
        }
    }

    @Test
    fun `accessFor withholds the error detail once past expiry, before any purge sweep`() {
        val id = newTask()
        assertNotNull(store.startNextRun(id, "bob@example.com"))
        store.failRun(id, "approval.query_failed", diagnostic = runError { message = "ER_NO_SUCH_TABLE"; rawMessage = "relation missing does not exist"; targetDbError = true })
        // Push the row past expiry WITHOUT purging: the ciphertext is still in the row when accessFor reads it.
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE query_result SET expires_at = now() - interval '1 second' WHERE task_id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        // accessFor withholds the detail on the expiry timestamp alone — the soft path — so a past-expiry row
        // never releases the backend text, distinct from the purge test which asserts the at-rest column is NULLed.
        assertNull(store.accessFor(id)?.errorDetail, "past-expiry accessFor must withhold the error detail without an explicit purge")
    }

    private fun approve(id: Long) = dataSource.connection.use { c ->
        c.prepareStatement("UPDATE access_request SET status = 'APPROVED' WHERE id = ?").use { ps ->
            ps.setLong(1, id); ps.executeUpdate()
        }
    }

    @Test
    fun `claimAndStartRun atomically claims the parent and starts the child, closing the cancel window`() {
        val id = newTask().also { approve(it) }
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

    // A cancel that arrives before the run starts — or between a batch's statements — finds no RUNNING
    // child, but must still stop the task rather than no-op while the run proceeds. It cancels the
    // statement that was about to run, so claimAndStartRun then finds nothing pending.
    @Test
    fun `cancelRun catches a not-yet-started statement`() {
        val id = newTask().also { approve(it) }
        val cancelled = assertNotNull(store.cancelRun(id), "a pre-run cancel must not no-op")
        assertEquals("CANCELLED", cancelled.status)
        assertEquals(0, cancelled.ordinal)
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
        assertNotNull(store.startNextRun(id, "bob@example.com"))
        val cancelled = store.cancelRun(id) { c, _ -> assertTrue(accessStore.markCancelled(id, c)) }
        assertEquals("CANCELLED", cancelled?.status)
        assertEquals("approval.canceled", cancelled?.errorCode)
        assertNotNull(cancelled?.expiresAt)
        assertEquals("CANCELLED", accessStore.getRequest(id)?.status)
        assertNull(store.completeRun(id, result(), 3600), "late completion must lose the child CAS")
        assertNull(store.cancelRun(id), "cancel-after-terminal is an idempotent no-op")
    }

    @Test
    fun `one task supports multiple children and metadata follows the active one`() {
        val id = newTask()
        dataSource.connection.use { c ->
            c.prepareStatement("INSERT INTO query_result (task_id, ordinal, sql, sql_hash) VALUES (?, 1, 'select 2', 'second')").use { ps ->
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
        assertNotNull(store.startNextRun(id, "bob@example.com"))
        assertEquals("FAILED", store.failRun(id, "approval.query_failed")?.status)
    }

    @Test
    fun `accessFor binds the released child's own sql to its ciphertext, not the first child's`() {
        // Regression: a batch whose statements differ. accessFor returns ONE child's ciphertext, so it must
        // return that SAME child's sql — the view re-decides the released bytes against their own statement,
        // never another child's (which would let one statement's PII be released under a different
        // statement's non-PII verdict when the output labels happen to match).
        val id = newTask() // statement 0 carries "select id, ssn from users"
        dataSource.connection.use { c ->
            c.prepareStatement(
                "INSERT INTO query_result (task_id, ordinal, sql, sql_hash) VALUES (?, 1, 'select ssn as v from users', 'second')",
            ).use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        assertNotNull(store.startNextRun(id, "bob@example.com")) // claims statement 0
        assertNotNull(store.completeRun(id, result(), 3600))
        assertNotNull(store.startNextRun(id, "bob@example.com")) // statement 1
        val done = store.completeRun(id, DecryptedResult(listOf("v"), listOf(listOf("PM_SECRET_900101"))), 3600)
        assertEquals("DONE", done?.status)

        val access = store.accessFor(id, 1)
        assertNotNull(access)
        assertEquals("select ssn as v from users", access?.sql, "accessFor.sql is the released child's own sql")
        assertEquals(listOf(listOf("PM_SECRET_900101")), access?.decrypted?.rows, "and its ciphertext is that same child's")
        // The other statement's bytes stay bound to ITS own sql — one task, two independently-gated results.
        assertEquals("select id, ssn from users", store.accessFor(id, 0)?.sql)
        assertEquals(result().rows, store.accessFor(id, 0)?.decrypted?.rows)
    }

    @Test
    fun `expiry purges the payload but keeps the child row and its sql for audit`() {
        val id = newTask()
        store.startNextRun(id, "bob@example.com")
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
