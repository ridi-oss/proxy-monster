package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A task holding SEVERAL statements: one query_result child per statement, addressed by ordinal.
 *
 * The batch runs in order and stops at the first statement that does not complete — the statements before
 * it keep their stored results, the one that stopped it is FAILED, and the rest are SKIPPED rather than
 * left reading as "not started yet".
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class QueryResultBatchDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var store: QueryResultStore
    private lateinit var accessStore: AccessStore
    private var datasourceId = 0L

    private val batch = listOf(
        "select id from users",
        "update users set name = 'x' where id = 1",
        "select ssn from users",
    )

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_qr_batch"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        accessStore = AccessStore(dataSource)
        datasourceId = DatasourceStore(dataSource).create(
            DatasourceInput(name = "ds", engine = "postgres", host = "h", port = 5432, dbName = "d"),
        ).id
        store = QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
    }

    /** An APPROVED batch task — the state execution starts from (claimExecution flips APPROVED → EXECUTING). */
    private fun newTask(statements: List<String> = batch): Long {
        val id = accessStore.createQueryRequest(
            principal = "alice@example.com",
            datasourceId = datasourceId,
            statements = statements,
            denyReason = null,
            sourceDecisionId = null,
            reason = "r",
            title = "t",
            evaluatedDecision = "ALLOW",
        ).id
        accessStore.decideQueryRequest(id, approved = true, rejectionReason = null, decidedBy = "bob@example.com")
        return id
    }

    private fun result(vararg values: String) = DecryptedResult(listOf("c"), values.map { listOf(it) })

    @Test
    fun `each statement becomes its own child, in batch order`() {
        val id = newTask()
        val statements = store.statements(id)
        assertEquals(batch, statements.map { it.sql })
        assertEquals(listOf(0, 1, 2), statements.map { it.ordinal })
        // Each child hashes its OWN statement — the batch is authorized per statement, so a hash over the
        // joined text would identify nothing that actually runs.
        val hashes = dataSource.connection.use { c ->
            c.prepareStatement("SELECT sql_hash FROM query_result WHERE task_id = ? ORDER BY ordinal").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs ->
                    val out = ArrayList<String>()
                    while (rs.next()) out += rs.getString(1)
                    out
                }
            }
        }
        assertEquals(3, hashes.toSet().size, "each statement must hash distinctly: $hashes")
    }

    @Test
    fun `the request's sql is the whole batch, and it counts its statements`() {
        val request = assertNotNull(accessStore.getRequest(newTask()))
        assertEquals(3, request.statementCount)
        for (statement in batch) {
            assertTrue(request.sql!!.contains(statement), "batch text is missing $statement: ${request.sql}")
        }
    }

    @Test
    fun `statements run in order, one at a time`() {
        val id = newTask()
        val first = assertNotNull(store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) })
        assertEquals(0, first.ordinal)
        assertEquals(batch[0], first.sql)
        // Only the first statement is running; the rest are still pending.
        assertEquals(listOf("RUNNING", null, null), store.statements(id).map { it.status })

        store.completeRun(id, result("a"), 3600)
        val second = assertNotNull(store.startNextRun(id, "bob@example.com"))
        assertEquals(1, second.ordinal)
        assertEquals(batch[1], second.sql)
        store.completeRun(id, result("b"), 3600)

        val third = assertNotNull(store.startNextRun(id, "bob@example.com"))
        assertEquals(2, third.ordinal)
        store.completeRun(id, result("c"), 3600)

        assertEquals(listOf("DONE", "DONE", "DONE"), store.statements(id).map { it.status })
        assertNull(store.startNextRun(id, "bob@example.com"), "a finished batch has nothing left to start")
    }

    @Test
    fun `each statement's rows are stored and read back by ordinal`() {
        val id = newTask()
        store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) }
        store.completeRun(id, result("first"), 3600)
        store.startNextRun(id, "bob@example.com")
        store.completeRun(id, result("second"), 3600)

        assertEquals(result("first"), store.accessFor(id, 0)?.decrypted)
        assertEquals(result("second"), store.accessFor(id, 1)?.decrypted)
        // The re-decision binds to the child whose bytes were read, so each access carries its own SQL.
        assertEquals(batch[0], store.accessFor(id, 0)?.sql)
        assertEquals(batch[1], store.accessFor(id, 1)?.sql)
    }

    @Test
    fun `a failure stops the batch and skips the statements after it`() {
        val id = newTask()
        store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) }
        store.completeRun(id, result("a"), 3600)
        store.startNextRun(id, "bob@example.com")

        val failed = assertNotNull(store.failRun(id, "approval.execute_denied", denyReason = "no"))
        assertEquals(1, failed.ordinal)
        // Statement 0 keeps its result; 1 carries the failure; 2 never ran.
        assertEquals(listOf("DONE", "FAILED", "SKIPPED"), store.statements(id).map { it.status })
        assertEquals(result("a"), store.accessFor(id, 0)?.decrypted, "an earlier statement's result survives")
        assertNull(store.startNextRun(id, "bob@example.com"), "a stopped batch never resumes")
    }

    @Test
    fun `a cancel ends the whole batch`() {
        val id = newTask()
        store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) }
        val cancelled = assertNotNull(store.cancelRun(id))
        assertEquals(0, cancelled.ordinal)
        assertEquals(listOf("CANCELLED", "SKIPPED", "SKIPPED"), store.statements(id).map { it.status })
    }

    // A cancel arriving BETWEEN statements finds no RUNNING child — the previous one is DONE and the next
    // has not started. It must still stop the batch: without this the cancel no-ops while the run
    // continues, the same EXECUTING-with-no-RUNNING-child hole claimAndStartRun closed at the start.
    @Test
    fun `a cancel between statements stops the batch`() {
        val id = newTask()
        store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) }
        store.completeRun(id, result("a"), 3600)
        // Statement 0 is DONE and statement 1 has not started — the gap.
        assertEquals(listOf("DONE", null, null), store.statements(id).map { it.status })

        val cancelled = assertNotNull(store.cancelRun(id), "a cancel in the gap must not no-op")
        assertEquals(1, cancelled.ordinal, "the cancel lands on the statement that was about to run")
        assertEquals(listOf("DONE", "CANCELLED", "SKIPPED"), store.statements(id).map { it.status })
        // The run loop asks for the next statement and gets nothing, so the batch cannot resume.
        assertNull(store.startNextRun(id, "bob@example.com"), "a cancelled batch never resumes")
        assertEquals(result("a"), store.accessFor(id, 0)?.decrypted, "the finished statement keeps its rows")
    }

    // The ordinal-less readers must report the statement that actually ran, not the trailing SKIPPED one —
    // SKIPPED rows carry the HIGHEST ordinals, so counting them as active would hide the real outcome.
    @Test
    fun `the ordinal-less readers ignore trailing SKIPPED statements`() {
        val id = newTask()
        store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) }
        store.completeRun(id, result("a"), 3600)
        store.startNextRun(id, "bob@example.com")
        store.failRun(id, "approval.execute_denied", denyReason = "no")
        assertEquals(listOf("DONE", "FAILED", "SKIPPED"), store.statements(id).map { it.status })

        val active = assertNotNull(store.meta(id))
        assertEquals(1, active.ordinal, "meta must report the FAILED statement, not the trailing SKIPPED one")
        assertEquals("FAILED", active.status)
        assertEquals("no", active.denyReason, "the denial's reason must reach an ordinal-less poller")
        assertEquals(1, store.accessFor(id)?.meta?.ordinal, "accessFor agrees with meta")
    }

    // A crash BETWEEN statements leaves no RUNNING child for the restart reconcile to attribute the failure
    // to — the previous statement is DONE and the next never started. The reconcile must still leave the
    // task explaining itself, rather than a FAILED task whose children are all DONE/SKIPPED.
    @Test
    fun `boot reconcile fails the statement a crash stopped before, not just the tail`() {
        val id = newTask()
        store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) }
        store.completeRun(id, result("a"), 3600)
        // The process dies here: statement 0 DONE, statement 1 never started, parent still EXECUTING.
        assertEquals("EXECUTING", accessStore.getRequest(id)?.status)
        assertEquals(listOf("DONE", null, null), store.statements(id).map { it.status })

        accessStore.reconcileOrphanedExecutions()

        assertEquals("FAILED", accessStore.getRequest(id)?.status)
        val statements = store.statements(id)
        assertEquals(listOf("DONE", "FAILED", "SKIPPED"), statements.map { it.status })
        assertEquals(
            "task.orphaned_on_restart",
            statements[1].errorCode,
            "the statement that would have run next carries the orphan reason",
        )
        // And the ordinal-less readers land on it, so a poller sees why the task failed.
        assertEquals(1, store.meta(id)?.ordinal)
        assertEquals("task.orphaned_on_restart", store.meta(id)?.errorCode)
    }

    @Test
    fun `a single-statement task behaves exactly as before`() {
        val id = newTask(listOf("select 1"))
        assertEquals(1, assertNotNull(accessStore.getRequest(id)).statementCount)
        val running = assertNotNull(store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) })
        assertEquals(0, running.ordinal)
        store.completeRun(id, result("only"), 3600)
        // The ordinal-less readers still land on the one child.
        assertEquals("DONE", store.meta(id)?.status)
        assertEquals(result("only"), store.accessFor(id)?.decrypted)
        assertEquals("select 1", store.accessFor(id)?.sql)
    }

    @Test
    fun `the ordinal-less readers follow the batch's active statement`() {
        val id = newTask()
        store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) }
        assertEquals(0, store.meta(id)?.ordinal)
        store.completeRun(id, result("a"), 3600)
        store.startNextRun(id, "bob@example.com")
        // Once statement 1 starts, the un-ordinal'd read follows it rather than staying on statement 0.
        assertEquals(1, store.meta(id)?.ordinal)
        assertEquals("RUNNING", store.meta(id)?.status)
    }

    // completeRun binds the result to the LOWEST running child, so a second RUNNING statement would let
    // statement 1's rows land on statement 0 and be re-authorized against statement 0's SQL.
    @Test
    fun `a task can never have two running statements`() {
        val id = newTask()
        assertNotNull(store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) })
        assertFailsWith<Exception>("starting a second statement while one runs must be refused") {
            store.startNextRun(id, "bob@example.com")
        }
        assertEquals(listOf("RUNNING", null, null), store.statements(id).map { it.status })
    }

    // A cancel that reads the running child, then loses it to a completion before its UPDATE, used to
    // return null — the route then skipped cancelActiveRun and the next statement ran anyway.
    @Test
    fun `a cancel racing a completion still stops the batch`() {
        val id = newTask()
        assertNotNull(store.claimAndStartRun(id, "bob@example.com") { accessStore.claimExecution(id, it) })
        store.completeRun(id, result("a"), 3600)
        // Nothing is RUNNING now — exactly the window the race lands in.
        val cancelled = assertNotNull(store.cancelRun(id), "a cancel between statements must still land")
        assertEquals(1, cancelled.ordinal)
        assertEquals(listOf("DONE", "CANCELLED", "SKIPPED"), store.statements(id).map { it.status })
        assertNull(store.startNextRun(id, "bob@example.com"), "a cancelled batch never resumes")
    }
}
