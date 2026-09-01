package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.postgresql.util.PGobject
import java.sql.PreparedStatement
import java.sql.Statement
import java.sql.Timestamp
import java.sql.Types
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The `AccessStore` task-lifecycle transitions — `claimExecution`, `markExecuted`, `markFailed`, `markDeleted`,
 * `resubmit`, `reconcileOrphanedExecutions` — plus their CAS guards and the child-metadata reshape, run
 * against a real **PostgreSQL** control-plane store on the full Flyway chain.
 *
 * Task state is read with plain `SELECT status/...` and child state through `QueryResultStore.meta`, so a
 * regression in any of these `UPDATE ... WHERE status = ?` compare-and-sets (or in the reconcile pass) fails
 * here on the store SQL itself rather than on a helper.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TaskStoreDbTest {
    private lateinit var fx: EnforcementFixture
    private val dataSource: DataSource get() = fx.dataSource
    private val datasourceId: Long get() = fx.datasource.id

    private val store: AccessStore get() = AccessStore(dataSource)
    private val resultStore: QueryResultStore get() = QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    private val json = Json
    private val stringList = ListSerializer(String.serializer())

    private fun bindJson(ps: PreparedStatement, idx: Int, value: String) {
        ps.setObject(idx, PGobject().apply { type = "jsonb"; this.value = value })
    }

    /** A QUERY task in [status] with [executeAs]/[creatorKind]; returns the generated id. */
    private fun seedTask(
        status: String,
        executeAs: List<String> = listOf("role-r"),
        creatorKind: String = "WORKFLOW",
        approvedAt: Boolean = false,
        sourceDecisionId: Long? = null,
    ): Long = dataSource.connection.use { c ->
        c.prepareStatement(
            "INSERT INTO access_request " +
                "(principal, requested_duration_sec, status, created_at, kind, datasource_id, execute_as, creator_kind, approved_at, source_decision_id) " +
                "VALUES (?, 3600, ?, ?, 'QUERY', ?, ?, ?, ?, ?)",
            Statement.RETURN_GENERATED_KEYS,
        ).use { ps ->
            ps.setString(1, "requester@example.com")
            ps.setString(2, status)
            ps.setTimestamp(3, Timestamp.from(Instant.now()))
            ps.setLong(4, datasourceId)
            bindJson(ps, 5, json.encodeToString(stringList, executeAs))
            ps.setString(6, creatorKind)
            if (approvedAt) ps.setTimestamp(7, Timestamp.from(Instant.now())) else ps.setNull(7, Types.TIMESTAMP)
            if (sourceDecisionId == null) ps.setNull(8, Types.BIGINT) else ps.setLong(8, sourceDecisionId)
            ps.executeUpdate()
            ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    /** A statement child for [taskId] at [ordinal], in [status] (null = not started). Leaves `sql` unset. */
    private fun seedChild(taskId: Long, status: String? = null, ordinal: Int = 0): Long = dataSource.connection.use { c ->
        c.prepareStatement(
            "INSERT INTO query_result (task_id, ordinal, status) VALUES (?, ?, ?)",
            Statement.RETURN_GENERATED_KEYS,
        ).use { ps ->
            ps.setLong(1, taskId)
            ps.setInt(2, ordinal)
            if (status == null) ps.setNull(3, Types.VARCHAR) else ps.setString(3, status)
            ps.executeUpdate()
            ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    private fun seedDecision(statement: String): Long = AuditStore(dataSource).insert(
        AuditEvent(
            principal = "requester@example.com",
            datasource = fx.datasource.name,
            statement = statement,
            decision = Decision.ALLOW,
        ),
    )

    private fun taskStatus(id: Long): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT status FROM access_request WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }
    }

    private fun timestampSet(id: Long, column: String): Boolean = dataSource.connection.use { c ->
        c.prepareStatement("SELECT $column FROM access_request WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> rs.next() && rs.getTimestamp(1) != null }
        }
    }

    private fun childCount(taskId: Long): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM query_result WHERE task_id = ?").use { ps ->
            ps.setLong(1, taskId)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    @Test
    fun `claimExecution moves APPROVED to EXECUTING and stamps executing_at`() {
        val id = seedTask("APPROVED")
        assertFalse(timestampSet(id, "executing_at"), "executing_at starts null")
        assertTrue(store.claimExecution(id))
        assertEquals("EXECUTING", taskStatus(id))
        assertTrue(timestampSet(id, "executing_at"), "the winning claim stamps executing_at")
    }

    @Test
    fun `claimExecution fires only from APPROVED`() {
        for (from in listOf("DRAFT", "PENDING", "REJECTED", "EXECUTING", "EXECUTED", "FAILED")) {
            val id = seedTask(from)
            assertFalse(store.claimExecution(id), "claim must not fire from $from")
            assertEquals(from, taskStatus(id), "a rejected claim must not move the task out of $from")
        }
    }

    @Test
    fun `two concurrent claims on separate connections yield exactly one winner`() {
        val id = seedTask("APPROVED")
        val s = store
        val pool = Executors.newFixedThreadPool(2)
        try {
            val start = CountDownLatch(1)
            val results = java.util.Collections.synchronizedList(ArrayList<Boolean>())
            val tasks = (1..2).map { pool.submit { start.await(); results += s.claimExecution(id) } }
            start.countDown()
            tasks.forEach { it.get(5, TimeUnit.SECONDS) }
            assertEquals(2, results.size)
            assertEquals(1, results.count { it }, "exactly one of two racing claims wins")
            assertEquals("EXECUTING", taskStatus(id))
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `markExecuted moves EXECUTING to EXECUTED and stamps executed_at, only from EXECUTING`() {
        val id = seedTask("EXECUTING")
        assertTrue(store.markExecuted(id))
        assertEquals("EXECUTED", taskStatus(id))
        assertTrue(timestampSet(id, "executed_at"), "terminal success stamps executed_at")

        val notExecuting = seedTask("APPROVED")
        assertFalse(store.markExecuted(notExecuting), "markExecuted must not fire from APPROVED")
        assertEquals("APPROVED", taskStatus(notExecuting))
    }

    @Test
    fun `markFailed moves EXECUTING to FAILED, only from EXECUTING`() {
        val id = seedTask("EXECUTING")
        assertTrue(store.markFailed(id))
        assertEquals("FAILED", taskStatus(id))

        val approved = seedTask("APPROVED")
        assertFalse(store.markFailed(approved))
        assertEquals("APPROVED", taskStatus(approved))
    }

    @Test
    fun `markCancelled moves only EXECUTING to CANCELLED and blocks later terminal transitions`() {
        val id = seedTask("EXECUTING")
        assertTrue(store.markCancelled(id))
        assertEquals("CANCELLED", taskStatus(id))
        assertFalse(store.markExecuted(id), "late success must lose to cancellation")
        assertFalse(store.markFailed(id), "late failure must lose to cancellation")
        assertEquals("CANCELLED", taskStatus(id))

        for (from in listOf("EXECUTED", "FAILED")) {
            val terminal = seedTask(from)
            assertFalse(store.markCancelled(terminal), "cancellation must not overwrite $from")
            assertEquals(from, taskStatus(terminal))
        }
    }

    @Test
    fun `no-child WIRE tasks use the shared terminal lifecycle`() {
        val wireDecisionId = seedDecision("wire lookup")
        val executed = seedTask(
            status = "APPROVED",
            executeAs = listOf("analyst"),
            creatorKind = "WIRE",
            approvedAt = true,
            sourceDecisionId = wireDecisionId,
        )
        assertEquals(0, childCount(executed))
        dataSource.connection.use { c ->
            assertEquals(executed, store.wireTaskIdForDecision(wireDecisionId, c))
        }
        assertTrue(store.claimExecution(executed))
        assertEquals("EXECUTING", taskStatus(executed))
        assertTrue(store.markExecuted(executed))
        assertEquals("EXECUTED", taskStatus(executed))

        val workflowDecisionId = seedDecision("workflow lookup")
        val workflow = seedTask(
            status = "APPROVED",
            creatorKind = "WORKFLOW",
            sourceDecisionId = workflowDecisionId,
        )
        dataSource.connection.use { c ->
            assertNull(
                store.wireTaskIdForDecision(workflowDecisionId, c),
                "a workflow task must not match a proxy completion",
            )
        }
        assertEquals("APPROVED", taskStatus(workflow))

        val failed = seedTask(
            status = "APPROVED",
            executeAs = listOf("analyst"),
            creatorKind = "WIRE",
            approvedAt = true,
        )
        assertEquals(0, childCount(failed))
        assertTrue(store.claimExecution(failed))
        assertEquals("EXECUTING", taskStatus(failed))
        assertTrue(store.markFailed(failed))
        assertEquals("FAILED", taskStatus(failed))
    }

    @Test
    fun `markDeleted fires from DRAFT PENDING REJECTED but never from live states`() {
        for (from in listOf("DRAFT", "PENDING", "REJECTED")) {
            val id = seedTask(from)
            assertTrue(store.markDeleted(id), "markDeleted must fire from $from")
            assertEquals("DELETED", taskStatus(id))
        }
        for (from in listOf("APPROVED", "EXECUTING", "EXECUTED", "FAILED")) {
            val id = seedTask(from)
            assertFalse(store.markDeleted(id), "markDeleted must not fire from $from")
            assertEquals(from, taskStatus(id))
        }
    }

    @Test
    fun `resubmit moves REJECTED to PENDING but never other states`() {
        val rejected = seedTask("REJECTED")
        assertTrue(store.resubmit(rejected))
        assertEquals("PENDING", taskStatus(rejected))

        for (from in listOf("PENDING", "APPROVED", "EXECUTING", "DELETED")) {
            val id = seedTask(from)
            assertFalse(store.resubmit(id), "resubmit must not fire from $from")
            assertEquals(from, taskStatus(id))
        }
    }

    @Test
    fun `execute_as and creator_kind round-trip through the reshaped columns`() {
        val id = seedTask("APPROVED", executeAs = listOf("role-a", "role-b"), creatorKind = "WORKFLOW")
        dataSource.connection.use { c ->
            c.prepareStatement("SELECT execute_as, creator_kind FROM access_request WHERE id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next())
                    val executeAs = rs.getString("execute_as")
                    assertTrue(executeAs.contains("role-a") && executeAs.contains("role-b"), "execute_as round-trips: $executeAs")
                    assertEquals("WORKFLOW", rs.getString("creator_kind"))
                }
            }
        }
    }

    @Test
    fun `a task carries one child per statement, and meta follows the active one`() {
        val id = seedTask("APPROVED")
        seedChild(id, status = "FAILED", ordinal = 0)
        seedChild(id, status = "RUNNING", ordinal = 1)
        assertEquals(2, childCount(id), "a batch task holds one child per statement")
        assertEquals("RUNNING", resultStore.meta(id)?.status, "meta follows the batch's active statement")
        assertEquals(1, resultStore.meta(id)?.ordinal)
    }

    @Test
    fun `reconcileOrphanedExecutions terminalizes EXECUTING tasks and RUNNING children, idempotently`() {
        val id = seedTask("EXECUTING")
        seedChild(id, status = "RUNNING")

        store.reconcileOrphanedExecutions()
        assertEquals("FAILED", taskStatus(id), "an orphaned EXECUTING task is failed on reconcile")
        assertEquals("FAILED", resultStore.meta(id)?.status, "its RUNNING child is failed too")
        assertEquals("task.orphaned_on_restart", resultStore.meta(id)?.errorCode)

        // Idempotent: a second pass finds nothing EXECUTING/RUNNING and leaves the terminal states intact.
        store.reconcileOrphanedExecutions()
        assertEquals("FAILED", taskStatus(id))
        assertEquals("FAILED", resultStore.meta(id)?.status)
    }

    @Test
    fun `createQueryRequest persists execute_as, creator_kind, and a not-started statement child`() {
        val roleId = fx.policyStore.createRole(RoleInput("task-store-round-trip")).id
        val req = store.createQueryRequest(
            principal = "alice@example.com", datasourceId = fx.datasource.id, statements = listOf("select 1"),
            denyReason = null, sourceDecisionId = null, reason = "need it", title = null,
            evaluatedDecision = "DENY", roleId = roleId,
        )
        assertEquals(listOf("task-store-round-trip"), req.executeAs, "execute_as is seeded from the picked role")
        assertEquals("WORKFLOW", req.creatorKind)
        assertNull(resultStore.meta(req.id)?.status, "the statement child is created not-started (null status)")
    }

    @Test
    fun `decideQueryRequest approve stamps approved_at, reject leaves it null`() {
        val approved = seedTask("PENDING")
        val a = store.decideQueryRequest(approved, approved = true, rejectionReason = null, decidedBy = "approver@example.com")
        assertEquals("APPROVED", a?.status)
        assertNotNull(a?.approvedAt, "approve stamps approved_at")

        val rejected = seedTask("PENDING")
        val r = store.decideQueryRequest(rejected, approved = false, rejectionReason = "no", decidedBy = "approver@example.com")
        assertEquals("REJECTED", r?.status)
        assertNull(r?.approvedAt, "reject must not stamp approved_at")
    }
}
