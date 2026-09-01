package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.Timestamp
import java.time.Instant
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The async-editor data model + lifecycle (editor-as-task), at the store layer. A `createEditorTask`
 * submit is a born-APPROVED EDITOR task with ONE result child (task:child 1:1), executing as the caller's
 * OWN roles — no elevation, no separate editor status path. It drives the SAME single-execution status
 * machine an approved workflow task does (claimExecution APPROVED → EXECUTING, then the child RUNNING →
 * DONE with the parent EXECUTED). The delete/purge methods back close-tab, delete-on-logout, and GC.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EditorTaskStoreDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var accessStore: AccessStore
    private lateinit var resultStore: QueryResultStore
    private var datasourceId = 0L

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_editor_store"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        accessStore = AccessStore(dataSource)
        resultStore = QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        datasourceId = DatasourceStore(dataSource).create(
            DatasourceInput(name = "ds", engine = "postgres", host = "h", port = 5432, dbName = "d"),
        ).id
    }

    private fun result() = DecryptedResult(listOf("id"), listOf(listOf("1"), listOf("2")))

    private fun expireChild(taskId: Long) = dataSource.connection.use { c ->
        c.prepareStatement("UPDATE query_result SET expires_at = ? WHERE task_id = ?").use { ps ->
            ps.setTimestamp(1, Timestamp.from(Instant.now().minusSeconds(60)))
            ps.setLong(2, taskId)
            ps.executeUpdate()
        }
    }

    private fun childCount(taskId: Long): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM query_result WHERE task_id = ?").use { ps ->
            ps.setLong(1, taskId)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    @Test
    fun `createEditorTask is born APPROVED as EDITOR with own roles and one child`() {
        val task = accessStore.createEditorTask(
            principal = "alice@example.com", datasourceId = datasourceId, statements = listOf("select id from t"),
            executeAs = listOf("analyst"), approver = "alice@example.com",
        )
        assertEquals("APPROVED", task.status)
        assertEquals("EDITOR", task.creatorKind)
        assertEquals("QUERY", task.kind)
        assertEquals(listOf("analyst"), task.executeAs)
        assertEquals("alice@example.com", task.decidedBy, "self-approved: decided_by == the submitter")
        assertEquals("alice@example.com", task.principal)
        assertEquals(1, childCount(task.id))
        assertEquals(task.id, accessStore.getRequest(task.id)?.let { task.id }) // sanity: re-readable
        assertTrue(accessStore.editorChildId(task.id)!! > 0)
    }

    @Test
    fun `createWireTask is born APPROVED as WIRE linked to its decision and has no child`() {
        val principal = "wire@example.com"
        val executeAs = listOf("analyst", "reporter")
        val auditStore = AuditStore(dataSource)
        val decisionId = auditStore.insert(
            AuditEvent(principal = principal, datasource = "ds", statement = "select 1", decision = Decision.ALLOW),
        )
        val taskId = dataSource.inTx { c ->
            accessStore.createWireTask(c, principal, datasourceId, executeAs, decisionId)
        }
        val task = accessStore.getRequest(taskId) ?: error("wire task was not re-readable")

        assertEquals("APPROVED", task.status)
        assertEquals("WIRE", task.creatorKind)
        assertEquals("QUERY", task.kind)
        assertEquals(executeAs, task.executeAs)
        assertEquals(principal, task.decidedBy)
        assertEquals(principal, task.principal)
        assertEquals(decisionId, task.sourceDecisionId)
        assertEquals(0, childCount(task.id))
        assertNull(task.sql)
        assertNull(task.sqlHash)
        assertNull(task.executedBy)

        assertTrue(accessStore.claimExecution(task.id), "APPROVED → EXECUTING")
        assertTrue(accessStore.markExecuted(task.id), "EXECUTING → EXECUTED")
        assertEquals("EXECUTED", accessStore.getRequest(task.id)?.status)

        val failedDecisionId = auditStore.insert(
            AuditEvent(principal = principal, datasource = "ds", statement = "select 2", decision = Decision.DENY),
        )
        val failedId = dataSource.inTx { c ->
            accessStore.createWireTask(c, principal, datasourceId, executeAs, failedDecisionId)
        }
        assertTrue(accessStore.claimExecution(failedId), "APPROVED → EXECUTING")
        assertTrue(accessStore.markFailed(failedId), "EXECUTING → FAILED")
        assertEquals("FAILED", accessStore.getRequest(failedId)?.status)
    }

    @Test
    fun `the born-APPROVED editor task runs the same single-execution status machine`() {
        val task = accessStore.createEditorTask(
            "bob@example.com", datasourceId, listOf("select id from t"), listOf("analyst"), "bob@example.com",
        )
        assertTrue(accessStore.claimExecution(task.id), "APPROVED → EXECUTING")
        assertEquals("EXECUTING", accessStore.getRequest(task.id)?.status)
        assertFalse(accessStore.claimExecution(task.id), "a second claim on a non-APPROVED task loses")

        assertEquals("RUNNING", resultStore.startNextRun(task.id, "bob@example.com")?.status)
        val done = resultStore.completeRun(task.id, result(), 3600) { conn, _ ->
            assertTrue(accessStore.markExecuted(task.id, conn))
        }
        assertEquals("DONE", done?.status)
        assertEquals(2, done?.rowCount)
        assertEquals("EXECUTED", accessStore.getRequest(task.id)?.status)
    }

    @Test
    fun `deleteResultsForTask drops the child but leaves the task, idempotently`() {
        val task = accessStore.createEditorTask(
            "carol@example.com", datasourceId, listOf("select id from t"), listOf("analyst"), "carol@example.com",
        )
        resultStore.startNextRun(task.id, "carol@example.com")
        resultStore.completeRun(task.id, result(), 3600)
        assertEquals(1, resultStore.deleteResultsForTask(task.id))
        assertEquals(0, childCount(task.id))
        assertEquals(0, resultStore.deleteResultsForTask(task.id), "idempotent: nothing left to delete")
        assertTrue(accessStore.getRequest(task.id) != null, "the task row survives — only its rows are gone")
    }

    @Test
    fun `deleteEditorResultsForPrincipal drops only that principal's editor children`() {
        val mine = accessStore.createEditorTask(
            "dave@example.com", datasourceId, listOf("select id from t"), listOf("analyst"), "dave@example.com",
        )
        val other = accessStore.createEditorTask(
            "erin@example.com", datasourceId, listOf("select id from t"), listOf("analyst"), "erin@example.com",
        )
        // A WORKFLOW task (creator_kind != EDITOR) owned by dave must be untouched by the editor-scoped delete.
        val workflow = accessStore.createQueryRequest(
            principal = "dave@example.com", datasourceId = datasourceId, statements = listOf("select id from t"),
            denyReason = null, sourceDecisionId = null, reason = "r", title = "t", evaluatedDecision = "MASK",
        )

        assertEquals(1, resultStore.deleteEditorResultsForPrincipal("dave@example.com"))
        assertEquals(0, childCount(mine.id), "dave's editor child is gone")
        assertEquals(1, childCount(other.id), "erin's editor child is untouched")
        assertEquals(1, childCount(workflow.id), "dave's WORKFLOW child is untouched")
    }

    @Test
    fun `purgeExpiredEditorChildren deletes only expired editor children`() {
        val expired = accessStore.createEditorTask(
            "frank@example.com", datasourceId, listOf("select id from t"), listOf("analyst"), "frank@example.com",
        )
        val live = accessStore.createEditorTask(
            "grace@example.com", datasourceId, listOf("select id from t"), listOf("analyst"), "grace@example.com",
        )
        expireChild(expired.id)
        assertEquals(1, resultStore.purgeExpiredEditorChildren())
        assertEquals(0, childCount(expired.id))
        assertEquals(1, childCount(live.id), "an unexpired editor child is kept")
    }

    @Test
    fun `deleteEditorTask cascades the child and is owner + EDITOR scoped`() {
        val task = accessStore.createEditorTask(
            "heidi@example.com", datasourceId, listOf("select id from t"), listOf("analyst"), "heidi@example.com",
        )
        assertFalse(accessStore.deleteEditorTask(task.id, "mallory@example.com"), "a non-owner cannot delete it")
        assertTrue(childCount(task.id) == 1 && accessStore.getRequest(task.id) != null)

        assertTrue(accessStore.deleteEditorTask(task.id, "heidi@example.com"))
        assertNull(accessStore.getRequest(task.id), "the task row is gone")
        assertEquals(0, childCount(task.id), "and its child cascaded away")
        assertFalse(accessStore.deleteEditorTask(task.id, "heidi@example.com"), "idempotent")
    }
}
