package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.request.get
import io.ktor.server.testing.testApplication
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Restart recovery ([AccessStore.reconcileOrphanedExecutions], wired at [Main] and [Application.module]):
 * a task/child left mid-execution by a process that died is failed on the next boot so nothing stays stuck
 * in EXECUTING/RUNNING forever, while a task that never started (APPROVED, NULL child) is left untouched.
 * Booting the module a second time proves the sweep is idempotent (no spurious re-fail, no error).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TaskReconcileStartupDbTest {
    private lateinit var ds: DataSource

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_reconcile_startup"))
        Flyway.configure().dataSource(ds).load().migrate()
    }

    @Test
    fun `boot fails orphaned executions, spares not-started tasks, and is idempotent`() {
        val core = ControlPlaneCore(ds)
        val datasource = core.datasourceStore.create(
            DatasourceInput(name = "reconcile-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )

        // An orphan: claimed for execution and its child moved to RUNNING, then the process "died" before
        // either reached a terminal state.
        val orphan = core.accessStore.createQueryRequest(
            principal = "requester@example.com", datasourceId = datasource.id, statements = listOf("select 1"),
            denyReason = null, sourceDecisionId = null, reason = "need it", title = null, evaluatedDecision = "DENY",
        ).id
        execute("UPDATE access_request SET status='APPROVED' WHERE id=$orphan")
        assertEquals(true, core.accessStore.claimExecution(orphan))
        execute(
            "UPDATE query_result SET status='RUNNING' WHERE task_id=$orphan",
        )

        // A task that never started: APPROVED with its statement child still NULL (not-started). Reconcile
        // must not touch it.
        val notStarted = core.accessStore.createQueryRequest(
            principal = "requester@example.com", datasourceId = datasource.id, statements = listOf("select 2"),
            denyReason = null, sourceDecisionId = null, reason = "need it", title = null, evaluatedDecision = "DENY",
        ).id
        execute("UPDATE access_request SET status='APPROVED' WHERE id=$notStarted")

        // A completed task: EXECUTED parent with a DONE child (completion commits both atomically, so this is
        // the only shape a finished run can take). Reconcile sweeps only EXECUTING/RUNNING, so a completed task
        // must survive restart untouched — a DONE child must never be dragged to FAILED under its EXECUTED task.
        val completed = core.accessStore.createQueryRequest(
            principal = "requester@example.com", datasourceId = datasource.id, statements = listOf("select 3"),
            denyReason = null, sourceDecisionId = null, reason = "need it", title = null, evaluatedDecision = "DENY",
        ).id
        execute("UPDATE access_request SET status='EXECUTED', executing_at=now(), executed_at=now() WHERE id=$completed")
        execute("UPDATE query_result SET status='DONE' WHERE task_id=$completed")

        // First boot runs the module-level reconcile as part of application startup; the /health GET forces
        // testApplication to start the app.
        testApplication {
            application { module(config(), ControlPlaneCore(ds)) }
            client.get("/health")
        }

        assertEquals("FAILED", core.accessStore.getRequest(orphan)?.status, "orphaned EXECUTING task -> FAILED")
        assertEquals("FAILED" to "task.orphaned_on_restart", childState(orphan), "orphaned RUNNING child -> FAILED with the restart code")
        assertEquals("APPROVED", core.accessStore.getRequest(notStarted)?.status, "a not-started task is left untouched")
        assertEquals(null to null, childState(notStarted), "a not-started child stays NULL")
        assertEquals("EXECUTED", core.accessStore.getRequest(completed)?.status, "a completed task is left EXECUTED")
        assertEquals("DONE" to null, childState(completed), "a completed child stays DONE — never dragged to FAILED")

        // Second boot: the sweep matches no EXECUTING task / RUNNING child, so both stay exactly as they were.
        testApplication {
            application { module(config(), ControlPlaneCore(ds)) }
            client.get("/health")
        }

        assertEquals("FAILED", core.accessStore.getRequest(orphan)?.status)
        assertEquals("FAILED" to "task.orphaned_on_restart", childState(orphan))
        assertEquals("APPROVED", core.accessStore.getRequest(notStarted)?.status)
        assertEquals(null to null, childState(notStarted))
        assertNull(core.accessStore.getRequest(notStarted)?.executedAt)
    }

    private fun childState(taskId: Long): Pair<String?, String?> = ds.connection.use { c ->
        c.prepareStatement("SELECT status, error_code FROM query_result WHERE task_id = ? ORDER BY id DESC LIMIT 1").use { ps ->
            ps.setLong(1, taskId)
            ps.executeQuery().use { rs -> rs.next(); rs.getString("status") to rs.getString("error_code") }
        }
    }

    private fun execute(sql: String) {
        ds.connection.use { c -> c.createStatement().use { it.executeUpdate(sql) } }
    }

    private fun config() = Config(
        httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
        sessionSecret = "reconcile-test-secret", oidc = null, resultKey = null, scimToken = null,
        sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
    )
}
