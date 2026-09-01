package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.MigrationVersion
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/**
 * V25 adds `query_result.ordinal` plus a unique `(task_id, ordinal)` index. `query_result` has always been
 * 1:N in schema, so a task holding two rows is schema-valid pre-V25 even though every pre-batch writer
 * inserted exactly one. Backfilling a constant 0 would collide on that index and ABORT the migration —
 * an upgrade that fails on data the old schema allowed. The backfill numbers by insert order instead.
 * Real PostgreSQL.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class QueryResultOrdinalMigrationDbTest {
    @BeforeAll
    fun requireDatabase() {
        requireDockerOrSkip()
    }

    @Test
    fun `V25 numbers pre-existing children by insert order instead of colliding on ordinal 0`() {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_v25"))
        // Stop just before V25, then plant data the OLD schema permits: one task with a single child (the
        // shape every pre-batch writer produced) and one with two (schema-valid, and what a constant-0
        // backfill would choke on).
        Flyway.configure().dataSource(ds).target(MigrationVersion.fromVersion("24")).load().migrate()
        val datasourceId = DatasourceStore(ds).create(
            DatasourceInput(name = "ds", engine = "postgres", host = "h", port = 5432, dbName = "d"),
        ).id
        val (single, plural) = ds.connection.use { c ->
            fun task(): Long = c.prepareStatement(
                """INSERT INTO access_request (principal, kind, datasource_id, requested_duration_sec, creator_kind)
                   VALUES ('alice@example.com', 'QUERY', ?, 3600, 'WORKFLOW') RETURNING id""",
            ).use { ps ->
                ps.setLong(1, datasourceId)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
            fun child(taskId: Long, sql: String) = c.prepareStatement(
                "INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, ?, ?)",
            ).use { ps ->
                ps.setLong(1, taskId); ps.setString(2, sql); ps.setString(3, "h-$sql")
                ps.executeUpdate()
            }
            val one = task().also { child(it, "select 1") }
            val two = task().also { child(it, "select 2"); child(it, "select 3") }
            one to two
        }

        // The migration under test must APPLY, not abort on the two-child task.
        Flyway.configure().dataSource(ds).load().migrate()

        fun ordinalsFor(taskId: Long): List<Pair<Int, String>> = ds.connection.use { c ->
            c.prepareStatement("SELECT ordinal, sql FROM query_result WHERE task_id = ? ORDER BY ordinal").use { ps ->
                ps.setLong(1, taskId)
                ps.executeQuery().use { rs ->
                    val out = ArrayList<Pair<Int, String>>()
                    while (rs.next()) out += rs.getInt("ordinal") to rs.getString("sql")
                    out
                }
            }
        }
        assertEquals(listOf(0 to "select 1"), ordinalsFor(single), "a single-child task keeps ordinal 0")
        assertEquals(
            listOf(0 to "select 2", 1 to "select 3"),
            ordinalsFor(plural),
            "plural children are numbered densely by insert order, not all collapsed onto 0",
        )
    }

    // The one-RUNNING index is built over live data, and a RUNNING row survives a crash. Two of them under
    // one task would abort V25 and leave the schema half-migrated, so the migration fails them first —
    // the same thing reconcileOrphanedExecutions does to every RUNNING row on the next boot.
    @Test
    fun `V25 applies to a task left holding two running children`() {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_v25_running"))
        Flyway.configure().dataSource(ds).target(MigrationVersion.fromVersion("24")).load().migrate()
        val datasourceId = DatasourceStore(ds).create(
            DatasourceInput(name = "ds", engine = "postgres", host = "h", port = 5432, dbName = "d"),
        ).id
        val taskId = ds.connection.use { c ->
            val id = c.prepareStatement(
                """INSERT INTO access_request (principal, kind, datasource_id, requested_duration_sec, creator_kind)
                   VALUES ('alice@example.com', 'QUERY', ?, 3600, 'WORKFLOW') RETURNING id""",
            ).use { ps ->
                ps.setLong(1, datasourceId)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
            for (sql in listOf("select 1", "select 2")) {
                c.prepareStatement(
                    "INSERT INTO query_result (task_id, sql, sql_hash, status) VALUES (?, ?, ?, 'RUNNING')",
                ).use { ps ->
                    ps.setLong(1, id); ps.setString(2, sql); ps.setString(3, "h-$sql")
                    ps.executeUpdate()
                }
            }
            id
        }

        Flyway.configure().dataSource(ds).load().migrate()

        val rows = ds.connection.use { c ->
            c.prepareStatement(
                "SELECT ordinal, status, error_code FROM query_result WHERE task_id = ? ORDER BY ordinal",
            ).use { ps ->
                ps.setLong(1, taskId)
                ps.executeQuery().use { rs ->
                    val out = ArrayList<Triple<Int, String, String>>()
                    while (rs.next()) out += Triple(rs.getInt(1), rs.getString(2), rs.getString(3))
                    out
                }
            }
        }
        assertEquals(
            listOf(
                Triple(0, "FAILED", "task.orphaned_on_restart"),
                Triple(1, "FAILED", "task.orphaned_on_restart"),
            ),
            rows,
            "both orphaned RUNNING children are failed, so the one-running index can be built",
        )
    }
}
