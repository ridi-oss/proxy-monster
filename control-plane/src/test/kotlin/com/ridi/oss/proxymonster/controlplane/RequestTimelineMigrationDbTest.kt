package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.MigrationVersion
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/** V46 upgrades role and rate-reset rows filed without a creator kind into workflow requests with a timeline. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RequestTimelineMigrationDbTest {
    @BeforeAll
    fun requireDatabase() {
        requireDockerOrSkip()
    }

    @Test
    fun `V46 backfills creator kind, timelines and deciders on rows filed before it`() {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_v46"))
        Flyway.configure().dataSource(ds).target(MigrationVersion.fromVersion("45")).load().migrate()
        fun insert(sql: String): Long = ds.connection.use { c ->
            c.prepareStatement(sql).use { ps -> ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) } }
        }
        val pending = insert(
            "INSERT INTO access_request (principal, role_id, reason, source) VALUES ('alice', 1, 'r', 'console') RETURNING id",
        )
        val approved = insert(
            """INSERT INTO access_request (principal, role_id, reason, source, status, decided_by, decided_at)
               VALUES ('alice', 1, 'r', 'console', 'APPROVED', 'bob', now()) RETURNING id""",
        )
        val autoReset = insert(
            """INSERT INTO access_request (principal, kind, reason, requested_duration_sec, status, decided_by, decided_at)
               VALUES ('alice', 'RATE_RESET', 'r', 0, 'APPROVED', 'system:auto-approver:agent', now()) RETURNING id""",
        )
        val datasource = insert(
            "INSERT INTO datasource (name, engine, host, port, db_name) VALUES ('ds', 'postgres', 'h', 5432, 'd') RETURNING id",
        )
        val editorTask = insert(
            "INSERT INTO access_request (principal, kind, datasource_id, creator_kind) VALUES ('alice', 'QUERY', $datasource, 'EDITOR') RETURNING id",
        )

        Flyway.configure().dataSource(ds).load().migrate()

        fun column(sql: String, id: Long): List<String> = ds.connection.use { c ->
            c.prepareStatement(sql).use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } }
            }
        }
        fun creatorKind(id: Long) = column("SELECT creator_kind FROM access_request WHERE id = ?", id).single()
        fun timeline(id: Long) = column("SELECT kind FROM request_event WHERE request_id = ? ORDER BY id", id)
        fun participants(id: Long) = column("SELECT principal FROM request_participant WHERE request_id = ?", id)

        assertEquals(listOf("WORKFLOW", "WORKFLOW", "WORKFLOW"), listOf(pending, approved, autoReset).map(::creatorKind))
        assertEquals("EDITOR", creatorKind(editorTask))
        assertEquals(listOf("requested"), timeline(pending))
        assertEquals(listOf("requested", "approved"), timeline(approved), "requested comes first when both share a timestamp")
        assertEquals(listOf("requested", "approved"), timeline(autoReset))
        assertEquals(emptyList(), timeline(editorTask))
        assertEquals(listOf("bob"), participants(approved))
        assertEquals(emptyList(), participants(autoReset), "a system decider is not a participant")
    }
}
