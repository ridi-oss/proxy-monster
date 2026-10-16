package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.MigrationVersion
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

/** V47 closes pending rate resets and keeps decided ones as history. */
class RateResetRemovalMigrationDbTest {
    @Test
    fun `V47 cancels pending rate resets and drops the markers`() {
        requireDockerOrSkip()
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_v47"))
        Flyway.configure().dataSource(ds).target(MigrationVersion.fromVersion("46")).load().migrate()
        fun insert(sql: String): Long = ds.connection.use { c ->
            c.prepareStatement(sql).use { ps -> ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) } }
        }
        val pending = insert(
            "INSERT INTO access_request (principal, kind, reason, requested_duration_sec, creator_kind) VALUES ('alice', 'RATE_RESET', 'r', 0, 'WORKFLOW') RETURNING id",
        )
        val approved = insert(
            """INSERT INTO access_request (principal, kind, reason, requested_duration_sec, status, decided_by, decided_at, creator_kind)
               VALUES ('alice', 'RATE_RESET', 'r', 0, 'APPROVED', 'bob', now(), 'WORKFLOW') RETURNING id""",
        )

        Flyway.configure().dataSource(ds).load().migrate()

        fun column(sql: String, vararg args: Any): List<String> = ds.connection.use { c ->
            c.prepareStatement(sql).use { ps ->
                args.forEachIndexed { i, a -> ps.setObject(i + 1, a) }
                ps.executeQuery().use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } }
            }
        }
        assertEquals(listOf("CANCELLED"), column("SELECT status FROM access_request WHERE id = ?", pending))
        assertEquals(listOf("cancelled"), column("SELECT kind FROM request_event WHERE request_id = ?", pending))
        assertEquals(listOf("APPROVED"), column("SELECT status FROM access_request WHERE id = ?", approved))
        assertEquals(listOf("0"), column("SELECT count(*) FROM pg_tables WHERE tablename = 'result_rate_reset'"))
    }
}
