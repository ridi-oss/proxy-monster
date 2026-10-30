package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.MigrationVersion
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/** V51 splits the prefixed content hash into content_hash and raw_hash and rekeys GitHub rows to match [changeKey]. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RequestRawHashMigrationDbTest {
    @BeforeAll
    fun requireDatabase() {
        requireDockerOrSkip()
    }

    @Test
    fun `V51 drops the hash prefix and rekeys GitHub rows`() {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_v51"))
        Flyway.configure().dataSource(ds).target(MigrationVersion.fromVersion("50")).load().migrate()
        val normalized = "a".repeat(64)
        val raw = "b".repeat(64)
        val datasource = ds.connection.use { c ->
            c.prepareStatement("INSERT INTO datasource (name, engine, host, port, db_name) VALUES ('ds', 'mysql', 'h', 3306, 'd') RETURNING id")
                .use { ps -> ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) } }
        }
        fun insert(source: String, fileKey: String?, hash: String?): Long = ds.connection.use { c ->
            c.prepareStatement(
                """INSERT INTO access_request (principal, kind, creator_kind, requested_duration_sec, datasource_id, source, file_key, content_hash, change_key)
                   VALUES ('alice', 'QUERY', 'WORKFLOW', 0, ?, ?, ?, ?, 'old') RETURNING id""",
            ).use { ps ->
                ps.setLong(1, datasource)
                ps.setString(2, source)
                ps.setString(3, fileKey)
                ps.setString(4, hash)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
        }
        val githubNormalized = insert("github", "0042", "n:$normalized")
        val githubRaw = insert("github", "0043", "r:$raw")
        val console = insert("console", null, "r:$raw")

        Flyway.configure().dataSource(ds).load().migrate()

        fun row(id: Long): List<String?> = ds.connection.use { c ->
            c.prepareStatement("SELECT content_hash, raw_hash, change_key FROM access_request WHERE id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs -> rs.next(); listOf(rs.getString(1), rs.getString(2), rs.getString(3)) }
            }
        }
        assertEquals(listOf(normalized, null, changeKey("0042", normalized, "unused")), row(githubNormalized))
        assertEquals(listOf(null, raw, changeKey("0043", null, raw)), row(githubRaw))
        assertEquals(listOf(null, raw, "old"), row(console))
    }
}
