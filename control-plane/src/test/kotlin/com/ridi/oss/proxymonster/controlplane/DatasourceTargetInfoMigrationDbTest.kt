package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.MigrationVersion
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/** V52 replaces a datasource's host and port with target_info. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DatasourceTargetInfoMigrationDbTest {
    @BeforeAll
    fun requireDatabase() {
        requireDockerOrSkip()
    }

    @Test
    fun `V52 backfills target info from the host and port`() {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_v52"))
        Flyway.configure().dataSource(ds).target(MigrationVersion.fromVersion("51")).load().migrate()
        ds.connection.use { c ->
            c.createStatement().use {
                it.execute("INSERT INTO datasource (name, engine, host, port, db_name) VALUES ('registered', 'mysql', 'db.internal', 3306, 'app'), ('blank', 'mysql', '', 0, '')")
            }
        }

        Flyway.configure().dataSource(ds).load().migrate()

        val targetInfo = ds.connection.use { c ->
            c.createStatement().use { s ->
                s.executeQuery("SELECT name, target_info FROM datasource ORDER BY name").use { rs ->
                    buildMap { while (rs.next()) put(rs.getString(1), rs.getString(2)) }
                }
            }
        }
        assertEquals(mapOf("blank" to "", "registered" to "db.internal:3306"), targetInfo)
    }
}
