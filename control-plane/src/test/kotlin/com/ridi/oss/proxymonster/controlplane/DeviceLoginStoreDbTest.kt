package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DeviceLoginStoreDbTest {
    @Test
    fun `purgeExpired removes only expired rows`() {
        requireDockerOrSkip()
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_device_login"))
        Flyway.configure().dataSource(ds).load().migrate()
        ds.connection.use { c ->
            c.createStatement().use { st ->
                st.execute(
                    """INSERT INTO device_login (handle, ttl_seconds, expires_at) VALUES
                       ('live', 3600, now() + interval '10 minutes'), ('dead', 3600, now() - interval '1 second')""",
                )
            }
        }

        assertTrue(DeviceLoginStore(ds).purgeExpired() >= 1)

        val left = ds.connection.use { c ->
            c.createStatement().use { st ->
                st.executeQuery("SELECT handle FROM device_login").use { rs -> buildSet { while (rs.next()) add(rs.getString(1)) } }
            }
        }
        assertEquals(setOf("live"), left)
    }
}
