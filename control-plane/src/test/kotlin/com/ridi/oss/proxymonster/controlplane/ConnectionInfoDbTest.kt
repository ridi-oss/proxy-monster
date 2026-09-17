package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ConnectionInfo
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.connectionInfo
import org.flywaydb.core.Flyway
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ConnectionInfoDbTest {
    @Test
    fun `registration preserves absence, clears explicit empty, and refuses secrets`() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_connection_info"))
        try {
            Flyway.configure().dataSource(dataSource).load().migrate()
            val store = DatasourceStore(dataSource)
            fun register(info: ConnectionInfo?) =
                store.register("native", Engine.MYSQL, "target", 3306, "shop", emptyList(), "proxy.example:3307", null, false, info)
            val published = connectionInfo { endpoint = "proxy.example:3307" }
            assertEquals(published, register(published).connectionInfo)
            assertEquals(published, register(null).connectionInfo)
            assertNull(register(null).withoutConnectionMaterial().connectionInfo)
            assertEquals("", register(connectionInfo {}).connectionInfo!!.endpoint)
            assertFailsWith<ManagementException> { register(connectionInfo { endpoint = "user:secret@proxy.example:3307" }) }
            assertFailsWith<ManagementException> { register(connectionInfo { endpoint = "proxy.example:3307"; properties["password"] = "secret" }) }
            assertEquals("", store.getByName("native")!!.connectionInfo!!.endpoint)
        } finally {
            (dataSource as AutoCloseable).close()
        }
    }
}
