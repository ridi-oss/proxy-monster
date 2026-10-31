package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ConnectionInfo
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.connectionInfo
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ConnectionInfoDbTest {
    @Test
    fun `registration preserves absence, clears explicit empty, refuses secrets, and names the database`() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_connection_info"))
        try {
            val store = DatasourceStore(dataSource)
            fun register(info: ConnectionInfo?) =
                store.register("native", Engine.MYSQL, "target:3306", emptyList(), "proxy.example:3307", null, false, info)
            val published = connectionInfo { endpoint = "proxy.example:3307"; properties["database"] = "shop" }
            assertEquals(published, register(published).connectionInfo)
            assertEquals(published, register(null).connectionInfo)
            assertEquals("shop", register(null).dbName)
            assertNull(register(null).withoutConnectionMaterial().connectionInfo)
            assertEquals("", register(null).withoutConnectionMaterial().dbName)
            assertEquals("", register(connectionInfo {}).connectionInfo!!.endpoint)
            assertFailsWith<ManagementException> { register(connectionInfo { endpoint = "user:secret@proxy.example:3307"; properties["database"] = "shop" }) }
            assertFailsWith<ManagementException> { register(connectionInfo { endpoint = "proxy.example:3307"; properties["password"] = "secret" }) }
            assertEquals("", store.getByName("native")!!.connectionInfo!!.endpoint)
        } finally {
            (dataSource as AutoCloseable).close()
        }
    }
}
