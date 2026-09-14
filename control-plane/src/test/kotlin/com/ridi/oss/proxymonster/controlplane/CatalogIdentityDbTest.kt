package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.pushedColumn
import com.ridi.oss.proxymonster.controlplane.support.snapshotOf
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.connectionInfo
import org.flywaydb.core.Flyway
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class CatalogIdentityDbTest {
    @Test
    fun `upgrade qualifies old rows and retarget cannot reuse old catalog classifications`() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_catalog_identity"))
        try {
            Flyway.configure().dataSource(dataSource).target("25").load().migrate()
            dataSource.connection.use { c ->
                c.createStatement().use { s ->
                    s.executeUpdate("INSERT INTO datasource(id,name,engine,host,port,db_name) VALUES (1,'mysql','mysql','h',3306,'shop'), (2,'pg','postgres','h',5432,'old')")
                    s.executeUpdate("INSERT INTO column_classification(datasource_id,schema_name,table_name,column_name,tags) VALUES (1,'shop','users','ssn','[\"pii\"]'), (2,'public','users','ssn','[\"pii\"]')")
                }
            }
            Flyway.configure().dataSource(dataSource).load().migrate()
            val store = DatasourceStore(dataSource)
            assertEquals("def", store.get(1)!!.currentCatalog)
            assertEquals("old", store.get(2)!!.currentCatalog)
            store.storePushedCatalog(1, listOf("shop"), 0, "8.0", snapshotOf(pushedColumn("shop", "users", "ssn", "text", 1, true)), currentCatalog = "def")
            store.storePushedCatalog(2, listOf("public"), null, "16.3", snapshotOf(pushedColumn("public", "users", "ssn", "text", 1, true)), currentCatalog = "old")
            assertEquals("def", store.catalog(1).columns.single().catalog)
            assertEquals("def", store.catalog(1).columns.single().classification!!.catalog)
            assertEquals("old", store.catalog(2).columns.single().classification!!.catalog)

            store.register("pg", Engine.POSTGRES, "h", 5432, "new", emptyList(), "", null, false)
            store.storePushedCatalog(2, listOf("public"), null, "16.3", snapshotOf(pushedColumn("public", "users", "ssn", "text", 1, true, catalog = "new")), currentCatalog = "new")
            val current = store.catalog(2).columns.single()
            assertEquals("new", current.catalog)
            assertNull(current.classification)
            assertEquals(listOf("pii"), store.classificationsFor(2).getValue(ColumnIdentity("old", "public", "users", "ssn")).tags)
            for (catalog in listOf("", "old")) {
                assertFailsWith<ManagementException> {
                    store.upsertClassification(2, ClassificationInput("public", "users", "ssn", listOf("pii"), catalog = catalog))
                }
                assertFailsWith<ManagementException> {
                    store.deleteClassification(2, "public", "users", "ssn", catalog)
                }
            }
            store.upsertClassification(2, ClassificationInput("public", "users", "ssn", listOf("current")))
            assertEquals(listOf("current"), store.catalog(2).columns.single().classification!!.tags)
            assertEquals(2, store.classificationsFor(2).size)
        } finally {
            (dataSource as AutoCloseable).close()
        }
    }

    @Test
    fun `stored column and classification joins keep catalog identity`() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_catalog_join"))
        try {
            Flyway.configure().dataSource(dataSource).load().migrate()
            val store = DatasourceStore(dataSource)
            val ds = store.create(DatasourceInput("joined", "postgres", dbName = "a"))
            dataSource.connection.use { c ->
                c.prepareStatement("UPDATE datasource SET catalog = ?, current_catalog_name = 'a' WHERE id = ?").use { ps ->
                    ps.setBytes(1, snapshotOf(
                        pushedColumn("schema.with.dot", "users", "ssn", "text", 1, true, catalog = "a"),
                        pushedColumn("schema.with.dot", "users", "ssn", "text", 1, true, catalog = "b"),
                    ).toByteArray())
                    ps.setLong(2, ds.id); ps.executeUpdate()
                }
                c.prepareStatement("INSERT INTO column_classification(datasource_id,catalog_name,schema_name,table_name,column_name,tags) VALUES (?,?,'schema.with.dot','users','ssn',?::jsonb)").use { ps ->
                    for (catalog in listOf("a", "b")) {
                        ps.setLong(1, ds.id); ps.setString(2, catalog); ps.setString(3, "[\"$catalog\"]"); ps.executeUpdate()
                    }
                }
            }
            val rows = store.catalog(ds.id).columns
            assertEquals(2, rows.size)
            assertEquals(mapOf("a" to listOf("a"), "b" to listOf("b")), rows.associate { it.catalog to it.classification!!.tags })
            assertEquals(2, store.classificationsFor(ds.id).size)
        } finally {
            (dataSource as AutoCloseable).close()
        }
    }

    @Test
    fun `connection info registration preserves absence and clears explicit empty`() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_connection_info"))
        try {
            Flyway.configure().dataSource(dataSource).load().migrate()
            val store = DatasourceStore(dataSource)
            fun register(info: com.ridi.oss.proxymonster.grpc.ConnectionInfo?) =
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
