package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.pushedColumn
import com.ridi.oss.proxymonster.controlplane.support.snapshotOf
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.Engine
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
            store.storePushedCatalog(1, listOf("shop"), 0, "8.0", snapshotOf(pushedColumn("shop", "users", "ssn", "text", 1, true, catalog = "def")), currentCatalog = "def")
            store.storePushedCatalog(2, listOf("public"), null, "16.3", snapshotOf(pushedColumn("public", "users", "ssn", "text", 1, true, catalog = "old")), currentCatalog = "old")
            assertEquals("def", store.catalog(1).columns.single().catalog)
            assertEquals("def", store.catalog(1).columns.single().classification!!.catalog)
            assertEquals("old", store.catalog(2).columns.single().classification!!.catalog)

            store.register("pg", Engine.POSTGRES, "h", 5432, "new", emptyList(), "", null, false)
            store.storePushedCatalog(2, listOf("public"), null, "16.3", snapshotOf(pushedColumn("public", "users", "ssn", "text", 1, true, catalog = "new")), currentCatalog = "new")
            val current = store.catalog(2).columns.single()
            assertEquals("new", current.catalog)
            assertNull(current.classification)
            assertEquals(listOf("pii"), store.classificationsFor(2).getValue(columnRef("old", "public", "users", "ssn")).tags)
            for (catalog in listOf("", "old")) {
                assertFailsWith<ManagementException> {
                    store.upsertClassification(2, ClassificationInput("public", "users", "ssn", listOf("pii"), catalog = catalog))
                }
                assertFailsWith<ManagementException> {
                    store.deleteClassification(2, "public", "users", "ssn", catalog)
                }
            }
            store.upsertClassification(2, ClassificationInput("public", "users", "ssn", listOf("current"), catalog = "new"))
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
    fun `classification keys are written in the canonical spelling decide joins on`() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_canonical_keys"))
        try {
            Flyway.configure().dataSource(dataSource).load().migrate()
            val store = DatasourceStore(dataSource)
            val mysql = store.create(DatasourceInput("shop", "mysql", dbName = "app"))
            store.storePushedCatalog(mysql.id, listOf("app"), 1, "8.0", snapshotOf(pushedColumn("app", "users", "ssn", "text", 1, true, catalog = "def")), currentCatalog = "def")
            val written = store.upsertClassification(mysql.id, ClassificationInput("App", "Users", "SSN", listOf("pii"), catalog = "def"))
            assertEquals(listOf("app", "users", "ssn"), listOf(written.schema, written.table, written.column))
            assertEquals(listOf("pii"), store.catalog(mysql.id).columns.single().classification!!.tags)
            assertEquals(true, store.deleteClassification(mysql.id, "APP", "users", "Ssn", "def"))

            val athena = store.create(DatasourceInput("lake", "athena", dbName = "hr"))
            store.storePushedCatalog(athena.id, listOf("hr"), null, "3", snapshotOf(pushedColumn("hr", "salaries", "ssn", "string", 1, true, catalog = "awsdatacatalog")), currentCatalog = "awsdatacatalog")
            store.upsertClassification(athena.id, ClassificationInput("HR", "Salaries", "SSN", listOf("pii"), catalog = "AwsDataCatalog"))
            assertEquals(listOf("pii"), store.catalog(athena.id).columns.single().classification!!.tags)

            val pg = store.create(DatasourceInput("pg", "postgres", dbName = "a"))
            store.storePushedCatalog(
                pg.id, listOf("public"), null, "16.3",
                snapshotOf(
                    pushedColumn("public", "users", "ssn", "text", 1, true, catalog = "a"),
                    pushedColumn("App", "T", "SSN", "text", 1, true, catalog = "a"),
                ),
                currentCatalog = "a",
            )
            val folded = store.upsertClassification(pg.id, ClassificationInput("public", "Users", "SSN", listOf("pii"), catalog = "a"))
            assertEquals(listOf("public", "users", "ssn"), listOf(folded.schema, folded.table, folded.column), "unquoted folds")
            val quoted = store.upsertClassification(pg.id, ClassificationInput("\"App\"", "\"T\"", "\"SSN\"", listOf("pii"), catalog = "a"))
            assertEquals(listOf("App", "T", "SSN"), listOf(quoted.schema, quoted.table, quoted.column), "quoted stays exact")
            assertEquals(listOf(listOf("pii"), listOf("pii")), store.catalog(pg.id).columns.map { it.classification?.tags })
            assertFailsWith<ManagementException> {
                store.upsertClassification(pg.id, ClassificationInput("public", "a b", "c", listOf("pii"), catalog = "a"))
            }

            // A browsed Postgres name sent quoted, the way the console sends it, keys the exact catalog row.
            val shop = store.create(DatasourceInput("browsed", "postgres", dbName = "Shop"))
            store.storePushedCatalog(
                shop.id, listOf("public"), null, "16.3",
                snapshotOf(
                    pushedColumn("public", "Users", "SSN", "text", 1, true, catalog = "Shop"),
                    pushedColumn("public", "a\"b", "c", "text", 1, true, catalog = "Shop"),
                ),
                currentCatalog = "Shop",
            )
            val q = { name: String -> shop.engine.definition.quoteIdentifier(name) }
            for ((table, column) in listOf("Users" to "SSN", "a\"b" to "c")) {
                store.upsertClassification(shop.id, ClassificationInput(q("public"), q(table), q(column), listOf("pii"), catalog = q("Shop")))
            }
            assertEquals(listOf(listOf("pii"), listOf("pii")), store.catalog(shop.id).columns.map { it.classification?.tags })
            assertFailsWith<ManagementException> {
                store.upsertClassification(shop.id, ClassificationInput("public", "Users", "SSN", listOf("pii"), catalog = "Shop"))
            }

            val unintrospected = store.create(DatasourceInput("fresh", "mysql", dbName = "app"))
            val refused = assertFailsWith<ManagementException> {
                store.upsertClassification(unintrospected.id, ClassificationInput("app", "users", "ssn", listOf("pii"), catalog = "def"))
            }
            assertEquals("datasource.case_mode_unknown", refused.error.code)
            for ((mode, expected) in listOf(0 to listOf("App", "Users", "ssn"), 2 to listOf("app", "users", "ssn"))) {
                val ds = store.create(DatasourceInput("mysql$mode", "mysql", dbName = "App"))
                store.storePushedCatalog(ds.id, listOf("App"), mode, "8.0", snapshotOf(), currentCatalog = "def")
                val key = store.upsertClassification(ds.id, ClassificationInput("App", "Users", "SSN", listOf("pii"), catalog = "def"))
                assertEquals(expected, listOf(key.schema, key.table, key.column), "lower_case_table_names=$mode")
            }
        } finally {
            (dataSource as AutoCloseable).close()
        }
    }
}
