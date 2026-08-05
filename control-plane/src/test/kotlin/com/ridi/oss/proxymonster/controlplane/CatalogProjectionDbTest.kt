package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The persisted half of the manager: `catalog_column` written per schema, versioned by `catalog_schema`,
 * with deletion licensed only by a reading that enumerated the whole server.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CatalogProjectionDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var store: DatasourceStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_catalog_projection"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        store = DatasourceStore(dataSource)
    }

    private fun datasource(name: String): Datasource =
        store.create(DatasourceInput(name = name, engine = "mysql", host = "h", port = 3306, dbName = "app"))

    private fun column(schema: String, table: String, column: String) =
        DatasourceStore.PushedColumn(schema, table, column, "bigint", 1, false)

    private fun version(hash: String, clock: Long, backend: String = "srv") =
        ReadingVersion(ContentHash(ByteString.copyFromUtf8(hash)), clock, backend)

    private fun schemasOf(id: Long): Set<String> = store.catalog(id).map { it.schema }.toSet()

    private fun storedVersion(id: Long, schema: String): Pair<String, Long>? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT hash, db_clock_micros FROM catalog_schema WHERE datasource_id = ? AND schema_name = ?").use { ps ->
            ps.setLong(1, id); ps.setString(2, schema)
            ps.executeQuery().use { rs -> if (rs.next()) String(rs.getBytes(1)) to rs.getLong(2) else null }
        }
    }

    @Test
    fun `a reading replaces only the schemas it spoke for`() {
        // The readings are per schema, so the write must be too. A whole-table delete-and-insert would make
        // every reading speak for every schema — one connection's measurement of `app` would erase `other`.
        val ds = datasource("proj-scoped")
        store.projectCatalogSchemas(
            ds.id,
            listOf(
                ProjectedObservation("app", listOf(column("app", "users", "id")), version("h-app", 100)),
                ProjectedObservation("other", listOf(column("other", "logs", "id")), version("h-other", 100)),
            ),
            namespaceComplete = false,
            namespace = null,
        )
        assertEquals(setOf("app", "other"), schemasOf(ds.id))

        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", listOf(column("app", "users", "renamed")), version("h-app2", 200))),
            namespaceComplete = false,
            namespace = null,
        )

        assertEquals(setOf("app", "other"), schemasOf(ds.id), "a scoped reading must leave its siblings alone")
        assertEquals(listOf("renamed"), store.catalog(ds.id).filter { it.schema == "app" }.map { it.column })
        assertEquals(listOf("id"), store.catalog(ds.id).filter { it.schema == "other" }.map { it.column })
    }

    @Test
    fun `an older reading does not overwrite the stored rows`() {
        // The same ordering rule the in-memory pointer follows, applied to the rows browse and the
        // classification joins read: a slow scan that arrives late must not replace newer stored columns.
        val ds = datasource("proj-stale")
        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", listOf(column("app", "users", "new")), version("h-new", 101))),
            namespaceComplete = false,
            namespace = null,
        )

        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", listOf(column("app", "users", "stale")), version("h-old", 100))),
            namespaceComplete = false,
            namespace = null,
        )

        assertEquals(listOf("new"), store.catalog(ds.id).map { it.column }, "the older reading must be dropped")
        assertEquals("h-new" to 101L, storedVersion(ds.id, "app"), "and the version must still describe the stored rows")
    }

    @Test
    fun `a newer reading replaces the rows and the version together`() {
        val ds = datasource("proj-newer")
        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", listOf(column("app", "users", "old")), version("h-old", 100))),
            namespaceComplete = false,
            namespace = null,
        )
        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", listOf(column("app", "users", "new")), version("h-new", 200))),
            namespaceComplete = false,
            namespace = null,
        )

        assertEquals(listOf("new"), store.catalog(ds.id).map { it.column })
        assertEquals("h-new" to 200L, storedVersion(ds.id, "app"))
    }

    @Test
    fun `only a namespace-complete reading deletes an absent schema`() {
        val ds = datasource("proj-delete")
        store.projectCatalogSchemas(
            ds.id,
            listOf(
                ProjectedObservation("app", listOf(column("app", "users", "id")), version("h-app", 100)),
                ProjectedObservation("dropped", listOf(column("dropped", "t", "c")), version("h-drop", 100)),
            ),
            namespaceComplete = true,
            namespace = null,
        )
        assertEquals(setOf("app", "dropped"), schemasOf(ds.id))

        // A SCOPED reading omitting `dropped` says nothing about it — a privilege-filtered account reads a
        // strict subset, and deleting on that would erase every schema it cannot see.
        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", listOf(column("app", "users", "id")), version("h-app", 200))),
            namespaceComplete = false,
            namespace = null,
        )
        assertEquals(setOf("app", "dropped"), schemasOf(ds.id), "a scoped reading must never imply deletion")

        // The same omission from a reading that enumerated the whole server IS the schema being gone.
        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", listOf(column("app", "users", "id")), version("h-app", 300))),
            namespaceComplete = true,
            namespace = null,
        )
        assertEquals(setOf("app"), schemasOf(ds.id))
        assertNull(storedVersion(ds.id, "dropped"), "the version goes with the rows")
    }

    @Test
    fun `an unversioned reading lands and leaves nothing to order against`() {
        // An older proxy sends no hashes. Its columns are still the catalog, so they are stored; recording a
        // version would invent an ordering claim the reading never made.
        val ds = datasource("proj-unversioned")
        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", listOf(column("app", "users", "id")), version = null)),
            namespaceComplete = false,
            namespace = null,
        )

        assertEquals(listOf("id"), store.catalog(ds.id).map { it.column })
        assertNull(storedVersion(ds.id, "app"))
    }

    @Test
    fun `a version-only reading records the version without touching the rows`() {
        // The economy form: a reading that confirms a schema's hash without re-sending its columns. Treating
        // its silence as "no columns" would empty a schema that never changed.
        val ds = datasource("proj-version-only")
        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", listOf(column("app", "users", "id")), version("h1", 100))),
            namespaceComplete = false,
            namespace = null,
        )

        store.projectCatalogSchemas(
            ds.id,
            listOf(ProjectedObservation("app", columns = null, version = version("h1", 200))),
            namespaceComplete = false,
            namespace = null,
        )

        assertEquals(listOf("id"), store.catalog(ds.id).map { it.column }, "the rows must survive a version-only reading")
        assertEquals("h1" to 200L, storedVersion(ds.id, "app"))
    }

    @Test
    fun `the whole-catalog writer still replaces everything and stamps the namespace`() {
        // storePushedCatalog is now expressed through the per-schema projection; its callers still hand it
        // the complete column set and expect the whole catalog replaced.
        val ds = datasource("proj-whole")
        store.storePushedCatalog(
            ds.id,
            defaultSchemas = listOf("app"),
            mysqlLowerCaseTableNames = 0,
            engineVersion = "8.4.0",
            columns = listOf(column("app", "users", "id"), column("gone", "t", "c")),
        )
        assertEquals(setOf("app", "gone"), schemasOf(ds.id))

        store.storePushedCatalog(
            ds.id,
            defaultSchemas = listOf("app"),
            mysqlLowerCaseTableNames = 0,
            engineVersion = "8.4.0",
            columns = listOf(column("app", "users", "id")),
        )

        assertEquals(setOf("app"), schemasOf(ds.id))
        val refreshed = store.get(ds.id)!!
        assertEquals(listOf("app"), refreshed.defaultSchemas)
        assertEquals("8.4.0", refreshed.engineVersion)
        assertTrue(refreshed.catalogSyncedAt != null)
    }
}
