package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.catalogSnapshot
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.canonicalColumns
import com.ridi.oss.proxymonster.controlplane.support.pushedColumn
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.Engine
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** Athena folds every name; the canonical spelling is the analyzer's. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IdentifierCaseAthenaDbTest {
    private lateinit var store: DatasourceStore
    private val counter = AtomicInteger()

    private val raw = listOf("SSN", "İsim", "Straße").mapIndexed { i, column ->
        pushedColumn("HR", "Salaries", column, "varchar", i + 1, true, catalog = "AwsDataCatalog")
    }
    private val canonical = canonicalColumns(Engine.ATHENA, "3", null, raw)

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        val metadata = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_names_athena"))
        store = DatasourceStore(metadata)
    }

    private fun datasource(): Datasource {
        val created = store.create(DatasourceInput("names-athena-${counter.incrementAndGet()}", "athena", "", 0, "AwsDataCatalog"))
        store.storePushedCatalog(
            id = created.id,
            defaultSchemas = listOf(canonical.first().schema),
            mysqlLowerCaseTableNames = null,
            engineVersion = "3",
            catalog = catalogSnapshot { columns.addAll(canonical) },
            currentCatalog = canonical.first().catalog,
        )
        return checkNotNull(store.get(created.id))
    }

    private fun assertAttached(catalog: String, schema: String, table: String, column: String, rawIndex: Int) {
        val ds = datasource()
        store.upsertClassification(ds.id, ClassificationInput(schema, table, column, listOf("pii"), null, catalog))
        val target = canonical[rawIndex]
        val row = store.catalog(ds.id).columns.single {
            it.catalog == target.catalog && it.schema == target.schema && it.table == target.table && it.column == target.column
        }
        assertEquals(listOf("pii"), assertNotNull(row.classification, "$catalog.$schema.$table.$column did not attach to $target").tags)
    }

    @Test
    fun `the analyzer folds the introspected rows`() {
        assertEquals(listOf("awsdatacatalog"), canonical.map { it.catalog }.distinct())
        assertEquals(listOf("hr.salaries.ssn"), canonical.take(1).map { "${it.schema}.${it.table}.${it.column}" })
    }

    @Test
    fun `a classification in canonical spelling attaches`() {
        val c = canonical[0]
        assertAttached(c.catalog, c.schema, c.table, c.column, 0)
    }

    @Test
    fun `a mixed-case classification attaches to the canonical column`() = assertAttached(canonical[0].catalog, "HR", "Salaries", "SSN", 0)

    @Test
    fun `a mixed-case catalog name attaches to the canonical column`() = assertAttached("AwsDataCatalog", "HR", "Salaries", "SSN", 0)

    @Test
    fun `a non-ASCII classification attaches to the canonical column`() {
        assertAttached(canonical[1].catalog, "HR", "Salaries", "İsim", 1)
    }

    @Test
    fun `a sharp-s classification attaches to the canonical column`() {
        assertAttached(canonical[2].catalog, "hr", "salaries", "STRAẞE", 2)
    }
}
