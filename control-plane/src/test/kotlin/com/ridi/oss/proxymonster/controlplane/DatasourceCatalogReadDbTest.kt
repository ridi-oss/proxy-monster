package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.pushedColumn
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.snapshotOf
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** What a catalog read returns: the pushed columns in order, each with its classification, and the system flags. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DatasourceCatalogReadDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var management: DatasourceManagementService
    private var id = 0L

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_catalog_read"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        management = DatasourceManagementService(
            core.datasourceStore, core.proxyEventsHub, TableDetailService(core), ManagementAuditRecorder(core.auditStore),
            core.connectionCatalog,
        )
        val store = core.datasourceStore
        id = store.create(DatasourceInput("catalog-read", "mysql", dbName = "shop")).id
        store.storePushedCatalog(
            id, listOf("shop"), 0, "8.0.36",
            snapshotOf(
                pushedColumn("shop", "users", "id", "bigint", 1, false, catalog = "def"),
                pushedColumn("shop", "users", "email", "varchar", 2, true, catalog = "def"),
                pushedColumn("shop", "users", "ssn", "char", 3, true, catalog = "def"),
                pushedColumn("shop", "orders", "id", "bigint", 1, false, catalog = "def"),
                pushedColumn("shop", "orders", "card", "varchar", 2, true, catalog = "def"),
                pushedColumn("information_schema", "TABLES", "TABLE_NAME", "varchar", 1, false, catalog = "def"),
            ),
            currentCatalog = "def",
        )
        val mask = core.policyStore.createMaskFn(MaskFnInput("catalog-read-last4", "LAST_N")).id
        store.upsertClassification(id, ClassificationInput("shop", "users", "email", listOf("pii"), catalog = "def"))
        store.upsertClassification(id, ClassificationInput("shop", "users", "ssn", listOf("pii", "national-id"), mask, catalog = "def"))
        store.upsertClassification(id, ClassificationInput("shop", "orders", "card", listOf("pci"), catalog = "def"))
    }

    @AfterAll
    fun teardown() {
        if (::dataSource.isInitialized) (dataSource as AutoCloseable).close()
    }

    private fun CatalogColumn.line() =
        "$catalog.$schema.$table.$column $dataType/$sqlType #$ordinal ${if (nullable) "null" else "not-null"} system=$system " +
            (classification?.let { "tags=${it.tags} mask=${it.maskFnName ?: "-"}" } ?: "unclassified")

    @Test
    fun `a catalog read returns every column with its classification`() {
        val catalog = core.datasourceStore.catalog(id)
        assertEquals(EXPECTED_CATALOG.trim(), catalog.columns.joinToString("\n") { it.line() })
        assertEquals(EXPECTED_BROWSE.trim(), management.browseCatalog("catalog-read").joinToString("\n") { it.line() })
    }
}

private const val EXPECTED_CATALOG = """
def.information_schema.TABLES.TABLE_NAME varchar/VARCHAR #1 not-null system=false unclassified
def.shop.orders.id bigint/BIGINT #1 not-null system=false unclassified
def.shop.orders.card varchar/VARCHAR #2 null system=false tags=[pci] mask=-
def.shop.users.id bigint/BIGINT #1 not-null system=false unclassified
def.shop.users.email varchar/VARCHAR #2 null system=false tags=[pii] mask=-
def.shop.users.ssn char/VARCHAR #3 null system=false tags=[pii, national-id] mask=catalog-read-last4
"""

private const val EXPECTED_BROWSE = """
def.information_schema.TABLES.TABLE_NAME varchar/VARCHAR #1 not-null system=true unclassified
def.shop.orders.id bigint/BIGINT #1 not-null system=false unclassified
def.shop.orders.card varchar/VARCHAR #2 null system=false tags=[pci] mask=-
def.shop.users.id bigint/BIGINT #1 not-null system=false unclassified
def.shop.users.email varchar/VARCHAR #2 null system=false tags=[pii] mask=-
def.shop.users.ssn char/VARCHAR #3 null system=false tags=[pii, national-id] mask=catalog-read-last4
"""
