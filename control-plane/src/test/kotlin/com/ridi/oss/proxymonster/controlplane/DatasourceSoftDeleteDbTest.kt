package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ControlEvent
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.column
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import com.google.protobuf.ByteString
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Deleting a datasource is a soft delete: the row is stamped `deleted_at`, not removed, so the
 * access_request / query_result / audit_event history that references it survives — and the referencing
 * foreign key that a hard delete could not satisfy is never touched. A soft-deleted row is invisible to
 * every read, and its name is freed for a new datasource to reuse.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DatasourceSoftDeleteDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var store: DatasourceStore
    private lateinit var datasources: DatasourceManagementService

    private val actor = AuditActor("soft-delete-admin@example.com", channel = AuditSource.CONSOLE)

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_ds_soft_delete"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        store = core.datasourceStore
        datasources = DatasourceManagementService(
            core.datasourceStore, core.proxyEventsHub, TableDetailService(core), ManagementAuditRecorder(core.auditStore),
            core.connectionCatalog,
        )
    }

    @AfterAll
    fun close() {
        (dataSource as? AutoCloseable)?.close()
    }

    @Test
    fun `deleting a datasource with access-request history soft-deletes it and keeps the rows`() {
        val name = "soft-del-history-${System.nanoTime()}"
        val ds = datasources.createDatasource(DatasourceInput(name, "mysql"), actor)
        // A QUERY task pins the access_request -> datasource foreign key; a hard delete cannot satisfy it.
        insertQueryRequest(ds.id, principal = "requester@example.com")

        val result = datasources.deleteDatasource(ds.id, actor)

        assertTrue(result.deleted, "delete succeeds despite the referencing access_request row")
        assertNull(store.get(ds.id), "a soft-deleted datasource is invisible to reads")
        assertEquals(0, store.list().count { it.id == ds.id }, "and absent from the list")
        assertEquals(
            1,
            rawCount("SELECT count(*) FROM datasource WHERE id = ? AND deleted_at IS NOT NULL", ds.id),
            "the row survives, stamped deleted",
        )
        assertEquals(
            1,
            rawCount("SELECT count(*) FROM access_request WHERE datasource_id = ?", ds.id),
            "its access-request history is retained for audit",
        )
        assertEquals(
            1,
            rawCount("SELECT count(*) FROM audit_event WHERE statement = ?", "delete datasource '$name'"),
            "the delete itself is audited",
        )
        // A second delete of the same id is a no-op (already gone), not a spurious success.
        assertEquals(false, datasources.deleteDatasource(ds.id, actor).deleted)
    }

    @Test
    fun `a soft-deleted name is free for a new datasource to reuse`() {
        val name = "soft-del-reuse-${System.nanoTime()}"
        val first = datasources.createDatasource(DatasourceInput(name, "mysql"), actor)
        assertTrue(datasources.deleteDatasource(first.id, actor).deleted)

        // The admin create surface reuses the freed name as a fresh datasource.
        val second = datasources.createDatasource(DatasourceInput(name, "mysql"), actor)
        assertNotEquals(first.id, second.id)
        assertEquals(second.id, store.getByName(name)?.id, "the live name resolves to the new datasource")

        // ...and so does a proxy self-registering the same name (the ON CONFLICT arbiter is live-only).
        assertTrue(datasources.deleteDatasource(second.id, actor).deleted)
        val third = store.register(
            name = name, engine = Engine.MYSQL, host = "db.internal", port = 3306, dbName = "app",
            tags = emptyList(), advertiseAddr = "", advertiseCertChain = null, advertiseWireTls = false,
        )
        assertNotEquals(second.id, third.id)
        assertEquals(third.id, store.getByName(name)?.id)
    }

    @Test
    fun `a soft-deleted datasource keeps its name and tags for historical-task authorization and audit`() {
        val name = "soft-del-retain-${System.nanoTime()}"
        // Register with a posture tag so the retained-tags property is observable — a task's lifecycle Cedar
        // check must still see `system:production` after the datasource is gone, not empty tags.
        val ds = store.register(
            name = name, engine = Engine.MYSQL, host = "db", port = 3306, dbName = "app",
            tags = listOf("system:production"), advertiseAddr = "", advertiseCertChain = null, advertiseWireTls = false,
        )
        assertTrue(datasources.deleteDatasource(ds.id, actor).deleted)

        assertNull(store.get(ds.id), "live reads exclude it")
        val retained = store.getIncludingDeleted(ds.id)
        assertNotNull(retained, "but a historical task can still resolve it by id")
        assertEquals(name, retained.name, "so audit keeps the name")
        assertEquals(listOf("system:production"), retained.tags, "and lifecycle authz keeps the original tags")
    }

    @Test
    fun `delete is refused while a proxy is attached`() {
        val name = "soft-del-attached-${System.nanoTime()}"
        val ds = datasources.createDatasource(DatasourceInput(name, "mysql"), actor)
        val channel = Channel<ControlEvent>(capacity = 1)
        core.proxyEventsHub.register(name, channel)

        val e = assertFailsWith<ManagementException> { datasources.deleteDatasource(ds.id, actor) }
        assertEquals("datasource.in_use_proxy_attached", e.error.code)
        assertNotNull(store.get(ds.id), "the datasource is untouched when the delete is refused")

        // Once the proxy detaches, the delete proceeds.
        core.proxyEventsHub.deregister(name, channel)
        assertTrue(datasources.deleteDatasource(ds.id, actor).deleted)
    }

    @Test
    fun `the in-flight guard blocks non-terminal query work but not approved or terminal work`() {
        // Non-terminal work still bound to the datasource blocks the delete.
        for (status in listOf("PENDING", "EXECUTING")) {
            val ds = datasources.createDatasource(DatasourceInput("guard-block-$status-${System.nanoTime()}", "mysql"), actor)
            insertQueryRequest(ds.id, principal = "r@example.com", status = status)
            val e = assertFailsWith<ManagementException> { datasources.deleteDatasource(ds.id, actor) }
            assertEquals("datasource.in_use_active_requests", e.error.code, "$status must block")
            assertNotNull(store.get(ds.id))
        }
        // An APPROVED query has no cancellation transition, so blocking on it would make the datasource
        // permanently undeletable — it must NOT block (deleting strands it fail-closed). Terminal history
        // never blocks — it is exactly what the soft delete retains.
        for (status in listOf("APPROVED", "EXECUTED", "CANCELLED")) {
            val ds = datasources.createDatasource(DatasourceInput("guard-pass-$status-${System.nanoTime()}", "mysql"), actor)
            insertQueryRequest(ds.id, principal = "r@example.com", status = status)
            assertTrue(datasources.deleteDatasource(ds.id, actor).deleted, "$status must not block")
        }
    }

    @Test
    fun `deleting a datasource drops its name-keyed enforcement catalog so a reused name re-measures`() = runBlocking {
        val name = "soft-del-catalog-${System.nanoTime()}"
        val ds = datasources.createDatasource(DatasourceInput(name, "mysql"), actor)
        // Seed the in-memory authoritative catalog for this datasource's name, as a proxy push would.
        val opened = core.connectionCatalog.open(Binding(name, "principal", "USER"), listOf("app"))
        core.connectionCatalog.applyPush(
            schemaFragmentPush {
                connectionId = opened.connectionId
                datasourceName = name
                schema = "app"
                contentHash = ByteString.copyFromUtf8("h1")
                backendGeneration = 1
                columns.add(column {
                    this.schema = "app"; table = "users"; column = "id"
                    dataType = "bigint"; ordinal = 1; nullable = false
                })
            },
            ds,
        )
        assertNotNull(core.connectionCatalog.authoritativeFor(name, "app"), "seeded")

        assertTrue(datasources.deleteDatasource(ds.id, actor).deleted)

        assertNull(
            core.connectionCatalog.authoritativeFor(name, "app"),
            "delete drops the name-keyed authoritative catalog",
        )
        // A new connection on the freed name must therefore re-measure its own target DB, not adopt the drop.
        val reused = core.connectionCatalog.open(Binding(name, "after", "USER"), listOf("app"), adoptHeldContent = true)
        assertEquals(
            listOf("app"),
            reused.onOpen.map { it.schema },
            "the reused name has no held structure to adopt",
        )
    }

    private fun insertQueryRequest(datasourceId: Long, principal: String, status: String = "EXECUTED") {
        dataSource.connection.use { c ->
            c.prepareStatement(
                "INSERT INTO access_request (kind, principal, datasource_id, status) VALUES ('QUERY', ?, ?, ?)",
            ).use { ps ->
                ps.setString(1, principal)
                ps.setLong(2, datasourceId)
                ps.setString(3, status)
                ps.executeUpdate()
            }
        }
    }

    private fun rawCount(sql: String, vararg params: Any): Int = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps ->
            params.forEachIndexed { i, p -> ps.setObject(i + 1, p) }
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }
}
