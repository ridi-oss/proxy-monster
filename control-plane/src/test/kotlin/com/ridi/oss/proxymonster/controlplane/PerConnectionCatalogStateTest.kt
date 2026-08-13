package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.column
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import io.grpc.Status
import kotlinx.coroutines.runBlocking
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PerConnectionCatalogStateTest {
    private val ds = Datasource(
        1, "ds", Engine.MYSQL, "", 0, "app", defaultSchemas = listOf("app"),
        mysqlLowerCaseTableNames = 0, engineVersion = "8.4.0",
    )

    private fun push(
        opened: OpenConnection,
        schema: String,
        hash: String,
        generation: Long = 1,
        unchanged: Boolean = false,
        columnName: String = "id",
    ) = schemaFragmentPush {
        connectionId = opened.connectionId
        datasourceName = ds.name
        this.schema = schema
        contentHash = ByteString.copyFromUtf8(hash)
        this.unchanged = unchanged
        backendGeneration = generation
        if (!unchanged) {
            columns.add(column {
                this.schema = schema; table = "users"; column = columnName
                dataType = "bigint"; ordinal = 1; nullable = false
            })
        }
    }

    @Test
    fun `minted ids are 16 bytes and collisions retry`() {
        val values = ArrayDeque(listOf(ByteArray(16), ByteArray(16), ByteArray(16) { 1 }))
        val random = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                values.removeFirst().copyInto(bytes)
            }
        }
        val registry = ConnectionCatalogRegistry(secureRandom = random)
        val first = registry.open(Binding("ds", "a", "USER"), listOf("app"))
        val second = registry.open(Binding("ds", "b", "USER"), listOf("app"))
        assertEquals(16, first.connectionId.size())
        assertEquals(16, second.connectionId.size())
        assertNotEquals(first.connectionId, second.connectionId)
    }

    @Test
    fun `pending is the push CAS and replay cannot regress authoritative`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "p", "USER"), listOf("app"))
        assertEquals(1, (registry.applyPush(push(opened, "app", "z"), ds) as CatalogMutationResult.Applied).generation)
        val replay = registry.applyPush(push(opened, "app", "a"), ds) as CatalogMutationResult.Rejected
        assertEquals(Status.Code.FAILED_PRECONDITION, replay.code)
        assertEquals("z", registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8())
    }

    @Test
    fun `backend generation binds and old pushes reject`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "p", "USER"), listOf("app"))
        registry.applyPush(push(opened, "app", "h1", generation = 5), ds)
        val connection = registry.find(opened.connectionId)!!
        registry.markAfterStatement(connection, listOf("app"))
        val rejected = registry.applyPush(push(opened, "app", "h2", generation = 4), ds) as CatalogMutationResult.Rejected
        assertEquals(Status.Code.FAILED_PRECONDITION, rejected.code)
        assertEquals("h1", connection.held.getValue("app").hash.bytes.toStringUtf8())
    }

    @Test
    fun `authoritative ordering follows accepted observation order including revert`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val one = registry.open(Binding(ds.name, "one", "USER"), listOf("app"))
        registry.applyPush(push(one, "app", "z"), ds)
        val epoch1 = registry.authoritativeFor(ds.name, "app")!!.epoch
        val two = registry.open(Binding(ds.name, "two", "USER"), listOf("app"))
        registry.applyPush(push(two, "app", "a"), ds)
        val epoch2 = registry.authoritativeFor(ds.name, "app")!!.epoch
        val three = registry.open(Binding(ds.name, "three", "USER"), listOf("app"))
        registry.applyPush(push(three, "app", "z"), ds)
        assertTrue(epoch2 > epoch1)
        assertEquals("z", registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8())
        assertTrue(registry.authoritativeFor(ds.name, "app")!!.epoch > epoch2)
    }

    @Test
    fun `a hash marker quiets one authoritative version and retriggers on the next`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val held = registry.open(Binding(ds.name, "held", "USER"), listOf("app"))
        registry.applyPush(push(held, "app", "h1"), ds)
        val sibling = registry.open(Binding(ds.name, "sibling", "USER"), listOf("app"))
        registry.applyPush(push(sibling, "app", "h2"), ds)

        val connection = registry.find(held.connectionId)!!
        assertEquals(setOf("app"), registry.freshnessGate(connection, listOf("app")))
        registry.markBeforeDecide(connection, listOf("app"))
        registry.applyPush(push(held, "app", "h1", unchanged = true), ds)
        assertTrue(registry.freshnessGate(connection, listOf("app")).isEmpty())

        val third = registry.open(Binding(ds.name, "third", "USER"), listOf("app"))
        registry.applyPush(push(third, "app", "h3"), ds)
        assertEquals(setOf("app"), registry.freshnessGate(connection, listOf("app")))
    }

    @Test
    fun `unchanged adoption shares pooled fragment and refreshes staleness clock`() = runBlocking {
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 10)
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1"), ds)
        val key = registry.find(first.connectionId)!!.held.getValue("app").pooledRef
        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"))
        now = 20
        registry.applyPush(push(second, "app", "h1", unchanged = true), ds)
        assertEquals(3, registry.pooledFor(key)!!.refCount) // authoritative + two connections
        assertTrue(registry.freshnessGate(registry.find(second.connectionId)!!, listOf("app")).isEmpty())
        now = 31
        assertEquals(setOf("app"), registry.freshnessGate(registry.find(second.connectionId)!!, listOf("app")))
    }

    @Test
    fun `adopting held content opens with no fetch and decides immediately`() = runBlocking {
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 100)
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        assertEquals(listOf("app"), first.onOpen.map { it.schema }) // nothing held yet: it must fetch
        registry.applyPush(push(first, "app", "h1"), ds)

        now = 10
        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"), adoptHeldContent = true)
        assertTrue(second.onOpen.isEmpty(), "an adopting connection must not be sent a refetch")
        val connection = registry.find(second.connectionId)!!
        assertEquals("h1", connection.held.getValue("app").hash.bytes.toStringUtf8())
        assertTrue(connection.pending.isEmpty())
        // The point of adopting: the first statement decides without waiting on the target DB.
        assertTrue(registry.freshnessGate(connection, listOf("app")).isEmpty())
    }

    @Test
    fun `adoption inherits the original measurement time so staleness still fires`() = runBlocking {
        // Adopting must not restart the staleness clock. If it did, a stream of new connections would keep
        // content alive indefinitely without anyone re-reading the target DB, and the bound could never fire.
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 10)
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1"), ds) // measured at now = 0

        now = 9
        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"), adoptHeldContent = true)
        val connection = registry.find(second.connectionId)!!
        assertTrue(registry.freshnessGate(connection, listOf("app")).isEmpty(), "still inside the window")

        now = 11 // past staleness measured from the ORIGINAL read, not from adoption
        assertEquals(
            setOf("app"),
            registry.freshnessGate(connection, listOf("app")),
            "adopted content must go stale on the original measurement's clock",
        )
    }

    @Test
    fun `an ambient refresh re-measures pooled content so adopters stay fresh`() = runBlocking {
        // The staleness ceiling sits above the ambient refresh interval on the premise that the refresh
        // itself keeps pooled content verified. Without that, content pooled once would age out no matter
        // how recently the target DB was read, and every new session would refetch.
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 10)
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1"), ds)

        now = 8
        val confirmed = registry.recordAmbientMeasurement(
            ds.name,
            mapOf("app" to listOf(FragmentColumn("app", "users", "id", "bigint", 1, false))),
        )
        assertEquals(setOf("app"), confirmed)

        now = 15 // past the original measurement, inside the window from the ambient one
        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"), adoptHeldContent = true)
        assertTrue(second.onOpen.isEmpty())
        assertTrue(
            registry.freshnessGate(registry.find(second.connectionId)!!, listOf("app")).isEmpty(),
            "the ambient re-measurement must reset the staleness clock for later adopters",
        )
    }

    @Test
    fun `an ambient refresh whose columns differ never overwrites pooled content`() = runBlocking {
        // Confirmation only. Divergence belongs to the connection's own probe, which alone knows what that
        // connection's target DB binds; installing a differing ambient read here would decide against a
        // catalog no connection measured.
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 10)
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1"), ds)

        now = 8
        val confirmed = registry.recordAmbientMeasurement(
            ds.name,
            mapOf("app" to listOf(FragmentColumn("app", "users", "DIFFERENT", "bigint", 1, false))),
        )
        assertTrue(confirmed.isEmpty(), "a differing ambient read must not count as a re-measurement")

        now = 15
        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"), adoptHeldContent = true)
        assertEquals(
            setOf("app"),
            registry.freshnessGate(registry.find(second.connectionId)!!, listOf("app")),
            "unconfirmed content must still go stale on its original clock",
        )
        // And the pooled structure is untouched: still the originally measured column.
        assertEquals(
            listOf("id"),
            registry.structuralRows(registry.find(second.connectionId)!!).map { it.column },
        )
    }

    @Test
    fun `adopting retains the pooled fragment so it survives the original holder closing`() = runBlocking {
        // Adoption takes a reference of its own. Without it the fragment would be released out from under
        // the adopter when the measuring connection closes, and structuralRows would silently go empty.
        val registry = ConnectionCatalogRegistry()
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1"), ds)
        val key = registry.find(first.connectionId)!!.held.getValue("app").pooledRef

        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"), adoptHeldContent = true)
        assertEquals(3, registry.pooledFor(key)!!.refCount) // authoritative + measurer + adopter

        registry.close(first.connectionId, ds.name)
        assertEquals(2, registry.pooledFor(key)!!.refCount)
        assertEquals(
            listOf("id"),
            registry.structuralRows(registry.find(second.connectionId)!!).map { it.column },
            "the adopter must still resolve its structure after the measurer closed",
        )

        registry.close(second.connectionId, ds.name)
        assertEquals(1, registry.pooledFor(key)!!.refCount) // authoritative alone
    }

    @Test
    fun `a schema with nothing held is still fetched when adopting`() = runBlocking {
        // Adoption only skips work that is already done; it never skips the first measurement of a schema.
        val registry = ConnectionCatalogRegistry()
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1"), ds)

        val second = registry.open(
            Binding(ds.name, "second", "USER"),
            listOf("app", "other"),
            adoptHeldContent = true,
        )
        assertEquals(listOf("other"), second.onOpen.map { it.schema })
        val connection = registry.find(second.connectionId)!!
        assertTrue(connection.held.containsKey("app"))
        assertTrue(connection.pending.containsKey("other"))
    }

    @Test
    fun `unchanged on-open cannot no-op an unconditional first fetch`() = runBlocking {
        // A fresh connection whose schema has no authoritative hash yet is issued an UNCONDITIONAL refetch
        // (pending.expectedHash == null). A proxy that replies unchanged=true has nothing to adopt — this
        // must fail closed, never silently establish a held reference with no structure behind it.
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "fresh", "USER"), listOf("app"))
        val rejected = registry.applyPush(push(opened, "app", "h1", unchanged = true), ds) as CatalogMutationResult.Rejected
        assertEquals(Status.Code.FAILED_PRECONDITION, rejected.code)
        val connection = registry.find(opened.connectionId)!!
        assertTrue(connection.held["app"] == null)
        assertTrue(connection.pending.containsKey("app")) // still pending: the fetch was not satisfied
    }

    @Test
    fun `system schema fragments dedup across datasources on the same engine version`() = runBlocking {
        // Two distinct datasources on the SAME engine version share one pooled fragment for a system schema
        // (PoolKey scope "engine:<version>"), so the shared catalog build is stored once. A ds-scoped schema
        // would never collide like this.
        val registry = ConnectionCatalogRegistry()
        val dsA = ds.copy(id = 1, name = "dsA")
        val dsB = ds.copy(id = 2, name = "dsB")
        val a = registry.openPushSystem(dsA, "information_schema", "sys-h1")
        registry.openPushSystem(dsB, "information_schema", "sys-h1")
        val key = registry.find(a.connectionId)!!.held.getValue("information_schema").pooledRef
        assertEquals(1, registry.poolSize())
        // dsA held + dsA authoritative + dsB held + dsB authoritative all reference the one pooled fragment.
        assertEquals(4, registry.pooledFor(key)!!.refCount)
    }

    @Test
    fun `invalidating a datasource forces the next connection to measure for itself`() = runBlocking {
        // Repointing a datasource at another database makes held structure describe a database that is no
        // longer there. Adoption would otherwise hand that structure to the next connection, which would
        // decide against a catalog its target DB never had.
        val registry = ConnectionCatalogRegistry()
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1"), ds)
        val key = registry.find(first.connectionId)!!.held.getValue("app").pooledRef

        val adoptsBefore = registry.open(Binding(ds.name, "before", "USER"), listOf("app"), adoptHeldContent = true)
        assertTrue(adoptsBefore.onOpen.isEmpty(), "same target: adoption is expected")

        assertEquals(setOf("app"), registry.invalidateDatasource(ds.name))

        val afterRetarget = registry.open(Binding(ds.name, "after", "USER"), listOf("app"), adoptHeldContent = true)
        assertEquals(
            listOf("app"),
            afterRetarget.onOpen.map { it.schema },
            "after a retarget the next connection must measure the new target itself",
        )
        // The fetch is unconditional: there is no hash left to claim the new database matches the old.
        assertTrue(afterRetarget.onOpen.single().ifHashDiffers.isEmpty)
        // Connections that already hold the content keep it — their own reference is still counted.
        assertEquals(2, registry.pooledFor(key)!!.refCount)
    }

    @Test
    fun `one datasource's ambient refresh cannot vouch for another's schema`() = runBlocking {
        // System-schema content is pooled once per engine version and shared by every datasource on it, so a
        // measurement recorded against the shared content would let a datasource nobody read look freshly
        // verified. Freshness is evidence about one target DB; only the content is shareable.
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 10)
        val dsA = ds.copy(id = 1, name = "dsA")
        val dsB = ds.copy(id = 2, name = "dsB")
        registry.openPushSystem(dsA, "information_schema", "sys-h1")
        registry.openPushSystem(dsB, "information_schema", "sys-h1")

        now = 8
        // Only dsA is re-read. Its columns match, so dsA is confirmed — dsB must not be.
        val confirmed = registry.recordAmbientMeasurement(
            dsA.name,
            mapOf(
                "information_schema" to
                    listOf(FragmentColumn("information_schema", "t", "c", "bigint", 1, false)),
            ),
        )
        assertEquals(setOf("information_schema"), confirmed)

        now = 15
        val onA = registry.open(
            Binding(dsA.name, "p", "USER"), listOf("information_schema"), adoptHeldContent = true,
        )
        assertTrue(onA.onOpen.isEmpty(), "dsA was re-read, so its adopter is fresh")

        val onB = registry.open(
            Binding(dsB.name, "p", "USER"), listOf("information_schema"), adoptHeldContent = true,
        )
        assertEquals(
            setOf("information_schema"),
            registry.freshnessGate(registry.find(onB.connectionId)!!, listOf("information_schema")),
            "dsB's target DB was never re-read; dsA's refresh must not make it look fresh",
        )
    }

    /** Open a connection on [ds] scoped to one system [schema] and push a single-column fragment for it. */
    private suspend fun ConnectionCatalogRegistry.openPushSystem(ds: Datasource, schema: String, hash: String): OpenConnection {
        val opened = open(Binding(ds.name, "p", "USER"), listOf(schema))
        val result = applyPush(
            schemaFragmentPush {
                connectionId = opened.connectionId
                datasourceName = ds.name
                this.schema = schema
                contentHash = ByteString.copyFromUtf8(hash)
                backendGeneration = 1
                columns.add(column {
                    this.schema = schema; table = "t"; column = "c"
                    dataType = "bigint"; ordinal = 1; nullable = false
                })
            },
            ds,
        )
        check(result is CatalogMutationResult.Applied) { "openPushSystem rejected: $result" }
        return opened
    }

    @Test
    fun `same hash with different columns rejects and close is idempotently fail-closed`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1", columnName = "id"), ds)
        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"))
        val alias = registry.applyPush(push(second, "app", "h1", columnName = "email"), ds)
        assertTrue(alias is CatalogMutationResult.Rejected)
        assertTrue(registry.close(first.connectionId, ds.name) is CatalogMutationResult.Applied)
        assertEquals(Status.Code.NOT_FOUND, (registry.close(first.connectionId, ds.name) as CatalogMutationResult.Rejected).code)
        assertNotNull(registry.authoritativeFor(ds.name, "app"))
        Unit
    }
}
