package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.catalogRequest
import com.ridi.oss.proxymonster.grpc.column
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import com.ridi.oss.proxymonster.grpc.schemaHash
import io.grpc.Status
import kotlinx.coroutines.runBlocking
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
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
        clockMicros: Long = 0,
        backend: String = "",
        trusted: Boolean = true,
        inTransaction: Boolean = false,
    ) = schemaFragmentPush {
        connectionId = opened.connectionId
        datasourceName = ds.name
        this.schema = schema
        contentHash = ByteString.copyFromUtf8(hash)
        this.unchanged = unchanged
        backendGeneration = generation
        dbClockMicros = clockMicros
        backendId = backend
        hashTrusted = trusted
        measuredInTransaction = inTransaction
        if (!unchanged) {
            columns.add(column {
                this.schema = schema; table = "users"; column = columnName
                dataType = "bigint"; ordinal = 1; nullable = false
            })
        }
    }

    /** A configuration reading — what registration and the ambient refresh push, carrying per-schema hashes. */
    private fun config(
        schema: String,
        hash: String,
        columnName: String? = "id",
        clockMicros: Long = 0,
        backend: String = "",
        trusted: Boolean = true,
        complete: Boolean = false,
        extraSchemas: Map<String, String> = emptyMap(),
    ) = catalogRequest {
        datasourceName = ds.name
        defaultSchemas.add("app")
        schemaHashes.add(schemaHash { this.schema = schema; this.hash = ByteString.copyFromUtf8(hash); this.trusted = trusted })
        extraSchemas.forEach { (name, h) ->
            schemaHashes.add(schemaHash { this.schema = name; this.hash = ByteString.copyFromUtf8(h); this.trusted = true })
            contentSchemas.add(name)
            columns.add(column {
                this.schema = name; table = "t"; this.column = "c"
                dataType = "bigint"; ordinal = 1; nullable = false
            })
        }
        dbClockMicros = clockMicros
        backendId = backend
        namespaceComplete = complete
        if (columnName != null) {
            contentSchemas.add(schema)
            columns.add(column {
                this.schema = schema; table = "users"; this.column = columnName
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
        // The point of adopting: the first statement decides without waiting on the backend.
        assertTrue(registry.freshnessGate(connection, listOf("app")).isEmpty())
    }

    @Test
    fun `adoption inherits the original measurement time so staleness still fires`() = runBlocking {
        // Adopting must not restart the staleness clock. If it did, a stream of new connections would keep
        // content alive indefinitely without anyone re-reading the backend, and the bound could never fire.
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
    fun `a configuration reading of the same content refreshes the staleness clock`() = runBlocking {
        // The staleness ceiling sits above the ambient refresh interval on the premise that the refresh
        // itself keeps pooled content verified. Without that, content pooled once would age out no matter
        // how recently the backend was read, and every new session would refetch.
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 10)
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1"), ds)

        now = 8
        registry.applyConfigCatalog(config("app", "h1"), ds)

        now = 15 // past the original measurement, inside the window from the configuration reading
        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"), adoptHeldContent = true)
        assertTrue(second.onOpen.isEmpty())
        assertTrue(
            registry.freshnessGate(registry.find(second.connectionId)!!, listOf("app")).isEmpty(),
            "the configuration reading must reset the staleness clock for later adopters",
        )
    }

    @Test
    fun `the first connection adopts content a configuration reading installed`() = runBlocking {
        // The point of the whole step. A registration scan holds the same six fields a fragment does and now
        // carries the backend's own hash for each schema, so its content is content-addressable exactly like
        // a connection's — meaning connection #1 starts from it instead of re-reading what the control plane
        // was handed seconds earlier.
        val registry = ConnectionCatalogRegistry()
        registry.applyConfigCatalog(config("app", "h1", clockMicros = 100, backend = "srv"), ds)

        val opened = registry.open(Binding(ds.name, "first", "USER"), listOf("app"), adoptHeldContent = true)
        assertTrue(opened.onOpen.isEmpty(), "the first connection must adopt, not fetch")
        assertEquals(
            listOf("id"),
            registry.structuralRows(registry.find(opened.connectionId)!!).map { it.column },
            "it must adopt the scan's actual columns",
        )
    }

    @Test
    fun `an untrusted configuration hash installs nothing`() = runBlocking {
        // A hash the producer could not vouch for names content it may already have proved stale. Installing
        // it would hand exactly that content to the next connection to adopt.
        val registry = ConnectionCatalogRegistry()
        registry.applyConfigCatalog(config("app", "h1", trusted = false), ds)

        assertNull(registry.authoritativeFor(ds.name, "app"), "an untrusted reading must not become authoritative")
        val opened = registry.open(Binding(ds.name, "first", "USER"), listOf("app"), adoptHeldContent = true)
        assertEquals(listOf("app"), opened.onOpen.map { it.schema }, "there is nothing proven to adopt")
    }

    @Test
    fun `a configuration reading naming a hash with no content asks for that schema`() = runBlocking {
        // A pointer that names content nothing resolves is worse than no pointer: an adopting connection
        // decides against an empty structure. The manager reports the gap instead so the proxy fills it.
        val registry = ConnectionCatalogRegistry()
        val result = registry.applyConfigCatalog(config("app", "h1", columnName = null), ds)

        assertEquals(listOf("app"), result.fetchSchemas)
        assertNull(registry.authoritativeFor(ds.name, "app"))
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
        // decide against a catalog its backend never had.
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
    fun `one datasource's configuration reading cannot vouch for another's schema`() = runBlocking {
        // System-schema content is pooled once per engine version and shared by every datasource on it, so a
        // measurement recorded against the shared content would let a datasource nobody read look freshly
        // verified. Freshness is evidence about one backend; only the content is shareable.
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 10)
        val dsA = ds.copy(id = 1, name = "dsA")
        val dsB = ds.copy(id = 2, name = "dsB")
        registry.openPushSystem(dsA, "information_schema", "sys-h1")
        registry.openPushSystem(dsB, "information_schema", "sys-h1")

        now = 8
        // Only dsA is re-read.
        registry.applyConfigCatalog(
            catalogRequest {
                datasourceName = dsA.name
                schemaHashes.add(schemaHash { schema = "information_schema"; hash = ByteString.copyFromUtf8("sys-h1"); trusted = true })
                contentSchemas.add("information_schema")
                columns.add(column {
                    schema = "information_schema"; table = "t"; this.column = "c"
                    dataType = "bigint"; ordinal = 1; nullable = false
                })
            },
            dsA,
        )

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
            "dsB's backend was never re-read; dsA's refresh must not make it look fresh",
        )
    }

    @Test
    fun `an older reading of the same backend is dropped, never installed`() = runBlocking {
        // The ordering rule's whole point. A whole-server scan takes tens of seconds, so a scan that read
        // state at time 100 routinely lands after a connection refetch that read newer state at 101. Under
        // accept order the slow scan displaces the newer catalog and a trusting connection adopts it.
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "fast", "USER"), listOf("app"))
        registry.applyPush(push(opened, "app", "new", clockMicros = 101, backend = "srv"), ds)

        registry.applyConfigCatalog(config("app", "old", columnName = "stale", clockMicros = 100, backend = "srv"), ds)

        assertEquals(
            "new",
            registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8(),
            "an older reading must not displace the newer content",
        )
        val adopter = registry.open(Binding(ds.name, "later", "USER"), listOf("app"), adoptHeldContent = true)
        assertEquals(
            listOf("id"),
            registry.structuralRows(registry.find(adopter.connectionId)!!).map { it.column },
            "and no connection may adopt the stale scan's columns",
        )
    }

    @Test
    fun `a strictly newer reading of the same backend installs`() = runBlocking {
        // The other half of the rule: it must still let genuine progress through, or the shared state would
        // simply freeze on whatever landed first.
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "slow", "USER"), listOf("app"))
        registry.applyPush(push(opened, "app", "old", clockMicros = 100, backend = "srv"), ds)

        registry.applyConfigCatalog(config("app", "new", columnName = "fresh", clockMicros = 101, backend = "srv"), ds)

        assertEquals("new", registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8())
        val adopter = registry.open(Binding(ds.name, "later", "USER"), listOf("app"), adoptHeldContent = true)
        assertEquals(listOf("fresh"), registry.structuralRows(registry.find(adopter.connectionId)!!).map { it.column })
    }

    @Test
    fun `an unclocked reading fills a hole but never overwrites a clocked one`() = runBlocking {
        // A reading with no clock cannot be shown to be the newer of the two, and refusing exactly that
        // claim is what the version exists for. It may still seed a schema nothing is held for.
        val registry = ConnectionCatalogRegistry()
        registry.applyConfigCatalog(config("app", "seed", clockMicros = 0, backend = "srv"), ds)
        assertEquals("seed", registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8())

        val opened = registry.open(Binding(ds.name, "clocked", "USER"), listOf("app"))
        registry.applyPush(push(opened, "app", "clocked", clockMicros = 500, backend = "srv"), ds)
        registry.applyConfigCatalog(config("app", "unclocked", columnName = "x", clockMicros = 0, backend = "srv"), ds)

        assertEquals(
            "clocked",
            registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8(),
            "an unversioned reading must not displace a versioned one",
        )
    }

    @Test
    fun `readings from different backends fall back to accept order`() = runBlocking {
        // A wall clock is only meaningful inside one backend. Comparing across two would let one server's
        // clock skew decide the other's content, so the comparison is skipped entirely — degraded ordering,
        // never a cross-backend clock claim.
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "a", "USER"), listOf("app"))
        registry.applyPush(push(opened, "app", "from-a", clockMicros = 900, backend = "srv-a"), ds)

        registry.applyConfigCatalog(config("app", "from-b", columnName = "b", clockMicros = 100, backend = "srv-b"), ds)

        assertEquals(
            "from-b",
            registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8(),
            "a lower clock on a DIFFERENT backend is not an older reading; accept order decides",
        )
    }

    @Test
    fun `an untrusted connection push stays connection-only`() = runBlocking {
        // The producer measured this hash and then proved its own reading stale — its two bracketing
        // measurements disagreed. Its columns are the connection's to decide against, and nobody else's.
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "measurer", "USER"), listOf("app"))
        val applied = registry.applyPush(
            push(opened, "app", "h-untrusted", columnName = "leaked", trusted = false, clockMicros = 100, backend = "srv"),
            ds,
        )
        assertTrue(applied is CatalogMutationResult.Applied, "the connection still gets its own content")
        assertEquals(
            listOf("leaked"),
            registry.structuralRows(registry.find(opened.connectionId)!!).map { it.column },
        )

        assertNull(registry.authoritativeFor(ds.name, "app"), "an untrusted push must never become authoritative")
        val adopter = registry.open(Binding(ds.name, "adopter", "USER"), listOf("app"), adoptHeldContent = true)
        assertEquals(listOf("app"), adopter.onOpen.map { it.schema }, "no connection may adopt it")
        assertTrue(
            registry.structuralRows(registry.find(adopter.connectionId)!!).isEmpty(),
            "and none may resolve its columns",
        )
    }

    @Test
    fun `an untrusted hash is never handed back as a refetch token`() = runBlocking {
        // The proxy would answer `unchanged` against bytes no coherent measurement stands behind, and the
        // connection would keep columns the producer already proved did not match that hash.
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 10)
        val opened = registry.open(Binding(ds.name, "measurer", "USER"), listOf("app"))
        registry.applyPush(push(opened, "app", "h-untrusted", trusted = false), ds)

        now = 20 // aged past the staleness bound, so the next decide re-checks
        val connection = registry.find(opened.connectionId)!!
        assertEquals(setOf("app"), registry.freshnessGate(connection, listOf("app")))
        val commands = registry.markBeforeDecide(connection, listOf("app"))
        assertTrue(
            commands.single().ifHashDiffers.isEmpty,
            "an untrusted hash must force an unconditional fetch",
        )
    }

    @Test
    fun `a dirty connection push stays connection-only`() = runBlocking {
        // Measured inside an open transaction, so its view is transactionally private: it may include the
        // connection's own uncommitted DDL, or miss committed DDL from elsewhere.
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "in-tx", "USER"), listOf("app"))
        registry.applyPush(
            push(opened, "app", "h-dirty", columnName = "uncommitted", inTransaction = true, clockMicros = 100, backend = "srv"),
            ds,
        )

        assertEquals(
            listOf("uncommitted"),
            registry.structuralRows(registry.find(opened.connectionId)!!).map { it.column },
            "the measuring connection still decides against what it read",
        )
        assertNull(registry.authoritativeFor(ds.name, "app"), "a dirty push must never become authoritative")
        val adopter = registry.open(Binding(ds.name, "adopter", "USER"), listOf("app"), adoptHeldContent = true)
        assertEquals(listOf("app"), adopter.onOpen.map { it.schema }, "no connection may adopt it")
    }

    @Test
    fun `a namespace-complete reading drops a schema it no longer sees`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        registry.applyConfigCatalog(
            config("app", "h1", clockMicros = 100, backend = "srv", complete = true, extraSchemas = mapOf("gone" to "g1")),
            ds,
        )
        assertNotNull(registry.authoritativeFor(ds.name, "gone"))

        registry.applyConfigCatalog(config("app", "h1", clockMicros = 200, backend = "srv", complete = true), ds)

        assertNull(registry.authoritativeFor(ds.name, "gone"), "a schema absent from a complete enumeration is gone")
        assertNotNull(registry.authoritativeFor(ds.name, "app"), "the schemas it did name survive")
        Unit
    }

    @Test
    fun `a scoped reading never implies deletion`() = runBlocking {
        // Both engines filter information_schema by privilege, so a least-privilege account reads a strict
        // subset. Deleting on a reading that never claimed completeness erases every schema it cannot see.
        val registry = ConnectionCatalogRegistry()
        registry.applyConfigCatalog(
            config("app", "h1", clockMicros = 100, backend = "srv", complete = true, extraSchemas = mapOf("unseen" to "u1")),
            ds,
        )
        assertNotNull(registry.authoritativeFor(ds.name, "unseen"))

        registry.applyConfigCatalog(config("app", "h1", clockMicros = 200, backend = "srv", complete = false), ds)

        assertNotNull(
            registry.authoritativeFor(ds.name, "unseen"),
            "a reading that did not enumerate the server says nothing about the schemas it omitted",
        )
        Unit
    }

    @Test
    fun `a schema declared present with no columns is distinct from one not carried`() = runBlocking {
        // "carried but empty" and "not carried by this push" are different claims. Collapsing them would let
        // an economy push that omits unchanged schemas read as those schemas having lost every column.
        val registry = ConnectionCatalogRegistry()
        registry.applyConfigCatalog(config("app", "h1", clockMicros = 100, backend = "srv"), ds)
        val pooled = registry.authoritativeFor(ds.name, "app")!!.pooledRef

        // A later reading names the same schema's NEW hash but carries no columns for it.
        val result = registry.applyConfigCatalog(config("app", "h2", columnName = null, clockMicros = 200, backend = "srv"), ds)

        assertEquals(listOf("app"), result.fetchSchemas, "the manager must ask for the content it lacks")
        assertEquals(
            "h1",
            registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8(),
            "the pointer must not move to a hash with nothing behind it",
        )
        assertNotNull(registry.pooledFor(pooled), "and the resolvable content stays")
        Unit
    }

    @Test
    fun `a same-content reading keeps the higher clock`() = runBlocking {
        // Two readings of identical content are equally good evidence of it. Taking the later clock stops an
        // old confirming reading from making the entry look older than a newer reading already proved.
        val registry = ConnectionCatalogRegistry()
        registry.applyConfigCatalog(config("app", "h1", clockMicros = 500, backend = "srv"), ds)
        registry.applyConfigCatalog(config("app", "h1", clockMicros = 100, backend = "srv"), ds)

        assertEquals(500, registry.authoritativeFor(ds.name, "app")!!.dbClockMicros)
        // And the entry still refuses an older differing reading measured against that higher clock.
        registry.applyConfigCatalog(config("app", "h2", columnName = "x", clockMicros = 200, backend = "srv"), ds)
        assertEquals("h1", registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8())
    }

    @Test
    fun `the ordering rule discriminates every case it claims to`() {
        // Without this the rule above is only exercised where a test happens to reach it; a predicate that
        // returned INCOMPARABLE for everything would still pass those, since accept order installs too.
        val h1 = ContentHash(ByteString.copyFromUtf8("h1"))
        val h2 = ContentHash(ByteString.copyFromUtf8("h2"))
        fun v(hash: ContentHash, clock: Long, backend: String) = ReadingVersion(hash, clock, backend)

        assertEquals(ReadingOrder.FIRST, orderReading(null, v(h1, 100, "srv")))
        assertEquals(ReadingOrder.SAME, orderReading(v(h1, 100, "srv"), v(h1, 200, "srv")))
        assertEquals(ReadingOrder.NEWER, orderReading(v(h1, 100, "srv"), v(h2, 101, "srv")))
        assertEquals(ReadingOrder.TIED, orderReading(v(h1, 100, "srv"), v(h2, 100, "srv")))
        assertEquals(ReadingOrder.STALE, orderReading(v(h1, 100, "srv"), v(h2, 99, "srv")))
        assertEquals(ReadingOrder.STALE, orderReading(v(h1, 100, "srv"), v(h2, 0, "srv")))
        assertEquals(ReadingOrder.NEWER, orderReading(v(h1, 0, "srv"), v(h2, 100, "srv")))
        assertEquals(ReadingOrder.INCOMPARABLE, orderReading(v(h1, 0, "srv"), v(h2, 0, "srv")))
        assertEquals(ReadingOrder.INCOMPARABLE, orderReading(v(h1, 100, "srv-a"), v(h2, 99, "srv-b")))
        assertEquals(ReadingOrder.INCOMPARABLE, orderReading(v(h1, 100, ""), v(h2, 99, "srv")))
        assertEquals(ReadingOrder.INCOMPARABLE, orderReading(v(h1, 100, "srv"), v(h2, 99, "")))

        // Only STALE and SAME withhold installation; everything else must be able to land.
        assertFalse(ReadingOrder.STALE.installs)
        assertFalse(ReadingOrder.SAME.installs)
        listOf(ReadingOrder.FIRST, ReadingOrder.NEWER, ReadingOrder.TIED, ReadingOrder.INCOMPARABLE)
            .forEach { assertTrue(it.installs, "$it must install") }
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
                hashTrusted = true
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
