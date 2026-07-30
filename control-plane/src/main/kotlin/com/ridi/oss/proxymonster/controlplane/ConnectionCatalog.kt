package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.grpc.Refetch
import com.ridi.oss.proxymonster.grpc.SchemaFragmentPush
import com.ridi.oss.proxymonster.grpc.refetch
import io.grpc.Status
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

private const val CONNECTION_ID_BYTES = 16

/**
 * How long a connection may hold a schema fragment before re-measuring it. This is the backstop for drift the
 * control plane never learned about — DDL run straight against the backend, which no push reports — so it
 * bounds how long such a change can go unnoticed.
 *
 * Set above the proxy's ambient refresh interval, which re-reads the whole backend catalog and, through
 * [ConnectionCatalogRegistry.recordAmbientMeasurement], re-measures the pooled fragments it still agrees
 * with. That cycle is what detects out-of-band DDL; this bound is the ceiling for a connection whose
 * schemas the refresh did not confirm, so it only has to sit far enough above the interval that an ordinary
 * slow or skipped cycle does not put a full fetch in front of a user's query.
 */
private const val DEFAULT_STALENESS_NANOS = 15L * 60 * 1_000_000_000

/** Immutable value key for catalog content. ByteString is required: raw ByteArray has reference equality. */
data class ContentHash(val bytes: ByteString)

data class FragmentColumn(
    val schema: String,
    val table: String,
    val column: String,
    val dataType: String,
    val ordinal: Int,
    val nullable: Boolean,
)

data class PoolKey(val scope: String, val schema: String, val hash: ContentHash)

data class SchemaFragment(val key: PoolKey, val hash: ContentHash, val columns: List<FragmentColumn>)

data class PooledFragment(val fragment: SchemaFragment, val refCount: Int)

/**
 * [measuredNanos] is when THIS datasource's backend was last read and found to hold this content — the
 * evidence a connection inherits when it adopts. It lives here rather than on [PooledFragment] because
 * identical content is pooled once and shared across datasources, while a reading only ever speaks for the
 * backend it came from.
 */
data class Authoritative(
    val hash: ContentHash,
    val pooledRef: PoolKey,
    val epoch: Long,
    val measuredNanos: Long,
)

data class Binding(val datasourceName: String, val principal: String, val tokenKind: String)

data class HeldSchema(
    val pooledRef: PoolKey,
    val hash: ContentHash,
    val lastFetchNanos: Long,
    val lastVerifiedNanos: Long,
    val revalidatedAgainstAuthoritativeHash: ContentHash?,
)

data class PendingRefetch(
    val expectedHash: ContentHash?,
    val authoritativeAtIssue: ContentHash?,
)

/** Build the proxy's conditional-refetch command; an absent [hash] leaves `if_hash_differs` empty
 *  (unconditional fetch, fail-safe). */
private fun refetchOf(schema: String, hash: ContentHash?): Refetch = refetch {
    this.schema = schema
    hash?.let { ifHashDiffers = it.bytes }
}

data class OpenConnection(val connectionId: ByteString, val onOpen: List<Refetch>)

data class EnforcementConnection(
    val connectionId: ByteString,
    val binding: Binding,
    val held: MutableMap<String, HeldSchema> = LinkedHashMap(),
    val pending: MutableMap<String, PendingRefetch> = LinkedHashMap(),
    var backendGeneration: Long? = null,
    var generation: Long = 0,
    val mutex: Mutex = Mutex(),
    @Volatile var lastUsedNanos: Long,
)

sealed interface CatalogMutationResult {
    data class Applied(val generation: Long) : CatalogMutationResult
    data class Rejected(val code: Status.Code, val description: String) : CatalogMutationResult
}

/**
 * Ephemeral, fail-closed enforcement catalog state. The wire exposes datasource/principal/token-kind but no
 * proxy-instance identifier, so [Binding] binds exactly those authoritative fields; backend_generation binds
 * the first backend-connection instance that successfully pushes and thereafter advances monotonically.
 */
class ConnectionCatalogRegistry(
    private val clockNanos: () -> Long = System::nanoTime,
    private val secureRandom: SecureRandom = SecureRandom(),
    internal val stalenessNanos: Long = DEFAULT_STALENESS_NANOS,
) {
    private val pool = ConcurrentHashMap<PoolKey, PooledFragment>()
    private val authoritative = ConcurrentHashMap<Pair<String, String>, Authoritative>()
    private val connections = ConcurrentHashMap<ByteString, EnforcementConnection>()
    private val authoritativeEpoch = AtomicLong()

    // A full push transitions both the held and authoritative references. The global monitor makes those
    // multi-map transitions atomic; every individual reference-count mutation still occurs under pool.compute.
    private val stateLock = Any()

    /**
     * [adoptHeldContent] lets a connection start from catalog content the control plane already holds instead
     * of fetching it, for an engine whose scan cannot vary by connection
     * ([Engine.catalogIsConnectionIndependent]). A schema with nothing held still gets its fetch, so this only
     * removes redundant work — never the first measurement.
     */
    fun open(
        binding: Binding,
        schemas: Collection<String>,
        adoptHeldContent: Boolean = false,
    ): OpenConnection {
        while (true) {
            val bytes = ByteArray(CONNECTION_ID_BYTES).also(secureRandom::nextBytes)
            val id = ByteString.copyFrom(bytes)
            val connection = EnforcementConnection(id, binding, lastUsedNanos = clockNanos())
            if (connections.putIfAbsent(id, connection) == null) {
                val commands = issueInitial(connection, schemas, adoptHeldContent)
                return OpenConnection(id, commands)
            }
        }
    }

    /** Recreate a well-formed id after CP restart; an already-live id is never overwritten. */
    fun recover(
        connectionId: ByteString,
        binding: Binding,
        schemas: Collection<String>,
        adoptHeldContent: Boolean = false,
    ): OpenConnection? {
        val connection = EnforcementConnection(connectionId, binding, lastUsedNanos = clockNanos())
        if (connections.putIfAbsent(connectionId, connection) != null) return null
        return OpenConnection(connectionId, issueInitial(connection, schemas, adoptHeldContent))
    }

    private fun issueInitial(
        connection: EnforcementConnection,
        schemas: Collection<String>,
        adoptHeldContent: Boolean,
    ): List<Refetch> =
        synchronized(stateLock) {
            schemas.asSequence().filter { it.isNotBlank() }.distinct().mapNotNull { schema ->
                val auth = authoritative[connection.binding.datasourceName to schema]
                val pooled = auth?.let { pool[it.pooledRef] }
                // Where a scan cannot vary by connection, content another connection already measured is
                // this connection's answer too, so it starts from that instead of putting a backend fetch in
                // front of the first query. lastVerifiedNanos carries the original measurement time rather
                // than now: the staleness gate must keep counting from when the backend was actually read, or
                // a stream of new connections would refresh the clock forever and the bound would never fire.
                if (adoptHeldContent && auth != null && pooled != null) {
                    retain(pooled.fragment, 1)
                    connection.held[schema] = HeldSchema(
                        pooledRef = auth.pooledRef,
                        hash = auth.hash,
                        lastFetchNanos = auth.measuredNanos,
                        lastVerifiedNanos = auth.measuredNanos,
                        revalidatedAgainstAuthoritativeHash = null,
                    )
                    return@mapNotNull null
                }
                val pending = PendingRefetch(auth?.hash, auth?.hash)
                connection.pending[schema] = pending
                refetchOf(schema, pending.expectedHash)
            }.toList()
        }

    fun find(connectionId: ByteString): EnforcementConnection? = connections[connectionId]

    suspend fun <T> withConnection(
        connectionId: ByteString,
        block: suspend (EnforcementConnection) -> T,
    ): T? {
        val connection = connections[connectionId] ?: return null
        return connection.mutex.withLock {
            if (connections[connectionId] !== connection) return@withLock null
            connection.lastUsedNanos = clockNanos()
            block(connection)
        }
    }

    suspend fun applyPush(request: SchemaFragmentPush, ds: Datasource): CatalogMutationResult {
        val connection = connections[request.connectionId]
            ?: return CatalogMutationResult.Rejected(Status.Code.NOT_FOUND, "unknown connection_id")
        return connection.mutex.withLock {
            if (connections[request.connectionId] !== connection) {
                return@withLock CatalogMutationResult.Rejected(Status.Code.NOT_FOUND, "unknown connection_id")
            }
            connection.lastUsedNanos = clockNanos()
            applyPushLocked(connection, request, ds)
        }
    }

    private fun applyPushLocked(
        connection: EnforcementConnection,
        request: SchemaFragmentPush,
        ds: Datasource,
    ): CatalogMutationResult {
        if (request.datasourceName != connection.binding.datasourceName || request.datasourceName != ds.name) {
            return CatalogMutationResult.Rejected(Status.Code.FAILED_PRECONDITION, "datasource binding mismatch")
        }
        if (request.backendGeneration < 0) {
            return CatalogMutationResult.Rejected(Status.Code.INVALID_ARGUMENT, "backend_generation exceeds signed range")
        }
        connection.backendGeneration?.let { bound ->
            if (request.backendGeneration < bound) {
                return CatalogMutationResult.Rejected(Status.Code.FAILED_PRECONDITION, "stale backend_generation")
            }
        }
        val pending = connection.pending[request.schema]
            ?: return CatalogMutationResult.Rejected(
                Status.Code.FAILED_PRECONDITION,
                "schema push has no pending REFETCH command",
            )
        val pushedHash = ContentHash(request.contentHash)
        if (request.unchanged) {
            val expected = pending.expectedHash
                ?: return CatalogMutationResult.Rejected(
                    Status.Code.FAILED_PRECONDITION,
                    "unchanged push cannot satisfy an unconditional REFETCH",
                )
            if (pushedHash != expected) {
                return CatalogMutationResult.Rejected(Status.Code.FAILED_PRECONDITION, "unchanged hash mismatch")
            }
            return synchronized(stateLock) {
                val key = poolKey(ds, request.schema, expected)
                val pooled = pool[key]
                    ?: return@synchronized CatalogMutationResult.Rejected(
                        Status.Code.FAILED_PRECONDITION,
                        "unchanged push references an unknown pooled fragment",
                    )
                val previous = connection.held[request.schema]
                if (previous?.pooledRef != key) retain(pooled.fragment, 1)
                val now = clockNanos()
                connection.held[request.schema] = HeldSchema(
                    pooledRef = key,
                    hash = expected,
                    // An unchanged reply is a live verification, not a full fetch. Preserve the separate
                    // last-fetch clock (zero for a fresh connection that adopted a shared fragment).
                    lastFetchNanos = previous?.lastFetchNanos ?: 0,
                    lastVerifiedNanos = now,
                    revalidatedAgainstAuthoritativeHash = pending.authoritativeAtIssue,
                )
                if (previous != null && previous.pooledRef != key) release(previous.pooledRef)
                accept(connection, request.schema, request.backendGeneration)
            }
        }

        val columns = request.columnsList.map {
            FragmentColumn(it.schema, it.table, it.column, it.dataType, it.ordinal, it.nullable)
        }
        if (columns.any { it.schema != request.schema }) {
            return CatalogMutationResult.Rejected(Status.Code.INVALID_ARGUMENT, "fragment column schema mismatch")
        }
        return synchronized(stateLock) {
            val key = poolKey(ds, request.schema, pushedHash)
            val fragment = SchemaFragment(key, pushedHash, columns.toList())
            val existing = pool[key]
            if (existing != null && existing.fragment.columns != fragment.columns) {
                return@synchronized CatalogMutationResult.Rejected(
                    Status.Code.FAILED_PRECONDITION,
                    "content hash aliases different fragment columns",
                )
            }

            val previousHeld = connection.held[request.schema]
            val authKey = ds.name to request.schema
            val previousAuth = authoritative[authKey]
            var retains = 0
            if (previousHeld?.pooledRef != key) retains++
            if (previousAuth?.pooledRef != key) retains++
            // Also performs the alias check atomically with insertion when another thread created the key.
            val retained = retain(fragment, retains)
            if (retained.fragment.columns != fragment.columns) {
                return@synchronized CatalogMutationResult.Rejected(
                    Status.Code.FAILED_PRECONDITION,
                    "content hash aliases different fragment columns",
                )
            }

            val now = clockNanos()
            connection.held[request.schema] = HeldSchema(key, pushedHash, now, now, null)
            // Authoritative is ACCEPT-ordered (last accepted push wins, via a monotonic epoch), NOT
            // content-monotonic: an accepted push from a lagging read-replica may legitimately set an older
            // content hash. This is a liveness hint, never a correctness input — every connection decides
            // against exactly what ITS OWN backend binds (freshnessGate re-verifies per connection). Under a
            // primary+replica pool a lagging push can regress this and cause bounded before_decide churn on
            // siblings (each self-heals in one round-trip); damping that is a deferred liveness optimization.
            authoritative[authKey] = Authoritative(pushedHash, key, authoritativeEpoch.incrementAndGet(), now)
            if (previousHeld != null && previousHeld.pooledRef != key) release(previousHeld.pooledRef)
            if (previousAuth != null && previousAuth.pooledRef != key) release(previousAuth.pooledRef)
            accept(connection, request.schema, request.backendGeneration)
        }
    }

    private fun accept(connection: EnforcementConnection, schema: String, backendGeneration: Long): CatalogMutationResult.Applied {
        connection.pending.remove(schema)
        connection.backendGeneration = maxOf(connection.backendGeneration ?: backendGeneration, backendGeneration)
        connection.generation++
        return CatalogMutationResult.Applied(connection.generation)
    }

    private fun poolKey(ds: Datasource, schema: String, hash: ContentHash): PoolKey {
        val system = ds.engine.isFixedSystemSchema(schema)
        val scope = if (system && !ds.engineVersion.isNullOrBlank()) {
            "engine:${ds.engineVersion}"
        } else {
            "ds:${ds.name}"
        }
        return PoolKey(scope, schema, hash)
    }

    private fun retain(fragment: SchemaFragment, count: Int): PooledFragment {
        var result: PooledFragment? = null
        pool.compute(fragment.key) { _, current ->
            val next = when {
                current == null -> PooledFragment(fragment, count)
                current.fragment.columns != fragment.columns -> current
                else -> current.copy(refCount = current.refCount + count)
            }
            result = next
            next
        }
        return result!!
    }

    private fun release(key: PoolKey) {
        pool.compute(key) { _, current ->
            if (current == null) return@compute null
            check(current.refCount > 0) { "catalog fragment refcount underflow for $key" }
            val remaining = current.refCount - 1
            if (remaining == 0) null else current.copy(refCount = remaining)
        }
    }

    /** Must be called while holding [EnforcementConnection.mutex]. */
    fun freshnessGate(connection: EnforcementConnection, requiredSchemas: Collection<String>): Set<String> {
        val now = clockNanos()
        return requiredSchemas.asSequence()
            .filter { it.isNotBlank() && !it.startsWith("pg_temp", ignoreCase = true) }
            .distinct()
            .filterTo(LinkedHashSet()) { schema ->
                val held = connection.held[schema]
                val auth = authoritative[connection.binding.datasourceName to schema]
                connection.pending.containsKey(schema) ||
                    held == null ||
                    (auth != null && held.hash != auth.hash && held.revalidatedAgainstAuthoritativeHash != auth.hash) ||
                    now - held.lastVerifiedNanos > stalenessNanos
            }
    }

    /** Issue or replay pending before-decide commands without changing an existing command's CAS token. */
    fun markBeforeDecide(connection: EnforcementConnection, schemas: Collection<String>): List<Refetch> =
        markPending(connection, schemas) { schema ->
            val held = connection.held[schema]
            val auth = authoritative[connection.binding.datasourceName to schema]
            PendingRefetch(held?.hash ?: auth?.hash, auth?.hash)
        }

    /** A catalog-miss qualifier was never held: force one bounded unconditional fetch. */
    fun markCatalogMiss(connection: EnforcementConnection, schemas: Collection<String>): List<Refetch> =
        markPending(connection, schemas) { schema ->
            PendingRefetch(null, authoritative[connection.binding.datasourceName to schema]?.hash)
        }

    fun markAfterStatement(connection: EnforcementConnection, schemas: Collection<String>): List<Refetch> =
        markPending(connection, schemas) { schema ->
            PendingRefetch(
                connection.held[schema]?.hash,
                authoritative[connection.binding.datasourceName to schema]?.hash,
            )
        }

    private fun markPending(
        connection: EnforcementConnection,
        schemas: Collection<String>,
        create: (String) -> PendingRefetch,
    ): List<Refetch> = synchronized(stateLock) {
        schemas.asSequence()
            .filter { it.isNotBlank() && !it.startsWith("pg_temp", ignoreCase = true) }
            .distinct()
            .map { schema ->
                val pending = connection.pending.getOrPut(schema) { create(schema) }
                refetchOf(schema, pending.expectedHash)
            }.toList()
    }

    fun structuralRows(connection: EnforcementConnection): List<FragmentColumn> = synchronized(stateLock) {
        // Sort by (schema, table, ordinal) so the analyzer catalog + client `SELECT *` expansion follow DB
        // column order regardless of the proxy's push order — matches DatasourceStore.catalog()'s
        // `ORDER BY ordinal` guarantee as CP-side defense-in-depth (masks stay self-consistent either way).
        connection.held.values
            .flatMap { held -> pool[held.pooledRef]?.fragment?.columns.orEmpty() }
            .sortedWith(compareBy({ it.schema }, { it.table }, { it.ordinal }))
    }

    fun heldAndFreshSchemas(connection: EnforcementConnection): Set<String> =
        connection.held.keys.filterTo(LinkedHashSet()) { freshnessGate(connection, listOf(it)).isEmpty() }

    /**
     * Fold a whole-catalog measurement from the proxy's ambient refresh into this datasource's authoritative
     * entries.
     *
     * The refresh reads every schema from the backend with the same six fields a fragment holds, so for a
     * schema whose columns are byte-identical it is a genuine re-measurement of exactly that content — the
     * same evidence a connection's own hash probe produces. Recording it advances the authoritative entry's
     * measurement time, so the staleness gate counts from this reading rather than from the first time the
     * content happened to be pooled.
     *
     * Recorded on the authoritative entry, NOT on the pooled fragment: identical system-schema content is
     * pooled once per engine version and shared by every datasource on it ([poolKey]), so writing the time
     * there would let one datasource's refresh vouch for another's schema that nobody read. Freshness is
     * evidence about one backend; only the content itself is shareable.
     *
     * Deliberately narrow: a schema whose columns differ is left untouched, so this can only ever confirm
     * content, never install it. Divergence stays the job of the connection's own probe, which alone knows
     * what that connection's backend binds.
     *
     * Returns the schemas confirmed, for logging.
     */
    fun recordAmbientMeasurement(
        datasourceName: String,
        columnsBySchema: Map<String, List<FragmentColumn>>,
    ): Set<String> = synchronized(stateLock) {
        val confirmed = LinkedHashSet<String>()
        val now = clockNanos()
        for ((schema, columns) in columnsBySchema) {
            val authKey = datasourceName to schema
            val auth = authoritative[authKey] ?: continue
            val pooled = pool[auth.pooledRef] ?: continue
            // Compared as sets: the whole-catalog read and the per-schema fragment read are separate
            // statements whose ORDER BY need not agree, and row order is not part of what a fragment
            // asserts — the decide path sorts for itself. Comparing lists would silently stop confirming
            // anything the moment the two orderings diverged, and nothing would report it.
            if (pooled.fragment.columns.toSet() != columns.toSet()) continue
            authoritative[authKey] = auth.copy(measuredNanos = now)
            confirmed += schema
        }
        confirmed
    }

    /**
     * Drop every authoritative entry for [datasourceName], for when the datasource is repointed at a
     * different database.
     *
     * The persisted catalog is already cleared on a retarget, because keeping it would authorize the new
     * target against the old schema. This state is the same hazard: a connection opening afterwards would
     * otherwise adopt structure measured from the database that is no longer there, and decide against a
     * catalog its backend never had. Dropping the entries makes the next connection measure for itself.
     *
     * Live connections are left alone — each already holds its own reference and re-verifies on its own
     * clock, and tearing their content out mid-session would empty structuralRows under an in-flight
     * statement. Returns the schemas invalidated, for logging.
     */
    /** When this datasource's [schema] was last read and found to hold the content held for it. */
    internal fun measuredNanosFor(datasourceName: String, schema: String): Long? =
        authoritative[datasourceName to schema]?.measuredNanos

    fun invalidateDatasource(datasourceName: String): Set<String> = synchronized(stateLock) {
        val dropped = LinkedHashSet<String>()
        val keys = authoritative.keys.filter { it.first == datasourceName }
        for (key in keys) {
            val auth = authoritative.remove(key) ?: continue
            release(auth.pooledRef)
            dropped += key.second
        }
        dropped
    }

    suspend fun close(connectionId: ByteString, datasourceName: String): CatalogMutationResult {
        val connection = connections[connectionId]
            ?: return CatalogMutationResult.Rejected(Status.Code.NOT_FOUND, "unknown connection_id")
        return connection.mutex.withLock {
            if (connection.binding.datasourceName != datasourceName) {
                return@withLock CatalogMutationResult.Rejected(Status.Code.FAILED_PRECONDITION, "datasource binding mismatch")
            }
            // Remove first so no new operation can enter after close wins; callers that already captured this
            // record re-check map identity after acquiring the same mutex and fail closed.
            if (!connections.remove(connectionId, connection)) {
                return@withLock CatalogMutationResult.Rejected(Status.Code.NOT_FOUND, "unknown connection_id")
            }
            synchronized(stateLock) {
                connection.held.values.forEach { release(it.pooledRef) }
                connection.held.clear()
                connection.pending.clear()
            }
            CatalogMutationResult.Applied(connection.generation)
        }
    }

    suspend fun sweepIdle(maxIdleMillis: Long): Int {
        val cutoff = clockNanos() - maxIdleMillis * 1_000_000
        var swept = 0
        for (connection in connections.values) {
            if (connection.lastUsedNanos >= cutoff) continue
            connection.mutex.withLock {
                if (connection.lastUsedNanos < cutoff && connections.remove(connection.connectionId, connection)) {
                    synchronized(stateLock) {
                        connection.held.values.forEach { release(it.pooledRef) }
                        connection.held.clear()
                        connection.pending.clear()
                    }
                    swept++
                }
            }
        }
        return swept
    }

    internal fun authoritativeFor(datasourceName: String, schema: String): Authoritative? =
        authoritative[datasourceName to schema]

    internal fun pooledFor(key: PoolKey): PooledFragment? = pool[key]
    internal fun poolSize(): Int = pool.size
    internal fun connectionCount(): Int = connections.size
}
