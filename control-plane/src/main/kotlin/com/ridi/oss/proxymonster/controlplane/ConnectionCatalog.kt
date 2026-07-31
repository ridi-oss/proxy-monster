package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.grpc.CatalogRequest
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

/** A hash-only reading naming content the pool does not hold; the proxy is asked for that schema's columns. */
private const val NO_CONTENT_FOR_HASH = "no pooled content for the observed hash"

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

/**
 * How long a schema may go without a clean observation before the manager asks a proxy to re-measure it.
 *
 * The clock is per `(datasource, schema)` and movable: any clean observation of a schema resets that
 * schema's clock and no other. So a schema kept fresh by its own traffic is never gratuitously
 * re-measured, while a quiet sibling still settles into a steady hash-confirm cadence instead of
 * starving behind it. Set below [DEFAULT_STALENESS_NANOS] so an ordinary re-measure lands before the
 * per-connection bound puts a full fetch in front of a user's query.
 */
private const val DEFAULT_REMEASURE_NANOS = 12L * 60 * 1_000_000_000

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
 *
 * [dbClockMicros] and [backendId] are the reading's own version: the backend's clock at the instant it
 * computed the hash, and which backend that was. They order observations across producers, which arrival
 * time cannot — a whole-server scan takes tens of seconds, so a scan that read older state routinely lands
 * after a connection refetch that read newer state. [epoch] survives as the tie-break for the exact-equal
 * clock and for readings that carry no comparable version at all. [measuredNanos] stays the staleness
 * input: version is the DB clock, age is the control-plane clock.
 */
data class Authoritative(
    val hash: ContentHash,
    val pooledRef: PoolKey,
    val epoch: Long,
    val measuredNanos: Long,
    val dbClockMicros: Long = 0,
    val backendId: String = "",
)

/**
 * One catalog reading of one schema, from any producer — the registration scan, an ambient refresh, or a
 * connection's own refetch. Everything the manager needs to decide what the reading may update travels
 * with it.
 *
 * [hash] is null when the producer could not measure one it trusts, and [columns] is null when the reading
 * only claims the content is unchanged. [dirty] is the raw fact that the reading was taken inside an open
 * transaction; the manager assigns the meaning, keeping the proxy free of interpretation.
 */
data class CatalogObservation(
    val datasourceName: String,
    val schema: String,
    val hash: ContentHash?,
    val columns: List<FragmentColumn>?,
    val dbClockMicros: Long,
    val backendId: String,
    val dirty: Boolean,
)

/**
 * Whether an observation may reach shared state, and why not when it cannot. A reading is shareable only
 * when it carries a hash the producer measured and vouches for, and was taken outside a transaction: an
 * untrusted hash may name content the producer itself proved stale, and a transactional reading may include
 * the connection's own uncommitted DDL or miss committed DDL from elsewhere. Either way the observing
 * connection still holds the content for its own decisions — this gates only what other connections can see.
 */
enum class ObservationTrust { SHAREABLE, UNTRUSTED_HASH, DIRTY }

private fun CatalogObservation.trust(): ObservationTrust = when {
    hash == null -> ObservationTrust.UNTRUSTED_HASH
    dirty -> ObservationTrust.DIRTY
    else -> ObservationTrust.SHAREABLE
}

/**
 * The result of one configuration reading: how many column rows it stored, and which schemas it named a
 * hash for that the manager holds no content behind — the proxy fetches exactly those next.
 */
data class ConfigCatalogResult(val columns: Int, val fetchSchemas: List<String>)

/** What the manager did with one observation's claim on the shared authoritative pointer. */
sealed interface AuthoritativeOutcome {
    /** The pointer now names this observation's content. */
    data object Installed : AuthoritativeOutcome

    /** Same content already held; only the entry's control-plane measurement time moved. */
    data object Confirmed : AuthoritativeOutcome

    /** The observation carried differing content but lost the ordering rule, or may never share. */
    data class Dropped(val reason: String) : AuthoritativeOutcome
}

data class Binding(val datasourceName: String, val principal: String, val tokenKind: String)

/**
 * [trusted] false means the producer measured this content but could not vouch for the hash, so the hash
 * cannot be offered back as a conditional-refetch token: a proxy replying `unchanged` against it would be
 * matching bytes no measurement stands behind. Such a schema is always re-fetched unconditionally.
 *
 * [dirty] records that the content was measured inside an open transaction, so nothing but this
 * connection has seen it. Nothing else can true it up — a dirty reading never moves the shared pointer,
 * so `freshnessGate` has no moved hash to notice — which is why the connection re-measures these schemas
 * when its transaction ends.
 */
data class HeldSchema(
    val pooledRef: PoolKey,
    val hash: ContentHash,
    val lastFetchNanos: Long,
    val lastVerifiedNanos: Long,
    val revalidatedAgainstAuthoritativeHash: ContentHash?,
    val trusted: Boolean = true,
    val dirty: Boolean = false,
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

/** A reading's identity for ordering: what it saw, when the backend's own clock said it saw it, and where. */
data class ReadingVersion(val hash: ContentHash, val dbClockMicros: Long, val backendId: String)

/** How an arriving reading orders against the one currently held for the same `(datasource, schema)`. */
enum class ReadingOrder {
    /** Nothing is held; the first reading of a schema is never skipped. */
    FIRST,

    /** The same content, so only the measurement time moves. */
    SAME,

    /** Strictly newer in the backend's own clock. */
    NEWER,

    /** The clocks are exactly equal and cannot discriminate; accept order is the only remaining signal. */
    TIED,

    /** No shared clock domain, or no clock at all on one side; accept order decides. */
    INCOMPARABLE,

    /** Older than what is held. */
    STALE,
}

/**
 * Order two readings of one schema by the backend's own clock.
 *
 * Arrival time cannot do this. A whole-server scan takes tens of seconds, so a scan that read state at
 * time 100 routinely lands after a connection refetch that read newer state at 101 — under accept order
 * the slow scan's stale content displaces the newer catalog and a trusting connection adopts it. An older
 * reading with differing content is therefore dropped, never installed.
 *
 * A clock is only meaningful inside one backend, so the comparison runs only between readings carrying the
 * same non-empty backend identity. Everything else falls back to accept order, which is where this started
 * — degraded ordering, never a wrong reuse, since a reading with no comparable version can still never
 * displace one that has a real clock.
 */
internal fun orderReading(current: ReadingVersion?, observed: ReadingVersion): ReadingOrder = when {
    current == null -> ReadingOrder.FIRST
    current.hash == observed.hash -> ReadingOrder.SAME
    current.backendId.isEmpty() || observed.backendId.isEmpty() ||
        current.backendId != observed.backendId -> ReadingOrder.INCOMPARABLE
    // An unversioned reading may fill a hole but never overwrites a versioned one: it cannot be shown to
    // be the newer of the two, and the whole point of the rule is to refuse exactly that claim.
    observed.dbClockMicros == 0L ->
        if (current.dbClockMicros == 0L) ReadingOrder.INCOMPARABLE else ReadingOrder.STALE
    current.dbClockMicros == 0L -> ReadingOrder.NEWER
    observed.dbClockMicros > current.dbClockMicros -> ReadingOrder.NEWER
    observed.dbClockMicros == current.dbClockMicros -> ReadingOrder.TIED
    else -> ReadingOrder.STALE
}

/** True when a reading ordered this way may replace the content held for its schema. */
internal val ReadingOrder.installs: Boolean
    get() = this == ReadingOrder.FIRST || this == ReadingOrder.NEWER ||
        this == ReadingOrder.TIED || this == ReadingOrder.INCOMPARABLE

/**
 * The persisted side of catalog state — `catalog_column` and the per-schema versions behind it. The
 * manager is its only caller; no handler writes the catalog directly, so one component decides what every
 * reading may update.
 */
interface CatalogProjection {
    /**
     * Every datasource's persisted per-schema readings, for rebuilding the pool after a restart. Only a
     * schema whose stored version and stored columns are both present is returned: a version with no rows
     * would leave the pointer naming content nothing resolves, and rows with no version cannot be ordered
     * against the next reading.
     */
    fun storedSchemaReadings(): List<StoredSchemaReading>

    /**
     * Replace the columns of each schema in [observations] that carries content and is not ordered behind
     * what is already stored, and record its version.
     *
     * [namespaceComplete] is the only thing that licenses deletion: when the reading enumerated every
     * schema on the server, a stored schema missing from it has been dropped and its rows go with it. A
     * scoped reading speaks only for the schemas it names — a privilege-filtered account reads a strict
     * subset, and deleting on that would erase every schema it cannot see.
     */
    fun projectSchemas(
        datasourceId: Long,
        observations: List<ProjectedObservation>,
        namespaceComplete: Boolean,
        namespace: ProjectedNamespace?,
    ): Int
}

/**
 * One schema's reading as the projection writer sees it. [columns] null means the reading carries no
 * content for this schema (it named the schema and its hash, nothing more); [version] null means the
 * reading carries no version that could order it, so it lands by accept order and leaves no version behind.
 */
data class ProjectedObservation(
    val schema: String,
    val columns: List<DatasourceStore.PushedColumn>?,
    val version: ReadingVersion?,
)

/**
 * One schema's persisted reading, as the restart rebuild reads it back: the version behind its stored
 * rows, and those rows. Keyed by datasource id, which the rebuild resolves to the datasource itself —
 * the pool key depends on the engine and engine version, so a rebuilt fragment has to be filed the same
 * way the next live reading of it will be.
 */
data class StoredSchemaReading(
    val datasourceId: Long,
    val schema: String,
    val version: ReadingVersion,
    val columns: List<FragmentColumn>,
)

/** The namespace facts only a whole-server reading can establish, since only it probes the namespace. */
data class ProjectedNamespace(
    val defaultSchemas: List<String>,
    val mysqlLowerCaseTableNames: Int?,
    val engineVersion: String,
)

/**
 * The single owner of catalog state: the in-memory fragment pool, the per-schema authoritative pointer, the
 * per-connection held/pending maps, and — through [projection] — the persisted `catalog_column` rows and
 * their versions. Every catalog reading enters through this class, from the registration scan, the ambient
 * refresh, and every per-connection refetch alike, so one component decides what each reading may update.
 *
 * The wire exposes datasource/principal/token-kind but no proxy-instance identifier, so [Binding] binds
 * exactly those authoritative fields; backend_generation binds the first backend-connection instance that
 * successfully pushes and thereafter advances monotonically.
 */
class ConnectionCatalogRegistry(
    private val clockNanos: () -> Long = System::nanoTime,
    private val secureRandom: SecureRandom = SecureRandom(),
    internal val stalenessNanos: Long = DEFAULT_STALENESS_NANOS,
    private val projection: CatalogProjection? = null,
    internal val remeasureNanos: Long = DEFAULT_REMEASURE_NANOS,
) {
    private val log = org.slf4j.LoggerFactory.getLogger(ConnectionCatalogRegistry::class.java)
    private val pool = ConcurrentHashMap<PoolKey, PooledFragment>()
    private val authoritative = ConcurrentHashMap<Pair<String, String>, Authoritative>()
    private val connections = ConcurrentHashMap<ByteString, EnforcementConnection>()
    private val authoritativeEpoch = AtomicLong()

    // When each (datasource, schema) last received a clean observation, from any producer. The manager
    // owns these because it is the only component every reading passes through, so it is the only one
    // that can reset a schema's clock on a reading that arrived by some other path.
    private val lastCleanNanos = ConcurrentHashMap<Pair<String, String>, Long>()

    // A full push transitions both the held and authoritative references. The global monitor makes those
    // multi-map transitions atomic; every individual reference-count mutation still occurs under pool.compute.
    private val stateLock = Any()

    /**
     * [adoptHeldContent] lets a connection start from catalog content the control plane already holds instead
     * of fetching it — trust mode. A schema with nothing held still gets its fetch, so this only removes
     * redundant work, never the first measurement. Under verify (the default) the connection is instead sent
     * a conditional refetch per schema and adopts only what its own backend confirms.
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
                    dirty = request.measuredInTransaction,
                )
                // A matching hash is itself a reading of the backend, and a clean one resets that schema's
                // re-measure clock exactly as a full fetch would. This is the economy the whole per-schema
                // clock buys: confirming a quiet schema costs one hash query and nothing else. A reading
                // taken in a transaction, or one whose producer could not vouch for it, confirms nothing
                // and leaves the schema due.
                val confirmation = CatalogObservation(
                    datasourceName = ds.name,
                    schema = request.schema,
                    hash = if (request.hashTrusted) expected else null,
                    columns = null,
                    dbClockMicros = request.dbClockMicros,
                    backendId = request.backendId,
                    dirty = request.measuredInTransaction,
                )
                noteAcceptedReading(
                    ds.name,
                    request.schema,
                    shareabilityOf(confirmation, authoritative[ds.name to request.schema]),
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
        val observation = CatalogObservation(
            datasourceName = ds.name,
            schema = request.schema,
            // An untrusted hash is not a content hash: the producer measured it and then proved its own
            // reading stale (its two bracketing measurements disagreed). Dropping it here is what keeps such
            // a reading out of the pool, where another connection could adopt columns already known stale.
            hash = if (request.hashTrusted) pushedHash else null,
            columns = columns,
            dbClockMicros = request.dbClockMicros,
            backendId = request.backendId,
            dirty = request.measuredInTransaction,
        )
        return synchronized(stateLock) {
            val key = if (request.hashTrusted) {
                poolKey(ds, request.schema, pushedHash)
            } else {
                connectionScopedKey(connection, request.schema, pushedHash)
            }
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
            val outcome = shareabilityOf(observation, previousAuth)
            val takesAuthoritative = outcome == AuthoritativeOutcome.Installed
            var retains = 0
            if (previousHeld?.pooledRef != key) retains++
            if (takesAuthoritative && previousAuth?.pooledRef != key) retains++
            // Also performs the alias check atomically with insertion when another thread created the key.
            val retained = retain(fragment, retains)
            if (retained.fragment.columns != fragment.columns) {
                return@synchronized CatalogMutationResult.Rejected(
                    Status.Code.FAILED_PRECONDITION,
                    "content hash aliases different fragment columns",
                )
            }

            val now = clockNanos()
            connection.held[request.schema] = HeldSchema(
                key, pushedHash, now, now, null,
                trusted = request.hashTrusted,
                // Nothing else will true this up: a reading taken in a transaction never moves the shared
                // pointer, so the connection has to remember that it owes a re-measure once it settles.
                dirty = observation.dirty,
            )
            noteAcceptedReading(ds.name, request.schema, outcome)
            when (outcome) {
                is AuthoritativeOutcome.Installed -> {
                    authoritative[authKey] = Authoritative(
                        pushedHash, key, authoritativeEpoch.incrementAndGet(), now,
                        request.dbClockMicros, request.backendId,
                    )
                    if (previousAuth != null && previousAuth.pooledRef != key) release(previousAuth.pooledRef)
                    projectObservation(ds, observation)
                }
                // The reading confirms what is held, so only the staleness clock moves. The version keeps
                // the higher clock: two readings of identical content are equally good evidence of it, and
                // taking the later one stops an old confirming reading from making the entry look older
                // than a newer reading already proved it to be.
                is AuthoritativeOutcome.Confirmed -> if (previousAuth != null) {
                    authoritative[authKey] = previousAuth.copy(
                        measuredNanos = now,
                        dbClockMicros = maxOf(previousAuth.dbClockMicros, request.dbClockMicros),
                    )
                }
                is AuthoritativeOutcome.Dropped -> log.warn(
                    "datasource '{}' schema '{}': connection observation not shared ({})",
                    ds.name, request.schema, outcome.reason,
                )
            }
            if (previousHeld != null && previousHeld.pooledRef != key) release(previousHeld.pooledRef)
            accept(connection, request.schema, request.backendGeneration)
        }
    }

    /**
     * Reset one schema's re-measure clock, having accepted a reading as evidence of what its backend
     * currently holds.
     *
     * Only that schema's clock moves. A datasource-wide clock would let one busy schema's traffic keep
     * postponing every sibling's re-measure, so drift on a quiet schema would go unnoticed for as long as
     * the busy one kept moving — per schema, the reset skips work just done without starving anything.
     *
     * A reading the manager did not accept — dirty, untrusted, ordered behind what is held, or naming
     * content nothing resolves — leaves the schema due, so the next nudge asks again. That is the
     * fail-closed direction: the cost is one extra measurement, while skipping the reset can only ever
     * delay noticing drift.
     */
    private fun noteAcceptedReading(datasourceName: String, schema: String, outcome: AuthoritativeOutcome) {
        if (outcome is AuthoritativeOutcome.Dropped) return
        lastCleanNanos[datasourceName to schema] = clockNanos()
    }

    /**
     * The schemas of [datasourceName] whose re-measure clock has expired — what the manager asks a proxy
     * to re-read.
     *
     * Only schemas the manager already holds are named. A schema it has never seen has nothing to
     * confirm and is found by the whole-server scan instead, which is also the only reading that may
     * decide a schema exists at all.
     */
    fun dueSchemas(datasourceName: String): Set<String> = synchronized(stateLock) {
        val now = clockNanos()
        authoritative.keys
            .filter { it.first == datasourceName }
            .filterTo(LinkedHashSet()) { key ->
                // Absent means nothing has read this schema's backend since the pointer appeared — a
                // restart rebuild, or an install by a path that left no confirmation. Due immediately, so
                // an unconfirmed pointer cannot sit unmeasured for a whole interval.
                val lastClean = lastCleanNanos[key] ?: return@filterTo true
                now - lastClean > remeasureNanos
            }
            .mapTo(LinkedHashSet()) { it.second }
    }

    /**
     * Decide what one observation may do to the shared pointer for its schema. Must be called under
     * [stateLock], so the decision and the write it drives cannot straddle another writer.
     */
    private fun shareabilityOf(
        observation: CatalogObservation,
        current: Authoritative?,
    ): AuthoritativeOutcome {
        when (observation.trust()) {
            ObservationTrust.UNTRUSTED_HASH -> return AuthoritativeOutcome.Dropped("hash is not a trusted measurement")
            ObservationTrust.DIRTY -> return AuthoritativeOutcome.Dropped("measured inside an open transaction")
            ObservationTrust.SHAREABLE -> Unit
        }
        val hash = observation.hash ?: return AuthoritativeOutcome.Dropped("no hash")
        val observed = ReadingVersion(hash, observation.dbClockMicros, observation.backendId)
        val held = current?.let { ReadingVersion(it.hash, it.dbClockMicros, it.backendId) }
        return when (val order = orderReading(held, observed)) {
            ReadingOrder.SAME -> AuthoritativeOutcome.Confirmed
            ReadingOrder.STALE -> AuthoritativeOutcome.Dropped(
                "older than the held reading (${observation.dbClockMicros} <= ${current?.dbClockMicros}) " +
                    "on backend '${observation.backendId}'",
            )
            else -> {
                if (order == ReadingOrder.TIED || order == ReadingOrder.INCOMPARABLE) {
                    log.warn(
                        "datasource '{}' schema '{}': installing by accept order ({})",
                        observation.datasourceName, observation.schema, order,
                    )
                }
                AuthoritativeOutcome.Installed
            }
        }
    }

    /**
     * Write one connection observation's content through to the persisted catalog. Never namespace-complete:
     * a connection measures the schemas it needs, so its silence about a sibling schema says nothing about
     * whether that schema exists.
     */
    private fun projectObservation(ds: Datasource, observation: CatalogObservation) {
        val projection = projection ?: return
        val columns = observation.columns ?: return
        val hash = observation.hash ?: return
        runCatching {
            projection.projectSchemas(
                ds.id,
                listOf(
                    ProjectedObservation(
                        observation.schema,
                        columns.map {
                            DatasourceStore.PushedColumn(it.schema, it.table, it.column, it.dataType, it.ordinal, it.nullable)
                        },
                        ReadingVersion(hash, observation.dbClockMicros, observation.backendId),
                    ),
                ),
                namespaceComplete = false,
                namespace = null,
            )
        }.onFailure {
            // The in-memory state that enforcement decides against is already correct; the stored catalog
            // feeds browse and classification joins and simply ages until the next reading. Failing the push
            // would instead refuse the connection over a projection the decision path never reads.
            log.warn(
                "datasource '{}' schema '{}': persisting the observed catalog failed",
                ds.name, observation.schema, it,
            )
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

    /**
     * Where an untrusted measurement's content is kept: a scope only the observing connection names, so the
     * content is stored without being content-addressed.
     *
     * The hash on such a push is a real measured value that simply failed its coherence bracket, so filing
     * the columns under it in the shared scope would let a later genuine observation of that hash resolve to
     * columns the producer already proved stale — the exact adoption of unproven content the trust flag
     * exists to prevent. Keeping it out of the shared scope also stops it from colliding with that genuine
     * observation and rejecting it as an alias.
     */
    private fun connectionScopedKey(connection: EnforcementConnection, schema: String, hash: ContentHash): PoolKey =
        PoolKey("conn:" + connection.connectionId.toByteArray().joinToString("") { "%02x".format(it) }, schema, hash)

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

    /**
     * The hash a conditional REFETCH may carry for a connection's held schema, or null for an unconditional
     * fetch. An untrusted held hash is never offered: the proxy would answer `unchanged` against bytes no
     * coherent measurement stands behind, and the connection would keep columns the producer already proved
     * did not match that hash. Absence of trust costs one full fetch, which is the fail-closed direction.
     */
    private fun heldRefetchToken(connection: EnforcementConnection, schema: String): ContentHash? =
        connection.held[schema]?.takeIf { it.trusted }?.hash

    /** Issue or replay pending before-decide commands without changing an existing command's CAS token. */
    fun markBeforeDecide(connection: EnforcementConnection, schemas: Collection<String>): List<Refetch> =
        markPending(connection, schemas) { schema ->
            val auth = authoritative[connection.binding.datasourceName to schema]
            PendingRefetch(heldRefetchToken(connection, schema) ?: auth?.hash, auth?.hash)
        }

    /** A catalog-miss qualifier was never held: force one bounded unconditional fetch. */
    fun markCatalogMiss(connection: EnforcementConnection, schemas: Collection<String>): List<Refetch> =
        markPending(connection, schemas) { schema ->
            PendingRefetch(null, authoritative[connection.binding.datasourceName to schema]?.hash)
        }

    fun markAfterStatement(connection: EnforcementConnection, schemas: Collection<String>): List<Refetch> =
        markPending(connection, schemas) { schema ->
            PendingRefetch(
                heldRefetchToken(connection, schema),
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
     * The schemas this connection holds from a reading taken inside a transaction.
     *
     * A dirty reading never moves the shared pointer, so nothing about it is self-correcting: the
     * connection is the only holder of that content and `freshnessGate` sees no moved hash to re-check
     * against. Naming them lets the transaction's end re-measure them outside the transaction, where the
     * reading is clean and trues the shared state up immediately rather than leaving it to the
     * re-measure clock. Must be called while holding [EnforcementConnection.mutex].
     */
    fun dirtyHeldSchemas(connection: EnforcementConnection): Set<String> =
        connection.held.entries.filterTo(LinkedHashSet()) { it.value.dirty }.mapTo(LinkedHashSet()) { it.key }

    /**
     * Apply a whole-server or scoped configuration reading — the registration scan and the ambient refresh.
     *
     * This is the path that dissolves the two-catalog split. The reading carries a per-schema hash measured
     * on the backend, so its content is content-addressable exactly like a connection's fragment: it seeds
     * the pool and the authoritative pointer rather than merely confirming what some connection already
     * measured. That is what lets the first connection after boot adopt instead of re-reading thousands of
     * columns the control plane was handed seconds earlier.
     *
     * A schema whose hash is absent or untrusted seeds nothing: with no version a reading cannot be ordered,
     * and content the manager cannot order is content it cannot safely install. Its columns are still
     * stored, because the stored catalog is what browse and classification read and they are no worse off
     * than before the reading carried versions at all.
     */
    fun applyConfigCatalog(request: CatalogRequest, ds: Datasource): ConfigCatalogResult {
        val columnsBySchema = request.columnsList
            .groupBy({ it.schema }) { FragmentColumn(it.schema, it.table, it.column, it.dataType, it.ordinal, it.nullable) }
        // A proxy that declares which schemas it carries is taken at its word, so "carried but empty" stays
        // distinguishable from "not carried". One that declares nothing — an older proxy — is read the only
        // way its message supports: the schemas its columns mention are the ones it carried.
        val contentSchemas = if (request.contentSchemasList.isEmpty()) {
            columnsBySchema.keys
        } else {
            request.contentSchemasList.toSet()
        }
        // Only a reading that says it enumerated every schema may imply deletion. A scoped set speaks for
        // the schemas it names and nothing else: both engines filter information_schema by privilege, so a
        // least-privilege account reads a strict subset, and deleting on that erases what it cannot see.
        //
        // A hashes-only reading answers a nudge for particular schemas, so it is scoped by construction and
        // its completeness claim is refused here rather than trusted. The check is the manager's, not the
        // producer's: the delete is what the flag licenses, so the component that would perform it is the
        // one that has to be sure — a proxy that sets both flags through a bug or a compromise then costs
        // one ignored claim instead of every schema it did not name.
        val namespaceComplete = request.namespaceComplete && !request.hashesOnly
        if (request.namespaceComplete && request.hashesOnly) {
            log.warn(
                "datasource '{}': a hashes-only reading claimed a complete namespace; refusing it the license to delete",
                ds.name,
            )
        }
        // An old proxy sends no schema_hashes. Its columns still carry the schemas it read, so the stored
        // catalog is written exactly as before — versionless, seeding nothing.
        val versioned = request.schemaHashesList.associate { it.schema to it }

        val observations = request.schemaHashesList.mapNotNull { pushed ->
            if (!pushed.trusted || pushed.schema.isBlank()) return@mapNotNull null
            CatalogObservation(
                datasourceName = ds.name,
                schema = pushed.schema,
                hash = ContentHash(pushed.hash),
                // "declared with no columns" and "not carried by this push" are different claims: a schema
                // this push does not carry keeps its stored content and only records its version, while one
                // declared present with no columns genuinely has none.
                columns = if (pushed.schema in contentSchemas) columnsBySchema[pushed.schema].orEmpty() else null,
                dbClockMicros = request.dbClockMicros,
                backendId = request.backendId,
                dirty = false,
            )
        }

        val fetch = ArrayList<String>()
        synchronized(stateLock) {
            for (observation in observations) {
                val applied = installShared(ds, observation)
                noteAcceptedReading(ds.name, observation.schema, applied)
                if (applied is AuthoritativeOutcome.Dropped) {
                    if (applied.reason == NO_CONTENT_FOR_HASH) fetch += observation.schema
                    log.warn(
                        "datasource '{}' schema '{}': configuration observation not installed ({})",
                        ds.name, observation.schema, applied.reason,
                    )
                }
            }
            if (namespaceComplete) {
                val present = request.schemaHashesList.map { it.schema }.toSet()
                val dropped = dropSchemasAbsentFrom(ds.name, present)
                if (dropped.isNotEmpty()) {
                    log.info("datasource '{}': {} schema(s) gone from the server", ds.name, dropped.size)
                }
            }
        }

        // Present-but-untrusted and absent are different claims, and only the first is a statement about the
        // reading's quality. A schema the producer declared it could not measure coherently keeps its stored
        // rows — its columns may have been read while the backend moved under them. A reading that names no
        // hashes at all is an older proxy saying nothing about quality either way, and its columns are
        // stored exactly as before hashes existed.
        val declaredUntrusted = request.schemaHashesList.filterNot { it.trusted }.map { it.schema }.toSet()
        val projected = (contentSchemas + versioned.keys).map { schema ->
            val pushed = versioned[schema]
            ProjectedObservation(
                schema = schema,
                columns = if (schema in contentSchemas && schema !in declaredUntrusted) {
                    columnsBySchema[schema].orEmpty().map {
                        DatasourceStore.PushedColumn(it.schema, it.table, it.column, it.dataType, it.ordinal, it.nullable)
                    }
                } else {
                    null
                },
                version = pushed?.takeIf { it.trusted }?.let {
                    ReadingVersion(ContentHash(it.hash), request.dbClockMicros, request.backendId)
                },
            )
        }
        val stored = projection?.projectSchemas(
            ds.id,
            projected,
            namespaceComplete,
            ProjectedNamespace(
                request.defaultSchemasList,
                if (request.hasMysqlLowerCaseTableNames()) request.mysqlLowerCaseTableNames else null,
                request.engineVersion,
            ),
        ) ?: 0
        return ConfigCatalogResult(stored, fetch)
    }

    /**
     * Rebuild the pool and the authoritative pointers from the persisted catalog, at startup.
     *
     * Without this a restart empties every pointer, so each connection re-reads schemas the control plane
     * already has the columns and the version for. Rebuilding is safe because it does not weaken either
     * adoption mode's argument: verify re-proves the content against its own backend before adopting it,
     * and trust already accepts exactly this provenance — these are the rows the last reading wrote.
     *
     * The rebuilt entry keeps the stored DB clock, so an arriving reading is ordered against what the
     * backend was last proved to be rather than against nothing. Its control-plane measurement time is
     * now: the staleness bound asks how long since the control plane last saw this confirmed, and a
     * process that just started has not confirmed anything — pretending otherwise would put a connection
     * on rebuilt content already past its bound.
     *
     * [resolve] maps a stored datasource id to the datasource, which decides the pool scope; a reading
     * whose datasource no longer exists is skipped. Returns how many schemas were rebuilt.
     */
    fun rebuildFromProjection(resolve: (Long) -> Datasource?): Int {
        val projection = projection ?: return 0
        val readings = runCatching { projection.storedSchemaReadings() }.getOrElse {
            // Enforcement is correct without this: every schema simply reads as absent, which is the
            // unconditional-fetch path. Refusing to start over a cache warm-up would be the worse failure.
            log.warn("rebuilding the catalog from the stored projection failed; connections will re-measure", it)
            return 0
        }
        var rebuilt = 0
        synchronized(stateLock) {
            for (reading in readings) {
                val ds = resolve(reading.datasourceId) ?: continue
                if (reading.columns.isEmpty()) continue
                val key = poolKey(ds, reading.schema, reading.version.hash)
                val fragment = SchemaFragment(key, reading.version.hash, reading.columns)
                val retained = retain(fragment, 1)
                if (retained.fragment.columns != fragment.columns) {
                    // Two datasources' stored rows disagree under one content hash, so at most one of them
                    // describes what that hash names. Neither is installed: leaving both absent costs a
                    // fetch, while guessing would hand a connection another backend's structure.
                    release(key)
                    log.warn(
                        "datasource '{}' schema '{}': stored rows do not match the pooled fragment for their hash; not rebuilt",
                        ds.name, reading.schema,
                    )
                    continue
                }
                val now = clockNanos()
                authoritative[ds.name to reading.schema] = Authoritative(
                    reading.version.hash, key, authoritativeEpoch.incrementAndGet(), now,
                    reading.version.dbClockMicros, reading.version.backendId,
                )
                // Deliberately NOT marked as observed clean: nothing has read the backend since this
                // process started, so every rebuilt schema is due at once and the first nudge re-confirms
                // them all. That is one grouped hash query, against a pointer that would otherwise sit
                // unverified for a full re-measure interval.
                rebuilt++
            }
        }
        if (rebuilt > 0) log.info("rebuilt {} catalog schema(s) from the stored projection", rebuilt)
        return rebuilt
    }

    /**
     * Install (or confirm) one datasource-scoped observation into the pool and the authoritative pointer.
     * Must be called under [stateLock].
     *
     * A reading with no columns can only point at content the pool already holds. It may never leave the
     * pointer naming a fragment nothing resolves: an adopting connection would then decide against an empty
     * structure, and a connection sent that hash as a conditional-refetch token could reply `unchanged`
     * against content that does not exist. The unresolvable case is reported so the proxy fetches it.
     */
    private fun installShared(ds: Datasource, observation: CatalogObservation): AuthoritativeOutcome {
        val hash = observation.hash ?: return AuthoritativeOutcome.Dropped("no hash")
        val authKey = ds.name to observation.schema
        val previousAuth = authoritative[authKey]
        val outcome = shareabilityOf(observation, previousAuth)
        val now = clockNanos()
        if (outcome is AuthoritativeOutcome.Confirmed) {
            if (previousAuth != null) {
                authoritative[authKey] = previousAuth.copy(
                    measuredNanos = now,
                    dbClockMicros = maxOf(previousAuth.dbClockMicros, observation.dbClockMicros),
                )
            }
            return outcome
        }
        if (outcome !is AuthoritativeOutcome.Installed) return outcome

        val key = poolKey(ds, observation.schema, hash)
        val columns = observation.columns ?: pool[key]?.fragment?.columns
            ?: return AuthoritativeOutcome.Dropped(NO_CONTENT_FOR_HASH)
        val fragment = SchemaFragment(key, hash, columns)
        val existing = pool[key]
        if (existing != null && existing.fragment.columns != fragment.columns) {
            return AuthoritativeOutcome.Dropped("content hash aliases different fragment columns")
        }
        val retained = retain(fragment, if (previousAuth?.pooledRef != key) 1 else 0)
        if (retained.fragment.columns != fragment.columns) {
            return AuthoritativeOutcome.Dropped("content hash aliases different fragment columns")
        }
        authoritative[authKey] = Authoritative(
            hash, key, authoritativeEpoch.incrementAndGet(), now, observation.dbClockMicros, observation.backendId,
        )
        if (previousAuth != null && previousAuth.pooledRef != key) release(previousAuth.pooledRef)
        return outcome
    }

    /**
     * Drop the authoritative entries for schemas a namespace-complete reading proved gone.
     *
     * Only a reading that enumerated every schema on the server may do this, so the caller establishes that
     * before calling: both engines filter `information_schema` by privilege, and a least-privilege account's
     * subset presented as a complete enumeration would delete every schema it cannot see.
     *
     * Live connections keep what they hold, exactly as on a retarget — each re-verifies on its own clock,
     * and emptying their structure mid-session would pull the catalog out from under an in-flight statement.
     */
    fun dropSchemasAbsentFrom(datasourceName: String, present: Set<String>): Set<String> = synchronized(stateLock) {
        val dropped = LinkedHashSet<String>()
        for (key in authoritative.keys.filter { it.first == datasourceName && it.second !in present }) {
            val auth = authoritative.remove(key) ?: continue
            release(auth.pooledRef)
            lastCleanNanos.remove(key)
            dropped += key.second
        }
        dropped
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
            lastCleanNanos.remove(key)
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
