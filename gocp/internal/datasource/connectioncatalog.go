package datasource

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"google.golang.org/grpc/codes"
)

// ---- The ephemeral enforcement catalog (ConnectionCatalog.kt, 05-datasources-catalog.md §5) -----
//
// Ephemeral, fail-closed enforcement catalog state. The wire exposes datasource/principal/token-kind
// but NO proxy-instance identifier, so [Binding] binds exactly those authoritative fields;
// backendGeneration binds the first backend-connection instance that successfully pushes and
// thereafter advances monotonically.

const connectionIDBytes = 16

// DefaultStalenessNanos is how long a connection may hold a schema fragment before re-measuring it.
// This is the backstop for drift the control plane never learned about — DDL run straight against
// the backend, which no push reports — so it bounds how long such a change can go unnoticed.
//
// Set ABOVE the proxy's ambient refresh interval, which re-reads the whole backend catalog and,
// through [ConnectionCatalogRegistry.RecordAmbientMeasurement], re-measures the pooled fragments it
// still agrees with. That cycle is what detects out-of-band DDL; this bound is the ceiling for a
// connection whose schemas the refresh did not confirm, so it only has to sit far enough above the
// interval that an ordinary slow or skipped cycle does not put a full fetch in front of a query.
const DefaultStalenessNanos int64 = 15 * 60 * 1_000_000_000

// ContentHash is an immutable value key for catalog content.
//
// 🔒 Kotlin's comment — "ByteString is required: raw ByteArray has reference equality" — has an
// exact Go counterpart the spec flags as "the single easiest map-key bug to introduce": a []byte is
// not comparable and cannot be a map key at all, while a string is. The bytes live in a string.
type ContentHash string

// NewContentHash wraps raw hash bytes.
func NewContentHash(b []byte) ContentHash { return ContentHash(b) }

// Bytes returns the raw hash bytes.
func (h ContentHash) Bytes() []byte { return []byte(h) }

// FragmentColumn is the six enforcement-relevant fields of a pushed column; value equality is used
// for content comparison (so every field is comparable and the struct works as a map key).
type FragmentColumn struct {
	Schema   string
	Table    string
	Column   string
	DataType string
	Ordinal  int32
	Nullable bool
}

// PoolKey identifies pooled content. See [ConnectionCatalogRegistry.poolKey] for the scope rule.
type PoolKey struct {
	Scope  string
	Schema string
	Hash   ContentHash
}

// SchemaFragment is immutable pooled content.
type SchemaFragment struct {
	Key     PoolKey
	Hash    ContentHash
	Columns []FragmentColumn
}

// PooledFragment is a fragment plus its reference count.
type PooledFragment struct {
	Fragment SchemaFragment
	RefCount int
}

// Authoritative is the per-(datasource, schema) latest accepted observation.
//
// 🔒 INV-A5-23 — MeasuredNanos lives HERE, never on [PooledFragment]. Identical content is pooled
// once and shared across datasources, while a reading only ever speaks for the backend it came from.
// Moving it to the pooled fragment lets one datasource's refresh vouch for another datasource nobody
// read.
type Authoritative struct {
	Hash          ContentHash
	PooledRef     PoolKey
	Epoch         int64
	MeasuredNanos int64
}

// Binding is the whole identity of a connection, value-equal.
type Binding struct {
	DatasourceName string
	Principal      string
	TokenKind      string
}

// HeldSchema is what one connection holds for one schema.
type HeldSchema struct {
	PooledRef PoolKey
	Hash      ContentHash
	// LastFetchNanos is when structure was actually transferred; LastVerifiedNanos is when the
	// backend last confirmed the hash. INV-A5-32: only the LATTER drives the staleness gate.
	LastFetchNanos    int64
	LastVerifiedNanos int64
	// RevalidatedAgainstAuthoritativeHash records WHICH authoritative version this connection's
	// "unchanged" reply was measured against, so one unchanged reply quiets exactly one version and
	// the NEXT authoritative change re-gates (INV-A5-37 rule 3). Collapsing it into a boolean
	// "revalidated" flag makes a connection permanently immune to sibling-observed drift.
	RevalidatedAgainstAuthoritativeHash *ContentHash
}

// PendingRefetch is the push compare-and-set token.
type PendingRefetch struct {
	ExpectedHash         *ContentHash
	AuthoritativeAtIssue *ContentHash
}

// ConnectionID is 16 CSPRNG bytes carried as a comparable string (see [ContentHash] for why).
type ConnectionID string

// Bytes returns the raw connection-id bytes, the shape the proto carries.
func (c ConnectionID) Bytes() []byte { return []byte(c) }

// OpenConnection is what open/recover hand back.
type OpenConnection struct {
	ConnectionID ConnectionID
	OnOpen       []*pb.Refetch
}

// EnforcementConnection is one live wire connection's mutable catalog state, guarded by its own
// mutex.
type EnforcementConnection struct {
	ConnectionID ConnectionID
	Binding      Binding
	Held         map[string]HeldSchema
	Pending      map[string]PendingRefetch
	// BackendGeneration is nil until the first accepted push binds it.
	BackendGeneration *int64
	Generation        int64

	// mu is the per-connection lock. 🔒 INV-A5-24: the ordering is ALWAYS connection-mutex THEN
	// stateLock, never the reverse. (Kotlin's Mutex is a coroutine mutex and its stateLock a blocking
	// monitor never held across a suspension point; the suspending half is a JVM artifact — OMIT.)
	mu sync.Mutex
	// lastUsedNanos is atomic because sweepIdle's cheap pre-check reads it outside the mutex
	// (INV-A5-47). Kotlin's @Volatile is exactly this.
	lastUsedNanos atomic.Int64
}

// LastUsedNanos exposes the sweeper's clock for tests and diagnostics.
func (c *EnforcementConnection) LastUsedNanos() int64 { return c.lastUsedNanos.Load() }

// CatalogMutationResult is Applied | Rejected. TODO(A10): the gRPC layer maps Rejected.Code.
type CatalogMutationResult interface{ isCatalogMutationResult() }

// Applied carries the connection generation after the mutation.
type Applied struct{ Generation int64 }

// Rejected carries the gRPC status the RPC boundary answers with.
type Rejected struct {
	Code        codes.Code
	Description string
}

func (Applied) isCatalogMutationResult()  {}
func (Rejected) isCatalogMutationResult() {}

// refetchOf builds the proxy's conditional-refetch command; an absent hash leaves if_hash_differs
// empty (unconditional fetch, fail-safe).
func refetchOf(schema string, hash *ContentHash) *pb.Refetch {
	cmd := &pb.Refetch{Schema: schema}
	if hash != nil {
		cmd.IfHashDiffers = hash.Bytes()
	}
	return cmd
}

func hashEq(a, b *ContentHash) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

type authKey struct {
	Datasource string
	Schema     string
}

// ConnectionCatalogRegistry owns the pool, the authoritative entries and the live connections.
//
// 🔒 INV-A5-24 — two lock levels, and the reason. A full push transitions both the held and the
// authoritative references; the global monitor makes those multi-map transitions atomic. Per-
// connection ordering is [EnforcementConnection.mu]; cross-map atomicity is stateLock. ORDER:
// connection-mutex THEN stateLock, never the reverse.
//
// ⚠️ LANGUAGE-FORCED DEVIATION. Kotlin's three ConcurrentHashMaps tolerate lock-free reads
// (freshnessGate reads `authoritative` with only the connection mutex; authoritativeFor /
// measuredNanosFor / pooledFor / poolSize read with no lock at all). A Go map is not merely stale
// under a concurrent write — it FATALLY throws "concurrent map read and map write" — so every read
// here takes the lock that guards its map. freshnessGate therefore takes stateLock while holding the
// connection mutex, which is the mandated order, so the invariant is preserved rather than bent.
// `connections` gets its own leaf mutex (connMu): it is never held while acquiring stateLock or a
// connection mutex, so it cannot participate in a cycle.
type ConnectionCatalogRegistry struct {
	clockNanos     func() int64
	rand           io.Reader
	stalenessNanos int64

	// stateLock is the global monitor.
	stateLock          sync.Mutex
	pool               map[PoolKey]PooledFragment
	authoritative      map[authKey]Authoritative
	authoritativeEpoch atomic.Int64

	connMu      sync.Mutex
	connections map[ConnectionID]*EnforcementConnection
}

// RegistryOption configures a [ConnectionCatalogRegistry]. The three seams match the Kotlin
// constructor's three defaulted parameters (clockNanos, secureRandom, stalenessNanos), which exist
// for the same reason: PerConnectionCatalogStateTest drives all three.
type RegistryOption func(*ConnectionCatalogRegistry)

// WithClockNanos injects the monotonic clock (default: time.Now-based nanoseconds).
func WithClockNanos(clock func() int64) RegistryOption {
	return func(r *ConnectionCatalogRegistry) { r.clockNanos = clock }
}

// WithRandom injects the CSPRNG connection ids are minted from (default: crypto/rand.Reader).
func WithRandom(src io.Reader) RegistryOption {
	return func(r *ConnectionCatalogRegistry) { r.rand = src }
}

// WithStalenessNanos overrides [DefaultStalenessNanos].
func WithStalenessNanos(n int64) RegistryOption {
	return func(r *ConnectionCatalogRegistry) { r.stalenessNanos = n }
}

// NewConnectionCatalogRegistry builds an empty registry.
func NewConnectionCatalogRegistry(opts ...RegistryOption) *ConnectionCatalogRegistry {
	r := &ConnectionCatalogRegistry{
		clockNanos:     func() int64 { return time.Now().UnixNano() },
		rand:           rand.Reader,
		stalenessNanos: DefaultStalenessNanos,
		pool:           map[PoolKey]PooledFragment{},
		authoritative:  map[authKey]Authoritative{},
		connections:    map[ConnectionID]*EnforcementConnection{},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// StalenessNanos is the configured staleness ceiling (Kotlin's `internal val stalenessNanos`).
func (r *ConnectionCatalogRegistry) StalenessNanos() int64 { return r.stalenessNanos }

// Open mints a connection id and issues its initial refetch commands.
//
// adoptHeldContent lets a connection start from catalog content the control plane already holds
// instead of fetching it, for an engine whose scan cannot vary by connection
// ([CatalogIsConnectionIndependent]). A schema with nothing held still gets its fetch, so this only
// removes redundant work — never the first measurement (INV-A5-28).
//
// 🔒 INV-A5-25 — connection ids are 16 CSPRNG bytes with a COLLISION RETRY LOOP. Never "generate and
// assume unique". TODO(A10): the RPC boundary additionally rejects any connection_id whose length ≠ 16.
func (r *ConnectionCatalogRegistry) Open(binding Binding, schemas []string, adoptHeldContent bool) OpenConnection {
	for {
		buf := make([]byte, connectionIDBytes)
		if _, err := io.ReadFull(r.rand, buf); err != nil {
			// Kotlin's SecureRandom.nextBytes cannot fail. A connection id that is not CSPRNG output
			// must never be issued, so this is fail-closed rather than a fallback.
			panic(fmt.Errorf("connection id CSPRNG read failed: %w", err))
		}
		id := ConnectionID(buf)
		connection := r.newConnection(id, binding)
		if r.putIfAbsent(id, connection) {
			return OpenConnection{ConnectionID: id, OnOpen: r.issueInitial(connection, schemas, adoptHeldContent)}
		}
	}
}

// Recover recreates a well-formed id after a CP restart; an already-live id is NEVER overwritten.
//
// 🔒 INV-A5-26 — recovery never adopts an id that is already live. Overwriting would give a second
// caller a connection record whose held/pending state the first caller is mid-flight on. Returns
// ok=false when the id is taken (TODO(A10): the RPC maps that to ABORTED).
func (r *ConnectionCatalogRegistry) Recover(
	connectionID ConnectionID, binding Binding, schemas []string, adoptHeldContent bool,
) (OpenConnection, bool) {
	connection := r.newConnection(connectionID, binding)
	if !r.putIfAbsent(connectionID, connection) {
		return OpenConnection{}, false
	}
	return OpenConnection{
		ConnectionID: connectionID,
		OnOpen:       r.issueInitial(connection, schemas, adoptHeldContent),
	}, true
}

func (r *ConnectionCatalogRegistry) newConnection(id ConnectionID, binding Binding) *EnforcementConnection {
	c := &EnforcementConnection{
		ConnectionID: id,
		Binding:      binding,
		Held:         map[string]HeldSchema{},
		Pending:      map[string]PendingRefetch{},
	}
	c.lastUsedNanos.Store(r.clockNanos())
	return c
}

func (r *ConnectionCatalogRegistry) putIfAbsent(id ConnectionID, c *EnforcementConnection) bool {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if _, exists := r.connections[id]; exists {
		return false
	}
	r.connections[id] = c
	return true
}

func (r *ConnectionCatalogRegistry) lookup(id ConnectionID) *EnforcementConnection {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	return r.connections[id]
}

// removeIfSame is ConcurrentHashMap.remove(key, value).
func (r *ConnectionCatalogRegistry) removeIfSame(id ConnectionID, c *EnforcementConnection) bool {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if r.connections[id] != c {
		return false
	}
	delete(r.connections, id)
	return true
}

// issueInitial runs under stateLock.
//
// 🔒 INV-A5-27 — adoption inherits the ORIGINAL measurement time, not now(). "The staleness gate must
// keep counting from when the backend was actually read, or a stream of new connections would
// refresh the clock forever and the bound would never fire." This is the single most important
// non-obvious line in the file.
//
// ⚠️ Reproduced quirk (§10 Q2): this filters ONLY blank schemas — it does NOT filter pg_temp*, unlike
// freshnessGate and markPending. Net effect: a PG connection is issued a one-time refetch for
// pg_temp_N whose pending entry is then invisible to every gate and never re-demanded. Deliberate or
// drift is an open question; the behaviour is carried as-is.
func (r *ConnectionCatalogRegistry) issueInitial(
	connection *EnforcementConnection, schemas []string, adoptHeldContent bool,
) []*pb.Refetch {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()

	commands := []*pb.Refetch{}
	seen := map[string]struct{}{}
	for _, schema := range schemas {
		if strings.TrimSpace(schema) == "" {
			continue
		}
		if _, dup := seen[schema]; dup {
			continue
		}
		seen[schema] = struct{}{}

		auth, hasAuth := r.authoritative[authKey{connection.Binding.DatasourceName, schema}]
		var pooled PooledFragment
		hasPooled := false
		if hasAuth {
			pooled, hasPooled = r.pool[auth.PooledRef]
		}
		// Where a scan cannot vary by connection, content another connection already measured is this
		// connection's answer too, so it starts from that instead of putting a backend fetch in front
		// of the first query.
		if adoptHeldContent && hasAuth && hasPooled {
			r.retain(pooled.Fragment, 1)
			connection.Held[schema] = HeldSchema{
				PooledRef:                           auth.PooledRef,
				Hash:                                auth.Hash,
				LastFetchNanos:                      auth.MeasuredNanos,
				LastVerifiedNanos:                   auth.MeasuredNanos,
				RevalidatedAgainstAuthoritativeHash: nil,
			}
			continue
		}
		var expected *ContentHash
		if hasAuth {
			h := auth.Hash
			expected = &h
		}
		connection.Pending[schema] = PendingRefetch{ExpectedHash: expected, AuthoritativeAtIssue: expected}
		commands = append(commands, refetchOf(schema, expected))
	}
	return commands
}

// Find is a bare map lookup: no mutex on the connection, no lastUsedNanos touch. Used by A10 to
// pre-check the binding before decideConnection, and by tests.
func (r *ConnectionCatalogRegistry) Find(connectionID ConnectionID) *EnforcementConnection {
	return r.lookup(connectionID)
}

// WithConnection runs block under the connection's mutex, re-checking map identity INSIDE the lock.
//
// 🔒 INV-A5-29 — the post-lock identity re-check is what makes close/sweep fail closed. Close and
// sweepIdle remove from the map BEFORE clearing state, so a caller that captured the record earlier
// must re-verify map identity after acquiring the mutex or it would operate on a torn-down
// connection. The same re-check appears in ApplyPush. It is REFERENCE identity, not value equality.
//
// ⚠️ LANGUAGE-FORCED DEVIATION: Kotlin's `suspend fun <T> withConnection(...): T?` is generic; Go
// methods cannot take type parameters, so the result is returned by the caller's closure capture and
// this reports only found/error. Same control flow: found=false is Kotlin's null.
func (r *ConnectionCatalogRegistry) WithConnection(
	connectionID ConnectionID, block func(*EnforcementConnection) error,
) (found bool, err error) {
	connection := r.lookup(connectionID)
	if connection == nil {
		return false, nil
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if r.lookup(connectionID) != connection {
		return false, nil
	}
	connection.lastUsedNanos.Store(r.clockNanos())
	return true, block(connection)
}

// ApplyPush applies a proxy's SchemaFragmentPush to the connection it names.
func (r *ConnectionCatalogRegistry) ApplyPush(request *pb.SchemaFragmentPush, ds Datasource) CatalogMutationResult {
	id := ConnectionID(request.GetConnectionId())
	connection := r.lookup(id)
	if connection == nil {
		return Rejected{codes.NotFound, "unknown connection_id"}
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if r.lookup(id) != connection {
		return Rejected{codes.NotFound, "unknown connection_id"}
	}
	connection.lastUsedNanos.Store(r.clockNanos())
	return r.applyPushLocked(connection, request, ds)
}

// applyPushLocked runs the validation ladder, then one of the two branches. Every rung is a distinct
// rejection.
func (r *ConnectionCatalogRegistry) applyPushLocked(
	connection *EnforcementConnection, request *pb.SchemaFragmentPush, ds Datasource,
) CatalogMutationResult {
	// Rung 1.
	if request.GetDatasourceName() != connection.Binding.DatasourceName || request.GetDatasourceName() != ds.Name {
		return Rejected{codes.FailedPrecondition, "datasource binding mismatch"}
	}
	// Rung 2 — the Go trap. backend_generation is proto uint64; the JVM reads it as a signed Long, so
	// a value above 2^63-1 arrives NEGATIVE and Kotlin's `< 0` catches it. In Go the field IS uint64
	// and can never be negative, so the same rung has to be spelled as an explicit range check.
	// Silently dropping it widens what the proxy can assert.
	if request.GetBackendGeneration() > math.MaxInt64 {
		return Rejected{codes.InvalidArgument, "backend_generation exceeds signed range"}
	}
	backendGeneration := int64(request.GetBackendGeneration())
	// Rung 3.
	if connection.BackendGeneration != nil && backendGeneration < *connection.BackendGeneration {
		return Rejected{codes.FailedPrecondition, "stale backend_generation"}
	}
	// Rung 4 — 🔒 INV-A5-30: a push must answer a pending REFETCH. `pending` is the CAS token, so the
	// proxy cannot install content the control plane never asked for.
	pending, hasPending := connection.Pending[request.GetSchema()]
	if !hasPending {
		return Rejected{codes.FailedPrecondition, "schema push has no pending REFETCH command"}
	}
	pushedHash := NewContentHash(request.GetContentHash())

	if request.GetUnchanged() {
		// 🔒 INV-A5-31 — an unchanged reply cannot satisfy an unconditional first fetch. A held schema
		// with no fragment behind it would make structuralRows silently omit the schema, and every
		// table in it would resolve as a catalog miss — or worse, resolve to a same-named table
		// elsewhere.
		if pending.ExpectedHash == nil {
			return Rejected{codes.FailedPrecondition, "unchanged push cannot satisfy an unconditional REFETCH"}
		}
		expected := *pending.ExpectedHash
		if pushedHash != expected {
			return Rejected{codes.FailedPrecondition, "unchanged hash mismatch"}
		}
		r.stateLock.Lock()
		defer r.stateLock.Unlock()
		key := r.poolKey(ds, request.GetSchema(), expected)
		pooled, ok := r.pool[key]
		if !ok {
			return Rejected{codes.FailedPrecondition, "unchanged push references an unknown pooled fragment"}
		}
		previous, hadPrevious := connection.Held[request.GetSchema()]
		if !hadPrevious || previous.PooledRef != key {
			r.retain(pooled.Fragment, 1)
		}
		now := r.clockNanos()
		// INV-A5-32 — an unchanged reply is a live VERIFICATION, not a fetch: preserve the separate
		// last-fetch clock (zero for a fresh connection that adopted a shared fragment).
		lastFetch := int64(0)
		if hadPrevious {
			lastFetch = previous.LastFetchNanos
		}
		connection.Held[request.GetSchema()] = HeldSchema{
			PooledRef:                           key,
			Hash:                                expected,
			LastFetchNanos:                      lastFetch,
			LastVerifiedNanos:                   now,
			RevalidatedAgainstAuthoritativeHash: pending.AuthoritativeAtIssue,
		}
		if hadPrevious && previous.PooledRef != key {
			r.release(previous.PooledRef)
		}
		return r.accept(connection, request.GetSchema(), backendGeneration)
	}

	columns := make([]FragmentColumn, 0, len(request.GetColumns()))
	for _, c := range request.GetColumns() {
		columns = append(columns, FragmentColumn{
			Schema: c.GetSchema(), Table: c.GetTable(), Column: c.GetColumn(),
			DataType: c.GetDataType(), Ordinal: c.GetOrdinal(), Nullable: c.GetNullable(),
		})
	}
	for _, c := range columns {
		if c.Schema != request.GetSchema() {
			return Rejected{codes.InvalidArgument, "fragment column schema mismatch"}
		}
	}

	r.stateLock.Lock()
	defer r.stateLock.Unlock()
	key := r.poolKey(ds, request.GetSchema(), pushedHash)
	fragment := SchemaFragment{Key: key, Hash: pushedHash, Columns: columns}
	// 🔒 INV-A5-33 — a content hash may never alias different columns. Two rejections (this pre-check
	// and the atomic one inside retain) close the same hole from the single-threaded and the racing
	// directions. If a hash could alias, a proxy that controls the hash input could make the control
	// plane decide against a fragment it never measured.
	if existing, ok := r.pool[key]; ok && !slices.Equal(existing.Fragment.Columns, fragment.Columns) {
		return Rejected{codes.FailedPrecondition, "content hash aliases different fragment columns"}
	}

	previousHeld, hadHeld := connection.Held[request.GetSchema()]
	ak := authKey{ds.Name, request.GetSchema()}
	previousAuth, hadAuth := r.authoritative[ak]
	retains := 0
	if !hadHeld || previousHeld.PooledRef != key {
		retains++
	}
	if !hadAuth || previousAuth.PooledRef != key {
		retains++
	}
	// retain also performs the alias check atomically with insertion when another writer created the
	// key; it does NOT bump the count on that path, so nothing leaks.
	retained := r.retain(fragment, retains)
	if !slices.Equal(retained.Fragment.Columns, fragment.Columns) {
		return Rejected{codes.FailedPrecondition, "content hash aliases different fragment columns"}
	}

	now := r.clockNanos()
	// Note RevalidatedAgainstAuthoritativeHash is RESET to nil by a full push.
	connection.Held[request.GetSchema()] = HeldSchema{
		PooledRef: key, Hash: pushedHash, LastFetchNanos: now, LastVerifiedNanos: now,
		RevalidatedAgainstAuthoritativeHash: nil,
	}
	// ⚠️ INV-A5-34 — `authoritative` is ACCEPT-ordered (last accepted push wins, via a monotonic
	// epoch), NOT content-monotonic: an accepted push from a lagging read-replica may legitimately
	// set an OLDER content hash. This is a liveness hint, never a correctness input — every
	// connection decides against exactly what ITS OWN backend binds (freshnessGate re-verifies per
	// connection). A port will be tempted to "fix" this; do not. Damping the resulting bounded
	// before_decide churn is a deferred liveness optimization.
	r.authoritative[ak] = Authoritative{
		Hash: pushedHash, PooledRef: key, Epoch: r.authoritativeEpoch.Add(1), MeasuredNanos: now,
	}
	if hadHeld && previousHeld.PooledRef != key {
		r.release(previousHeld.PooledRef)
	}
	if hadAuth && previousAuth.PooledRef != key {
		r.release(previousAuth.PooledRef)
	}
	return r.accept(connection, request.GetSchema(), backendGeneration)
}

// accept clears the pending CAS token and advances both generations. `maxOf(current ?: pushed,
// pushed)` means an EQUAL generation is accepted — the same backend instance.
func (r *ConnectionCatalogRegistry) accept(connection *EnforcementConnection, schema string, backendGeneration int64) Applied {
	delete(connection.Pending, schema)
	bound := backendGeneration
	if connection.BackendGeneration != nil && *connection.BackendGeneration > bound {
		bound = *connection.BackendGeneration
	}
	connection.BackendGeneration = &bound
	connection.Generation++
	return Applied{Generation: connection.Generation}
}

// poolKey scopes pooled content.
//
// 🔒 INV-A5-35 — only a FIXED system schema pools across datasources, and only with a known engine
// version. A missing/blank engineVersion falls back to the per-datasource scope, so an unversioned
// datasource can never share content with anything.
//
// ⚠️ The scope string uses the RAW engineVersion, not the parsed series — "8.0.44" and "8.0.44-log"
// do not share. Deliberate conservatism or oversight is §10 Q3; reproduced either way.
func (r *ConnectionCatalogRegistry) poolKey(ds Datasource, schema string, hash ContentHash) PoolKey {
	system := MustIsFixedSystemSchema(ds.Engine, schema)
	version := ""
	if ds.EngineVersion != nil {
		version = *ds.EngineVersion
	}
	scope := "ds:" + ds.Name
	if system && strings.TrimSpace(version) != "" {
		scope = "engine:" + version
	}
	return PoolKey{Scope: scope, Schema: schema, Hash: hash}
}

// retain adds count references, inserting the fragment when absent. The alias arm returns the
// CURRENT entry unchanged (no bump), which is what makes the caller's post-check safe.
//
// The count == 0 case can only occur when both previous refs already point at key, which implies the
// entry exists, so a zero-refcount entry is unreachable BY CONSTRUCTION. A port that reorders the
// caller's steps can create one.
//
// Must be called under stateLock.
func (r *ConnectionCatalogRegistry) retain(fragment SchemaFragment, count int) PooledFragment {
	current, ok := r.pool[fragment.Key]
	var next PooledFragment
	switch {
	case !ok:
		next = PooledFragment{Fragment: fragment, RefCount: count}
	case !slices.Equal(current.Fragment.Columns, fragment.Columns):
		next = current
	default:
		next = PooledFragment{Fragment: current.Fragment, RefCount: current.RefCount + count}
	}
	r.pool[fragment.Key] = next
	return next
}

// release drops one reference, removing the entry at zero.
//
// 🔒 INV-A5-36 — underflow is a HARD FAILURE, not a clamp. It is a "this cannot happen" assertion
// protecting a refcount that decides whether structure exists at all; clamping to zero would hide a
// double-release and eventually serve an EMPTY catalog. Kotlin's `check` throws; the Go shape the
// spec names is panic.
//
// Must be called under stateLock.
func (r *ConnectionCatalogRegistry) release(key PoolKey) {
	current, ok := r.pool[key]
	if !ok {
		return
	}
	if current.RefCount <= 0 {
		panic(fmt.Sprintf("catalog fragment refcount underflow for %+v", key))
	}
	remaining := current.RefCount - 1
	if remaining == 0 {
		delete(r.pool, key)
		return
	}
	r.pool[key] = PooledFragment{Fragment: current.Fragment, RefCount: remaining}
}

// FreshnessGate returns the schemas that still REQUIRE a refetch. It MUST be called holding the
// connection mutex.
//
// 🔒 INV-A5-37 — the gate is a disjunction of FOUR independent fail-closed conditions:
//  1. a command is outstanding (pending);
//  2. nothing held;
//  3. a sibling observed different content and this connection has not yet said "mine is unchanged
//     against THAT authoritative version";
//  4. the staleness ceiling elapsed since last verification.
//
// ⚠️ DEVIATION: Kotlin returns a LinkedHashSet — an INSERTION-ORDERED set. Go has no ordered set, so
// this returns a deduplicated, order-preserving slice, which is exactly what the two consumers see
// (emptiness, and the order the resulting Refetch commands are emitted in).
func (r *ConnectionCatalogRegistry) FreshnessGate(connection *EnforcementConnection, requiredSchemas []string) []string {
	now := r.clockNanos()
	r.stateLock.Lock()
	defer r.stateLock.Unlock()

	out := []string{}
	seen := map[string]struct{}{}
	for _, schema := range requiredSchemas {
		if strings.TrimSpace(schema) == "" || strings.HasPrefix(strings.ToLower(schema), "pg_temp") {
			continue
		}
		if _, dup := seen[schema]; dup {
			continue
		}
		seen[schema] = struct{}{}

		held, hasHeld := connection.Held[schema]
		auth, hasAuth := r.authoritative[authKey{connection.Binding.DatasourceName, schema}]
		_, isPending := connection.Pending[schema]
		switch {
		case isPending:
			out = append(out, schema)
		case !hasHeld:
			out = append(out, schema)
		case hasAuth && held.Hash != auth.Hash && !hashEq(held.RevalidatedAgainstAuthoritativeHash, &auth.Hash):
			out = append(out, schema)
		case now-held.LastVerifiedNanos > r.stalenessNanos:
			out = append(out, schema)
		}
	}
	return out
}

// MarkBeforeDecide prefers the connection's OWN held hash as the conditional, falling back to the
// authoritative one.
func (r *ConnectionCatalogRegistry) MarkBeforeDecide(connection *EnforcementConnection, schemas []string) []*pb.Refetch {
	return r.markPending(connection, schemas, func(schema string) PendingRefetch {
		auth := r.authoritativeHashLocked(connection.Binding.DatasourceName, schema)
		expected := auth
		if held, ok := connection.Held[schema]; ok {
			h := held.Hash
			expected = &h
		}
		return PendingRefetch{ExpectedHash: expected, AuthoritativeAtIssue: auth}
	})
}

// MarkCatalogMiss forces one bounded UNCONDITIONAL fetch: a catalog-miss qualifier was never held.
//
// 🔒 INV-A5-38 — a catalog miss forces an unconditional fetch. A conditional one would let the proxy
// answer `unchanged` against a hash for content that does not contain the missing qualifier, and the
// query would stay denied forever. This is the consumer of A6 INV-A6-14 (the deny that carries
// schemaCandidates).
func (r *ConnectionCatalogRegistry) MarkCatalogMiss(connection *EnforcementConnection, schemas []string) []*pb.Refetch {
	return r.markPending(connection, schemas, func(schema string) PendingRefetch {
		return PendingRefetch{
			ExpectedHash:         nil,
			AuthoritativeAtIssue: r.authoritativeHashLocked(connection.Binding.DatasourceName, schema),
		}
	})
}

// MarkAfterStatement issues the post-relay refetch for a catalog-changing statement.
func (r *ConnectionCatalogRegistry) MarkAfterStatement(connection *EnforcementConnection, schemas []string) []*pb.Refetch {
	return r.markPending(connection, schemas, func(schema string) PendingRefetch {
		var expected *ContentHash
		if held, ok := connection.Held[schema]; ok {
			h := held.Hash
			expected = &h
		}
		return PendingRefetch{
			ExpectedHash:         expected,
			AuthoritativeAtIssue: r.authoritativeHashLocked(connection.Binding.DatasourceName, schema),
		}
	})
}

// authoritativeHashLocked must be called under stateLock (every `create` callback runs there).
func (r *ConnectionCatalogRegistry) authoritativeHashLocked(datasourceName, schema string) *ContentHash {
	auth, ok := r.authoritative[authKey{datasourceName, schema}]
	if !ok {
		return nil
	}
	h := auth.Hash
	return &h
}

// markPending issues or replays pending before-decide commands.
//
// 🔒 INV-A5-39 — getOrPut, NEVER overwrite: "without changing an existing command's CAS token".
// Re-issuing with a fresh expectedHash would let a push computed against the old expectation satisfy
// the new command, so a replayed command is byte-identical to the original.
func (r *ConnectionCatalogRegistry) markPending(
	connection *EnforcementConnection, schemas []string, create func(string) PendingRefetch,
) []*pb.Refetch {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()

	out := []*pb.Refetch{}
	seen := map[string]struct{}{}
	for _, schema := range schemas {
		if strings.TrimSpace(schema) == "" || strings.HasPrefix(strings.ToLower(schema), "pg_temp") {
			continue
		}
		if _, dup := seen[schema]; dup {
			continue
		}
		seen[schema] = struct{}{}

		pending, ok := connection.Pending[schema]
		if !ok {
			pending = create(schema)
			connection.Pending[schema] = pending
		}
		out = append(out, refetchOf(schema, pending.ExpectedHash))
	}
	return out
}

// StructuralRows is the connection's whole held structure, sorted.
//
// INV-A5-40 — sorted by (schema, table, ordinal), and the reason is MASKING: the analyzer catalog and
// the client `SELECT *` expansion must follow DB column order regardless of the proxy's push order.
// It matches DatasourceStore.Catalog's ORDER BY ordinal guarantee as CP-side defense-in-depth.
//
// Note the "absent pooled fragment contributes nothing" arm: combined with INV-A5-31, that is why an
// empty held reference must never be created.
func (r *ConnectionCatalogRegistry) StructuralRows(connection *EnforcementConnection) []FragmentColumn {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()

	out := []FragmentColumn{}
	for _, held := range connection.Held {
		if pooled, ok := r.pool[held.PooledRef]; ok {
			out = append(out, pooled.Fragment.Columns...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Schema != out[j].Schema {
			return out[i].Schema < out[j].Schema
		}
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		return out[i].Ordinal < out[j].Ordinal
	})
	return out
}

// HeldAndFreshSchemas is the held schemas the gate does not demand back.
//
// ⚠️ REPRODUCED INEFFICIENCY: one FreshnessGate call per held schema (O(n) gate calls, each
// re-reading the clock and re-taking stateLock). Functionally the per-schema evaluation is
// independent so it is correct; the PORT POLICY makes inefficiency REPRODUCE, never OMIT.
func (r *ConnectionCatalogRegistry) HeldAndFreshSchemas(connection *EnforcementConnection) []string {
	out := []string{}
	for schema := range connection.Held {
		if len(r.FreshnessGate(connection, []string{schema})) == 0 {
			out = append(out, schema)
		}
	}
	return out
}

// RecordAmbientMeasurement folds a whole-catalog measurement from the proxy's ambient refresh into
// this datasource's authoritative entries. Returns the schemas confirmed, for logging.
//
// 🔒 INV-A5-41 — it can only CONFIRM content, never install it: a schema whose columns differ is left
// untouched. Divergence stays the job of the connection's own probe, which alone knows what that
// connection's backend binds.
//
// 🔒 INV-A5-42 — the time is recorded on the AUTHORITATIVE entry, not the pooled fragment. Identical
// system-schema content is pooled once per engine version and shared by every datasource on it, so
// writing the time there would let one datasource's refresh vouch for another's schema nobody read.
//
// ⚠️ INV-A5-43 — columns are compared as SETS, not lists: the whole-catalog read and the per-schema
// fragment read are separate statements whose ORDER BY need not agree, and "comparing lists would
// silently stop confirming anything the moment the two orderings diverged, and nothing would report
// it." A DUPLICATE row is therefore invisible to the comparison — that is inherited, not fixed.
//
// INV-A5-44 — the whole staleness budget depends on this being called. TODO(A10): A10's pushCatalog
// handler is the caller.
func (r *ConnectionCatalogRegistry) RecordAmbientMeasurement(
	datasourceName string, columnsBySchema map[string][]FragmentColumn,
) []string {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()

	confirmed := []string{}
	now := r.clockNanos()
	for schema, columns := range columnsBySchema {
		ak := authKey{datasourceName, schema}
		auth, ok := r.authoritative[ak]
		if !ok {
			continue
		}
		pooled, ok := r.pool[auth.PooledRef]
		if !ok {
			continue
		}
		if !sameColumnSet(pooled.Fragment.Columns, columns) {
			continue
		}
		auth.MeasuredNanos = now
		r.authoritative[ak] = auth
		confirmed = append(confirmed, schema)
	}
	return confirmed
}

// sameColumnSet is Kotlin's `a.toSet() != b.toSet()` — SET semantics, so duplicates collapse.
func sameColumnSet(a, b []FragmentColumn) bool {
	setOf := func(cols []FragmentColumn) map[FragmentColumn]struct{} {
		out := make(map[FragmentColumn]struct{}, len(cols))
		for _, c := range cols {
			out[c] = struct{}{}
		}
		return out
	}
	sa, sb := setOf(a), setOf(b)
	if len(sa) != len(sb) {
		return false
	}
	for c := range sa {
		if _, ok := sb[c]; !ok {
			return false
		}
	}
	return true
}

// MeasuredNanosFor is when this datasource's schema was last read and found to hold the content held
// for it. TODO(A10): GrpcRegistrationHandlerDbTest is its only consumer.
func (r *ConnectionCatalogRegistry) MeasuredNanosFor(datasourceName, schema string) (int64, bool) {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()
	auth, ok := r.authoritative[authKey{datasourceName, schema}]
	if !ok {
		return 0, false
	}
	return auth.MeasuredNanos, true
}

// InvalidateDatasource drops every authoritative entry for datasourceName, for when the datasource is
// repointed at a different database. Returns the schemas invalidated, for logging.
//
// 🔒 INV-A5-45 — a retarget must drop authoritative entries, and must NOT touch live connections.
// "The persisted catalog is already cleared on a retarget, because keeping it would authorize the new
// target against the old schema. This state is the same hazard: a connection opening afterwards would
// otherwise adopt structure measured from the database that is no longer there, and decide against a
// catalog its backend never had. … LIVE CONNECTIONS ARE LEFT ALONE — each already holds its own
// reference and re-verifies on its own clock, and tearing their content out mid-session would empty
// structuralRows under an in-flight statement."
//
// 🔴 F21 — REPRODUCED GAP, DO NOT FIX HERE. The only production caller is the gRPC Register path, and
// it is DOUBLY guarded: `priorDbName != null && priorDbName != ds.dbName`
// (ControlPlaneGrpcService.kt:363). DatasourceStore.Update (rename or db_name change) and
// DatasourceStore.Delete clear the PERSISTED catalog and never call this. Because `authoritative` is
// keyed by datasource NAME, freeing a name leaves its authoritative entries and pooled refs live; the
// replacement target's Register then sees priorDbName == null and SKIPS invalidation entirely,
// inheriting them — and on MySQL (catalogIsConnectionIndependent = true) the next connection ADOPTS
// them with no fetch. Nothing sweeps orphaned entries either, so they are also an unbounded leak.
// Wiring this into Update/Delete here would HIDE a possible live defect; §10 Q1 is the open question
// and it is a product decision, not a port decision.
func (r *ConnectionCatalogRegistry) InvalidateDatasource(datasourceName string) []string {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()

	dropped := []string{}
	keys := []authKey{}
	for k := range r.authoritative {
		if k.Datasource == datasourceName {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		auth, ok := r.authoritative[k]
		if !ok {
			continue
		}
		delete(r.authoritative, k)
		r.release(auth.PooledRef)
		dropped = append(dropped, k.Schema)
	}
	return dropped
}

// Close tears a connection down.
//
// 🔒 INV-A5-46 — remove-before-teardown: "Remove first so no new operation can enter after close
// wins; callers that already captured this record re-check map identity after acquiring the same
// mutex and fail closed" (INV-A5-29's other half). Close is idempotently fail-closed — the second
// call returns NOT_FOUND — and the datasource's authoritative entry SURVIVES.
func (r *ConnectionCatalogRegistry) Close(connectionID ConnectionID, datasourceName string) CatalogMutationResult {
	connection := r.lookup(connectionID)
	if connection == nil {
		return Rejected{codes.NotFound, "unknown connection_id"}
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.Binding.DatasourceName != datasourceName {
		return Rejected{codes.FailedPrecondition, "datasource binding mismatch"}
	}
	if !r.removeIfSame(connectionID, connection) {
		return Rejected{codes.NotFound, "unknown connection_id"}
	}
	r.teardown(connection)
	return Applied{Generation: connection.Generation}
}

// teardown releases every held pooled ref and clears the connection's maps, under stateLock.
func (r *ConnectionCatalogRegistry) teardown(connection *EnforcementConnection) {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()
	for _, held := range connection.Held {
		r.release(held.PooledRef)
	}
	clear(connection.Held)
	clear(connection.Pending)
}

// SweepIdle removes connections untouched for longer than maxIdleMillis, releasing their references.
// TODO(A1): App.kt:424 wires it at 60 * 60 * 1000 (1 hour) inside the periodic purge loop.
//
// INV-A5-47 — the double-check is REQUIRED. The lock-free pre-check is an optimization only; the
// authoritative decision is re-made under the connection mutex, because WithConnection bumps
// lastUsedNanos while the sweeper is between the two reads. That is why lastUsedNanos is atomic.
//
// ⚠️ DEVIATION: Kotlin iterates the ConcurrentHashMap's weakly-consistent value view. Go snapshots
// the connection slice under connMu and releases it before taking any connection mutex, so connMu
// stays a leaf lock and cannot invert against stateLock.
func (r *ConnectionCatalogRegistry) SweepIdle(maxIdleMillis int64) int {
	cutoff := r.clockNanos() - maxIdleMillis*1_000_000
	r.connMu.Lock()
	snapshot := make([]*EnforcementConnection, 0, len(r.connections))
	for _, c := range r.connections {
		snapshot = append(snapshot, c)
	}
	r.connMu.Unlock()

	swept := 0
	for _, connection := range snapshot {
		if connection.lastUsedNanos.Load() >= cutoff {
			continue
		}
		func() {
			connection.mu.Lock()
			defer connection.mu.Unlock()
			if connection.lastUsedNanos.Load() < cutoff && r.removeIfSame(connection.ConnectionID, connection) {
				r.teardown(connection)
				swept++
			}
		}()
	}
	return swept
}

// ---- Test-observability accessors (Kotlin's `internal fun`s) --------------------------------
//
// §5: "A Go port needs equivalents or 17 of its 69 test cases cannot be ported." PoolSize and
// ConnectionCount have no non-test callers in the Kotlin either; they are REPRODUCE-as-test-helper,
// not OMIT.

// AuthoritativeFor returns the authoritative entry for (datasource, schema).
func (r *ConnectionCatalogRegistry) AuthoritativeFor(datasourceName, schema string) (Authoritative, bool) {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()
	auth, ok := r.authoritative[authKey{datasourceName, schema}]
	return auth, ok
}

// PooledFor returns the pooled fragment under key.
func (r *ConnectionCatalogRegistry) PooledFor(key PoolKey) (PooledFragment, bool) {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()
	p, ok := r.pool[key]
	return p, ok
}

// PoolSize is the number of distinct pooled fragments.
func (r *ConnectionCatalogRegistry) PoolSize() int {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()
	return len(r.pool)
}

// ConnectionCount is the number of live connections.
func (r *ConnectionCatalogRegistry) ConnectionCount() int {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	return len(r.connections)
}
