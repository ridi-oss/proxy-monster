# Catalog manager — one owner for the catalog

The catalog manager is the single control-plane owner of all catalog state: the
persisted `catalog_column` table, the in-memory content-addressed fragment pool,
and the per-connection held/pending maps. Every catalog observation — the
registration scan, the ambient refresh, and every per-connection refetch —
enters through one contract, and the manager alone decides what each
observation may update.

This supersedes the two-catalog split in
[per-connection-catalog.md](./per-connection-catalog.md). The machinery that
doc specifies — content-addressed per-schema fragments, the `REFETCH`
primitive and its three positions (`on_open`, `before_decide`,
`after_statement`), the DB-side hash requirements, the verdict/`before_decide`
`oneof`, the trust model — carries over unchanged and is not restated here.
What changes is who owns the state and how observations are versioned and
shared.

## Decision (TL;DR)

One manager, one input. Every catalog read of a backend becomes an
*observation*: `(datasource, backend id, schema, hash, db clock, columns?,
clean|dirty, connection?)`. The hash, the DB-side clock reading, and the
backend id are measured in the same SQL statement on the same connection, so
an observation timestamps itself in the backend's own clock domain. The
manager orders observations of the same backend by that clock — never by
control-plane arrival time — and a newer clean observation updates the shared
state: the fragment pool, the per-schema authoritative pointer, and the
`catalog_column` rows for that schema. A dirty observation (measured inside an
open transaction) updates only the observing connection's held fragment.

Because the registration and ambient scans now carry per-schema hashes, their
content lands in the same pool a connection adopts from. A new connection
adopts that content outright under trust (the MySQL default) or after one
hash query per schema against its own backend under verify (the PostgreSQL
default) — either way with no column fetch, including the first connection
after boot, which today re-reads ~6,800 columns the control plane received
seconds earlier.

## The split today

There are two catalogs and nothing reconciles them:

- `goproxy/boot/boot.go` registers and then re-pushes a whole-server
  `information_schema` scan every 12 minutes (`ambientRefreshInterval`).
  `pushCatalog` in
  `control-plane/.../grpc/ControlPlaneGrpcService.kt` writes it to
  `catalog_column` via `storePushedCatalog`. This copy feeds browse,
  classification joins, table detail, and approval dry-runs.
- Every enforcement connection separately measures the schemas it needs
  (`defaultSchemas + systemSchemas`) into the in-memory pool in
  `ConnectionCatalog.kt`, via `REFETCH` commands and `PushSchemaFragment`.
  This copy — and only this copy — is what `ConnectionDecide.kt` builds a live
  decision's structure from (`structuralRows`).

The two never seed each other, for a mechanical reason: `CatalogRequest`
carries no content hashes, and the pool is content-addressed by the DB-side
hash. `recordAmbientMeasurement` can therefore only *confirm* content the pool
already holds (by comparing column sets) — it can never *install* content. So
a connection opening against a MySQL datasource fetches five schemas,
~6,800 columns, that the same proxy pushed from the same server moments
before. Connections 2..N now adopt held content
(`ConnectionCatalogRegistry.open` with `adoptHeldContent`), but connection #1
still pays the full fetch, and on PostgreSQL every connection does.

The redundancy is the symptom. The root problem is ownership: two writers
(`storePushedCatalog` and `applyPush`) maintain two stores under two freshness
regimes, and the ordering authority for "which catalog is newer" is
control-plane arrival time (`Authoritative.epoch`, `measuredNanos` from
`System.nanoTime()`), which says when the control plane *learned* something,
not when the backend *was* it.

## The model

### One observation contract

The manager's single entry point:

```kotlin
data class CatalogObservation(
    val datasourceName: String,
    val backendId: String,          // "" = unavailable
    val schema: String,
    val hash: ContentHash?,         // null = untrusted measurement (connection-only, never installed)
    val dbClockMicros: Long,        // 0 = unavailable
    val columns: List<FragmentColumn>?,  // null = unchanged claim against a known hash
    val dirty: Boolean,             // measured inside an open transaction
    val connectionId: ByteString?,  // null = datasource-scoped (registration / ambient)
)
```

Producers:

- Registration scan — one observation per schema found, clean,
  `connectionId = null`. Runs before the datasource is considered attached.
- Ambient refresh — same shape, driven by a per-schema clock: a schema is
  due for re-measure 12 minutes after the last clean observation of it
  reached the manager, from any producer.
- Connection refetch (`on_open`, `before_decide`, `after_statement`) — one
  observation per `REFETCH`, `connectionId` set, dirty iff the held backend
  connection reported an open transaction at measurement time.

`hash`, `dbClockMicros`, and `backendId` come from one SQL statement (see
[SQL changes](#sql-changes)); `columns` comes from the companion column scan
on the same connection when the hash misses. The existing measure-fetch-measure
coherence check in `goproxy/engine/refetch.go` stays; it additionally requires
the two measurements' `backendId` to match, and the observation carries the
first measurement's clock (the conservative choice — claiming less recency can
only cause an extra refetch, never a wrong reuse).

Hash trust is explicit on the wire, and the rule is normative: an untrusted
observation is connection-only — never installed into the shared pool, never
authoritative, never adoptable. Today `Refetcher` sends a random 32-byte
nonce in `content_hash` when the coherence check fails, indistinguishable
from a real SHA-256. That is harmless while pushed content stays
connection-scoped, and fail-open here, where pushed content is installed and
adopted: a nonce taken for a trusted hash would let another connection adopt
columns the producer itself just proved stale (its two measurements
disagreed, meaning the fetched columns no longer match the backend).
`Refetcher` therefore stops sending a random value in a field the contract
treats as a content hash and marks the push untrusted instead — a
producer-side change the migration carries.

### Clean and dirty

An observation is dirty iff it was measured inside an open transaction on the
held backend connection. The proxy stamps the raw fact and the manager
assigns the meaning, keeping the proxy free of interpretation.

The wire fact exists today only on the PostgreSQL path: `goproxy/pgproxy`
tracks the `ReadyForQuery` transaction-status byte end-to-end
(`lastTxStatus`), so a PostgreSQL measurement stamps it directly. The MySQL
proxy tracks no `SERVER_STATUS_IN_TRANS` latch — and it does not need one:
the only refetch that could run inside a transaction is `after_statement`,
which fires only on a catalog-changing statement (`ConnectionDecide.kt`),
i.e. after DDL, and MySQL DDL implicitly commits. A MySQL measurement on
that path is out-of-transaction by construction, so
`measured_in_transaction` is always false there — a derived truth, not a
measured one. If a future MySQL path ever measures inside an explicit
transaction, it needs `SERVER_STATUS_IN_TRANS` plumbing first; this design
adds none.

Why transaction status and not "mid-connection": what makes an observation
unshareable is that its view is transactionally private — it may include the
connection's own uncommitted DDL, or (under snapshot isolation) miss committed
DDL from elsewhere. An idle autocommit MySQL session between statements reads
committed state exactly like the ambient scan does; there is nothing
connection-specific about *when* it read. Keying dirtiness on transaction
status means a MySQL `after_statement` refetch is always clean — so the
shared state and the `catalog_column` rows true up within one statement of a
DDL, instead of waiting up to 12 minutes for the ambient clock.

What each may do (an untrusted observation — no genuine hash — follows the
dirty column regardless of transaction status, and additionally cannot be
`unchanged`-matched, since there is no hash to match):

| | Clean | Dirty / untrusted |
| --- | --- | --- |
| Update the observing connection's held fragment | yes | yes |
| Update the authoritative `(datasource, schema)` pointer | yes, if newer | never |
| Update `catalog_column` rows for the schema | yes, if newer | never |
| Content enters the fragment pool | yes | dirty: yes (content-addressing is by hash; pooling is harmless); untrusted: no — held for the connection only, never content-addressed |
| Be adopted by another connection | yes | never (nothing points at it) |

A dirty observation never promotes. Its *content* may later be pointed at by a
clean observation that measures the same hash — the pool entry is already
there and the pointer moves to it — but the dirty observation itself confers
no shared authority. On PostgreSQL, where DDL can sit uncommitted, the
`COMMIT` of a transaction that produced a dirty held fragment gets an
`after_statement REFETCH` of the dirtied schemas; that measurement runs
outside the transaction, is clean, and trues up the shared state immediately
instead of leaving it to the ambient clock.

### The version: a DB-side clock

The ordering key for observations of one backend is the backend's own clock,
read in the same statement that computes the hash: MySQL `NOW(6)`
(statement-start, microseconds), PostgreSQL `clock_timestamp()` (wall clock at
evaluation time, microseconds). Not the control-plane wall clock, not
`System.nanoTime()` — those order *arrival*, and arrival order inverts under
exactly the conditions that matter (a slow push of an old read landing after
a fast push of a new read).

The PostgreSQL choice is deliberate and the obvious-looking alternative is
wrong: `statement_timestamp()` does not advance within a transaction — inside
`BEGIN` it equals `transaction_timestamp()`, the transaction's start time
(measured on PostgreSQL 17: two statements 150 ms apart returned the
identical value). A dirty observation is by definition measured in an open
transaction, so under `statement_timestamp()` every measurement in that
transaction would carry the same version and the ordering key would freeze
exactly where ordering matters — while passing any autocommit test, where it
advances normally. `clock_timestamp()` is the real wall clock read at
evaluation time, which is what "captured with the hash" requires. MySQL's
`NOW(6)` advances per statement even inside a transaction, so it is correct
as specified (`SYSDATE(6)` is the stricter per-evaluation form if the hash
query ever grows to read the clock more than once).

The unit is microseconds (`dbClockMicros`). Neither engine exposes a
sub-microsecond SQL clock, so a nanosecond field would be false precision.

A DB clock is a wall clock, not a monotonic one, and it is only meaningful
within one backend. Two rules make it safe:

- Comparability domain. An observation carries the backend's identity —
  MySQL `@@server_uuid`, PostgreSQL `system_identifier` from
  `pg_control_system()` — measured in the same statement. Clock comparison
  happens only between observations with the same non-empty `backendId`.
- Ordering rule, per `(datasource, schema)`, same `backendId`: a clean
  observation replaces the authoritative pointer iff its `dbClockMicros` is
  strictly newer. An *older* observation with a differing hash is dropped
  (logged at warn), never installed — this is the rule's whole point, and it
  is not theoretical: a whole-server scan takes tens of seconds (measured
  53 s on a real deployment), so a scan that read schema state at time 100
  routinely arrives after a connection refetch that read newer state at
  time 101; accept order would let the slow scan's stale content displace
  the newer catalog, and a trust-mode connection would adopt it. Only on an
  exact tie (`t' == t`), where the clock genuinely cannot discriminate, does
  accept order (the existing monotonic epoch) break it, warned. A true
  backwards clock step therefore holds the newer content until the clock
  catches up — the safe direction; the staleness bound and per-connection
  verification still force re-measurement. Same hash merely refreshes the
  entry's control-plane measurement time.

Different or missing `backendId`: no clock comparison. A clean observation
from a different backend replaces the pointer by accept order (today's
behavior, warning logged); an observation with no `backendId` or no clock may
install where nothing is held but never overwrites a clocked entry. In all of
these cases the connection that produced the observation still holds it for
its own decisions — comparability only gates the *shared* pointer.

The clock orders observations across producers; it never orders observations
within one connection. A connection's own pushes apply in push order under
the connection mutex (`applyPush`), so two measurements from the same
connection — including successive dirty measurements in one transaction —
need no clock to sequence them. The clock's only consumer is the shared
authoritative pointer, which only clean observations reach.

The DB clock orders observations; it does not age them. The staleness bound
(`DEFAULT_STALENESS_NANOS`, 15 minutes) keeps measuring "how long since the
control plane last saw this confirmed" and stays on the control-plane clock,
because the control plane cannot read "now" in a backend's clock domain
without a round trip. Version = DB clock; age = control-plane clock.

### Adoption: verify and trust

A per-datasource setting, `catalog_adoption`, with three states:

- unset — the default. The mode is derived from the engine:
  `Engine.catalogIsConnectionIndependent` picks trust for MySQL and verify
  for PostgreSQL. The engine only ever supplies the default; it never
  overrides an explicit setting.
- `verify`. `on_open` issues the usual
  `REFETCH(schema, if_hash_differs = authoritative hash)` per schema. The
  connection measures each hash on its *own* backend; a match becomes an
  `unchanged` push and the connection adopts the pooled content — no column
  fetch. A miss fetches the columns and pushes a clean observation, which
  seeds the pool for the next connection. Cost per open: one hash query per
  schema (~15 ms server-side for a 3,263-column schema) instead of a
  ~400 KB column transfer.
- `trust`. `on_open` adopts held content with no probe at all — the first
  statement decides with zero backend round-trips. This is today's MySQL
  behavior. It is sound when every backend session for the datasource
  reaches one backend with one service account (the
  [KNOWN_LIMITATIONS](../KNOWN_LIMITATIONS.md) single-backend assumption)
  and the catalog scan holds nothing connection-specific. An explicit
  `trust` is accepted on any engine, PostgreSQL included — the operator's
  setting is trusted, never second-guessed by a predicate.

The two mechanisms relate as assumption vs proof:
`catalogIsConnectionIndependent` is a static, engine-level assumption that a
scan is connection-independent, while a verify-mode hash check is a
per-connection *proof* — this connection measured this hash against exactly
the backend state it will bind. That is why PostgreSQL, which never adopts
today, adopts safely under verify: at open the connection has no transaction,
its `pg_temp_*` schemas are excluded from held fragments, and the hash
equality is its own measurement. The predicate's remaining role is picking
the unset-mode default.

What an operator setting `trust` on PostgreSQL takes on is narrower than
"PostgreSQL catalogs are per-session" suggests. The per-session part —
`pg_temp_*` — never enters a held fragment at all: `freshnessGate` and
`markPending` in `ConnectionCatalog.kt` filter `pg_temp*` out, and temp
columns reach decisions through the per-query overlay instead. So a trusted
PostgreSQL connection is not at risk of inheriting another session's temp
schemas. The real residual is the same one MySQL trust carries — adopting
structure measured by an earlier session when backends or credentials can
disagree (a lagging replica, per-session service accounts whose
privilege-filtered `information_schema` views differ) — plus PostgreSQL's
larger population of connection-influenced catalog surfaces making
"one backend, one account" the operator's assertion to keep true.

### What the manager owns

All catalog state, exclusively:

- The fragment pool (`PoolKey(scope, schema, hash)` → `PooledFragment`,
  refcounted) — kept as is.
- The authoritative map, extended:
  `(datasource, schema) → Authoritative(hash, pooledRef, backendId,
  dbClockMicros, epoch, measuredNanos)`. `epoch` remains as the tie-break;
  `measuredNanos` remains the staleness input.
- Per-connection state (`EnforcementConnection`: held, pending, generation,
  binding, mutex) — kept as is, plus a per-held-schema dirty flag.
- The per-schema ambient clocks: when each `(datasource, schema)` last
  received a clean observation, driving the 12-minute re-measure nudges
  (see [the flows](#the-flows)).
- The persisted projection: `catalog_column` rows, updated per schema when a
  clean observation is newer; a new `catalog_schema` table
  `(datasource_id, schema_name, hash, db_clock_micros, backend_id,
  observed_at)` persisting each schema's authoritative version, so a
  control-plane restart rebuilds the pool from `catalog_column` +
  `catalog_schema` instead of forcing every connection to refetch. Restart
  rebuild is safe because verify-mode connections re-prove content against
  their own backend regardless, and trust mode already trusts exactly this
  provenance.
- `datasource.default_schemas`, `mysql_lower_case_table_names`,
  `engine_version`, `catalog_synced_at` — still written only by whole-server
  observations, which are the only ones that probe the namespace.

`DatasourceStore.storePushedCatalog` becomes manager-internal (the per-schema
projection writer); the gRPC handlers (`pushCatalog`, `pushSchemaFragment`)
route through the manager and hold no catalog logic of their own.

## Load-bearing vs incidental

Load-bearing — the design fails without these:

- One entry point for every observation; the manager is the only writer of
  every catalog store.
- The DB-side clock captured in the same statement as the hash as the
  ordering key, scoped to a backend identity captured the same way.
- Clean/dirty gating what an observation may update; dirty content is never
  adopted and never authoritative.
- Hash trust explicit on the wire; an untrusted observation is
  connection-only — never installed, never authoritative, never adoptable.
- Deletion gated on a namespace-complete observation; a scoped hash set
  never implies deletion.
- Registration and ambient scans carrying per-schema hashes, so pushed
  content can seed the pool (this single wire change dissolves the
  split-brain).
- Fail-closed on every absence: no hash → unconditional fetch; no content →
  `before_decide`, empty fragment, deny by unresolvability.

Incidental — reasonable to change without breaking the model:

- The exact field names and the `catalog_schema` table shape.
- The engine-derived defaults for the unset adoption mode (trust for MySQL,
  verify for PostgreSQL) — the model works under either mode; the safety
  argument shifts between assumption and per-connection proof.
- Whether ambient content pushes are hash-gated (fetch only changed schemas)
  or always full — an economy choice.
- The 12-minute and 15-minute constants.
- Batching the per-schema `on_open` verifications into one grouped hash
  statement (an optimization, not a correctness property).

## State and transitions

Shared entry, per `(datasource, schema)`:

```
absent ──trusted clean obs──▶ held(hash H, backendId B, dbClock t, epoch e)
held ──clean obs, same B, t' > t, hash H'──────▶ held(H', B, t', e')   pool ref moves; catalog_column rows replaced
held ──clean obs, same B, t' == t, hash H'─────▶ held(H', B, t', e')   epoch tie-break; warn
held ──clean obs, same B, t' < t, hash H'──────▶ unchanged   stale observation dropped; warn
held ──clean obs, same B, hash H───────────────▶ held(H, B, max(t,t'), e)  measurement time refreshed
held ──clean obs, different/empty B────────────▶ replaced by accept order; warn
held ──dirty or untrusted obs──────────────────▶ unchanged
held ──12 min since last clean obs─────────────▶ due (manager nudges the proxy to re-measure; clean arrival resets)
held ──namespace-complete obs set lacking this schema▶ absent   (schema dropped; rows deleted)
held ──datasource retarget (invalidateDatasource)──▶ absent
```

Connection-held schema (per `EnforcementConnection.held[schema]`):

```
absent ──open/decide references it──▶ pending (REFETCH issued)
pending ──unchanged push (hash matches pooled)──▶ held-clean (adopted; no fetch)
pending ──full push, not in tx─────────────────▶ held-clean (observation also offered to shared state)
pending ──full push, in tx─────────────────────▶ held-dirty (connection-only)
pending ──full push, hash untrusted────────────▶ held-untrusted (connection-only; never installed)
held-clean ──authoritative hash moved──────────▶ re-check on next decide (freshnessGate) ──▶ pending
held-clean ──older than staleness bound────────▶ pending on next decide
held-dirty ──COMMIT (after_statement REFETCH)──▶ held-clean (out-of-tx re-measure)
any ──close / idle sweep───────────────────────▶ released (refcounts decremented)
```

Who writes what:

| Store | Writer | Trigger |
| --- | --- | --- |
| Fragment pool | manager | any trusted observation carrying content (untrusted content is held connection-side only) |
| Authoritative map | manager | newer trusted clean observation |
| `catalog_column`, `catalog_schema` | manager | newer trusted clean observation (per schema); a namespace-complete set defines schema existence |
| `datasource` namespace fields | manager | whole-server observation |
| Connection held/pending | manager | pushes and command issuance, under the connection mutex |

The generation/CAS discipline of `decideConnection` — snapshot the generation
at entry, hold the mutex through analysis and audit, assert it unchanged at
emit — is untouched.

## Wire changes

`SchemaFragmentPush` gains the observation fields:

```protobuf
message SchemaFragmentPush {
  // fields 1..7 unchanged
  int64  db_clock_micros = 8;         // DB clock at hash measurement; 0 = unavailable
  bool   measured_in_transaction = 9; // raw tx status (PostgreSQL; false by construction on MySQL)
  string backend_id = 10;             // MySQL @@server_uuid / PG system_identifier; "" = unavailable
  bool   hash_trusted = 11;           // false = content_hash is not a real measurement;
                                      // the observation is connection-only, never installed
}
```

`hash_trusted` replaces the nonce trick: `content_hash` only ever carries a
genuine DB-side hash, and a failed coherence check is declared, not
disguised.

`CatalogRequest` — the field whose absence causes the split today — gains
per-schema hashes and the same clock/identity, and learns a hash-only form so
an ambient re-measure can skip content the manager already holds:

```protobuf
message SchemaHash {
  string schema = 1;
  bytes  hash = 2;
  bool   trusted = 3;                     // false = this schema's hash failed (truncation, shape);
                                          // present-but-untrusted, distinct from absent
}
message CatalogRequest {
  // fields 1..5 unchanged
  repeated SchemaHash schema_hashes = 6;  // one entry per measured schema
  int64  db_clock_micros = 7;
  string backend_id = 8;
  bool   hashes_only = 9;                 // no columns: ask which schemas need content
  repeated string content_schemas = 10;   // which schemas' columns this push carries
                                          // (distinguishes "included but empty" from "not included")
  bool   namespace_complete = 11;         // true = schema_hashes enumerates EVERY schema on the
                                          // server; only then may absence mean deletion
}
message CatalogResponse {
  int32 columns = 1;
  repeated string fetch_schemas = 2;      // schemas whose hash the manager holds no content for
}
```

Deletion is gated on `namespace_complete`, normatively: a schema the manager
holds that is absent from a `namespace_complete` push's hashes has been
dropped, and its rows and authoritative entry are removed. A scoped hash set
— a due-schema nudge response, any push without the flag — never implies
deletion, ever; it speaks only for the schemas it names. Registration and
whole-server scans set the flag; the due-schema economy form does not. A
schema whose hash failed inside a grouped scan is sent present-but-untrusted
(`trusted = false`), so a measurement failure is never mistaken for the
schema not existing. `Refetch` and the `before_decide`/`after_statement`
command flow are unchanged.

`RefreshCatalog` — today an empty admin-refresh nudge — gains the due set,
so the manager can ask for exactly the schemas whose clocks expired:

```protobuf
message RefreshCatalog {
  repeated string schemas = 1;   // due schemas to re-measure; empty = whole server (admin refresh)
}
```

Both sides tolerate the old shape: a push without hashes behaves exactly as
today (content to `catalog_column`, confirm-only against the pool), so a
mixed-version proxy/control-plane pair degrades to the current behavior rather
than failing.

## SQL changes

`SchemaHashSQL` today returns exactly three columns (hash, aggregate length,
row count). It gains two: the clock and the backend id, computed in the same
statement as the hash so the reading timestamps the measurement itself.

MySQL (`goproxy/db/db.go`, appended to the existing select):

```sql
  CAST(ROUND(UNIX_TIMESTAMP(NOW(6)) * 1000000) AS UNSIGNED),  -- statement-start, micros
  @@server_uuid
```

PostgreSQL:

```sql
  (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000)::pg_catalog.int8,
  (SELECT system_identifier::pg_catalog.text FROM pg_catalog.pg_control_system())
```

`clock_timestamp()`, not `statement_timestamp()`: the latter is frozen at the
transaction's start time for every statement inside a transaction, so a dirty
measurement would not be ordered against a later one from the same
transaction (see [the version](#the-version-a-db-side-clock)).

`SchemaHashFromRows` widens to five columns; a malformed clock or id marks
those fields unavailable without discarding a well-formed hash.

The registration/ambient scan gains a whole-server grouped variant of the same
statement — the per-row digest subquery without a `WHERE`, aggregated
`GROUP BY table_schema` — yielding one `(schema, hash, length, count)` row per
schema plus the clock and id columns, in one statement. The clock column is
read at evaluation time, so per-schema rows may carry readings microseconds
apart; each schema's observation carries its own reading, which is exactly
what a per-schema version wants. The per-row length check
(`64 × COUNT(*)`) applies per group, so
MySQL `GROUP_CONCAT` truncation is still detected per schema, and a schema
whose check fails is pushed present-but-untrusted rather than omitted. For
its content to be installable, the whole-server path must apply the same
measure-fetch-measure discipline as `goproxy/engine/refetch.go` (hash,
columns, hash again, equal); hashes it cannot bracket that way are sent
`trusted = false`. A schema with zero columns produces no group and no
`catalog_column` rows — indistinguishable from absent, which is fail-closed
(nothing resolvable) and matches the current whole-server scan.

If `@@server_uuid` / `pg_control_system()` is not readable under the service
account, `backend_id` is empty and the observation follows the
no-comparability path — degraded liveness for the shared pointer, never a
wrong reuse.

## The flows

- Registration. `registerAndPushCatalog` runs the grouped hash statement and
  the column scan on the pinned introspection connection, pushes one
  `CatalogRequest` with hashes + content, and only then is the datasource
  attached (`Events`). Every schema lands in the pool, so the first
  connection adopts outright (trust) or its verify round hits.
- Ambient refresh (per-schema movable clock). The manager keeps, per
  `(datasource, schema)`, when the last clean observation of that schema
  arrived — from any producer: a scan, an ambient re-measure, a
  connection's refetch, a miss-fill at open. A schema that goes 12 minutes
  without one is due; the manager nudges the attached proxy over `Events`
  with the due schema set, and the proxy runs the grouped hash statement for
  those schemas and pushes `hashes_only` — scoped, so never
  `namespace_complete`: a due-schema push speaks only for the schemas it
  names and can never delete a quiet sibling. A known hash is itself a clean
  observation — it resets that schema's clock and refreshes the entry's
  measurement time (this is what keeps `freshnessGate`'s 15-minute bound
  from firing on quiet schemas, the role `recordAmbientMeasurement` plays
  today, now by hash instead of column-set comparison). An unknown hash
  comes back in `fetch_schemas` and the proxy fetches only those schemas'
  columns. So a schema kept fresh by its own traffic keeps resetting its own
  clock and is never gratuitously re-measured, while a quiet schema settles
  into a steady 12-minute hash-confirm cadence — the reset never redoes work
  just done, and never starves a sibling schema. The proxy's fixed
  `ambientRefreshInterval` ticker goes away; the manager owns the clocks, so
  it drives re-measurement. With no proxy attached, due schemas simply age —
  nothing can measure them — and the staleness bound still forces
  per-connection re-checks for enforcement. On the common no-change nudge
  the backend does one grouped hash scan and the wire carries a few hundred
  bytes, instead of the full multi-hundred-KB catalog — which matters on the
  remote backends where the full scan has been measured at tens of seconds
  (`goproxy/introspect/introspect.go`).
- Connection open. Verify or trust, per the datasource setting
  (engine-derived when unset), through the unchanged `on_open` `REFETCH`
  machinery. A verify miss fetches, pushes clean, and — by the general rule —
  resets that schema's ambient clock.
- `before_decide` / catalog miss / `after_statement`. Unchanged mechanics;
  each resulting push is now an observation, so a clean one (MySQL DDL,
  autocommit measurements) advances the shared state and the explorer sees
  the DDL immediately.
- PostgreSQL `COMMIT` after in-transaction DDL. The connection's held
  fragment is dirty-flagged; `decideConnection` attaches an
  `after_statement REFETCH` of the dirty schemas to the `COMMIT` verdict.
  The re-measure runs outside the transaction and is clean.

There is no explicit "mark all connections stale" step. Moving the
authoritative pointer *is* the marking: `freshnessGate` already compares each
connection's held hash against the authoritative hash on its next decide, per
schema, and `revalidatedAgainstAuthoritativeHash` already stops a connection
whose own backend legitimately disagrees (replica lag) from looping. The
fan-out is lazy, per schema, and self-coalescing — see
[the herd analysis](#cost-and-the-herd).

## Failure matrix

Every row denies or degrades to a fetch; none allows.

| Failure | Behavior | Why closed |
| --- | --- | --- |
| Manager holds nothing for a schema at open | unconditional `REFETCH` (no `if_hash_differs`); fetch failure refuses the connection | first measurement is never skipped |
| Decide references a never-seen schema | `markCatalogMiss` unconditional fetch; empty result → empty fragment | unresolvable names deny |
| Hash query fails / untrusted (truncation, shape, `backendId` flipped between the paired measurements) | degrade to unconditional full fetch; push marked `hash_trusted = false` | an untrusted observation is connection-only — never installed, never authoritative, never adoptable |
| Ambient hash statement fails | the nudge is skipped, logged; the schemas stay due and the next nudge retries | enforcement never depended on the ambient path; the 15-min staleness bound still forces per-connection re-checks, `catalog_column` merely ages |
| Column fetch fails midway | observation not applied; prior state stands; on the connection path the refetch error is terminal (connection refused / session failed) | a partial fragment is never installed |
| `db_clock_micros` absent (0) | may install where nothing held; never overwrites a clocked entry | an unversioned write cannot displace a versioned one |
| Clock regression (`t' < t`), same backend, differing hash | stale observation dropped, warning | the newer content is held until the clock catches up; the staleness bound and per-connection verification force re-measurement |
| Exact clock tie (`t' == t`), same backend, differing hash | epoch tie-break, warning | the clock cannot discriminate; accept order is the only remaining signal |
| `backend_id` differs or empty | no clock comparison; accept-order replace with warning; verify-mode connections unaffected (own-backend proof) | the shared pointer is a liveness hint for verify mode, not a correctness input |
| Control-plane restart | pool rebuilt from `catalog_schema` + `catalog_column`; unknown `connection_id` recovers via `before_decide` as today | verify re-proves rebuilt content per connection; trust already accepts exactly this provenance |
| `trust` on a datasource with disagreeing replicas | unsound, as today (MySQL's unset default is trust) | the single-backend assumption is documented and per-datasource; switching that datasource to `verify` discharges it per connection |

The temp paths are untouched: `pg_temp*` stays excluded from held fragments
and rides the per-query overlay with its existing gates; MySQL temp tables
stay invisible to every scan and reach decisions through the overlay only.

## Cost and the herd

Measured on a 3,263-column schema: the hash query costs 14.6 ms server-side
against 8.6 ms for the plain column scan — the hash's win is transfer
(320 bytes vs 396 KB), not backend work. So the design spends hash queries
where transfer or redundant fetching is saved, and avoids gratuitous ones:

- A clean change to schema `S` causes each open connection to re-check `S` —
  one hash query — on its next statement that needs `S`. The fan-out is
  bounded by sessions actually touching `S`, spread over their own request
  times (no synchronized stampede), once per connection per pointer move
  (`revalidatedAgainstAuthoritativeHash` coalesces). An unchanged-hash clean
  observation moves nothing and triggers nothing.
- Verify-mode open costs one hash query per schema (five on a typical
  five-schema datasource, ~75 ms server-side plus round trips) against
  today's ~400 KB first-connection fetch; a trust-mode open (the MySQL
  default) costs nothing. Batching the five into one grouped statement is a
  noted optimization.
- The ambient path drops from a fixed-tick full catalog scan + full transfer
  to a per-schema-clocked grouped hash scan + usually nothing — and the
  per-schema reset means a schema whose own traffic keeps it fresh is not
  re-measured at all.

Per-connection staleness marking is deliberately *not* introduced beyond what
`freshnessGate` already does per schema; a coarser per-connection mark would
only add re-checks for schemas the connection never touches.

## Where this deviates from the motivating sketch

The sketch this design answers proposed a manager with input
`(hash, catalog, db_nanos, clean|dirty)`, a mark-all-connections-stale step, a
movable 12-minute clock, and an `ALWAYS_FETCH_CATALOG_PER_CONNECTION` switch.
The deviations and refinements, each deliberate:

- Dirty means "measured in an open transaction", not "measured
  mid-connection". Mid-connection autocommit measurements observe committed
  state; classifying them dirty would forfeit the immediate DDL true-up on
  MySQL — the priority engine, where DDL implicitly commits — for no safety
  gain. On PostgreSQL, transaction status is a wire fact the proxy already
  tracks; on MySQL the bit is false by construction (see
  [Clean and dirty](#clean-and-dirty)) — either way, nothing to interpret.
- The input tuple needs three more fields. Per-schema identity (the pool,
  the hashes, and the staleness machinery are all per-schema); the backend
  identity (without it, `db_nanos` ordering silently compares clocks of
  different servers — the exact cross-backend contamination the design must
  not add); and the unchanged/content distinction (the cheap common case).
- No mark-all-connections-stale step. The existing per-schema lazy
  re-check (`freshnessGate` against the authoritative hash) is strictly
  better: finer-grained, self-coalescing, already implemented, and immune to
  the herd a broadcast mark invites.
- The movable 12-minute clock is kept, made per schema. The sketch's
  "12 minutes since the last catalog reached the manager" is adopted with
  the clock scoped to `(datasource, schema)`: a clean arrival for schema `A`
  resets only `A`'s clock, so a datasource with DDL every 10 minutes on `A`
  still re-measures `B..E` on their own schedules — the reset skips work
  just done without starving drift detection on the quiet schemas. A single
  datasource-wide clock would starve them; per schema, the sketch's clock is
  strictly better than a fixed tick.
- Microseconds, not nanoseconds. Neither engine exposes a sub-microsecond
  SQL clock; the field says what it holds.
- The DB clock is the order, with one narrow escape. It is a wall clock;
  after a backwards NTP step, strictly-newer-wins holds the current content
  until the clock catches up — accepted as the safe direction, since the
  staleness bound and per-connection verification force re-measurement
  regardless. Accept order (the epoch) decides only an exact tie, where the
  clock genuinely cannot discriminate. The firm intent — backend observation
  time, never control-plane arrival time, as the version — is kept; an
  arriving observation that is *older* than the held one is dropped, not
  installed, because the slow-scan-overtaken-by-refetch race
  (a 53 s whole-server scan is routinely overtaken) is precisely what the
  version exists to reject.
- `verify`/`trust`/unset per datasource instead of a global
  `ALWAYS_FETCH_CATALOG_PER_CONNECTION`. Backend topology is a
  per-datasource fact, so the switch lives there; unset derives the mode
  from the engine (trust for MySQL, verify for PostgreSQL — today's behavior
  as the default), and an explicit setting always wins over the engine.

## Open questions, resolved

1. Clean vs dirty — defined in [Clean and dirty](#clean-and-dirty). Dirty =
   measured in an open transaction; usable only by its own connection; never
   adopted, never authoritative, never persisted. No promotion — a later clean
   measurement (the `COMMIT` refetch on PostgreSQL, any autocommit
   re-measurement on MySQL) advances the shared state instead.
2. Multi-replica comparability — the backend id measured with the hash
   defines the clock domain; cross-domain observations never clock-compare and
   fall back to accept order (today's epoch), warned. The pointer stays a
   liveness hint; verify-mode connections prove content against their own
   backend, so no new contamination channel exists. Caveat: PostgreSQL
   physical replicas share `system_identifier` (promotion changes the
   timeline, lag does not), so the domain test under-discriminates there;
   bounded by verify-mode self-proof and by MySQL — fully discriminated by
   `@@server_uuid` — being the priority engine.
3. Thundering herd — staleness is already per-schema and lazy
   (`freshnessGate`); the design adds no broadcast. Re-checks are one hash
   query per touching connection per pointer move, self-coalesced by
   `revalidatedAgainstAuthoritativeHash`. See
   [Cost and the herd](#cost-and-the-herd).
4. Granularity — the manager's unit is the per-schema fragment (kept); the
   hash stays per-schema; whole-server scans decompose into per-schema
   observations and — when `namespace_complete` — additionally define the
   schema set. `catalog_column` updates become per-schema instead of
   whole-table delete-and-insert.
5. Fail-closed — the [failure matrix](#failure-matrix). Every absence
   (hash, trust, content, clock, identity) degrades toward fetching or
   denying, never toward reuse.
6. The adoption switch — [Adoption: verify and trust](#adoption-verify-and-trust).
   Tri-state per datasource: unset (the default) derives the mode from
   `catalogIsConnectionIndependent` — trust on MySQL, verify on PostgreSQL —
   and an explicit setting always wins, on any engine. Verify hash-proves
   adoption per connection; trust's safety argument is the single-backend
   assumption, which an explicit setting makes the operator's own assertion.
   The predicate's remaining role is picking the unset default, never
   vetoing a choice.
7. Migration — below.

## Migration

Kept: the fragment pool and refcounting, `PoolKey`, `EnforcementConnection`
with held/pending, `freshnessGate`, the three command positions,
`markBeforeDecide`/`markAfterStatement`/`markCatalogMiss`, `applyPush`'s
validation skeleton, `Refetcher`, the DB-side hash construction, the
verdict/`before_decide` contract, close/sweep/`invalidateDatasource`.

Replaced or removed: `recordAmbientMeasurement` (subsumed by hash-carrying
observations, which install rather than merely confirm);
`storePushedCatalog`'s whole-table delete-and-insert (per-schema projection);
`adoptHeldContent`/`catalogIsConnectionIndependent` as the adoption decision
(demoted to the unset-mode default); the proxy's fixed
`ambientRefreshInterval` ticker (replaced by manager-driven per-schema
nudges); arrival time as the ordering authority (`epoch` demoted to
tie-break).

Landing order, each step shippable alone:

1. Wire + SQL: the five-column `SchemaHashSQL`, the observation fields on
   `SchemaFragmentPush` (including `hash_trusted`), the hash fields on
   `CatalogRequest` (including `namespace_complete` — set by the
   whole-server scans this step ships; only the step-4 economy form sends
   scoped sets), the `schemas` field on `RefreshCatalog`. `Refetcher` stops
   sending the random nonce and marks the push untrusted instead — the
   producer-side half of the trust contract lands with the field. Both sides
   treat absence as today's behavior, so old proxies keep working.
2. The manager: route `pushCatalog` and `pushSchemaFragment` through one
   component; pool installation from trusted config pushes; the ordering and
   trust rules; the `catalog_schema` table and per-schema `catalog_column`
   projection. From this step connection #1 adopts.
3. Adoption modes: the tri-state per-datasource setting with the
   engine-derived unset default (today's behavior unchanged for both
   engines). The KNOWN_LIMITATIONS single-backend entry becomes a
   description of trust mode, with `verify` as the per-datasource remedy.
4. Economy + true-up: the per-schema movable clock with manager-driven
   `RefreshCatalog(schemas)` nudges and `hashes_only`/`fetch_schemas` (the
   scoped, never-`namespace_complete` push form), the dirty flag from
   transaction status, the PostgreSQL `COMMIT` refetch, restart rebuild from
   `catalog_schema`. The control plane ships before the proxy drops its
   fixed ticker, so a datasource is never left with neither a ticker nor a
   nudging manager.

## Known limitations carried

The residuals in
[per-connection-catalog.md](./per-connection-catalog.md#known-limitations)
carry over unchanged — rename laundering of classifications, DML-fired
trigger DDL, the MySQL temp-table scope, PostgreSQL transactional-DDL edges,
the pgcrypto/md5 fallback. New here: PostgreSQL replica identity
under-discrimination (above); the exact-tie epoch window, bounded to today's
accept-order behavior; and, on the experimental PostgreSQL path, the
transaction-status stamp for a probe issued mid extended-protocol batch
inherits that path's existing held-connection-probe residuals.
