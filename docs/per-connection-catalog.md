# Per-connection enforcement catalog

Two catalogs with opposite freshness contracts run on separate gRPC channels:

- The **enforcement catalog** is per-connection, control-plane-commanded, and
  transactionally current. Every wire/editor connection resolves decisions
  against catalog fragments the proxy introspected on that connection's own held
  backend connection, so they reflect uncommitted in-transaction DDL. The
  control plane always decides against exactly what _that_ connection's backend
  will bind.
- The **config catalog** is datasource-global and SWR-refreshed (~12 min), on
  its own channel. It feeds the config/admin surfaces — catalog browsing,
  tagging/classification, table detail, the system-classification manifest, the
  liveness UI, and HTTP approval dry-run previews — and is never the structure
  source for connection-scoped wire/editor/`RunExec` Decide.

The enforcement catalog is built from content-addressed, immutable, per-schema
fragments, kept current by one command primitive —
`REFETCH(schema, if the live DB-side hash differs from H)` — issued at three
positions (`on_open`, `after_statement`, `before_decide`). All hashing is
DB-side; the proxy computes no hash and makes no enforcement or refresh
decision.

Two principles hold throughout:

1. The proxy makes zero enforcement or refresh decisions. It executes
   control-plane-issued imperative commands (run a DB-side hash query; on
   mismatch full-introspect the schema on the held connection and push the
   fragment) and relays wire bytes. It never classifies SQL and never interprets
   a hash beyond byte equality.
2. Enforcement is at least as safe as a datasource-global catalog: it closes the
   staleness windows a global snapshot only bounds, and dissolves the
   in-transaction quarantine a global snapshot needs.

Target-engine priority: MySQL is the priority target engine and the whole model
is built for it; PostgreSQL as a target engine is experimental. (The
control-plane store is PostgreSQL only and plays no part here — see
[`../AGENTS.md`](../AGENTS.md#two-independent-engine-axes).) PG-only
transactional-DDL edge cases are documented as known limitations below, with one
exception that is a plain PG mechanism fix, not an edge case — the
extended-protocol probe — which must be correct for normal PG operation.

Where this fits: [connection-model.md](./connection-model.md) makes enforcement
resolve against a connection's live namespace; this doc keeps that connection's
catalog transactionally current. A datasource-global at-commit refresh leaves
wrong-ALLOW holes — an in-transaction `DROP` then a bare-name `SELECT` (refresh
deferred to COMMIT → stale wrong-ALLOW), `COMMIT AND CHAIN` never reaching idle
(refresh never fires), disconnect-after-DDL (refresh lost) — because a global
snapshot cannot represent one connection's transactional view, and because
deciding _when_ to refresh is itself a decision a stateless-relay proxy must not
make. Scoping the catalog to the connection whose view it is, and moving the
whole freshness decision into the control plane, dissolves all of it.

The implementation lives in `proto/src/main/proto/controlplane.proto`, the
control-plane per-connection catalog + Decide (`ConnectionCatalog.kt` /
`ConnectionDecide.kt`, wired via `ControlPlaneGrpcService.decide`), the Go proxy
held-connection refetch (`goproxy/engine/refetch.go`, `goproxy/cp/client.go`),
the DB-side hash (`goproxy/db/db.go`), and the config-channel split (a second
`grpc.ClientConn` in `goproxy/boot/boot.go`).

## Two catalogs — why separate

<!-- prettier-ignore -->
|  | Enforcement catalog | Config catalog |
| --- | --- | --- |
| Scope | one wire/editor connection (per-schema fragments) | the datasource |
| Freshness | transactionally current for the issuing connection | SWR, ambient ~12 min + admin refresh |
| Kept current by | control-plane `REFETCH` commands, DB-hash-gated | proxy timer + Events `RefreshCatalog` |
| Introspected on | the connection's held backend connection | a dedicated short-lived connection (`introspect.Run`) |
| Channel | enforcement (`ValidateToken`/`Decide`/`PushSchemaFragment`/`CloseConnection`/`RunExec`/`ReportCompletion`) | config (`Register`/`PushCatalog`/`Events`/`TableDetailExec`) |
| Control-plane storage | in-memory content-addressed fragments + per-connection held-hash map | `catalog_column` + `datasource` rows |
| Read by | `decideConnection` → `decideQuery` (wire/editor/`RunExec`) | catalog browser, classification writes/reads, MCP `browse_catalog`, table detail, approval dry-run previews, manifest logging, liveness UI |

Their correctness contracts are opposite: enforcement must never serve a stale
answer (a stale fragment is a wrong-ALLOW), and config must never let a browsing
admin or a multi-MB push sit in front of the `Decide` hot path. Separate
channels (two `grpc.ClientConn`s) also keep a large config push from
head-of-line-blocking in-flight `Decide`s on a shared HTTP/2 connection.

## Content-addressed, immutable, per-schema fragments

The enforcement catalog is a set of per-schema fragments, each immutable and
keyed by a stable content hash of its enforcement-relevant fields:

- A schema's structure changes → a new fragment under a new hash. Fragments are
  never mutated in place; connections hold references to a hash.
- User schemas are keyed by `(datasource, schema, hash)`.
- System schemas (`information_schema`, `pg_catalog`, `mysql`, `sys`,
  `performance_schema`) are immutable per engine build, so they are keyed by
  `(engine_version, schema, hash)` and dedup globally across datasources on the
  same engine version. System schemas are introspected and access-controlled as
  first-class resources, never excluded or shadowed (`columnsSQL`).
- Connections on the same schema version share one fragment — content-addressing
  gives dedup and bounds control-plane memory. A fragment is GC'd when no
  connection references it and it is not the current authoritative version
  (refcount).

So "reuse instead of refetch" falls out for free: two connections that see the
same `s1` share `(datasource, s1, H)`; a connection whose backend already
matches the held hash for a schema skips the fetch (a no-op `REFETCH`). It also
makes the after-DDL refresh a content event, not a timing event.

## The `REFETCH` primitive and its three positions

One generic, extensible command carries the whole mechanism; `REFETCH` is its
only value today.

`REFETCH(schema S, if_hash_differs H)` — the proxy runs a DB-side hash query for
`S` on the held backend connection. If the live hash equals `H` it is a no-op
(the connection already holds the right fragment) and the proxy acks
"unchanged". If it differs (or no trustworthy hash can be produced), the proxy
full-introspects `S` on the held connection and pushes the fragment plus its
live hash. `H` is the hash the control plane currently holds for
`(this connection, S)`; empty/absent `H` means an unconditional fetch
(fail-safe). The hash query is cheap and gates the expensive full introspection,
so over-issuing `REFETCH` is cheap.

All three positions carry this same conditional command:

- `on_open` — returned in the `ValidateToken` admit response: one `REFETCH` per
  schema the connection will use (the datasource's default schemas + the system
  schemas), each with `H` = the currently-held hash. Base reuse is just the
  matching schemas no-op'ing; any other schema the connection later references
  is fetched lazily via `before_decide`. The proxy must complete all `on_open`
  commands (each push acknowledged) before serving the first client statement.
- `after_statement` — attached to a normal verdict when the control plane flags
  the statement as possibly catalog-changing: non-temp DDL, and CALL /
  routine-invoking statements (a stored routine can run DDL). It `REFETCH`es the
  affected schema(s); because the hash gate makes an unchanged schema a no-op,
  the control plane flags conservatively (the connection's active schema set)
  rather than predicting exactly what a routine touched. It runs on the held
  connection, so it sees the statement's uncommitted effects.
- `before_decide` — a `WireDecision` arm that carries no verdict: "run these
  commands, then re-send the same `DecisionRequest`."

## `before_decide` — the four cases

`before_decide` covers exactly the situations where the need to refresh is
discovered at decide time, not caused by this connection's own connect or its
own statement:

1. Cross-connection change (proxy-observed). Another connection changed schema
   `S`; this connection holds `S` at an older hash and ran no catalog-changing
   statement of its own. On its next `Decide` the control plane sees the held
   `S`-hash ≠ the datasource-authoritative `S`-hash →
   `before_decide REFETCH(S, H = held)` → retry. The proxy re-hashes `S` on its
   own backend: if that backend also has the change it pushes the new fragment;
   if it legitimately does not (replica lag), the `REFETCH` is a no-op and the
   control plane records the connection as revalidated so it does not loop. The
   control plane always decides against what _this_ connection's backend binds,
   never a sibling's.
2. Control-plane restart. The control plane lost its in-memory per-connection
   catalogs; the next `Decide` for an unknown `connection_id` → `before_decide`
   (re-push the needed schemas) → retry. A mid-transaction connection
   re-introspects its still-open transaction on the held connection, so the
   transactional view is re-derived correctly.
3. External / out-of-band DDL (staleness-bounded). A change neither this
   connection nor the control plane observed (direct DDL on the target, another
   tool). Time is the only trigger: when a connection's held fragment is older
   than the staleness bound, its next `Decide` re-checks (a no-op under the hash
   gate if nothing moved). This is the only residual class that remains
   time-bounded rather than event-driven.
4. Defense against a non-compliant proxy. A proxy that skipped an
   `after_statement REFETCH` is caught: the control plane set a pending mark on
   that schema when it issued the command, so the next `Decide` touching it
   returns `before_decide`, never a verdict, until the push lands. The control
   plane does not depend on the proxy running `after_statement` proactively. The
   proxy is trusted (see the trust model), so this is a robustness property, not
   a trust boundary — a proxy that lies about a hash or bypasses `Decide`
   defeats enforcement regardless.

## The enforcement lifecycle (per connection)

1. Connect. Client connects (MySQL handshake / PG startup + cleartext password).
2. Admit, mint, command. The proxy calls
   `ValidateToken(token, datasource_name, client_addr)`. The control plane
   decides admit/reject; on admit it mints a 128-bit CSPRNG `connection_id`,
   creates the per-connection state, and returns `connection_id` + `on_open`
   (`REFETCH`s for the default + system schemas).
3. Fetch-on-open (hash-gated). The proxy dials its backend, then runs each
   `on_open REFETCH` on that held connection: hash the schema, push the fragment
   only if it differs. Matching schemas are no-ops (shared fragment reuse). Only
   after every `on_open` push is acknowledged does the proxy serve client
   statements. Any introspection/push failure at open is fail-closed (connection
   refused).
4. Decide, refresh-on-command. Every client statement → `Decide` (carrying
   `connection_id` + the live `search_path`). The response is a `oneof`: a
   verdict (with any `after_statement` commands) or a `before_decide` (run
   commands, re-send). On a verdict the proxy relays, observes the backend's
   mechanical success signal, and runs any `after_statement REFETCH` on the held
   connection before the next statement.
5. Close. On connection close the proxy sends `CloseConnection(connection_id)`;
   a control-plane idle-TTL sweep backstops a proxy that died. The
   per-connection state is dropped and fragment refcounts decremented.

### The correctness property

The hash query and the full introspection both run on the held backend
connection, inside the client's current transaction, so they see uncommitted
DDL. After `BEGIN; DROP TABLE s1.accounts;` the `after_statement REFETCH(s1, …)`
hashes `s1` on the held connection (now differs) → full-introspects `s1` inside
the transaction (sees the drop) → pushes a fragment without `accounts` → the
connection's held `s1`-hash updates. The next decision for
`SELECT … FROM accounts` (search_path `s1, s2`) resolves the bare name to what
the backend will actually bind — `s2.accounts` — and denies it if the principal
lacks access.

This eliminates, for the enforcing session: datasource-global staleness (no
shared snapshot to be stale against), the committed-DDL wrong-ALLOW gate
(refresh is not deferred to a commit boundary), and the whole in-transaction
quarantine (its premise — "no trusted global capture can represent an
uncommitted schema" — is dissolved by capturing per connection). The three holes
go directly: the refresh runs inside the transaction right after the DDL;
`COMMIT AND CHAIN` is just another statement whose completion runs its command,
so there is no idle gate to miss; a disconnect takes the connection's fragments
with it and no sibling's catalog ever depended on that session.

Scope (MySQL temporary tables). The "decides against exactly what the backend
binds" property is scoped to objects visible in `information_schema`. A MySQL
`CREATE TEMPORARY TABLE` is invisible to `information_schema` even within its
own session, so the held-connection hash/introspection cannot see a session temp
that shadows a base-table name — `decideQuery` resolves the bare name to the
base table while the backend binds the temp. This is mostly fail-closed in
practice (a temp `CREATE … AS SELECT` is a write gated by the
write-references-masked deny; a shape-mismatched read tends to error) but the
property does not cover it. PostgreSQL's `pg_temp` is handled by the per-query
temp overlay; MySQL has no overlay (`SupportsTempOverlay() == false`), so this
residual is MySQL-specific (see known limitations).

### Trust model

The proxy is inside the trusted computing base. Correctness depends on it (a)
calling the control plane for every statement, (b) enforcing the verdict
(mask/deny), and (c) honestly executing a forced `REFETCH` (running the hash
query on its backend and reporting the result truthfully). A proxy that bypasses
`Decide`, forwards raw SQL, or fabricates a hash / `unchanged` reply defeats
enforcement — no protocol mechanism here prevents that; removing the proxy from
the TCB would require DB-enforced, control-plane-signed per-statement
capabilities, a different architecture out of scope. What this design avoids is
depending on the proxy's proactive, voluntary freshness bookkeeping:
`before_decide` + the pending mark let the control plane demand freshness at
decide time. That is a liveness/robustness property (self-healing against a
proxy that forgot to refresh), not a defense against a dishonest proxy.

## Wire / proto contract

`proto/src/main/proto/controlplane.proto` carries `Register`, `PushCatalog`,
`ValidateToken`, `Decide`, `Events`, `RunExec`, and `TableDetailExec`, plus:

```protobuf
// Generic, extensible command. REFETCH is today's only value.
message ProxyCommand {
  oneof command {
    Refetch refetch = 1;   // future commands add arms here
  }
}
message Refetch {
  string schema = 1;          // the schema to conditionally re-introspect
  bytes  if_hash_differs = 2; // CP's currently-held content hash for (connection, schema);
                              // empty/absent = unconditional fetch (fail-safe)
}

// ---- Connection open: ValidateToken admits, mints, and commands ----
message ValidateTokenRequest { string token = 1; string datasource_name = 2; string client_addr = 3; }
message WireIdentity {
  string principal = 1;
  repeated string roles = 2;
  bytes connection_id = 3;             // 128-bit control-plane-minted CSPRNG
  repeated ProxyCommand on_open = 4;   // REFETCH per default + system schema
}

// ---- Per-schema fragment push (proxy -> CP, enforcement channel) ----
rpc PushSchemaFragment(SchemaFragmentPush) returns (SchemaFragmentAck);
message SchemaFragmentPush {
  bytes  connection_id      = 1;
  string datasource_name    = 2;
  string schema             = 3;
  bytes  content_hash       = 4;  // the live DB-side hash the proxy just measured for this schema
  bool   unchanged          = 5;  // true = live hash matched H; columns omitted (no-op ack)
  repeated Column columns   = 6;  // enforcement-relevant fields only (schema/table/column/
                                  // data_type/ordinal/nullable) — the same Column message as PushCatalog
  uint64 backend_generation = 7;  // which backend-connection instance measured this
}
message SchemaFragmentAck { uint64 generation = 1; }  // per-connection generation after applying

// ---- Connection close (proxy -> CP; CP idle-sweep is the backstop) ----
rpc CloseConnection(CloseConnectionRequest) returns (CloseConnectionResponse);
message CloseConnectionRequest { bytes connection_id = 1; string datasource_name = 2; }
message CloseConnectionResponse {}

// ---- Decide: connection-scoped, verdict-or-before_decide oneof ----
message DecisionRequest {
  // fields 1-6 unchanged (token, datasource_name, sql, search_path, client_addr, temp_columns)
  bytes connection_id = 7;
}
message WireDecision {
  oneof outcome {
    Verdict      verdict       = 1;
    BeforeDecide before_decide = 2;   // NO verdict — run commands, then re-send the same request
  }
}
message Verdict {
  EnfAction decision = 1;
  string deny_reason = 2;
  repeated ColumnMask masks = 3;
  repeated string effective_roles = 4;
  optional string rewritten_sql = 5;
  int64 decision_id = 6;
  bool unmaskable_permitted = 7;
  repeated ProxyCommand after_statement = 8;   // runs after statement success
  uint64 generation = 9;                       // per-connection generation this verdict was computed under
}
message BeforeDecide { repeated ProxyCommand commands = 1; }

// OpenRunChannel carries on_open so an editor session is just another connection:
message OpenRunChannel {
  string session_id = 1;
  string ephemeral_token = 2;
  bytes  connection_id = 3;            // control-plane-minted for the session
  repeated ProxyCommand on_open = 4;
}
```

The verdict/`before_decide` `oneof` is a security property, not ergonomics: a
`before_decide` response structurally cannot carry an action or masks, so a bug
that failed to check it cannot act on a verdict computed against a stale
catalog. The Go proxy branches on `before_decide` before mapping any verdict; a
message with neither arm set fails closed.

`after_statement` is a per-connection, in-transaction, hash-gated refresh: it
runs after the statement succeeds (not at COMMIT), on the held connection (sees
the transaction), and replaces this connection's fragment (not a global
catalog).

### Security invariants baked into the wire and control plane

- Generations + serialization. Per-connection state transitions (fragment
  applies, pending set/clear) are linearized (single-writer per `connection_id`)
  and stamped with a monotonic `generation`. A push that would not advance state
  — a replayed, delayed, or stale fragment, or one carrying an old
  `backend_generation` — is rejected, so it can never clobber a newer fragment.
  A verdict is stamped with the generation it was computed under and is emitted
  only if that generation is still current (stated normatively so a future
  concurrent implementation cannot regress it).
- Connection-id. 128-bit CSPRNG, minted at admit, bound to
  `(datasource, principal, token_kind)` (`Binding` in `ConnectionCatalog.kt`);
  `backend_generation` is bound on the first successful fragment push and
  advances monotonically. There is no proxy-instance field on the wire. A
  `Decide` whose binding tuple mismatches, or a `PushSchemaFragment`/
  `CloseConnection` whose id is unknown, whose datasource binding mismatches, or
  whose `backend_generation` is stale is rejected — a torn-down or reused id
  cannot be driven by a late or forged message.
- Lockstep is normative. The proxy must not read or authorize the next client
  command until the current command's push is acknowledged by the control plane.
  This holds today (the proxy is synchronous on the `Decide`/push round-trips);
  it is stated as an invariant so a future pipelining/async optimization cannot
  silently let a verdict be issued against an un-acknowledged catalog.

## Control-plane state and `decideConnection`

- State. Per `(datasource, schema)`: the authoritative
  `{ hash, immutable fragment, epoch }` (last accepted push; a liveness hint,
  never a correctness input — each connection re-verifies against its own
  backend), plus a content-addressed fragment pool (dedup + refcount). Per
  `connection_id`:
  `{ held schema→hash map, per-schema pending mark, generation, binding tuple, backend_generation }`.
  All in-memory — session-scoped ephemeral state; persisting it would be
  fail-open on restart (case 2 recovers it instead).
- Applying a push. `PushSchemaFragment` (invariant checks pass) stores the
  fragment under its content key, sets the connection's held `schema→hash`,
  clears that schema's pending mark, sets the authoritative
  `(datasource, schema)` hash to the last accepted push (accept-ordered via a
  monotonic epoch — not content-monotonic; a lagging replica may regress the
  hint), and bumps the connection generation.
- `decideConnection` (`ConnectionDecide.kt`) assembles the analyzer catalog from
  the connection's held fragments plus the per-query temp overlay, then calls
  `decideQuery` for the grant walk. Classifications remain joined
  control-plane-side by `(datasource, schema, table, column)`; only the
  structural rows come from the fragments. System-classification keeps reading
  the datasource's global engine version. If a referenced schema's fragment is
  absent, stale (held ≠ authoritative, or older than the staleness bound), or
  pending, `decideConnection` returns `before_decide` instead of a verdict.
- Command attachment. On a non-DENY verdict for a catalog-changing statement
  (non-temp DDL, or a statement that invokes a function/routine —
  `catalogChanging` from analysis), `decideConnection` attaches
  `after_statement = [REFETCH(schemas)]` and marks those schemas pending. The
  affected-schema set is the connection's active schemas (search_path ∪ explicit
  qualifiers) — conservative, cheap under the hash gate.
- Config catalog. `Register`/`PushCatalog`/`storePushedCatalog`/`Events` stay as
  they are. Connection-scoped Decide builds structure from held fragments only;
  the global catalog still feeds config/admin surfaces and HTTP approval dry-run
  previews that call `decideQuery` without a connection.

## Go proxy

- `cp.Client`. `ValidateToken` gains `datasource_name` and returns
  `connection_id` + `on_open`; new `PushSchemaFragment` + `CloseConnection`;
  `Decide` sends `connection_id` and its result mapper branches on the `outcome`
  oneof — `before_decide` first, else map the verdict (unknown/empty → DENY, the
  fail-closed mapping).
- Held-connection introspection (per schema). Two held-connection queries, both
  through the same injected-probe mechanism as
  `probeNamespace`/`probeTempColumns`: the DB-side hash query for a schema, and
  the per-schema full introspection (the `columnsSQL` column scan filtered to
  the schema — all schemas including system, never excluded). Both run on the
  wire session's backend connection so they see its transaction.
  `introspect.Run` (dedicated connection) stays for the config catalog only.
- PG extended-protocol capture uses the extended probe. When a PG connection is
  mid extended-query batch (Parse/Bind/Execute), the held-connection hash and
  introspection queries are issued via the extended protocol (unnamed
  Parse/Bind/Execute, Flush), never an injected simple `Query` — a simple query
  would trigger an implicit commit/sync of the pending extended batch and
  corrupt normal operation.
- Fetch-on-open / refresh-on-command. Run `on_open` before the serve loop; run
  `after_statement` immediately after the backend's mechanical success signal
  (PG simple: no `ErrorResponse` before `ReadyForQuery`; PG extended:
  `CommandComplete` for the flagged `Execute`; MySQL: the tracked OK/EOF
  terminator, `relayQueryResponseTracked`, for both `COM_QUERY` and
  `COM_STMT_EXECUTE`). No tx-status gate, no pending flags.
- `before_decide` loop. Run the commands, re-send the same `DecisionRequest`
  (bounded retries; repeated failure → fail closed).
- Refresh failure is fail-closed, per-connection. A failed `after_statement`
  refetch would leave this connection's fragment provably wrong for the open
  transaction → close both connections (forcing backend rollback). The
  control-plane pending mark makes this belt-and-suspenders.

## The catalog hash

The hash gates every `REFETCH`. A hash collision would let the control plane
reuse the wrong fragment for a schema — a wrong-ALLOW — so it is specified by
requirements, with the concrete DB-side realization chosen here.

Requirements:

- DB-side only. The hash is computed by a query on the target; the proxy never
  computes a hash from catalog rows. The proxy does only byte-equality of the
  returned hash against the command's `H` (equality is not hashing).
- Intra-server deterministic. Same schema, same server ⇒ same hash over time.
  Cross-server/cross-version stability is not required — a differing server just
  triggers a fetch (at worst an extra fetch, never a wrong reuse).
- Complete. Covers every enforcement-relevant field the fragment carries and
  `decideQuery` relies on: per column — table name, column name, ordinal, data
  type (the `sql_type` the analyzer resolves), nullability — plus table
  existence (a drop/rename must change the hash). A field omitted from the hash
  is a change to it that does not refetch — a fragment that misdescribes the
  schema — a wrong-ALLOW. (Classifications are not hashed; they are joined
  control-plane-side. Their rename hazard is a known limitation below.)
- Collision-resistant against a DDL-shaping adversary. An attacker who can run
  DDL must not be able to craft two distinct enforcement-relevant schema states
  with the same hash ⇒ a cryptographic hash (SHA-256), never
  MD5/CRC/XOR-set-hash (all forgeable/linearizable by a chosen-input adversary).
  MySQL (the priority engine) always has `SHA2`; PostgreSQL without `pgcrypto`
  falls back to `md5()` (a known limitation below).
- Per-schema.
- Fail-safe. If the target cannot produce a trustworthy hash (function
  unavailable, aggregate truncated, error, unexpected shape), the `REFETCH`
  degrades to an unconditional full fetch. A missing / truncated / untrusted /
  ambiguous hash must never suppress a refetch.

MySQL (priority engine):

- Source `information_schema.COLUMNS` filtered to `TABLE_SCHEMA = ?`, ordered
  deterministically by `(TABLE_NAME, ORDINAL_POSITION, COLUMN_NAME)`.
- Serialize each row with an unambiguous, length-prefixed encoding of the fields
  — each field emitted as its byte length followed by its bytes — so no two
  distinct rows can share a serialization (`('ab','c')` ≠ `('a','bc')`). Plain
  per-field hex without a length is not sufficient (`HEX('ab')‖HEX('c')` =
  `HEX('a')‖HEX('bc')` = `616263`); a length prefix is required.
- Per-row cryptographic digest `SHA2(row_blob, 256)`, then aggregate
  order-dependently and digest again:
  `SHA2(GROUP_CONCAT(row_digest ORDER BY … SEPARATOR ''), 256)`.
- `GROUP_CONCAT` silently truncates at `group_concat_max_len` (default 1024
  bytes), which could collide two schemas. Set `group_concat_max_len` to a large
  bound for the hashing query, and detect truncation fail-safe — compare the
  produced length against the expected `64 × COUNT(*)`; if short (cap hit),
  treat the hash as untrustworthy → unconditional fetch. Never trust a
  possibly-truncated aggregate.

PostgreSQL (experimental):

- Source `information_schema.columns` (or
  `pg_attribute`/`pg_class`/`pg_namespace`) for the schema, ordered by
  `(table_name, ordinal_position, column_name)`; aggregate with `string_agg` (no
  truncation limit — the MySQL trap does not exist on PG) then digest.
- SHA-256 needs pgcrypto's `digest(…, 'sha256')`. If pgcrypto is available, use
  it; if not, fall back to core `md5()` — not an unconditional full fetch, which
  would negate the hash gate for every PG-without-pgcrypto deployment. `md5()`
  is deterministic and complete, so it detects ordinary schema drift, but it is
  not collision-resistant against a DDL-shaping adversary (a known limitation
  below). Installing `pgcrypto` restores full collision-resistance.

The hash runs on the held connection (so `after_statement` sees uncommitted DDL)
and, mid PG extended batch, via the extended probe.

## The config-catalog channel

A second `grpc.ClientConn` (its own HTTP/2 connection to the same control-plane
endpoint, same `x-pm-secret-token`), owned by a config-side client in
`goproxy/boot/boot.go`:

- Carries `Register` (boot + Events-reconnect resync), `PushCatalog` (boot,
  ambient ~12 min SWR, admin `RefreshCatalog` via Events), the `Events` stream
  (liveness + editor/table-detail nudges), and `TableDetailExec`.
- The enforcement channel carries `ValidateToken`, `Decide`,
  `PushSchemaFragment`, `CloseConnection`, `RunExec`, `ReportCompletion`.
- Config reads never touch the per-connection enforcement path — separate store,
  channel, and failure domain. Ambient config refresh is a full
  `introspect.Run` + `PushCatalog` (not the enforcement per-schema hash gate).

## Editor, table-detail, temp overlay

- The editor session is just another connection. It already holds one backend
  connection per session (`RunExecService.openSession` / one `RunExec` stream).
  `OpenRunChannel` carries `connection_id` + `on_open`; the proxy fetches the
  session's schemas before the first `RunQuery`; editor DDL/CALL gets the same
  `after_statement`; `closeSession`/`sweepIdleSessions` evict.
- The temp-column overlay is separate. Per-connection base fragments exclude
  `pg_temp*` (they carry no special trust); the per-query `temp_columns` overlay
  on `DecisionRequest` continues with its EDITOR-channel + `pg_temp*` gates
  (`editorTempOverlay`), because temp columns read unmasked and skip the
  uncovered-scan gate — trust semantics the base catalog must not inherit. That
  overlay is what `CatalogColumn.isTemp` marks, and it exists only for the
  duration of a decision: `GET /api/datasources/{id}/catalog` serves the
  persisted catalog, so every row it returns has `isTemp: false`.
- Table-detail is admin metadata browsing — a config surface, on the
  `TableDetailExec` / config channel.

## Known limitations

- Rename launders classifications (fail-open; administrator responsibility).
  Column tags / classifications are name-keyed
  `(datasource, schema, table, column)`. A `RENAME` / `ALTER … RENAME` moves
  columns to a new key, so the fragment refreshes correctly (structure current)
  but the tags do not follow — a PII column can read unmasked under a broad
  "everything unless `pii`" grant until it is re-tagged. Keeping classifications
  correct after a rename / schema change is the administrator's responsibility.
- DDL inside a trigger fired by DML (niche, not flagged). `after_statement`
  flags explicit DDL and CALL/routine invocation. A `DELETE`/`INSERT`/`UPDATE`
  that fires a trigger which runs DDL is a side effect the control plane cannot
  see without treating nearly every DML as catalog-changing. The staleness bound
  bounds it as external drift.
- PostgreSQL transactional-DDL edges (experimental; severity mixed). MySQL DDL
  is implicit-commit (no transactional-DDL rollback), so none of these arise on
  the priority engine. On PG: an implicit-transaction/`Sync` rollback undoing a
  captured DDL; a failed COMMIT via deferred constraints reverting DDL after the
  fragment already reflects it; a savepoint-local `ROLLBACK TO` reverting a
  subset; a control-plane restart losing transaction-dirty provenance
  mid-transaction. When the reverted object has no search-path fall-through
  candidate this is fail-closed (the bare name no longer resolves → deny →
  availability, not disclosure). When the name is shadowed later in the
  `search_path` it is fail-open (disclosure): e.g. `search_path = app, public`,
  both holding `accounts`; an in-tx `DROP app.accounts` is captured, then
  `COMMIT` / `Sync` / `ROLLBACK TO` reverts it; the held fragment still shows
  `app.accounts` gone, so `decideQuery` resolves bare `accounts` to
  `public.accounts` (allowed) while the reverted backend binds the restored
  `app.accounts` → cleartext of `app.accounts`. Fail-closed stopgap: on any
  observed rollback / `Sync`-abort / savepoint-revert, force a `before_decide`
  re-check of the transaction-dirty schemas instead of trusting the held
  fragment.
- MySQL temporary-table shadowing (mostly fail-closed). A
  `CREATE TEMPORARY TABLE` is invisible to `information_schema`, so a session
  temp shadowing a base-table name is not captured in the held fragment;
  `decideQuery` resolves the bare name to the base table while the backend binds
  the temp. Mostly fail-closed in practice (temp creation is a write gated by
  the write-references-masked deny; shape-mismatched reads against the temp tend
  to error). MySQL has no `pg_temp`-style overlay
  (`SupportsTempOverlay() == false`).
- PostgreSQL without `pgcrypto` (weakened schema-hash collision-resistance).
  Where `pgcrypto` is absent the schema hash falls back to core `md5()` rather
  than full-fetching every schema. `md5` detects ordinary schema drift but is
  not collision-resistant against a principal who can shape DDL, who could in
  principle force an `md5` collision to suppress a `REFETCH` and hold a stale
  catalog → wrong-ALLOW. Install `pgcrypto` (or use a PG build exposing a core
  SHA) to restore collision-resistance.
- Refetch hash/columns coherence (ABA revert window, bounded). The Go proxy's
  content hash is measured before and after the per-schema introspection
  (`engine.Refetcher`) and trusted only if both match; this catches a single
  concurrent change but not an external `A→B→A` byte-identical revert landing
  between the back-to-back probe queries (a ~microsecond window). It would push
  `columns(B)` under `hash(A)`, letting a later connection at state A satisfy an
  `unchanged` gate against the wrong fragment. It cannot arise on the priority
  self-DDL path (no external race) and is a refinement of the external-drift
  class. Robust fix: derive the hash from the same snapshot/query as the
  fragment rows so they cannot diverge.
- PostgreSQL held-connection-probe residuals (experimental, fail-closed). A
  catalog-changing extended-protocol statement ending in `PortalSuspended`
  (row-limited Execute) defers its `after_statement` refetch to the next
  `CommandComplete` — niche for DDL (returns no rows) and backstopped by the
  pending mark. A held-connection probe that draws an `ErrorResponse` mid
  extended-batch leaves the backend awaiting `Sync`, so the next probe blocks
  until the read-idle timeout before failing closed — a latency amplification,
  not a leak; a `Sync`-to-resync removes it.

[KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md) and [backlog.md](./backlog.md)
hold the tracked severities and follow-ups.
