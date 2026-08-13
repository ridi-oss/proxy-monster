# Datasource registration — the proxy is the source of truth

The proxy registers itself with the control-plane over gRPC; the control-plane
never connects to a target datasource. On boot a proxy declares its identity,
introspects the target itself using the one credential that matters — its own
broker service account — and pushes the resulting catalog. The control-plane's
only database dependency is its own metadata Postgres: zero target-datasource
credentials live in the control-plane, ever.

Point a proxy at a new target and it appears in the control-plane on its own.
The admin "Add Datasource" form is optional pre-provisioning (reserve a name,
set up policy ahead of time), not a required gate.

A proxy needs only `PM_DATASOURCE_NAME` — already what Cedar policies key on
(`Datasource::"<name>"`, `authz/Authz.kt`) — plus `PM_TARGET_*` for its own
target-DB connection. No numeric id crosses the wire; the control-plane keeps a
`BIGSERIAL` surrogate internally and resolves `name` → `id` on every call.

## The gRPC surface

gRPC is the proxy↔control-plane transport, an internal trusted-service surface
(`proto/src/main/proto/controlplane.proto`). The web UI keeps talking HTTP/JSON
to the control-plane — browsers do not speak gRPC natively, and the admin/query
surface gains nothing from it. gRPC is a clear win on the proxy path: `Decide`
runs on every brokered query, so protobuf encoding + HTTP/2 multiplexing matter
there; one `.proto` replaces two hand-synced type sets; and a proxy-initiated
stream is the natural fit for liveness and refresh push.

```protobuf
service ControlPlane {
  rpc Register(RegisterRequest) returns (RegisterResponse);            // boot: declare identity
  rpc PushCatalog(CatalogRequest) returns (CatalogResponse);          // push the introspected catalog
  rpc ValidateToken(ValidateTokenRequest) returns (WireIdentity);     // wire-auth handshake, once per session
  rpc Decide(DecisionRequest) returns (WireDecision);                 // per-query enforcement decision
  rpc PushSchemaFragment(SchemaFragmentPush) returns (SchemaFragmentAck);  // per-connection catalog fragment
  rpc CloseConnection(CloseConnectionRequest) returns (CloseConnectionResponse);
  rpc Events(EventsRequest) returns (stream ControlEvent);            // liveness + refresh/run/table-detail nudges
  rpc RunExec(stream ProxyRunMsg) returns (stream ControlRunMsg);     // CP-driven editor/workflow execution
  rpc TableDetailExec(stream ProxyTableDetailMsg) returns (stream ControlTableDetailMsg);  // admin table browser
  rpc ReportCompletion(CompletionReport) returns (google.protobuf.Empty);  // post-relay result-volume, audit-only
}
```

The Go proxy client is `goproxy/cp/client.go`; the control-plane gRPC server is
`grpc/GrpcServer.kt` + `grpc/ControlPlaneGrpcService.kt`. Every RPC carries the
shared secret as call metadata (see [Trust model](#trust-model)).

## Registration

`goproxy/boot/boot.go` calls `Register` then `PushCatalog` on boot, retrying
with backoff. Registration is idempotent, upserted by `name`: a restart or
redeploy upserts the same row.

```protobuf
message RegisterRequest {
  string name = 1;              // stable identity; Cedar's Datasource::"<name>"; upsert key
  Engine engine = 2;            // POSTGRES | MYSQL
  string host = 3;              // advisory only — admin UI / triage
  int32 port = 4;               // advisory only
  string db_name = 5;           // advisory only
  repeated string tags = 6;     // posture tags; empty => production floor
  string advertise_addr = 7;                    // client-facing host:port a wire client dials to reach THIS proxy
  reserved 8, 9;                                // a leaf SHA-256 clients pinned against, and the leaf alone
  optional string advertise_cert_chain = 10;    // PEM chain to trust for this proxy, leaf first; absent = no opinion, present-blank = clear
  bool advertise_wire_tls = 11;                 // whether this proxy serves client-facing TLS at all
}
```

`host`/`port`/`db_name` are descriptive: nothing in enforcement reads them
(Cedar keys on `name`; lineage reads the pushed catalog). They exist for the
admin UI and incident triage — which physical instance a datasource points at.

The three `advertise_*` fields are the opposite — client-facing and consumed.
`advertise_addr` is the `host:port` a wire client dials to reach this
datasource's proxy (`PM_ADVERTISE_ADDR`, [`../INSTALL.md`](../INSTALL.md)), not
the upstream target DB `host`/`port` above.

`advertise_cert_chain` is the certificate chain a client should trust to reach
this proxy: PEM, leaf first, then any intermediates and the root. A self-signed
cert is the one-element case. Verification is ordinary TLS — `pmon` uses it as
its root pool with `advertise_addr` checked against it, and `psql`/`mysql`/
DataGrip take the same bytes as `sslrootcert` / `--ssl-ca` with `verify-full`
(served by `GET /api/datasources/{id}/wire-cert`). The field is `optional` for
explicit presence: ABSENT means "no opinion, keep the stored chain" (a transient
cert read on the proxy), while PRESENT-but-empty CLEARS it, so an operator who
stops publishing does not leave clients on roots the proxy no longer serves.

`advertise_wire_tls` says whether the proxy serves TLS at all, and is
deliberately independent of the chain: a proxy may serve a publicly-trusted
certificate and publish nothing (`PM_TLS_NO_ADVERTISE`), so an empty chain does
NOT mean plaintext. `pmon` refuses to send its token to a proxy that offers no
TLS whenever this is set — inferring the requirement from the chain instead
would make an attacker's plaintext greeting indistinguishable from a datasource
that never had TLS. `pmon` brokers MySQL only today, so a PostgreSQL client
verifies with the downloaded file instead.

`GET /api/datasources` surfaces all three (`advertiseAddr`,
`advertiseCertChain`, `advertiseWireTls`). That is how a client finds them:
`pmon` lists `?connectable=true`, and an entry carrying an `advertiseAddr` is
enough to open a local broker port for that datasource.

Only a proxy sets them; the admin REST create/update does not. A proxy with wire
TLS fails to boot only if its certificate cannot be READ — whether the chain is
usable as a client's trust anchor is the client's verification to make, and is
logged as a warning rather than refused. `advertise_addr` upserts through
`COALESCE`, so a blank preserves the stored value. The chain carries explicit
presence instead: absent preserves, present-blank clears. Turning wire TLS off
also clears the stored chain, so a datasource never keeps advertising trust
material for a certificate it no longer serves.

A chain the control plane cannot verify a path through is stored and served with
a logged warning, never refused. Refusing would mean the datasource is never
created at all — no catalog, every decision failing closed — which is a worse
outcome than one client reporting its own TLS error. See
[`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) for the trust-widening
tradeoff that follows from serving unverified material.

`tags` carry the datasource's policy posture — `system:development` (permissive,
audited, nothing masked) versus the `system:production` floor an untagged
datasource falls back to (fail-closed, deny-by-default). See
[`policy-store.md`](./policy-store.md). A dev proxy self-registering with
`system:development` gets a sane, audited posture with zero hand-authored
policy.

## Catalog

The proxy introspects the target and pushes the catalog — it already holds the
live connection (`goproxy/introspect/`). The scan is the ordinary
`information_schema.columns` query per engine.

```protobuf
message CatalogRequest {
  string datasource_name = 1;
  repeated string default_schemas = 2;               // PG: unnest(current_schemas(true))
  optional int32 mysql_lower_case_table_names = 3;   // MySQL: @@lower_case_table_names
  repeated Column columns = 4;
  string engine_version = 5;                         // SELECT version() (+ aurora marker)
}
```

`default_schemas` and `mysql_lower_case_table_names` are load-bearing, not
advisory: schema-threading resolves every bare table reference to catalog+schema
via exactly these values, and getting them wrong authorizes a different table
than the target DB binds (see [`connection-model.md`](./connection-model.md)).
Both come from live server/session state the proxy holds and cannot be
hand-configured reliably. `engine_version` feeds
[`system-classification.md`](./system-classification.md), whose
per-engine/version manifest the control-plane cannot probe itself — it never
dials the target, so the proxy, the side with a live connection, supplies the
version.

## Per-query decision

`Decide` takes the raw token, not a cached principal. The proxy holds only the
token string and forwards it on every call; the control-plane re-derives the
principal and re-resolves roles server-side, every time. One consistent rule at
every layer: never trust client-asserted authorization state.

```protobuf
message DecisionRequest {
  string token = 1;             // re-validated + re-resolved server-side on every call
  string datasource_name = 2;
  string sql = 3;
  repeated string search_path = 4;
  bytes connection_id = 7;
  // ... per-connection temp columns, client_addr, live sql_mode flags
}
```

Every query re-Decides, including PostgreSQL server-prepared statements: a
statement's Parse/Bind-time decision is not reused across `Execute`s. So a
mid-session token revocation, grant expiry, or role change is caught on the very
next `Execute`, not deferred until the client re-Parses. There is no
per-statement decision cache — the prepared-statement fast path is traded for
the fail-closed guarantee. A cached `ALLOW` whose grant expired would otherwise
relay cleartext.

`ValidateToken` stays scoped to the wire-protocol auth handshake — MySQL and
PostgreSQL need an accept/reject signal at the auth step before any query flows.
Its job is "may this session open," not "cache something `Decide` will trust."

## Trust model

The same shared secret gates every proxy↔control-plane RPC: `PM_SECRET_TOKEN`,
carried as gRPC call metadata (`x-pm-secret-token`) and checked by a server-side
interceptor (`grpc/SecretTokenInterceptor.kt`). A proxy holding it is already
trusted to report a decision or an audit record for any datasource; trusting it
to also describe its own identity and catalog is the same trust boundary,
extended — not a new one.

It is one system-wide secret, and `Register` takes a caller-asserted name: any
holder can register under, or overwrite, any datasource name. A wrong catalog or
wrong tags on a name is detectable — an admin sees a `host`/`port` that does not
match what they expect. The `advertise_*` fields are not: whoever holds the
secret can repoint a datasource at their own address, advertise a chain that
matches the certificate they serve there, and collect the wire tokens `pmon`
sends. No client-side verification covers this, because the attacker supplies
the trust material and the address together — the chain is verified correctly
and belongs to the wrong proxy. Per-datasource registration tokens or gRPC
mutual-TLS client certs bound to the permitted name are the fix; see
[`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md).

The gate is only as good as the secret being set: `SecretTokenInterceptor` with
no configured secret lets every call through, and `GrpcServer` logs the surface
as `OPEN — dev only`. Set `PM_SECRET_TOKEN` on the control plane and on every
proxy.

## Liveness and on-demand refresh

The proxy opens `Events` once at startup and keeps it open for its lifetime,
reconnecting if it drops. The open stream is itself the liveness signal — the
control-plane sees the stream close and knows the proxy is down, with no polling
interval to wait out. Down the same stream the control-plane pushes nudges:
`RefreshCatalog` (re-introspect now — an admin just added a column), plus the
`OpenRunChannel` and `OpenTableDetailChannel` nudges below.

```protobuf
message ControlEvent {
  oneof kind {
    RefreshCatalog refresh_catalog = 1;
    OpenRunChannel open_run_channel = 2;
    OpenTableDetailChannel open_table_detail_channel = 3;
  }
}
```

The proxy re-introspects on boot, on a `RefreshCatalog` nudge, and on a longer
ambient cadence as a safety net against silent schema drift — a new unclassified
PII column with zero policy coverage is exactly the gap this tool exists to
close.

The REST projection of that signal is three routes, none of which dials a
target:

- `POST /api/datasources/{id}/test` is a proxy-attachment check, not a database
  connection test: `ok` is true when a proxy `Events` stream is currently
  attached to this datasource, and `message` adds the catalog-sync and last-seen
  state. It reaches neither the target DB nor the proxy.
- `GET /api/datasources/live` is the same signal as a list of attached
  datasource names. `Datasource.lastSeenAt` is weaker — it records only that a
  proxy was seen at some point, and never clears.
- `POST /api/datasources/{id}/refresh` pushes `RefreshCatalog` down every open
  stream for the datasource and answers with how many were notified (`0` = no
  proxy attached, and the call is otherwise a no-op). The catalog then updates
  asynchronously: each notified proxy re-introspects and pushes fresh columns
  back via `PushCatalog`, which is what actually replaces the persisted rows and
  bumps `catalogSyncedAt`.

## Engine is immutable

Re-registering an existing `name` under a different `engine` is rejected
fail-closed. `DatasourceStore.register` (`Datasources.kt`) throws
`DatasourceEngineConflictException` before the upsert, which
`ControlPlaneGrpcService.register` maps to gRPC `FAILED_PRECONDITION`; the row
and catalog are left untouched. A silent engine flip would repoint every
`datasource_id` foreign key at a schema from a different dialect and stale the
analyzer dialect and system-classification manifest — all fail-open — so it is
guarded, not warned.

The guard is atomic in the conflict arm:
`ON CONFLICT (name) DO UPDATE SET … WHERE datasource.engine = EXCLUDED.engine` —
a row raced in under a different engine matches 0 rows and `register` rejects,
regardless of who else writes the row. `host`/`port`/`db_name` stay
advisory-mutable; a `db_name` change still invalidates the stale catalog
fail-closed. The admin edit path (`PUT /api/datasources/{id}`) enforces the same
immutability, rejecting an `engine` change with
`409 datasource.engine_immutable`; the web edit form seeds `engine` from the
current value and disables it.

## The run channel — editor and workflow execution

The SQL editor and the approval-workflow executor run their queries through the
proxy, over the same `Decide` and result-relay path a native-wire client uses —
not a separate in-control-plane enforcement path. Since the control-plane never
dials into a proxy, execution rides a proxy-dialed bidirectional stream: the
control-plane nudges the proxy over `Events` (`OpenRunChannel`, carrying a
short-lived ephemeral token minted for the requester), and the proxy dials back
with `RunExec`. Data then flows both ways over a connection the control-plane
never opened.

One stream serves one session (session ↔ `RunExec` stream ↔ its own target-DB
connection), so a slow query in one session cannot head-of-line-block another,
the stream's lifecycle is the session's lifecycle, and each session gets a
dedicated target-DB connection where transactions, `SET`, and temp tables behave
like a real session.

```protobuf
// ProxyRunMsg (proxy -> cp):
//   RunReady        — correlates this stream to its OpenRunChannel
//   RunDecision     — the enforcement verdict + UX metadata, before any rows
//   RunResultRows   — masked rows (ALLOW/MASK only)
//   RunDone | RunError
// ControlRunMsg (cp -> proxy): RunQuery{sql, max_rows} | RunClose
```

The proxy runs the query on the session's connection, decides it through its
normal `Decide` (so the requester's principal, grants, and masking all apply
identically), and streams the decision and masked rows back. The decision
metadata rides the same stream because the editor draws enforcement affordances
around the grid: `decision_id` (the audit-row id) is what a "Request approval"
button attaches to, `masked_columns` drives the "masked" badges so a `####`
reads as masked rather than a bug, `deny_reason` is the human "denied because
…", and `decision` + `effective_roles` round out the audit view. Because the
proxy is the party that ran `Decide`, it already holds the verdict and emits it
up its own stream — no decision↔rows correlation dance. See
[`approval-workflow.md`](./approval-workflow.md).
