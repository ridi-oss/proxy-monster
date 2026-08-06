# A10 — gRPC Surface (proxy → control-plane)

Files: `grpc/ControlPlaneGrpcService.kt` (594) · `grpc/GrpcServer.kt` (77) ·
`grpc/GrpcMappers.kt` (44) · `grpc/SecretTokenInterceptor.kt` (42). **Total 757
LOC. Fully read.** Also read in full, as the machine-readable half of this
contract: `proto/src/main/proto/controlplane.proto` (355) ·
`proto/src/main/proto/engine.proto` (16) ·
`proto/src/main/kotlin/com/ridi/oss/proxymonster/grpc/WireMetadata.kt` (24) ·
`goproxy/cp/client.go` (**500**, the existing Go **client** this server half
must satisfy) · `goproxy/internal/pb/controlplane_grpc.pb.go` (the generated
service descriptor).

**Tables touched:** none directly — every handler goes through a store.
Transitively, in one handler transaction: `audit_event` + `audit_chain_head` (A8
`AuditStore.insert`) and `access_request` (A7 `AccessStore`), both inside
`reportCompletion`'s `inTx`. Read/written via stores elsewhere in the area:
`proxy_token` (A4), `datasource` / `catalog_column` / `column_classification`
(A5), `app_user` (A3), `policy` (A2), plus everything `decideQuery` reaches
(A6).

> **The one area with an existing machine-readable spec.** `controlplane.proto`
> is the contract, it is already the single source of truth for both sides'
> bindings, and `goproxy` already generates a Go **client** from it
> (`goproxy/internal/pb`). The Go control-plane therefore does not get to
> redesign this surface: it must serve exactly the ten RPCs
> `pb.ControlPlaneServer` declares, with the same status codes, because
> `goproxy/cp/client.go` already maps those codes to fail-closed behaviour.

---

## Purpose

The proxy↔control-plane transport. Ten RPCs over plaintext HTTP/2 on
`PM_GRPC_PORT`, gated by one shared transport secret, all handled by a single
service class backed by the **same** `ControlPlaneCore` dependency graph the
HTTP surface uses (A1 INV-A1-1 — sharing is mandatory, because Cedar's policy
cache invalidates on an in-memory version counter, so a second graph would serve
permanently stale decisions to the data plane).

Three of the ten are the hot path: `ValidateToken` (session handshake), `Decide`
(per-statement enforcement, re-validating the raw token on **every** call), and
`ReportCompletion` (post-relay volume signal). Four keep catalog state current
(`Register`, `PushCatalog`, `PushSchemaFragment`, `CloseConnection`). Three are
streams the **proxy dials** — `Events` (liveness + push), `RunExec` (CP-driven
query execution), `TableDetailExec` (admin table browser) — so that data flows
both ways without the control-plane ever opening a connection toward a proxy.

This area owns transport, request validation, and marshalling only. Every
decision it returns is computed by A5's `decideConnection` → A6's `decideQuery`;
every catalog mutation is A5's; every audit write is A8's. The handler bodies
are almost entirely **argument derivation and fail-closed guards**, and that is
where the security content of the area lives.

---

## 1. Wire contract

There are **no `@Serializable` DTOs in this area** — the wire contract is
protobuf, not JSON. The tables below are the complete contract as the handlers
read and write it. Field numbers are load-bearing and must not be renumbered.

### 1.1 Service — ten RPCs

Every RPC passes through exactly one gate: `SecretTokenInterceptor` (§3.4).
There is no per-RPC gate and no `requireApi`/`requireAdmin` equivalent here —
the _proxy_ is authenticated by the shared secret; the _end user_ is
authenticated per call by the token inside the request body.

| #   | RPC                  | Shape         | Request                      | Response                       | Gate         | Error codes emitted by the handler                                                   |
| --- | -------------------- | ------------- | ---------------------------- | ------------------------------ | ------------ | ------------------------------------------------------------------------------------ |
| 1   | `Register`           | unary         | `RegisterRequest`            | `RegisterResponse`             | secret token | `INVALID_ARGUMENT`, `FAILED_PRECONDITION`                                            |
| 2   | `PushCatalog`        | unary         | `CatalogRequest`             | `CatalogResponse`              | secret token | `NOT_FOUND` (+ store exceptions → `UNKNOWN`)                                         |
| 3   | `ValidateToken`      | unary         | `ValidateTokenRequest`       | `WireIdentity`                 | secret token | `UNAUTHENTICATED`, `INVALID_ARGUMENT`, `NOT_FOUND`                                   |
| 4   | `Decide`             | unary         | `DecisionRequest`            | `WireDecision`                 | secret token | `UNAUTHENTICATED`, `NOT_FOUND`, `INVALID_ARGUMENT`, `ABORTED`, `FAILED_PRECONDITION` |
| 5   | `PushSchemaFragment` | unary         | `SchemaFragmentPush`         | `SchemaFragmentAck`            | secret token | `NOT_FOUND`, `FAILED_PRECONDITION`, + any `Status.Code` A5's `Rejected` carries      |
| 6   | `CloseConnection`    | unary         | `CloseConnectionRequest`     | `CloseConnectionResponse`      | secret token | any `Status.Code` A5's `Rejected` carries (`NOT_FOUND` in practice)                  |
| 7   | `Events`             | server stream | `EventsRequest`              | `stream ControlEvent`          | secret token | `NOT_FOUND`                                                                          |
| 8   | `RunExec`            | **bidi**      | `stream ProxyRunMsg`         | `stream ControlRunMsg`         | secret token | `FAILED_PRECONDITION`, `NOT_FOUND`, `DEADLINE_EXCEEDED`                              |
| 9   | `TableDetailExec`    | **bidi**      | `stream ProxyTableDetailMsg` | `stream ControlTableDetailMsg` | secret token | `FAILED_PRECONDITION`, `NOT_FOUND`, `DEADLINE_EXCEEDED`                              |
| 10  | `ReportCompletion`   | unary         | `CompletionReport`           | `google.protobuf.Empty`        | secret token | `INVALID_ARGUMENT`, `NOT_FOUND`                                                      |

The RPC **declaration order** in `service ControlPlane {}`
(`controlplane.proto:37-67`) is
`Register, PushCatalog, ValidateToken, Decide, PushSchemaFragment, CloseConnection, Events, RunExec, TableDetailExec, ReportCompletion`.
It is not semantically meaningful, but reordering churns generated code for
nothing. ⚠️ **Correction:** that is _not_ the generated `ServiceDesc` order.
protoc-gen-go-grpc splits the descriptor into two arrays
(`goproxy/internal/pb/controlplane_grpc.pb.go:448-495`): `Methods` =
`Register, PushCatalog, ValidateToken, Decide, PushSchemaFragment, CloseConnection, ReportCompletion`
(unary; `ReportCompletion` is `Methods[6]`, **not** the tenth entry), and
`Streams` = `Events, RunExec, TableDetailExec`. Declaration order is preserved
only _within_ each group. A Go server that implements the interface satisfies
both regardless of order — the point is that "the tenth RPC" is not a position
anything in Go can be indexed by.

### 1.2 Metadata

| Header              | Type         | Meaning                                                                                                                                                                                                                                             |
| ------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `x-pm-secret-token` | ASCII string | `PM_SECRET_TOKEN`. Authenticates the **proxy** to the control-plane. Distinct from `DecisionRequest.token` / `ValidateTokenRequest.token`, which authenticate the DB **client** and are re-resolved server-side per call (`WireMetadata.kt:13-18`). |

Server-side handle: `WireMetadata.SECRET_TOKEN_CTX`
(`Context.key("pm-secret-token")`). See **F21** — no production handler reads
it.

### 1.3 Enums

| Enum                            | Values (name = number)                                    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EnfAction`                     | `ENF_ACTION_UNSPECIFIED=0`, `ALLOW=1`, `MASK=2`, `DENY=3` | 🔒 **INV-A10-53** — see below.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `Engine` (`engine.proto:12-16`) | `ENGINE_UNSPECIFIED=0`, `POSTGRES=1`, `MYSQL=2`           | One enum shared across wire boundaries so there is no parallel hand-rolled type per boundary. ⚠️ **Correction:** it is used in exactly **two** places today — `RegisterRequest.engine` (`controlplane.proto:85`) and the analyzer's `EngineConfig.engine` (`analyzer.proto:57`). `CatalogRequest` carries **no** `Engine` field; `engine.proto:3-6`'s own comment ("RegisterRequest/CatalogRequest") is stale. Do not add one back "for symmetry" — the catalog push is scoped by `datasource_name` and the CP already knows that row's engine. |

🔒 **INV-A10-53 — `EnfAction` crosses the wire by NAME, and 0 is a fail-closed
sentinel.** Quote (`controlplane.proto:14-16`): "Proto3 reserves 0 for a
fail-closed UNSPECIFIED sentinel, so these numbers deliberately do NOT match the
Kotlin enum's ordinals (ALLOW=0/MASK=1/DENY=2 there). **Map by NAME across the
wire, never by ordinal.**" Both sides honour it: `GrpcRunExecDbTest` case 5 pins
that a proxy-supplied `ENF_ACTION_UNSPECIFIED` fails closed to DENY on the CP
side, and `goproxy/engine/engine.go:228-237` (`EnfActionName`) returns `"DENY"`
for every value that is not `ALLOW`/`MASK`. The hazard is latent in the
_current_ code only because `DecisionContext.action` already **is** the proto
enum (INV-A10-51) — the moment a port introduces a domain enum, this invariant
becomes live.

### 1.4 Messages — registration and catalog

| Message            | Field                                 | #        | Type                  | Presence / semantics                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------ | ------------------------------------- | -------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RegisterRequest`  | `name`                                | 1        | string                | stable identity; Cedar's `Datasource::"<name>"`; the upsert key. Blank rejected.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|                    | `engine`                              | 2        | `Engine`              | `ENGINE_UNSPECIFIED`/`UNRECOGNIZED` rejected                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|                    | `host`                                | 3        | string                | advisory only (admin UI / triage)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|                    | `port`                                | 4        | int32                 | advisory only                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|                    | `db_name`                             | 5        | string                | advisory only — **but a change invalidates the enforcement catalog** (§3.1 `register` rule 7)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|                    | `tags`                                | 6        | repeated string       | free-form; posture tags `system:development` / `system:production`; empty ⇒ production floor via deny-by-default                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|                    | _reserved_                            | **8, 9** | —                     | ⚠️ a leaf SHA-256 clients pinned against, and the leaf alone. **"Neither number may be reused."**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|                    | `advertise_addr`                      | 7        | string                | client-facing `host:port` a wire client dials to reach _this datasource's proxy_ — **not** the upstream `host`/`port` above. Empty when the proxy isn't told its reachable address.                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|                    | `advertise_cert_chain`                | 10       | **`optional` string** | 🔒 three-valued (INV-A10-27): ABSENT = "no opinion, keep what is stored"; PRESENT-empty = "publish nothing", clears it; PRESENT-nonempty = the PEM chain, **leaf first**, then intermediates, then root. Served by `GET /api/datasources/{id}/wire-cert`; every client verifies it the ordinary way (pmon as its root pool, psql/mysql/DataGrip as `sslrootcert` / `--ssl-ca` with verify-full) — **one trust mechanism, no separate pinning path**, which is why 8/9 are reserved. ⚠️ Empty does **not** mean "no TLS": an operator may serve a publicly-trusted cert and publish nothing (`PM_TLS_NO_ADVERTISE`), leaving clients to their own trust store. |
|                    | `advertise_wire_tls`                  | 11       | bool                  | whether the proxy serves client-facing TLS **at all**. Authoritative and independent of the chain, "because trust MATERIAL and the TLS REQUIREMENT are different facts: a proxy can serve TLS while publishing no chain, and a transient cert-read at re-register sends no chain without TLS going away." 🔒 **Reason the flag exists at all** (`controlplane.proto:111-112`, and the reason a Go port must not fold it into "chain is non-empty"): "A client that knows TLS is expected refuses to fall back to plaintext — which is what stops an on-path attacker from answering with a no-TLS greeting and collecting the token in the clear."            |
| `RegisterResponse` | `name`                                | 1        | string                | echoes the stored name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `Column`           | `schema`,`table`,`column`,`data_type` | 1–4      | string                | reused by `CatalogRequest` **and** `SchemaFragmentPush`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                    | `ordinal`                             | 5        | int32                 |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|                    | `nullable`                            | 6        | bool                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `CatalogRequest`   | `datasource_name`                     | 1        | string                | must already exist (no implicit create)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                    | `default_schemas`                     | 2        | repeated string       | "load-bearing: PG `current_schemas(true)`"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|                    | `mysql_lower_case_table_names`        | 3        | **`optional` int32**  | "load-bearing on MySQL"; absent ⇒ `null`, not 0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|                    | `columns`                             | 4        | repeated `Column`     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|                    | `engine_version`                      | 5        | string                | raw `SELECT version()` with an `(aurora <v>)` suffix when `aurora_version()` resolves. The CP never dials the target, so the proxy is the only source. The CP owns parsing major + Aurora marker.                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `CatalogResponse`  | `columns`                             | 1        | int32                 | ack: **rows stored**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

### 1.5 Messages — auth handshake and per-connection catalog

| Message                   | Field                              | #    | Type                    | Presence / semantics                                                                   |
| ------------------------- | ---------------------------------- | ---- | ----------------------- | -------------------------------------------------------------------------------------- |
| `ValidateTokenRequest`    | `token`                            | 1    | string                  | raw end-user wire token                                                                |
|                           | `datasource_name`                  | 2    | string                  | blank rejected                                                                         |
| `WireIdentity`            | `principal`                        | 1    | string                  |                                                                                        |
|                           | `roles`                            | 2    | repeated string         | ⚠️ straight from the token row, **not** server-resolved — see **F25**                  |
|                           | `connection_id`                    | 3    | bytes                   | 128-bit CP-minted CSPRNG. The Go client rejects any length ≠ 16 (`client.go:148-150`). |
|                           | `on_open`                          | 4    | repeated `ProxyCommand` | one `Refetch` per default + system schema                                              |
| `SchemaFragmentPush`      | `connection_id`                    | 1    | bytes                   |                                                                                        |
|                           | `datasource_name`                  | 2    | string                  | stamped by the Go client, not the refetcher (`client.go:375`)                          |
|                           | `schema`                           | 3    | string                  |                                                                                        |
|                           | `content_hash`                     | 4    | bytes                   | the live DB-side hash the proxy just measured                                          |
|                           | `unchanged`                        | 5    | bool                    | true = live hash matched the REFETCH hash; `columns` omitted (no-op ack)               |
|                           | `columns`                          | 6    | repeated `Column`       |                                                                                        |
|                           | `backend_generation`               | 7    | uint64                  | which backend-connection instance measured this fragment                               |
| `SchemaFragmentAck`       | `generation`                       | 1    | uint64                  | per-connection generation **after** applying                                           |
| `CloseConnectionRequest`  | `connection_id`, `datasource_name` | 1, 2 | bytes, string           |                                                                                        |
| `CloseConnectionResponse` | —                                  | —    | —                       | empty                                                                                  |

### 1.6 Messages — the per-query decision

| Message           | Field                                | #                        | Type                    | Presence / semantics                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ----------------- | ------------------------------------ | ------------------------ | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DecisionRequest` | `token`                              | 1                        | string                  | 🔒 re-validated + re-resolved server-side on **every** call                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|                   | `datasource_name`                    | 2                        | string                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | `sql`                                | 3                        | string                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | `search_path`                        | 4                        | repeated string         | 🔒 the proxy's **live** namespace, passed through verbatim (INV-A10-15)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|                   | `client_addr`                        | 5                        | string                  | end-client address, for the audit record and (WIRE channel only) `requester_ip`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | `temp_columns`                       | 6                        | repeated `TempColumn`   | "Editor-session only; empty for one-shot/wire paths". 🔒 **Why it exists** (`controlplane.proto:182-185`, a reason the handler summary loses): "the session/temp tables live on THIS connection, invisible to the datasource-global catalog. The proxy introspects them off its held connection and sends them so the control-plane resolves a bare name to the connection's temp (**matching what the backend binds**) instead of a shadowed real table." Without the overlay the CP would authorize `select * from t` against `public.t` while the backend reads `pg_temp_N.t` — an authorization/execution mismatch, not merely a missing feature. |
|                   | `connection_id`                      | 7                        | bytes                   | must be exactly 16 bytes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|                   | `mysql_ansi_quotes`                  | 8                        | bool                    | live MySQL session `sql_mode` has ANSI_QUOTES; forwarded to the analyzer's `EngineConfig` so `"col"` parses as a quoted identifier (a masked column read) rather than a string literal. Absent/false for PG and default MySQL. `NO_BACKSLASH_ESCAPES` / `ANSI` stay fail-closed at the proxy.                                                                                                                                                                                                                                                                                                                                                         |
| `TempColumn`      | `schema`,`table`,`column`,`sql_type` | 1–4                      | string                  | "the temp namespace as the backend reports it (e.g. a `pg_temp_N` schema)"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|                   | `ordinal`                            | 5                        | int32                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | _(message-level)_                    | —                        | —                       | 🔒 **The reason an overlay column may be read UNMASKED at all** (`controlplane.proto:196-199` — this is the justification INV-A10-16's two gates protect, and it must not be dropped): "Carries no classification — a temp is unclassified; **the write-references-masked deny at CREATE time ensures a temp only ever holds data its creator was entitled to read**, so an editor session reading its own temp is safe (elevation is a separate, one-shot path that does not create persistent-session temps)." A Go port that relaxes the CREATE-time write-references-masked deny (A6) silently invalidates the unmasked temp read here.           |
| `ColumnMask`      | `column`                             | 1                        | string                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | `mask_fn`                            | 2                        | string                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | `kind`                               | 3                        | string                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | `ordinal`                            | 4                        | **`optional` int32**    | 🔒 explicit presence is a security requirement (INV-A10-52). Quoted: "Without it, proto3's implicit-zero default would silently bind a malformed/omitted mask to result column 0 — **masking the wrong column and leaking the intended one**. The mapper must reject absence fail-closed rather than treat it as column 0." The Go client deliberately does **not** normalize it (`client.go:211-213`).                                                                                                                                                                                                                                               |
| `WireDecision`    | _reserved_                           | **8** / `"after_commit"` | —                       | ⚠️ number **and name** reserved. Do not reuse.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|                   | `verdict` \| `before_decide`         | 1, 2                     | `oneof outcome`         | 🔒 "A message with neither outcome arm set must fail closed." The Go client returns `denyClosed("control plane returned no verdict")` (`client.go:206`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `Verdict`         | `decision`                           | 1                        | `EnfAction`             |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | `deny_reason`                        | 2                        | string                  | ⚠️ English prose on the wire (A6 **F13** — unlocalized)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|                   | `masks`                              | 3                        | repeated `ColumnMask`   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | `effective_roles`                    | 4                        | repeated string         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|                   | `rewritten_sql`                      | 5                        | **`optional` string**   | 🔒 "ABSENT = forward the client's original SQL verbatim (no `*`-expansion rewrite). A plain proto3 string would collapse that to `""`, making the mapper send an **empty query** for every non-rewritten decision."                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|                   | `decision_id`                        | 6                        | int64                   | `0` == none. Safe sentinel because `BIGSERIAL` audit ids start at 1.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|                   | `unmaskable_permitted`               | 7                        | bool                    | plain bool: absent/false ⇒ not permitted, the proxy refuses fail-closed. Set only for MASK.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|                   | `after_statement`                    | 8                        | repeated `ProxyCommand` | one `Refetch` per touched schema after a committed catalog-changing statement, each with an `if_hash_differs` guard when the CP holds a prior hash. Keeps the committed-DDL stale-catalog gate closed. **A blank-schema Refetch is never emitted** (the proxy rejects it fail-closed — `client.go:134-136`).                                                                                                                                                                                                                                                                                                                                          |
|                   | `generation`                         | 9                        | uint64                  | the per-connection generation this verdict was computed under                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|                   | `sanitize_diagnostics`               | 10                       | bool                    | 🔒 an imperative command: strip backend error/notice messages to code + severity + a generic message. "DB diagnostics echo stored values that masking hides, so they are an unmasked side-channel." Evaluated fresh per decision and **NOT latched**; deliberately DENY-inclusive and whole-row-safe.                                                                                                                                                                                                                                                                                                                                                 |
| `BeforeDecide`    | `commands`                           | 1                        | repeated `ProxyCommand` | "carries NO verdict: run commands, then re-send the same request"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `ProxyCommand`    | `refetch`                            | 1                        | `oneof command`         | the generic envelope; REFETCH is today's only arm. Unknown arms fail closed at the proxy.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `Refetch`         | `schema`                             | 1                        | string                  | the schema to conditionally re-introspect. Blank ⇒ malformed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|                   | `if_hash_differs`                    | 2                        | bytes                   | the CP's currently-held content hash for (connection, schema). **Empty/absent = unconditional fetch (fail-safe).**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

### 1.7 Messages — the three proxy-dialed streams

| Message                  | Field                                                                  | #   | Type                    | Notes                                                                                                                                                                                 |
| ------------------------ | ---------------------------------------------------------------------- | --- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EventsRequest`          | `datasource_name`                                                      | 1   | string                  |                                                                                                                                                                                       |
| `ControlEvent`           | `refresh_catalog` \| `open_run_channel` \| `open_table_detail_channel` | 1–3 | `oneof kind`            | "room for more (tag/config change, revocation hint, …) without a shape change"                                                                                                        |
| `RefreshCatalog`         | —                                                                      | —   | —                       | empty                                                                                                                                                                                 |
| `OpenRunChannel`         | `session_id`                                                           | 1   | string                  | the proxy dials `RunExec` tagging this id                                                                                                                                             |
|                          | `ephemeral_token`                                                      | 2   | string                  | short-lived wire token minted for the requester; the proxy re-presents it to its normal `Decide` path so editor and workflow queries share the exact same enforcement + relay channel |
|                          | `connection_id`                                                        | 3   | bytes                   | CP-minted for the run session. The Go client requires 16 bytes (`client.go:429`).                                                                                                     |
|                          | `on_open`                                                              | 4   | repeated `ProxyCommand` |                                                                                                                                                                                       |
| `OpenTableDetailChannel` | `session_id`,`schema`,`table`                                          | 1–3 | string                  | metadata-only introspection — **no query token needed**                                                                                                                               |
| `ProxyRunMsg`            | `session_ready`\|`decision`\|`result_rows`\|`done`\|`error`            | 1–5 | `oneof kind`            | first message **must** be `session_ready`                                                                                                                                             |
| `ControlRunMsg`          | `query`\|`close`\|`cancel`                                             | 1–3 | `oneof kind`            | `cancel` cancels the in-flight statement out-of-band; a no-op when none is running                                                                                                    |
| `RunReady`               | `session_id`                                                           | 1   | string                  |                                                                                                                                                                                       |
| `RunQuery`               | `sql`                                                                  | 1   | string                  |                                                                                                                                                                                       |
|                          | `max_rows`                                                             | 2   | int32                   | **0 = the proxy's default cap** (the proxy re-coerces). `GrpcRunExecDbTest` case 3 pins that 0 crosses the wire as 0.                                                                 |
| `RunClose` / `RunCancel` | —                                                                      | —   | —                       | empty                                                                                                                                                                                 |
| `RunDecision`            | `decision`                                                             | 1   | `EnfAction`             |                                                                                                                                                                                       |
|                          | `decision_id`                                                          | 2   | int64                   | 0 == none                                                                                                                                                                             |
|                          | `masked_columns`                                                       | 3   | repeated string         |                                                                                                                                                                                       |
|                          | `deny_reason`                                                          | 4   | string                  |                                                                                                                                                                                       |
|                          | `effective_roles`                                                      | 5   | repeated string         |                                                                                                                                                                                       |
| `RunResultRows`          | `columns`                                                              | 1   | repeated string         |                                                                                                                                                                                       |
|                          | `rows`                                                                 | 2   | repeated `RunRow`       |                                                                                                                                                                                       |
| `RunRow`                 | `values`                                                               | 1   | repeated `RunValue`     |                                                                                                                                                                                       |
| `RunValue`               | `value`                                                                | 1   | string                  |                                                                                                                                                                                       |
|                          | `is_null`                                                              | 2   | bool                    | distinguishes a real SQL NULL from an empty string                                                                                                                                    |
| `RunDone`                | `rows_affected`                                                        | 1   | int32                   | **-1 when not applicable** (a SELECT)                                                                                                                                                 |
| `RunError`               | `message`                                                              | 1   | string                  |                                                                                                                                                                                       |
| `ProxyTableDetailMsg`    | `session_ready`\|`result`\|`error`                                     | 1–3 | `oneof kind`            |                                                                                                                                                                                       |
| `ControlTableDetailMsg`  | `close`                                                                | 1   | `oneof kind`            |                                                                                                                                                                                       |
| `TableDetailReady`       | `session_id`                                                           | 1   | string                  |                                                                                                                                                                                       |
| `TableDetailResult`      | `json`                                                                 | 1   | string                  | shared engine `TableDetail` JSON; **literal `null` means not found**                                                                                                                  |
| `TableDetailError`       | `message`                                                              | 1   | string                  |                                                                                                                                                                                       |
| `TableDetailClose`       | —                                                                      | —   | —                       | empty                                                                                                                                                                                 |

### 1.8 `CompletionReport`

| Field            | #   | Type   | Semantics                                                                                                        |
| ---------------- | --- | ------ | ---------------------------------------------------------------------------------------------------------------- |
| `decision_id`    | 1   | int64  | `Verdict.decision_id` — the audit id the `Decide` response carried. **0 is rejected.**                           |
| `rows_returned`  | 2   | int64  | the audit monitor's mass-export rule keys on this                                                                |
| `bytes_returned` | 3   | int64  | ditto                                                                                                            |
| `status`         | 4   | string | exactly one of `ok` \| `error` \| `canceled`; error/cancel carry the **partial** counts relayed before the fault |
| `duration_ms`    | 5   | int64  | relay wall time (**not** decision latency)                                                                       |

Contract note from the proto (`controlplane.proto:61-65`): "Best-effort — the
proxy fires it off the client session's critical path and a failure never
affects the query. **A DENY relays nothing, so it produces no completion.**" The
Go client logs and swallows every failure (`client.go:311`).

---

## 2. Routes

**None.** This area exposes no HTTP routes and calls no HTTP auth gate helper
(`requireApi` / `requireAdmin` / `requireAuthz` / `requireScimAuth` are all
absent from every file in `grpc/`). Its sole gate is `SecretTokenInterceptor`
(§3.4).

---

## 3. Symbols

### 3.1 `ControlPlaneGrpcService.kt`

#### `RUN_STREAM_TIMEOUT_MS` · internal const

Kotlin: `internal const val RUN_STREAM_TIMEOUT_MS = 15 * 60 * 1000L`
**Contract:** the default lifetime cap on one proxy-dialed `RunExec` stream (15
min). **Behavior:** used only as the default value of the service's
`runStreamTimeoutMs` constructor parameter. Production overrides it:
`Main.kt:19-20` computes
`maxOf(15 * 60_000L, DIAL_TIMEOUT_MS + queryExchangeTimeoutMs + 30_000)`.
**Reason (quote, `Main.kt:12-17`):** "The stream is opened before the proxy
reports ready, so its lifetime has to cover the dial as well as the exchange
that follows. Leave the dial out and the cap falls short of the work it wraps
once `PM_QUERY_TIMEOUT` is large: the stream then dies under a statement that is
still legitimately running, and the caller sees a stream-closed error rather
than the timeout it actually is." **Go shape:** an injectable duration on the
service struct, defaulted to 15 min, with the same `max(...)` derivation at
boot. This is the top rung of A1's timeout ladder (A7 INV-A7-30).

#### `TABLE_DETAIL_STREAM_TIMEOUT_MS` · private const

Kotlin: `private const val TABLE_DETAIL_STREAM_TIMEOUT_MS = 60_000L`
**Contract:** lifetime cap on one `TableDetailExec` stream (60 s). **Behavior:**
hard-coded; **not** injectable, unlike its `RunExec` sibling. No test drives it.
See **F22**.

#### `COMPLETION_STATUSES` · private val

Kotlin: `private val COMPLETION_STATUSES = setOf("ok", "error", "canceled")`
**Reason (quote, lines 63-66):** "The completion-event terminal statuses the
proxy reports: a clean finish, a backend/relay error carrying partial counts, or
a canceled statement. Any other value is rejected fail-closed **so a malformed
report can't write an uninterpretable outcome into the audit trail**." **Go
shape:** a package-level set; the joined form `"ok|error|canceled"` appears
verbatim in the `INVALID_ARGUMENT` description, so the join order matters for
message parity.

#### `editorTempOverlay(channel, temps, engine, dbName): List<CatalogColumn>` · internal fn

Kotlin:

```kotlin
internal fun editorTempOverlay(
  channel: Channel, temps: List<TempColumn>, engine: Engine, dbName: String,
): List<CatalogColumn>
```

**Contract:** turn the proxy's self-reported session-temp columns into catalog
rows the decision path may read UNMASKED — after applying **both** trust gates.
Extracted out of `decide` specifically so the gates are unit-testable without a
DB or a gRPC server.

**Behavior:**

1. `channel != Channel.EDITOR` ⇒ `emptyList()`.
2. `temps.isEmpty()` ⇒ `emptyList()`.
3. `catalogName = engine.catalogName(dbName)` (A5: MySQL pins `"def"`, Postgres
   uses the db name).
4. Keep only entries where `schema.startsWith("pg_temp")` — a plain,
   **case-sensitive** prefix test, not `pg_temp_<N>`.
5. Map each survivor to
   `CatalogColumn(catalog, schema = t.schema, table = t.table, column = t.column, dataType = t.sqlType, sqlType = t.sqlType, ordinal = t.ordinal, nullable = true, isTemp = true)`.
   Note `dataType` **and** `sqlType` both take the proxy's `sql_type`;
   `nullable` is hard-coded `true`; `classification` is left at its `null`
   default (a temp is unclassified by construction).

🔒 **INV-A10-16 — the temp overlay has TWO independent trust gates and both are
load-bearing.** The source states why (lines 68-82): "an overlay column is read
without a Cedar grant **and** skips the uncovered-scan gate, so it is
load-bearing that only genuine session temps reach it."

- **Channel gate** — "temps are only legitimate on the `Channel.EDITOR` path (a
  persistent editor session holds the backend connection whose temps these are).
  A wire / approver-exec decision carrying `temp_columns` is a buggy or
  compromised proxy: **drop them all** rather than grant the unmask on a channel
  that was never analyzed for it (the native-wire/one-shot proxies never send
  temps)."
- **`pg_temp*` filter** — "a temp overlay entry names a schema read unmasked, so
  it must be an actual session-temp namespace. Drop anything whose schema isn't
  `pg_temp*`, so a proxy cannot unmask a real table (e.g. `public.users`) by
  mislabeling it a temp. **Postgres reserves the `pg_` prefix, so no real schema
  is ever named `pg_temp*`.**"

**INV-A10-7 — the catalog segment must match the analyzer namespace's** (PG: the
database name; MySQL: `"def"`) "so a temp key aligns with the base-catalog
keys." A mismatched catalog segment silently makes every temp key un-matchable.
(`GrpcTempOverlayTest` case 5's comment notes the MySQL arm is defensive-only:
"MySQL never actually sends temps (they're invisible to `information_schema`),
but if it did the catalog segment must be `def`.")

⚠️ **F31 — the two `pg_temp` filters in the decide path disagree on case.** This
one is `it.schema.startsWith("pg_temp")` — **case-sensitive**
(`ControlPlaneGrpcService.kt:92`). A5's freshness gate, on the _same_ request's
`search_path`, is
`searchPath.filterNot { it.startsWith("pg_temp", ignoreCase = true) }`
(`ConnectionDecide.kt:43`) — **case-INsensitive**. So a `PG_TEMP_9` entry is
excluded from the fragments the freshness gate requires while any `PG_TEMP_9`
temp columns are dropped by the overlay. Postgres folds unquoted identifiers to
lower case, so a _correct_ proxy never produces this; a compromised one sends
arbitrary strings. The divergence resolves fail-closed today (no fragment and no
overlay row ⇒ the name cannot resolve ⇒ DENY), but a Go port must pick one
casing rule **deliberately** for both call sites rather than transliterate the
mismatch. No test covers either casing.

**Deps:** `Engine.catalogName` (A5 `Engines.kt:50`), `CatalogColumn` (A5
`Datasources.kt:85`), `Channel` (A6 `Query.kt:114`). **Go shape:** a pure
function, no I/O. Keep it a separate exported-for-test function — the entire
`GrpcTempOverlayTest` suite (5 cases) targets it directly and is the cheapest
possible signal on the two gates.

#### `class ControlPlaneGrpcService(core, runStreamTimeoutMs = RUN_STREAM_TIMEOUT_MS)`

Kotlin:
`class ControlPlaneGrpcService(private val core: ControlPlaneCore, private val runStreamTimeoutMs: Long = RUN_STREAM_TIMEOUT_MS) : ControlPlaneGrpcKt.ControlPlaneCoroutineImplBase()`

**Contract:** all ten handlers, backed by the shared `ControlPlaneCore`.
**Reason (quote, lines 102-111):** "backed by the shared `ControlPlaneCore` —
the **SAME** store/authz graph the HTTP surface uses, so policy edits made
through the web API are seen by these decisions." `GrpcDecideHandlerDbTest` case
10 is the regression test for exactly this and explains the failure mode:
"Because `CedarEngine`'s cache invalidates only on the shared
`CedarPolicyStore`'s in-memory `stateVersion`, a second/divergent graph would
leave this green while the gRPC engine served a stale `PolicySet`." **Go
shape:** a struct holding the core plus the run-stream timeout, satisfying the
generated `pb.ControlPlaneServer` interface. It must embed
`pb.UnimplementedControlPlaneServer` **only if** you intend
forward-compatibility with new RPCs; embedding it silently turns a _forgotten_
handler into `Unimplemented` at runtime rather than a compile error, so prefer
an explicit assertion that every RPC is implemented.

---

#### `validateToken(request: ValidateTokenRequest): WireIdentity` · override suspend

**Contract:** the once-per-session wire handshake. "May this session open?" On
success it mints the connection state and returns the identity plus the on-open
refetch plan.

**Behavior (order is observable):**

1. `core.tokenStore.validate(request.token)` — the **write** path (stamps
   `last_used_at`) restricted to kinds `SESSION|USER` (`Tokens.kt:176-199`).
   Null ⇒ `UNAUTHENTICATED "invalid, expired, or revoked wire token"`.
2. `core.userGroupStore.isDeactivated(id.principal)` ⇒
   `UNAUTHENTICATED "principal is deprovisioned"`.
3. `request.datasourceName.isBlank()` ⇒
   `INVALID_ARGUMENT "datasource_name must not be blank"`. ⚠️ **This runs
   third**, so a bad token _and_ a blank name reports `UNAUTHENTICATED` (F26).
4. `core.datasourceStore.getByName(name)` ⇒ null →
   `NOT_FOUND "unknown datasource '<name>'"`.
5. `core.connectionCatalog.open(Binding(ds.name, id.principal, id.kind), ds.defaultSchemas + ds.engine.systemSchemas, adoptHeldContent = ds.engine.catalogIsConnectionIndependent)`.
6. Respond
   `wireIdentity { principal; roles.addAll(id.roles); connectionId = opened.connectionId; onOpen.addAll(opened.onOpen.map { proxyCommand { refetch = it } }) }`.

🔒 **INV-A10-21 — an ephemeral (EDITOR / APPROVER_EXEC) token must never pass
the wire-session handshake.** Enforced in `TokenStore.validate`'s
`kind IN ('SESSION','USER')` predicate, not here. Reason quoted
(`Tokens.kt:178-181`): "A transient editor/approver-exec token authorizes
exactly ONE proxy-mediated query via the per-query `resolve` path — it must NOT
pass the wire-session handshake, so a leaked ephemeral token can't open a native
MySQL/PG session as that principal within its short TTL."
`GrpcDecideHandlerDbTest` case 13 pins it — ⚠️ **correction:** it asserts _three
of the four_ `TokenKind`s (`validate(EDITOR)` null, `validate(APPROVER_EXEC)`
null, `validate(USER)` non-null); **`SESSION` is not exercised**. It also calls
`core.tokenStore.validate(...)` **directly**, not the RPC, so it pins the store
predicate rather than the gRPC handler — consistent with the invariant living in
A4, but it means no test proves `ValidateToken` _the RPC_ rejects an ephemeral
token.

**INV-A10-8 — the handshake's search-path seed is
`defaultSchemas + systemSchemas` only.** No `search_path` crosses the wire on
`ValidateToken` (the proxy has not opened a client session yet). Note the
asymmetry with `Decide`'s recovery path, which seeds
`request.searchPathList + defaultSchemas + systemSchemas`.

**Deps:** A4 `TokenStore.validate`, A3 `UserGroupStore.isDeactivated`, A5
`DatasourceStore.getByName` / `ConnectionCatalogRegistry.open` /
`Engine.systemSchemas` / `Engine.catalogIsConnectionIndependent`. **Go shape:**
straight-line handler returning `(*pb.WireIdentity, error)` with
`status.Error(codes.X, msg)` for each guard. The `roles` field must be populated
from the token row, not re-resolved (F25 explains why that is worth pinning
rather than "fixing").

---

#### `decide(request: DecisionRequest): WireDecision` · override suspend

**Contract:** the per-statement enforcement decision. Never trusts a
proxy-asserted principal, channel, or role set; every one of those is derived
server-side from the raw token.

**Behavior — the full ordered rule list:**

1. `core.tokenStore.resolve(request.token)` ⇒ null →
   `UNAUTHENTICATED "invalid, expired, or revoked wire token"`.
2. `core.userGroupStore.isDeactivated(id.principal)` ⇒
   `UNAUTHENTICATED "principal is deprovisioned"`.
3. `core.datasourceStore.getByName(request.datasourceName)` ⇒ null →
   `NOT_FOUND "unknown datasource '<name>'"`.
4. `clientAddr = request.clientAddr.ifBlank { null }` — a blank becomes null, so
   a proxy that sends `""` is not mistaken for having observed an address.
5. `kind = TokenKind.fromWire(id.kind)` ⇒ null →
   `UNAUTHENTICATED "token kind is not valid for query decisions"`. (`fromWire`
   returns null on an unrecognized value rather than throwing, so callers fail
   closed — `Tokens.kt:26-29`.)
6. `assumeRoles = if (kind == EDITOR || kind == APPROVER_EXEC) id.roles.toSet().takeIf { it.isNotEmpty() } else null`.
7. `channel = when (kind) { SESSION, USER -> WIRE; EDITOR -> EDITOR; APPROVER_EXEC -> if (assumeRoles != null) WORKFLOW_EXECUTOR else EDITOR }`.
8. `tempColumns = editorTempOverlay(channel, request.tempColumnsList, ds.engine, ds.dbName)`.
9. `httpIp = if (kind == EDITOR || kind == APPROVER_EXEC) core.runRequesterIps.get(tokenHash(request.token)) else null`.
10. `request.connectionId.size() != 16` ⇒
    `INVALID_ARGUMENT "connection_id must be exactly 16 bytes"`. ⚠️ This is rule
    **ten**, after three DB round-trips and two derivations (F27).
11. `binding = Binding(ds.name, id.principal, id.kind)`.
12. `connection = core.connectionCatalog.find(request.connectionId)`. If
    **null**:
    `core.connectionCatalog.recover(request.connectionId, binding, request.searchPathList + ds.defaultSchemas + ds.engine.systemSchemas, adoptHeldContent = ds.engine.catalogIsConnectionIndependent)`
    ⇒ null → `ABORTED "connection recovery raced with another request"`;
    otherwise **return** `beforeDecideDecision(recovered.onOpen)` — no verdict,
    no audit row.
13. `connection.binding != binding` ⇒
    `FAILED_PRECONDITION "connection binding mismatch"`.
14. `decideConnection(core, connectionId, id.principal, ds, request.sql, request.searchPathList, clientAddr, request.mysqlAnsiQuotes, channel, assumeRoles, tempColumns, httpRequesterIp = httpIp)`
    (A5 `ConnectionDecide.kt`). Null ⇒
    `NOT_FOUND "connection disappeared during Decide"`. **Note the positional
    10th argument:** `assumeRoles` lands on `decideConnection`'s
    `providedRoles`.
15. `EnforcementOutcome.BeforeDecide` ⇒
    `beforeDecideDecision(outcome.commands)`. `EnforcementOutcome.Verdict` ⇒
    `outcome.ctx.toWireDecision(outcome.decisionId, outcome.generation, outcome.afterStatement)`.

🔒 **INV-A10-9 — the RAW token is re-validated on every query.** Quote (lines
145-150): "Re-validate the RAW token on every query so a mid-session revocation
takes effect **on the next query, not at session end** — the proxy-asserted
principal is never trusted for the life of the connection."
`GrpcDecideHandlerDbTest` cases 5 and 9 pin revocation and expiry.

🔒 **INV-A10-10 — `Decide` uses `resolve`, not `validate`.** Quote: "Read-only
(resolve, not validate) so the per-query check doesn't serialize concurrent
queries on the token row's `last_used_at` write." Two different SQL statements,
two different accepted kind sets. A port that unifies them either serializes the
hot path or opens INV-A10-21's hole.

🔒 **INV-A10-11 — authN failure is `UNAUTHENTICATED`, never a DENY verdict.**
Quote: "An authN failure (bad/revoked/expired token, deprovisioned principal) is
UNAUTHENTICATED **so the proxy can tear the session down**, distinct from an
authZ policy DENY." The deactivation check is explicitly duplicated here even
though `decideQuery` has its own deactivation gate, because that one produces a
DENY — and a DENY leaves the session open. `GrpcDecideHandlerDbTest` case 6's
own comment says so.

🔒 **INV-A10-12 — channel and assume-roles derive from the token KIND, which
only the CP can set.** Quote (lines 164-168): "Derive the channel and
assume-role set from the resolved token's KIND (the control-plane minted it;
**the proxy can't assert it**). A native-wire token (SESSION/USER) is
`channel=wire`, and its roles are ALWAYS resolved server-side (never taken from
the token). The ephemeral editor/approver-exec kinds map to
editor/workflow-executor; **only they** may carry a CP-computed assume-role set
(execute-under-R)."

🔒 **INV-A10-13 — a native-wire token's on-token roles are ignored entirely.**
This is the same fact from the other side, and it is the invariant
`GrpcDecideHandlerDbTest` case 11 exists for: a `USER` token issued _carrying_
role `elevated` is still denied, while an `APPROVER_EXEC` token carrying the
same role is allowed. Cross-ref A7 INV-A7-1: `assumeRoles` is R alone and
reaches `decideQuery` as `providedRoles`, which **replaces** server role
resolution (A6 step 6).

🔒 **INV-A10-14 — a no-R `APPROVER_EXEC` decides at EDITOR, never at
WORKFLOW_EXECUTOR.** Quote (lines 179-182): "workflow-executor (where a policy
may unmask R at execute) is reachable **ONLY** by an approver-exec token that
actually carries an assume-role set (execute-under-R). A no-R approver-exec
(approver runs as themselves, no elevation) decides at the editor channel with
NORMAL enforcement." `GrpcDecideHandlerDbTest` case 12 pins "the no-R escalation
fix" — this is a bug that was already fixed once. A port that maps
`APPROVER_EXEC → WORKFLOW_EXECUTOR` unconditionally reintroduces it.

🔒 **INV-A10-15 — `search_path` crosses verbatim; an empty list is NOT collapsed
to the datasource default.** Quote (lines 158-162): "The proxy always sends its
live namespace. Pass `search_path` through verbatim — do **NOT** collapse an
empty list to the datasource default: treating 'absent = default' would be
**fail-OPEN** here, since a failed/empty namespace probe would authorize against
the stored default (possibly the wrong schema). An empty namespace reaches
`decideQuery` as-is and resolves fail-closed (unqualified references can't
resolve → DENY)."

🔒 **INV-A10-17 — the requester-IP registry read is gated strictly on token
KIND, never on "an entry exists".** Quote (lines 187-190): "Gated strictly on
KIND (never just 'an entry exists') so a native-wire (SESSION/USER) token can
**never** pick up a registry entry — the registry is only ever populated for
EDITOR/APPROVER_EXEC tokens, but this keeps the read itself honest about that
intent." `GrpcDecideHandlerDbTest` case 16 plants an entry under a `USER`
token's hash and asserts it is ignored. Cross-ref A7 INV-A7-33
(`RequesterIpRegistry`'s `put`/`set` null semantics) and A12 (the HTTP-side
resolution that produced the IP). The registry is keyed by **token SHA-256
hash**, never the raw token.

**INV-A10-44 — the channel selects the `requester_ip` SOURCE; it is not a
nullable fallback.** The selection itself lives in A5 `ConnectionDecide.kt`
(`WIRE -> parseRequesterIp(clientAddr); else -> httpRequesterIp`), but this
handler is what makes it real by passing exactly one of the two.
`GrpcDecideHandlerDbTest` cases 17 and 18 are a deliberate complementary pair:
an EDITOR token with an in-range `client_addr` and **no** registry entry is
DENIED (no borrowing), while a USER token with the same `client_addr` is
allowed. Port them together or the pair proves nothing.

🔒 **INV-A10-18 — `connection_id` must be exactly 16 bytes.** Both directions
enforce it: the CP here, and the Go client on receive (`client.go:148-150`,
`client.go:429`).

🔒 **INV-A10-19 — a live connection's binding must equal
`(datasource, principal, kind)`.** A live id presented with a different
principal's token is `FAILED_PRECONDITION`, not a decision.
`GrpcPerConnectionCatalogDbTest` case 6 pins the cross-principal case.

⚠️ **INV-A10-20 — an unknown `connection_id` is RECOVERED, not rejected.** This
is deliberate (it is how a control-plane restart re-learns live proxy
connections) and it is a **documented defect**: `GrpcPerConnectionCatalogDbTest`
carries a `@Disabled` test named _"post-close Decide reuse is rejected"_ with
the reason string "closed/forged connection_id is recovered by Decide — no
tombstone/mint-evidence", paired with a loud characterization test _"current
post-close Decide behavior recovers the closed id"_. Recovery does re-bind to
`(ds.name, principal, kind)` from the freshly-resolved token, so the blast
radius is bounded by the proxy's own trust boundary — but a Go port must
reproduce the behaviour **and** carry the `@Disabled` pair forward, or the
defect quietly loses its record. See **F29**.

**Deps:** A4 `TokenStore.resolve`, A3 `UserGroupStore.isDeactivated`, A5
`DatasourceStore.getByName` / `ConnectionCatalogRegistry.find|recover` /
`decideConnection`, A7 `RequesterIpRegistry.get` + `tokenHash`, A6 `Channel`, A4
`TokenKind.fromWire`, this file's `editorTempOverlay`, `GrpcMappers`. **Go
shape:** one function, fifteen sequential steps, `(*pb.WireDecision, error)`.

⚠️ **Correction — the guard order is almost entirely UNPINNED, and the previous
claim here was wrong.** It said cases 6 and 7 "assert specific codes that only
hold at this ordering". They do not: both build their request with
`connectionId = open(<token>)`, i.e. a well-formed 16-byte id
(`GrpcDecideHandlerDbTest.kt:160, 168`), and case 7's datasource name is the
only thing wrong with it. What is actually pinned:

- **case 6 pins one ordering only** — the handler's own deactivation gate must
  run _before_ `decideConnection`. Its comment: "Must be UNAUTHENTICATED (authN
  teardown), NOT the DENY that `decideQuery`'s internal deactivation gate would
  otherwise produce — that split is the point of the explicit check." That is
  INV-A10-11, and it is a real constraint.
- **nothing pins** the relative position of the datasource lookup, the 16-byte
  `connection_id` check, the temp-overlay build, or the requester-IP read. Every
  `decide` call in every suite in the area supplies a valid 16-byte id (7 of 7
  builders in `GrpcPerConnectionCatalogDbTest`, all of
  `GrpcDecideHandlerDbTest`), so **F27's hoist of the length check to rule 1
  breaks no test**. The two statements are not in tension once this is stated
  plainly.
- 🔒 **new coverage gap** —
  `INVALID_ARGUMENT "connection_id must be exactly 16 bytes"` is asserted by
  **no test anywhere**.
  `grep -rn INVALID_ARGUMENT control-plane/src/test/.../grpc/` returns only the
  two `reportCompletion` cases and the two `register` cases. So INV-A10-18's
  control-plane half is entirely unpinned; only the Go client's receive-side
  length checks are exercised. Add a case before porting.

---

#### `reportCompletion(request: CompletionReport): Empty` · override suspend

**Contract:** record the post-relay completion as a chained audit event, and
move a correlated **native-wire** task to its terminal state. "This handler
records the proxy's outcome; **it never re-decides enforcement**."

**Behavior:**

1. `request.decisionId == 0L` ⇒
   `INVALID_ARGUMENT "decision_id must reference a recorded decision"`.
2. `status !in COMPLETION_STATUSES` ⇒
   `INVALID_ARGUMENT "status must be one of " + COMPLETION_STATUSES.joinToString("|")`
   → literally `"status must be one of ok|error|canceled"`.
3. `core.auditStore.get(request.decisionId)` ⇒ null →
   `NOT_FOUND "unknown decision_id <id>"`.
4. Build
   `AuditEvent(principal = decision.principal, datasource = decision.datasource, statement = decision.statement, decision = decision.decision, channel = decision.channel, kind = "completion", decisionId = request.decisionId, rowsReturned, bytesReturned, outcome = status, latencyMs = request.durationMs)`.
   ⚠️ **Exactly five** identity fields are mirrored. `roles`, `clientAddr`,
   `effectiveNamespace`, `maskedColumns`, `piiTouched`, `contextTags`,
   `failedStage`, `detail` are all left at their defaults — see **F24**.
5. `core.dataSource.inTx { conn -> ... }`: a.
   `core.auditStore.insert(conn, completionEvent)`. b.
   `core.accessStore.wireTaskIdForDecision(request.decisionId, conn)?.let { taskId -> if    (core.accessStore.claimExecution(taskId, conn)) { if (status == "ok")    check(markExecuted(taskId, conn)) else check(markFailed(taskId, conn)) } }`.
   The two `check(...)` messages are `"wire task $taskId left EXECUTING"`.
6. Return `Empty.getDefaultInstance()`.

🔒 **INV-A10-22 — both request guards run before any DB work.** A malformed
report must not be able to write an uninterpretable `outcome` into the audit
trail (the `COMPLETION_STATUSES` comment).

🔒 **INV-A10-23 — the completion event and the task transition commit in ONE
transaction.** Quote (lines 230-232): the task moves "APPROVED → EXECUTED on
`ok`, or APPROVED → FAILED on `error`/`canceled`, **in the same transaction as
the completion event**." So an audit-insert failure rolls the task transition
back and vice versa.

**INV-A10-24 — the task transition is an idempotent compare-and-set; duplicate
reports still append completion events.** Quote (lines 236-239): "Duplicate
reports **still append completion events as before**; the task transition is an
idempotent compare-and-set and silently no-ops after the first terminal report."
`claimExecution` is the CAS. `GrpcReportCompletionHandlerDbTest` case 3 and
`WireTaskDecideDbTest` case 6 pin the two halves.

🔒 **INV-A10-25 — a completion for a decision with no wire task is audit-only.**
Quote: "Decisions without a WIRE task remain audit-only, so editor and workflow
execution lifecycles are untouched." `GrpcReportCompletionHandlerDbTest` case 2
asserts `access_request` row count is unchanged.

**INV-A10-45 — the completion row must be self-describing.** Quote (lines
235-238): "The completion mirrors the referenced decision's identity fields so
the row is self-describing for the audit monitor and satisfies the audit
schema." That claim is what F24 questions.

**Deps:** A8 `AuditStore.get|insert`, A7
`AccessStore.wireTaskIdForDecision|claimExecution|markExecuted|markFailed`, A1
`DataSource.inTx`. **Go shape:** `(*emptypb.Empty, error)`. The two `check(...)`
calls are Kotlin `IllegalStateException`s. _Unverified:_ they are expected to
surface as gRPC `UNKNOWN` because this service installs no exception mapper — no
test drives either `check`, so the status code is inferred from grpc-kotlin's
default, not observed. What **is** certain from the source is that they
propagate out of `inTx` and therefore abort the transaction. In Go they become
`return nil, fmt.Errorf(...)` from inside the tx closure so the rollback
happens; do **not** map them to a nice status, because an unclaimable/unmarkable
task is an invariant violation, not a client error.

---

#### `pushSchemaFragment(request: SchemaFragmentPush): SchemaFragmentAck` · override suspend

**Behavior:**

1. `core.connectionCatalog.find(request.connectionId)` ⇒ null →
   `NOT_FOUND "unknown connection_id"`.
2. `request.datasourceName != connection.binding.datasourceName` ⇒
   `FAILED_PRECONDITION "datasource binding mismatch"`.
3. `core.datasourceStore.getByName(request.datasourceName)` ⇒ null →
   `NOT_FOUND "unknown datasource '<name>'"`.
4. `core.connectionCatalog.applyPush(request, ds)`: `Applied(generation)` ⇒
   `schemaFragmentAck { generation }`; `Rejected(code, description)` ⇒
   `StatusException(Status.fromCode(code).withDescription(description))`.

**INV-A10-46 — connection lookup precedes the datasource checks.** A forged
`connection_id` is `NOT_FOUND` regardless of what `datasource_name` says; only a
**live** id with a mismatched name reaches `FAILED_PRECONDITION`.
`GrpcPerConnectionCatalogDbTest` case 2 asserts both in one test.

**INV-A10-47 — A5 owns the rejection reason AND its status code.**
`CatalogMutationResult.Rejected` carries a `Status.Code`
(`ConnectionCatalog.kt:97`), so the generation/hash/unchanged validation lives
entirely in A5 and this handler is a pass-through.
`GrpcPerConnectionCatalogDbTest` case 3 exercises two of those A5 rejections
(`FAILED_PRECONDITION` for an old `backend_generation`, and for an
`unchanged = true` push whose hash does not match). **Go shape:** the `Rejected`
type must keep carrying a gRPC code, or the mapping has to be re-derived at this
boundary — which is exactly the duplication A5's design avoids.

#### `closeConnection(request: CloseConnectionRequest): CloseConnectionResponse` · override suspend

**Behavior:**
`core.connectionCatalog.close(request.connectionId, request.datasourceName)`:
`Applied` ⇒ `closeConnectionResponse { }`; `Rejected` ⇒ status as above. No
other guard. Note the `Applied.generation` is **discarded** on this path.
`GrpcPerConnectionCatalogDbTest` cases 2 and 7 cover a forged id and a
post-close late push.

---

#### `register(request: RegisterRequest): RegisterResponse` · override suspend

**Contract:** idempotent upsert by name. The proxy declares its own identity on
boot; the CP never dials the target and holds no service credential for it.

**Behavior:**

1. `request.name.isBlank()` ⇒
   `INVALID_ARGUMENT "datasource name must not be blank"`.
2. `engine = when (request.engine) { ENGINE_UNSPECIFIED, UNRECOGNIZED -> throw INVALID_ARGUMENT "engine must be POSTGRES or MYSQL"; else -> request.engine }`.
3. `certChain = if (request.hasAdvertiseCertChain()) request.advertiseCertChain else null`.
4. `if (!certChain.isNullOrBlank()) inspectTrustChain(certChain)?.let { log.warn(...) }`
   — the warning text is
   `"datasource '{}' advertised a wire cert chain that may not verify: {} — serving it anyway; clients will report their own verification errors"`.
   Note a PRESENT-but-**blank** chain skips inspection but is still forwarded
   (and therefore clears the stored chain).
5. `priorDbName = core.datasourceStore.getByName(request.name)?.dbName`.
6. `core.datasourceStore.register(name, engine, host, port, dbName, tags = request.tagsList, advertiseAddr, advertiseCertChain = certChain, advertiseWireTls)`,
   catching `DatasourceEngineConflictException` ⇒ `FAILED_PRECONDITION` with
   `e.message`.
7. `if (priorDbName != null && priorDbName != ds.dbName) { core.connectionCatalog.invalidateDatasource(ds.name); log.info("datasource '{}' retargeted {} -> {}: dropped {} enforcement schema(s)", ...) }`.
8. Respond `registerResponse { name = ds.name }`.

🔒 **INV-A10-26 — the engine check is INVERTED on purpose.** Quote (lines
309-313): "Pass the proto `Engine` through as the domain type, rejecting only
the invalid sentinels (the proto3 zero value and the generated unrecognized
value) — an unset/garbage engine must not silently default to postgres and
mis-drive introspection/dialect resolution. **Inverting the check this way lets
a future proto engine pass through untouched instead of being rejected by an
enumeration of the currently-known ones.**" A Go port that writes
`switch { case POSTGRES, MYSQL: ok; default: reject }` inverts the intent. ⚠️
Go's generated enums have no `UNRECOGNIZED` constant — an unknown wire value
arrives as the raw `Engine(n)`. So the Go condition is
`e == ENGINE_UNSPECIFIED || Engine_name[int32(e)] == ""`, or an explicit
`e.Enum().Descriptor().Values().ByNumber(...) == nil` check. Getting this wrong
silently accepts garbage.

**INV-A10-27 — `advertise_cert_chain` presence is three-valued and collapsing it
breaks a real deployment.** Quote (lines 330-332): "Explicit presence is
load-bearing: ABSENT means 'no opinion, keep what is stored' (a transient cert
read on the proxy), while PRESENT-but-empty means 'publish nothing' and clears
it. **Collapsing the two would either drop a chain on every hiccup or strand
clients on roots the proxy no longer serves.**" Three tests pin the three
states: `GrpcRegistrationHandlerDbTest` 2 (blank re-register preserves), 3 (TLS
off clears), 4 (TLS on, no chain).

🔒 **INV-A10-28 — a questionable chain is REPORTED, never refused.** Quote
(lines 320-328): "The advertised chain is inspected, **never refused**. Whether
a chain is usable is the CLIENT's verification to make… Rejecting at
registration costs far more than it buys: the datasource never gets created at
all, so no catalog is pushed and **every decision fails closed — a total outage
in place of one client's TLS error.** … This is also the honest boundary: the
registering proxy is authenticated by the same shared secret either way, and it
chooses `advertise_addr` and the chain together, so a compromised registrar is
not stopped by the control plane second-guessing the material."

🔒 **INV-A10-29 — a `db_name` retarget invalidates the held enforcement
catalog.** Quote (lines 361-363): "The catalog push that follows registration
**cannot repair this**: it only confirms content it agrees with, and a retarget
is precisely the case where it disagrees. So the held structure would survive,
describing a database that is no longer there, and the next connection would
adopt it." `GrpcRegistrationHandlerDbTest` case 19 pins the store-side half;
case 18 pins that a **same**-target re-register must NOT wipe it.

**INV-A10-48 — engine is immutable at register, and rejection touches nothing.**
The guard is A5's (atomic `WHERE datasource.engine = EXCLUDED.engine` on the
conflict arm); this handler only maps the exception. Quote (lines 356-358):
"Engine is immutable at register — a mismatched re-register is a client
**precondition failure** (fix the caller's engine or delete-and-recreate), not a
server error." Three tests: `GrpcRegistrationHandlerDbTest` 7 (row untouched,
catalog retained), 8 (concurrent first-registrations), 9 (a cross-writer race
that never takes register's name lock).

**Deps:** A5 `DatasourceStore.getByName|register`, A5
`ConnectionCatalogRegistry.invalidateDatasource`, this file's
`inspectTrustChain`.

---

#### `pushCatalog(request: CatalogRequest): CatalogResponse` · override suspend

**Behavior:**

1. `core.datasourceStore.getByName(request.datasourceName)` ⇒ null →
   `NOT_FOUND "unknown datasource '<name>' — Register first"` (em dash,
   verbatim).
2. `pushedColumns = request.columnsList.map { DatasourceStore.PushedColumn(schema, table, column, dataType, ordinal, nullable) }`.
3. `mysqlLowerCaseTableNames = if (request.hasMysqlLowerCaseTableNames()) request.mysqlLowerCaseTableNames else null`.
4. `stored = core.datasourceStore.storePushedCatalog(id = ds.id, defaultSchemas = request.defaultSchemasList, mysqlLowerCaseTableNames, engineVersion = request.engineVersion, columns = pushedColumns)`.
5. `confirmed = core.connectionCatalog.recordAmbientMeasurement(ds.name, pushedColumns.groupBy({ it.schema }) { FragmentColumn(...) })`;
   if non-empty, `log.debug`.
6. `log.info("datasource '{}': {}", ds.name, core.systemClassification.describeManifestFor(ds.engine, request.engineVersion))`.
7. Respond `catalogResponse { columns = stored }`.

🔒 **INV-A10-30 — `PushCatalog` never implicitly creates a datasource.** Quote
(lines 375-376): "The proxy must Register (which creates/upserts the row) before
it can push a catalog for it; an unknown name is a **fail-closed NOT_FOUND,
never an implicit create here**."

**INV-A10-31 — the push doubles as an ambient re-measurement of the ENFORCEMENT
catalog, and the staleness ceiling depends on it.** Quote (lines 393-396): "This
push is a fresh whole-catalog read of the backend, so where it agrees with
content the enforcement pool already holds it **re-measures** that content — the
ambient refresh keeps held fragments verified instead of only feeding the config
catalog, and a connection is not made to re-probe a schema the proxy just
confirmed." `GrpcRegistrationHandlerDbTest` case 17's own comment explains why
it asserts _measurement time moved_ rather than _freshness_: "the adopter would
look fresh anyway from the original measurement seconds earlier, so a freshness
assertion holds even with this handler unwired and proves nothing." A Go port
must keep an observable measurement timestamp or that test cannot be ported.

**INV-A10-49 — the manifest resolution is LOGGED at push time, per datasource.**
Quote (lines 406-408): "Which shipped system-classification manifest governs
THIS datasource, resolved from the version the proxy just pushed — so an
operator sees at connect time whether its system schemas are classified, on a
fallback major, or uncertified (deny-by-default). **Boot logs the available set;
this logs the hit.**"

**Deps:** A5 `DatasourceStore.getByName|storePushedCatalog`, A5
`ConnectionCatalogRegistry.recordAmbientMeasurement` + `FragmentColumn`, A5
`SystemClassificationService.describeManifestFor`.

---

#### `runExec(requests: Flow<ProxyRunMsg>): Flow<ControlRunMsg>` · override

Kotlin:
`override fun runExec(requests: Flow<ProxyRunMsg>): Flow<ControlRunMsg> = channelFlow { ... }`
**Contract:** "A proxy-dialed, single-request run stream. The first request must
claim a pending run session; every later proxy message is relayed to that
request's private inbound channel."

**Behavior:**

1. Local state: `var sessionId: String? = null`,
   `var attached: Attached? = null`.
2. `withTimeout(runStreamTimeoutMs) { requests.collect { message -> ... } }` —
   the request Flow is **collected exactly once**, "because grpc-kotlin's bidi
   request stream is single-collect."
3. First message (`attached == null`): `!message.hasSessionReady()` ⇒
   `FAILED_PRECONDITION "the first RunExec message must be RunReady"`. Else
   `sessionId = message.sessionReady.sessionId`;
   `attached = core.runChannels.attach(id, channel)` ⇒ null →
   `NOT_FOUND "unknown or already-claimed run session '<id>'"`. (`channel` here
   is `channelFlow`'s own `SendChannel<ControlRunMsg>` — the outbound side of
   this stream, handed to the registry so `RunExecService` can write down it.)
4. Every later message: `current.inbound.send(message)`.
5. After `collect` returns with `attached == null` ⇒
   `FAILED_PRECONDITION "RunExec closed before RunReady"`.
6. `catch (e: TimeoutCancellationException)` ⇒
   `DEADLINE_EXCEEDED "run stream lifetime exceeded"`.
7. `finally { attached?.inbound?.close(); sessionId?.let { core.runChannels.remove(it) } }`.

🔒 **INV-A10-32 — the first message must be the Ready arm, and a session is
claimable exactly once.** `RunChannelRegistry.attach` removes-then-completes
atomically (A7 INV-A7-32), so an unknown id and a duplicate claim are
indistinguishable by design — both are `NOT_FOUND`. Quote from A7: a
claimed-twice stream "can never share another request's token or query."
`GrpcRunExecDbTest` cases 9 and 10 pin both.

**INV-A10-33 — the request Flow is collected exactly once.** Any Go port must
likewise read the stream in one loop; grpc-go's `stream.Recv()` is naturally
single-consumer, so this constraint disappears — but the _shape_ (one goroutine
draining `Recv`, writes going out through a registry-held channel) must survive.

**INV-A10-34 — the `finally` block runs on every exit path.**
`attached?.inbound?.close()` unblocks whoever is reading the private inbound
channel; `runChannels.remove(sessionId)` is a no-op when `attach` already
removed the entry, so the failed-claim path is safe. ⚠️ `sessionId` is assigned
**before** `attach` is attempted, deliberately: if `attach` throws `NOT_FOUND`,
the `finally` still names the session. Since `attach` already removed it on the
winning path, the loser's `remove` finds nothing. Reproduce this ordering.

**INV-A10-50 — the stream timeout covers the whole stream lifetime, not one
query.** A persistent editor session runs N queries on ONE held stream
(`GrpcRunExecDbTest` case 11 is the proof: it asserts
`queriesSeen == listOf("select 1", "select 2", "select 4")` on a single stream),
so the cap bounds the session, which is why `Main.kt` sizes it from dial +
exchange + slack.

**Deps:** A7 `RunChannelRegistry.attach|remove`, A7 `Attached`. **Go shape:**
`func (s *Service) RunExec(stream pb.ControlPlane_RunExecServer) error`. Needs a
context with the run-stream deadline (`context.WithTimeout` on
`stream.Context()`), a `Recv` loop, and a `defer` performing both cleanup steps.
Map the deadline to
`status.Error(codes.DeadlineExceeded, "run stream lifetime exceeded")`
explicitly, so the wire status carries `DEADLINE_EXCEEDED` rather than whatever
a bare cancelled context surfaces as. ⚠️ **Correction:** the previous
justification cited `client.go:463` as the Go client "distinguishing the message
text". It does not. That line is
`if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded`
— a **code** check, not a text check, and it is on the **`Events`** rotation
path (`RunEventsLoop`, downgrading an expected 4-minute stream expiry from a
fault to an info log), not `RunExec`. Nothing on the Go side reads the
`"run stream lifetime exceeded"` string. So the string is for operators, and the
load-bearing part is the **code**: keep it `DEADLINE_EXCEEDED`.

#### `tableDetailExec(requests: Flow<ProxyTableDetailMsg>): Flow<ControlTableDetailMsg>` · override

Structurally identical to `runExec` with four differences:

- timeout is the hard-coded `TABLE_DETAIL_STREAM_TIMEOUT_MS` (60 s), not
  injectable (**F22**);
- registry is `core.tableDetailChannels` (A5 `TableDetailExec.kt`), state type
  `AttachedTableDetail`;
- messages: `"the first TableDetailExec message must be TableDetailReady"`,
  `"unknown or already-claimed table-detail session '<id>'"`,
  `"TableDetailExec closed before TableDetailReady"`,
  `"table-detail stream lifetime exceeded"`;
- contract note: "No query token is needed: this is metadata-only introspection"
  (`controlplane.proto:281-283`).

**Coverage:** zero direct tests in this area (see §5 gaps). It is exercised
indirectly by `TableDetailDbTest` (an A5 suite).

#### `events(request: EventsRequest): Flow<ControlEvent>` · override

**Contract:** "The proxy-initiated liveness + refresh stream. The proxy opens
this once at startup and holds it open for its lifetime; **the open stream IS
the liveness signal** (close == the proxy detached)."

**Behavior:**

1. `name = request.datasourceName`; `core.datasourceStore.getByName(name)` ⇒
   null → `NOT_FOUND "unknown datasource '<name>' — Register first"`. (No
   separate blank-name guard — `getByName("")` returns null.)
2. `core.datasourceStore.markSeen(ds.id)`.
3. `core.proxyEventsHub.register(name, channel)`.
4. `awaitClose { core.proxyEventsHub.deregister(name, channel); core.datasourceStore.markSeen(ds.id) }`.
5. Emits nothing of its own; while open it relays whatever A12's
   `ProxyEventsHub` pushes down `channel`.

🔒 **INV-A10-35 — the control-plane never dials into a proxy.** Quote (lines
516-519): "The control-plane only ever writes back down this proxy-opened pipe —
**it never dials into a proxy**." Same invariant as A12 INV-A12-12; this handler
is where the pipe is created.

**INV-A10-36 — `markSeen` is stamped on BOTH attach and detach.** Quote (lines
528-530): "Stamp last-alive on detach too — otherwise `last_seen_at` would
report when the proxy **ATTACHED**, under-reporting liveness by a whole
(possibly days-long) session. `attached()` covers 'live now'." This is not
cosmetic: the Go client rotates the stream every 4 minutes
(`eventsStreamMaxAgeDefault = 4 * time.Minute`, `client.go:54`), so in practice
the CP sees a detach-immediately-followed-by-attach on a 4-minute cadence and
`last_seen_at` tracks it. 🔒 **The rotation's REASON, which the CP side must
understand and which was missing here** (`client.go:46-53`): "HTTP/2 keepalive
proves the CONNECTION is alive, not that the stream on it still reaches a live
control plane: a load balancer that keeps a connection open toward a replaced
backend leaves the proxy holding a stream nothing will ever answer, and because
the proxy's other calls are unary they open their own connections and keep
succeeding — **so the catalog stays fresh while the control plane reports this
datasource as having no proxy attached, and every query against it is refused**.
Ending the stream on a timer makes that state self-healing and bounds it to one
period, **without needing the control plane to notice anything**." Two
consequences for the port: (a) the CP must tolerate attach/detach churn on a
4-minute cadence as _normal_, not as flapping; (b) the CP must **not** grow its
own liveness probe on the assumption the stream is authoritative — the design
deliberately puts the recovery on the client.

**Deps:** A5 `DatasourceStore.getByName|markSeen`, A12
`ProxyEventsHub.register|deregister`. **Go shape:**
`func (s *Service) Events(req *pb.EventsRequest, stream pb.ControlPlane_EventsServer) error`.
Register a buffered `chan *pb.ControlEvent`, then loop on
`select { case ev := <-ch: stream.Send(ev); case <-stream.Context().Done(): return nil }`,
with the `awaitClose` body as a `defer`. ⚠️ A12 INV-A12-14 warns that Go's
send-on-closed-channel **panics** rather than failing, so the hub's channel
needs a `done` channel or a `closed` flag; that is A12's problem but this is
where the channel is created.

---

#### `KEY_USAGE_CERT_SIGN` · private const · and `inspectTrustChain(pem: String): String?` · internal fn

Kotlin: `private const val KEY_USAGE_CERT_SIGN = 5` (line 554) ·
`internal fun inspectTrustChain(pem: String): String?` (line 556). Both are
**top-level, outside the service class** (the class closes at line 534). ⚠️
Source quirk worth not reproducing: the long KDoc that describes
`inspectTrustChain` sits at lines 537-553, i.e. immediately above
`KEY_USAGE_CERT_SIGN` — so Dokka/IDE attach it to the **const**, not the
function. It is documentation for the function by intent and by content only.
F32.

**Contract:** "Inspects a PEM certificate chain **the way a client will**,
returning `null` when it looks usable or a short reason when it does not. **This
REPORTS; it never decides.** Callers log the reason and serve the chain
regardless — the client performs the real verification and is the only party
that can act on the outcome."

**Behavior:**

1. Parse:
   `CertificateFactory.getInstance("X.509").generateCertificates(ByteArrayInputStream(pem.toByteArray(US_ASCII)))`
   under `runCatching`, filtered to `X509Certificate`. Failure ⇒
   `"is not a parseable PEM certificate chain"`.
2. `certs.isEmpty()` ⇒ `"contains no certificate"`.
3. `certs.size == 1` ⇒ `leaf.verify(leaf.publicKey)`; success ⇒ `null`
   (self-signed is its own anchor, the ordinary proxy case); failure ⇒
   `"carries one certificate and it is not self-signed, so it cannot be a trust anchor — append the issuing CA"`.
4. For `i in 0 until certs.size - 1`, with `issuer = certs[i + 1]`: a.
   `issuer.basicConstraints < 0` ⇒
   `"is not a valid chain: certificate ${i+1} is not a CA, so it    cannot issue certificate $i"`.
   b. `issuer.keyUsage?.getOrNull(KEY_USAGE_CERT_SIGN) == false` ⇒
   `"is not a valid chain: certificate    ${i+1} is not permitted to sign certificates"`.
   c. `certs[i].verify(issuer.publicKey)` fails ⇒
   `"is not a valid chain: certificate ${i+1} does not    issue certificate $i"`.
5. `anchor = certs.last()`; `anchor.verify(anchor.publicKey)` fails ⇒
   `"does not end in a self-signed trust anchor, so a client could not verify the leaf"`.
6. Else `null`.

**Reasons, quoted, all three load-bearing:**

- Chain shape: "The chain must actually CHAIN: the first certificate is the leaf
  a client will be presented, the last is the trust anchor, and each must be
  issued by the next. A single certificate is only valid when it is
  self-signed."
- Smuggled anchor: "A client pointed at this as `sslrootcert` / `--ssl-ca`
  **trusts EVERY certificate in it**, so an extra CA appended to a real leaf is
  worth flagging — it is not a link in the chain."
- Signature, not name: "Issuance is checked by SIGNATURE, never by name: a
  certificate naming itself or its predecessor as issuer proves nothing on its
  own."
- basicConstraints: "A signature alone is not enough: a client enforces
  `basicConstraints`, so a chain whose issuer is CA:FALSE is rejected by OpenSSL
  as 'invalid CA certificate' — accepting it here would store a chain no client
  can use, and would let a leaf that happens to hold a key be presented as an
  issuer." `TrustChainInspectionTest` case 6 adds: "Verified against openssl
  before this test was written" (error 79 at depth 1).

**Deps:** JDK `java.security.cert` only. **Called from two places:** this file's
`register`, and A5 `Datasources.kt:913` (the
`GET /api/datasources/{id}/wire-cert` download route). See **F23**.

**Go shape — three concrete divergence traps, all untested:**

1. `basicConstraints < 0` means "**the extension is absent OR CA:FALSE**";
   `>= 0` is the pathLen (or `Int.MAX_VALUE` for CA:TRUE with no constraint).
   Go's equivalent is `!cert.IsCA`, **not** `cert.MaxPathLen < 0` (which means
   something else entirely).
2. `issuer.keyUsage?.getOrNull(5) == false` fires **only when the KeyUsage
   extension is PRESENT and bit 5 is clear**. A CA with **no** KeyUsage
   extension has `keyUsage == null`, so `null == false` is `false` and the check
   is **skipped**. Go's `cert.KeyUsage` is `0` when the extension is absent, so
   the naive `cert.KeyUsage & x509.KeyUsageCertSign == 0` would **reject** a CA
   that Kotlin accepts. The Go port must consult the raw extension's presence
   (`cert.Extensions` for OID `2.5.29.15`) to match.
3. `certs[i].verify(issuer.publicKey)` is a **pure signature check**. Go's
   `certs[i].CheckSignatureFrom(issuer)` additionally enforces `IsCA` and
   `KeyUsageCertSign` and returns different errors, which would double up rules
   4a/4b and change which message is produced. The faithful call is
   `issuer.CheckSignature(certs[i].SignatureAlgorithm, certs[i].RawTBSCertificate, certs[i].Signature)`.
4. `generateCertificates` accepts a concatenated PEM bundle. Go needs a
   `pem.Decode` loop over the whole input; `pem.Decode` on `""` returns `nil`
   (no block), which must map to _some_ non-nil reason — the test only asserts
   non-null, so either `"is not a parseable PEM certificate chain"` or
   `"contains no certificate"` satisfies it. Pick one deliberately.

`(LIB)` X.509/PEM parsing and RSA/ECDSA signature verification — capability
needed; the Go standard library covers it, so no third-party choice is implied.

---

### 3.2 `GrpcMappers.kt`

#### `DecisionContext.toWireDecision(auditId, generation, afterStatement): WireDecision` · internal ext fn

Kotlin:
`internal fun DecisionContext.toWireDecision(auditId: Long, generation: Long, afterStatement: List<Refetch>): WireDecision`

**Contract:** build the `Verdict` arm from an internal `DecisionContext` (A6
`Query.kt:122`).

**Behavior:** `wireDecision { verdict = verdict { ... } }` with

1. `decision = ctx.action` — **already the proto `EnfAction`**, so it crosses
   verbatim.
2. `ctx.denyReason?.let { denyReason = it }` — left at `""` when null.
3. `masks.addAll(ctx.masks)` — **already proto `ColumnMask`**, verbatim.
4. `effectiveRoles.addAll(ctx.effectiveRoles)`.
5. `ctx.rewrittenSql?.let { rewrittenSql = it }` — left **UNSET** when null.
6. `if (auditId != 0L) decisionId = auditId` — left `0` when there is no audit
   id.
7. `unmaskablePermitted = ctx.unmaskablePermitted`.
8. `generation = generation`.
9. `afterStatement.addAll(afterStatement.map { proxyCommand { refetch = it } })`.
10. `sanitizeDiagnostics = ctx.sanitizeDiagnostics`.

**INV-A10-37 — absence is the signal, on two fields.** Quote (lines 11-16):
"Optional wire fields carry the load-bearing absence semantics: `rewritten_sql`
is left UNSET when there is no `*`-expansion rewrite (= forward the client's
original SQL), and `decision_id` is left 0 when there is no audit id."
`GrpcMappersTest` case 4 asserts `!hasRewrittenSql()` for an ALLOW with no
rewrite.

**INV-A10-51 — the action and the masks are ALREADY proto types; there is no
name/ordinal mapping.** Quote: "The action and masks are already the proto types
(EnfAction / ColumnMask), so they cross the wire verbatim — **no name/ordinal
mapping**." This is why **INV-A10-53**'s ordinal hazard never materializes in
the current code: `DecisionContext.action` _is_
`com.ridi.oss.proxymonster.grpc.EnfAction` (`Query.kt:25` imports it;
`Query.kt:123`). A Go port inherits this for free (generated types all the way
down) — but if it introduces a domain enum, the proto's warning applies again:
**map by NAME**. (⚠️ Earlier revisions of this doc cited "INV-A10-39" here and
in §4; INV-A10-39 is the empty-`if_hash_differs` invariant below. The enum
invariant is INV-A10-53, §1.3.)

🔒 **INV-A10-52 — `ColumnMask.ordinal`'s explicit presence must survive the
mapper untouched.** `masks.addAll(ctx.masks)` copies the proto objects, so an
absent ordinal stays absent all the way to the proxy, which fails closed on it
(`BindMasks`). Quote from `controlplane.proto:211-214`: "Without it, proto3's
implicit-zero default would silently bind a malformed/omitted mask to result
column 0 — **masking the wrong column and leaking the intended one**." The Go
client makes the same promise in the other direction: "An absent ordinal keeps
its explicit-presence nil … do **NOT** normalize it to a sentinel here"
(`client.go:211-213`). A Go control-plane that builds masks from a domain struct
with a plain `int32` ordinal reintroduces exactly this leak.

**Go shape:** a pure constructor. `optional` fields become pointer fields in
generated Go (`*string` / `*int32`), so "leave unset" is `nil` — mechanically
simpler than Kotlin's builder, but `proto.String("")` is _not_ the same as `nil`
and a helper that always wraps would break INV-A10-37.

#### `beforeDecideDecision(commands: List<Refetch>): WireDecision` · internal fn

`wireDecision { beforeDecide = beforeDecide { commands.addAll(commands.map { proxyCommand { refetch = it } }) } }`

🔒 **INV-A10-38 — `Verdict` and `BeforeDecide` are structurally exclusive, and
neither-set must fail closed.** The proto says it
(`controlplane.proto:221-225`), the mapper enforces it by construction (two
functions, one `oneof`), the Go client enforces it on receive by checking
`GetBeforeDecide()` **first** and treating a missing verdict as
`denyClosed("control plane returned no verdict")` (`client.go:195-207`).
`GrpcMappersTest` case 3 asserts `hasBeforeDecide() && !hasVerdict()`. ⚠️ The Go
client's precedence is _before_decide wins over verdict_ — so a Go server that
ever set both arms would have its verdict silently ignored. `oneof` makes that
impossible; do not replace it with two plain fields.

**INV-A10-39 — a before-decide `Refetch` may carry an empty `if_hash_differs`,**
which means "unconditional fetch (fail-safe)". `GrpcMappersTest` case 3 asserts
exactly that for a fresh `refetch { schema = "app" }`.

---

### 3.3 `GrpcServer.kt`

#### `class GrpcServer(port: Int, service: ControlPlaneGrpcKt.ControlPlaneCoroutineImplBase, secretToken: String?)`

**Contract:** boots the gRPC surface alongside the Ktor HTTP server. Lifecycle
is owned by the caller.

**Construction (all in the field initializer, so a bad config fails at
construction):**

```
NettyServerBuilder.forPort(port)
  .maxInboundMessageSize(64 * 1024 * 1024)
  .keepAliveTime(30, SECONDS)
  .keepAliveTimeout(10, SECONDS)
  .permitKeepAliveTime(15, SECONDS)
  .permitKeepAliveWithoutCalls(true)
  .addService(ServerInterceptors.intercept(service, SecretTokenInterceptor(secretToken)))
  .build()
```

**INV-A10-40 — the 64 MiB inbound limit is a functional requirement, not
tuning.** Quote (lines 29-31): "A full `PushCatalog` (every column, system
schemas included) can exceed gRPC's 4 MiB default inbound limit on a large
database — raise it so a big catalog pushes in one unary call instead of failing
and **falling into the proxy's empty-catalog fail-closed boot state**." 64 MiB
is described as "generous headroom over the 4 MiB default."

**INV-A10-41 — the four keepalive knobs are a matched pair with the client's,
and getting one wrong GOAWAYs the liveness stream.** Quote (lines 33-36):
"HTTP/2 keepalive for the long-lived, mostly-idle Events stream. The server
pings idle connections (so a dead proxy's stream closes → `awaitClose`
deregisters it, **no ghost in the liveness view**) and permits the proxy's own
30 s keepalive pings (**permit ≤ client interval, and without-calls**, or the
server would GOAWAY the idle stream for 'too_many_pings')." Verified against the
client: `keepaliveTime = 30s`, `keepaliveTimeout = 10s`,
`PermitWithoutStream: true` (`client.go:56-58, 93-97`). So
`permitKeepAliveTime = 15s ≤ 30s` holds.

**INV-A10-42 — ONE interceptor wraps the single service, so the gate runs on
every RPC.** Quote: "The secret-token gate wraps the single service so it runs
on every RPC." A per-handler check would be the failure mode; this is the choke
point.

**Typing note (quote, lines 20-22):** the constructor takes the **generated base
class**, not the concrete impl — "the server only needs 'a ControlPlane
service', which lets tests bind a probe handler without opening the production
class." `GrpcServerTest` depends on this: it binds a `CtxProbeService`.

##### `start()`

`server.start()`, then
`log.info("control-plane gRPC listening on :{} (secret-token gate {})", port, if (secretTokenConfigured) "enabled" else "OPEN — dev only")`.
`secretTokenConfigured` is captured at construction as `secretToken != null`.

🔒 **INV-A10-5 — bind failure is fatal** (= A1 INV-A1-2). `start()` does not
swallow the exception and `Main.kt` does not catch it. Quote from
`Main.kt:53-56`: "Fail-fast on purpose: a control-plane that can't bind its
required gRPC port is misconfigured — like a bad DB or a taken HTTP port — and
**must not come up serving only HTTP while the data plane is silently dead.**"

**INV-A10-43 — `start()` registers NO JVM shutdown hook as a side effect.**
Quote (lines 15-16): "Lifecycle (start/shutdown) is owned by the caller —
`[start]` does not register a JVM shutdown hook as a side effect (Main does,
matching the proxy's Main; tests drain via their own teardown)." ⚠️
**Correction:** "every DB suite in this area relies on it" was too strong —
seven of them call `server.shutdown()` in `@AfterAll`
(`GrpcDecideHandlerDbTest`, `GrpcRegistrationHandlerDbTest`,
`GrpcEventsHandlerDbTest`, `GrpcRunExecDbTest`,
`GrpcReportCompletionHandlerDbTest`, `GrpcPerConnectionCatalogDbTest`,
`EditorSessionDecideTimingDbTest`) plus `GrpcServerTest` in `@AfterTest`;
**`WireTaskDecideDbTest` starts no server at all** (it calls the service
in-process).

##### `shutdown()`

```
server.shutdown()
if (!server.awaitTermination(5, SECONDS)) { server.shutdownNow(); server.awaitTermination(5, SECONDS) }
```

**INV-A10-6 — graceful drain then FORCE-cancel, because a long-lived stream
never finishes on its own.** Quote (lines 54-57): "Graceful drain: stop
accepting new calls, then wait (bounded) for in-flight RPCs to finish. **A
long-lived Events stream never finishes on its own** (its handler awaits the
client forever), so after the grace period force-cancel remaining calls —
otherwise orderly shutdown would block indefinitely and the streams would never
deregister." A Go port using only `GracefulStop()` hangs forever; it needs
`GracefulStop` raced against a 5 s timer then `Stop()`.

##### `boundPort: Int` · val, `get() = server.port`

"The actually-bound port, valid after `[start]`. Equals `[port]` unless `[port]`
was 0 (ephemeral)." ⚠️ **Correction:** not "every test in this area" — **eight
of the twelve** suites bind port 0 and read `boundPort` (the four that do not
are the three pure-unit suites plus `WireTaskDecideDbTest`). Two suites in
**other** areas do too — A6's `EditorSubmitRouteDbTest` and A7's
`ApprovalExecuteRouteDbTest` both construct `GrpcServer(...)` and read
`boundPort`. So a Go port needs the same ephemeral-port readback
(`net.Listener.Addr()` before `Serve`) **and** must keep `GrpcServer` +
`ControlPlaneGrpcService` constructible from outside this area's package.

##### `private companion object`

`MAX_INBOUND_MESSAGE_BYTES = 64 * 1024 * 1024` · `KEEPALIVE_SECONDS = 30L` ·
`KEEPALIVE_TIMEOUT_SECONDS = 10L` · `PERMIT_KEEPALIVE_SECONDS = 15L`. Comment on
the last: "permit (15s) must be <= the proxy client's `keepAliveTime` (30s)."

**JVM-only note that disappears in Go:** "Netty is the `grpc-netty-shaded`
transport, **relocated so it can't clash with Ktor's own Netty on the
classpath**." A single-binary Go control-plane has no such conflict — but it
inherits the _reason_ the shading exists: the HTTP and gRPC surfaces are
co-hosted in one process on two ports. `(LIB)` a gRPC server implementation
exposing per-connection HTTP/2 keepalive/enforcement policy, `maxRecvMsgSize`,
unary+bidi streaming, per-call interceptors, ephemeral-port readback, and a
graceful stop distinguishable from a hard stop.

---

### 3.4 `SecretTokenInterceptor.kt`

#### `class SecretTokenInterceptor(private val expected: String?) : ServerInterceptor`

**Contract:** "Gate on the proxy's transport secret (`x-pm-secret-token`). When
an `[expected]` shared secret is configured, every call must present a
constant-time-matching token or it is closed `UNAUTHENTICATED` **before reaching
a handler, fail-closed**. When `[expected]` is null (local dev, no secret set)
the gate is open. Either way the presented token is stashed on the gRPC
`Context`."

##### `interceptCall(call, headers, next): ServerCall.Listener<ReqT>` · override

1. `presented = headers.get(WireMetadata.SECRET_TOKEN_KEY)`.
2. `if (expected != null && !constantTimeEquals(presented, expected))`:
   `call.close(Status.UNAUTHENTICATED.withDescription("missing or invalid x-pm-secret-token"), Metadata())`
   and **return a no-op listener** (`object : ServerCall.Listener<ReqT>() {}`)
   so no request message ever reaches the handler.
3. `ctx = io.grpc.Context.current().withValue(WireMetadata.SECRET_TOKEN_CTX, presented)`;
   `return Contexts.interceptCall(ctx, call, headers, next)`.

##### `constantTimeEquals(a: String?, b: String): Boolean` · private

`a == null` ⇒ `false`; else
`MessageDigest.isEqual(a.toByteArray(UTF_8), b.toByteArray(UTF_8))`.

🔒 **INV-A10-1 — the gate runs on EVERY RPC, before any handler.** Structurally
guaranteed: `GrpcServer` wraps the one service with the one interceptor. Because
it closes the call and returns a dead listener, a rejected call's request
message is never deserialized into a handler.

🔒 **INV-A10-2 — `expected == null` opens the gate, and that is a documented
dev-only state.** It is logged loudly at start (`"OPEN — dev only"`).
`GrpcServerTest` case 4 pins that the open path still reaches the handler and
propagates a **null** token — not the empty string, not a stale value. A Go port
must not "helpfully" reject empty secrets in the open configuration;
`PM_SECRET_TOKEN` unset is a supported local-dev mode (its production guard is
A1's `Config.fromEnv`).

🔒 **INV-A10-3 — the comparison is constant-time and a null presented token
never matches.** `null` is handled before any byte work, so an absent header is
a plain `false`, and a present one is compared without an early-exit on the
first differing byte. ⚠️ Java's `MessageDigest.isEqual` leaks the _length_ (it
compares lengths into the accumulator) but not the content. Go's
`crypto/subtle.ConstantTimeCompare` returns 0 immediately on a length mismatch —
the same leak, so the two are equivalent for this purpose. Do **not** use `==` /
`bytes.Equal`.

**INV-A10-4 — the presented token is propagated VERBATIM, including null.**
Quote: "so handlers can resolve a per-datasource secret later" — and the class
doc adds "never a stale or wrong value" (`GrpcServerTest`'s header comment). See
**F21**: no production handler reads it today, so this is forward plumbing whose
only current consumer is the test probe.

**Go shape:** a `grpc.UnaryServerInterceptor` **and** a
`grpc.StreamServerInterceptor` — ⚠️ Go requires **two** interceptors where
Java's `ServerInterceptor` covers both call shapes. Registering only the unary
one leaves `Events`, `RunExec`, and `TableDetailExec` **ungated**, which is the
single most dangerous mechanical mistake available in this area. The gate must
be proven on a streaming RPC, not just a unary one (today `GrpcServerTest` only
exercises `decide`, a unary RPC — see §5 gaps). Value propagation is
`context.WithValue` on the stream/unary context; for streams that means wrapping
`grpc.ServerStream` to override `Context()`.

---

## 4. Test inventory — 12 files, 3,337 LOC, **104 cases**

Counted with `grep -rhoE '@Test\b' --include='*.kt' <path> | wc -l`. Per-file
counts and the enumerated case names below **agree exactly for every one of the
twelve files** (97 in `grpc/` + 7 in `TrustChainInspectionTest.kt`). ✅
**Re-counted independently in the A10 audit.** All twelve numbers reproduce
(4·4·5·7·18·22·2·14·6·11·10·1 = 104), every enumerated case name matches a
declared `fun` one-for-one, all twelve LOC figures reproduce (sum 3,337),
`grpc/` contains exactly eleven test files and nothing uncounted, and none of
the twelve appears in another area's inventory.

⚠️ **Boundary decision, stated so it is not double-counted.**
`TrustChainInspectionTest.kt` lives in the parent package
(`.../gocp/TrustChainInspectionTest.kt`) but tests `inspectTrustChain`, which is
defined in **this area's** `grpc/ControlPlaneGrpcService.kt:556`. It is counted
**here**. A5's doc must not re-count it even though `Datasources.kt:913` is a
second caller (see **F23**).

⚠️ **Runtime executions ≠ case count.** `WireTaskDecideDbTest.kt` declares 10
`@Test` on an `abstract class WireTaskDecideDbContract`, subclassed by
`WireTaskDecideMysqlDbTest` and `WireTaskDecidePostgresDbTest` — so **20
executions from 10 declared cases**, one pass per engine. The inventory counts
10 (declarations), consistent with the repo-wide method.

| Suite                                  | LOC | Cases              | Kind                                      |
| -------------------------------------- | --- | ------------------ | ----------------------------------------- |
| `GrpcServerTest.kt`                    | 97  | 4                  | unit — real gRPC over loopback, **no DB** |
| `GrpcMappersTest.kt`                   | 92  | 4                  | unit — pure                               |
| `GrpcTempOverlayTest.kt`               | 77  | 5                  | unit — pure                               |
| `TrustChainInspectionTest.kt`          | 194 | 7                  | unit — pure                               |
| `GrpcDecideHandlerDbTest.kt`           | 409 | 18                 | **DB** + live gRPC server                 |
| `GrpcRegistrationHandlerDbTest.kt`     | 685 | 22                 | **DB** + live gRPC server                 |
| `GrpcEventsHandlerDbTest.kt`           | 86  | 2                  | **DB** + live gRPC server                 |
| `GrpcRunExecDbTest.kt`                 | 667 | 14                 | **DB** + live gRPC server + fake proxy    |
| `GrpcReportCompletionHandlerDbTest.kt` | 232 | 6                  | **DB** + live gRPC server                 |
| `GrpcPerConnectionCatalogDbTest.kt`    | 280 | 11 (2 `@Disabled`) | **DB** + live gRPC server                 |
| `WireTaskDecideDbTest.kt`              | 328 | 10 (×2 engines)    | **DB**, service called in-process         |
| `EditorSessionDecideTimingDbTest.kt`   | 190 | 1                  | **DB** + live gRPC server + fake proxy    |

The four unit suites (20 cases) need no Docker and are the cheapest first port:
they cover INV-A10-1..4, 16, 37, 38, and the whole `inspectTrustChain`
behaviour.

### `GrpcServerTest.kt` — 97 LOC, 4 cases · unit

Header comment states the two properties under test: "the gate is fail-closed
(wrong/missing secret → UNAUTHENTICATED before the handler), and it propagates
exactly the presented token into the handler Context (a null on the open-gate
path — never a stale or wrong value)."

1. 🔒 correct secret passes the gate and reaches the handler with the token
   propagated (INV-A10-1, 4)
2. 🔒 wrong secret is rejected UNAUTHENTICATED before the handler (INV-A10-1, 3)
3. 🔒 missing secret is rejected UNAUTHENTICATED when a secret is configured
   (INV-A10-3)
4. 🔒 open gate (no secret configured) reaches the handler with a null token
   context (INV-A10-2, 4)

### `GrpcMappersTest.kt` — 92 LOC, 4 cases · unit (pure)

1. MASK decision carries the proto action and every mask field and generation
2. targeted after-statement refetch maps schema and hash
3. 🔒 before-decide is structurally exclusive from verdict (INV-A10-38, 39)
4. 🔒 ALLOW with no rewrite leaves rewrittenSql absent (INV-A10-37)

### `GrpcTempOverlayTest.kt` — 77 LOC, 5 cases · unit (pure)

Header: "BOTH gates that keep a hostile/buggy proxy from turning that into an
**exfiltration primitive** are load-bearing and must be pinned."

1. an editor pg_temp column is overlaid under the pg database catalog as a temp
   (INV-A10-7)
2. 🔒 a non-pg_temp overlay entry is DROPPED — a proxy cannot mislabel a real
   table as a temp (INV-A10-16)
3. 🔒 a mixed batch keeps only the pg_temp entries (INV-A10-16)
4. 🔒 temps are dropped on every non-editor channel (INV-A10-16) — loops WIRE,
   WORKFLOW_EXECUTOR, WORKFLOW_VIEWER
5. mysql overlays under the def catalog segment (INV-A10-7)

Note case 4 does **not** cover `Channel.MCP`, the fifth enum value.

### `TrustChainInspectionTest.kt` — 194 LOC, 7 cases · unit (pure)

Header: "`inspectTrustChain` REPORTS on trust material; **it never gates.**"

1. a self-signed certificate is its own anchor
2. a leaf with its issuer is a valid chain
3. a CA-issued leaf alone is reported because nothing anchors it
4. 🔒 a smuggled trust anchor is reported — asserts **two** shapes
   (leaf+issuer+unrelated CA, and leaf+unrelated CA)
5. 🔒 a certificate that only CLAIMS to be its own issuer is reported
   (signature, not name)
6. 🔒 a chain whose issuer is not a CA is reported ("Verified against openssl
   before this test was written")
7. unparseable or empty input is reported — asserts `""`, `"not a certificate"`,
   and a bad-base64 PEM block

Fixtures are six hard-coded throwaway PEM certificates in a
`private companion object` (`SELF_SIGNED`, `CA_LEAF`, `ISSUING_CA`,
`LEAF_ISSUED_BY_A_NON_CA`, `NON_CA_ISSUER`, `FORGED_SELF_ISSUER`, at
`TrustChainInspectionTest.kt:68,89,110,130,151,172`). `SELF_SIGNED` is
**duplicated verbatim** into `GrpcRegistrationHandlerDbTest`'s companion as
`SELF_SIGNED_CHAIN` (`:50-…`) — port them into one shared test fixture.

⚠️ **Correction — the "they expire, so both suites go red after 2027-07-27"
claim was wrong.** The PEMs do carry
`notBefore 2026-07-27 / notAfter 2027-07-27`, but **nothing in this code path
checks validity dates**: `inspectTrustChain` uses
`CertificateFactory.generateCertificates` (no validity check) and
`X509Certificate.verify(publicKey)`, which verifies **the signature only** —
`checkValidity()` appears nowhere in `control-plane/src` (verified by grep).
Expiry therefore changes no assertion in either suite.

🔒 That correction turns into the **real** Go trap, which is more dangerous than
the fake one: Go's `x509.Certificate.Verify(opts)` and `x509.CertPool`-based
path building **do** enforce validity (and `opts.CurrentTime`). A Go port that
reaches for `Verify` gets a behaviour change _and_ fixture rot at once: these
chains would start being reported as unusable, and, worse, a production chain
with an expired root would begin producing a warning the Kotlin never produced.
Stay on `issuer.CheckSignature(...)` (§3.1 trap 3), which — like Kotlin's
`verify` — ignores dates. Generating certificates at test time is still the
better fixture strategy, just not for the stated reason.

### `GrpcDecideHandlerDbTest.kt` — 409 LOC, 18 cases · DB

Header: "The focus is what's NEW in the gRPC path: per-query token re-validation
(the revocation-gap fix), datasource-by-name resolution, deactivation rechecks,
and the authN-vs-authZ status split. Decision _correctness_ (ALLOW/MASK/lineage)
is exercised directly against `decideAndAudit` by `SchemaThreadingDbTest`" (an
A6 suite).

1. validateToken returns the identity for a valid token
2. 🔒 validateToken rejects an unknown token UNAUTHENTICATED
3. 🔒 validateToken rejects a revoked token UNAUTHENTICATED
4. 🔒 validateToken rejects a deactivated principal UNAUTHENTICATED
5. 🔒 decide re-validates the token per query - a token revoked mid-session is
   rejected (INV-A10-9)
6. 🔒 decide rejects a deactivated principal UNAUTHENTICATED (session teardown,
   not a policy deny) (INV-A10-11)
7. decide rejects an unknown datasource NOT_FOUND
8. decide denies an ungranted principal by default and audits the decision
9. 🔒 decide rejects an expired token UNAUTHENTICATED (INV-A10-9)
10. 🔒 an HTTP-side policy edit is seen by the gRPC decision path (A1 INV-A1-1 —
    the `ControlPlaneCore` regression test)
11. 🔒 a native-wire token cannot assert roles from the token, but an
    approver-exec token's assume-role is honored (INV-A10-12, 13; A7 INV-A7-1)
12. 🔒 a no-R approver-exec decides at the editor channel, only a with-R token
    reaches workflow-executor (INV-A10-14)
13. 🔒 an editor or approver-exec token cannot open a wire session — validate
    rejects both ephemeral kinds (INV-A10-21)
14. 🔒 an EDITOR token's registered requester_ip reaches Cedar and satisfies an
    ip-gated permit (INV-A10-17)
15. 🔒 an APPROVER_EXEC token's registered requester_ip also reaches Cedar
    (run-minted, not just openSession-minted) (INV-A10-17)
16. 🔒 a registry entry is ignored for a native-wire (USER) token — gated
    strictly on kind, never merely 'an entry exists' (INV-A10-17)
17. 🔒 an EDITOR token with no registry entry does NOT fall back to the proxy
    client_addr — requester_ip stays absent (INV-A10-44)
18. 🔒 a native-wire token DOES resolve requester_ip from client_addr (the
    WIRE-channel source) (INV-A10-44)

Cases 14–18 are the requester-IP suite and 17+18 are an explicit complementary
pair (case 18's comment: "Together the two tests prove the source is
CHANNEL-selected, not a 'editor ignores client_addr, wire always trusts it'
nullable fallback"). Port them as a group.

### `GrpcRegistrationHandlerDbTest.kt` — 685 LOC, 22 cases · DB

1. register self-creates a datasource by name with no service credential
2. register persists the advertised proxy address and cert chain and preserves
   them on a blank re-register (INV-A10-27)
3. 🔒 turning wire TLS off clears a previously advertised chain (INV-A10-27)
4. 🔒 a proxy serving TLS without publishing a chain still reports the TLS
   requirement (INV-A10-27) — its comment names the attack: "an attacker
   answering the greeting without CLIENT_SSL collects a live session token"
5. register stores a questionable chain rather than refusing the datasource
   (INV-A10-28)
6. register is idempotent by name and updates advisory fields
7. 🔒 register refuses an engine change FAILED_PRECONDITION and leaves the row
   untouched (INV-A10-48)
8. 🔒 concurrent first registrations with different engines cannot bypass the
   engine guard (INV-A10-48)
9. 🔒 a row racing into an in-flight register cannot bypass the engine guard
   (cross-writer) (INV-A10-48)
10. 🔒 admin update refuses an engine change and invalidates the catalog on a
    db_name retarget (INV-A10-29) — an **A5-side** assertion driven through this
    suite
11. re-register with empty tags preserves the existing tags
12. register accepts a free-form tag bag including both postures and custom tags
13. register rejects an unspecified engine INVALID_ARGUMENT (INV-A10-26)
14. register rejects a blank name INVALID_ARGUMENT
15. 🔒 pushCatalog for an unknown datasource is NOT_FOUND (INV-A10-30)
16. pushCatalog stores the proxy-pushed columns and default schemas
17. pushCatalog re-measures the enforcement catalog, not only the stored one
    (INV-A10-31)
18. re-register with the same target preserves the catalog and updates advisory
    fields
19. 🔒 re-register to a different schema invalidates the stale catalog
    (fail-closed) (INV-A10-29)
20. pushCatalog rolls back a mid-batch failure and keeps the prior catalog
21. pushCatalog replaces the prior catalog (delete-then-insert)
22. pushCatalog replacement preserves classification for a surviving column
    identity

Case 9 uses a **deterministic DB-lock interleaving barrier**, not a sleep: a
helper `awaitRegisterParkedOnUpsert()` polls `pg_stat_activity` for a backend in
this database with `wait_event_type = 'Lock'` whose
`query ILIKE '%insert into datasource%on conflict%'`. That helper is
Postgres-specific and will need a Go equivalent; without it the test is
timing-dependent and worthless.

### `GrpcEventsHandlerDbTest.kt` — 86 LOC, 2 cases · DB

1. an open events stream marks attached, stamps last_seen_at, and relays a
   RefreshCatalog (INV-A10-35, 36) — also asserts `requestRefresh` returns 1
   attached then 0 after detach
2. events for an unregistered datasource is NOT_FOUND

Uses `.first()` on the stream, which "collects exactly one event then cancels
the stream (→ server `awaitClose` → deregister)" — so cancellation-driven
deregistration is covered.

### `GrpcRunExecDbTest.kt` — 667 LOC, 14 cases · DB

"DB-backed end-to-end coverage for the control-plane half of the proxy-dialed
editor channel." The `exchange(...)` helper builds a fake proxy that opens
`Events`, awaits the `OpenRunChannel` nudge, dials `RunExec`, and plays scripted
`ProxyRunMsg`s — plus it asserts, on every call, the ephemeral token's liveness,
its absence from the user-visible token list, and the `runRequesterIps` entry
before **and** after.

1. run's requesterIp is carried on ControlPlaneCore for the life of the
   ephemeral token (A7 INV-A7-33)
2. ALLOW assembles chunked rows, nulls, metadata, audit PII, and SELECT
   rowsAffected — also pins `maxRows` clamped to 5,000 before crossing the wire
3. MASK preserves masked-column metadata and returns only proxy-produced values
   — pins `max_rows = 0` crossing as 0
4. 🔒 DENY is terminal and never returns rows
5. 🔒 an unspecified wire decision fails closed to DENY (**INV-A10-53** — the
   `EnfAction` 0 sentinel; the fake proxy sends `ENF_ACTION_UNSPECIFIED` in a
   `RunDecision` and A7's `RunExecService` must read it as DENY, so this pins
   the _inbound_ direction, not `GrpcMappers`)
6. 🔒 RunError fails the whole exchange without exposing earlier rows
7. no attached proxy returns the typed service-unavailable outcome and revokes
   its token (A7 INV-A7-34)
8. dial timeout is typed, leaves no active token, and never needs a proxy stream
9. 🔒 unknown and duplicate session ids fail NOT_FOUND claim-once (INV-A10-32;
   A7 INV-A7-32)
10. 🔒 a non-ready first message fails FAILED_PRECONDITION (INV-A10-32)
11. 🔒 a persistent session runs multiple queries on ONE held stream, then
    closes and revokes (INV-A10-50) — also pins non-owner run **and** non-owner
    close rejection, and per-query requester-IP refresh/clear
12. active task registry sends RunCancel on the attached stream
13. closeSessionsForPrincipal closes only the matching principal's streams
14. 🔒 a run-minted APPROVER_EXEC token's requester_ip reaches a real gRPC
    decide (approverExec=true, the ONLY APPROVER_EXEC minter) (INV-A10-17)

Case 14's comment states why it exists rather than trusting case 15 of the
decide suite: "APPROVER_EXEC tokens are minted **ONLY** by
`run(approverExec = true)`, so this exercises the production mint path the
manual-insert decide tests can't."

### `GrpcReportCompletionHandlerDbTest.kt` — 232 LOC, 6 cases · DB

1. a completion report inserts a chained completion event referencing the
   decision — asserts `prev_hash == decision.row_hash`, `chain_version`, that
   the stored `row_hash` **recomputes** from the persisted bytes under
   `AuditCanonical`, and that the chain head advanced (INV-A10-23; A8's chain)
2. 🔒 a completion for a decision without a wire task stays audit-only
   (INV-A10-25)
3. a completion carries the terminal error status and partial counts
4. 🔒 a completion with decision_id 0 is rejected INVALID_ARGUMENT (INV-A10-22)
5. 🔒 a completion for an unknown decision is rejected NOT_FOUND (uses
   `Long.MAX_VALUE`)
6. 🔒 a completion with an unknown status is rejected INVALID_ARGUMENT
   (INV-A10-22)

### `GrpcPerConnectionCatalogDbTest.kt` — 280 LOC, 11 cases · DB (2 `@Disabled`)

This suite is the area's **defect ledger**: two `@Disabled` expected-behaviour
tests each paired with a loud "current behavior" characterization test.

1. validate mints connection id and system on-open commands — asserts 16 bytes
   and `{pg_catalog, information_schema}`
2. 🔒 forged push and close reject not-found and live datasource mismatch
   rejects precondition (INV-A10-46)
3. 🔒 push rejects old backend generation and unchanged hash mismatch
   (INV-A10-47)
4. ⚠️
   `@Disabled("a replayed full push can satisfy a newer pending REFETCH because the command has no nonce")`
   — replayed full push cannot satisfy a newer pending refetch
5. ⚠️ current replay behavior accepts an old full push for a newer pending
   command — "Defect characterization: this is intentionally loud and paired
   with the disabled expected-reject test."
6. 🔒 cross-principal Decide on a live id rejects binding mismatch (INV-A10-19)
7. 🔒 post-close late push rejects not-found
8. ⚠️
   `@Disabled("closed/forged connection_id is recovered by Decide — no tombstone/mint-evidence")`
   — post-close Decide reuse is rejected
9. ⚠️ current post-close Decide behavior recovers the closed id (INV-A10-20) —
   "restart recovery and a closed/forged id are indistinguishable today."
10. real restart recovers original id and token then anchors the principal —
    **stops and restarts the gRPC server and rebuilds `ControlPlaneCore`**
    mid-test, asserts before-decide with **no audit row**, then a verdict after
    fragments are re-pushed, then a cross-principal FAILED_PRECONDITION
11. unknown connection Decide recovers with before-decide only and no audit
    (INV-A10-20)

Cases 10 and 11 pin a property no other suite does: **a recovery round writes no
`audit_event` row.** A Go port that audits the before-decide round breaks them.

### `WireTaskDecideDbTest.kt` — 328 LOC, 10 cases (×2 engines) · DB

`abstract class WireTaskDecideDbContract` + `WireTaskDecideMysqlDbTest` /
`WireTaskDecidePostgresDbTest`. Calls `ControlPlaneGrpcService.reportCompletion`
**in-process** (no gRPC server) and `decideConnection` directly. Its distinctive
assertion is `assertWireBytesUnchanged`, which serializes an
independently-computed `toWireDecision(...)` and compares **`toByteArray()`
byte-for-byte** against the enforcement path's — a golden-bytes check on the
mapper.

1. 🔒 ALLOW stays approved until a clean completion executes it and preserves
   relay bytes (INV-A10-23, 24)
2. 🔒 error and canceled completions fail their wire tasks
3. 🔒 only the completed decision executes in a prepare then execute pair
4. 🔒 MASK stays approved until completion and preserves mask relay bytes
5. 🔒 policy DENY fails its wire task inline and preserves deny relay bytes
6. duplicate clean completions leave the wire task executed (INV-A10-24)
7. 🔒 task request forbid overrides enforcement to deny without creating a task
8. 🔒 datasource-scoped task approve forbid overrides enforcement to deny
   without creating a task
9. stale catalog before-decide creates no wire task
10. non-wire decide creates no wire task

Note the WIRE-task lifecycle itself lives in A5's `decideConnection` + A7's
`AccessStore`; this suite is listed here because `reportCompletion` is the
terminalizing half and the byte-golden check targets `GrpcMappers`. Also note
the fixture comment: "WIRE tasks are internal lifecycle rows, deliberately kept
OFF the `/api/approvals` human feed (`listQueryRequests` returns WORKFLOW rows
only), so list them straight from the table here."

### `EditorSessionDecideTimingDbTest.kt` — 190 LOC, 1 case · DB

A pure timing regression, and the header explains exactly why it exists as a
separate suite: `GrpcRunExecDbTest` case 11 "asserts the registry value only
AFTER `runOnSession` returns — which holds regardless of whether the refresh ran
before or after the send — and its fake proxy never invokes the real `Decide`.
So moving the refresh to after the send leaves it green."

1. 🔒 each session query's real gRPC Decide sees THAT query's refreshed
   requester_ip, proving refresh-before-send (A7 INV-A7-33)

Its fake proxy calls the **real** `stub.decide(...)` with the session's
ephemeral token while servicing each query, against an IP-gated permit, and
asserts query 1 → ALLOW / query 2 (null IP) → DENY. This is the only test
anywhere that closes a gRPC `Decide` loop from inside a `RunExec` stream. **Port
it.**

### Coverage gaps in A10

1. 🔒 **`TableDetailExec` has no direct test at all.** Zero cases cover the
   Ready-first guard, the claim-once `NOT_FOUND`, the "closed before Ready"
   `FAILED_PRECONDITION`, or the 60 s `DEADLINE_EXCEEDED`. Its `RunExec` twin
   has four cases for the same four rules. Trivially closable by cloning
   `GrpcRunExecDbTest` cases 9 and 10.
2. 🔒 **The secret-token gate is only ever exercised on a UNARY RPC**
   (`GrpcServerTest` calls `decide`). In Go this is the difference between one
   interceptor and two — an unstreamed gate leaves `Events`, `RunExec`, and
   `TableDetailExec` wide open. Add a streaming-RPC gate case **before**
   porting.
3. **No `DEADLINE_EXCEEDED` test on either stream.** `runStreamTimeoutMs` is
   constructor-injectable specifically so a test could shorten it, and no test
   does.
4. **`GrpcServer.shutdown()`'s force-cancel path is untested.** Every suite
   calls `shutdown()` in teardown, so the graceful path runs constantly, but
   nothing asserts that a held-open `Events` stream is force-cancelled after the
   5 s grace period — the exact property INV-A10-6 exists for, and the exact
   thing a Go `GracefulStop()`-only port gets wrong.
5. **`maxInboundMessageSize` (64 MiB) is untested.** Nothing pushes a >4 MiB
   catalog, so a Go port that forgets `grpc.MaxRecvMsgSize` fails only in
   production, on a large database — and the failure mode is the proxy's
   empty-catalog fail-closed boot state.
6. **The keepalive/enforcement policy is untested.**
   `permitKeepAliveTime ≤ client keepAliveTime` and
   `permitKeepAliveWithoutCalls(true)` are asserted nowhere; getting them wrong
   GOAWAYs the liveness stream with `too_many_pings` after the connection idles.
7. **`Channel.MCP` is not covered by the temp-overlay channel gate test** (which
   loops WIRE, WORKFLOW_EXECUTOR, WORKFLOW_VIEWER). It is dropped by the
   `!= EDITOR` test, so the behaviour is correct — but the enum can grow.
8. **`validateToken`'s guard ordering is untested** (F26): no test presents a
   bad token _and_ a blank `datasource_name`.
9. **`ValidateToken`'s `INVALID_ARGUMENT` on a blank datasource name is untested
   at all.**
10. **`reportCompletion`'s dropped identity fields (F24) are unasserted in
    either direction** — no test says the completion row carries the decision's
    `roles`, and none says it must not.
11. **`inspectTrustChain`'s three Java/Go divergence traps are untested**
    (§3.1): a CA with **no** KeyUsage extension, `basicConstraints`
    present-with-pathLen vs absent, and the reason string for empty input. All
    three are exactly where a Go port silently changes behaviour.
12. 🔒 **NO TEST ANYWHERE RUNS THE REAL `goproxy` AGAINST A REAL
    CONTROL-PLANE.** Verified: every goproxy-side test binds a hand-written fake
    — six of them, all embedding `pb.UnimplementedControlPlaneServer`
    (`goproxy/cp/client_test.go:194` and `:567`,
    `goproxy/mysqlproxy/proxy_test.go:46`, `goproxy/pgproxy/proxy_test.go:39`,
    `goproxy/run/runner_test.go:45`, `goproxy/run/table_detail_test.go:35`). And
    every control-plane-side test drives the real service with a **generated
    stub**, never with `goproxy`. **The `.proto` file is the only thing holding
    the two halves together.** A field-number reuse, a status-code change, or a
    presence-semantics slip is caught by nothing. This is the single most
    valuable test the port should add: one end-to-end suite running real
    `goproxy` against a real control-plane over a real socket. Recorded as
    **F28**.
13. 🔒 **`Decide`'s 16-byte `connection_id` guard is asserted by no test**
    (added in this audit). `INVALID_ARGUMENT` appears in exactly four assertions
    across the area's suites — two in `GrpcReportCompletionHandlerDbTest` and
    two in `GrpcRegistrationHandlerDbTest`. Every `decide` call in every suite
    passes a well-formed id, so INV-A10-18's CP half is unpinned and F27's
    reordering is free.
14. **Neither `pg_temp` casing rule is tested** (F31): no case sends `PG_TEMP_1`
    in `temp_columns` or in `search_path`, so the
    case-sensitive/case-insensitive split between `editorTempOverlay` and
    `ConnectionDecide.kt:43` is invisible to the suite.
15. **`validateToken` is untested for `TokenKind.SESSION`** — case 13 covers
    EDITOR/APPROVER_EXEC/USER only.

---

## 5. Cross-area dependencies

| Direction | Area    | What                                                                                                                                                                                                              |
| --------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ←         | **A1**  | `ControlPlaneCore` (the shared graph, INV-A1-1); `Main.kt` boot step 5 + INV-A1-2 (bind failure fatal); `config.grpcPort` / `config.secretToken`; `DataSource.inTx`; `runStreamTimeoutMs(queryExchangeTimeoutMs)` |
| ←         | **A2**  | nothing directly — Cedar is reached through A6                                                                                                                                                                    |
| ←         | **A3**  | `UserGroupStore.isDeactivated` (both `validateToken` and `decide`)                                                                                                                                                |
| ←         | **A4**  | `TokenStore.validate` (handshake, kind-restricted) vs `TokenStore.resolve` (per-query, read-only); `TokenKind.fromWire`; `tokenHash`                                                                              |
| ←         | **A5**  | `DatasourceStore.getByName                                                                                                                                                                                        | register                                                                                              | storePushedCatalog | markSeen     | PushedColumn`; `ConnectionCatalogRegistry.open        | recover | find | applyPush | close | invalidateDatasource | recordAmbientMeasurement`; `CatalogMutationResult`(which carries the gRPC`Status.Code`); `decideConnection`+`EnforcementOutcome`; `Engine.catalogName | systemSchemas | catalogIsConnectionIndependent`; `SystemClassificationService.describeManifestFor`; `TableDetailChannelRegistry`; `CatalogColumn`, `FragmentColumn`, `Binding`, `OpenConnection` |
| ←         | **A6**  | `DecisionContext` (the mapper's input); `Channel`; every actual authorization decision                                                                                                                            |
| ←         | **A7**  | `RunChannelRegistry.attach                                                                                                                                                                                        | remove`+`Attached`(INV-A7-32);`RequesterIpRegistry.get`(INV-A7-33);`AccessStore.wireTaskIdForDecision | claimExecution     | markExecuted | markFailed`; INV-A7-1 (`assumeRoles`→`providedRoles`) |
| ←         | **A8**  | `AuditStore.get                                                                                                                                                                                                   | insert` (the completion event and its hash chain)                                                     |
| ←         | **A12** | `ProxyEventsHub.register                                                                                                                                                                                          | deregister` (INV-A12-12 direction invariant, INV-A12-14 wedged-vs-not-attached)                       |
| →         | **A5**  | `inspectTrustChain` is consumed by `Datasources.kt:913` (the `GET /api/datasources/{id}/wire-cert` download route) — this area exports a symbol _into_ A5 (F23)                                                   |
| →         | **A6**  | `EditorSubmitRouteDbTest` constructs `GrpcServer` + `ControlPlaneGrpcService` and reads `boundPort` — an A6-owned suite that cannot compile until this area's boot surface exists                                 |
| →         | **A7**  | `ApprovalExecuteRouteDbTest` does the same. Together with A6's, these are the two out-of-area consumers of `GrpcServer`; port order must put this area's server ahead of both                                     |

---

## 6. Candidate findings (new — number as **F21+** in `00-INDEX.md`)

| #       | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Where                                                                                                                                                  | Kind                                  |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------- |
| **F21** | `WireMetadata.SECRET_TOKEN_CTX` is written on every call but read by **no production code** — only `GrpcServerTest`'s probe handler. The interceptor's doc claims it exists "so handlers can resolve a per-datasource secret later"; there is no per-datasource secret. Forward plumbing whose sole consumer is a test. **REPRODUCE as a test-visible propagation (index F81)** — production-dead but fixture-live, so it falls outside the OMIT boundary: dropping it in Go silently kills `GrpcServerTest` cases 1 and 4, which assert the propagated value. The stale doc claim ("so handlers can resolve a per-datasource secret later") is the OMIT half. | `SecretTokenInterceptor.kt:18,34`; `WireMetadata.kt:23`                                                                                                | dead-code / stale-doc                 |
| **F22** | `tableDetailExec`'s 60 s lifetime is a `private const`, while `runExec`'s is constructor-injectable _specifically so a test could shorten it_. Neither timeout is actually tested, and the asymmetry means the table-detail path cannot be.                                                                                                                                                                                                                                                                                                                                                                                                                    | `ControlPlaneGrpcService.kt:61,114`                                                                                                                    | inconsistency + coverage gap          |
| **F23** | `inspectTrustChain` + `KEY_USAGE_CERT_SIGN` are pure X.509 helpers living in the **gRPC handler file**, consumed both by `register` and by A5's `/api/datasources/{id}/wire-cert` route. Their test suite sits in the parent package. In Go they belong in a shared cert package, not the gRPC server. Also: two of the test PEMs are duplicated verbatim across `TrustChainInspectionTest` and `GrpcRegistrationHandlerDbTest`, and both expire **2027-07-27**.                                                                                                                                                                                               | `ControlPlaneGrpcService.kt:554-594`; `Datasources.kt:913`                                                                                             | placement inconsistency + duplication |
| **F24** | `reportCompletion` mirrors only `principal`, `datasource`, `statement`, `decision`, `channel` onto the completion event, dropping `roles`, `clientAddr`, `effectiveNamespace`, `maskedColumns`, `piiTouched`, `contextTags`. The handler doc claims the row is "self-describing for the audit monitor"; an `auditmon` rule keying on `roles` sees an empty list on every completion row. **No test asserts either behaviour.**                                                                                                                                                                                                                                 | `ControlPlaneGrpcService.kt:252-264`                                                                                                                   | possible bug / stale doc              |
| **F25** | `WireIdentity.roles` on the handshake comes straight from the token row (`TokenStore.validate`), and `decide` **deliberately ignores** on-token roles for SESSION/USER kinds (pinned by `GrpcDecideHandlerDbTest` case 11). So a non-authoritative role list crosses the wire into `spi.Identity.Roles` in goproxy. Not exploitable today (nothing authorizes on it), but the field's authority is ambiguous and the port should pin it deliberately.                                                                                                                                                                                                          | `ControlPlaneGrpcService.kt:136-141`; `client.go:155-160`                                                                                              | contract ambiguity                    |
| **F26** | `validateToken`'s blank-`datasource_name` `INVALID_ARGUMENT` check runs **after** token validation and the deactivation check, so a request that is wrong in both ways reports `UNAUTHENTICATED`. Order is observable, undocumented, and untested.                                                                                                                                                                                                                                                                                                                                                                                                             | `ControlPlaneGrpcService.kt:120-128`                                                                                                                   | untested ordering                     |
| **F27** | `Decide`'s 16-byte `connection_id` check is the **tenth** rule — after three DB round-trips, the temp-overlay build, and a requester-IP registry read. A malformed id pays the whole prelude. It could be rule 1 at zero cost.                                                                                                                                                                                                                                                                                                                                                                                                                                 | `ControlPlaneGrpcService.kt:196`                                                                                                                       | inefficiency                          |
| **F28** | 🔒 **No test anywhere runs real `goproxy` against a real control-plane.** Six hand-written fakes embed `pb.UnimplementedControlPlaneServer` on the Go side; the Kotlin side always drives a generated stub. The `.proto` is the sole integration contract, and nothing catches a field-number reuse, a status-code change, or a presence-semantics slip. Highest-value test the port should add.                                                                                                                                                                                                                                                               | `goproxy/cp/client_test.go:194,567`; `mysqlproxy/proxy_test.go:46`; `pgproxy/proxy_test.go:39`; `run/runner_test.go:45`; `run/table_detail_test.go:35` | coverage gap                          |
| **F29** | 🔒 Two **documented, deliberately-unfixed** defects carried as `@Disabled` + characterization pairs: (a) _"a replayed full push can satisfy a newer pending REFETCH because the command has no nonce"_, (b) _"closed/forged connection_id is recovered by Decide — no tombstone/mint-evidence"_. Both are fail-open-shaped and both are bounded by the proxy trust boundary. The port must reproduce the behaviour **and** carry the disabled pairs forward, or the record is lost.                                                                                                                                                                            | `GrpcPerConnectionCatalogDbTest.kt:132,181`                                                                                                            | possible bug (documented)             |
| **F30** | Go's generated enums have **no `UNRECOGNIZED` constant**, so `register`'s deliberately-inverted engine check (INV-A10-26) cannot be transliterated. A naive `switch { case POSTGRES, MYSQL }` inverts the stated intent ("lets a future proto engine pass through untouched"); a naive `e == 0` check lets garbage through. Needs an explicit descriptor-based validity test.                                                                                                                                                                                                                                                                                  | `ControlPlaneGrpcService.kt:314-319`                                                                                                                   | port trap                             |
| **F31** | 🔒 The two `pg_temp` filters on the **same** `Decide` request disagree on case: `editorTempOverlay` is case-**sensitive** (`startsWith("pg_temp")`), A5's freshness gate on `search_path` is case-**insensitive** (`startsWith("pg_temp", ignoreCase = true)`). A `PG_TEMP_9` entry is dropped by one and honoured by the other. Fail-closed today (no fragment + no overlay row ⇒ unresolvable name ⇒ DENY) and unreachable from a correct proxy, but neither casing is tested and a port must choose one rule for both sites deliberately.                                                                                                                   | `ControlPlaneGrpcService.kt:92`; `ConnectionDecide.kt:43`                                                                                              | inconsistency                         |
| **F32** | The 17-line KDoc that documents `inspectTrustChain` (its whole "REPORTS, never gates" contract plus the three load-bearing reasons) sits **above `private const val KEY_USAGE_CERT_SIGN`**, so tooling attaches it to the const, not the function. Purely a placement bug, but it is the only place those reasons are written down and they are one careless refactor from being deleted with the const.                                                                                                                                                                                                                                                       | `ControlPlaneGrpcService.kt:537-556`                                                                                                                   | stale-doc / placement                 |
| **F33** | 🔒 `Decide`'s `connection_id` length guard is asserted **nowhere** (`INVALID_ARGUMENT` appears in only four assertions across the area, none of them on `Decide`), and every `decide` call in every suite supplies a valid 16-byte id. So INV-A10-18's control-plane half rests entirely on the Go client's receive-side checks, and a Go server that dropped the check would pass the whole suite. Discovered while falsifying the (incorrect) claim that cases 6+7 pin the guard order.                                                                                                                                                                      | `ControlPlaneGrpcService.kt:196`; `GrpcDecideHandlerDbTest.kt` (no case)                                                                               | coverage gap                          |

### Corrections applied to this document by the A10 audit

| Was                                                                          | Is                                                                                                                                                                                                                       |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| "the generated `ServiceDesc` order" == proto declaration order               | protoc-gen-go-grpc splits `Methods` (7 unary, `ReportCompletion` last) from `Streams` (3) — §1.1                                                                                                                         |
| `goproxy/cp/client.go` (501)                                                 | 500 (`wc -l`)                                                                                                                                                                                                            |
| `Engine` used by "registration, catalog push, and `EngineConfig`"            | `RegisterRequest.engine` + `analyzer.proto:57` only; `CatalogRequest` has no `Engine` field, and `engine.proto:3-6` is itself stale — §1.3                                                                               |
| "INV-A10-39's ordinal hazard" (×2)                                           | INV-A10-53, newly numbered in §1.3; INV-A10-39 is the empty-`if_hash_differs` invariant                                                                                                                                  |
| `GrpcDecideHandlerDbTest` 6+7 "assert codes that only hold at this ordering" | case 6 pins only _deactivation-before-`decideConnection`_; nothing pins the rest; F27's hoist is free — §3.1                                                                                                             |
| `client.go:463` "distinguishes the message text"                             | it is a **code** check (`status.Code(err) == codes.DeadlineExceeded`) on the **Events** rotation path, not `RunExec` — §3.1                                                                                              |
| PEM fixtures "go red after 2027-07-27"                                       | no validity check exists anywhere in the path (`verify()` is signature-only; no `checkValidity` in `control-plane/src`); the real trap is Go's `Verify(opts)`, which _does_ check dates — §4                             |
| "Every test in this area binds port 0"                                       | 8 of 12; plus 2 suites in A6/A7 — §3.3                                                                                                                                                                                   |
| "Every DB suite relies on `shutdown()` in `@AfterAll`"                       | 7 do; `WireTaskDecideDbTest` starts no server — §3.3                                                                                                                                                                     |
| case 13 "pins all three kinds"                                               | 3 of 4 `TokenKind`s (`SESSION` untested), and via `tokenStore.validate` directly, not the RPC — §4                                                                                                                       |
| lost proto reasons                                                           | restored: `TempColumn`'s CREATE-time write-references-masked justification, `temp_columns`' shadowed-real-table reason, `advertise_wire_tls`' plaintext-downgrade reason, `eventsStreamMaxAge`'s replaced-backend reason |

---

## 7. Open questions

| #   | Question                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | `editorTempOverlay`'s filter is `schema.startsWith("pg_temp")` — a case-sensitive prefix, not `pg_temp_<N>`. Postgres refuses to create any `pg_`-prefixed schema, so no _real_ schema can match. But the proxy also supplies `search_path` on the same request, so a compromised (not merely buggy) proxy could put a fabricated `pg_temp_*` entry in the namespace and bind a bare table name to an overlay column. Is the gate intended as a hard boundary against a compromised proxy, or as defence-in-depth against a buggy one (which is what the source comment describes)? Confirm before "tightening" or loosening it. |
| Q2  | `Decide`'s recovery path seeds `request.searchPathList + ds.defaultSchemas + ds.engine.systemSchemas`, while `ValidateToken`'s `open` seeds only `ds.defaultSchemas + ds.engine.systemSchemas`. Deliberate (recovery must cover the client's live namespace, the handshake has none yet) or drift?                                                                                                                                                                                                                                                                                                                               |
| Q3  | F24: should the completion event mirror the decision's `roles` / `piiTouched` / `maskedColumns`? Ask `auditmon` what its rules read before deciding. Whichever way, add the missing test.                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Q4  | F25: does `goproxy` use `spi.Identity.Roles` for anything other than display/logging? If not, consider dropping the field from `WireIdentity` in the Go port rather than shipping a non-authoritative role list.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Q5  | The `check(...)` failures in `reportCompletion` ("wire task N left EXECUTING") surface as gRPC `UNKNOWN` because this service installs no exception mapper. Is `UNKNOWN` the intended wire behaviour for an invariant violation, or should it be `INTERNAL`? The Go client treats any non-nil error identically (logs and drops), so nothing observes the difference today.                                                                                                                                                                                                                                                      |
| Q6  | `TABLE_DETAIL_STREAM_TIMEOUT_MS` (60 s) vs the HTTP-side table-detail fetch timeout in A5 — are they derived from one another, or independently chosen? A 60 s stream cap under a longer HTTP wait would surface as a stream-closed error rather than a timeout, the exact failure `Main.kt:12-17` describes for `RunExec`.                                                                                                                                                                                                                                                                                                      |
| Q7  | The Go client rotates the `Events` stream every 4 minutes (`eventsStreamMaxAgeDefault`) so a stream pointing at a replaced backend self-heals. Is any control-plane-side behaviour tuned to that cadence (e.g. a `last_seen_at` staleness threshold, or the idle-connection sweep)? If so, the two constants are a cross-language pair and should be documented as one, like A7 INV-A7-31's `QUERY_TIMEOUT_MESSAGE`.                                                                                                                                                                                                             |
| Q8  | `CloseConnection` discards `Applied.generation`. Is that just an unused ack value, or was a generation echo intended (the message has no field for it, so probably the former)?                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Q9  | F31: which casing is intended for the `pg_temp` prefix — the overlay's case-sensitive test or the freshness gate's `ignoreCase = true`? Postgres folds unquoted identifiers, so the observable difference only exists for a proxy sending a quoted/hostile schema string. Pick one for both call sites before porting, and say which.                                                                                                                                                                                                                                                                                            |
| Q10 | F33 / gap 13: is the CP-side 16-byte `connection_id` check meant as a real guard or as belt-and-braces behind the Go client's own checks? If the former it needs a test; if the latter, say so, because a Go port will otherwise be told to "keep the guard order" for a guard nothing observes.                                                                                                                                                                                                                                                                                                                                 |
| Q11 | `advertise_cert_chain` is inspected but the _result_ is only logged (INV-A10-28). Is there an intended consumer for the reason string — an admin-visible datasource health field, say — or is a warn-level log genuinely the whole contract? Two call sites (`register`, the wire-cert download) both only log, so today it is log-only.                                                                                                                                                                                                                                                                                         |
