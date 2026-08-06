# A5 — Datasources, Catalog, Engines, System Classification

Files: `Datasources.kt` (967) · `ConnectionCatalog.kt` (532) · `Engines.kt`
(173) · `SystemClassificationService.kt` (160) · `TableDetailExec.kt` (158) ·
`ConnectionDecide.kt` (157). **Total 2,147 LOC. Fully read.**

DB tables: `datasource` (V2, extended by V9 `datasource_cert_chain`) ·
`catalog_column` (V2) · `column_classification` (V2) · `mask_fn` (V2, read-only
here — owned by A9) — plus reads of `proxy_token` and `app_user` through A4/A3
stores in the Bearer gate.

## Purpose

A5 owns **what a datasource is and what its schema looks like**. Three separate
catalog notions live here and must not be conflated:

| Notion                                                                    | Storage                               | Written by                                      | Consumed by                                                                  |
| ------------------------------------------------------------------------- | ------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------- |
| **Persisted config catalog** — `catalog_column` + `column_classification` | Postgres                              | proxy `PushCatalog` (gRPC, A10)                 | admin console browse, `TableDetailService` overlay, HTTP/editor decide paths |
| **Ephemeral enforcement catalog** — per-connection schema fragments       | in-memory `ConnectionCatalogRegistry` | proxy `PushSchemaFragment` (gRPC, A10)          | `decideConnection` → `decideQuery` (A6) on the native-wire path              |
| **Live table detail** — indexes, FKs, metadata                            | nothing; fetched on demand            | proxy over a dedicated `TableDetailExec` stream | one admin route, never persisted                                             |

It also owns the **engine as a type** (`Engines.kt` — the single home for every
"is this MySQL or Postgres?" fact), the **system-classification manifest
resolution** keyed off the stored `datasource.engine_version`, and the
connection-scoped decide orchestration (`decideConnection`) that serializes
freshness-gating, analysis, audit and verdict emission under one mutex.

The headline design constraint, restated in four separate source comments and
load-bearing for the whole area: **the control-plane never dials a target
database.** It holds no target credential, so `host`/`port`/`db_name` are
advisory display fields, "test connection" is a liveness report rather than a
dial, and every byte of schema knowledge arrives because a proxy pushed it.

---

## 1. Wire contract

Every `@Serializable` DTO owned by A5. `web/` and `pmon` consume these.

### `Datasource` (`Datasources.kt:37`) — the datasource row as served

| JSON field                 | Type         | Nullable | Default | Notes                                                                                      |
| -------------------------- | ------------ | -------- | ------- | ------------------------------------------------------------------------------------------ |
| `id`                       | number (i64) | no       | —       |                                                                                            |
| `name`                     | string       | no       | —       | UNIQUE; **the wire identity** the proxy presents (never the numeric id)                    |
| `engine`                   | string       | no       | —       | `EngineWireSerializer`: exactly `"mysql"` or `"postgres"`                                  |
| `host`                     | string       | no       | —       | **advisory** — proxy `Register` overwrites                                                 |
| `port`                     | number (i32) | no       | —       | advisory                                                                                   |
| `dbName`                   | string       | no       | —       | advisory, but **load-bearing for catalog identity** (see INV-A5-6)                         |
| `tags`                     | string[]     | no       | `[]`    | free-form bag; only `system:development` / `system:production` govern policy (A2 INV-A2-7) |
| `defaultSchemas`           | string[]     | no       | `[]`    | PG `current_schemas(true)` / the MySQL database; empty until a push                        |
| `mysqlLowerCaseTableNames` | number (i32) | **yes**  | `null`  | CHECK 0..2 in the schema                                                                   |
| `catalogSyncedAt`          | string       | **yes**  | `null`  | `Instant.toString()` — variable fractional precision                                       |
| `lastSeenAt`               | string       | **yes**  | `null`  | last Events-stream open; `null` = never attached                                           |
| `engineVersion`            | string       | **yes**  | `null`  | **raw** `SELECT version()` + `(aurora <v>)`; drives manifest resolution                    |
| `advertiseAddr`            | string       | **yes**  | `null`  | client-facing `host:port` of the proxy — distinct from `host`/`port`                       |
| `advertiseCertChain`       | string       | **yes**  | `null`  | PEM chain, leaf first. Public material                                                     |
| `advertiseWireTls`         | boolean      | no       | `false` | separate fact from the chain (see INV-A5-4)                                                |

⚠️ Timestamp formatting: both timestamps are
`getTimestamp(...)?.toInstant()?.toString()`, i.e. Java `Instant.toString()`,
which **omits trailing zeros in the fractional second**. Same wire-visible
hazard as A2 Q3 — a Go port emitting RFC3339Nano or fixed-millis differs.

No route ever _deserializes_ a `Datasource` (verified:
`grep -rn 'receive<Datasource>' control-plane/src` returns nothing), so
`EngineWireSerializer.deserialize` is exercised only by `EnginesTest`.

🔒 **INV-A5-67 — the chain replaced a leaf-digest pin, and the pin must not come
back.** `V9__datasource_cert_chain.sql` DROPs `advertise_cert_sha256` (and its
`^[0-9a-f]{64}$` CHECK) with the reason recorded in the migration itself: "It
pinned the leaf by digest, which required turning OFF the usual CA and hostname
checks to work — so a stolen leaf replayed on another host passed the pin.
Verifying against the chain with the server name checked is strictly stronger …
Holding both also meant two values describing one certificate, which could
disagree." A Go port that re-adds a digest field re-opens exactly that replay.
The same migration explains `advertise_wire_tls NOT NULL DEFAULT FALSE`: "a row
that predates any registration is treated as plaintext until a proxy says
otherwise: the safe direction is to withhold trust, never to assume it."

### `DatasourceInput` (`Datasources.kt:76`) — admin create/update body

| JSON field | Type   | Default      |
| ---------- | ------ | ------------ |
| `name`     | string | required     |
| `engine`   | string | `"postgres"` |
| `host`     | string | `""`         |
| `port`     | number | `0`          |
| `dbName`   | string | `""`         |

Everything but `name` defaults so the form can create a **name-only
placeholder** before a proxy attaches. **There are no credential fields, by
design.** `engine` is a plain `String` here (not the serializer) precisely so
the route can canonicalize it and render its own error.

### `CatalogColumn` (`Datasources.kt:85`)

| JSON field       | Type             | Nullable | Default                                       |
| ---------------- | ---------------- | -------- | --------------------------------------------- |
| `catalog`        | string           | no       | —                                             |
| `schema`         | string           | no       | —                                             |
| `table`          | string           | no       | —                                             |
| `column`         | string           | no       | —                                             |
| `dataType`       | string           | no       | — (the raw DB type, e.g. `character varying`) |
| `sqlType`        | string           | no       | — (normalized; see `sqlTypeFor`)              |
| `ordinal`        | number (i32)     | no       | —                                             |
| `nullable`       | boolean          | no       | —                                             |
| `classification` | `Classification` | **yes**  | `null`                                        |
| `isTemp`         | boolean          | no       | `false`                                       |

`catalog` is **computed in SQL**, not stored:
`CASE WHEN lower(d.engine)='mysql' THEN 'def' ELSE d.db_name END`
(`Datasources.kt:539`). A Go port must reproduce this, including the `lower()`.

🔒 **INV-A5-1 — `isTemp` is never set by A5.** Both A5 producers
(`DatasourceStore.catalog` and `decideConnection`'s catalog build) leave it at
`false`. Only the per-request temp overlay (A6/A10) sets it true, and A6 reads
temps **unmasked without a Cedar grant**. A Go port that defaulted `isTemp` true
— or that let a _base-catalog_ column carry it — turns every column into an
ungranted cleartext read.

### `ClassificationInput` (`Datasources.kt:104`)

`schema: string? = null` · `table: string` · `column: string` ·
`tags: string[] = []` · `maskFnId: i64? = null`. A null `schema` means "resolve
the datasource's default schema" (see `defaultSchema`).

### `ClassificationDelete` (`Datasources.kt:113`)

`schema: string? = null` · `table: string` · `column: string`.

### `TestResult` (`Datasources.kt:116`)

`ok: boolean` · `message: string`.

### `RefreshResult` (`Datasources.kt:120`)

`notified: number` — how many attached proxy Events streams took the push. `0`
means no proxy attached, reported honestly (A12 INV-A12-14's honesty rule
surfaced at the REST layer).

### Borrowed shapes served by A5 routes (owned elsewhere — do not re-derive)

- `Classification` (`engine/.../probe/TableDetail.kt:7`): `schema`, `table`,
  `column`, `tags=[]`, `maskFnId=null`, `maskFnName=null`. Returned by
  `PUT {id}/classification`.
- `TableDetail` +
  `TableDetailColumn`/`TableIndex`/`TableIndexColumn`/`TableRelation`/`TableMetadata`
  (same file): returned verbatim by `GET {id}/table-detail`. `TableDetailDbTest`
  pins the top-level key set to exactly
  `{schema, table, columns, indexes, foreignKeys, referencedBy, metadata}` and
  asserts no `rows`/`data`/`preview` key ever appears.
- `ApiError(code, params)` — A1.

---

## 2. Routes

All under
`Route.datasourceRoutes(config, authz, roleResolver, store, eventsHub, tableDetailService, tokenStore, userGroupStore, management)`
(`Datasources.kt:759`). `management` defaults to
`DatasourceManagementService(store, eventsHub, tableDetailService)` (A11).

| Method | Path                                   | Gate                                    | Success                                                                                                                                                                                                          | Error codes                                                                                                                                                                                                                |
| ------ | -------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/api/datasources`                     | `requireApiOrBearer` (private helper)   | 200 `Datasource[]`                                                                                                                                                                                               | 401 `common.unauthenticated`                                                                                                                                                                                               |
| GET    | `/api/datasources/live`                | `requireApi`                            | 200 `string[]` (attached names)                                                                                                                                                                                  | 401                                                                                                                                                                                                                        |
| POST   | `/api/datasources/{id}/refresh`        | `requireAdmin(ADMIN_DATASOURCES)`       | 200 `RefreshResult`                                                                                                                                                                                              | 400 `common.bad_id` · 404 `common.not_found{resource:datasource}`                                                                                                                                                          |
| POST   | `/api/datasources`                     | `requireAdmin(ADMIN_DATASOURCES)`       | **201** `Datasource`                                                                                                                                                                                             | 400 `common.field_required{fields:name}` · 400 `datasource.invalid_engine{engine}`                                                                                                                                         |
| GET    | `/api/datasources/{id}`                | `requireApi`                            | 200 `Datasource`                                                                                                                                                                                                 | 400 `common.bad_id` · 404 `common.not_found`                                                                                                                                                                               |
| PUT    | `/api/datasources/{id}`                | `requireAdmin(ADMIN_DATASOURCES)`       | 200 `Datasource`                                                                                                                                                                                                 | 400 `common.bad_id` · 400 `datasource.invalid_engine` · **409 `datasource.engine_immutable`** · 404 `common.not_found`                                                                                                     |
| DELETE | `/api/datasources/{id}`                | `requireAdmin(ADMIN_DATASOURCES)`       | **204**                                                                                                                                                                                                          | 400 `common.bad_id` · 404 `common.not_found`                                                                                                                                                                               |
| POST   | `/api/datasources/{id}/test`           | `requireAdmin(ADMIN_DATASOURCES)`       | 200 `TestResult`                                                                                                                                                                                                 | 400 · 404                                                                                                                                                                                                                  |
| GET    | `/api/datasources/{id}/catalog`        | `requireApiOrBearer` **+ `mayConnect`** | 200 `CatalogColumn[]`                                                                                                                                                                                            | 401 · 400 `common.bad_id` · 404 `common.not_found` · **403 `datasource.not_connectable`**                                                                                                                                  |
| GET    | `/api/datasources/{id}/wire-cert`      | `requireApiOrBearer` **+ `mayConnect`** | 200, body = raw PEM, `Content-Type: application/x-pem-file` (`ContentType.parse`, `Datasources.kt:922` — **not** a `text/*` type), + `Content-Disposition: attachment; filename="datasource-<id>-wire-cert.pem"` | 401 · 400 · 404 `common.not_found` · 403 `datasource.not_connectable` · **404 `datasource.no_wire_cert`**                                                                                                                  |
| GET    | `/api/datasources/{id}/table-detail`   | `requireAdmin(ADMIN_DATASOURCES)`       | 200 `TableDetail`                                                                                                                                                                                                | 400 `common.bad_id` (also for `id <= 0`) · 400 `common.field_required{fields:"schema, table"}` · 404 `common.not_found` · 404 `common.not_found{resource:table}` · **502 `datasource.table_introspection_failed{detail}`** |
| PUT    | `/api/datasources/{id}/classification` | `requireAdmin(ADMIN_DATASOURCES)`       | 200 `Classification`                                                                                                                                                                                             | 400 `common.bad_id` · 400 `datasource.schema_required` · 400 `datasource.reserved_tag{tag}` · 400 `common.field_required` · 404 `common.not_found{resource:datasource}`                                                    |
| DELETE | `/api/datasources/{id}/classification` | `requireAdmin(ADMIN_DATASOURCES)`       | **204**                                                                                                                                                                                                          | as PUT                                                                                                                                                                                                                     |

⚠️ **Two route-level error facts the table cannot express, both verified in
source:**

- **DELETE `{id}/classification` is unconditionally 204.** The route discards
  `management.clearColumnClassification`'s `DeleteResult`
  (`Datasources.kt:961-962`), so deleting a classification that does not exist
  is **204, never 404**. A Go port that 404s on zero rows changes an idempotent
  surface into a failing one.
- **A duplicate `name` on POST/PUT is an unmapped 500.** `store.create` /
  `store.update` do no uniqueness check and the routes catch only
  `DatasourceEngineConflictException`, so the `name` UNIQUE violation propagates
  to `App.kt:452`'s `install(StatusPages) { exception<Throwable> }` and answers
  **500 `common.fallback`** — not 409. Untested, and a candidate finding: the
  honest code would be a 409 `datasource.name_taken`. Port the current behaviour
  only if the console depends on it; otherwise decide deliberately (§10 Q12).

**Deliberate openness of list + detail** (`Datasources.kt:783-787`): "The
datasource list + detail stay open to every authenticated principal: the SQL
editor's picker, JIT-request compose (which must show datasources you CANNOT yet
connect to, precisely so they can be requested), and token generation all need
it — not an admin action." `?connectable=true` narrows the _list_; the
**catalog** and the **certificate** are connect-gated.

🔒 **INV-A5-2 — schema visibility tracks connect authority, not session
existence.** `{id}/catalog` and `{id}/wire-cert` both call `mayConnect`, which
runs the _same_ name-keyed `datasource.connect` Cedar decision, with two-pass
derived context tags, that the proxy runs at connect time. "Browsing the catalog
needs the same `datasource.connect` authority as opening a session."

🔒 **INV-A5-3 — `requireApiOrBearer` must return the principal that
authenticated.** The bug this fixed is recorded in
**`WireCertRouteDbTest.kt:42-47`** (the suite's class KDoc, _not_ a comment on
the route — the earlier draft of this doc mis-attributed it): the route "reveals
WHICH datasources exist and which address they answer on, and it previously
resolved its principal as `userSession()?.principal ?: \"debug-user\"` — an
unauthenticated caller silently became `debug-user` and got whatever that
identity could connect to. Nothing in the response distinguishes the two cases,
which is exactly why it needs a test rather than an inspection." The in-source
statement of the same rule is on the **`{id}/catalog`** route
(`Datasources.kt:863-866`): "resolving the principal from the session alone
would fall through to the literal `debug-user` and run the Cedar check against a
synthetic identity. The helper hands back whichever identity authenticated, and
only answers `debug-user` when `PM_AUTH_DEBUG` actually says so." A Go port must
not reintroduce a `?: "debug-user"` fallback at any call site; the helper
answers `"debug-user"` **only** when `config.authDebug` is actually on
(`Datasources.kt:752`). `WireCertRouteDbTest` case 1 is the regression test.

Two smaller route facts a port will otherwise get wrong:

- The `Content-Disposition` filename is built **from the numeric id, not the
  name** — "a datasource name is barely constrained, and a quote or CRLF in one
  would be header injection here." Pinned by `WireCertRouteDbTest` case 3.
- `datasource.no_wire_cert` (404) is deliberately distinct from
  `common.not_found` (404) so the console can say "this proxy has no wire TLS"
  instead of "no such datasource". `WireCertRouteDbTest` cases 4 and 5 pin
  **both directions** — a nonexistent id must _not_ report `no_wire_cert`,
  because that would confirm the id exists.

---

## 3. Symbols — `Engines.kt`

The datasource engine is the **proto enum**
`com.ridi.oss.proxymonster.grpc.Engine` used directly as the domain type; there
is no parallel Kotlin twin. The file header states the contract: "These
extensions are the single home for every 'is this MySQL or Postgres?' decision,
so nothing else compares an engine string literal. MySQL is the priority engine
and is listed first in each mapping."

Every `when`-based mapping — **nine** of them: `wireName`, `dialect`,
`catalogName`, `defaultSchema`, `requireCaseMode`, `systemSchemas`,
`isFixedSystemSchema`, `isSystemSchema`, `catalogIsConnectionIndependent` — has
an `else -> error(...)` arm for `ENGINE_UNSPECIFIED` / `UNRECOGNIZED`. The three
non-`when` members do not and do not need one: `isMySql` / `isPostgres` are
plain `== Engine.MYSQL` / `== Engine.POSTGRES` (so an unspecified engine is
simply `false` for both, which is why branching on them is discouraged), and
`resolveSchema` inherits `defaultSchema`'s throw.

🔒 **INV-A5-4 — engine mappings are total-or-throw, never defaulted.** A silent
default (e.g. "treat unknown as postgres") would give an unspecified engine a
working dialect, catalog name and system-schema set, and every downstream
decision would be made against the wrong model. `EnginesTest` case 6 asserts
`IllegalStateException` for six of the nine (`wireName`, `dialect`,
`catalogName`, `defaultSchema`, `systemSchemas`, `isFixedSystemSchema`);
`requireCaseMode`, `isSystemSchema` and `catalogIsConnectionIndependent` are the
three untested arms (see §9 coverage gaps).

### `val Engine.wireName: String` · public

`MYSQL → "mysql"`, `POSTGRES → "postgres"`. The canonical persistence /
registration / wire string.

### `val Engine.isMySql` / `val Engine.isPostgres: Boolean` · public

Kdoc: "Calling this at a call site to branch behavior is almost always wrong:
per-engine behavior belongs in a method on `Engine` … Kept only for a genuinely
local one-off." ⚠️ **Zero main-source call sites** (verified) — only
`EnforcementFixture` and two per-connection test suites use them. Candidate
finding (dead in production code).

### `val Engine.dialect: Dialect` · public

`MYSQL → Dialect.MYSQL`, `POSTGRES → Dialect.POSTGRES`. `Dialect` is the
analyzer's (engine module, A13).

### `fun Engine.catalogName(dbName): String` · public

`MYSQL → "def"` (pinned), `POSTGRES → dbName`. **This is the analyzer catalog
segment**, and it is the same value `DatasourceStore.catalog`'s SQL `CASE`
computes. Two implementations of one rule — keep them in agreement (candidate
duplication finding).

### `fun Engine.defaultSchema(dbName): String` · public

`MYSQL → dbName`, `POSTGRES → "public"`. Reason recorded verbatim: "In ANSI
terms a MySQL 'database' IS the schema (catalog is always 'def'), so the default
schema is the database name."

### `fun Engine.resolveSchema(requestedSchema, dbName): String` · public

`if (requestedSchema == "public") defaultSchema(dbName) else requestedSchema`.
`"public"` is a **cross-engine default selector**, not a literal Postgres schema
name. Any other value is an explicit schema — "for MySQL an explicit database,
since a MySQL 'database' is the ANSI schema — and is used as-is, so MySQL
addresses every database, not only the connection's default." **Mirrors
`Dialect.ResolveSchema` in the Go proxy** — the port must keep the two
byte-identical.

### `fun Engine.requireCaseMode(lowerCaseTableNames: Int?): Int?` · public

`MYSQL → requireNotNull(lowerCaseTableNames) { "MySQL lower_case_table_names has not been captured by introspection" }`;
`POSTGRES → null`.

🔒 **INV-A5-5 — MySQL refuses to analyze without a captured case mode.**
Guessing the fold would make identifier resolution wrong in the direction of
resolving a name to a _different_ table. Throwing is the fail-closed answer.
**Go shape:** an `(int, error)` return, not a zero value — `0` is a _valid_
`lower_case_table_names` value, so a Go port using `int` zero-value as "absent"
silently picks case-sensitive mode.

### `val Engine.systemSchemas: Set<String>` · public

`MYSQL → {information_schema, mysql, performance_schema, sys}` ·
`POSTGRES → {pg_catalog, information_schema}`. Kdoc: "the fixed catalog schemas
whose content is identical across every datasource of the same engine version …
it holds only **concrete** names — Postgres's per-session `pg_temp_` /
`pg_toast` schemas are ephemeral and never appear."

### `fun Engine.isFixedSystemSchema(schema): Boolean` · public

`MYSQL → schema.lowercase() in systemSchemas` ·
`POSTGRES → schema in systemSchemas` (**no case folding**).

The asymmetry is documented and deliberate: "the MySQL fold is an interim
compensation for schema names that reach the control plane un-canonicalized
(safe only because MySQL system schemas are always case-insensitive) — see
KNOWN_LIMITATIONS.md 'Identifier handling'." Postgres matches exactly "its
unquoted identifiers being canonically lowercase". This predicate is **the
catalog pool key** decision (`poolKey`).

### `fun Engine.isSystemSchema(schema): Boolean` · public

`MYSQL → isFixedSystemSchema` ·
`POSTGRES → isFixedSystemSchema || startsWith("pg_temp_") || startsWith("pg_toast")`.

⚠️ Note the prefixes require the trailing underscore for `pg_temp` but **not**
for `pg_toast` (`pg_toast` alone matches; `pg_temp` alone does not).
`EnginesTest` case 11 pins `isSystemSchema("pg_temp") == false`. Reproduce
exactly.

### `val Engine.catalogIsConnectionIndependent: Boolean` · public

`MYSQL → true` · `POSTGRES → false`. This single boolean gates the whole
adopt-instead-of-fetch optimization. **Its only job is to supply
`adoptHeldContent` at every registry entry point** — four call sites, all
verified: `grpc/ControlPlaneGrpcService.kt:134` (`open`) and `:206` (`recover`)
for the native wire path, and `RunExec.kt:291` / `:383` (A7) for the
editor/approval-exec paths. A Go port that wires the flag into only the gRPC
path silently forces a full fetch on every editor session. The reason is
recorded in full and must be carried over:

> "MySQL's temporary tables are absent from `information_schema.COLUMNS`
> entirely — a session's temp tables cannot appear in a catalog scan, so nothing
> a scan returns varies by connection. They reach a decision as the per-request
> temp overlay instead, never through the catalog. PostgreSQL's `pg_temp_*`
> schemas are real, per-session, and visible in the catalog, so there a fragment
> is only true for the connection that measured it."

🔒 **INV-A5-6 — adoption is legal only where a scan cannot vary by connection.**
Flipping this to `true` for Postgres lets connection B decide against connection
A's temp tables — a wrong-grant read.

### `fun engineFromWire(raw): Engine` / `fun engineFromWireOrNull(raw): Engine?` · public

`raw.lowercase()`: `"mysql"` → MYSQL, `"postgres"` → POSTGRES, anything else
null / `IllegalArgumentException`.

🔒 **INV-A5-7 — exactly two spellings, case-insensitive, no aliases.**
`"postgresql"` is **rejected** (`EnginesTest` case 2 asserts it explicitly, with
the note "Kotlin and Go both accept exactly {mysql, postgres}"). This is the one
gate raw engine input passes through, and the admin-create route canonicalizes
through it _before_ storing, because — quoting `Datasources.kt:819-823` — "a
non-canonical value (e.g. 'Postgres', 'psql') would be stored verbatim and then
LOCKED by the engine-immutability guard, so the datasource can never be adopted
by its proxy … unusable until deletion."

### `object EngineWireSerializer : KSerializer<Engine>` · public

Primitive STRING descriptor; encodes `wireName`, decodes via `engineFromWire`.
Applied per field with `@Serializable(with = …)`, so the JSON stays
`"mysql"`/`"postgres"` rather than the proto enum name.

### ⚠️ Two `Engine` extensions live **outside** this file

- `Engine.parseServerVersion` — `SystemClassificationService.kt:141` (below).
  Cross-referenced from `Engines.kt`'s kdoc, so at least intentional.
- `Engine.leaksDiagnosticsOnAllow` — `Query.kt:188` (**A6**). Verified: it is a
  per-engine `when` branch living outside the declared "single home". Candidate
  inconsistency finding.

---

## 4. Symbols — `Datasources.kt`

### `fun sqlTypeFor(dataType: String): String` · public

`dataType.lowercase().trim()` mapped to one of eight normalized names the
sqlglot schema understands:

| Output      | Inputs                                                                                    |
| ----------- | ----------------------------------------------------------------------------------------- |
| `INTEGER`   | integer, int, int4, smallint, int2, serial, tinyint, mediumint                            |
| `BIGINT`    | bigint, int8, bigserial                                                                   |
| `DECIMAL`   | numeric, decimal, real, double precision, double, float, float4, float8, money            |
| `BOOLEAN`   | boolean, bool                                                                             |
| `DATE`      | date, year                                                                                |
| `TIMESTAMP` | timestamp, timestamp without time zone, timestamp with time zone, timestamptz, datetime   |
| `TIME`      | time, time without time zone, time with time zone                                         |
| `VARCHAR`   | **everything else** — "varchar, text, char, uuid, json, jsonb, bytea, blob, enum, set, …" |

**INV-A5-8 — `sqlTypeFor` is idempotent on its own outputs.** All eight outputs
map to themselves (verified branch by branch). This matters because it is
applied twice on the enforcement path: `storePushedCatalog` derives `sql_type`
from the raw `data_type`, and `decideConnection` re-derives
`sqlType = sqlTypeFor(row.dataType)` from a fragment column whose `dataType` may
already be normalized (`support/PerConnectionCatalogFixture.kt:63` pushes the
normalized value). A Go port whose default arm mangled an already-normalized
name would silently widen every column to `VARCHAR`.

### `class DatasourceEngineConflictException(name, existingEngine, requestedEngine) : IllegalStateException`

Message:
`"datasource '<name>' is registered as <existing>; refusing re-register as <requested> — engine is immutable at register (delete and re-create to change it)"`.

🔒 **INV-A5-9 — engine is immutable, and the reason is a four-way fail-open.**
Quoted from `Datasources.kt:126-129`: "silently flipping it would repoint every
FK keyed off `datasource_id` (`catalog_column`, `column_classification`,
`query_history`, `access_request`) at a schema from a different dialect, and the
analyzer/system-classification manifest resolution keyed off engine would go
stale — **all fail-open**. Thrown BEFORE any write, so the row/catalog are left
untouched." Enforced on **both** mutation surfaces: gRPC `Register` (→
`FAILED_PRECONDITION`) and admin `PUT` (→ 409 `datasource.engine_immutable`).

### `class DatasourceStore(internal val dataSource: DataSource)`

`companion object { const val RESERVED_TAG_PREFIX = "system:" }` — "The
`system:` tag namespace is owned by the shipped classification manifests — user
column tags may not use it." This is the **write side** of A2 INV-A2-7's
type-scoping; A2 enforces the read side at Cedar-marshalling time. Both are
required (see `PresetPolicyDbTest` case 9, counted in A2).

#### `list()` / `get(id)` / `get(id, conn)` / `getByName(name)` / `getByName(name, conn)`

One shared 15-column projection
(`id, name, engine, host, port, db_name, tags, default_schemas, mysql_lower_case_table_names, catalog_synced_at, last_seen_at, engine_version, advertise_addr, advertise_cert_chain, advertise_wire_tls`),
`ORDER BY id` for `list()`. `name` is UNIQUE so `getByName` returns at most one
row. Every read maps through a single private `ResultSet.toDatasource()`.

🔒 **INV-A5-10 — the certificate body is NOT in this projection… except it is.**
`wireCertChain(id)` has its own `SELECT advertise_cert_chain` with the reason
"Read on its own rather than joined into the list/get projection, so a
certificate body never rides along in the datasource poll every client makes."
⚠️ **The projection above _does_ include `advertise_cert_chain`** and the
`Datasource` DTO carries it — `Datasources.kt:59-63` states the opposite intent
("the browser downloads the same bytes from `{id}/wire-cert`… a few KB on a poll
no client makes hot, which is cheaper than a second round trip"). The two
comments contradict each other. Candidate finding; the _behaviour_ to port is
"the chain rides on the list", and `wireCertChain` is then a redundant query.

#### `register(name, engine, host, port, dbName, tags, advertiseAddr, advertiseCertChain, advertiseWireTls): Datasource`

The gRPC `Register` upsert-by-name. Hand-rolled transaction (`autoCommit=false`
/ commit / rollback / `finally autoCommit=true`), five ordered steps:

1. **`pg_advisory_xact_lock(hashtext("datasource:register:" + name))`.** Stated
   to be _only_ a serialization nicety: "it does **NOT** carry the
   engine-immutability guarantee, because the admin `create`/`update` (rename)
   surfaces do NOT take this lock."
2. `SELECT id, engine, db_name FROM datasource WHERE name = ? FOR UPDATE` →
   `prior`. Locks the row and captures the prior load-bearing identity.
3. **Fast-path engine check:**
   `prior != null && prior.engine != engine.wireName` ⇒ throw
   `DatasourceEngineConflictException` with a precise message, nothing written.
4. **The atomic upsert** — reproduced field by field because every arm is
   load-bearing:

   | Column                         | `ON CONFLICT DO UPDATE SET`                                                                                                                                                             |
   | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | `engine`                       | `EXCLUDED.engine` (guarded by the `WHERE`)                                                                                                                                              |
   | `host`, `port`, `db_name`      | `EXCLUDED.*`                                                                                                                                                                            |
   | `tags`                         | `CASE WHEN EXCLUDED.tags = '[]'::jsonb THEN datasource.tags ELSE EXCLUDED.tags END`                                                                                                     |
   | `advertise_addr`               | `COALESCE(EXCLUDED.advertise_addr, datasource.advertise_addr)`                                                                                                                          |
   | `advertise_cert_chain`         | `CASE WHEN NOT EXCLUDED.advertise_wire_tls THEN NULL WHEN EXCLUDED.advertise_cert_chain IS NULL THEN datasource.advertise_cert_chain ELSE NULLIF(EXCLUDED.advertise_cert_chain,'') END` |
   | `advertise_wire_tls`           | `EXCLUDED.advertise_wire_tls` (authoritative every register)                                                                                                                            |
   | `catalog_synced_at`            | `CASE WHEN datasource.db_name IS DISTINCT FROM EXCLUDED.db_name THEN NULL ELSE datasource.catalog_synced_at END`                                                                        |
   | `default_schemas`              | same guard → `'[]'::jsonb`                                                                                                                                                              |
   | `mysql_lower_case_table_names` | same guard → `NULL`                                                                                                                                                                     |

   plus `WHERE datasource.engine = EXCLUDED.engine` and
   `RETURNING id, (catalog_synced_at IS NULL) AS catalog_cleared`.

   Parameter binding: `advertiseAddr.ifBlank { null }` (blank → NULL so COALESCE
   preserves), but `advertiseCertChain` bound **raw** — "Do not collapse blank
   to null here — that would make 'stop publishing' unexpressible."

5. `upsertedId == null` ⇒ the `WHERE` guard refused a flip that raced in after
   step 2 read null; re-read the committed engine for a precise message and
   throw. Then
   `if (catalogCleared) DELETE FROM catalog_column WHERE datasource_id = ?`.
   Commit. Return `getByName(name)!!`.

🔒 **INV-A5-11 — the engine guard is the `WHERE` clause, not the pre-read.**
Quoted: "If a row for this name raced in after the prior read,
`WHERE datasource.engine = EXCLUDED.engine` refuses to flip its engine: the
update touches 0 rows and RETURNING is empty. That is the only way `upsertedId`
comes back null (a fresh insert and a same-engine update both RETURN the id), so
it unambiguously means 'engine conflict'." A Go port must keep the guard **in**
the conflict arm; moving it to application code reintroduces the TOCTOU the
advisory lock explicitly does not cover.

🔒 **INV-A5-12 — a `db_name` retarget invalidates the catalog atomically,
decided from OLD vs NEW inside the UPDATE.** Quoted: "comparing the OLD row
(`datasource.db_name`) to the NEW (`EXCLUDED.db_name`) inside the atomic UPDATE
removes the TOCTOU of deciding from the pre-read `prior` — correct regardless of
the advisory lock's coverage." Why it matters: "`catalog()` builds the analyzer
catalog name from `db_name` — so leaving it would authorize the new target
against the wrong schema, **a fail-OPEN**." A host/port-only move (same
`db_name`) **deliberately keeps** the catalog.

🔒 **INV-A5-13 — `advertise_wire_tls = false` CLEARS the chain; a blank chain
PRESERVES it.** Quoted: "Blank preserves the prior chain (a transient cert read
sends none), EXCEPT when the proxy reports TLS is off: that is an intentional
clear, and keeping a stale chain would have clients verify a rotated or absent
cert against dead roots." And `advertise_wire_tls` is authoritative every
register "so TLS-on → TLS-off is observable rather than sticky."

**INV-A5-14 — an EMPTY `tags` list preserves admin-set tags.** "an EMPTY list
PRESERVES any admin-set tags on an existing row rather than clobbering them (a
fresh row defaults to `'[]'`)." A proxy that does not manage tags must not erase
the posture tag an operator set.

⚠️ **Insert-arm / conflict-arm asymmetry (candidate finding).** The
`INSERT … VALUES` arm binds `advertise_cert_chain` **raw**, so on a _fresh_ row:
a PRESENT-blank chain stores `''` (not NULL), and a non-blank chain is stored
even when `advertiseWireTls = false`. The conflict arm normalizes both. The
`wire-cert` route hides the difference (`chain.isNullOrBlank()`), but
`Datasource.advertiseCertChain` is `""` vs `null` on the wire. Also: the inline
comment at `Datasources.kt:298-301` says the chain is preserved "via COALESCE"
and that a present blank "becomes the empty string" — the SQL uses a `CASE` and
`NULLIF(…, '')`, so it becomes NULL. Stale comment; port the SQL, not the
comment.

Minor: `catalogCleared` is `catalog_synced_at IS NULL` _after_ the upsert, so it
is also true for a fresh insert and for an existing row that was simply never
synced. The `DELETE` is idempotent, which is what makes that harmless — **keep
it idempotent**.

#### `markSeen(id)`

`UPDATE datasource SET last_seen_at = now() WHERE id = ?`. Called when a proxy's
Events stream opens (A10 `ControlPlaneGrpcService.kt:525,531`).

#### `data class PushedColumn(schema, table, column, dataType, ordinal, nullable)` · nested

The gRPC `Column` shape, one per introspected column.

#### `storePushedCatalog(id, defaultSchemas, mysqlLowerCaseTableNames, engineVersion, columns): Int`

Hand-rolled transaction, four ordered steps:

1. `SELECT id FROM datasource WHERE id = ? FOR UPDATE` with
   `check(rs.next()) { "datasource $id disappeared before catalog push" }`.
2. `DELETE FROM catalog_column WHERE datasource_id = ?`.
3. Batch
   `INSERT INTO catalog_column (datasource_id, schema_name, table_name, column_name, data_type, sql_type, ordinal, nullable)`,
   `sql_type = sqlTypeFor(col.dataType)`.
4. `UPDATE datasource SET default_schemas = ?::jsonb, mysql_lower_case_table_names = ?, engine_version = ?, catalog_synced_at = now() WHERE id = ?`
   with `check(executeUpdate() == 1)`. `engineVersion.ifBlank { null }`.

Returns `columns.size`.

🔒 **INV-A5-15 — the row lock serializes concurrent pushes; without it the
UNIQUE trips.** Quoted: "Lock the datasource row so concurrent pushes (multiple
proxy replicas fronting one name) serialize instead of interleaving their
DELETE/INSERT — otherwise the second push's insert races the first's delete and
trips the `(datasource, schema, table, column)` UNIQUE. Also doubles as the
disappeared-datasource check."

**INV-A5-16 — replace, never merge.** Delete-then-insert in one transaction is
what makes a dropped table disappear from the catalog. A Go port using upserts
would leave removed columns behind forever, and a dropped-then-recreated table
would keep stale classifications resolving.

#### `create(input): Datasource`

Plain
`INSERT INTO datasource (name, engine, host, port, db_name) … RETURNING id`,
then `get(id)!!`. No engine validation here — **the route validates**
(`engineFromWireOrNull`) before calling. A Go port that exposed `create` to
another caller would lose that.

#### `private invalidateCatalog(c, id)`

`DELETE FROM catalog_column WHERE datasource_id = ?` +
`UPDATE datasource SET catalog_synced_at = NULL, default_schemas = '[]'::jsonb, mysql_lower_case_table_names = NULL WHERE id = ?`.
Shared by `register`'s retarget (inline, not via this helper) and `update`'s
admin `db_name` change.

#### `update(id, input): Datasource?`

Hand-rolled transaction: `SELECT engine, db_name … FOR UPDATE` (null ⇒ rollback,
return `null`) → `prior.engine != input.engine` ⇒
`DatasourceEngineConflictException` → `UPDATE name, engine, host, port, db_name`
→ `if (prior.dbName != input.dbName) invalidateCatalog(c, id)` → commit.

Note the kdoc's containment argument: "The admin update surface is not a bypass:
the web edit form seeds engine from the current value, so a normal edit carries
the unchanged engine and never trips this." The route's `engineFromWireOrNull`
canonicalization exists for exactly this — "otherwise a PUT carrying 'Postgres',
'postgresql', or the `DatasourceInput` default 'postgres' would be compared
verbatim against the stored canonical engine and spuriously trip the
immutability guard."

⚠️ Minor inconsistency: the exception is constructed with `input.name` (the
**new** name), while `register` uses the stored name. The 409 body carries no
name, so this only affects logs.

⚠️ **F21 candidate (security-relevant, untested).** `update` and `delete` clear
the **persisted** catalog but never touch the in-memory
`ConnectionCatalogRegistry`. Only the gRPC `Register` path calls
`connectionCatalog.invalidateDatasource` — and it is **doubly guarded**
(`ControlPlaneGrpcService.kt:363-369`, read this session):

```kotlin
val priorDbName = core.datasourceStore.getByName(request.name)?.dbName   // :342, BEFORE the register
…
if (priorDbName != null && priorDbName != ds.dbName) {                   // :363
    val dropped = core.connectionCatalog.invalidateDatasource(ds.name)
```

The `priorDbName != null` half is the sharp edge, and it makes F21 **worse**
than "admin surfaces forgot to call it": a datasource registering under a name
that has no row yet has `priorDbName == null`, so `invalidateDatasource` is
**never** called on a fresh registration. Rename-or-delete frees a name, the
authoritative entries keyed by that name survive, and the _new_ target's
`Register` takes the `priorDbName == null` path and inherits them wholesale.
There is no db_name comparison to save it, because there is no prior row to
compare against. The registry's own kdoc states why the call exists at all: "a
connection opening afterwards would otherwise adopt structure measured from the
database that is no longer there, and decide against a catalog its backend never
had." Because `authoritative` is keyed by **datasource NAME**, an admin `PUT`
that _renames_ a datasource — or a `DELETE` — frees the name while leaving its
authoritative entries and pooled fragments in place. A different target
registering under the freed name then inherits them, and on MySQL
(`catalogIsConnectionIndependent = true`) the next connection **adopts** that
structure with no fetch. Nothing sweeps orphaned `authoritative` entries either,
so they are also an unbounded leak. Details in §10 Q1.

#### `delete(id): Boolean`

`DELETE FROM datasource WHERE id = ?`, `rows > 0`. `catalog_column` and
`column_classification` cascade (`ON DELETE CASCADE`, V2).

#### `test(datasource, proxyAttached): TestResult`

A **creds-free liveness report**, not a dial:
`catalogState = catalogSyncedAt?.let { "catalog synced $it" } ?: "catalog not synced"`,
`seenState = lastSeenAt?.let { "last seen $it" } ?: "never seen"`, then
`TestResult(proxyAttached, "<proxy attached|no proxy attached>; $catalogState; $seenState")`.

⚠️ **l10n gap (candidate finding, analogous to F13).** `TestResult.message` is
English prose on the wire, which `AGENTS.md` says never happens outside SCIM. A
Go port should keep the field for compatibility but the strings are not
localizable as written.

#### `catalog(id)` / `catalog(id, c): List<CatalogColumn>`

```sql
SELECT CASE WHEN lower(d.engine) = 'mysql' THEN 'def' ELSE d.db_name END AS catalog_name,
       c.schema_name, c.table_name, c.column_name, c.data_type, c.sql_type, c.ordinal, c.nullable,
       cl.tags, cl.mask_fn_id, m.name AS mask_fn_name
FROM catalog_column c
JOIN datasource d ON d.id = c.datasource_id
LEFT JOIN column_classification cl ON cl.datasource_id = c.datasource_id AND cl.schema_name = c.schema_name
                                  AND cl.table_name = c.table_name AND cl.column_name = c.column_name
LEFT JOIN mask_fn m ON m.id = cl.mask_fn_id
WHERE c.datasource_id = ?
ORDER BY c.schema_name, c.table_name, c.ordinal
```

`classification` is non-null **iff `cl.tags` is non-null** (i.e. a
`column_classification` row exists) — a column with a row but empty tags still
gets a `Classification` with `tags = []`.

🔒 **INV-A5-17 — `ORDER BY … ordinal` is a masking guarantee, not cosmetics.**
Column order is what fixes mask ordinals for the proxy's inline result
rewriting. `structuralRows` re-sorts for the same reason (INV-A5-27).

#### `wireCertChain(id): String?`

`SELECT advertise_cert_chain FROM datasource WHERE id = ?`. See INV-A5-10's
contradiction note.

#### `classificationsFor(id): Map<Triple<schema,table,column>, Classification>`

`SELECT … FROM column_classification cl LEFT JOIN mask_fn m … WHERE cl.datasource_id = ?`.
Kdoc: "Live classification metadata keyed independently of `catalog_column`.
Enforcement fragments provide the structural rows; classifications remain
CP-owned and can change without a connection re-introspection." This is the
enforcement path's classification source (`decideConnection`).

🔒 **INV-A5-18 — structure and classification are independently sourced.**
Structure comes from the connection's fragment; classification from Postgres. A
newly-tagged PII column therefore takes effect on the **next statement**, with
no proxy round-trip. Joining them (as `catalog()` does) on the enforcement path
would make a classification change wait for a catalog push.

#### `defaultSchema(id)` / `defaultSchema(id, c): String?`

`get(id, c)?.defaultSchemas.firstOrNull { !engine.isSystemSchema(it) }` — the
first **non-system** entry of the ordered default-schema list. Null when the
list is empty (never introspected) or all-system.

#### `upsertClassification(id, input[, c]): Classification`

1. `input.tags.firstOrNull { it.startsWith(RESERVED_TAG_PREFIX) }` ⇒
   `IllegalArgumentException("tag '<t>' is reserved: the 'system:' namespace is owned by system classification")`.
2. `schema = input.schema ?: defaultSchema(id, c) ?: IllegalArgumentException("schema is required until datasource introspection captures a default schema")`.
3. `INSERT … ON CONFLICT (datasource_id, schema_name, table_name, column_name) DO UPDATE SET tags = EXCLUDED.tags, mask_fn_id = EXCLUDED.mask_fn_id, updated_at = now()`.
4. Returns
   `Classification(schema, table, column, tags, maskFnId, maskFnName(maskFnId, c))`.

🔒 **INV-A5-19 — the reserved-prefix guard exists at BOTH layers,
deliberately.** `DatasourceManagementService` (A11) checks it first and throws
`ManagementException(ApiError("datasource.reserved_tag"))`; the store checks
again and throws a bare `IllegalArgumentException`. The store copy is the
backstop for a non-HTTP caller. ⚠️ Consequence: the store's exception is not a
`ManagementException`, so it has **no `respondManagementError` mapping** and
would fall through to `App.kt:452`'s `exception<Throwable>` handler as **500
`common.fallback`** — losing both the status and the `{tag}` param. Currently
unreachable via HTTP (the management layer at `ManagementServices.kt:135-137` /
`:155-157` always checks first). Candidate finding (duplication with divergent
error types). The same fall-through applies to the store's
`"schema is required until datasource introspection captures a default schema"`
throw, whose HTTP-visible counterpart is `datasource.schema_required` (400).

`private maskFnName(id, c)`: `SELECT name FROM mask_fn WHERE id = ?`, null for a
null id or a missing row — so a dangling `maskFnId` yields `maskFnName = null`
rather than an error.

#### `deleteClassification(id, schema, table, column[, c]): Boolean`

`DELETE … WHERE datasource_id=? AND schema_name=? AND table_name=? AND column_name=?`,
`rows > 0`. Requires an explicit `schema` — the _management_ layer resolves the
default (A11).

#### Private helpers

`setNullableLong` / `setNullableInt` (`setNull(idx, Types.BIGINT|INTEGER)`) ·
`ResultSet.longOrNull(col)` (`getLong` + `wasNull`) · `ResultSet.intOrNull(col)`
— ⚠️ **dead: zero call sites** (`toDatasource` inlines the same
`getInt(...).let { if (wasNull()) null else it }`). Candidate finding
(`05-datasources-catalog.md:611`); disposition **OMIT** — private helpers with
no call path, so there is no observable behaviour to preserve. Sweep the test
tree for fixture uses before dropping them: several "dead" symbols elsewhere
(A3's `setUserActive`, `find…ByExternalId`) turned out to be live test fixtures,
and those are REPRODUCE-as-test-helper, not OMIT.

### Route-file gates and helpers

#### `suspend fun ApplicationCall.requireApi(config): Boolean` · public

`if (!config.authDebug && userSession() == null) { respond(401, ApiError("common.unauthenticated")); false } else true`.

⚠️ **Cross-area:** this is _the_ generic authenticated-session gate, used by
`App.kt`, `QueryHistory.kt`, `Policies.kt`, `Query.kt`, `Access.kt`,
`AuditRoutes.kt`, `Approvals.kt` — but it is **declared in `Datasources.kt`**. A
Go port should hoist it somewhere neutral — a **file-placement** decision, not a
behaviour one: the gate itself is REPRODUCE, byte-for-byte, including the
`authDebug` short-circuit and the `common.unauthenticated` body. It answers "is
there a session", never "is this allowed" — that is A2's
`requireAdmin`/`requireAuthz`.

#### `suspend fun ApplicationCall.idParam(): Long?` · public

`parameters["id"]?.toLongOrNull()`. Used by 8 route files.

#### `internal suspend fun ApplicationCall.respondManagementError(exception: ManagementException)`

Maps `exception.error.code` → status:

| Code                                                                         | Status              |
| ---------------------------------------------------------------------------- | ------------------- |
| `common.not_found`                                                           | 404                 |
| `datasource.table_introspection_failed`                                      | **502 Bad Gateway** |
| `group.system_immutable`, `role.system_immutable`, `policy.system_immutable` | 409                 |
| anything else                                                                | 400                 |

The 502 is the honest status for "we asked the proxy and the proxy failed" — the
control-plane is a gateway to the target, and a 500 would blame the wrong
component.

#### `private fun ApplicationCall.bearerWirePrincipal(tokenStore, userGroupStore): String?`

1. `Authorization` header absent ⇒ null.
2. Not `Bearer ` (case-insensitive) ⇒ null;
   `substring(7).trim().ifBlank { return null }`.
3. `tokenStore.resolve(token)` ⇒ null if unresolvable (A4: also enforces
   not-revoked, not-expired).
4. `TokenKind.fromWire(id.kind)` must be `SESSION` or `USER` — **not**
   `EDITOR`/`APPROVER_EXEC`.
5. `userGroupStore.isDeactivated(id.principal)` ⇒ null.

🔒 **INV-A5-20 — the Bearer path is discovery-only and cannot bootstrap
credentials.** Quoted: "Only native-wire kinds (SESSION/USER) count, and this is
wired ONLY into the read-only datasource GET routes — never mutations or token
mint — so a leaked wire token cannot bootstrap more credentials through the API.
Roles are still resolved server-side per principal, so this is a new
**authentication** surface, not a privilege grant." Both the function and
`requireApiOrBearer` are `private` — "PRIVATE by design … so no other route file
can reach it (compiler-enforced scope)". A Go port must reproduce the _scoping_,
not just the logic.

🔒 **INV-A5-21 — a deactivated principal fails closed even with a live token
row.** Quoted: "matches the gRPC decide path (a SCIM `active=false` push or a
failed IdP liveness recheck can mark the `app_user` inactive without the
credential revoke having raced in yet)."

#### `private suspend fun ApplicationCall.requireApiOrBearer(config, tokenStore, userGroupStore): String?`

`userSession()?.principal` → `bearerWirePrincipal(...)` →
`if (config.authDebug) "debug-user"` → else
`respond(401, ApiError("common.unauthenticated")); null`. See INV-A5-3.

#### `fun mayConnect(call, principal, ds): Boolean` — local closure inside `datasourceRoutes`

1. `config.authDebug` ⇒ true.
2. `roles = roleResolver.resolve(principal)`;
   `raw = call.httpAuthzContext(config)` (A12).
3. `tags = authz.resolveContextTags(principal, roles, ds.name, raw, ds.tags)` —
   A2 pass 1.
4. `authz.authorizeDatasourceAction(principal, roles, DATASOURCE_CONNECT, ds.name, raw.copy(tags = tags), ds.tags) !is AuthzDecision.Deny`.

Note it resolves roles **once** and threads that snapshot through both passes,
matching A2 INV-A2-10.

#### `private val datasourceLog`

`LoggerFactory.getLogger("com.ridi.oss.proxymonster.controlplane.Datasources")`
— used only for the `inspectTrustChain` warning on the `wire-cert` route.

🔒 **INV-A5-22 — trust material is inspected and served, never withheld.** The
route calls `inspectTrustChain(chain)` (A10, `ControlPlaneGrpcService.kt:556`)
and **logs** a warning; it still serves the bytes. Quoted: "Served whatever it
looks like. The client verifies, and it is the only party that can report a
meaningful error about its own trust store — withholding the file just leaves
the operator with nothing to install and no way to see why." ⚠️ The route's own
kdoc (`Datasources.kt:888-890`) contradicts the code, describing a "409 rather
than 500" re-validation refusal that does not exist. Its premise — "Registration
already refuses a chain that does not chain" — is **also false**:
`ControlPlaneGrpcService.kt:325-341` warns and registers anyway ("The advertised
chain is inspected, never refused … Rejecting at registration costs far more
than it buys: the datasource never gets created at all, so no catalog is pushed
and every decision fails closed — a total outage in place of one client's TLS
error"), and `TrustChainInspectionTest.kt:9` states the rule flatly:
"`inspectTrustChain` REPORTS on trust material; it never gates." Candidate
stale-doc finding — the whole paragraph is wrong, not just the status code.

---

## 5. Symbols — `ConnectionCatalog.kt` (the ephemeral enforcement catalog)

The hardest part of the area. Design statement (`ConnectionCatalog.kt:100-104`):
"Ephemeral, fail-closed enforcement catalog state. The wire exposes
datasource/principal/token-kind but **no proxy-instance identifier**, so
`Binding` binds exactly those authoritative fields; `backend_generation` binds
the first backend-connection instance that successfully pushes and thereafter
advances monotonically."

### Constants

- `private const val CONNECTION_ID_BYTES = 16`.
- `private const val DEFAULT_STALENESS_NANOS = 15L * 60 * 1_000_000_000` (15
  minutes). Reason, in full: "the backstop for drift the control plane never
  learned about — DDL run straight against the backend, which no push reports …
  Set **above** the proxy's ambient refresh interval, which re-reads the whole
  backend catalog and, through `recordAmbientMeasurement`, re-measures the
  pooled fragments it still agrees with. That cycle is what detects out-of-band
  DDL; this bound is the ceiling for a connection whose schemas the refresh did
  not confirm, so it only has to sit far enough above the interval that an
  ordinary slow or skipped cycle does not put a full fetch in front of a user's
  query."

### Value types

| Type                    | Fields                                                                                                                                                                                            | Notes                                                                                                                                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ContentHash`           | `bytes: ByteString`                                                                                                                                                                               | "**ByteString is required**: raw `ByteArray` has reference equality." In Go, a `[N]byte` array or a string is comparable; a `[]byte` is not — this is the single easiest map-key bug to introduce |
| `FragmentColumn`        | `schema, table, column, dataType, ordinal: Int, nullable: Boolean`                                                                                                                                | the six enforcement-relevant fields; value equality is used for content comparison                                                                                                                |
| `PoolKey`               | `scope: String, schema: String, hash: ContentHash`                                                                                                                                                |                                                                                                                                                                                                   |
| `SchemaFragment`        | `key: PoolKey, hash: ContentHash, columns: List<FragmentColumn>`                                                                                                                                  | immutable                                                                                                                                                                                         |
| `PooledFragment`        | `fragment: SchemaFragment, refCount: Int`                                                                                                                                                         |                                                                                                                                                                                                   |
| `Authoritative`         | `hash, pooledRef: PoolKey, epoch: Long, measuredNanos: Long`                                                                                                                                      | per (datasource, schema)                                                                                                                                                                          |
| `Binding`               | `datasourceName, principal, tokenKind`                                                                                                                                                            | value-equal; the whole identity of a connection                                                                                                                                                   |
| `HeldSchema`            | `pooledRef, hash, lastFetchNanos, lastVerifiedNanos, revalidatedAgainstAuthoritativeHash: ContentHash?`                                                                                           | per (connection, schema)                                                                                                                                                                          |
| `PendingRefetch`        | `expectedHash: ContentHash?, authoritativeAtIssue: ContentHash?`                                                                                                                                  | the push CAS token                                                                                                                                                                                |
| `OpenConnection`        | `connectionId: ByteString, onOpen: List<Refetch>`                                                                                                                                                 |                                                                                                                                                                                                   |
| `EnforcementConnection` | `connectionId, binding, held: MutableMap (LinkedHashMap), pending: MutableMap (LinkedHashMap), var backendGeneration: Long?, var generation: Long = 0, mutex: Mutex, @Volatile var lastUsedNanos` | mutable, guarded by its own `mutex`                                                                                                                                                               |
| `CatalogMutationResult` | `Applied(generation: Long)` \| `Rejected(code: Status.Code, description: String)`                                                                                                                 | gRPC status is mapped by A10                                                                                                                                                                      |

🔒 **INV-A5-23 — `measuredNanos` lives on `Authoritative`, never on
`PooledFragment`.** Quoted: "It lives here rather than on `PooledFragment`
because identical content is pooled once and shared across datasources, while
**a reading only ever speaks for the backend it came from**." Moving it to the
pooled fragment lets one datasource's refresh vouch for another datasource
nobody read. `PerConnectionCatalogStateTest` case 16 is the regression test.

### `private fun refetchOf(schema, hash: ContentHash?): Refetch`

Proto `Refetch { schema; if_hash_differs }`. **An absent hash leaves
`if_hash_differs` empty = unconditional fetch = fail-safe.**

### `class ConnectionCatalogRegistry(clockNanos = System::nanoTime, secureRandom = SecureRandom(), internal val stalenessNanos = DEFAULT_STALENESS_NANOS)`

State:

- `pool: ConcurrentHashMap<PoolKey, PooledFragment>`
- `authoritative: ConcurrentHashMap<Pair<String,String>, Authoritative>` —
  (datasourceName, schema)
- `connections: ConcurrentHashMap<ByteString, EnforcementConnection>`
- `authoritativeEpoch: AtomicLong`
- `private val stateLock = Any()` — the **global monitor**

🔒 **INV-A5-24 — two lock levels, and the reason.** Quoted: "A full push
transitions both the held and authoritative references. **The global monitor
makes those multi-map transitions atomic**; every individual reference-count
mutation still occurs under `pool.compute`." Per-connection ordering is the
`EnforcementConnection.mutex` (a _coroutine_ mutex, so suspending); cross-map
atomicity is `synchronized(stateLock)` (a _blocking_ monitor, never held across
a suspension point). **Go shape:** a `sync.Mutex` for `stateLock` plus a
per-connection `sync.Mutex`; the ordering is always connection-mutex **then**
stateLock, never the reverse.

#### `open(binding, schemas, adoptHeldContent = false): OpenConnection`

`while (true) { 16 random bytes → ByteString; if (connections.putIfAbsent(id, conn) == null) return OpenConnection(id, issueInitial(...)) }`.

🔒 **INV-A5-25 — connection ids are 16 CSPRNG bytes with a collision retry
loop.** `PerConnectionCatalogStateTest` case 1 drives a stubbed `SecureRandom`
that returns the same 16 zero bytes twice, then a distinct value, and asserts
both minted ids are 16 bytes and differ. A Go port must keep the retry:
`putIfAbsent`-style insertion + loop, never "generate and assume unique". A10
additionally rejects any `connection_id` whose length ≠ 16 at the RPC boundary.

#### `recover(connectionId, binding, schemas, adoptHeldContent = false): OpenConnection?`

"Recreate a well-formed id after CP restart; **an already-live id is never
overwritten**." Returns `null` when `putIfAbsent` finds an existing entry (A10
maps that to `ABORTED`).

🔒 **INV-A5-26 — recovery never adopts an id that is already live.** Overwriting
would give a second caller a connection record whose `held`/`pending` state the
first caller is mid-flight on.

#### `private issueInitial(connection, schemas, adoptHeldContent): List<Refetch>`

Inside `synchronized(stateLock)`; `schemas.filter { isNotBlank() }.distinct()`:

- If `adoptHeldContent && auth != null && pooled != null`:
  `retain(pooled.fragment, 1)`, then
  `connection.held[schema] = HeldSchema(auth.pooledRef, auth.hash, lastFetchNanos = auth.measuredNanos, lastVerifiedNanos = auth.measuredNanos, revalidatedAgainstAuthoritativeHash = null)`
  and emit **no** command.
- Else `connection.pending[schema] = PendingRefetch(auth?.hash, auth?.hash)` and
  emit `refetchOf(schema, expectedHash)`.

🔒 **INV-A5-27 — adoption inherits the ORIGINAL measurement time, not `now()`.**
Quoted verbatim: "`lastVerifiedNanos` carries the original measurement time
rather than now: **the staleness gate must keep counting from when the backend
was actually read, or a stream of new connections would refresh the clock
forever and the bound would never fire.**" This is the single most important
non-obvious line in the file. `PerConnectionCatalogStateTest` case 8 exists
solely for it.

**INV-A5-28 — adoption removes redundant work, never the first measurement.** "A
schema with nothing held still gets its fetch." Pinned by case 12.

⚠️ `issueInitial` filters **only blank** schemas — it does **not** filter
`pg_temp*`, unlike `freshnessGate` and `markPending`. See §10 Q2.

#### `find(connectionId): EnforcementConnection?`

Bare map lookup, no mutex, no `lastUsedNanos` touch. Used by A10 to pre-check
the binding before `decideConnection`, and by tests.

#### `suspend fun <T> withConnection(connectionId, block): T?`

1. `connections[id] ?: return null`.
2. `connection.mutex.withLock { … }`.
3. **Re-check identity inside the lock**:
   `if (connections[id] !== connection) return null`.
4. `connection.lastUsedNanos = clockNanos()`, then `block(connection)`.

🔒 **INV-A5-29 — the post-lock identity re-check is what makes close/sweep fail
closed.** `close` and `sweepIdle` remove from the map **before** clearing state,
so a caller that captured the record earlier must re-verify map identity after
acquiring the mutex or it would operate on a torn-down connection. The same
re-check appears in `applyPush`. Reference (`!==`) identity, not value equality.

#### `suspend fun applyPush(request: SchemaFragmentPush, ds: Datasource): CatalogMutationResult`

Map lookup → `NOT_FOUND "unknown connection_id"`; then under the connection
mutex, re-check identity (→ same `NOT_FOUND`), touch `lastUsedNanos`, delegate
to `applyPushLocked`.

#### `private applyPushLocked(connection, request, ds): CatalogMutationResult`

Validation ladder, in order — every rung is a distinct rejection a Go port must
reproduce:

| #   | Condition                                                                         | Result                                                             |
| --- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| 1   | `request.datasourceName != connection.binding.datasourceName` **or** `!= ds.name` | `FAILED_PRECONDITION "datasource binding mismatch"`                |
| 2   | `request.backendGeneration < 0`                                                   | `INVALID_ARGUMENT "backend_generation exceeds signed range"`       |
| 3   | `connection.backendGeneration != null && request.backendGeneration < bound`       | `FAILED_PRECONDITION "stale backend_generation"`                   |
| 4   | `connection.pending[request.schema] == null`                                      | `FAILED_PRECONDITION "schema push has no pending REFETCH command"` |

⚠️ **Go trap on rung 2.** `backend_generation` is proto **`uint64`**; the JVM
reads it as a signed `Long`, so a value above `2^63-1` arrives negative and this
check catches it. In Go the field _is_ `uint64` and can never be negative — the
port needs an explicit `if req.BackendGeneration > math.MaxInt64` (or to keep
the whole field unsigned end to end, and then adjust rung 3's comparison).
Silently dropping this check widens what the proxy can assert.

🔒 **INV-A5-30 — a push must answer a pending REFETCH.** `pending` is the CAS
token. An unsolicited push is rejected, so the proxy cannot install content the
control-plane never asked for. `PerConnectionCatalogStateTest` case 2 ("pending
is the push CAS and replay cannot regress authoritative") pins the replay case.

**Unchanged branch** (`request.unchanged == true`):

1. `pending.expectedHash == null` ⇒
   `FAILED_PRECONDITION "unchanged push cannot satisfy an unconditional REFETCH"`.
2. `pushedHash != expected` ⇒ `FAILED_PRECONDITION "unchanged hash mismatch"`.
3. Under `stateLock`: `key = poolKey(ds, schema, expected)`; `pool[key] == null`
   ⇒
   `FAILED_PRECONDITION "unchanged push references an unknown pooled fragment"`.
4. `if (previous?.pooledRef != key) retain(pooled.fragment, 1)`.
5. `held[schema] = HeldSchema(key, expected, lastFetchNanos = previous?.lastFetchNanos ?: 0, lastVerifiedNanos = now, revalidatedAgainstAuthoritativeHash = pending.authoritativeAtIssue)`.
6. `if (previous != null && previous.pooledRef != key) release(previous.pooledRef)`.
7. `accept(connection, schema, backendGeneration)`.

🔒 **INV-A5-31 — an unchanged reply cannot satisfy an unconditional first
fetch.** Quoted from the test that pins it (case 13): "A fresh connection whose
schema has no authoritative hash yet is issued an UNCONDITIONAL refetch
(`pending.expectedHash == null`). A proxy that replies `unchanged=true` has
nothing to adopt — this must fail closed, **never silently establish a held
reference with no structure behind it**." A held schema with no fragment would
make `structuralRows` silently omit the schema and every table in it would
resolve as a catalog miss — or worse, resolve to a same-named table elsewhere.

**INV-A5-32 — an unchanged reply is a verification, not a fetch.** Quoted:
"Preserve the separate last-fetch clock (zero for a fresh connection that
adopted a shared fragment)." Two clocks: `lastFetchNanos` (when structure was
actually transferred) and `lastVerifiedNanos` (when the backend last confirmed
the hash). Only the latter drives the staleness gate.

**Full branch** (`unchanged == false`):

1. `columns = request.columnsList.map { FragmentColumn(...) }`.
2. `columns.any { it.schema != request.schema }` ⇒
   `INVALID_ARGUMENT "fragment column schema mismatch"`.
3. Under `stateLock`: `key = poolKey(ds, schema, pushedHash)`,
   `fragment = SchemaFragment(key, hash, columns)`.
4. Pre-check:
   `existing != null && existing.fragment.columns != fragment.columns` ⇒
   `FAILED_PRECONDITION "content hash aliases different fragment columns"`.
5. `retains = (previousHeld?.pooledRef != key) + (previousAuth?.pooledRef != key)`
   (0, 1 or 2).
6. `retained = retain(fragment, retains)` — "**Also performs the alias check
   atomically** with insertion when another thread created the key";
   `retained.fragment.columns != fragment.columns` ⇒ the same
   `FAILED_PRECONDITION`. `retain` does **not** bump the count on that path, so
   nothing leaks.
7. `held[schema] = HeldSchema(key, pushedHash, now, now, null)` — note
   `revalidatedAgainstAuthoritativeHash` is **reset to null** by a full push.
8. `authoritative[(ds.name, schema)] = Authoritative(pushedHash, key, authoritativeEpoch.incrementAndGet(), now)`.
9. Release the two previous pooled refs where they differ from `key`.
10. `accept(...)`.

🔒 **INV-A5-33 — a content hash may never alias different columns.** Two
rejections (a pre-check and an atomic in-`compute` check) close the same hole
from both the single-threaded and racing directions. If a hash could alias, a
proxy that controls the hash input could make the control-plane decide against a
fragment it never measured. `PerConnectionCatalogStateTest` case 17 pins it.

⚠️ **INV-A5-34 — `authoritative` is ACCEPT-ordered, NOT content-monotonic.**
Quoted in full because a port will be tempted to "fix" it: "an accepted push
from a lagging read-replica may legitimately set an older content hash. **This
is a liveness hint, never a correctness input** — every connection decides
against exactly what ITS OWN backend binds (`freshnessGate` re-verifies per
connection). Under a primary+replica pool a lagging push can regress this and
cause bounded `before_decide` churn on siblings (each self-heals in one
round-trip); damping that is a deferred liveness optimization."
`PerConnectionCatalogStateTest` case 4 asserts the epoch advances **and** that a
revert to an older hash wins.

#### `private accept(connection, schema, backendGeneration): Applied`

`pending.remove(schema)` ·
`backendGeneration = maxOf(current ?: pushed, pushed)` (so equal is accepted —
the same backend instance) · `generation++` · `Applied(generation)`.

#### `private poolKey(ds, schema, hash): PoolKey`

```
scope = if (ds.engine.isFixedSystemSchema(schema) && !ds.engineVersion.isNullOrBlank())
            "engine:${ds.engineVersion}" else "ds:${ds.name}"
```

🔒 **INV-A5-35 — only a FIXED system schema pools across datasources, and only
with a known engine version.** A missing/blank `engineVersion` falls back to the
per-datasource scope, so an unversioned datasource can never share content with
anything. `PerConnectionCatalogStateTest` case 14 asserts two datasources on the
same version share one pooled fragment with `refCount == 4` (held×2 +
authoritative×2). ⚠️ The scope string uses the **raw** `engineVersion`, not the
parsed series — `"8.0.44"` and `"8.0.44-log"` would not share. Deliberate
conservatism or oversight; §10 Q3.

#### `private retain(fragment, count): PooledFragment`

`pool.compute(key) { _, current -> when { current == null -> PooledFragment(fragment, count); current.fragment.columns != fragment.columns -> current; else -> current.copy(refCount = current.refCount + count) } }`
and returns the resulting value.

Note the alias arm returns `current` **unchanged** (no bump) — that is what
makes step 6 above safe. The `count == 0` case can only occur when both previous
refs already point at `key`, which implies `current != null`, so a zero-refcount
entry is unreachable **by construction**. A Go port that reorders these steps
can create one.

#### `private release(key)`

`pool.compute`: absent ⇒ null;
`check(current.refCount > 0) { "catalog fragment refcount underflow for $key" }`;
`remaining == 0` ⇒ **remove the entry**, else decrement.

**INV-A5-36 — underflow is a hard failure, not a clamp.** The `check` throws. It
is a "this cannot happen" assertion protecting a refcount that decides whether
structure exists at all; clamping to zero would hide a double-release and
eventually serve an empty catalog. **Go shape:** panic, or a returned error that
callers `must`-handle — not `if n > 0 { n-- }`.

#### `fun freshnessGate(connection, requiredSchemas): Set<String>` — **must be called holding the connection mutex**

Filter `isNotBlank() && !startsWith("pg_temp", ignoreCase = true)`,
`distinct()`, then keep the schema (i.e. **require a refetch**) when **any** of:

1. `connection.pending.containsKey(schema)` — a command is outstanding;
2. `held == null` — nothing held;
3. `auth != null && held.hash != auth.hash && held.revalidatedAgainstAuthoritativeHash != auth.hash`
   — a sibling observed different content and this connection has not yet said
   "mine is unchanged against _that_ authoritative version";
4. `now - held.lastVerifiedNanos > stalenessNanos`.

Returns a `LinkedHashSet` (insertion-ordered).

🔒 **INV-A5-37 — the gate is a disjunction of four independent fail-closed
conditions.** Rule 3 is the subtle one: `revalidatedAgainstAuthoritativeHash`
records **which authoritative version** the connection's "unchanged" reply was
measured against, so one unchanged reply quiets exactly one version and the
**next** authoritative change re-gates. `PerConnectionCatalogStateTest` case 5
and `PerConnectionCatalogAdversarialDbTest` case 2 pin both halves. Collapsing
it into a boolean "revalidated" flag makes a connection permanently immune to
sibling-observed drift.

#### `fun markBeforeDecide(connection, schemas): List<Refetch>`

`markPending` with `PendingRefetch(held?.hash ?: auth?.hash, auth?.hash)` —
prefer the connection's own held hash as the conditional, falling back to the
authoritative one.

#### `fun markCatalogMiss(connection, schemas): List<Refetch>`

`markPending` with `PendingRefetch(null, auth?.hash)` — **expectedHash null ⇒
unconditional fetch**. Kdoc: "A catalog-miss qualifier was never held: force one
bounded unconditional fetch."

🔒 **INV-A5-38 — a catalog miss forces an UNCONDITIONAL fetch.** A conditional
one would let the proxy answer `unchanged` against a hash for content that does
not contain the missing qualifier, and the query would stay denied forever. This
is the consumer of A6 INV-A6-14 (the deny that carries `schemaCandidates`).

#### `fun markAfterStatement(connection, schemas): List<Refetch>`

`markPending` with `PendingRefetch(connection.held[schema]?.hash, auth?.hash)`.

#### `private markPending(connection, schemas, create): List<Refetch>`

Under `stateLock`: filter blank + `pg_temp` (case-insensitive), `distinct()`,
then `pending.getOrPut(schema) { create(schema) }` and
`refetchOf(schema, pending.expectedHash)`.

🔒 **INV-A5-39 — `getOrPut`, never overwrite: "Issue or replay pending
before-decide commands without changing an existing command's CAS token."**
Re-issuing with a fresh `expectedHash` would let a push computed against the old
expectation satisfy the new command. So a replayed command is byte-identical to
the original.

#### `fun structuralRows(connection): List<FragmentColumn>`

Under `stateLock`:
`held.values.flatMap { pool[it.pooledRef]?.fragment?.columns.orEmpty() }` sorted
by `(schema, table, ordinal)`.

**INV-A5-40 — sorted, and the reason is masking.** Quoted: "Sort by (schema,
table, ordinal) so the analyzer catalog + client `SELECT *` expansion follow DB
column order regardless of the proxy's push order — matches
`DatasourceStore.catalog()`'s `ORDER BY ordinal` guarantee as CP-side
defense-in-depth (masks stay self-consistent either way)." Note the
`.orEmpty()`: a held schema whose pooled fragment vanished contributes
**nothing** rather than throwing — combined with INV-A5-31 that is why an empty
held reference must never be created.

#### `fun heldAndFreshSchemas(connection): Set<String>`

`held.keys.filterTo(LinkedHashSet()) { freshnessGate(connection, listOf(it)).isEmpty() }`
— one `freshnessGate` call per held schema (O(n) gate calls, each re-reading the
clock). Minor inefficiency; functionally the per-schema evaluation is
independent so it is correct.

#### `fun recordAmbientMeasurement(datasourceName, columnsBySchema): Set<String>`

Under `stateLock`, for each `(schema, columns)`:
`auth = authoritative[(ds, schema)] ?: continue` ·
`pooled = pool[auth.pooledRef] ?: continue` ·
**`if (pooled.fragment.columns.toSet() != columns.toSet()) continue`** ·
`authoritative[key] = auth.copy(measuredNanos = now)` · `confirmed += schema`.
Returns `confirmed`.

Four documented reasons, all of which must survive the port:

🔒 **INV-A5-41 — it can only CONFIRM content, never install it.** "a schema
whose columns differ is left untouched … Divergence stays the job of the
connection's own probe, which alone knows what that connection's backend binds."
Case 10 pins it.

🔒 **INV-A5-42 — the time is recorded on the AUTHORITATIVE entry, not the pooled
fragment.** "identical system-schema content is pooled once per engine version
and shared by every datasource on it, so writing the time there would let one
datasource's refresh vouch for another's schema that nobody read. Freshness is
evidence about one backend; only the content itself is shareable." Case 16 pins
it.

⚠️ **INV-A5-43 — columns are compared as SETS, not lists.** Quoted: "the
whole-catalog read and the per-schema fragment read are separate statements
whose `ORDER BY` need not agree, and row order is not part of what a fragment
asserts — the decide path sorts for itself. **Comparing lists would silently
stop confirming anything the moment the two orderings diverged, and nothing
would report it.**" A Go port must use set semantics (and note a _duplicate_ row
is therefore invisible to the comparison).

**INV-A5-44 — the whole staleness budget depends on this being called.** The
15-minute ceiling is set above the ambient refresh interval _on the premise that
the refresh keeps pooled content verified_ (case 9's comment: "Without that,
content pooled once would age out no matter how recently the backend was read,
and every new session would refetch"). Called from A10's `pushCatalog` handler.

#### `internal fun measuredNanosFor(datasourceName, schema): Long?`

`authoritative[(ds, schema)]?.measuredNanos`. Used by
`grpc/GrpcRegistrationHandlerDbTest` (A10).

⚠️ **Misplaced KDoc (candidate finding).** The 13-line doc block at
`ConnectionCatalog.kt:458-470` is written for `invalidateDatasource` but sits
**above `measuredNanosFor`**, which has its own one-line doc at 471. Kotlin
attaches only the immediately-preceding comment, so `invalidateDatasource`
(line 475) is undocumented and the long block is dangling. The block's content
is the authoritative rationale for INV-A5-45 and should move with it.

#### `fun invalidateDatasource(datasourceName): Set<String>`

Under `stateLock`: for every `authoritative` key whose first component matches,
`remove` it and `release(auth.pooledRef)`; return the schema names dropped.

🔒 **INV-A5-45 — a retarget must drop authoritative entries, and must NOT touch
live connections.** From the (misplaced) doc: "The persisted catalog is already
cleared on a retarget, because keeping it would authorize the new target against
the old schema. This state is the same hazard: a connection opening afterwards
would otherwise adopt structure measured from the database that is no longer
there, and decide against a catalog its backend never had. Dropping the entries
makes the next connection measure for itself. **Live connections are left
alone** — each already holds its own reference and re-verifies on its own clock,
and tearing their content out mid-session would empty `structuralRows` under an
in-flight statement." Case 15 asserts the next `adoptHeldContent` open gets an
**unconditional** refetch (`ifHashDiffers.isEmpty`) and that the prior holder's
refcount is preserved.

#### `suspend fun close(connectionId, datasourceName): CatalogMutationResult`

1. Absent ⇒ `NOT_FOUND "unknown connection_id"`.
2. Under the connection mutex: `binding.datasourceName != datasourceName` ⇒
   `FAILED_PRECONDITION "datasource binding mismatch"`.
3. `connections.remove(id, connection)` — **remove first**; false ⇒ `NOT_FOUND`.
4. Under `stateLock`: release every held pooled ref, clear `held`, clear
   `pending`.
5. `Applied(connection.generation)`.

🔒 **INV-A5-46 — remove-before-teardown, with the reason.** Quoted: "Remove
first so no new operation can enter after close wins; callers that already
captured this record re-check map identity after acquiring the same mutex and
fail closed" (INV-A5-29's other half). Close is idempotently fail-closed: the
second call returns `NOT_FOUND`, and the datasource's `authoritative` entry
survives (case 17).

#### `suspend fun sweepIdle(maxIdleMillis): Int`

`cutoff = clockNanos() - maxIdleMillis * 1_000_000`; for each connection,
**cheap unsynchronized pre-check** `lastUsedNanos >= cutoff ⇒ continue`; else
take the mutex and **re-check**
`lastUsedNanos < cutoff && connections.remove(id, connection)`, then
release/clear under `stateLock`, `swept++`. Returns the count. Wired in
`App.kt:424` with `60L * 60 * 1000` (1 hour) inside the periodic purge loop,
wrapped in `runCatching`.

**INV-A5-47 — the double-check is required.** The `@Volatile` pre-check is an
optimization only; the authoritative decision is re-made under the mutex,
because `withConnection` bumps `lastUsedNanos` while the sweeper is between the
two reads. **Go shape:** `atomic.Int64` for `lastUsedNanos` (or read it under
the mutex twice); a plain field read races.

#### `internal authoritativeFor(ds, schema)` / `pooledFor(key)` / `poolSize()` / `connectionCount()`

Test-observability accessors. `poolSize`/`connectionCount` have **no non-test
callers**; `pooledFor` and `authoritativeFor` are used only by
`PerConnectionCatalogStateTest`. **A Go port needs equivalents or 17 of its 69
test cases cannot be ported.**

---

## 6. Symbols — `ConnectionDecide.kt`

### `sealed interface EnforcementOutcome`

- `Verdict(ctx: DecisionContext, decisionId: Long, generation: Long, afterStatement: List<Refetch>)`
- `BeforeDecide(commands: List<Refetch>)`

### `suspend fun decideConnection(core, connectionId, principal, ds, sql, searchPath, clientAddr, ansiQuotes = false, channel = Channel.WIRE, providedRoles = null, tempColumns = emptyList(), httpRequesterIp = null): EnforcementOutcome?`

Entire body runs inside
`core.connectionCatalog.withConnection(connectionId) { … }`, so `null` means the
connection disappeared (A10 → `NOT_FOUND`). Steps:

1. **`generationAtEntry = connection.generation`.**
2. `required = searchPath.filterNot { it.startsWith("pg_temp", ignoreCase = true) }`.
3. **Pre-gate:** `freshnessGate(connection, required)`; non-empty ⇒ return
   `BeforeDecide(markBeforeDecide(connection, preGate))` — **before any analysis
   and before any audit row**.
4. `catalogName = ds.engine.catalogName(ds.dbName)`;
   `classifications = datasourceStore.classificationsFor(ds.id)`.
5. Build `catalog: List<CatalogColumn>` from `structuralRows(connection)`, one
   row per fragment column, with `sqlType = sqlTypeFor(row.dataType)` and
   `classification = classifications[Triple(schema, table, column)]`.
6. `t0 = System.nanoTime()`.
7. **`requesterIp` is selected by CHANNEL, never by nullable fallback:**
   `Channel.WIRE → parseRequesterIp(clientAddr)` (A6), everything else →
   `httpRequesterIp`.
8. `ctx = decideQuery(…)` (A6) with
   `context = AuthzContext(requesterIp = requesterIp)`,
   `liveSearchPath = searchPath`, `liveAnsiQuotes = ansiQuotes`,
   `systemClassification`, `tempColumns`, `providedRoles`.
9. **Post-gate:** `freshnessGate(connection, ctx.referencedSchemas)`; non-empty
   ⇒ `BeforeDecide(markBeforeDecide(...))`.
10. **Catalog-miss branch:** if `ctx.catalogMiss`,
    `fresh = heldAndFreshSchemas(connection)`;
    `candidates = ctx.schemaCandidates.filterNotTo(LinkedHashSet()) { it in fresh }`
    — an _order-preserving_ set difference, not a hash-set one, so the emitted
    `Refetch` list keeps `schemaCandidates`' order; non-empty ⇒
    `BeforeDecide(markCatalogMiss(connection, candidates))`.
11. `wireGateDenied = channel == WIRE && !autoApproveTask(principal, ctx.effectiveRoles.toSet(), ds, AuthzContext(requesterIp), authz, WIRE)`
    (A7).
12. `effectiveCtx = if (wireGateDenied) wireTaskForbiddenDeny(ctx.effectiveRoles, ctx.contextTags) else ctx`
    (A6).
13. `afterStatement = if (effectiveCtx.action != DENY && effectiveCtx.catalogChanging) markAfterStatement(connection, required + effectiveCtx.referencedSchemas) else emptyList()`.
14. `ms = (System.nanoTime() - t0) / 1_000_000`; `decisionRecord(...)` (A6).
15. **Audit + task, channel-dependent:**
    - `WIRE`: inside `core.dataSource.inTx { }` —
      `id = auditStore.insert(conn, record)`, then
      **`if (!wireGateDenied) { … }`**, and the DENY-fail step is **nested
      inside that same block**:
      ```
      if (!wireGateDenied) {
          taskId = accessStore.createWireTask(conn, principal, ds.id, ctx.effectiveRoles, id)
          if (effectiveCtx.action == DENY) {
              check(accessStore.claimExecution(taskId, conn)) { "new wire task $taskId was not claimable" }
              check(accessStore.markFailed(taskId, conn))    { "wire task $taskId left EXECUTING" }
          }
      }
      ```
      The nesting is load-bearing and easy to flatten by mistake: when
      `wireGateDenied` is true `effectiveCtx.action` **is** DENY (that is what
      `wireTaskForbiddenDeny` produces), so a Go port with the two `if`s as
      siblings would reach the fail-the-task branch with no `taskId` at all. A
      wire-gate refusal creates **no task**, only the audit row.
    - otherwise: `auditStore.insert(record)` (its own transaction).
16. `check(connection.generation == generationAtEntry) { "connection generation changed during serialized decide" }`.
17. `Verdict(effectiveCtx, decisionId, generationAtEntry, afterStatement)`.

🔒 **INV-A5-48 — the generation stamped on a verdict is exactly the generation
analyzed.** Quoted from the file header: "The registry mutex is held from
freshness pre-gate through audit and verdict emission, so the generation stamped
on a verdict is exactly the generation analyzed (the connection's
compare-and-set on the decision generation)." And from step 1: "only an
`applyPush` (which needs the same mutex) can bump it — impossible mid-flow.
Stamping the entry value and asserting it is unchanged at emit is the
connection's compare-and-set … and guards against a future edit bumping it under
us." **The assertion at step 16 is not redundant defensive code; it is the guard
against a future refactor that releases the mutex.** Keep it.

🔒 **INV-A5-49 — `before_decide` writes NO audit row.** All three `BeforeDecide`
returns happen before step 14/15. `PerConnectionCatalogAdversarialDbTest` case 1
asserts the audit-row count is unchanged across a blocked decision, and
`PerConnectionCatalogDbTest` case 3 asserts a missing search-path fragment
yields `BeforeDecide` with exactly that schema's command. A port that audited
the gate would flood the chain and make every stale-catalog round-trip look like
a decision.

🔒 **INV-A5-50 — two freshness gates, before AND after analysis.** The pre-gate
covers the declared `search_path`; the post-gate covers `ctx.referencedSchemas`,
i.e. schemas the analyzer discovered were actually touched (a fully-qualified
reference outside the search path). Dropping the post-gate lets a statement be
authorized against a schema whose structure was never verified.

🔒 **INV-A5-51 — the catalog-miss refetch is BOUNDED.**
`candidates = ctx.schemaCandidates - heldAndFreshSchemas` means a schema already
held **and fresh** is never re-fetched for a miss, so a genuinely absent table
cannot ping-pong `before_decide` forever: the second attempt has nothing left to
subtract and falls through to the DENY. Reproduce the subtraction exactly.

🔒 **INV-A5-52 — `requesterIp` source is channel-selected, not "whichever is
non-null".** Quoted: "WIRE attests the client socket; editor/workflow channels
use only the HTTP carrier recorded when the CP minted their token." A nullable
fallback would let a WIRE statement inherit some other channel's HTTP IP (or
vice versa) and satisfy a network-gated policy it should not.

🔒 **INV-A5-53 — after-statement refetch only on a non-DENY catalog-changing
statement.** A DENY relayed nothing, so the backend catalog cannot have changed;
issuing a command would leave a `pending` entry that gates the _next_ statement
for no reason. `CatalogRefreshCommandDbTest` (5 cases, MySQL-only —
`EnforcementFixture.mysql()`) pins the `action × catalogChanging` grid plus the
temp-CTAS and bare-`PREPARE` edges.

**INV-A5-54 — the wire decision and its task are written in ONE transaction.**
Quoted: "Keeping the decision and task in one transaction prevents either record
from existing without the other. The extra insert under the audit chain-head
lock is acceptable for this per-statement path's traffic volume." A DENY's task
is failed **inline** because "A DENY relays nothing and produces no completion,
so fail its task inline."

⚠️ Note step 11 passes `ctx.effectiveRoles` (the pre-override context) while
step 15's `createWireTask` also uses `ctx.effectiveRoles`, not `effectiveCtx`'s
— deliberate: `wireTaskForbiddenDeny` synthesizes a deny context and the task
must record the roles actually resolved.

---

## 7. Symbols — `SystemClassificationService.kt`

Control-plane wrapper over the bundled manifests
(`docs/system-classification.md`). The manifest store itself
(`SystemClassificationStore`, `SystemClassifier`, `SystemTag`,
`BaselineDangerousFunctions`) lives in the **engine** module (A13) — not
re-specified here.

### `class SystemClassificationService(store = SystemClassificationStore.load(), allowFallback = false)`

Kdoc, load-bearing: "Loads + validates every manifest once at construction — **a
malformed manifest aborts boot, like a failed migration**. … Keyed off the
STORED `datasource.engine_version` (raw `SELECT version()`

- `(aurora <v>)`), so it is **path-agnostic** — it works identically for a
  proxy-`PushCatalog` datasource and a legacy CP-introspected one, without
  touching either catalog path. A datasource whose version is absent or an
  uncertified major resolves to no manifest → no system tag → the object stays
  deny-by-default (system schemas closed) unless the operator enables the
  nearest-major fallback."

🔒 **INV-A5-55 — a malformed manifest aborts startup.** Construction happens in
`ControlPlaneCore` (A1), so the failure is a boot failure. Booting with a broken
manifest would leave system schemas **unclassified**, and A6's utility path
hard-denies unclassified utilities while its function path treats an
unclassified function as **safe** — i.e. a silent loss of the dangerous-function
floor. Fail fast.

`init` logs the governing set: manifest count, sorted `"<engine>/<series>"`
list, `store.checksum.take(12)` ("to spot a drifted bundle"), and
`uncertified-version-fallback=on|off`. Per-datasource resolution observability
is a documented deferred follow-up.

#### `tagForTable(engine, engineVersion, catalog, schema, table): String?`

`classifierFor(engine, engineVersion)?.classifyRelation(catalog, schema, table)?.id`.
Null when no manifest governs the datasource. Consumed by A6 as the `systemTags`
map feeding A2's `Table` entity parents.

#### `tagForFunction(engine, engineVersion, name): String?`

```
governing   = classifierFor(engine, engineVersion)
manifestTag = if (governing != null) governing.classifyBareFunction(name)
              else noManifestFunctionFloor(engine, name)
baselineTag = BaselineDangerousFunctions.classify(name)
return floor(manifestTag, baselineTag)?.id
```

🔒 **INV-A5-56 — the function model is enumerate-dangerous / allow-safe, and
null means SAFE.** Kdoc: "null when it is an ordinary safe function (a standard
builtin or an unclassified user/UDF) … **Only a non-null (dangerous) result is
marshalled as a Cedar Function** and hits the shipped
`system:data-leak`/`system:critical` forbid." This is exactly A2 INV-A2-11's
caller-side contract: a safe function has no tag and no permit, so marshalling
it would deny-by-default and break every `now()`/user-UDF query.

🔒 **INV-A5-57 — the analyzer emits only BARE function names.** "sqlglot drops
the schema qualifier at parse time, so this resolves it against every
system/logical schema + the cross-schema rules." Hence the MySQL
`mysql.rds_kill` case resolves from the bare `rds_kill` (test case 6), and PG
folds case (case 4).

🔒 **INV-A5-58 — the no-manifest path unions EVERY shipped manifest of the
engine, strongest tag per name.** The reason is recorded as a fixed bug: a thin
hand-curated baseline "missed → a cleartext-PII relay on any pg≠16/17,
mysql≠8.0/8.4 datasource". The union brings "no-manifest function-gating to
PARITY with certified … derived from the manifests themselves so nothing drifts.
Over-classifying a function absent in the datasource's real version is a
harmless over-deny (fail-safe)."

🔒 **INV-A5-59 — the baseline is a FLOOR: it can raise or match, never lower,
and classifies no safe function.** `floor(m, b)` = `b` if `m == null`, `m` if
`b == null`, else `SystemTag.stronger(m, b)`. A **governed** datasource still
gets the baseline unioned in.

#### `private noManifestFunctionFloor(engine, name): SystemTag?`

Iterate `store.classifiersForEngine(engine.wireName)`,
`classifyBareFunction(name)`, reduce with `SystemTag.stronger`. Null when no
manifest of the engine classifies it.

#### `private floor(manifestTag, baselineTag): SystemTag?`

As above.

#### `tagForCommand(engine, engineVersion, command): String?`

`classifierFor(...)?.classifyCommand(command)?.id`.

🔒 **INV-A5-60 — for a UTILITY, null does NOT mean safe.** Kdoc, explicitly
contrasted with functions: "Unlike a function, a null result does NOT mean
'safe': the caller marshals the utility anyway, so an unclassified
**recognized** utility denies-by-default (`Authz.authorizeUtilities`)." The two
nulls have **opposite** meanings, and A6/A2 depend on that. Getting this
backwards in either direction is a security bug: treating a null command as safe
relays `SHOW CREATE USER`; treating a null function as dangerous denies `now()`.

#### `private classifierFor(engine, engineVersion): SystemClassifier?`

`engine.parseServerVersion(engineVersion)` → null version ⇒ null; else
`store.resolve(engine.wireName, version, allowFallback)?.classifier`.

#### `describeManifestFor(engine, engineVersion): String`

Three shapes, for the proxy-registration log (A10 `pushCatalog` calls it):

- `"<engine> (version unreported) → no manifest (system schemas deny-by-default)"`
- `"<engine> <v> → no manifest (uncertified series → system schemas deny-by-default)"`
- `"<engine> <v> → manifest <engine>/<series>"` or
  `"… (FALLBACK — series <requested> uncertified)"`

### `fun Engine.parseServerVersion(raw: String?): Pair<String?, Boolean>` · public top-level

Returns `(versionForResolution, isAurora)`.

1. `raw` null/blank ⇒ `null to false`.
2. `isAurora = raw.contains("aurora", ignoreCase = true)`.
3. **MySQL:**
   `base = raw.substringBefore("mysql_aurora").substringBefore("(aurora")`, then
   `Regex("""\d+\.\d+\.\d+""")` on `base`, falling back to
   `Regex("""\d+\.\d+""")`.
4. **Postgres (and any other value — note the `else` arm, not an explicit
   `POSTGRES` branch):** `Regex("""PostgreSQL\s+(\d+(?:\.\d+)?)""")` group 1,
   falling back to `Regex("""\d+(?:\.\d+)?""")`.

🔒 **INV-A5-61 — never grab the Aurora engine version as the server version.**
The comment records the fixed bug precisely: "Aurora MySQL `version()` embeds
the MySQL major.minor BEFORE a `mysql_aurora` infix — `8.0.mysql_aurora.3.04.0`
→ 8.0, `5.7.mysql_aurora.2.11.4` → 5.7 … Take the base BEFORE either, so the
Aurora engine version (3.04.0) is never grabbed as the server version."
`SystemClassificationServiceTest` case 2 states the consequence: "Before the fix
this returned null (regex grabbed 3.04.0 → no manifest) → classification inert"
— i.e. **system schemas silently unclassified on every Aurora MySQL
datasource**.

Note the asymmetry the tests pin: Aurora MySQL resolves to `"8.0"` (major.minor,
two components, because the three-component regex fails on the truncated base)
while vanilla MySQL resolves to `"8.0.44"` (three components). Both resolve to
the same manifest series. Postgres yields `"17.4"` / `"16.13"`.

⚠️ The `else` arm means `ENGINE_UNSPECIFIED` silently takes the Postgres regex
rather than throwing — the one mapping in the area that is **not**
total-or-throw (contrast INV-A5-4). §10 Q4.

---

## 8. Symbols — `TableDetailExec.kt`

One HTTP admin request ⇄ one proxy-dialed bidirectional gRPC stream. Same
claim-once pattern as A7's `RunExec`, and the source says so explicitly.

### `internal const val TABLE_DETAIL_EXCHANGE_TIMEOUT_MS = 30_000L`

The dial timeout is `DIAL_TIMEOUT_MS = 120_000L`, which lives in `RunExec.kt`
(A7) — a cross-area constant dependency.

### `data class PendingTableDetail(sessionId: String, ready: CompletableDeferred<AttachedTableDetail>)`

### `data class AttachedTableDetail(outbound: SendChannel<ControlTableDetailMsg>, inbound: Channel<ProxyTableDetailMsg>)`

### `class TableDetailChannelRegistry`

`private pending = ConcurrentHashMap<String, PendingTableDetail>()`.

| Method                                              | Behavior                                                                                                                                            |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `register(session)`                                 | `check(putIfAbsent(...) == null) { "table-detail session '<id>' is already registered" }`                                                           |
| `attach(sessionId, outbound): AttachedTableDetail?` | `pending.remove(sessionId) ?: return null`; build `AttachedTableDetail(outbound, Channel(BUFFERED))`; `session.ready.complete(attached)`; return it |
| `remove(sessionId): PendingTableDetail?`            | `pending.remove(sessionId)`                                                                                                                         |

🔒 **INV-A5-62 — claim-once by removal.** `attach` removes the pending entry, so
a second dial with the same session id gets `null` and cannot hijack an
in-flight request's stream. The session id is a `UUID.randomUUID()` minted per
request.

### Exception hierarchy

`sealed class TableDetailExecException(message, cause)` ·
`NoTableDetailProxyAttachedException` ("no proxy is attached to this
datasource") · `ProxyTableDetailTimeoutException` ("the proxy table-detail
channel timed out") · `ProxyTableDetailException(message)`. All three are caught
by A11's `getTableDetail` and mapped to `datasource.table_introspection_failed`
(→ 502).

### `class TableDetailService(private val core: ControlPlaneCore)`

#### `suspend fun fetch(dsName, schema, table): TableDetail?`

1. `core.datasourceStore.getByName(dsName) ?: return null`.
2. **`expectedSchema = datasource.engine.resolveSchema(schema, datasource.dbName)`**
   — "the `\"public\"` default selector maps to this engine's default schema
   (MySQL's database), any other value is an explicit schema/database."
3. `sessionId = UUID.randomUUID()`;
   `pending = PendingTableDetail(sessionId, CompletableDeferred())`.
4. `core.tableDetailChannels.register(pending)`; `registered = true`.
5. `core.proxyEventsHub.requestOpenTableDetail(dsName, sessionId, schema, table)`
   (A12) — `NOT_ATTACHED` **or** `WEDGED` ⇒
   `NoTableDetailProxyAttachedException`. ⚠️ **Note the asymmetry, verified at
   `TableDetailExec.kt:74` vs `:83`:** the **raw, unresolved** `schema` goes
   down the wire to the proxy, while `expectedSchema` (the locally resolved one)
   is what step 8 compares against. The proxy therefore performs the _same_
   `resolveSchema` itself — this is the concrete consumer of §3's "**Mirrors
   `Dialect.ResolveSchema` in the Go proxy** — keep the two byte-identical." A
   port that sends `expectedSchema` instead makes step 8's guard tautological on
   MySQL and can double-resolve; a port whose proxy-side resolution drifts turns
   every `?schema=public` MySQL request into a spurious
   `proxy returned table detail for an unexpected table`.
6. `attached = withTimeout(DIAL_TIMEOUT_MS) { pending.ready.await() }`,
   `TimeoutCancellationException` ⇒ `ProxyTableDetailTimeoutException`.
7. `detail = withTimeout(TABLE_DETAIL_EXCHANGE_TIMEOUT_MS) { collectResponse(attached.inbound) }`,
   same timeout mapping. `null` ⇒ return `null` (→ 404
   `common.not_found{resource:table}`).
8. **Identity check:**
   `detail.schema != expectedSchema || detail.table != table` ⇒
   `ProxyTableDetailException("proxy returned table detail for an unexpected table")`.
9. **Classification overlay:** `core.datasourceStore.catalog(datasource.id)`
   filtered to `it.schema == detail.schema && it.table == detail.table`,
   associated `column → classification`, then
   `detail.copy(columns = detail.columns.map { it.copy(classification = classifications[it.name]) })`.
10. `finally` block — the attach-vs-timeout race resolution, quoted: "Resolve
    the same attach-vs-timeout race as `RunExec`: either `remove` wins while
    pending, or `attach` already completed `ready` and cleanup obtains the
    claimed outbound channel."
    ```
    if (registered && attached == null && core.tableDetailChannels.remove(sessionId) == null)
        attached = withContext(NonCancellable) { pending.ready.await() }
    try { attached?.outbound?.trySend(close) } finally { if (registered) core.tableDetailChannels.remove(sessionId) }
    ```

🔒 **INV-A5-63 — the response must match the RESOLVED schema and the requested
table.** Step 8 is the channel/response-mixup guard. Without it a proxy (or a
crossed stream) could return another table's metadata under the requested name,
and the classification overlay in step 9 would then attach _this_ table's PII
classifications to _that_ table's columns — mislabelling which columns are
sensitive.

🔒 **INV-A5-64 — the finally block must be leak-free in BOTH race directions.**
`NonCancellable` matters: the enclosing coroutine may already be cancelled by
the timeout, and a cancellable `await()` there would skip the close and strand
the proxy's stream. `TableDetailDbTest`'s fake proxy asserts the service "always
closes a claimed stream, including result/error/not-found paths" by blocking on
`outbound.receive()`.

🔒 **INV-A5-65 — table detail is metadata-only and NEVER persisted.**
`TableDetailDbTest`'s route contract asserts, for both engines: the response
body contains no sentinel row value, the JSON has no `rows`/`data`/`preview`
key, `datasourceStore.catalog(id)` is **byte-identical** before and after,
`catalogSyncedAt` is unchanged, and a live-only column (`live_only`, present in
the proxy's detail but not in the pushed catalog) has **0** `catalog_column`
rows afterwards. A port that cached the live detail into `catalog_column` would
let an unauthenticated-to-that-schema decision resolve against structure no push
ever attested.

#### `private suspend fun collectResponse(inbound): TableDetail?`

Iterate the inbound channel:

- `hasResult()`: payload `"null"` ⇒ return `null` (the not-found signal); else
  `Json.decodeFromString<TableDetail>(payload)`, and on exception
  `currentCoroutineContext().ensureActive()` **first**, then
  `ProxyTableDetailException("proxy sent invalid table-detail JSON", e)`.
- `hasError()` ⇒
  `ProxyTableDetailException(message.ifBlank { "proxy table introspection failed" })`.
- `hasSessionReady()` ⇒
  `ProxyTableDetailException("proxy sent TableDetailReady more than once")`.
- else ⇒
  `ProxyTableDetailException("proxy sent an empty table-detail message")`.
- Channel exhausted ⇒
  `ProxyTableDetailException("proxy table-detail stream closed before a terminal response")`.

**INV-A5-66 — `ensureActive()` before wrapping a decode failure.** A
`CancellationException` from the enclosing `withTimeout` would otherwise be
swallowed and re-thrown as "invalid JSON", so a timeout would be misreported as
a malformed proxy response. Same idiom appears in A7. **Go shape:** check
`ctx.Err()` before wrapping an unmarshal error.

---

## 9. Test inventory — 10 files, 2,344 LOC, **69 cases**

Counted with `grep -rhoE '@Test\b' <file> | wc -l` per file; each per-file count
**equals** its enumeration below. Independently re-counted in a second pass:
13+6+6+2+17+3+8+5+4+5 = **69**, LOC 2,344. ⚠️ Two suites
(`PerConnectionCatalogDbContract`, `PerConnectionCatalogAdversarialDbContract`)
are abstract contracts inherited by per-engine subclasses, so JUnit _executes_
more tests than there are `@Test` annotations — the annotation count is what is
reported here, as mandated. ⚠️ Do **not** count with `grep -c '@Test'`:
`@TestInstance(TestInstance.Lifecycle.PER_CLASS)` appears in 6 of these 10 files
and inflates the count (e.g. `GrpcRegistrationHandlerDbTest` reads 23 that way,
22 with `-oE '@Test\b'`). Repo-wide baseline for cross-checking:
`control-plane/src/test` = 847 `@Test`, `engine/src/test` = 56, total **903**;
A5's 69 are all in `control-plane`.

| Suite                                      | LOC | Cases | Kind                                                           |
| ------------------------------------------ | --- | ----- | -------------------------------------------------------------- |
| `EnginesTest.kt`                           | 122 | 13    | unit (pure)                                                    |
| `SystemClassificationServiceTest.kt`       | 147 | 6     | unit (real classpath manifests, no DB)                         |
| `DbSupportMatrixTest.kt`                   | 143 | 6     | unit + one DB/container case                                   |
| `ManifestCommandCoverageDbTest.kt`         | 220 | 2     | **DB** (PG + MySQL)                                            |
| `PerConnectionCatalogStateTest.kt`         | 402 | 17    | unit (in-memory registry, injected clock + `SecureRandom`)     |
| `PerConnectionCatalogDbTest.kt`            | 110 | 3     | **DB** contract × 2 engine subclasses                          |
| `PerConnectionCatalogAdversarialDbTest.kt` | 447 | 8     | **DB** contract (3) × 2 engines + MySQL-only (3) + PG-only (2) |
| `CatalogRefreshCommandDbTest.kt`           | 74  | 5     | **DB** (MySQL)                                                 |
| `TableDetailDbTest.kt`                     | 452 | 4     | **DB** + route (`ktor-server-test-host`) + gRPC stream         |
| `WireCertRouteDbTest.kt`                   | 227 | 5     | **DB** + route                                                 |

### `EnginesTest.kt` — 122 LOC, 13 cases · unit

1. `engineFromWire` accepts the canonical spellings, case-insensitively
2. 🔒 `engineFromWire` is fail-closed on unknown engines and the `postgresql`
   alias (INV-A5-7)
3. `EngineWireSerializer` round-trips as the exact wire string
4. `wireName` and `dialect` are the canonical mappings
5. `catalogName`, `defaultSchema` and `resolveSchema` follow each engine's
   namespace model
6. 🔒 value-returning engine methods fail closed on an unspecified engine
   (INV-A5-4)
7. `systemSchemas` is the concrete enumerable set per engine
8. MySQL system schemas match case-insensitively
9. MySQL non-system schema does not match
10. Postgres system schemas require exact lowercase spelling, unlike MySQL
11. Postgres temp and toast schemas match `isSystemSchema` by prefix but are not
    fixed
12. `isFixedSystemSchema` keeps each engine's casing but drops the prefixes
13. Postgres non-system schema does not match

Cases 7–13 are the `systemSchemas` / `isFixedSystemSchema` / `isSystemSchema`
split — they are what makes `poolKey`'s system-schema decision (INV-A5-35)
reproducible. Port them first; they need nothing.

### `SystemClassificationServiceTest.kt` — 147 LOC, 6 cases · unit (real manifests)

1. 🔒 `parseServerVersion` handles vanilla and Aurora formats (INV-A5-61;
   includes garbage/empty → null)
2. 🔒 Aurora MySQL `3_x` `version()` resolves to the MySQL `8_0` manifest and
   classifies (INV-A5-61 — the fixed bug)
3. Aurora PostgreSQL resolves to the PG major manifest (and no version ⇒ null,
   deny-by-default)
4. 🔒 `tagForFunction` classifies dangerous PostgreSQL builtins from the bare
   name (INV-A5-56/57/58)
5. 🔒 the baseline floor classifies every former `dangerousFuncs` name with or
   without a manifest (INV-A5-59)
6. 🔒 `tagForFunction` classifies dangerous MySQL builtins including Aurora
   `rds_` from the bare name (INV-A5-57)

Cases 4–6 also assert the negative half in every state: `now`, `count`, `lower`,
`concat`, `my_udf` stay **null** governed _and_ un-governed. That negative half
is INV-A5-56 and is as load-bearing as the positive one.

### `DbSupportMatrixTest.kt` — 143 LOC, 6 cases · unit (+1 container)

1. 🔒 every supported target series has a bundled classification manifest and
   vice versa
2. every declared version pins an image of that same series
3. storage engines are postgres only
4. the CI matrix runs exactly the declared versions
5. the shared test containers default to a declared version
6. the running servers are the versions the images asked for (requires Docker)

`db-support.json` currently declares targets `mysql 8.0`, `mysql 8.4`,
`postgres 16`, `postgres 17`, and storage `postgres 16`/`17`. Case 1 is
bidirectional and derives the engine list from what the classifier _ships_, not
from the file — "deriving them from `declared` would make deleting an engine's
last target entry hide its manifests from the comparison instead of failing it."
Case 4 asserts a workflow reads `db-support.json`, sets
`PM_TEST_POSTGRES_IMAGE`/`PM_TEST_MYSQL_IMAGE`, and sets `PM_REQUIRE_DB_TESTS` —
"a Docker-less leg would pass by skipping". **This suite is the mechanism the
index's sequencing note depends on; a Go port must keep an equivalent or the
version matrix silently narrows.**

### `ManifestCommandCoverageDbTest.kt` — 220 LOC, 2 cases · **DB** (PG + MySQL fixtures)

1. 🔒 every manifest dangerous command is gated (or documented passthrough) —
   fail-closed emission guard
2. 🔒 `SELECT INTO OUTFILE` cannot exfil a masked column even with `sql-ddl`
   granted

Case 1 is a **completeness gate over the manifests**, not a fixed list: it
enumerates every `system:critical`/`system:data-leak`/`system:activity` command
id in every shipped manifest and requires each to have either a representative
statement that DENIES or an entry on a 3-item `INTENTIONAL_PASSTHROUGH`
allowlist (`SHOW_VARIABLES`, `SHOW_STATUS`, `PG_SHOW_GUC`, each with a written
reason, `ManifestCommandCoverageDbTest.kt:143-148`). It then decides all **50**
sample statements (`samples`, `:73-140` — recounted; an earlier draft of this
doc said 48) **twice** — once with a certified `engine_version`
(`PostgreSQL 17.4 …` / `8.0.44`), once with `engine_version = NULL` — because "a
typo'd/wrong emitted command id … would pass ONLY the no-manifest branch, not
the certified tag-forbid". Finally it flips the datasource to
`system:development` and asserts `SHOW REPLICA STATUS` (activity) **relaxes to
ALLOW** while `SHOW CREATE USER` and `SHOW GRANTS` (critical) **never** relax —
proving the emitted ids carry the right tag, not merely "some deny". That last
third runs **only** on the certified state, and the source says why:
"No-manifest can't distinguish these — both hard-deny unclassified."

The suite's header records the reason it exists: "Three consecutive access-model
audits each found a DIFFERENT dangerous command that `utilityFacts` failed to
emit — so it relayed verbatim as a passthrough (`SET PERSIST`;
`SHOW CREATE USER`, which leaks the service account's password hash;
`SHOW GRANTS`; `SHOW REPLICA STATUS`). The hand-maintained subset kept leaking."
**This is the highest-value single test case in A5 and it must be ported as a
generated gate, not flattened into a list of expectations.**

### `PerConnectionCatalogStateTest.kt` — 402 LOC, 17 cases · unit

Injected `clockNanos`, injected `SecureRandom`, `stalenessNanos` overridden per
case. No DB, no container.

1. 🔒 minted ids are 16 bytes and collisions retry (INV-A5-25)
2. 🔒 pending is the push CAS and replay cannot regress authoritative
   (INV-A5-30)
3. 🔒 backend generation binds and old pushes reject (rung 3)
4. authoritative ordering follows accepted observation order including revert
   (INV-A5-34)
5. 🔒 a hash marker quiets one authoritative version and retriggers on the next
   (INV-A5-37 rule 3)
6. unchanged adoption shares pooled fragment and refreshes staleness clock
   (refCount 3 = auth + 2 conns)
7. adopting held content opens with no fetch and decides immediately (INV-A5-28)
8. 🔒 adoption inherits the original measurement time so staleness still fires
   (INV-A5-27)
9. an ambient refresh re-measures pooled content so adopters stay fresh
   (INV-A5-44)
10. 🔒 an ambient refresh whose columns differ never overwrites pooled content
    (INV-A5-41)
11. 🔒 adopting retains the pooled fragment so it survives the original holder
    closing (refcount 3→2→1)
12. a schema with nothing held is still fetched when adopting (INV-A5-28)
13. 🔒 unchanged on-open cannot no-op an unconditional first fetch (INV-A5-31)
14. system schema fragments dedup across datasources on the same engine version
    (INV-A5-35; `poolSize()==1`, refCount 4)
15. 🔒 invalidating a datasource forces the next connection to measure for
    itself (INV-A5-45)
16. 🔒 one datasource's ambient refresh cannot vouch for another's schema
    (INV-A5-42)
17. 🔒 same hash with different columns rejects and close is idempotently
    fail-closed (INV-A5-33, INV-A5-46)

**This is the porting critical path for A5.** All 17 cases need only the
registry, a fake clock and a fake RNG — no Docker, no Postgres, no analyzer.
They cover 16 of the area's invariants directly. They also depend on
`authoritativeFor`, `pooledFor`, `poolSize`, `find` and
`EnforcementConnection.held/pending` being observable, so the Go registry must
expose test hooks.

### `PerConnectionCatalogDbTest.kt` — 110 LOC, 3 cases · **DB**

Abstract `PerConnectionCatalogDbContract`, subclassed as
`PerConnectionCatalogMysqlDbTest` and `PerConnectionCatalogPostgresDbTest` (so 6
executions from 3 annotations). Cases 1 and 2 early-return on Postgres.

1. decision uses held structure after global `catalog_column` rows are deleted
   (asserts `generation == 1`)
2. 🔒 `ANSI_QUOTES` threads through `decideConnection` so a double-quoted pii
   column masks
3. missing search path fragment returns before-decide without audit (INV-A5-49)

Case 2's comment states the leak it prevents: with `ansiQuotes = true` the
proxy's observed `sql_mode=ANSI_QUOTES` must reach the analyzer's `EngineConfig`
so `"rrn"` is read as the **masked pii column** and the verdict is MASK; with
the flag false the same SQL is the string literal `'rrn'` and the verdict is
ALLOW. Both directions are asserted **through the real per-connection catalog
path the wire Decide RPC runs**. A Go port that dropped the flag would relay
cleartext on an ANSI_QUOTES session.

### `PerConnectionCatalogAdversarialDbTest.kt` — 447 LOC, 8 cases · **DB**

`PerConnectionCatalogAdversarialDbContract` (3 cases, inherited by both engine
subclasses) + MySQL-only (3, one `@Disabled`) + Postgres-only (2). Each case
drives **real backend connections** through `DriverManager` and pushes fragments
introspected off the caller-owned connection, so transaction-local DDL is
observed.

Contract (both engines):

1. 🔒 ignored after-statement command blocks the next decision without auditing
   it (INV-A5-49, INV-A5-53)
2. 🔒 an unchanged reply quiets one authoritative version and the next version
   re-gates (INV-A5-37 rule 3)
3. 🔒 closing a mutated connection never changes a sibling verdict (asserts
   identical `action`, `masks`, `rewrittenSql`)

MySQL only: 4. 🔒 MySQL implicit-commit DROP cannot leave a stale allow 5.
literal MySQL `CALL` is denied before it can create a stale-catalog window
(asserts `afterStatement` is empty) 6. ⚠️ **`@Disabled`** — allowed MySQL `CALL`
carries after-statement refetch. Reason given: "literal CALL is classified
catalog-changing but the OTHER kind gate makes its ALLOW arm unreachable." The
`@Test` is counted; a Go port should carry the disabled case with the same note
rather than delete it.

Postgres only: 7. 🔒 transaction-local DROP changes bare-name resolution before
commit (after the DROP, the bare `accounts` resolves to `restricted.accounts`
and DENIES — asserted on the deny reason) 8. PostgreSQL SELECT invoking a
function carries after-statement refetch (asserts `ctx.catalogChanging`)

Cases 4 and 7 are the two engine-specific staleness windows the whole registry
exists to close: MySQL's implicit-commit DDL and Postgres's transactional DDL.
They require **both** target engines under Testcontainers and a
`sql.unanalyzable` permit (a bare `DROP TABLE` has no lineage), configured in
each subclass's `configureFlagship()`.

### `CatalogRefreshCommandDbTest.kt` — 74 LOC, 5 cases · **DB** (MySQL)

Drives `decideQuery` directly (A6) but pins the `catalogChanging` **input** to
A5's INV-A5-53.

1. allowed non-temporary DDL carries a catalog refresh command
2. allowed SELECT carries no catalog refresh command
3. denied DDL carries no catalog refresh command
4. allowed **temporary** CTAS carries no catalog refresh command
5. bare `PREPARE` is denied without a catalog refresh command

Case 4 is the interesting one: a `CREATE TEMPORARY TABLE … AS SELECT` is
catalog-changing in the plain sense but MySQL temps never appear in a catalog
scan (INV-A5-6), so no refetch is warranted.

### `TableDetailDbTest.kt` — 452 LOC, 4 cases · **DB** + route + gRPC

A `FakeTableDetailProxy` registers on the real `ProxyEventsHub`, claims the
session through `tableDetailChannels.attach`, replies, and blocks on
`outbound.receive()` to prove the service always closes the stream.

1. 🔒 postgres route assembles proxy detail, overlays classification and stays
   stateless (INV-A5-65)
2. 🔒 mysql route assembles proxy detail, overlays classification and stays
   stateless (INV-A5-65)
3. gRPC table-detail stream claims once and relays both directions (INV-A5-62)
4. 🔒 route validates selectors, rejects identifier attacks and reports proxy
   failures

Case 4 covers: missing `schema` ⇒ 400; missing `table` ⇒ 400; blank either ⇒
400; **no proxy nudge is issued before validation** (asserted by request count);
unknown id with no params ⇒ 400; unknown id with params ⇒ 404; absent table ⇒
404; five SQL/backtick **identifier-injection payloads** in `schema` and `table`
each ⇒ **404, treated as an exact lookup** (never executed, never truncated); a
proxy that returns an error ⇒ **502** with the proxy's message in the body; a
datasource with no attached proxy ⇒ **502**.

Cases 1–2 additionally assert the exact top-level JSON key set, that the
`live_only` column (present in the proxy's live detail, absent from the pushed
catalog) has `classification == null` while `classified_secret` carries
`tags = ["pii"]` and the right `maskFnName`, and that a sentinel row value never
appears anywhere in the body.

### `WireCertRouteDbTest.kt` — 227 LOC, 5 cases · **DB** + route

`authDebug = false` — "the whole point: with it on, every gate short-circuits
and this test proves nothing." Datasources are created through
`DatasourceStore.register`, "the same path the proxy's gRPC Register drives, so
the presence/clear semantics of the chain are exercised rather than bypassed by
a direct INSERT."

1. 🔒 an unauthenticated caller gets 401, never a `debug-user` fallback
   (INV-A5-3)
2. 🔒 an authenticated caller without `datasource.connect` gets 403 (INV-A5-2)
3. a granted caller downloads the advertised chain as a PEM attachment (id-based
   filename)
4. 🔒 a datasource whose proxy published no chain is 404 with its own code
5. 🔒 an unknown datasource id is 404 and is **not** confused with a missing
   chain

Cases 1 and 2 both additionally assert the body contains no `BEGIN CERTIFICATE`.

### Suites that touch A5 but are owned elsewhere

`grpc/GrpcRegistrationHandlerDbTest` (22) and
`grpc/GrpcPerConnectionCatalogDbTest` (11) → **A10**; they are the RPC-boundary
half of `register`/`storePushedCatalog`/`open`/`applyPush`/`close` and of
`measuredNanosFor`. `TrustChainInspectionTest` (7) → **A10**
(`inspectTrustChain` is defined in `grpc/ControlPlaneGrpcService.kt:556`, not
here). `SchemaThreadingDbTest`, `CatalogCoverageGateDbTest`,
`SystemClassificationEnforcementDbTest`,
`BaselineDangerousFunctionEnforcementDbTest`, `UtilityGateDbTest`,
`ScannedTableMySqlTest` → **A6**. `ProvisionMergeDbTest` → **A3**.
`ElevationContextRouteAuthzDbTest` (A6) carries the "catalog browse is gated by
`datasource.connect`" and "datasource list is filtered by connect only when
`connectable` is requested" cases — the only route-level coverage of
`mayConnect` on `/api/datasources` and `{id}/catalog`.

### Fixtures

`support/PerConnectionCatalogFixture.kt` (120 LOC, no `@Test`) is A5-specific
and gates 11 of the DB cases: it turns real target-introspected rows into
fragments and hashes them with
`SHA-256(DataOutputStream(writeUTF schema, table, column, dataType; writeInt ordinal; writeBoolean nullable))`.
That hash is a **test-side** construction — the production hash is the proxy's —
but a Go port of the fixture must produce _some_ stable content hash with the
same collision properties. `support/EnforcementFixture.kt` /
`EnforcementHarness.kt` / `TestDatabases.kt` are shared with A6/A7.

### Coverage gaps in A5

- **F21's mechanism is entirely untested.** No case covers admin `PUT` retarget
  / rename / `DELETE` versus in-memory `authoritative` state.
  `PerConnectionCatalogStateTest` case 15 covers `invalidateDatasource` in
  isolation; nothing covers _who calls it_.
- **`sweepIdle` has zero direct tests** (INV-A5-47's double-check race, and the
  release-on-sweep path). It is the only backstop for a proxy that never sends
  `CloseConnection`.
- **`release`'s underflow `check`** (INV-A5-36) is never exercised.
- **`recover`** is untested at this layer (A10's
  `GrpcPerConnectionCatalogDbTest` may cover the RPC side; the "already-live id
  is never overwritten" branch of INV-A5-26 is the one to verify).
- **`DatasourceStore.register` concurrency**: neither the advisory lock nor the
  `WHERE datasource.engine = EXCLUDED.engine` race backstop (INV-A5-11) has a
  concurrent test — only the sequential fast path, and that is in A10's suite.
- **`storePushedCatalog` concurrent pushes** (INV-A5-15) — the UNIQUE-violation
  race it exists to prevent is not reproduced.
- **`sqlTypeFor`** has no direct test at all; its 40-odd input spellings and the
  `VARCHAR` default arm are only exercised incidentally. Cheap and high-value to
  add (INV-A5-8's idempotence in particular).
- **`test()` / `TestResult`** and `GET /api/datasources/live` have no test.
- **`upsertClassification`'s reserved-prefix guard at the STORE layer**
  (INV-A5-19) is untested; only the management-layer copy is reachable from the
  routes, and A11 reports `ManagementServices.kt` has no dedicated test file at
  all (F19).
- **`defaultSchema`'s "all entries are system schemas" branch** returning null
  is untested.
- **`markCatalogMiss`** has no unit case; it is covered only indirectly through
  A6's enforcement suites. INV-A5-51's bounded-ness (the `- heldAndFreshSchemas`
  subtraction) is the specific thing to pin.
- **`describeManifestFor`'s three output shapes** are untested (log-only, but
  the FALLBACK wording is how an operator learns a datasource is uncertified).
- **`allowFallback = true`** is never exercised — every test constructs
  `SystemClassificationService()` with the default.
- **Three of the nine `else -> error` arms are untested** (INV-A5-4):
  `requireCaseMode`, `isSystemSchema` and `catalogIsConnectionIndependent`.
  `EnginesTest` case 6 covers the other six. `requireCaseMode` is the one worth
  adding — it has _two_ fail-closed paths (the unspecified-engine `error` and
  the `requireNotNull` of INV-A5-5) and neither is pinned.
- **Duplicate-name create/update** (§2's unmapped-500 note, §10 Q12) has no test
  in either direction, so nothing detects a change from 500 to 409 or the
  reverse.
- **`DELETE {id}/classification`'s unconditional 204** (§10 Q13) has no test, so
  a port that starts 404ing on a missing classification would pass the suite.

---

## 10. Open questions

| #   | Question                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | **F21 (new, security-relevant).** Admin `PUT` (rename or `db_name` change) and `DELETE` clear the persisted catalog but never call `connectionCatalog.invalidateDatasource`; only gRPC `Register` does, and only under `priorDbName != null && priorDbName != ds.dbName` (`ControlPlaneGrpcService.kt:363`). Because `authoritative` is keyed by datasource **NAME**, freeing a name (rename/delete) leaves its authoritative entries and pooled refs live; the replacement target's `Register` then sees `priorDbName == null` and so **skips invalidation entirely**, inheriting them — on MySQL (`catalogIsConnectionIndependent = true`) the next connection **adopts** them with no fetch. Nothing sweeps orphaned entries either. Is this a real live gap, and should `invalidateDatasource` move into `DatasourceStore.update`/`delete` (which today has no reference to the registry) or into the management layer? Separately: should the `priorDbName != null` guard become "invalidate whenever a register does not find the same `(name, db_name)` it left behind"? |
| Q2  | `issueInitial` does **not** filter `pg_temp*`, while `freshnessGate` and `markPending` both do (case-insensitively, on the prefix `pg_temp` without the underscore — a fourth spelling versus `Engine.isSystemSchema`'s `pg_temp_`). Net effect: a PG connection is issued a one-time refetch for `pg_temp_N`, whose `pending` entry is then invisible to every gate and never re-demanded. Deliberate (measure temps once, then rely on A6's temp overlay) or drift? Four copies of the `pg_temp` predicate exist — unify or freeze?                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Q3  | `poolKey`'s `"engine:<engineVersion>"` scope uses the **raw** `version()` string, so `8.0.44` and `8.0.44-log` do not share a pooled fragment, and neither do two patch releases in the same series. Should it use `parseServerVersion`'s parsed series instead, or is the conservatism intentional (identical _content_ is the real key, so a wider scope only saves memory)?                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Q4  | `Engine.parseServerVersion` uses an `else ->` arm for Postgres, so `ENGINE_UNSPECIFIED` silently takes the Postgres regex instead of throwing like every other mapping in `Engines.kt` (INV-A5-4). Intentional (the function is defensive by nature) or an oversight?                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Q5  | `Datasource.advertiseCertChain` is in the list/get projection, and `Datasources.kt:59-63` argues for that, but `wireCertChain`'s kdoc (`:525-528`) says the chain is read separately "so a certificate body never rides along in the datasource poll every client makes". Which is the intended design? If the projection stays, `wireCertChain` is a redundant query.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Q6  | `register`'s INSERT arm binds `advertise_cert_chain` raw while the conflict arm normalizes it (`NULLIF(…,'')`, and NULL when TLS is off). So a _fresh_ row can store `''` or can store a chain with `advertise_wire_tls = false`. Intentional or an oversight? A Go port needs a decision, because the two arms produce different wire values for the same input.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Q7  | `Datasources.kt:888-891` documents a re-validation that returns **409** for an unusable chain; the code logs a warning and serves the bytes (INV-A5-22), which `TrustChainInspectionTest`'s own header confirms is the intent ("REPORTS on trust material; it never gates"). Confirm the doc is stale and drop it rather than porting it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Q8  | `TestResult.message` is English prose on the wire, contra `AGENTS.md`'s "errors are never English prose" and A1 INV-A1-13 (same class as F13). Should the Go port emit a code + params instead, and does `web/` parse the string today?                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Q9  | `Engine.leaksDiagnosticsOnAllow` (A6, `Query.kt:188`) is a per-engine mapping outside `Engines.kt`'s declared "single home". Move it, or amend the header comment?                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Q10 | `ResultSet.intOrNull` (`Datasources.kt:664`) has zero call sites; `isMySql`/`isPostgres` have zero **main-source** call sites; `poolSize()`/`connectionCount()` have zero non-test callers. Confirm each and decide delete-vs-keep before porting.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Q11 | `PerConnectionCatalogFixture`'s content hash is a test-side SHA-256 over a `DataOutputStream` encoding (`writeUTF` schema/table/column/dataType + `writeInt` ordinal + `writeBoolean` nullable, `PerConnectionCatalogFixture.kt:108-118` — verified). The **production** hash is computed by the Go proxy. Is that encoding specified anywhere (`goproxy`), and does the CP ever need to recompute it? If not, the Go port's fixture may choose any stable hash — but it must be documented as fixture-only so nobody later assumes the CP can verify a pushed hash.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Q12 | **Duplicate-name 500 (new).** `POST /api/datasources` and `PUT /api/datasources/{id}` do not check `name` uniqueness and catch only `DatasourceEngineConflictException`, so the `datasource.name UNIQUE` violation reaches `App.kt:452`'s `exception<Throwable>` and answers **500 `common.fallback`** instead of a 409 with a code the console can localize. Untested. Keep bug-compatible, or emit `datasource.name_taken` (409) in the Go port?                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Q13 | **Unconditional-204 DELETE (new).** `DELETE {id}/classification` discards `DeleteResult` (`Datasources.kt:961-962`), so removing a classification that does not exist is 204. Intentional idempotence, or should the port report 404 for zero rows? (The store and the management layer both return the boolean/`DeleteResult`, so the information is available and deliberately dropped at the route.)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
