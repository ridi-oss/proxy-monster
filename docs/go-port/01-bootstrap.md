# A1 — Bootstrap, Config, Shared Types

Files: `Main.kt` (69) · `App.kt` (785) · `Config.kt` (307) ·
`ControlPlaneCore.kt` (54) · `Db.kt` (48) · `ApiErrors.kt` (58) · `Decision.kt`
(46). Total 1,367 LOC. Fully read.

## Purpose

Owns process startup, the environment contract, the shared dependency graph, the
HTTP application composition root (plugins, cookies, background timers, route
wiring), and three types used across every other area: `Decision`, `AuditEvent`,
`ApiError`.

---

## 1. Environment contract

Read once by `Config.fromEnv(env: (String) -> String?)`. The `env` lambda is
injected, which is what makes `ConfigGuardTest` able to drive all 25 cases
without touching the real environment — **preserve this seam**; a Go port
reading `os.Getenv` directly loses the whole config test suite.

| Var                                                               | Default                                         | Parse                                  | Notes                                                                                                                |
| ----------------------------------------------------------------- | ----------------------------------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `PM_HTTP_PORT`                                                    | `8080`                                          | int, invalid→default                   |                                                                                                                      |
| `PM_GRPC_PORT`                                                    | `9090`                                          | int, invalid→default                   | `DEFAULT_GRPC_PORT`                                                                                                  |
| `PM_DB_URL`                                                       | `jdbc:postgresql://localhost:5432/proxymonster` | —                                      | **JDBC URL form**; a Go port must accept or translate this exact shape (deploy docs, compose, mise tasks all set it) |
| `PM_DB_USER` / `PM_DB_PASSWORD`                                   | `proxymonster` / `proxymonster`                 | —                                      |                                                                                                                      |
| `PM_AUTH_DEBUG`                                                   | **`true`**                                      | strict bool                            | full auth bypass; default-on                                                                                         |
| `PM_SECRET_TOKEN`                                                 | `null`                                          | —                                      | gates **all** gRPC RPCs + HTTP ingest; null = gate open                                                              |
| `PM_SESSION_SECRET`                                               | `dev-insecure-session-secret-change-me`         | —                                      | cookie MAC key                                                                                                       |
| `PM_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_REDIRECT_URI` | `null`                                          | —                                      | **all four** required or `oidc = null`                                                                               |
| `PM_OIDC_SCOPES`                                                  | `openid profile email groups offline_access`    | —                                      | `offline_access` is load-bearing (refresh token → liveness)                                                          |
| `PM_OIDC_GROUP_MAP`, `PM_OIDC_GROUP_PREFIX`                       | —                                               | `OidcGroupMapping.parse`               | in `auth/` module                                                                                                    |
| `PM_RESULT_KEY`                                                   | `null`                                          | base64 → **exactly 32 bytes**          | null ⇒ approver-exec refused fail-closed                                                                             |
| `PM_SCIM_TOKEN`                                                   | `null`                                          | —                                      | null ⇒ SCIM disabled fail-closed                                                                                     |
| `PM_SESSION_WINDOW`                                               | `7200`                                          | `parseDuration`                        |                                                                                                                      |
| `PM_WEB_SESSION_ABSOLUTE`                                         | `7200`                                          | `parseDuration`                        |                                                                                                                      |
| `PM_WEB_SESSION_IDLE`                                             | `900`                                           | `parseDuration`                        |                                                                                                                      |
| `PM_WEB_SESSION_SLIDE`                                            | `120`                                           | `parseDuration`                        | must be `< idle`                                                                                                     |
| `PM_WEB_SESSION_IDLE_WARN_LEAD`                                   | `60`                                            | `parseDuration`                        | may exceed its window (client clamps)                                                                                |
| `PM_WEB_SESSION_ABSOLUTE_WARN_LEAD`                               | `300`                                           | `parseDuration`                        | may exceed its window                                                                                                |
| `PM_WEB_SESSION_HEARTBEAT`                                        | `90`                                            | `parseDuration`                        |                                                                                                                      |
| `PM_IDP_RECHECK_INTERVAL`                                         | `300`                                           | `toLong` (**not** `parseDuration`)     | must be `> 0`                                                                                                        |
| `PM_DEV`                                                          | `false`                                         | strict bool                            | non-production marker                                                                                                |
| `PM_TRUSTED_PROXIES`                                              | `""` → `∅`                                      | split `,`, trim, drop blank            | socket-peer IPs/CIDRs                                                                                                |
| `PM_MCP_RESOURCE`                                                 | `http://127.0.0.1:8080/mcp`                     | `canonicalMcpResource`                 |                                                                                                                      |
| `PM_WEB_ORIGIN`                                                   | `""`                                            | —                                      | blank ⇒ same origin as `mcpIssuer`                                                                                   |
| `PM_OAUTH_ACCESS_TTL`                                             | `600`                                           | `clampTtlSeconds` (in `auth/`)         |                                                                                                                      |
| `PM_OAUTH_REFRESH_TTL`                                            | `21600`                                         | `clampTtlSeconds`                      |                                                                                                                      |
| `PM_OAUTH_DEBUG_AUTO_CONSENT`                                     | `true`                                          | strict bool                            |                                                                                                                      |
| `PM_QUERY_TIMEOUT`                                                | `600`                                           | `toLongOrNull` — **throws on garbage** |                                                                                                                      |
| `PM_DB_REPAIR_CHECKSUMS`                                          | `false`                                         | `equals("true", ignoreCase)`           | ⚠️ read in `Db.migrate()`, **not** in `Config` — the only env var outside `fromEnv`                                  |

### Validation rules (all fail startup)

| ID     | Rule                                                                                                                                                                                                                     | Source          |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------- |
| V1     | `webSessionSlideSeconds < webSessionIdleSeconds`                                                                                                                                                                         | `Config.kt:100` |
| V2     | `idpRecheckIntervalSeconds > 0` — a zero would busy-loop the liveness sweep (exhausting single-use refresh tokens) or make `delay()` throw and kill the sole revalidator                                                 | `Config.kt:106` |
| V3     | `queryTimeoutSeconds > 0`                                                                                                                                                                                                | `Config.kt:185` |
| V4     | `queryTimeoutSeconds <= 9_223_372_006` (`MAX_QUERY_TIMEOUT_SECONDS`) — identical to the proxy's bound in `goproxy/config/config.go`; keeps the shared-`PM_QUERY_TIMEOUT` lockstep exact and every ms conversion in range | `Config.kt:189` |
| V5 🔒  | `!authDebug ∨ devMarker ∨ (oidc == null ∧ sessionSecret == DEV_SESSION_SECRET)` — refuse to boot with the auth bypass on in a production-_looking_ context                                                               | `Config.kt:199` |
| V6 🔒  | `authDebug ∨ (sessionSecret != DEV ∧ len ≥ 32)`                                                                                                                                                                          | `Config.kt:203` |
| V7 🔒  | `authDebug ∨ oidc != null`                                                                                                                                                                                               | `Config.kt:206` |
| V8 🔒  | `!authDebug ⇒` issuer is HTTPS with no userInfo/query/fragment                                                                                                                                                           | `Config.kt:208` |
| V9 🔒  | `!authDebug ⇒ redirectUri == "$mcpIssuer/auth/oidc/callback"`                                                                                                                                                            | `Config.kt:209` |
| V10 🔒 | `PM_MCP_RESOURCE` is absolute, has a host, no userInfo/query/fragment, path **exactly** `/mcp`, scheme ∈ {http,https}, **https required unless authDebug**; canonicalised to lowercase scheme+host                       | `Config.kt:256` |
| V11    | `PM_RESULT_KEY` base64-decodes to exactly 32 bytes                                                                                                                                                                       | `Config.kt:226` |

V5's rationale is worth carrying verbatim into the Go doc comment: the heuristic
can't be perfect, but it stops the common "forgot to unset `PM_AUTH_DEBUG` in
prod" mistake.

### Derived values

| Name                     | Definition                                                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| `mcpIssuer`              | origin of `mcpResource` (scheme + host + port), trailing `/` stripped. Never inferred from request headers.         |
| `webBaseUrl`             | `webOrigin` trimmed of trailing `/`, or `mcpIssuer` when blank                                                      |
| `queryExchangeTimeoutMs` | `queryTimeoutSeconds * 1000 + 150_000` (`QUERY_EXCHANGE_GRACE_MS`)                                                  |
| `runStreamTimeoutMs(q)`  | `max(900_000, DIAL_TIMEOUT_MS + q + 30_000)` — top-level fn in `Main.kt:19`, must cover the dial _and_ the exchange |

The `QUERY_EXCHANGE_GRACE_MS = 150_000` constant exists so the **proxy's**
watchdog fires first and cancels the statement in-band. Shrinking it makes the
control-plane blame a query for time spent before it started (catalog probes
have been measured in tens of seconds on large remote catalogs).

---

## 2. Symbols

### `parseDuration(raw: String): Long` · internal top-level fn

Kotlin: `internal fun parseDuration(raw: String): Long`

**Contract:** parse a duration to whole seconds; throw
`IllegalArgumentException` on anything invalid.

**Behavior:**

1. Empty ⇒ throw.
2. All-digits ⇒ `toLong()`, must be `> 0`.
3. Otherwise, match `(\d+)([hms])` repeatedly from offset 0. Each match **must
   start exactly where the previous ended** (no gaps, no leading junk) — so
   `1h30m` is valid, `1h x 30m` is not.
4. Multipliers `h`=3600, `m`=60, `s`=1. Accumulate with
   `Math.addExact`/`multiplyExact`.
5. After the loop, `offset == raw.length ∧ total > 0`, else throw.
6. `ArithmeticException` from the exact-math ⇒ rethrow as
   `IllegalArgumentException("duration is too large: …")`.

**Go shape:** must reject what Go's `time.ParseDuration` accepts (`1.5h`,
`300ms`, `-5m`, unit-less) and accept the bare-integer-seconds form it rejects.
Write it by hand; do not delegate. `⟦LIB⟧` none.

### `Config` · data class + `companion.fromEnv`

Contract: immutable, fully-validated snapshot. Constructed by name in ~40 test
files, so **most fields carry defaults** — a Go struct needs an equivalent
"specify only what the test cares about" ergonomic.

`⟦LIB⟧` none required, but note `resultKey: ByteArray?` — Kotlin data-class
`equals` on `ByteArray` is reference identity; no test appears to rely on
`Config` equality, but a Go port using value comparison changes this silently.

### `Db` · class

Kotlin: `class Db(config: Config)`; `val dataSource: DataSource`;
`fun migrate()`

**Behavior:**

1. Pool: JDBC URL/user/password from config, driver hardcoded
   `org.postgresql.Driver`, pool name `pm-control-plane`,
   **`maximumPoolSize = 10`**.
2. `migrate()`: if `PM_DB_REPAIR_CHECKSUMS=true`, run repair first (rewrites
   `flyway_schema_history` rows only — no SQL applied, no schema/data touched),
   then migrate.

**Deps:** `resources/db/migration/V1..V10`.

**Go shape:** connection pool with a size cap of 10 `⟦LIB⟧`; a migration runner
that keeps Flyway's `flyway_schema_history` table shape and versioned-checksum
semantics `⟦LIB⟧`. **Migrating an existing deployment means the Go runner must
read the table Flyway already wrote** — this is a hard compatibility constraint,
not a greenfield choice. Decide in the library discussion whether to keep
Flyway's table or ship a one-time translation migration.

### `ControlPlaneCore` · class

Kotlin: `class ControlPlaneCore(val dataSource: DataSource)`

**Contract:** the single shared enforcement dependency graph, constructed
**once** and used by both the HTTP application and the gRPC service.

🔒 **INV-A1-1 — sharing is mandatory, not an optimization.** `CedarEngine`
caches its compiled `PolicySet` and rebuilds only when
`CedarPolicyStore.stateVersion()` moves; that version is an in-memory
`AtomicLong` bumped on the _same instance_ that commits a policy mutation. Two
graphs ⇒ each keeps its own counter ⇒ a policy edited over HTTP never
invalidates the gRPC-side engine, whose decisions go silently and permanently
stale. One graph → one cache → one counter.

Members (17): `auditStore`, `datasourceStore`, `policyStore`, `accessStore`,
`userGroupStore`, `tokenStore`, `mcpTokenStore`, `roleResolver`,
`cedarPolicyStore`, `cedarEngine`, `authz`, `systemClassification`,
`proxyEventsHub`, `connectionCatalog`, `runChannels`, `tableDetailChannels`,
`runRequesterIps`.

`systemClassification` loads and validates the bundled manifests at construction
— **a malformed manifest aborts startup**.

`runChannels` / `runRequesterIps` live here (rather than in the HTTP module)
specifically because `ControlPlaneGrpcService` is constructed in `Main.kt`
_before_ the HTTP module's `RunExecService` exists.

### `main()` · fn

**Boot sequence — order is contractual:**

1. `Config.fromEnv()`.
2. If `authDebug`, emit the boxed multi-line warning banner (`Main.kt:33-41`).
3. `Db(config)`, then `db.migrate()`.
4. `ControlPlaneCore(db.dataSource)`, then
   `core.accessStore.reconcileOrphanedExecutions()`.
5. `GrpcServer(config.grpcPort, ControlPlaneGrpcService(core, runStreamTimeoutMs), config.secretToken)`,
   `.start()`, register a shutdown hook calling `.shutdown()`.
6. HTTP server on `config.httpPort` with `module(config, core)`, blocking.

🔒 **INV-A1-2 — gRPC bind failure is fatal.** A control-plane that cannot bind
its gRPC port must not come up serving only HTTP with the data plane silently
dead. Step 5 fails the process.

**INV-A1-3** — `reconcileOrphanedExecutions()` runs **twice** (here and in
`module()`, `App.kt:351`). Idempotent by design; the `module()` call is what
makes `testApplication { module() }` exercise it. Keep both.

### `Application.module(config, core)` · fn — the HTTP composition root

**JSON codec** (`App.kt:340`):
`Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }`

🔒 **INV-A1-4 — all three flags are load-bearing and application-wide.**

- `encodeDefaults = true`: the UI relies on
  `effectiveRoles[]`/`rows[]`/`columns[]` being present arrays, never absent.
- `explicitNulls = false`: the co-hosted MCP surface is consumed by the MCP
  TypeScript SDK's strict Zod schemas, which model optional protocol fields as
  `.optional()` (key **absent**), never `.nullable()`. With explicit nulls,
  every `claude mcp login` failed with a bare client-side `invalid_union` and
  zero server-side signal (confirmed against a real session, 2026-07-15).
- A route-scoped override was tried and **rejected**: it broke
  `AuthAndIngestRoutesDbTest`'s catch-all coverage, because a route registered
  via a separate `routing {}` call outside `module()` did not inherit it.

For a Go port this reduces to: **omit optional fields entirely, always emit
empty slices as `[]`.** Naive `encoding/json` gives the opposite of both by
default (`omitempty` drops empty slices; absent pointers marshal as `null`).
Every DTO needs deliberate tags, and this needs a conformance fixture.

**Startup warning (non-fatal):**
`unusableTrustedProxyEntries(config.trustedProxies)` — a malformed entry fails
_closed_ (that hop is untrusted), which presents as "forwarded headers stopped
working" with nothing pointing at the cause. Log it; do **not** refuse to boot,
since a narrower trust set is the safer failure.

**Plugins, in order:** `ContentNegotiation(appJson)` → `CallLogging(INFO)` →
`StatusPages` → `Sessions` (5 cookies) → `Authentication`.

⚠️ **SSE is deliberately NOT installed here** (`App.kt:464`) — the MCP SDK's
stateless streamable-HTTP mount installs it unconditionally and Ktor throws on
duplicate install. `/api/tasks/events` reuses that application-level plugin. **A
Go port that replaces the MCP mount must supply SSE itself.**

**`StatusPages`** — unhandled `Throwable`: log, then

- path starts `/oauth/` **or** equals `/.well-known/oauth-authorization-server`
  ⇒ `500 OAuthError("server_error")`
- else ⇒ `500 ApiError("common.fallback")`

**Cookies** — all five: `path=/`, `httpOnly`,
`secure = mcpIssuer.startsWith("https://")`, `SameSite=Lax`, JSON-serialized,
and MAC-authenticated with `sessionSecret.toByteArray()`.

| Cookie                     | Payload                   | maxAge                      | Purpose                                                                                                                                   |
| -------------------------- | ------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `SESSION_COOKIE`           | `WebSessionRef`           | `webSessionAbsoluteSeconds` | web session; backed by `PrincipalSessionStorage` (server-side store, not a self-contained cookie)                                         |
| `OAUTH_STATE_COOKIE`       | `OAuthStateSession`       | 300                         | CSRF state across the OIDC redirect                                                                                                       |
| `OAUTH_NONCE_COOKIE`       | `OAuthNonceSession`       | 300                         | 🔒 id_token nonce — defends against authorization-code injection                                                                          |
| `DEVICE_VERIFY_COOKIE`     | `DeviceVerifySession`     | 600                         | 🔒 proves the browser viewed `/device` for a specific `user_code`; the only thing binding a device login to SSO (device-phishing defense) |
| `MCP_OAUTH_PENDING_COOKIE` | `McpPendingAuthorization` | 600                         | pending MCP authorization                                                                                                                 |

`⟦LIB⟧` HMAC-authenticated, tamper-evident cookie encoding, byte-compatible with
Ktor's `SessionTransportTransformerMessageAuthentication` **if** existing
browser sessions must survive cutover — otherwise a fresh scheme is fine and
every user re-logs in. **Decide explicitly**; it changes whether cutover logs
everyone out.

**Background timers** — two `launch`ed loops, cancelled on application stop:

_Loop 1, every `RESULT_PURGE_INTERVAL_MS` (15 min)._ Each step wrapped so a
failure logs and does not kill the loop:

1. `deviceLoginStore.purgeExpired()`
2. if result storage configured: `queryResultStore.purgeExpiredEditorChildren()`
   **then** `purgeExpired()`
3. `runExecService.sweepIdleSessions(EDITOR_SESSION_MAX_IDLE_MS = 30 min)`
4. `core.connectionCatalog.sweepIdle(60 min)`

🔒 **INV-A1-5 — step 2's order is mandatory.** `purgeExpired()` NULLs
`expires_at` on every expired child (workflow _and_ editor). An editor sweep
ordered after it would never match its `expires_at <= now` predicate, and
expired editor rows would linger payload-stripped forever.

_Loop 2, every `idpRecheckIntervalSeconds`._ `sweepSessionLiveness(...)` — the
**sole** revalidator for web and daemon sessions. A rejected refresh token
retires only its own session; transient failures preserve cached state.

**Routes declared directly in `module()`** (the rest delegate to 15 route-group
functions):

| Method | Path                      | Gate                                        | Response                                                                                                                        |
| ------ | ------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/health`                 | none                                        | `{status:"ok", diagnostics:[...]}` — diagnostics = `system:admin` has no active assignee, plus `contextTagLint(enabledSources)` |
| GET    | `/auth/config`            | none (public — the login shell needs it)    | `AuthConfigResponse`                                                                                                            |
| POST   | `/api/ingest/decision`    | `X-PM-Ingest-Token == secretToken` when set | `202 {status:"accepted"}`                                                                                                       |
| POST   | `/auth/debug`             | `authDebug` else `404 common.not_found`     | `200 UserSession`                                                                                                               |
| GET    | `/api/me/permissions`     | `requireApi`                                | `MePermissions`                                                                                                                 |
| GET    | `/auth/me`                | `WEB_SESSION_AUTH`                          | `UserSession`, `Cache-Control: no-store`                                                                                        |
| GET    | `/auth/session/status`    | `WEB_SESSION_AUTH`                          | `SessionStatus`, `no-store`                                                                                                     |
| POST   | `/auth/session/heartbeat` | `WEB_SESSION_AUTH`                          | `SessionStatus` or 401                                                                                                          |
| POST   | `/auth/logout`            | none                                        | `LogoutResponse`                                                                                                                |
| SSE    | `/api/tasks/events`       | cookie session                              | `taskEventsRoute`                                                                                                               |

🔒 **INV-A1-6 — `/auth/debug` writes roles to the database, in one transaction
with the session mint.** Roles are `replaceDirectRoles` (replace, not add — a
second debug login must not accumulate), and the mint happens under the same
per-principal advisory lock (re-entrant). Committing separately would let a
failed mint leave roles rewritten under a login that never succeeded, and would
let two concurrent logins interleave so the surviving session claims `{A}` while
the database says `{B}`.

**INV-A1-7** — a malformed `requesterIp` in `/auth/debug` is **rejected with 400
`auth.invalid_requester_ip`**, never silently dropped, because a
silently-ignored address presents as "the tag rule doesn't work" and sends the
reader after a policy bug that isn't there. Validity is
`isStorableIpLiteral(ip, authz::evaluatesInCedar)` — i.e. _the Cedar engine_ is
the arbiter, not a regex.

**INV-A1-8** — `/auth/me` resolves roles **per request** via
`roleResolver.resolve`, never from the session, so a role gained or lost after
login is visible on the next read. `debugRequesterIp` is reported **only while
`authDebug` is on**, so the console never shows a simulated address the decision
path is ignoring.

**INV-A1-9** — conditional logout: if the request names a `sessionId` and it
differs from the cookie's current session, respond
`200 LogoutResponse(ended=false)` and do nothing. An automatic logout may only
end the exact session the client observed; a re-login may already have replaced
the row.

### SSE stream · `Route.taskEventsRoute(...)`

One per-principal stream of task terminal transitions
(EXECUTED/FAILED/CANCELLED).

**Behavior:**

1. Resolve the live web session (or `"debug-user"` under `authDebug`). No
   principal ⇒ send `ServerSentEvent(retry = 60_000)` and end.
2. Subscribe to `taskCompletionHub`. Loop on a two-way `select`:
   - event received ⇒ filter through the live `task.read` Cedar gate; if
     permitted, send `event: task` with the JSON-encoded `TaskEvent`. Then
     re-check session liveness.
   - `onTimeout(30_000)` ⇒ send a keepalive comment, then re-check session
     liveness.
3. `IOException` ⇒ end quietly. `finally` ⇒ `unsubscribe`.

🔒 **INV-A1-10 — the push is bound to the poll's authorization.** Every event
passes the same live `task.read` gate the poll and detail routes enforce, so a
Cedar forbid that 404s the poll also suppresses the push. The session is
re-validated every 30s so a revoked / expired / newest-wins- displaced session
stops receiving pushes rather than streaming on its handshake identity.

**INV-A1-11 — the keepalive rides the consumer's own coroutine, deliberately.**
Ktor's `heartbeat` helper writes from a separate coroutine, so when the client
is gone its write throws where no handler can reach it — every ordinary
disconnect surfaced as an unhandled exception and a 500. Writing on this loop
puts the throw inside the `catch`. **A Go port must keep writes and the
read-loop on one goroutine, or reproduce the equivalent recovery.**

**INV-A1-12** — an unauthenticated stream lengthens the client's reconnect
backoff to 60s rather than erroring: `EventSource` cannot be told to stop
reconnecting after a 200 handshake. Poll is the truth; a missed event only
delays an update.

### Helpers

- `sessionStillLive(config, sessionId, deviceId, store)` —
  `authDebug ∨ (sessionId != null ∧ store.resolveWeb(...) != null)`.
- `taskReadableForPush(...)` — `authDebug ⇒ true`; missing task ⇒ `false`; else
  `authorizeWithContext(TASK_READ, ApprovalRequest(...))` is **not** `Deny`.
- `computeMePermissions(principal, authz, context)` — four independent Cedar
  decisions: `isAdmin = ADMIN_DATASOURCES ∨ ADMIN_POLICIES ∨ ADMIN_IDENTITY`
  (deliberately independent — one permitted domain exposes the shared admin
  area), `canReadAllAudit = AUDIT_READ` on `AuditLog`, `canApprove = isAdmin`
  (`task.approve` is request-scoped, so no honest coarse System check exists
  yet).
- `normalizeDuration(seconds)` — `%3600==0 ⇒ hours`, `%60==0 ⇒ minutes`, else
  seconds.
- `respondSessionUnauthorized(call, store)` — reason ∈ `none` | `displaced` |
  `bind_mismatch` | `expired`, from `FAILED_WEB_SESSION` attribute +
  `store.webEndedReason`. Always `Cache-Control: no-store`.

---

## 3. Wire contract — shared DTOs

### `Decision` · enum

`ALLOW | MASK | DENY | ERROR`. `ERROR` is the internal-failure case (the proxy
could not reach a verdict) and is **distinct from the fail-closed `DENY`**.

### `AuditEvent` · data class

🔒 The wire contract shared by the proxy (emitting to `/api/ingest/decision`),
the UI (reading back), **and `auditmon`** (re-verifying the hash chain). Field
names and order are frozen — `auditmon/canon` encodes 22 business columns in a
fixed order.

| Field                | Type           | Default      | Note                                               |
| -------------------- | -------------- | ------------ | -------------------------------------------------- |
| `id`                 | `Long?`        | `null`       | server-assigned; ingest leaves null                |
| `ts`                 | `String?`      | `null`       | ISO-8601; server fills if null                     |
| `principal`          | `String`       | required     |                                                    |
| `roles`              | `List<String>` | `[]`         |                                                    |
| `datasource`         | `String`       | required     |                                                    |
| `clientAddr`         | `String?`      | `null`       |                                                    |
| `statement`          | `String`       | required     |                                                    |
| `decision`           | `Decision`     | required     |                                                    |
| `failedStage`        | `String?`      | `null`       | `parse\|validate\|convert\|lineage`                |
| `effectiveNamespace` | `List<String>` | `[]`         |                                                    |
| `maskedColumns`      | `List<String>` | `[]`         |                                                    |
| `piiTouched`         | `List<String>` | `[]`         |                                                    |
| `latencyMs`          | `Long`         | `0`          |                                                    |
| `detail`             | `String?`      | `null`       |                                                    |
| `channel`            | `String?`      | `null`       | `wire\|editor\|workflow-executor\|workflow-viewer` |
| `contextTags`        | `List<String>` | `[]`         |                                                    |
| `authzAction`        | `String?`      | `null`       | management decisions                               |
| `authzResource`      | `String?`      | `null`       |                                                    |
| `outcome`            | `String?`      | `null`       |                                                    |
| `kind`               | `String`       | `"decision"` |                                                    |
| `rowsReturned`       | `Long?`        | `null`       |                                                    |
| `bytesReturned`      | `Long?`        | `null`       |                                                    |
| `decisionId`         | `Long?`        | `null`       |                                                    |

### `ApiError` · data class

`{code: String, params: Map<String,String> = {}}`

🔒 **INV-A1-13 — no English prose on the wire.** `code` is a stable
dot-namespaced i18n key the web looks up directly (`docs/l10n.md`). `Scim.kt` is
the **only** exempt file — its error body follows the SCIM 2.0 spec.

Shared `common.*` codes and their statuses:

| Helper                           | Status | Code                     | Params                      |
| -------------------------------- | ------ | ------------------------ | --------------------------- |
| `badId()`                        | 400    | `common.bad_id`          | —                           |
| `notFound(resource)`             | 404    | `common.not_found`       | `resource`                  |
| `fieldRequired(vararg fields)`   | 400    | `common.field_required`  | `fields` (comma-joined)     |
| `alreadyExists(resource, name?)` | 409    | `common.already_exists`  | `resource`, optional `name` |
| `unauthenticated()`              | 401    | `common.unauthenticated` | —                           |
| `invalidToken(kind?)`            | 401    | `common.invalid_token`   | optional `kind`             |
| (StatusPages)                    | 500    | `common.fallback`        | —                           |
| (`requireAuthz`)                 | 403    | `common.forbidden`       | `detail`                    |

Every code must exist in every locale under `web/messages/<locale>/`. I found no
automated completeness check in the mise tasks — see `00-INDEX.md` contract #11.

### App-local DTOs

`MePermissions{isAdmin, canReadAllAudit, canApprove}` ·
`SessionStatus{now, idleExpiresAt, absoluteExpiresAt, principal, sessionId}` ·
`SessionStatusError{reason}` · `LogoutRequest{sessionId: Long? = null}` ·
`LogoutResponse{ended}` · `AuthConfigResponse{oidcEnabled, authDebug, session}`
·
`SessionUxConfig{heartbeatMs, idleWarnLeadMs, absoluteWarnLeadMs, absoluteCapAmount, absoluteCapUnit}`
(all ms values are `seconds * 1000`).

---

## 4. Test inventory — 3 suites, 706 LOC, **34 cases**

_(Corrected by the reconciliation pass from 27. `MePermissionsRouteTest.kt` —
235 LOC, 7 cases — was owned by no area; both symbols under test live in
`App.kt` (`mePermissionsRoute` at `:293`, `computeMePermissions` at `:255`), so
it is A1's. Note cases 5–6 are A12 anti-spoof assertions ("`requester_ip` from a
trusted edge reaches the me-permissions admin decision", "an untrusted peer
cannot spoof `requester_ip` via `X-Forwarded-For`"), so A12 should
cross-reference them.)_

### `MePermissionsRouteTest.kt` — 235 LOC, 7 cases · route (`ktor-server-test-host`)

1. non-debug requests require a session
2. auth debug returns all capabilities without a session
3. each independent admin action grants admin and approval but not audit
   collection access (INV-A1's `computeMePermissions` — the three admin domains
   are deliberately independent)
4. auditor can read the audit collection without admin or approval capabilities
5. 🔒 `requester_ip` from a trusted edge reaches the me-permissions admin
   decision (A12 INV-A12-1)
6. 🔒 an untrusted peer cannot spoof `requester_ip` via `X-Forwarded-For` at the
   me-permissions route (A12 INV-A12-2)
7. ordinary principal has no coarse capabilities

### `ConfigGuardTest.kt` — 356 LOC, 25 cases, pure unit (injected `env` lambda, no DB)

| #   | Case                                                                                | Asserts                                           |
| --- | ----------------------------------------------------------------------------------- | ------------------------------------------------- |
| 1   | bare defaults boot fine (local dev, debug on, dev secret, no oidc)                  | happy path                                        |
| 2   | debug mode leaves oidc null unless all four required fields are present             | partial OIDC ⇒ null                               |
| 3   | oidc scopes default to `openid profile email groups offline_access`                 | default                                           |
| 4   | oidc scopes are overridable via `PM_OIDC_SCOPES`                                    | override                                          |
| 5   | debug on plus real oidc config without `PM_DEV` refuses to start                    | V5 🔒                                             |
| 6   | debug on plus a real session secret without `PM_DEV` refuses to start               | V5 🔒                                             |
| 7   | debug on plus a production-looking context WITH `PM_DEV` is allowed                 | V5 escape 🔒                                      |
| 8   | debug off is always allowed, even with real oidc + session secret                   | V5                                                |
| 9   | debug off rejects the public development session secret                             | V6 🔒                                             |
| 10  | debug off requires complete secure oidc config on the co-hosted callback            | V7,V8,V9 🔒                                       |
| 11  | debug off requires secure canonical MCP origins                                     | V10 🔒                                            |
| 12  | session window, web clocks, idp recheck interval, and scim token default sanely     | defaults                                          |
| 13  | session window, idp recheck interval, and scim token are overridable                | overrides                                         |
| 14  | web idle and slide durations accept units and plain seconds                         | `parseDuration`                                   |
| 15  | web session absolute duration accepts seconds and concatenated units                | `parseDuration`                                   |
| 16  | web session UX timings accept duration units                                        | `parseDuration`                                   |
| 17  | web session slide must be strictly less than idle                                   | V1                                                |
| 18  | malformed web session durations fail fast                                           | `parseDuration` throws                            |
| 19  | idp recheck interval must be positive                                               | V2                                                |
| 20  | `PM_TRUSTED_PROXIES` parses comma-separated entries, trimmed, with blanks dropped   | parse                                             |
| 21  | `PM_QUERY_TIMEOUT` defaults, overrides, and rejects invalid values                  | V3 + throw-on-garbage                             |
| 22  | `PM_QUERY_TIMEOUT` is bounded to the proxy's duration-safe ceiling (no ms overflow) | V4                                                |
| 23  | the exchange budget outlives the proxy's own statement watchdog                     | `queryExchangeTimeoutMs`                          |
| 24  | the run stream outlives the dial and exchange it wraps                              | `runStreamTimeoutMs`                              |
| 25  | run token TTL always outlives the configured query window                           | ⚠️ asserts the **pure function only** — see below |

Cases 21–25 are a coupled group asserting the **timeout ladder**:
`PM_QUERY_TIMEOUT` < proxy watchdog < `queryExchangeTimeoutMs` <
`runStreamTimeoutMs` ≤ run-token TTL. Port them together; each alone is
meaningless.

🔴 **CORRECTION — the ladder is NOT total, and case 25's "always" is false.**
(Index finding **F26**.) `RunExec.kt:280` passes `runTokenTtlSeconds` into
`TokenStore.issue`, which clamps it: `Tokens.kt:126`
`clampTtlSeconds(ttlSeconds)` → `Tokens.kt:81`
`coerceIn(60, TOKEN_MAX_TTL_SECONDS)` → `Tokens.kt:76`
`TOKEN_MAX_TTL_SECONDS = 24 * 3600`. But `PM_QUERY_TIMEOUT` is bounded only by
the overflow guard (V4, `9_223_372_006`). So the stored TTL stops tracking the
query window:

| `PM_QUERY_TIMEOUT` | TTL wanted | TTL **stored** | margin       | outlives query?                    |
| ------------------ | ---------- | -------------- | ------------ | ---------------------------------- |
| 600                | 900        | 900            | +300         | ✅                                 |
| 86,220 (23h57m)    | 86,400     | 86,400         | +180         | ✅ last point the full grace holds |
| 86,300             | 86,480     | 86,400         | +100         | ⚠️ grace silently eroded           |
| 86,400 (24h)       | 86,580     | 86,400         | **0**        | ⚠️ token dies exactly at timeout   |
| > 86,400           | —          | 86,400         | **negative** | ❌ token expires mid-statement     |

`ConfigGuardTest.kt:65-79` asserts `RunExecService.runTokenTtlSeconds(q) > q` —
**the pure function**, never the value persisted to `proxy_token.expires_at`. So
the test passes at any `PM_QUERY_TIMEOUT` while the real token expires 24h in
and the query fails `UNAUTHENTICATED` on the proxy's mid-run revalidation.

**Port action:** do not carry "always". Either clamp `PM_QUERY_TIMEOUT` to
`TOKEN_MAX_TTL_SECONDS − TOKEN_TTL_GRACE_SECONDS` at config-parse time (a new
V-rule, and the honest fix), or assert the ladder on the stored expiry rather
than the pure function. Cross-ref A7 INV-A7-30, which had the same error.

### `MigrationSelfContainmentTest.kt` — 115 LOC, 2 cases

| #   | Case                                                        | Asserts                                         |
| --- | ----------------------------------------------------------- | ----------------------------------------------- |
| 1   | every migration is self-contained                           | no migration references anything outside itself |
| 2   | the guard rejects the reference forms that break a database | the guard's own negative cases                  |

Case 2 is a **meta-test** (the guard is tested against known-bad inputs). Port
it — a guard that cannot fail is not a guard.

### Coverage gaps in A1

No test covers: `Db.migrate()`'s `PM_DB_REPAIR_CHECKSUMS` path; the
`unusableTrustedProxyEntries` startup warning; the two background timer loops
(including INV-A1-5's mandatory ordering); the `StatusPages` OAuth-vs-ApiError
branch; `normalizeDuration`. INV-A1-5 in particular is a silent data-retention
bug if reversed and nothing would catch it — a Step 3 hardening candidate.

`ConfigGuardTest` also does not cover `PM_RESULT_KEY` (V11), `PM_OAUTH_*`
clamping, or `PM_OAUTH_DEBUG_AUTO_CONSENT`.

---

## 5. Open questions

1. **`PM_DB_URL` is a JDBC URL.** Keep the `jdbc:postgresql://` prefix and
   translate internally, or change the contract? Changing it touches `deploy/`,
   `docker-compose.yml`, `mise.toml:58`, and every deployed environment.
2. **Flyway history table.** Does the Go migration runner adopt
   `flyway_schema_history` as-is, or is a translation step acceptable? Existing
   deployments have populated it.
3. **Session cookie compatibility.** Must live browser sessions survive cutover?
   If not, a fresh cookie scheme is simpler and safer.
4. **SSE ownership.** If the Go MCP SDK's HTTP handler does not install SSE, the
   port must provide it for `/api/tasks/events`. Confirm during the MCP spike.
5. `runStreamTimeoutMs` reads `DIAL_TIMEOUT_MS`, which is defined outside A1 —
   resolve when A5/A7 are specified.
