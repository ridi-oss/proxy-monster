# A2 — Authorization (Cedar)

Files: `authz/Authz.kt` (915) · `authz/CedarEngine.kt` (217) ·
`authz/CedarPolicyStore.kt` (320). Total 1,452 LOC. Fully read. Resource:
`resources/authz/schema.cedarschema` (235 lines).

**Highest-risk area in the port.** Everything here is a security control, and it
is the only area whose behaviour depends on a third-party policy engine whose Go
implementation is not feature-matched (§7).

## Purpose

The authz boundary (`docs/authz-model.md`). Cedar, the schema, entity
marshalling, and the policy store all stay internal to this package; consumers
see only `authorize*` and the two route gates. Owns: the action vocabulary,
resource→Cedar-entity marshalling, per-column/table/function/utility batch
decisions, the two-pass derived-tag mechanism, policy CRUD with
validate-on-write, and the compiled-`PolicySet` cache.

---

## 1. Cedar schema (the authz model)

Entity types: `System`, `Role`, `Group`, `Datasource`, `Table`, `Column`, `Tag`,
`Function`, `Utility`, `User`, `Request`, `AccessGrant`, `Token`, `AuditRecord`,
`AuditLog`.

Membership (`in`) relationships declared in the schema:
`Table in [Datasource, Tag]` · `Column in [Table, Datasource, Tag]` ·
`Function in [Datasource, Tag]` · `Utility in [Datasource, Tag]` ·
`User in [Role]` · `Datasource in [Tag]` · `Request in [Datasource, Role]` ·
`AccessGrant in [Datasource, Role]`.

`Tag` is a **leaf entity type** holding freeform labels (`"pii"`, `system:*`).
⚠️ It is _not_ Cedar's entity-tags language feature — verified: no
`getTag`/`hasTag` anywhere in `control-plane/src` or `engine/src`. This matters
for the port: cedar-go needs no entity-tag support.

Shared action context shape (`schema.cedarschema:117-118`):
`{ channel?: String, requester_ip?: ipaddr, tags?: Set<String>, network_zones: Set<String> }`.
`ipaddr` is the only Cedar extension type used. No `decimal`, no `datetime`, no
`duration`.

Seeded policies: **52** `permit`/`forbid` statements in `V8__seed.sql`, plus
migration-owned `SYSTEM`-origin rows (V20, V24, V32 referenced in tests) using
**negative ids**.

---

## 2. Action vocabulary

### `AuthzAction` · enum — 24 values

`cedarId` is the literal `Action::"..."` id.

| Constant                                                              | `cedarId`                          | Scope                                 |
| --------------------------------------------------------------------- | ---------------------------------- | ------------------------------------- |
| `ADMIN_DATASOURCES`                                                   | `admin.datasources`                | `System`                              |
| `ADMIN_POLICIES`                                                      | `admin.policies`                   | `System`                              |
| `ADMIN_IDENTITY`                                                      | `admin.identity`                   | `System`                              |
| `TASK_APPROVE`                                                        | `task.approve`                     | `Request`                             |
| `TASK_REQUEST`                                                        | `task.request`                     | `Datasource`-scoped                   |
| `TASK_READ`                                                           | `task.read`                        | `Request` (metadata)                  |
| `TASK_ASSUME`                                                         | `task.assume`                      | `Request` (result **data**)           |
| `TASK_CANCEL`                                                         | `task.cancel`                      | `Request`                             |
| `TASK_DELETE`                                                         | `task.delete`                      | `Request`                             |
| `GRANT_REVOKE`                                                        | `grant.revoke`                     | `AccessGrant`                         |
| `TOKEN_MINT` / `TOKEN_LIST` / `TOKEN_REVOKE`                          | `token.mint` / `.list` / `.revoke` | `Token`                               |
| `AUDIT_READ`                                                          | `audit.read`                       | `AuditRecord` / `AuditLog`            |
| `RESULT_READ_UNMASKED`                                                | `result.read.unmasked`             | `Column`/`Table`/`Function`/`Utility` |
| `RESULT_READ_MASKED`                                                  | `result.read.masked`               | ditto                                 |
| `DATASOURCE_CONNECT`                                                  | `datasource.connect`               | `Datasource`                          |
| `SQL_SELECT` / `SQL_INSERT` / `SQL_UPDATE` / `SQL_DELETE` / `SQL_DDL` | `sql.select` … `sql.ddl`           | `Datasource`                          |
| `SQL_UNANALYZABLE`                                                    | `sql.unanalyzable`                 | `Datasource`                          |
| `SQL_UNMASKABLE`                                                      | `sql.unmaskable`                   | `Datasource`                          |

🔒 **INV-A2-1 — the two exception gates are not a hardcoded deny.** A statement
the analyzer cannot reason about (`analyzable=false`) or whose result cannot be
masked on the chosen path (`maskable=false`, e.g. EXPLAIN-of-masked) asks its
**datasource** for `sql.unanalyzable` / `sql.unmaskable` rather than being
blanket-denied in code. Deny-by-default: no exception policy ⇒ DENY, so the
production floor is unchanged, but a permissive dev datasource can permit the
relay. This is `AGENTS.md:136-139`'s "fail-closed through Cedar, not a hardcoded
deny" — coverage gaps are security gaps.

`TASK_READ` gates metadata, `TASK_ASSUME` gates result data. Keep them distinct.

---

## 3. Resources and EUID conventions

### `AuthzResource` · sealed interface — 6 variants

`System` (object) · `AuditRecord(principal)` · `AuditLog` (object) ·
`ApprovalRequest(requester, approver?, executedBy?, datasourceName?, roleName?)`
· `AccessGrant(owner, id, datasourceName?, roleName?)` ·
`Token(owner, kind: TokenKind?)`

### EUID table — the complete marshalling contract

| Resource                 | EUID                                                 | Attributes                                                | Parents                                    |
| ------------------------ | ---------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------ |
| `System`                 | `System::"system"`                                   | —                                                         | —                                          |
| `AuditRecord`            | `AuditRecord::"<principal>"`                         | `principal: User::"<principal>"`                          | —                                          |
| `AuditLog`               | `AuditLog::"all"`                                    | —                                                         | —                                          |
| `ApprovalRequest`        | `Request::"<requester>#<datasourceName ?: "-">"`     | `requester`, `approver?`, `executedBy?` (all `User` refs) | `Datasource::"<name>"?`, `Role::"<name>"?` |
| `AccessGrant`            | `AccessGrant::"<owner>#<id>"`                        | `owner: User`                                             | `Datasource?`, `Role?`                     |
| `Token`                  | `Token::"<owner>#<kind?.name ?: "-">"`               | `owner: User`, `kind: String?`                            | —                                          |
| principal                | `User::"<principal>"`                                | —                                                         | every `Role::"<r>"`                        |
| datasource (batch paths) | `Datasource::"<name>"`                               | `name: String`                                            | posture `Tag`s only                        |
| table                    | `Table::"<ds>/<catalog>/<schema>/<table>"`           | —                                                         | `Datasource`, `systemTag?`                 |
| column                   | `Column::"<ds>/<catalog>/<schema>/<table>/<column>"` | —                                                         | `Table`, `Datasource`, user tags           |
| function                 | `Function::"<ds>/<name>"`                            | —                                                         | `Datasource`, `systemTag?`                 |
| utility                  | `Utility::"<ds>/<command>"`                          | —                                                         | `Datasource`, `systemTag?`                 |

🔒 **INV-A2-2 — datasource entities are keyed by NAME, never numeric id.** All
five batch/extension entry points (`authorizeColumns`, `authorizeTables`,
`authorizeFunctions`, `authorizeUtilities`, `authorizeDatasourceAction`,
`resolveContextTags`) key `Datasource::"<name>"`, matching every seed policy and
doc example. These functions deliberately do **not** route through
`Authz.authorize` or its private `marshalResource`.

⚠️ **REPRODUCE the behaviour, OMIT the comment (F1).** `Authz.kt:757-758` says
"`Authz.authorize`'s own `AuthzResource.Datasource` marshalling keys off the
numeric id instead (`Datasource::"2"`) — reusing it here would silently deny
every query." **`AuthzResource` has no `Datasource` variant** (verified:
`marshalResource` has exactly six branches, none for a datasource). The comment
describes a removed variant. The name-keyed marshalling it warns about is
observable and is ported verbatim; the KDoc itself has no call path and no wire
effect, so it is the OMIT half — a stale comment is a non-observable artifact,
not a behaviour. See §8 Q1.

🔒 **INV-A2-3 — `Token` kind absence is meaningful.** `kind = null` (e.g.
listing a principal's tokens) leaves the Cedar `kind` attribute **absent**,
which lets a policy permit short sessions while forbidding long-lived PATs.
Emitting `kind: ""` or `kind: "null"` would break those policies.

### `dedupeByEuid(entities: List<Entity>): Set<Entity>` · private fn

First-wins collapse of entities sharing an EUID, via
`LinkedHashMap.putIfAbsent`.

**Why:** cedar-java rejects a set containing two distinct `Entity` objects for
one `EntityUID` outright ("duplicate entity entry"), _even when structurally
identical_. This is load-bearing in `authorizeAs`: an `ApprovalRequest.roleName`
equal to one of the principal's own roles produces exactly that collision.

**Go shape:** cedar-go models entities as a **map keyed by UID**, so duplicates
collapse for free and this helper is structurally unnecessary. Confirm no test
asserts the _error_; if one does, the port changes observable behaviour. See §8
Q2.

---

## 4. Verdict types and refs

| Type          | Fields                                         | Verdict enum                              | Deny-by-default? |
| ------------- | ---------------------------------------------- | ----------------------------------------- | ---------------- |
| `ColumnRef`   | `key, catalog, schema, table, column, tags=[]` | `ColumnVerdict{UNMASKED, MASKED, DENIED}` | ✅               |
| `TableRef`    | `key, catalog, schema, table`                  | `TableVerdict{READ, DENIED}`              | ✅               |
| `FunctionRef` | `name` (bare, unqualified)                     | `FunctionVerdict{ALLOWED, DENIED}`        | ✅               |
| `UtilityRef`  | `command` (canonical per-engine id)            | `UtilityVerdict{USE, DENIED}`             | ✅               |

🔒 **INV-A2-4 — `key` is opaque and identity is never recovered by parsing it.**
`catalog`/`schema`/ `table`/`column` come from the exact matching catalog row
(or the analyzer's resolved identity for tables). `key` is _only_ the map key
the verdict returns under. Reconstructing identity by splitting `key` would
reintroduce the delimiter-collision class INV-A2-6 exists to prevent.

🔒 **INV-A2-5 — every input gets an explicit verdict; there is no "absent =
allow".** All four batch functions return a verdict for every entry in their
input list.

🔒 **INV-A2-6 — delimiter guard.** Both `/` (the EUID join) and `.` (the
analyzer key join) are legal _inside_ a quoted SQL identifier. A component
containing either would let two distinct identities render to one EUID — e.g.
schema `public/a` + table `users` and schema `public` + table `a/users` both →
`.../public/a/users` — a wrong-grant collision. Any ref whose resolved identity
(including the **datasource name**) contains a delimiter **builds no EUID and is
DENIED fail-closed**.

- Columns/tables check `/` **and** `.` on datasource, catalog, schema, table,
  column.
- Functions/utilities check **`/` only** on datasource and name/command.

This asymmetry is intentional (a function name cannot carry the analyzer's
dot-qualification) but is a sharp edge — replicate exactly.

### Masking is not authorization

`ColumnVerdict.MASKED` says _a_ mask applies; **which** mask fn is column
config, resolved elsewhere (A9 `Policies.kt`). `TableVerdict.READ` is granted by
_either_ `result.read.unmasked` **or** `result.read.masked` because a masked
reader already observes the table's rows through masked projections, so
existence and cardinality are not additionally protected.

---

## 5. Tag type-scoping (a security invariant enforced at marshalling)

```kotlin
private val DATASOURCE_POSTURE_TAGS = setOf("system:development", "system:production")
private fun isReservedTag(t: String) = t.startsWith("system:") || t == "udf:output-vouched"
```

🔒 **INV-A2-7 — reserved tag namespaces are TYPE-SCOPED, enforced here, not only
at the admin write API.**

- `system:development` / `system:production` marshal **only** onto a
  `Datasource` (`datasourceEntity` filters to `DATASOURCE_POSTURE_TAGS`; all
  other datasource tags are dropped as parents, though free-form tags are
  carried and inert).
- Every other `system:*` tag (`system:critical`, `activity`, `data-leak`,
  `catalog`) attaches to a `Table`/`Column`/`Function`/`Utility` **only from the
  shipped manifest**, passed in as `systemTags` — never honoured from a
  user-authored column tag.
- `Column` parents are built from `col.tags.filterNot(::isReservedTag)`. A
  column's real system tag is inherited transitively through its `Table` parent.
- `udf:output-vouched` is valid only on a UDF `Function`.

**Attack this prevents:** a `Column` whose catalog row carried a hand-written
`system:development` (or a forged `system:critical`) would satisfy a preset
permit or bypass a shipped forbid and **leak cleartext**. `PresetPolicyDbTest`
case 9 is the regression test ("a forged preset-development tag is honored on a
datasource but stripped off a column").

### `datasourceEntity(dsEuid, name, datasourceTags, tagEuids): Entity` · private fn

Returns `Entity(dsEuid, {name: PrimString(name)}, parents = posture tags only)`.
`tagEuids` is the caller's shared dedup map so one `Tag` EUID object is reused
across the batch.

---

## 6. Symbols

### `AuthzContext` · data class

`(networkZones: List<String> = [], channel: String? = null, requesterIp: String? = null, tags: Set<String> = ∅)`

#### `toCedarMap(includeTags: Boolean = true): Map<String, Value>`

1. `network_zones` — **always present**, empty set if none.
2. `tags` — present **unless `includeTags = false`**.
3. `channel` — only when non-null.
4. `requesterIp` — only when non-null **and parseable**: wrapped in
   `runCatching { IpAddress(ip) }`; an unparseable value is **dropped**, not
   propagated.

🔒 **INV-A2-8 — optional-attribute absence is the fail-closed signal.** A policy
conditioning on an absent attribute simply does not fire (Cedar skips it), which
denies. So a malformed IP must never throw — a thrown constructor would error
_every_ query. Dropping it is the fail-closed behaviour.
`ChannelContextAuthzTest` case 3 ("an absent channel fails the guard closed")
pins this.

🔒 **INV-A2-9 — context is server-attested, never client-asserted.** No client
value reaches `toCedarMap`. `tags` are derived (pass-1), never supplied.

### `AuthzDecision` · sealed interface

`Allow` (object) · `Deny(reason: String, code: String = "forbidden")`

### `RoleSource` · fun interface

`fun rolesOf(principal: String): Set<String>`. Authz **never** resolves roles
itself; the caller wires `RoleResolver.resolve` (or a stub). This is what keeps
role resolution swappable and Cedar-independent.

### `AuthorizationResponse.toAuthzDecision()` · private ext fn

1. No `success` payload ⇒
   `Deny("authorization engine error: " + joined error messages)` — **fail
   closed on engine error**.
2. `success.isAllowed` ⇒ `Allow`.
3. Else ⇒ `Deny`, reason = `"no policy permits this action"` when reasons are
   empty, else `"denied by policy: <reasons joined>"`.

Shared by `authorize`/`authorizeAs` and `authorizeDatasourceAction` so the
single-resource entry points cannot drift. The batch paths deliberately read
only `success…isAllowed` inline — they need a verdict per column, not a reason.

### `class Authz(engine: CedarEngine, policyStore: CedarPolicyStore, roleSource: RoleSource)`

`engine` is `internal` (not `private`) because the batch extension functions in
this file need the raw engine for their two-actions-per-column marshalling.
Still module-private — the authz boundary holds. `policyStore` is
`@Suppress("unused")` — constructor-retained only.

#### `rolesOf(principal): Set<String>` · internal

Accessor over the private `roleSource`, so `authorizeWithContext` can take
**one** role snapshot.

#### `evaluatesInCedar(ip: String): Boolean`

Whether the **engine** can evaluate `ip` as `requester_ip` — a question
cedar-java's `IpAddress` regex does not answer. Runs one throwaway decision
(`User::"ip-probe"`, `sql.select`, `System::"system"`) and returns
`response.success.isPresent`; the verdict is irrelevant, only the absence of an
engine error. `runCatching` ⇒ `false`.

**Go shape:** high conformance risk. cedar-go exposes IP parsing directly, so
the probe likely becomes a direct parse — but "which literals does cedar-java
accept that Go's parser rejects, and vice versa" is an empirical question.
`/auth/debug` rejects a 400 based on this (INV-A1-7), so a divergence is
user-visible. Spike input.

#### `authorize(principal, action, resource, context = AuthzContext()): AuthzDecision`

Resolves roles once via `roleSource`, delegates to `authorizeAs`. The common
case (System/AuditLog, no datasource-scoped tags).

#### `authorizeAs(principal, roles, action, resource, context): AuthzDecision`

Explicit already-resolved `roles`; no second out-of-band resolution.

1. `principalEntity = Entity(User::principal, {}, parents = roles)`; plus a bare
   `Entity` per role.
2. `marshalResource(resource)` → `(euid, entities)`.
3. `entities = Entities(dedupeByEuid([principal] + roles + resourceEntities))`.
4. `engine.isAuthorized(...).toAuthzDecision()`.

🔒 **INV-A2-10 — single role resolution.** `authorizeWithContext` resolves roles
once and threads that snapshot through _both_ pass-1 tag derivation and pass-2
authorization, so a role revoked or a JIT grant expiring between passes can
never earn a `context.tag` the final decision no longer sees. This mirrors
`decideQuery`'s invariant (A6). `ElevationContextTagTest` case 7 pins it.

### Batch entry points

All five share a skeleton: build principal+roles+datasource entities → per-item
delimiter guard → build item entities with tag parents → **one** `Entities`
batch → query Cedar per item.

| Function                    | Actions asked per item    | Verdict logic                                                 |
| --------------------------- | ------------------------- | ------------------------------------------------------------- |
| `authorizeColumns`          | `unmasked`, then `masked` | `UNMASKED` / `MASKED` / `DENIED` (**ordered**: unmasked wins) |
| `authorizeTables`           | `unmasked` OR `masked`    | `READ` / `DENIED`                                             |
| `authorizeFunctions`        | `unmasked` OR `masked`    | `ALLOWED` / `DENIED`                                          |
| `authorizeUtilities`        | `unmasked` OR `masked`    | `USE` / `DENIED`                                              |
| `authorizeDatasourceAction` | the given `action`, once  | full `AuthzDecision` via `toAuthzDecision()`                  |

`authorizeColumns` signature:

```kotlin
fun Authz.authorizeColumns(
  principal: String, roles: Set<String>, datasource: String, columns: List<ColumnRef>,
  context: AuthzContext = AuthzContext(),
  systemTags: Map<Triple<String,String,String>, String> = emptyMap(),  // (catalog,schema,table) → system tag
  datasourceTags: List<String> = emptyList(),
): Map<String, ColumnVerdict>
```

🔒 **INV-A2-11 — caller-side marshalling contracts.**

- `authorizeFunctions`: the caller passes **only** DANGEROUS-classified
  functions. A safe function has no tag and no permit, so marshalling it would
  deny-by-default and break every `now()`/user-UDF query.
- `authorizeUtilities`: the caller passes **only** CLASSIFIED utilities. An
  unclassifiable one is HARD-denied _upstream_, because an untagged `Utility`
  (Datasource parent only, no forbid) would be **PERMITTED** by a
  datasource-scoped read grant. The deny-by-default on an untagged EUID remains
  a defensive backstop but is **not** the load-bearing path.

That second one is the subtlest rule in the area: marshalling an unclassified
utility inverts the decision from deny to allow. A Go port must keep the
upstream hard-deny.

### `resolveContextTags(principal, roles, datasource, rawContext, datasourceTags): Set<String>`

Pass-1 of the two-pass mechanism (`docs/authz-context.md`).

1. `vocab = engine.contextTagVocabulary()`; **empty ⇒ return ∅ with no
   evaluation** (the common deployment).
2. Build principal/roles/datasource entities exactly as
   `authorizeDatasourceAction` does (NAME-keyed).
3. `contextMap = rawContext.toCedarMap(includeTags = false)`.
4. For each tag `T` in vocab, ask
   `isAuthorized(principal, Action::"context.tag::T", <Datasource>, …)`. Each
   ALLOW earns `T`. Collected into a `sortedSetOf()` — **result order is
   sorted**.

🔒 **INV-A2-12 — no tag-on-tag, enforced on both sides.** `includeTags = false`
means a tag rule cannot read `context.tags` at evaluation time; the generated
tag-action schema also omits `tags`, so such a rule fails validation and never
loads. Two independent closures of the same hole — keep both.
`TagResolutionTest` cases 6 and 7 pin each side.

🔒 **INV-A2-13 — pass-1 fail-closed.** A tag exists only if a rule PERMITTED it.
An engine error is a non-allow, so the tag is absent — never "present on error".

### `authorizeWithContext(principal, action, resource, raw, datasourceName, datasourceTags)` · internal

The coherent non-query decision:

1. `roles = rolesOf(principal)` — **once**.
2. `context = if (datasourceName == null) raw else raw.copy(tags = resolveContextTags(...))`.
3. `authorizeAs(principal, roles, action, resource, context)`.

🔒 **INV-A2-14 — tags derive only when a datasource is in scope, and no
pseudo-datasource is ever synthesized.** The tag mechanism is Datasource-scoped
by construction: pass-1's Cedar action is declared
`appliesTo { resource: [Datasource] }`, so it needs a real `Datasource` to
evaluate against. A null `datasourceName` authorizes over `raw` **unchanged** —
`requesterIp` and every other raw signal still reach Cedar, but `tags` stays
empty. Fail-closed: a tag-conditioned policy simply does not fire; it never
invents a tag from a fabricated resource. `ElevationContextTagTest` cases 3 and
4 pin both halves.

**INV-A2-15** — `channel` is deliberately never set on this path. These
admin/audit/approval routes have no query-decision channel, and inventing one
for a route that is not deciding a query would be dishonest.

### Route gates

```kotlin
suspend fun ApplicationCall.requireAdmin(config, authz, action, resource = AuthzResource.System): Boolean
suspend fun ApplicationCall.requireAuthz(config, authz, action, resource): Boolean
```

`requireAdmin` is the `System`-resource alias; both share one body:

1. `config.authDebug` ⇒ `true` (dev bypass).
2. `userSession() == null` ⇒ `401 ApiError("common.unauthenticated")`, `false`.
3. `authz.authorize(session.principal, action, resource, httpAuthzContext(config))`:
   `Allow` ⇒ `true`; `Deny` ⇒
   `403 ApiError("common.forbidden", {detail: reason})`, `false`.

🔒 **INV-A2-16 — the dev bypass never skips Cedar; it prevents Cedar from being
reached.** `Authz` itself has no bypass. This is the choke point that closes the
"admin routes require admin.*, not any session" hole once `authDebug=false`.
Threading `httpAuthzContext(config)` here fixes `requester_ip` for ~35 admin
call sites with no call-site churn.

---

## 7. `CedarEngine.kt`

### Tag-name extraction

```kotlin
CONTEXT_TAG_ACTION   = Regex("""Action::"context\.tag::([^"]+)"""")
CONTEXT_TAGS_CONSUMED = Regex("""context\.tags\.contains\(\s*"([^"]+)"\s*\)""")
internal fun extractContextTagNames(cedarSrc: String): Set<String>
```

The tag vocabulary is **derived** from policy source by regex, not predefined.
An action EID is always a literal `Action::"context.tag::<name>"`, so scanning
source text is exact and cheap.

### `contextTagLint(enabledSources: List<Pair<Long,String>>): List<String>`

Compares PRODUCED (tag-rule action targets) against CONSUMED
(`context.tags.contains("…")` literals):

- consumed with no producer ⇒
  `"context tag \"X\" is consumed by a policy but no tag rule produces it (grant can never apply)"`
- produced with no consumer ⇒
  `"context tag \"X\" is produced by a tag rule but no policy consumes it (dead tag rule)"`

Both sorted. **Purely diagnostic** — dangling tags are fail-closed-safe, so this
WARNS and never blocks a policy write or boot. Surfaced in `/health`
diagnostics.

### `object CedarSchema`

- `text` — loaded from classpath `/authz/schema.cedarschema`; missing ⇒
  `error(...)` at class init.
- `schema: Schema` — `Schema.parse(JsonOrCedar.Cedar, text)`, i.e.
  **human-readable Cedar schema syntax**, not JSON.
- `augmentedSchemas: ConcurrentHashMap<Set<String>, Schema>` — validation-only
  cache.
- `engine = BasicAuthorizationEngine()` — shared across calls/threads; holds no
  per-call state.

#### `schemaFor(tagNames: Set<String>): Schema`

Empty ⇒ base schema. Otherwise append one declaration per **sorted** tag name:

```
action "context.tag::<name>" appliesTo { principal: [User, Role], resource: [Datasource],
  context: { channel?: String, requester_ip?: ipaddr, tailscale_caps?: Set<String> } };
```

🔒 The generated context **deliberately omits `tags`** (INV-A2-12). Note it
declares `tailscale_caps?: Set<String>`, which does not appear in `AuthzContext`
— a deployment-specific attribute a rule may reference. Carry it verbatim.

#### `validate(cedarSrc: String): List<String>`

**Contract: never throws for policy-shaped input.** Empty list = valid.

1. Blank ⇒ `["cedar policy source must not be blank"]`.
2. `Policy(cedarSrc, "candidate")`; catch `NullPointerException` ⇒ return its
   message.
3. **Self-augment**: validate against
   `schemaFor(extractContextTagNames(cedarSrc))`, so a not-yet- predefined tag
   rule is loadable. `schemaFor` is **inside** the try — a pathological tag name
   (e.g. a trailing backslash from a `\"` escape) makes the generated
   declaration malformed and `Schema.parse` throw; that must surface as a
   validation error, not break the never-throws contract.
4. `AuthException` ⇒ `[message]`; other `Exception` ⇒
   `["invalid context.tag action name: …"]`.
5. Result = `response.errors` messages (**parse** failures, top-level) **++**
   `response.success .validationErrors` messages (**semantic**/ill-typed).
   Concatenating both covers either shape.

Empirically verified against cedar-java 4.3.1: it never throws for either error
class — both surface as a `ValidationResponse`.

### `class CedarEngine`

Two constructors: `(policyStore: CedarPolicyStore)` — production, polls
`stateVersion()`; and `(policySources: List<Pair<Long,String>>)` — a fixed
in-memory set with a constant `0L` version, for unit tests with no JDBC.

- `init` — validates **every** source; any failure ⇒ `check(...)` throws
  `"authz: enabled cedar polic{y|ies} failed schema validation at startup: policy #<id>: <errors>"`.
  🔒 **INV-A2-17 — fail fast at construction.** Cedar would otherwise silently
  refuse to load a malformed policy and effectively deny everything for it.
- `rebuildIfStale()` — `@Synchronized`; returns early when
  `cachedPolicies != null && v == cachedVersion`. Rebuilds `cachedPolicies` (ids
  → `Policy(src, "policy-$id")`) **and** `cachedVocab` together, then sets
  `cachedVersion`, then `buildCount++`. 🔒 **INV-A2-18 — the policy set and the
  tag vocabulary rebuild atomically**, so they can never disagree, and
  concurrent callers never observe a torn cache.
- `contextTagVocabulary()`,
  `isAuthorized(principal, action, resource, entities, context = ∅)`,
  `validate(src)`.
- `buildCount` — `@JvmField internal`, exists solely for
  `CedarEngineCacheTest`'s O(1)-per-query assertion. **The Go port needs an
  equivalent observable counter or that test cannot be ported.**

`@Volatile` on `cachedVersion`/`cachedPolicies`/`cachedVocab` + `@Synchronized`
on the rebuild. **Go shape:** `sync.RWMutex` or `atomic.Pointer` to an immutable
snapshot struct; the initial `cachedVersion = Long.MIN_VALUE` sentinel
guarantees a first-use build.

---

## 8. `CedarPolicyStore.kt`

### Wire DTOs

| DTO                   | Fields                                                                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CedarPolicy`         | `id: Long`, `origin: String`, `systemKey: String? = null`, `name: String`, `cedarSrc: String`, `enabled: Boolean`, `updatedBy: String? = null`, `updatedAt: String` |
| `CedarPolicyInput`    | `name`, `cedarSrc`, `enabled = true`                                                                                                                                |
| `CedarValidateInput`  | `cedarSrc`                                                                                                                                                          |
| `CedarValidateResult` | `valid: Boolean`, `errors: List<String> = []`                                                                                                                       |
| `CedarSchemaResult`   | `schema: String` — the bundled schema text, served to the editor for schema-aware linting (the schema is the authz model, not secret)                               |

`updatedAt` is `getTimestamp(...).toInstant().toString()` — **Java
`Instant.toString()` formatting**, which omits trailing zeros in the fractional
second (`2026-07-31T04:05:06.123Z`, but `2026-07-31T04:05:06Z` when zero). A Go
port using RFC3339Nano differs; RFC3339 with forced millis differs too.
Wire-visible.

### Exceptions

`InvalidCedarPolicyException(errors: List<String>)` → 400 ·
`SystemPolicyImmutableException` → 409 · `ReservedPolicyNameException` → 400/409

### `class CedarPolicyStore(dataSource, auditStore = AuditStore(dataSource))`

Table `policy` (V3). `version: AtomicLong(0)`; `stateVersion()`;
`markCommittedMutation()`.

🔒 **INV-A2-19 — the version bumps only after commit.** Each mutation runs
`inTx { … }` then calls `markCommittedMutation()`. The connection-taking
overloads exist for callers composing a larger transaction, and those callers
must call `markCommittedMutation()` themselves **after** their outer transaction
commits. Bumping inside the transaction would publish a cache invalidation for a
rollback that never happened.

| Method                                       | Behavior                                                                                                                                                                          |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `list()`                                     | all rows `ORDER BY id`                                                                                                                                                            |
| `get(id)` / `get(id, conn)`                  | by id                                                                                                                                                                             |
| `getByName(name)` / `(name, conn)`           | by name                                                                                                                                                                           |
| `create(input, updatedBy[, conn])`           | ① `name.startsWith("system:")` ⇒ `ReservedPolicyNameException`; ② `validate` ⇒ `InvalidCedarPolicyException`; ③ `INSERT … origin='USER' RETURNING id`                             |
| `update(id, input, updatedBy[, conn])`       | ① `SELECT origin … FOR UPDATE` (null ⇒ return null); ② `origin=='SYSTEM'` ⇒ immutable; ③ reserved-name check; ④ `validate`; ⑤ `UPDATE … updated_at=now()`                         |
| `setEnabled(id, enabled, updatedBy[, conn])` | ① `SELECT … FOR UPDATE` (null ⇒ null); ② **only when enabling**, `validate(existing.cedarSrc)`; ③ `UPDATE`; ④ if `origin=='SYSTEM'` ∧ state actually changed, insert an audit row |
| `delete(id[, conn])`                         | ① `SELECT origin … FOR UPDATE`; ② SYSTEM ⇒ immutable; ③ `DELETE`, return `rows > 0`                                                                                               |
| `enabledSources()`                           | `(id, cedar_src)` for `enabled = true`, `ORDER BY id` — stable order                                                                                                              |

🔒 **INV-A2-20 — origin guards live in the store, under a row lock.** Not in the
route: (a) non-HTTP callers cannot rewrite migration-owned source, and (b) a
concurrent transaction cannot swap the checked row between guard and update.
`SELECT … FOR UPDATE` is the mechanism.

🔒 **INV-A2-21 — enabling revalidates.** A row that became malformed while
disabled (or was inserted by a migration) is rejected on enable and stays
disabled. Disabling never validates.

🔒 **INV-A2-22 — a SYSTEM toggle writes a visible sentinel audit record**, on
the **same connection**, so an audit-insert failure rolls the toggle back:
`statement = "[ADMIN policy.toggle] policy <id> (<systemKey>) enabled <old>-><new>"`,
`principal = updatedBy ?: "unknown"`, `datasource = "control-plane"`,
`decision = ALLOW`, `detail = "SYSTEM_POLICY_TOGGLE"`. `CedarPolicyOriginTest`
case 3 pins the rollback.

⚠️ `insertReturningId` (`CedarPolicyStore.kt:229`) is private and **unused** —
**OMIT (F2)**. It is `private`, so no test can reach it either; with no call
path in main _or_ test there is no observable behaviour to preserve and nothing
depends on it as a fixture.

### Routes — `/api/policies`

Every route gated `requireAdmin(config, authz, ADMIN_POLICIES)`. Delegates to
`PolicyManagementService` (A11), catching `CedarValidationManagementException` ⇒
`400 {errors: [...]}` and `ManagementException` ⇒ `respondManagementError`.

| Method | Path                         | Success                                             |
| ------ | ---------------------------- | --------------------------------------------------- |
| GET    | `/api/policies`              | 200 list                                            |
| POST   | `/api/policies`              | **201** created                                     |
| PUT    | `/api/policies/{id}`         | 200 updated (400 `common.bad_id` on unparseable id) |
| DELETE | `/api/policies/{id}`         | **204**                                             |
| POST   | `/api/policies/validate`     | 200 `CedarValidateResult`                           |
| GET    | `/api/policies/schema`       | 200 `CedarSchemaResult`                             |
| POST   | `/api/policies/{id}/enable`  | 200                                                 |
| POST   | `/api/policies/{id}/disable` | 200                                                 |

Note the validation-error body is `{errors: [...]}` — a **bare map**, not
`ApiError`. An exception to INV-A1-13; the messages are Cedar's own compiler
output. Preserve the shape.

---

## 9. cedar-java → cedar-go mapping (spike input)

Verified: cedar-go **v1.8.0** (2026-06-01) · `types.IPAddr` exists ·
`x/exp/schema/validate` provides `New(*resolved.Schema, ...Option) *Validator`
with `Policy(policyID string, policy *ast.Policy) error`, `Entities`, `Entity`,
`Request`, and `WithStrict()` (default) / `WithPermissive()`.

| cedar-java (used here)                              | cedar-go                                    | Risk                          |
| --------------------------------------------------- | ------------------------------------------- | ----------------------------- |
| `BasicAuthorizationEngine.isAuthorized`             | `cedar.Authorize`                           | low                           |
| `Schema.parse(Cedar, text)`                         | `x/exp/schema` text parser                  | **`x/exp`**                   |
| `ValidationRequest` + `engine.validate`             | `validate.Validator.Policy`                 | **`x/exp`**, per-policy only  |
| `Policy(src, id)`, `PolicySet`                      | policy/policy-set types                     | low                           |
| `Entities`, `Entity(euid, attrs, parents)`          | `types.EntityMap`, `types.Entity`           | dedup semantics differ (§3)   |
| `EntityUID`, `EntityTypeName.of`                    | `types.NewEntityUID`                        | low                           |
| `PrimString`, `CedarList`, `IpAddress`              | `types.String`, `types.Set`, `types.IPAddr` | IP literal acceptance differs |
| `AuthorizationResponse.success/isAllowed/getReason` | `cedar.Decision` + `Diagnostic`             | error-vs-deny mapping         |
| `AuthException`                                     | `error`                                     | message text differs          |

### Questions the spike must answer

| #   | Question                                                                                                                                                             | Blocks                                          |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| S1  | Do all 52 seeded policies + the SYSTEM migration rows validate identically (accept/reject) under cedar-go strict?                                                    | whole area                                      |
| S2  | Does `validate` still satisfy "never throws for policy-shaped input", and can parse errors be distinguished from semantic errors to reproduce the concatenated list? | `CedarValidateResult.errors` wire shape         |
| S3  | Does the `schemaFor` augmentation trick work — appending generated `action "context.tag::X"` declarations to schema **text** and re-parsing?                         | the entire tag mechanism                        |
| S4  | Does cedar-go surface an engine-**error** distinguishable from a deny, so INV-A2-8's fail-closed mapping survives?                                                   | `toAuthzDecision`, `evaluatesInCedar`           |
| S5  | Which IP literals does cedar-java accept that cedar-go rejects (and vice versa)?                                                                                     | INV-A1-7, `evaluatesInCedar`                    |
| S6  | Does any test assert cedar-java's duplicate-entity **error**?                                                                                                        | whether `dedupeByEuid` is portable or removable |
| S7  | Is `x/exp/schema/validate`'s API stable enough to pin, or is out-of-process validation (Rust CLI) needed?                                                            | the deferred decision                           |

S3 is the sharpest: the augmentation is string concatenation onto schema source.
If cedar-go's schema API is AST-only for construction, the trick needs rewriting
as programmatic action declarations — mechanically different, same semantics.

`⟦LIB⟧` Cedar engine choice; deferred per agreed sequencing →
`99-library-decisions.md`.

---

## 10. Test inventory — 14 files, 2,624 LOC, **90 cases**

Counted as `@Test` on its own line (a bare `grep -c '@Test'` over-counts: it
also matches `@TestInstance`). Verified per file that the `@Test` count equals
the number of backtick-named test functions, so the enumeration below is
complete.

### `AuthzTest.kt` — 278 LOC, 14 cases · unit (in-memory `CedarEngine(List)`), **the seed oracle**

1. system-admin is allowed on admin actions
2. 🔒 no roles is denied on admin actions — the "admin = any session" hole stays
   closed
3. a role other than system-admin is still denied on admin actions
4. the audit policies allow own records and grant auditors the whole collection
5. an approver may approve someone else's request
6. 🔒 ROLE self-approval is denied even for a system-admin — the self-approval
   hole stays closed
7. 🔒 a non-admin approving someone else's request is still denied — no ambient
   permit
8. an approval request scoped to a role is matched via `resource in Role` —
   `Request` carries the role as a Cedar parent
9. a request scoped to a DIFFERENT role than the policy grants is denied — the
   Role parent is the request's, not ambient
10. task lifecycle and grant revoke actions validate against the bundled schema
11. task assume seeds validate and allow only parties or auditor
12. approval request marshals `executedBy` as a User attribute
13. retired workflow action ids are rejected by the bundled schema
14. an approval request scoped to a datasource is matched via
    `resource in Datasource` by NAME

### `AuthzDatasourceActionTest.kt` — 144 LOC, 6 cases · unit

1. a granted role may connect to the named datasource
2. a granted role may run a granted sql kind on the named datasource
3. `sql.unmaskable` follows the preset-development datasource tag (INV-A2-1)
4. 🔒 an ungranted sql kind is denied — deny-by-default, not absent-equals-allow
5. 🔒 the same grant on a different datasource name does not apply — NAME-keyed,
   not blanket (INV-A2-2)
6. no roles at all is denied

### `ColumnAuthzTest.kt` — 215 LOC, 11 cases · unit

1. an untagged column in the granted table is unmasked
2. a fully-qualified `Column` EUID grant matches its exact column
3. 🔒 an identifier containing a key delimiter is denied fail-closed (INV-A2-6)
4. a pii-tagged column in the granted table is masked, not unmasked
5. 🔒 a column in an ungranted table is denied — deny-by-default, not
   absent-equals-cleartext
6. 🔒 a pii-tagged column in an UNGRANTED table is denied, not masked — the
   masked grant is table-scoped
7. no roles at all is denied on every column
8. a batch of columns resolves independent verdicts in one call (INV-A2-5)
9. 🔒 a permit on `public.users` does not cover `analytics.users` with the same
   table name
10. 🔒 a permit in one catalog does not cover the same schema+table in another
    catalog
11. 🔒 a different datasource with the same qualified table is not covered by
    the grant

Cases 9–11 are the EUID-injectivity suite. Together with case 3 they are the
whole defence against wrong-grant collisions — port as a group.

### `CedarEngineCacheTest.kt` — 119 LOC, 2 cases · **DB**

1. disable invalidates the cache; re-enable and delete both take effect on the
   next call
2. `isAuthorized` only rebuilds the `PolicySet` when store state changes — O(1)
   per query

Case 2 reads `buildCount`. Needs an equivalent Go counter.

### `CedarPolicyStoreTest.kt` — 221 LOC, 9 cases · **DB**

1. V20 system seeds and the V32-converted audit seeds are enabled and validate
   as one Cedar engine
2. a schema-valid policy is created
3. an unparseable policy is rejected with errors, not written
4. 🔒 a policy referencing an unknown action is rejected — schema validation,
   not just syntax
5. enable and disable round-trip into `enabledSources`
6. 🔒 enabling a stored-malformed row is rejected and leaves it disabled
   (INV-A2-21)
7. delete removes the row
8. `stateVersion` monotonically bumps on create, `setEnabled`, and delete
   (INV-A2-19)

### `CedarPolicyOriginTest.kt` — 247 LOC, 4 cases · **DB**

1. 🔒 store rejects system mutation and reserved user names before touching
   state (INV-A2-20)
2. system toggle changes only mutable fields and writes a visible sentinel audit
   record (INV-A2-22)
3. 🔒 audit failure rolls back the system toggle in the same transaction
   (INV-A2-22)
4. negative-id migration is decision-equivalent to the `AuthzTest` seed oracle

Case 4 is a **cross-suite equivalence** test — it ties the migration-owned
SYSTEM rows to `AuthzTest`'s expectations. Port `AuthzTest` first.

### `CedarPolicyRoutesTest.kt` — 181 LOC, 5 cases · route (`ktor-server-test-host`)

1. list exposes system provenance without accepting it in input
2. POST and USER rename reject the reserved `system:` namespace
3. PUT and DELETE of a system policy return the immutable conflict (409)
4. enable and disable remain available for system policies
5. REST-shaped policy mutation remains bound to its numeric id after name reuse

### `AdminGateTest.kt` — 86 LOC, 2 cases · unit

1. 🔒 no admin role is denied `admin_policies`
2. system-admin role is allowed `admin_policies`

### `AdminContextAuthzTest.kt` — 161 LOC, 3 cases · route

1. 🔒 an admin session with no trusted edge is denied even though the policy
   would allow with the right ip
2. a trusted edge's forwarded ip reaches Cedar and satisfies the ip-gated admin
   policy
3. no session is unauthenticated regardless of ip

Depends on A12 `RequesterIp.kt` + `PM_TRUSTED_PROXIES`. Port A12 first.

### `ChannelContextAuthzTest.kt` — 86 LOC, 4 cases · unit

1. a channel-conditioned grant fires only for the matching channel
2. the same grant does not apply on a different channel
3. 🔒 an absent channel fails the guard closed (INV-A2-8)
4. 🔒 an unguarded optional-attr policy is rejected at engine construction
   (INV-A2-17)

### `ElevationContextTagTest.kt` — 178 LOC, 7 cases · unit

1. `rolesOf` exposes the wired `RoleSource`
2. a `requester_ip`-derived tag gates a `TASK_APPROVE` elevation decision
3. 🔒 a null datasource derives no tags — a tag-conditioned permit fails closed
   (INV-A2-14)
4. a null datasource still passes `requester_ip` through to Cedar (INV-A2-14)
5. a datasource-scoped tag rule fires only for the datasource in scope
6. `datasourceTags` reach the tag rule's `Datasource` entity (preset posture)
7. 🔒 tag derivation and final authorization share ONE role snapshot — no
   second, disagreeing resolution (INV-A2-10)

### `TagResolutionTest.kt` — 182 LOC, 9 cases · unit

1. a tag rule loads though its action is not predefined, and fires when its
   condition holds (INV-A2 `schemaFor`)
2. 🔒 the tag is absent when the raw signal does not match — fail closed
   (INV-A2-13)
3. an empty vocabulary short-circuits to no tags
4. a datasource-scoped tag rule fires only for the named datasource
5. a derived tag drives a consuming grant end-to-end (the full two-pass)
6. 🔒 an unguarded tag-on-tag rule is rejected at construction — `tags` absent
   from the tag-action schema (INV-A2-12)
7. 🔒 a guarded tag-on-tag rule loads but can never earn a tag — no recursion
   (INV-A2-12)
8. `effectiveAuthzContext` makes channel authoritative and discards
   caller-supplied tags (INV-A2-9)
9. the dangling-tag lint flags a consumer with no producer and a producer with
   no consumer

Case 8 tests `effectiveAuthzContext`, which lives in A6 (`Query.kt`) —
cross-area.

### `PolicyOriginDbTest.kt` — 240 LOC, 5 cases · **DB**

1. 🔒 the shipped default security posture is unchanged
2. a clean database installs the admin and audit system rows
3. the development preset ships **enabled** and the production preset ships
   **disabled**
4. 🔒 the four origin constraints reject every cross-namespace raw insert
5. explicit negative ids do not disturb the user sequence and a system upsert
   preserves `disabled`

Case 1 is a **golden posture** test — exactly the kind of fixture §Layer 0 of
the harness should capture before cutover.

### `PresetPolicyDbTest.kt` — 286 LOC, 9 cases · **DB**, the preset matrix

1. development role matrix grants connect and only the corresponding SQL kind
2. production role matrix grants connect and only the corresponding SQL kind
   once enabled
3. development reads cleartext including PII because dev holds no PII
4. development system floor permits catalog, activity, and data-leak but never
   critical
5. 🔒 production is denied until enabled, then masks PII unless a pii-accessor
   earns trusted-network
6. production PII unmasks via the `workflow-executor` channel off
   trusted-network and re-masks at the viewer
7. 🔒 production system surfaces stay closed even for a pii-accessor on
   trusted-network
8. default developer group connects, selects, writes, and reads dev data
   cleartext
9. 🔒 a forged preset-development tag is honored on a datasource but stripped
   off a column (INV-A2-7)

Cases 5–7 are the production-posture core: they encode the intended difference
between dev and prod and are the single best end-to-end check that the ported
Cedar layer decides identically.

### Fixture dependencies

`support/TestDatabases.kt` (shared containers) for the 5 DB suites;
`ktor-server-test-host` for the 2 route suites; the rest construct
`CedarEngine(List<Pair<Long,String>>)` directly — **no DB, no Testcontainers**.

| Kind                            | Suites                                                                                                                                                  | Cases  |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| unit (in-memory `CedarEngine`)  | `AuthzTest`, `AuthzDatasourceActionTest`, `ColumnAuthzTest`, `AdminGateTest`, `ChannelContextAuthzTest`, `ElevationContextTagTest`, `TagResolutionTest` | **53** |
| DB (Testcontainers Postgres)    | `CedarEngineCacheTest`, `CedarPolicyStoreTest`, `CedarPolicyOriginTest`, `PolicyOriginDbTest`, `PresetPolicyDbTest`                                     | 29     |
| route (`ktor-server-test-host`) | `CedarPolicyRoutesTest`, `AdminContextAuthzTest`                                                                                                        | 8      |

The 53 unit cases need no store and no container — they are portable the moment
a Cedar decision is available. **Port them first: they are the cheapest possible
signal on S1**, and they cover every 🔒 invariant in §3–§6 except the store-side
ones (INV-A2-19..22).

### Coverage gaps in A2

No test covers: `evaluatesInCedar` directly (only via `/auth/debug`);
`authorizeFunctions` or `authorizeUtilities` at unit level (only through A6's
enforcement suites); INV-A2-11's "unclassified utility marshalled ⇒ wrongly
permitted" inversion; `contextTagLint`'s output being surfaced in `/health`;
concurrent `rebuildIfStale` (the `@Synchronized`/torn-cache guarantee). The
utility-marshalling inversion is a **security** gap and a prime Step 3 hardening
target.

---

## 11. Open questions

| #   | Question                                                                                                                                                                                                                                                                                                                                                         |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | `Authz.kt:757-758` documents an `AuthzResource.Datasource` variant that does not exist (F1). Confirm it was removed (not renamed). Disposition is already settled: **REPRODUCE** the name-keyed marshalling, **OMIT** the comment — a stale KDoc has no observable behaviour.                                                                                    |
| Q2  | Does any test rely on cedar-java's duplicate-entity **error**? Either answer, `dedupeByEuid` is **REPRODUCE** — it decides whether a duplicated EUID authorizes or throws, which is observable at the Cedar call. A map-keyed Go entity set that silently last-wins is a behaviour change, so raise it as its own decision rather than folding it into the port. |
| Q3  | `CedarPolicy.updatedAt` uses Java `Instant.toString()` variable-precision formatting. Is `web/` sensitive to it, or can the Go port emit fixed-precision RFC3339?                                                                                                                                                                                                |
| Q4  | `schemaFor` declares `tailscale_caps?: Set<String>`, absent from `AuthzContext`. Is a deployment injecting it, or is it vestigial?                                                                                                                                                                                                                               |
| Q5  | `insertReturningId` is dead (F2). Disposition **OMIT** — it is `private` with no call path, so no test fixture depends on it. Confirm the grep, then simply leave it out of the Go store.                                                                                                                                                                        |
| Q6  | The seven S-questions in §9 are the Cedar spike's charter.                                                                                                                                                                                                                                                                                                       |
