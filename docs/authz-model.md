# Authz model — RBAC statements, masking as column config, enforced by Cedar

The fundamental model — the analyzer states facts and Cedar sets policy over
every tagged resource per datasource (not just columns but functions, UDFs, and
system catalog objects; `system:` tags; schema-aware resource keys; datasource
postures) — is [`access-model.md`](./access-model.md). This doc is the
RBAC-spine and Cedar policy-language detail it builds on: roles, statements,
masking-as-column-config, and the `result.read.*` decision.

## Decision (TL;DR)

A role is a set of statements —
`allow <action> on <selector> [when <condition>]`. Roles are assigned to users
directly, via groups, or via a time-boxed JIT grant. Masking is column
configuration, not authorization: a column _may_ carry tags, and — if it should
be masked — one mask fn. Most columns have neither. Authorization is
deny-by-default, evaluated by Cedar (`cedar-java`): for each column a query
touches, a `result.read.unmasked` grant returns cleartext; else a
`result.read.masked` grant returns the column's configured mask (or a safe
default); else deny. Uncovered table scans, classified functions and utilities,
and datasource statement actions are authorized from the same analyzer facts.
Conditions (e.g. network isolation) are Cedar `context`. Cedar sits upstream in
the control-plane and produces the ALLOW/MASK/DENY verdict and ordinal masks the
wire brokers consume.

Two layers, kept strictly separate:

- Role resolution (layer 1):
  `RoleResolver.resolve(principal) = direct ∪ group ∪ active JIT grants`. Expiry
  and revocation live only here. A JIT grant is nothing but "role R assigned
  with an `expires_at`."
- Authorization (layer 2, Cedar): takes the resolved role set + the touched
  resources + context, and answers the analyzer's datasource, result-read,
  Function, and Utility grants. It never sees role grants, expiry, or how a role
  was assigned.

## Why Cedar

- Deny-by-default native, with `forbid`-override when needed.
- Entity hierarchy (`in`): a column `in Tag::"pii"`, `in Table::…`,
  `in Datasource::…`. Entities are passed per request from the live catalog —
  there is no policy store to materialize or sync for tag→column membership, so
  nothing drifts.
- Conditions are first-class `context`
  (`when { context.tags.contains("trusted-network") }`) — no separate expression
  language, no CEL.
- Schema, validation, and formal analysis: you can _prove_ properties like "no
  policy grants cleartext PII off the trusted network." Real value for a
  fail-closed product.
- `com.cedarpolicy:cedar-java` is loaded from Maven Central. Tradeoff: its Rust
  core uses JNI; the `uber` artifact bundles macOS, Linux, and Windows natives
  for x86_64 and aarch64.

Admins author Cedar policies directly. The grants (what a role may do) _are_
Cedar policy text, validated against a schema with entity types
`System`/`User`/`Role`/`Group`/`Datasource`/`Table`/`Column`/`Tag`/`Function`/
`Utility`/`Request`/`AccessGrant`/`Token`/`AuditRecord`/`AuditLog` plus the
action set. This is far less to build than a row-authoring UI plus a row→Cedar
generator, plays to Cedar's strengths (schema validation, formal analysis,
gitops-reviewable text), and fits a technical admin audience. Structured data
stays structured and is NOT policy: identity (role assignments, group
membership, JIT grants) and column config (tags, mask fn) are rows, resolved
per-request into Cedar _entities_. A row-based policy builder for non-technical
self-service is a possible later convenience.

## Concepts

- User / Group — a group maps to roles.
- Role — the assignable unit; a named set of statements.
- Statement — `allow <action> on <selector> [when <condition>]`.
- Column config — per column, both optional: tags (freeform labels, e.g. `pii`,
  `financial`; most columns have none) and a mask fn (only on columns you mask).
  Tags are _just groupings_ for statements; they carry no built-in "protected"
  meaning.
- Action — dot-scoped by capability domain: `result.read.unmasked` /
  `result.read.masked` (column value visibility);
  `sql.select`/`sql.insert`/`sql.update`/`sql.delete`/`sql.ddl` (statement
  kinds); `sql.unanalyzable`/`sql.unmaskable` (datasource-exception gates);
  `datasource.connect`; the approval lifecycle `task.request`/`task.read`/
  `task.approve`/`task.assume`/`task.cancel`/`task.delete` and `grant.revoke`;
  `token.mint`/`token.list`/`token.revoke` (credential issuance/management);
  `audit.read`; and `admin.datasources`/ `admin.policies`/`admin.identity`.
  Context-tag policies use generated `context.tag::<name>` actions.
- Selector (resource) — a tag (`tag:pii`), a path (`datasource:acme-mysql`,
  `…/table:orders`, `…/column:email`), or `*`.
- Condition — Cedar `context` (network zones, channel, requester IP, and derived
  tags); the request-context model and its attestation are in
  [`authz-context.md`](./authz-context.md). Fail-closed: absent / unattributable
  / error → condition false.

Deny-by-default is the whole protection model. Nothing is readable without a
matching grant. "Most columns are innocuous" is not a special case — it is just
a broad grant (`allow read on datasource:x`) that you do not extend to the
sensitive columns. There is no per-column "protected" flag, no sensitivity enum,
no restricted-tag registry.

Tagging is the control, and its failure mode is real. The common pattern — "read
table X _except_ pii" (`unless resource in Tag::"pii"`) — is fail-open on a
missing tag: a genuinely-PII column left untagged is not `in Tag::"pii"`, so the
exclusion does not catch it and it is returned cleartext. Cedar is not the risk;
the reliability of the pii tagging is. Wherever you rely on "except pii," the
classification pipeline that keeps those tags complete is load-bearing.

## Worked examples

Column config (catalog side, set by data owners):

```
  acme-mysql/def/app/users/email   tags=[pii]        mask=email-domain-only
  acme-mysql/def/app/users/rrn     tags=[pii]        mask=last4
  acme-mysql/def/app/orders/amount tags=[financial]  mask=fixed
```

The equivalent PostgreSQL identity is, for example,
`acme-pg/acme/public/users/email`: datasource / catalog (bound database) /
schema / table / column.

Policies — the roles' grants, authored directly as Cedar and validated against
the schema:

```cedar
// analyst: read app.users EXCEPT pii-tagged columns; pii columns are masked instead
permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Table::"acme-mysql/def/app/users")
    unless { resource in Tag::"pii" };
permit(principal in Role::"analyst", action == Action::"result.read.masked",   resource in Table::"acme-mysql/def/app/users")
    when   { resource in Tag::"pii" };
// pii-reader: cleartext pii, only from the trusted network
permit(principal in Role::"pii-reader", action == Action::"result.read.unmasked", resource in Tag::"pii")
    when { context has tags && context.tags.contains("trusted-network") };
// billing-ops: read the orders table
permit(principal in Role::"billing-ops", action == Action::"result.read.unmasked", resource in Table::"acme-mysql/def/app/orders");
// batch-writer: insert into the datasource
permit(principal in Role::"batch-writer",  action == Action::"sql.insert", resource in Datasource::"acme-mysql");
// approve: the resource is the Request (in Datasource::"acme-mysql", carrying a `requester` attribute)
permit(principal in Role::"acme-approver", action == Action::"task.approve", resource in Datasource::"acme-mysql");
// no self-approval — authoritative forbid, overrides any permit
forbid(principal, action == Action::"task.approve", resource) when { principal == resource.requester };
permit(principal in Role::"system:admin",  action in [Action::"admin.datasources", Action::"admin.policies", Action::"admin.identity"], resource);
```

The `analyst` pair is the "read the table except pii" pattern you will want
constantly; note its failure mode — the exclusion is only as good as the pii
tagging.

Per decision, entities are marshaled from the catalog + resolved roles:

```
User::"alice@example.com"  in [Role::"analyst", Role::"pii-reader"]     // roles resolved in layer 1 (incl. JIT)
Column::"acme-mysql/def/app/users/email"
  in [Tag::"pii", Table::"acme-mysql/def/app/users", Datasource::"acme-mysql"]
context = { tags: ["trusted-network"] }
```

The full resource id is load-bearing: the analyzer emits `def.app.users.email`,
the control-plane matches that exact catalog row, and any missing
`catalog.schema.table.column` match denies rather than shortening the key. Per
touched column: `isAuthorized(result.read.unmasked)` → cleartext; else
`isAuthorized(result.read.masked)` → apply the column's mask fn; else deny. The
mask fn is ours; Cedar only picks unmasked / masked / deny.

## Data model

- `policy` — the grant store, held as Cedar policy text, validated against the
  schema on write. A role's grants are the enabled policies that mention it.
  There is no `role_statement` row→Cedar generation. The table schema and the
  system/user id convention are owned by
  [policy-store.md](./policy-store.md#target-schema).
- `column_classification` carries `tags JSONB` and `mask_fn_id` — the per-column
  config.
- `classification_profile`, `classification_profile_rule`, and
  `datasource_classification_profile` — a named rule set several datasources
  share, plus its attachments. A column's effective tags are the union of the
  datasource's own row and every attached profile, so a per-datasource override
  adds tags but never drops one a profile applied; the mask function instead
  resolves by precedence, the datasource's own row first.
  `DatasourceStore.classificationsFor` is the single resolution both read paths
  use.
- Identity: `app_role`, `principal_role`, `app_group`, `group_member`,
  `group_role`, `app_user`.
- `access_grant(id, request_id, principal, role_id, granted_by, granted_at, expires_at, revoked_at)`
  — a JIT grant is a role assignment with an expiry.
- `mask_fn` — the mask function registry.
- `audit_event` records each decision — principal, roles, datasource, statement,
  verdict — plus `channel` and the derived `context_tags` (see
  [`authz-context.md`](./authz-context.md)).

Approval routing is Cedar, not a config table: who may approve is a
`task.approve` policy on the request, and the rest of the workflow is fixed —
single approval, a single execution path (the approver runs the approved query
under role `R` and stores the result, masked exactly as `R` would see it), and
no requester re-execution grant. The inherited `requested_duration_sec` column
is stored but not consumed by query approval. When any of these must vary per
resource, reintroduce it as data — a small rule row or a Cedar `context` value.

## Enforcement

One decision point — `decideQuery(principal, ds, sql, channel, …)` (`Query.kt`),
called identically by the wire proxy and the editor. Two phases: engine
(structural facts) then authorize (Cedar, deny-by-default).

Admission (the sqlglot-go probe): what the query _is_, no authz decision. Parse
and hard-deny structurally inadmissible input such as an ambiguous batch. Emit
one or more datasource action grants
(`sql.select`/`insert`/`update`/`delete`/`ddl`), resource grants, and a failure
class when complete lineage cannot be proved. Dangerous functions and utilities
are facts for the authorization phase, not admission hardcodes. Column grants
carry output ordinals and a `MaskedDisposition`.

Authorize (Cedar, deny-by-default; consumes admission's required grants):

```
resolveRoles(principal)                         -- layer 1: direct ∪ group ∪ active JIT grants (expiry here)
isAuthorized(datasource.connect)                -- else DENY: "no access to datasource"
authorize classified Utility grants             -- missing classification or permit -> DENY
for each emitted datasource action:
      isAuthorized(sql.<action>)                 -- write kinds deny-by-default
if unresolved: isAuthorized(sql.unanalyzable)   -- else DENY; permit relays verbatim
authorize classified Function grants            -- system policy decides
for each Column grant c:
      unmasked   if isAuthorized(result.read.unmasked, c)
      c.maskFn   else if isAuthorized(result.read.masked, c)   -- safe default if c has no mask fn
      DENY       otherwise
      DENY       if masked and c's MaskedDisposition forbids masking
authorize each uncovered Table scan              -- either result-read action permits
```

`decideQuery` returns DENY if any required grant fails, MASK if an output grant
requires masking, else ALLOW. Each `ColumnMask` carries the analyzer's
zero-based output ordinal; `goproxy` applies masks by ordinal, never by name.
The analyzer and proxy never evaluate Cedar, roles, tags, or context.

Writes and DDL. A write must pass its emitted `sql.*` action; and since every
column a write reads or targets is a _reference_ (non-maskable), any
masked-or-denied column in a write is a DENY (you cannot mask a write). Plain
DDL with a supported analyzer shape, such as `CREATE TABLE (cols)`, is gated by
`sql.ddl` (no data flow, no lineage), fully audited. `ALTER`, `DROP`, and
`TRUNCATE` currently also require `sql.unanalyzable` because their roots are not
lineage-analyzed. DDL that reads data — `CREATE TABLE … AS SELECT` (CTAS),
`CREATE VIEW` — is _also_ a write: it needs `sql.ddl` and is subject to the
write rule, so a masked/denied column in its `SELECT` is a DENY. This is the
classic exfiltration path (copy PII into a fresh, unprotected table), so it must
fail closed.

Worked walk-throughs — policies + column config from
[Worked examples](#worked-examples) above; `alice` holds `analyst`
(`email`→`email-domain-only`, `rrn`→`last4`, both tagged `pii`):

<!-- prettier-ignore -->
| query | admission (+ lineage) | authorize | outcome |
| --- | --- | --- | --- |
| `SELECT id, email, rrn FROM users` | `select`; outputs `{id, email, rrn}` | connect ok · `sql.select` ok · `id`→unmasked · `email`,`rrn`→ no unmasked, `result.read.masked` ok | MASK `{id, email→domain, rrn→last4}` |
| `SELECT id FROM users WHERE rrn = '…'` | `select`; output `{id}`; ref `{rrn}` | `id` ok — but `rrn` is a _reference_ and `alice` has no `result.read.unmasked` on it | DENY (predicate inference-oracle) |
| `UPDATE users SET name = rrn WHERE id = 1` | `update` (write); `rrn` read into the write | `sql.update` ungranted → deny; even granted, `rrn` in a write is non-maskable | DENY (write) |
| `CREATE TABLE t (id INT)` | `ddl` (plain, no data flow) | `sql.ddl` is the whole gate (no lineage) | DENY if ungranted (audited) |
| `CREATE TABLE leaked AS SELECT rrn FROM users` | `ddl` + write; payload reads `users.rrn` | `sql.ddl` ungranted → deny; even granted, `rrn` copied into a persisted table is a non-maskable write payload | DENY (exfiltration — write-payload) |

## Statement kinds

Admission emits datasource grants for select / insert / update / delete / ddl.
Some statements require more than one: an upsert that can update requires both
`sql.insert` and `sql.update`. Write actions are deny-by-default until
explicitly granted per role. An unspecified action, including `REPLACE` and
`MERGE`, denies.

## The authz boundary (a separable module)

Authz is a decision service. Its core single-resource primitive is backed by
Cedar:

```
authorize(principal, action, resource, context) -> ALLOW | DENY(reason)
```

Every feature that needs a permission decision calls this; none of them live
inside authz. Each owns its own logic and workflow and asks authz only _"may
this principal do this?"_

For the query hot path, `decideQuery` orchestrates the analyzer facts and the
batched authz helpers; authz never parses SQL:

```
decideQuery(principal, datasource, sql, channel, ...)
    -> DecisionContext(ALLOW | MASK | DENY, masks=[ColumnMask(ordinal, kind)], ...)
```

`ordinal` = a column's 0-based result-set position (masks bind by position,
never name). `decideQuery` resolves each masked ordinal to its column's mask fn
and kind from the catalog. Authz decides _whether_ to mask; config decides
_how_.

The concerns you might expect to be "in authz" are consumers that call it, each
owning its own workflow:

- Query enforcement (wire proxy / editor): analyzer facts → `decideQuery`
  (Cedar + catalog mask fns) → proxy masks by ordinal.
- Approval workflow (its own module): owns the whole lifecycle — create / inbox
  / decide / execute / encrypted-result storage + retention. It calls authz only
  to decide _who may act_. The whole lifecycle is Cedar-gated: `task.request`
  (open a request against a datasource), `task.approve` (approve / reject, and
  run the query under role R; plus the self-approval `forbid`), `task.read`
  (request/grant metadata), `task.assume` (view the two-party stored result
  under role R), and `grant.revoke` for JIT access grants. The `task.cancel` and
  `task.delete` actions exist in the schema but have no workflow route. On
  execute the proxy re-runs the approved query through `decideQuery` as the
  approver with `providedRoles={R}`. Routing is Cedar policies scoped by the
  request's Role / Datasource.
- Admin API / UI: each route gates on
  `authorize(principal, admin.*, resource, context)`; the endpoints and their
  side effects are the API's.

Authz's own writable state is just the Cedar policy store (`create` / `update` /
`setEnabled` / `delete`, with validation). Role assignments, JIT grants, and
column config are identity/catalog data authz only _reads_, managed by their own
admin surfaces. `Authz` depends on the `RoleSource` interface; query callers
supply catalog facts and tags to the batched authorization helpers. Cedar, the
schema, entity marshaling, and the policy store stay internal.

## HTTP auth gates

Every control-plane HTTP route funnels through one of four gate helpers. Which
one a route calls _is_ its auth requirement; grep the helper name to find its
call sites. Per-route request and response shapes are the Kotlin DTO data
classes in the owning file.

Handler names do not track their path prefixes, so this is how to find the owner
of a route and the gate it calls. Paths are relative to
`control-plane/src/main/kotlin/com/ridi/oss/proxymonster/controlplane/`.

<!-- prettier-ignore -->
| Route group | Path prefix | Owner file | Auth |
| --- | --- | --- | --- |
| Health, auth config, debug login, logout | `/health`, `/auth/config`, `/auth/debug`, `/auth/logout` | `App.kt` | none (`/auth/debug` 404s unless `PM_AUTH_DEBUG`) |
| Web session | `/auth/me`, `/auth/session/status`, `/auth/session/heartbeat` | `App.kt` | Ktor `authenticate(WEB_SESSION_AUTH)` |
| OIDC web login | `/auth/oidc/login`, `/auth/oidc/callback` | `Oidc.kt` | none — this mints the session |
| CLI device authorization | `/auth/device/start`, `/auth/device/poll` | `DeviceAuth.kt` | none — the handle plus the IdP grant are the credential |
| Daemon session renew | `/auth/session/renew` | `DaemonSession.kt` | `Authorization: Bearer <renewalToken>` only |
| OAuth 2.1 authorization server | `/.well-known/oauth-authorization-server`, `/oauth/**` | `oauth/OAuthRoutes.kt` | protocol-native (PKCE, client metadata, consent CSRF); `/oauth/consents` needs a session |
| MCP admin surface | `/mcp`, `/.well-known/oauth-protected-resource**` | `mcp/McpServer.kt` | MCP access-token bearer + host/origin checks in an interceptor; metadata routes public |
| SCIM 2.0 provisioning | `/api/scim/v2/**` | `Scim.kt` | `requireScimAuth` — `PM_SCIM_TOKEN` bearer, TLS-only; 501 when unconfigured |
| Audit ingest (from the proxy) | `/api/ingest/decision` | `App.kt` | `X-PM-Ingest-Token` vs `PM_SECRET_TOKEN`; open when that env is unset (dev only) |
| Audit read | `/api/audit`, `/api/audit/{id}` | `AuditRoutes.kt` | `requireApi` + Cedar `audit.read` — allow on `AuditLog` returns all rows, else own rows only |
| Caller capability summary | `/api/me/permissions` | `App.kt` | `requireApi`; UI convenience, computed from `admin.*` + `audit.read` |
| Datasources, catalog, classification | `/api/datasources**` | `Datasources.kt` | mixed: list = `requireApiOrBearer`; `live`, `{id}` = `requireApi`; `{id}/catalog` = `requireApi` + `datasource.connect`; rest = `requireAdmin(admin.datasources)` |
| Classification profiles + attachments | `/api/classification-profiles**`, `/api/datasources/{id}/classification-profiles**` | `ClassificationProfileRoutes.kt` | `requireAdmin(admin.datasources)` |
| One-shot editor query | `/api/datasources/{id}/query` | `Query.kt` | `requireApi`, then the per-statement `decideQuery` |
| Editor sessions and tasks | `/api/editor/**` | `Query.kt` | `requireApi` + owner scope; cancel adds `task.cancel`, result adds `task.assume` |
| Task-completion SSE | `/api/tasks/events` | `App.kt` | resolves the session itself; each push re-filtered through `task.read` |
| Editor query history | `/api/query-history` | `QueryHistory.kt` | `requireApi`, own rows only |
| Query-approval workflow | `/api/approvals**` | `Approvals.kt` | `requireApi` + per-route Cedar (`task.read` / `task.approve` / `task.cancel` / `task.assume`) |
| JIT access requests and grants | `/api/access-requests**`, `/api/access-grants**` | `Access.kt` | `requireApi` + `task.read` forward-filtering; revoke = `requireAuthz(grant.revoke)` |
| Wire tokens | `/api/wire-tokens`, `/api/tokens**` | `Tokens.kt` | `requireAuthz(token.mint / token.list / token.revoke)` on the token's real owner and kind |
| Roles, mask functions | `/api/roles**`, `/api/mask-fns**` | `Policies.kt` | `requireAdmin(admin.policies)`; `GET /api/roles` is `requireApi` |
| Principal-to-role assignment | `/api/role-assignments**` | `Policies.kt` | `requireAdmin(admin.identity)` |
| Users, groups, group-to-role map | `/api/users**`, `/api/groups**` | `Users.kt` | `requireAdmin(admin.identity)` |
| Cedar policies | `/api/policies**` | `authz/CedarPolicyStore.kt` | `requireAdmin(admin.policies)` |

- `requireApi(config)` (`Datasources.kt`) — a live web session, or
  `PM_AUTH_DEBUG`. Authentication only, no authorization. Routes behind it do
  their own per-row Cedar filtering (audit, tasks, grants).
- `requireAdmin(config, authz, action)` (`authz/Authz.kt`) — a session plus
  `authorize(principal, admin.datasources | admin.policies | admin.identity, System) == Allow`.
  401 (`common.unauthenticated`) without a session, 403 (`common.forbidden`,
  carrying the Cedar deny reason) on a deny. A session alone is never enough.
- `requireAuthz(config, authz, action, resource)` — the same gate for non-admin,
  resource-scoped actions: token mint / list / revoke (`Tokens.kt`) and grant
  revoke (`Access.kt`), where the resource is built from the row the call
  targets.
- `requireScimAuth(config)` (`Scim.kt`) — the standing `PM_SCIM_TOKEN` bearer,
  constant-time compared, TLS-only. Not a session and not Cedar: this is an
  IdP-to-control-plane integration ([`auth-model.md`](./auth-model.md)).

`PM_AUTH_DEBUG` short-circuits all four to allow. It is a full authentication
bypass and must be off in production.

Ungated by design: `GET /health`, `GET /auth/config`, the OIDC and
device-authorization routes (they mint the session), and `POST /auth/logout`,
which clears the cookie unconditionally. `POST /auth/debug` returns 404 unless
`PM_AUTH_DEBUG` is set. The OAuth 2.1 authorization-server routes and `/mcp`
carry their own credential checks — PKCE, client-metadata validation, and an MCP
access-token bearer resolved in an interceptor
([`mcp-access-control.md`](./mcp-access-control.md)). `/auth/me`,
`/auth/session/status`, and `/auth/session/heartbeat` sit inside Ktor's
`WEB_SESSION_AUTH` authentication block instead of a helper.
`POST /auth/session/renew` authenticates by the mint-once renewal-token bearer
only — never a request-body principal. The task-event SSE stream resolves the
session itself, ends the stream when there is none, and re-checks `task.read`
per pushed event.

Two exceptions to "session or nothing":

- `POST /api/ingest/decision` is the proxy's audit-ingest path. It checks
  `X-PM-Ingest-Token` against `PM_SECRET_TOKEN` — and when that env is unset the
  gate is open to any caller, which is dev-only.
- `GET /api/datasources` is the one `/api/**` route that also accepts
  `Authorization: Bearer <wire token>` (`requireApiOrBearer`, private to
  `Datasources.kt`), because `pmon` must discover datasources without a browser
  cookie. Only the native-wire kinds `SESSION` and `USER` are accepted; `EDITOR`
  and `APPROVER_EXEC` are rejected, and a deactivated principal's surviving
  token fails closed. Roles are still resolved server-side, so this is an extra
  authentication surface, not a privilege grant, and it is wired into this one
  read-only route: a leaked wire token cannot mutate a datasource or mint
  another credential over HTTP.

`GET /api/datasources?connectable=true` narrows the list to datasources the
caller may `datasource.connect` to — the same name-keyed Cedar decision, with
derived context tags, the proxy runs on connect. The unfiltered default is
deliberate: JIT-request compose must show datasources you cannot yet connect to,
precisely so they can be requested. The catalog itself
(`GET /api/datasources/{id}/catalog`) is connect-gated, returning
`datasource.not_connectable` otherwise.

## What this fixes (falls out of the model, not bolted on)

- Admin routes require `admin.*` — not "any authenticated session."
- No self-approval bypass: `task.approve` on the request (which is
  `in Datasource::…`) grants eligibility, and an authoritative
  `forbid … when { principal == resource.requester }` bans self-approval. The
  request is the resource and carries the requester, so `≠` is a Cedar
  condition, not an app check.
- `principal_role` is enforced — `resolveRoles` includes it.
- Classified columns are deny-by-default; a column is unreadable unless a
  statement grants it.

## Open questions

- Tagging reliability — "read except `tag:pii`" is fail-open on a missing tag: a
  genuinely-PII column left untagged is returned cleartext. Wherever exclusion
  grants are used, the completeness of the pii tagging is load-bearing — treat
  its reliability as an open risk.
