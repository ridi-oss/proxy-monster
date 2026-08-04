# A3 — Identity, Users, Groups, SCIM 2.0

Files: `Users.kt` (1031) · `Scim.kt` (594) · `Deprovision.kt` (106) ·
`RoleResolver.kt` (94). Total 1,825 LOC. Fully read. DB tables: `app_user`,
`app_group`, `group_member`, `group_role` (all `V1__identity.sql`), plus reads
of `app_role` / `principal_role` (A9's tables), a read of `access_grant` (A6's)
in `hasActiveAssignee`, and a `DELETE FROM principal_role` in
`releaseTombstone`. Seed data: `V8__seed.sql` (one `LOCAL` group plus **seven**
`SYSTEM` groups — see INV-A3-12).

Depth: MEDIUM. Two things push it above its LOC weight and must not be
compressed: the **teardown atomicity contract** (`Deprovision.kt`, used by
A6/A7/A11 and by A11's `replaceDirectRoles`) and the **principal-recycling**
rules in `releaseTombstone`. Both encode already-fixed security bugs.

---

## Purpose

A3 owns the local directory: who exists (`app_user`), what groups they are in
(`app_group` + `group_member`), and which roles those groups confer
(`group_role`). It owns the three write surfaces onto that directory — the admin
REST API (`/api/users**`, `/api/groups**`), SCIM 2.0 push from an IdP
(`/api/scim/v2/**`), and OIDC JIT-on-login reconciliation — and the single read
surface every enforcement path in the system depends on, `RoleResolver.resolve`.

It also owns the **deprovisioning backstop**: the per-principal advisory lock,
the one-transaction credential revoke, and the mint-side twin that closes the
check-then-mint TOCTOU. The IdP never mints a role (`V1__identity.sql:4-6`): its
group claim provisions _membership_, and `group_role` — a local, admin-owned map
— is the only thing that turns membership into a role. That separation is the
whole reason A3 exists as its own layer, and it is stated as Layer 1 in
`docs/authz-model.md` ("identity, no Cedar"); A2 is Layer 2 and consumes A3 only
through `RoleSource`.

---

## Wire contract

⚠️ **Serializer configuration is part of the contract.** `App.kt:340` —
`Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }`:

- `encodeDefaults = true` — defaulted fields **are** emitted (`schemas`,
  `active`, `emails: []`, `groups: []`, `members: []`, `memberCount: 0`,
  `roles: []` all appear in responses).
- `explicitNulls = false` — a null field is **omitted entirely**, never
  `"field": null`. So `AppUser.displayName == null` produces no `displayName`
  key at all.
- `ignoreUnknownKeys = true` — an IdP sending SCIM attributes this server does
  not model does not 400.

A Go port whose JSON emits `null` for absent optionals, or drops zero-valued
defaults, changes every DTO below. This is the single easiest way to break
`web/` and Okta simultaneously.

Content type is `application/json` for SCIM too — **not** RFC 7644's
`application/scim+json` (F33).

### `Users.kt` DTOs — `/api/users**`, `/api/groups**`

| DTO                | Field         | JSON type         | Nullable | Default | Notes                                                            |
| ------------------ | ------------- | ----------------- | -------- | ------- | ---------------------------------------------------------------- |
| `GroupRef`         | `id`          | number (i64)      | no       | —       |                                                                  |
|                    | `name`        | string            | no       | —       |                                                                  |
| `AppUser`          | `id`          | number (i64)      | no       | —       |                                                                  |
|                    | `principal`   | string            | no       | —       | globally UNIQUE in `app_user`                                    |
|                    | `displayName` | string            | **yes**  | `null`  | omitted when null                                                |
|                    | `email`       | string            | **yes**  | `null`  | omitted when null; **NOT unique** in the table (F23)             |
|                    | `source`      | string            | no       | —       | `LOCAL` \| `OIDC` \| `SCIM` \| `SYSTEM`                          |
|                    | `externalId`  | string            | **yes**  | `null`  | partial-UNIQUE where not null                                    |
|                    | `active`      | boolean           | no       | —       |                                                                  |
|                    | `createdAt`   | string            | no       | —       | `Timestamp.toInstant().toString()` — **Java variable-precision** |
|                    | `groups`      | array\<GroupRef\> | no       | `[]`    | the user's groups, `ORDER BY g.name`                             |
| `AppUserInput`     | `principal`   | string            | no       | —       | required; blank ⇒ `common.field_required`                        |
|                    | `displayName` | string            | yes      | `null`  |                                                                  |
|                    | `email`       | string            | yes      | `null`  |                                                                  |
|                    | `active`      | boolean           | no       | `true`  |                                                                  |
| `AppGroup`         | `id`          | number (i64)      | no       | —       |                                                                  |
|                    | `name`        | string            | no       | —       | globally UNIQUE                                                  |
|                    | `description` | string            | yes      | `null`  |                                                                  |
|                    | `source`      | string            | no       | —       | `LOCAL` \| `OIDC` \| `SCIM` \| `SYSTEM`                          |
|                    | `externalId`  | string            | yes      | `null`  |                                                                  |
|                    | `memberCount` | number (i32)      | no       | `0`     |                                                                  |
|                    | `roles`       | array\<GroupRef\> | no       | `[]`    | ⚠️ holds **role** id/name — see F32                              |
| `AppGroupInput`    | `name`        | string            | no       | —       | required                                                         |
|                    | `description` | string            | yes      | `null`  |                                                                  |
| `GroupMemberEntry` | `userId`      | number (i64)      | no       | —       |                                                                  |
|                    | `principal`   | string            | no       | —       |                                                                  |
|                    | `displayName` | string            | yes      | `null`  |                                                                  |
| `GroupMemberInput` | `userId`      | number (i64)      | no       | —       |                                                                  |
| `GroupRoleEntry`   | `roleId`      | number (i64)      | no       | —       |                                                                  |
|                    | `roleName`    | string            | no       | —       |                                                                  |
| `GroupRoleInput`   | `roleId`      | number (i64)      | no       | —       |                                                                  |

`AppGroup` carries **no** `createdAt` — `app_group` has no such column
(`V1__identity.sql:28-34`; `app_user` does, at `:25`).

**INV-A3-1 — `createdAt` is Java `Instant.toString()`, not RFC3339Nano.**
Trailing zeros in the fractional second are omitted (`2026-07-31T04:05:06.123Z`,
but `2026-07-31T04:05:06Z` when the fraction is zero). Same caveat as A2's
`CedarPolicy.updatedAt`; the two must be decided together, since `web/` may
parse both with one helper.

### `Scim.kt` DTOs — `/api/scim/v2/**`

Schema URN constants (`Scim.kt:35-39`), all emitted verbatim:

| Constant                              | Value                                                         |
| ------------------------------------- | ------------------------------------------------------------- |
| `SCIM_USER_SCHEMA`                    | `urn:ietf:params:scim:schemas:core:2.0:User`                  |
| `SCIM_GROUP_SCHEMA`                   | `urn:ietf:params:scim:schemas:core:2.0:Group`                 |
| `SCIM_LIST_RESPONSE_SCHEMA`           | `urn:ietf:params:scim:api:messages:2.0:ListResponse`          |
| `SCIM_ERROR_SCHEMA`                   | `urn:ietf:params:scim:api:messages:2.0:Error`                 |
| `SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA` | `urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig` |

| DTO                   | Field          | JSON type                   | Nullable | Default                                                       |
| --------------------- | -------------- | --------------------------- | -------- | ------------------------------------------------------------- |
| `ScimName`            | `formatted`    | string                      | yes      | `null`                                                        |
| `ScimEmail`           | `value`        | string                      | yes      | `null`                                                        |
|                       | `primary`      | boolean                     | yes      | `null`                                                        |
|                       | `type`         | string                      | yes      | `null` — **accepted and ignored**                             |
| `ScimUserGroupRef`    | `value`        | string                      | no       | — (the group's `id` as a decimal string)                      |
|                       | `display`      | string                      | yes      | `null`                                                        |
| `ScimMemberRef`       | `value`        | string                      | no       | — (the user's `id` as a decimal string)                       |
|                       | `display`      | string                      | yes      | `null`                                                        |
| `ScimUser`            | `schemas`      | array\<string\>             | no       | `[SCIM_USER_SCHEMA]`                                          |
|                       | `id`           | string                      | yes      | `null` — `app_user.id` as decimal                             |
|                       | `externalId`   | string                      | yes      | `null`                                                        |
|                       | `userName`     | string                      | no       | `""`                                                          |
|                       | `name`         | ScimName                    | yes      | `null`                                                        |
|                       | `emails`       | array\<ScimEmail\>          | no       | `[]`                                                          |
|                       | `active`       | boolean                     | no       | **`true`** — see F22                                          |
|                       | `groups`       | array\<ScimUserGroupRef\>   | no       | `[]` — **response-only**, ignored on input                    |
| `ScimGroup`           | `schemas`      | array\<string\>             | no       | `[SCIM_GROUP_SCHEMA]`                                         |
|                       | `id`           | string                      | yes      | `null`                                                        |
|                       | `externalId`   | string                      | yes      | `null`                                                        |
|                       | `displayName`  | string                      | no       | `""`                                                          |
|                       | `members`      | array\<ScimMemberRef\>      | no       | `[]`                                                          |
| `ScimListResponse<T>` | `schemas`      | array\<string\>             | no       | `[SCIM_LIST_RESPONSE_SCHEMA]`                                 |
|                       | `totalResults` | number (i32)                | no       | —                                                             |
|                       | `Resources`    | array\<T\>                  | no       | — (`@SerialName("Resources")`, capital R)                     |
| `ScimError`           | `schemas`      | array\<string\>             | no       | `[SCIM_ERROR_SCHEMA]`                                         |
|                       | `status`       | **string**                  | no       | — the HTTP status as a decimal string, per RFC **7644** §3.12 |
|                       | `scimType`     | string                      | yes      | `null`                                                        |
|                       | `detail`       | string                      | yes      | `null`                                                        |
| `ScimPatchOperation`  | `op`           | string                      | no       | —                                                             |
|                       | `path`         | string                      | yes      | `null`                                                        |
|                       | `value`        | any JSON                    | yes      | `null`                                                        |
| `ScimPatchOp`         | `schemas`      | array\<string\>             | no       | `[]` — **read but never validated**                           |
|                       | `Operations`   | array\<ScimPatchOperation\> | no       | `[]` (`@SerialName("Operations")`)                            |

🔒 **INV-A3-2 — `ScimError` is the ONE documented exemption from the `ApiError`
envelope** (`ApiErrors.kt:16-17` — "SCIM (`Scim.kt`) is exempt: its error body
follows the SCIM 2.0 spec for the IdP, not this envelope"; `AGENTS.md`;
INV-A1-13): the consumer is an IdP, not the web console, and an IdP parses
SCIM's own error shape. Every deliberate SCIM error path builds a `ScimError`.
**It is not airtight** — see F30: `StatusPages`' catch-all rewrites any
_uncaught_ exception on a SCIM route into `ApiError("common.fallback")`.

`ScimListResponse` carries **no `startIndex` / `itemsPerPage`** and the list
endpoints take no `startIndex`/`count`/`filter` — `ServiceProviderConfig`
honestly advertises `filter.supported = false`. `GET /Users` and `GET /Groups`
return the **entire** directory in one unbounded response, and `GET /Groups`
additionally issues one `listMembers` query per group (N+1).

### `ScimPatchAction` · sealed interface — the validator's output

| Variant     | Fields                                                                        |
| ----------- | ----------------------------------------------------------------------------- |
| `SetActive` | `active: Boolean`                                                             |
| `MemberOp`  | `op: String` (always lowercase `"add"` or `"remove"`), `values: List<String>` |

`ScimPatchInvalidException(scimType: String, detailMessage: String)` — carries
the SCIM `scimType` the route echoes.

### Static discovery documents

Built once as `JsonObject`/`JsonArray` literals, served verbatim.

`SERVICE_PROVIDER_CONFIG` (`Scim.kt:235-255`): `patch.supported = true`;
`bulk.supported = false, maxOperations = 0, maxPayloadSize = 0`;
`filter.supported = false, maxResults = 0`; `changePassword.supported = false`;
`sort.supported = false`; `etag.supported = false`; one `authenticationSchemes`
entry
`{type: "oauthbearertoken", name: "OAuth Bearer Token", description: "Authentication via a standing PM_SCIM_TOKEN bearer credential, TLS-only", primary: true}`.
No `meta`, no `documentationUri`.

`RESOURCE_TYPES` (`Scim.kt:257-276`): a bare **array** of two objects (`User` →
`/Users`, `Group` → `/Groups`), each with `schemas: [urn:...:ResourceType]`,
`id`, `name`, `endpoint`, `schema`.

`SCHEMAS` (`Scim.kt:278-304`): a bare **array** of two schema objects. `User`
attributes: `userName`/`externalId` (string, readWrite), `name` (complex,
readWrite), `emails` (complex, multiValued, readWrite), `active` (boolean,
readWrite), `groups` (complex, multiValued, **readOnly**). `Group` attributes:
`displayName`/`externalId` (string, readWrite), `members` (complex, multiValued,
readWrite).

⚠️ Asymmetry inside the two discovery arrays: each `RESOURCE_TYPES` entry
carries a `schemas` key
(`[urn:ietf:params:scim:schemas:core:2.0:ResourceType]`), but the two `SCHEMAS`
entries carry **only** `id`, `name`, `attributes` — no `schemas` key, no `meta`,
no per-attribute `required`/`caseExact`/ `returned`/`uniqueness`. Replicate the
omissions; they are part of the bytes Okta already accepts.

RFC 7644 §4 wants `/ResourceTypes` and `/Schemas` wrapped in a `ListResponse`;
these return bare arrays (F33). Okta tolerates it today.

---

## Routes

### Admin REST — `Users.kt:892-1031`

Every route: `requireAdmin(config, authz, AuthzAction.ADMIN_IDENTITY)` (A2's
gate; `System` resource). Matches `docs/authz-model.md:345`. All mutations
delegate to `IdentityManagementService` (**A11**) and map `ManagementException`
through `respondManagementError` (`Datasources.kt:709-717`). That helper's
**full** mapping (it is shared with A5/A9/A11, so port all of it, not just A3's
reachable subset): `common.not_found` → **404** ·
`datasource.table_introspection_failed` → **502** · `group.system_immutable` /
`role.system_immutable` / `policy.system_immutable` → **409** · everything else
→ **400**. Only the first and third arms are reachable from A3's fourteen
routes.

The `ApiError` codes A11 raises for these routes come from three one-line
helpers (`ManagementServices.kt:716-731`): `required(field, value)` ⇒
`common.field_required{fields:<field>}` on blank, `notFound(resource)` ⇒
`common.not_found{resource:<resource>}`, and `unique(resource, name) { … }` ⇒
`common.already_exists{resource,name}` on SQLSTATE `23505`. Note the `resource`
values are **not** uniform with the route path: user creates/updates pass
`unique("principal", …)` but `notFound("user")`, while group ones pass
`unique("group", …)` and `notFound("group")`.

| Method | Path                                | Gate                         | Success                    | Error codes                                                                                                                |
| ------ | ----------------------------------- | ---------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/api/users`                        | requireAdmin(ADMIN_IDENTITY) | 200 `[AppUser]`            | 401 `common.unauthenticated`, 403 `common.forbidden`                                                                       |
| POST   | `/api/users`                        | ↑                            | **201** `AppUser`          | 400 `common.field_required{fields:principal}`, 409 `common.already_exists{resource:principal,name}`                        |
| PUT    | `/api/users/{id}`                   | ↑                            | 200 `AppUser`              | 400 `common.bad_id`, 400 `common.field_required`, 404 `common.not_found{resource:user}`, 409 `common.already_exists`       |
| DELETE | `/api/users/{id}`                   | ↑                            | **204**                    | 400 `common.bad_id`, 404 `common.not_found{resource:user}`                                                                 |
| GET    | `/api/groups`                       | ↑                            | 200 `[AppGroup]`           | 401/403                                                                                                                    |
| POST   | `/api/groups`                       | ↑                            | **201** `AppGroup`         | 400 `common.field_required{fields:name}`, 409 `common.already_exists{resource:group,name}`                                 |
| PUT    | `/api/groups/{id}`                  | ↑                            | 200 `AppGroup`             | 400 `common.bad_id`, 404 `common.not_found{resource:group}`, **409 `group.system_immutable`**, 409 `common.already_exists` |
| DELETE | `/api/groups/{id}`                  | ↑                            | **204**                    | 400 `common.bad_id`, 404, **409 `group.system_immutable`**                                                                 |
| GET    | `/api/groups/{id}/members`          | ↑                            | 200 `[GroupMemberEntry]`   | 400 `common.bad_id`, 404 `common.not_found{resource:group}`                                                                |
| POST   | `/api/groups/{id}/members`          | ↑                            | **201** `GroupMemberEntry` | 400 `common.bad_id`, 404 `{resource:group\|user}`, 409 `group.system_immutable`                                            |
| DELETE | `/api/groups/{id}/members/{userId}` | ↑                            | **204**                    | 400 `common.bad_id` (either param), 404 `common.not_found{resource:group member}`, 409 `group.system_immutable`            |
| GET    | `/api/groups/{id}/roles`            | ↑                            | 200 `[GroupRoleEntry]`     | 400 `common.bad_id`, 404 `{resource:group}`                                                                                |
| POST   | `/api/groups/{id}/roles`            | ↑                            | **201** `GroupRoleEntry`   | 400 `common.bad_id`, 404 `{resource:group\|role}`, 409 `group.system_immutable`                                            |
| DELETE | `/api/groups/{id}/roles/{roleId}`   | ↑                            | **204**                    | 400 `common.bad_id`, 404 `{resource:group role mapping}`, 409 `group.system_immutable`                                     |

`idParam()` = `parameters["id"]?.toLongOrNull()` (`Datasources.kt:707`);
`{userId}`/`{roleId}` are parsed inline the same way.

⚠️ The `group.system_immutable` 409 is raised by **two different A11
mechanisms**, and the difference is a concurrency one a port must keep: the
`/members` routes use `rejectSystem` → `isSystemGroup(group.id, c)`, a plain
read on the transaction's connection, while the `/roles` routes use
`lockMutableGroup(id, c)` →
`SELECT source FROM app_group WHERE id = ? FOR UPDATE`, which both
existence-checks (404 `{resource:group}`) and SYSTEM-checks **under a row lock**
(`lockMutableGroup` at `ManagementServices.kt:703-710`; `rejectSystem` at
`:712-714`; the by-id `addGroupMember`/`removeGroupMember` at
`:630-636`/`:651-656`, `addGroupRole`/`removeGroupRole` at
`:670-675`/`:677-681`). That row lock is what `UserAdminDeprovisionDbTest` case
10's two-thread race actually exercises. Same story as INV-A3-45 one layer up:
two guards for one rule, only one of them hardened.

⚠️ Note the asymmetry: the two **read** sub-routes (`/members`, `/roles` GET)
call `store.getGroup` / `store.listMembers` / `store.listGroupRoles`
**directly**, bypassing `IdentityManagementService`. Harmless (reads need no
SYSTEM guard) but it means those two are the only identity routes not funnelled
through A11.

⚠️ `userGroupRoutes`' `management` parameter has a **default** that builds a
fresh `IdentityManagementService` with a _new_ `PolicyStore`
(`Users.kt:899-901`). `App.kt:633-635` passes the shared `identityManagement`
explicitly, so the default is test-only. `PolicyStore` holds no cache, so this
is not the A2 `ControlPlaneCore` hazard — but do not reproduce the default in Go
without checking that whatever it constructs is cache-free.

### SCIM 2.0 — `Scim.kt:320-594`

Every route: `requireScimAuth(config)`. **No Cedar, no session, and — verified —
no `PM_AUTH_DEBUG` bypass** (F21).

| Method | Path                                 | Gate            | Success                           | Error bodies (`ScimError`)                                                                                                                                                                                |
| ------ | ------------------------------------ | --------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/api/scim/v2/ServiceProviderConfig` | requireScimAuth | 200 raw JSON                      | 501/403/401                                                                                                                                                                                               |
| GET    | `/api/scim/v2/ResourceTypes`         | ↑               | 200 raw array                     | 501/403/401                                                                                                                                                                                               |
| GET    | `/api/scim/v2/Schemas`               | ↑               | 200 raw array                     | 501/403/401                                                                                                                                                                                               |
| GET    | `/api/scim/v2/Users`                 | ↑               | 200 `ScimListResponse<ScimUser>`  | 501/403/401                                                                                                                                                                                               |
| POST   | `/api/scim/v2/Users`                 | ↑               | **201** `ScimUser`                | 400 `invalidValue` "externalId is required"; 400 `invalidValue` "userName is required"; 409 `uniqueness` "principal or externalId already in use"                                                         |
| GET    | `/api/scim/v2/Users/{id}`            | ↑               | 200 `ScimUser`                    | 404 (`scimType` **null**) "no such user"                                                                                                                                                                  |
| PUT    | `/api/scim/v2/Users/{id}`            | ↑               | 200 `ScimUser`                    | 404 "no such user"; 400 `invalidValue` "externalId is required"; 409 `uniqueness` "externalId already belongs to a different user"                                                                        |
| PATCH  | `/api/scim/v2/Users/{id}`            | ↑               | 200 `ScimUser`                    | 404 "no such user"; 400 `invalidPath`/`invalidValue` from the validator; 400 `invalidPath` "path 'members' is only valid on Groups"                                                                       |
| DELETE | `/api/scim/v2/Users/{id}`            | ↑               | **204**                           | 404 "no such user"                                                                                                                                                                                        |
| GET    | `/api/scim/v2/Groups`                | ↑               | 200 `ScimListResponse<ScimGroup>` | 501/403/401                                                                                                                                                                                               |
| POST   | `/api/scim/v2/Groups`                | ↑               | **201** `ScimGroup`               | 400 `invalidValue` "externalId is required"; 400 `invalidValue` "displayName is required"; **409 `mutability` "system-managed group is immutable"**; 409 `uniqueness` "name or externalId already in use" |
| GET    | `/api/scim/v2/Groups/{id}`           | ↑               | 200 `ScimGroup`                   | 404 "no such group"                                                                                                                                                                                       |
| PUT    | `/api/scim/v2/Groups/{id}`           | ↑               | 200 `ScimGroup`                   | 404; **409 `mutability`**; 400 `invalidValue` "externalId is required"; 409 `uniqueness` "externalId already belongs to a different group"                                                                |
| PATCH  | `/api/scim/v2/Groups/{id}`           | ↑               | 200 `ScimGroup`                   | 404; **409 `mutability`**; 400 validator errors; 400 `invalidPath` "path 'active' is only valid on Users"                                                                                                 |
| DELETE | `/api/scim/v2/Groups/{id}`           | ↑               | **204**                           | **409 `scimType = null`** "system-managed group is immutable" (F26); 404 "no such group"                                                                                                                  |

Gate failures, uniformly: **501**
`ScimError(status="501", detail="SCIM provisioning is not configured")` ·
**403** `("403", "SCIM requires TLS")` · **401**
`("401", "invalid bearer token")`.

⚠️ **`{id}` that does not parse as a Long is 404, never 400** — every SCIM route
does `parameters["id"]?.toLongOrNull()` and falls into the not-found branch.
Deliberate: RFC 7644 addresses resources by opaque id, so "not a number" and "no
such resource" are the same answer to an IdP. It diverges from the admin REST
routes, which return `400 common.bad_id`.

---

## Symbols

### `Deprovision.kt` — the shared teardown primitives

These four are consumed by A4 (`/auth/session/renew`, device-poll mint), A6
(`Query.kt` deactivation gate reads `isDeactivated`), A7 (approval execute), and
A11 (`ManagementServices`, including `replaceDirectRoles` — INV-A11-30). Specify
them exactly; every other area assumes these semantics.

#### `Connection.advisoryLockPrincipal(principal: String)` · internal ext fn

Kotlin: `internal fun Connection.advisoryLockPrincipal(principal: String)`

Contract: after it returns, the calling transaction holds an exclusive,
transaction-scoped lock keyed on `principal`, released automatically at commit
**or** rollback.

Behavior:

1. Executes exactly `SELECT pg_advisory_xact_lock(hashtext(?))` with `principal`
   bound, and drains one row.
2. Blocks until the lock is available. No timeout, no `try` variant.
3. Re-entrant within a session: a transaction already holding it acquires again
   for free, so composing callers cannot self-deadlock.

Deps: Postgres only; touches no table.

🔒 **INV-A3-3 — one serialization primitive, taken FIRST, for every
principal-mutating path.** The source states it: _"Call it FIRST inside a
transaction, before any read/write that must not interleave with a concurrent
teardown/re-mint for the SAME principal."_ Every rename, deactivate, tombstone,
tombstone-release, credential revoke, and credential mint for a principal
funnels through this one lock. A second, differently-keyed lock would let a
teardown and a mint interleave, which is exactly the hole
`mintForActivePrincipalLocked` exists to close.

🔒 **INV-A3-4 — the lock key must stay `hashtext(<principal>)`, computed BY
POSTGRES.** It is a server-side expression, not a client-side hash. A Go port
that computes its own 32/64-bit hash and passes an integer will not serialize
against a still-running Kotlin instance, and a rolling cutover would silently
lose mutual exclusion for the duration of the deploy. `hashtext` is a 32-bit
hash, so distinct principals **can** collide — that only over-serializes (safe);
the converse cannot happen. `ProvisionMergeDbTest` cases 12–13 and
`DeprovisionDbTest` case 8 all take the lock from raw SQL with this exact
expression, so the tests themselves pin the key.

**Go shape:** a function taking an open transaction handle and a principal
string, issuing that literal SQL. Do **not** model it as an in-process mutex —
cross-instance exclusion is the point. ⟦LIB⟧ none.

#### `DataSource.inTx(body: (Connection) -> T): T` · internal inline fn

Kotlin: `internal inline fun <T> DataSource.inTx(body: (Connection) -> T): T`

Behavior:

1. Takes a connection, sets `autoCommit = false`.
2. Runs `body`, `commit()`, returns its value.
3. Any exception ⇒ `rollback()`, rethrow.
4. `finally` restores `autoCommit = true` **before** the connection returns to
   the pool.

Reason recorded in the source: it exists because "the manual-commit idiom this
module already uses ad hoc (`Access.kt`'s `approve`, `QueryResultStore`'s
private `inTransaction`)" was duplicated, and every locked-teardown call site
must share one implementation. Cross-ref F14 — `AccessStore.approve` still
hand-rolls its own; that is the duplication this helper was meant to end.

**Go shape:** begin/commit/rollback wrapper with deferred
rollback-if-not-committed. Step 4 has no Go analogue (no per-connection
autoCommit flag) and can be dropped. ⟦LIB⟧ none.

#### `revokeActiveCredentials(principal, tokenStore, accessStore, daemonSessionStore): Int` · public fn

Contract: kills **every** currently-active credential for `principal`,
immediately, in one committed transaction; returns the total revoked, for
logging.

Behavior:

1. `tokenStore.dataSource.inTx { c -> revokeActiveCredentialsTx(principal, c, …) }`.
2. `dataSource` is pulled from `tokenStore` "purely as a connection source;
   every store passed here uses the same pooled DataSource" — an assumption a Go
   port must preserve or make explicit.

#### `revokeActiveCredentialsTx(principal, c, tokenStore, accessStore, daemonSessionStore): Int` · public fn

Contract: the composable core, on a caller-supplied connection, so a directory
mutation and its credential teardown commit **together**.

Behavior:

1. `c.advisoryLockPrincipal(principal)` — **taken here itself**, "so direct
   callers cannot forget the serialization boundary". Idempotent when the caller
   already holds it.
2. Returns the sum of four revokes, in this order:
   `tokenStore.revokeAllForPrincipal(principal, c)` (wire tokens, A4) `+`
   `accessStore.revokeAllForPrincipal(principal, c)` (JIT grants, A6) `+`
   `daemonSessionStore.deactivateAllForPrincipal(principal, c)` (daemon renewal
   windows, A4) `+`
   `daemonSessionStore.endAllWebForPrincipal(principal, ENDED_DEACTIVATED, c)`
   (web sessions, A4).
3. `ENDED_DEACTIVATED = "DEACTIVATED"` (`DaemonSession.kt:56`, A4) is the
   recorded `ended_reason`.

🔒 **INV-A3-5 — all four credential classes, or none.** The source names the
reason for each: closing daemon windows "makes deprovisioning durable: even a
later reactivation cannot reuse an old renewal secret", and ending web rows
"invalidates existing browser cookies immediately". A port that revokes tokens
and grants but leaves the daemon window open re-creates a resurrection bug —
reactivating the principal later would revive a live renewal secret.

🔒 **INV-A3-6 — the revoke commits in the SAME transaction as the directory
write, never as a follow-up.** The source is explicit that a separate follow-up
transaction is "a separate follow-up a crash could skip, leaving a principal
inactive-but-still-credentialed (a later reactivation would then resurrect the
live token/renewal secret)". This is why every mutating store method takes the
three credential stores rather than the routes calling revoke afterwards.

**Go shape:** a function over an open transaction returning an int; the four
sub-revokes are A4/A6 symbols. Keep the return value — `DeprovisionDbTest` case
4 asserts the exact sum `6`.

#### `DataSource.mintForActivePrincipalLocked(principal, userGroupStore, mint): T?` · public fn

Kotlin:
`fun <T> DataSource.mintForActivePrincipalLocked(principal: String, userGroupStore: UserGroupStore, mint: (Connection) -> T): T?`

Contract: issues a credential **only** if the principal is not deprovisioned,
with the check and the mint on one transaction under the per-principal lock.
`null` ⇒ deprovisioned; caller maps to 403.

Behavior:

1. `inTx { c -> c.advisoryLockPrincipal(principal); if (userGroupStore.isDeactivated(principal, c)) null else mint(c) }`.

🔒 **INV-A3-7 — the mint-side twin of the teardown; this is where the
check-then-mint TOCTOU is closed, once, for every mint route.** The source
spells out both orderings: a concurrent teardown takes the same lock, so it
"either commits fully BEFORE this lock is acquired (`isDeactivated` then reads
true → null, nothing is minted) or fully AFTER this transaction commits (its
sweep revokes whatever `mint` just inserted)". Without the lock "a teardown
could slip its revoke between the check and the INSERT, leaving a credential
that outlives deprovisioning **or group revocation**" — the second half matters,
because it is the clause INV-A3-8 rests on. Named funnels: `/api/wire-tokens`,
`/api/tokens`, and the device-poll session mint (all A4).

🔒 **INV-A3-8 — the web-session mint resolves role eligibility INSIDE `mint`,
under this same lock.** The source states the guarantee positively: holding the
lock across the resolve **is** what makes it so that "group reconciliation
cannot end existing sessions and then lose a race to a zero-role insert." Read
the failure mode the other way round: resolve roles _before_ entering the locked
region and a concurrent group reconciliation can revoke membership, end the
existing sessions, and then be beaten by this transaction inserting a session
whose role list was snapshotted pre-revocation — a live session carrying roles
the directory no longer grants. A Go port that hoists the resolve out
reintroduces it.

**Go shape:** generic-over-T (or an `any`-returning) helper taking a closure
that receives the transaction. `DeprovisionDbTest` case 8 asserts the _blocking_
behaviour, so the port must genuinely block on the DB lock, not poll.

---

### `RoleResolver.kt`

#### `class RoleResolver(dataSource, userGroupStore: UserGroupStore, accessStore: AccessStore)`

The Layer-1 identity resolver (`docs/authz-model.md`). All three constructor
params are `private val`. Constructed once in `ControlPlaneCore.kt:31` and
shared by HTTP and gRPC.

#### `directRoles(principal: String): List<String>`

`SELECT r.name FROM principal_role pr JOIN app_role r ON r.id = pr.role_id WHERE pr.principal = ?`.
No active/expiry filter of any kind — `resolve`'s short-circuit is the only gate
on this source. Also called directly by A4's web-session routes
(`WebSessionRoutesDbTest`).

#### `resolve(principal: String): Set<String>` — **the sole source of truth for effective roles**

Kotlin: `fun resolve(principal: String): Set<String>`

Contract: the principal's complete effective role set, resolved server-side; the
empty set when nothing applies. A2 wires it in as
`RoleSource { p -> roleResolver.resolve(p) }` (`ControlPlaneCore.kt:34`), so
**A6 INV-A6-7 and every Cedar decision in the system read this and nothing
else.**

Behavior:

1. `if (userGroupStore.isDeactivated(principal)) return emptySet()` — **before**
   any role read.
2. Otherwise
   `effectiveRoles(directRoles(principal), accessStore.listGrants(principal, activeOnly = true).map { it.roleName }, userGroupStore.rolesForPrincipal(principal))`.
   `effectiveRoles` lives in `Query.kt:197` (**A6**) — a set union; do not
   re-specify it here.
3. Never throws for an unknown principal; the three sources simply return
   nothing.

Deps: `app_user` (via `isDeactivated`), `principal_role` + `app_role`,
`access_grant` (A6's `AccessStore.listGrants`),
`app_user`+`group_member`+`group_role`+`app_role` (via `rolesForPrincipal`).

🔒 **INV-A3-9 — deprovisioning short-circuits ALL role sources, not just the
directory one.** The source: _"this returns the empty set regardless of any
direct `principal_role` assignment, group membership, or JIT grant."_ Because
`directRoles` and `listGrants` are keyed on the principal **string** and are
independent of `app_user` entirely, dropping the short-circuit would leave a
deprovisioned user holding every direct and JIT role. `DeprovisionDbTest` case 6
pins all three sources at once.

🔒 **INV-A3-10 — "no `app_user` row" is NOT "deactivated".** A purely local
`principal_role`-only identity, never synced into the directory, keeps its
direct roles: "there's nothing to deactivate." Inverting this to
fail-closed-on-absence would break every local-only operator identity and every
wire token minted before a directory row existed. `DeprovisionDbTest` case 7 and
`ProvisionMergeDbTest` case 17 both pin it.

⚠️ **INV-A3-11 — `resolve` is NOT transactional.** Its four reads run on four
separate pooled connections, so a deactivation committing mid-resolve yields a
torn view (roles read before the flip, `isDeactivated` read before it, or vice
versa). Contrast A2's INV-A2-10, which takes **one** role snapshot and threads
it through both passes — that invariant protects the _consumer_; nothing
protects `resolve` itself. Untested. Recorded as F31; a Go port could wrap it in
one transaction, but that is a behaviour **change** and must be a deliberate
decision, not a side effect.

#### `hasActiveAssignee(roleName: String): Boolean`

Contract: whether at least one _active_ principal can reach `roleName` through
the same three-way union `resolve` uses. Consumed only by `/health`'s readiness
diagnostics (`App.kt:563` → `"system:admin role has no active assignee"`).

Behavior — one SQL statement, three `EXISTS` arms OR'd, `roleName` bound three
times:

1. **direct**: `principal_role` ⋈ `app_role(name=?)`
   `LEFT JOIN app_user ON u.principal = pr.principal`
   `WHERE u.id IS NULL OR u.active` — a direct principal with **no** `app_user`
   row counts (mirrors INV-A3-10); an inactive directory user does not.
2. **group**: `group_role` ⋈ `app_role(name=?)` ⋈ `group_member` ⋈
   `app_user(u.active)` — an **INNER** join, so a `group_role` link with no
   active member deliberately does **not** count.
3. **JIT**: `access_grant` ⋈ `app_role(name=?)` with
   `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`, plus the
   same `LEFT JOIN app_user` / `u.id IS NULL OR u.active` rule.

**INV-A3-12 — arm 2 is an INNER join on purpose.** The shipped seed installs the
`system:admin` group with a `group_role` link and **zero members**
(`V8__seed.sql:48-66`; `BootstrapAdminDbTest` case 8), so counting the bare link
as an assignee would report a fresh install as "admin is reachable" when nobody
can actually log in as one. `ReadinessDiagnosticDbTest` case 1's first assertion
is exactly this.

⚠️ **There are SEVEN seeded SYSTEM groups, not one.** `V8__seed.sql:48-58`
inserts eight `app_group` rows: `query-approvers` (`source=LOCAL`) plus
**seven** with `source=SYSTEM` — `system:admin`, `system:developer`,
`system:production-viewer`, `system:production-pii-accessor`,
`system:production-updater`, `system:production-deleter`,
`system:production-architect`. All seven carry `external_id = NULL` and zero
seeded members, and **every** SYSTEM-immutability guard in this area
(`isSystemGroup`, `lockGroupSource`, A11's `rejectSystem`) applies to all seven
identically. The tests only ever exercise `system:admin`; a Go port that
special-cases the string `"system:admin"` instead of the `source = 'SYSTEM'`
column would leave the other six freely mutable through SCIM and the admin API.
The seed's own comment states the design: "Membership is always assigned at
login from the IdP claim, never seeded", and `system:developer` aggregates the
five development roles while each production role gets its own 1:1 group.

**INV-A3-13 — readiness must agree with `resolve`, arm for arm.**
`ReadinessDiagnosticDbTest`'s helper `assertResolvedAndDiagnosed` asserts
`("system:admin" in resolve(p)) == hasActiveAssignee("system:admin")` at **ten**
state transitions
(`ReadinessDiagnosticDbTest.kt:44,46,48,56,58,67,69,71,73,76`), plus **three**
readiness-only `assertFalse(hasActiveAssignee(...))` checkpoints at `:41,51,60`
— thirteen assertion points, ten of them mirrored. Two independent
implementations of one predicate is the drift risk; the test is the only thing
holding them together. Keep the test.

**Go shape:** one query, one boolean. Do not decompose into three round trips —
the point is a single readiness probe.

---

### `Users.kt` — `class UserGroupStore(internal val dataSource: DataSource)`

`dataSource` is `internal`, not private, because `userGroupRoutes`' default
`management` parameter reads it (`Users.kt:900`).

#### Plain reads

| Method                                                                         | Behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `listUsers(): List<AppUser>`                                                   | `userGroups(null)` on one connection, then `SELECT … FROM app_user ORDER BY principal` on **another** — two connections, no transaction (read skew possible)                                                                                                                                                                                                                                                                                                                               |
| `getUser(id)` / `getUser(id, c)`                                               | groups first, then the row; `null` if absent                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `getUserByPrincipal(principal)` / `(principal, c)`                             | id lookup, then `getUser(id, c)`. Used by A11                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `listGroups(): List<AppGroup>`                                                 | `memberCounts(null)` + `groupRoles(null)` + `SELECT … ORDER BY name`, three connections                                                                                                                                                                                                                                                                                                                                                                                                    |
| `getGroup(id)` / `(id, c)`                                                     | member count + `listGroupRoles` + the row                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `getGroupByName(name)` / `(name, c)`                                           | id lookup then `getGroup`. Used by A11                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `listMembers(groupId[, c])`                                                    | `group_member ⋈ app_user`, `ORDER BY u.principal`                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `listGroupRoles(groupId[, c])`                                                 | `group_role ⋈ app_role`, `ORDER BY r.name`                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `findUserByExternalId(id)` / `findGroupByExternalId(id)`                       | partial-unique `external_id` lookup → full DTO. ⚠️ **production-dead** — verified zero callers in `control-plane/src/main`, `auth/src`, `engine/src`; the only references are `ProvisionMergeDbTest:302,362-365`, `ScimUsersDbTest:148-149,177-178`, `ScimGroupsDbTest:52-53`. F27                                                                                                                                                                                                         |
| `isSystemGroup(id[, c])`                                                       | `SELECT source = 'SYSTEM' FROM app_group WHERE id = ?`; absent row ⇒ `false`. The **only** SYSTEM predicate with production callers (SCIM PUT/PATCH/DELETE `Scim.kt:524,557,585`; A11's `rejectSystem` `ManagementServices.kt:712`)                                                                                                                                                                                                                                                        |
| `role(id)` / `roleExists(id)`                                                  | **dead** — see F27                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `ResultSet.toUser(groups)` / `ResultSet.toGroup(memberCount, roles)` · private | the two row mappers, and the **only** place the column→field mapping is defined: `id`, `principal`, `display_name`, `email`, `source`, `external_id`, `active`, `created_at` → `AppUser` (with `createdAt = getTimestamp("created_at").toInstant().toString()`, INV-A3-1); `id`, `name`, `description`, `source`, `external_id` + the injected `memberCount`/`roles` → `AppGroup`. Every `SELECT` in the area lists exactly those columns in exactly that order (`Users.kt:77,87,248,260`) |

**INV-A3-14 — every list has a deterministic order** (`principal`, `name`,
`g.name`, `r.name`). Not cosmetic: `web/` renders these directly and the SCIM
list responses are built from them; an unordered Go equivalent produces diff
churn and flaky tests.

#### `isDeactivated(principal)` / `isDeactivated(principal, c)`

`SELECT EXISTS(SELECT 1 FROM app_user WHERE principal=? AND NOT active)`.

Contract: **true iff a row exists AND it is inactive.** No row ⇒ **false**
(INV-A3-10).

The `(principal, c)` overload exists so "a locked renewal check uses the
transaction holding the per-principal advisory lock, rather than a separate
connection that could race a concurrent commit" — that is
`mintForActivePrincipalLocked`'s call site (INV-A3-7). Read by A4
(`DaemonSession.kt:655`, `Datasources.kt:739`), A6 (`Query.kt:361,1130`), A7
(`Approvals.kt:800`), A10 (`grpc/ControlPlaneGrpcService.kt:123`) and A3 itself.
**The most widely depended-on predicate in the area.**

#### `rolesForPrincipal(principal): List<String>`

`SELECT DISTINCT r.name FROM app_user u JOIN group_member gm … JOIN group_role gr … JOIN app_role r … WHERE u.principal = ? AND u.active`.

**INV-A3-15 — INNER JOINs from `app_user` plus `AND u.active` make this fail
closed on its own.** The source comment: _"an unknown or inactive principal
yields zero rows (fail-closed)."_ This is belt-and- braces behind INV-A3-9 — the
group source is guarded twice, the direct and JIT sources only once.

#### Principal-mutating writes — the atomic-teardown family

All six share one skeleton. **Get the ordering right; it is the whole security
property.**

```
1. confirm the row exists (else null/false)
2. current = lockCurrentPrincipal(c, id)        // locks the row's CURRENT principal, re-read under lock
3. releaseTombstone(c, targetPrincipal, id)     // locks the TARGET principal; frees a stale tombstone
4. UPDATE app_user …                            // the actual mutation
5. if (current != null && current != target) {  // RENAME
       deactivatePrincipalTombstone(current, c)
       revokeActiveCredentialsTx(current, c, …)
   }
6. if (!active) revokeActiveCredentialsTx(target, c, …)   // DEACTIVATE — independent of step 5
7. all of the above inside ONE inTx { }
```

🔒 **INV-A3-16 — steps 5 and 6 are INDEPENDENT branches, not an if/else.** The
source: a rename-and-deactivate onto a principal that already holds credentials
"retires BOTH the old and the new string." `UserAdminDeprovisionDbTest` case 3
is precisely this: the rename target `new` has a live token/grant/session but
**no `app_user` row of its own**, and a PUT that renames _and_ deactivates must
revoke both. Collapsing to `else` leaves `new`'s credentials live, and a later
reactivation resurrects them.

🔒 **INV-A3-17 — the retired principal is RE-READ under the lock, never taken
from a pre-lock snapshot.** See `lockCurrentPrincipal` below.
`ProvisionMergeDbTest` cases 12 and 13 are the two halves of this.

| Method                                                                        | Signature / notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `createUser(input, tokenStore, accessStore, daemonSessionStore)` and `(…, c)` | `releaseTombstone(c, input.principal, **null**)` → INSERT `(principal, display_name, email, active)` RETURNING id → **if `!input.active`, revoke that principal's credentials**. `excludeId = null` because there is no row to protect yet.                                                                                                                                                                                                                                                                                  |
| `updateUser(id, input, …)` and `(…, c)`                                       | The full skeleton. `null` if no such row.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `deleteUser(id, …)` (4-arg)                                                   | A thin wrapper: `setActiveById(id, active = false, …) != null`. ⚠️ **No `main` caller** — A11 always takes the 5-arg overload. Only `UserAdminDeprovisionDbTest:218,232` (cases 7 and 8) call it, so **the two "DELETE" store tests exercise the `setActiveById` path, not the production `deleteUser` body**. The 5-arg one is covered only indirectly, through case 9's `management.deprovisionUser(id)`.                                                                                                                  |
| `deleteUser(id, …, c)` (5-arg)                                                | Row check (`false` if absent) → `lockCurrentPrincipal(c, id) ?: return false` — **a second `false` exit**, if the row vanished between the check and the locked re-read → `UPDATE app_user SET active = FALSE WHERE id = ?` → `revokeActiveCredentialsTx(current, …)` → `true`. **Does not tombstone-release and does not rename** — no target principal is involved. This is the overload A11 calls (`ManagementServices.kt:575,581`), so both `DELETE /api/users/{id}` (by id) and the by-principal deprovision land here. |
| `setActiveById(id, active, …)`                                                | Row check → `inTx { lockCurrentPrincipal; UPDATE app_user SET active = ? WHERE id = ?; if (!active && current != null) revoke(current) }` → re-read and return the row.                                                                                                                                                                                                                                                                                                                                                      |

🔒 **INV-A3-18 — `createUser(active = false)` must revoke.** Reason quoted from
`Users.kt:108-111`: _"a principal can accumulate a live wire token / daemon
session BEFORE any app_user row exists for it at all (`isDeactivated` is false
with no row), so deliberately creating it inactive must not leave those
pre-existing credentials usable."_ This is the direct consequence of INV-A3-10
and is easy to miss — "create" reads like it cannot need a revoke.
`UserAdminDeprovisionDbTest` cases 4 and 5 pin both directions.

🔒 **INV-A3-19 — DELETE deprovisions, never hard-deletes.** Both `deleteUser`
paths only flip `active`. Reason: audit history must keep resolving the
principal. `UserAdminDeprovisionDbTest` case 7 asserts the row still exists
afterwards. `setActiveById` is the shared id-stable teardown behind local-admin
DELETE, SCIM `PATCH replace:active=false`, and SCIM DELETE — **one**
implementation, deliberately.

#### `setUserActive(principal: String, active: Boolean): Boolean`

`UPDATE app_user SET active=? WHERE principal=?`, returns `rows > 0`. **No lock,
no revoke.**

⚠️ Its kdoc claims it is the "SCIM `active=true` reactivate, or a local admin
action" path. Verified: **no production caller exists** — SCIM reactivate goes
through `setActiveById` (`Scim.kt:454`), and
`grep -rn setUserActive control-plane/src/main auth/src/main engine/src/main`
returns nothing but the declaration. It survives only because **nine** test
suites use it as a fixture shortcut: `ProvisionMergeDbTest`, `ScimUsersDbTest`,
`DeprovisionDbTest`, `DeactivationEnforcementDbTest`,
`TokenRoutesDeactivationTest`, `RenewalWindowTest`,
`ApprovalResultViewContextDbTest`, `ApprovalResultDeactivationDbTest`,
`GrpcDecideHandlerDbTest` — i.e. across five different areas, so **it cannot
simply be dropped at cutover: disposition is REPRODUCE as a test-visible
helper** — an equivalent test-only "flip active by principal, no teardown"
function — or nine suites need rewriting. It is production-dead but
fixture-live, which puts it outside the OMIT boundary. Recorded as F27 (index
F80); the kdoc is stale and is itself OMIT. Its one correct half — "the
credential-affecting DEACTIVATE paths go through `setActiveById` instead" — is
the rule that matters and must be preserved.

#### `lockCurrentPrincipal(c: Connection, id: Long): String?` · private

Contract: take the per-principal advisory lock on the row's principal and return
**that principal re-read under the lock**, guaranteed to be the string `c`
actually holds the lock for. `null` if the row does not exist.

Behavior:

1. `seen = principalForUserId(id, c)`; `null` ⇒ return `null`.
2. Loop: `c.advisoryLockPrincipal(seen)`; `current = principalForUserId(id, c)`;
   if `current == seen` return it; else `seen = current` and repeat.

🔒 **INV-A3-20 — the loop is load-bearing; a single-shot lock-then-read is the
bug it fixes.** Quoted verbatim from the kdoc at `Users.kt:749-759`: _"the
single-shot version of this could lock a stale snapshot, then re-read a
DIFFERENT, unlocked value if a concurrent rename committed in between, and
return THAT unlocked."_ Locking the new value too is harmless — "re-entrant, and
every lock taken here is released together at commit". Termination: _"each
iteration either returns or observes a value it hasn't tried yet, and only a
bounded number of concurrent renames can interleave with this transaction."_

**Go shape:** the same loop. Note it holds an unbounded set of advisory locks in
pathological cases — acceptable because they all release at commit. ⟦LIB⟧ none.

#### `deactivatePrincipalTombstone(principal: String, c: Connection)` · private

```sql
INSERT INTO app_user (principal, source, active) VALUES (?, 'SCIM', FALSE)
ON CONFLICT (principal) DO UPDATE SET active = FALSE
```

🔒 **INV-A3-21 — a renamed-away principal string must be left DEPROVISIONED, not
merely orphaned.** Reason (`ProvisionMergeDbTest` case 7's comment): everything
that authenticates or authorizes is keyed on the principal **string**, and every
chokepoint gates on `isDeactivated(principal)`; so an orphaned old string with
no row at all would read `isDeactivated == false` (INV-A3-10) and its still-live
token/session/roles would "sail past".

**INV-A3-22 — `external_id` is left NULL deliberately**, so the tombstone "never
collides with the renamed row's external_id (and NULLs don't collide with each
other under the unique index)" — the index is partial,
`WHERE external_id IS NOT NULL` (`V1__identity.sql:41` for `app_user`, `:42` for
`app_group`; both named `idx_app_{user,group}_external_id_unique`). It is also
the _marker_ `releaseTombstone` matches on.

⚠️ The `ON CONFLICT` branch sets only `active`; it does **not** normalise
`source` to `'SCIM'`. A conflicting `LOCAL`/`OIDC` row would therefore be
deactivated but never match `releaseTombstone`'s narrow shape, permanently
squatting the string. Narrow (the renamed row itself just vacated the string, so
a conflict needs a concurrent third writer) and untested — §Open questions Q3.

#### `releaseTombstone(c: Connection, principal: String, excludeId: Long?)` · private

Contract: free `principal` for reuse by a genuinely new or renamed-back
identity, and purge the stale direct grants attached to that string — without
ever deleting a real inactive user.

Behavior:

1. `c.advisoryLockPrincipal(principal)` — **first**, "so this can't race a
   concurrent writer reusing the same retired string."
2. Probe:
   `SELECT 1 FROM app_user WHERE principal = ? AND source = 'SCIM' AND external_id IS NULL AND NOT active`.
   Not a tombstone ⇒ **return, doing nothing**.
3. `DELETE FROM principal_role WHERE principal = ?`.
4. `DELETE FROM app_user WHERE principal = ? AND source = 'SCIM' AND external_id IS NULL AND NOT active`
   `[ AND id <> ? ]` when `excludeId != null`.

🔒 **INV-A3-23 — the tombstone match is DELIBERATELY NARROW: all four
predicates, always.** Quoted: _"matches ONLY the exact shape
`deactivatePrincipalTombstone` creates … so a genuinely distinct inactive
identity — a real SCIM user with its own `external_id`, or a local admin's
deliberately-deactivated user — is NEVER silently deleted, only our own
synthetic teardown artifact is."_ Dropping any one predicate turns a rename into
silent deletion of a real user.

🔒 **INV-A3-24 — the `principal_role` purge is a privilege-escalation fix and
runs BEFORE the `excludeId` filter.** Quoted at length because the ordering is
genuinely non-obvious: _"revoking wire tokens/JIT grants/daemon sessions on
deprovision does NOT touch `principal_role` — it's keyed purely on the principal
STRING, independent of `app_user` entirely … While the string stays tombstoned
that's harmless (`RoleResolver.resolve` short-circuits to empty for a
deactivated principal regardless), but the MOMENT this string is handed to a
genuinely different identity and goes active again, a stale direct grant would
silently reattach to whoever claims it — privilege escalation via principal
recycling. Checked and purged BEFORE the `excludeId` filter, deliberately:
`upsertScimUser`'s fallback principal-match can resolve `existingId` onto the
tombstone row ITSELF (reusing that exact id rather than inserting a fresh one),
in which case the app_user DELETE below is correctly excluded (there's no
separate row to remove) but the STRING is still being handed to a new identity
(a different `externalId`) and the stale grant must still go."_
`ScimUsersDbTest` case 11 is the regression test.

🔒 **INV-A3-25 — without the release, a tombstone squats a UNIQUE column
forever.** `app_user.principal` is globally UNIQUE, so "renaming a different
identity onto that same string — or the retired string legitimately coming back
into use — would 500 on a unique-constraint violation." `ScimUsersDbTest` cases
13 and 14 cover reuse-by-a-different-identity and rename-back-onto-itself.

**INV-A3-26 — `excludeId` guards the very row the caller is about to update.**
`createUser` passes `null` (no row yet); every other caller passes the row's id.

#### `provisionFromOidc(principal, email, idpGroups, mapping = OidcGroupMapping(emptyMap(), null)): AppUser`

Contract: JIT-provision from a validated OIDC login and **sync** group
membership to the claim.

Behavior:

1. Delegates entirely to
   `auth/OidcDirectoryProvisioner(dataSource).provision(principal, email, idpGroups, mapping)`
   (**A14** — `auth/src/.../OidcDirectoryProvisioner.kt`), then
   `getUser(userId)!!`.
2. That provisioner, in one hand-rolled transaction:
   `INSERT INTO app_user (principal, email, source, active) VALUES (?, ?, 'OIDC', TRUE) ON CONFLICT (principal) DO UPDATE SET email = COALESCE(EXCLUDED.email, app_user.email), source = EXCLUDED.source WHERE app_user.source <> 'SCIM'`
   — then resolves the claim through `mapping.resolve`, `ensureGroup`s each
   target (`ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`
   — a no-op write so RETURNING still fires, "without ever touching an existing
   row's `source`"), and reconciles `group_member` to **exactly** the target set
   (batch INSERT of the additions, batch DELETE of the removals).

🔒 **INV-A3-27 — SCIM is authoritative once it manages a principal.** The
`WHERE app_user.source <> 'SCIM'` clause on the upsert is the enforcement point:
a JIT login must never flip a SCIM row's `source` back to `OIDC` nor overwrite
its email. `ProvisionMergeDbTest` case 4 pins it — including that an
attacker-supplied email in the id_token cannot overwrite a SCIM-owned one.

🔒 **INV-A3-28 — OIDC membership is a SYNC, not an add.** Groups no longer
claimed are **REMOVED**, so "dropping someone from the IdP admin group revokes
their `system:admin` on their next login." Accepted cost, stated in the source:
a manual or SCIM group assignment for an OIDC user is reconciled away, because
there is no membership-origin column yet. `ProvisionMergeDbTest` case 2 and
`BootstrapAdminDbTest` case 2 both pin the revoke-on-next-login path.

⚠️ The two kdoc blocks stacked on `provisionFromOidc` (`Users.kt:328-343`)
**contradict each other**: the first says "Never removes a membership (SCIM push
is the only path that revokes `group_member` rows)", the second says membership
is reconciled and removed. The second is correct (verified against
`OidcDirectoryProvisioner.kt:44-51` and `ProvisionMergeDbTest` case 2). **The
reconcile-and-remove behaviour is REPRODUCE; the first KDoc is OMIT (F104)** — a
comment has no call path and no wire effect, so leaving it out preserves every
observable behaviour and carrying it over would only re-import a claim the code
already contradicts.

🔒 **INV-A3-29 — the JIT add/remove deliberately BYPASSES the route-level
SYSTEM-group immutability guard.** Reason: "membership of `system:admin` is
system-managed here, not hand-edited." So the SYSTEM guard protects the _group's
identity_ (name, source, external_id, its `group_role` link), never its
membership. Membership of the admin group comes **only** from the IdP claim
(`BootstrapAdminDbTest` case 8: the seeded group ships with zero members).

🔒 **INV-A3-30 — the reserved `system:` namespace is unreachable through the
unmapped fallback.** Enforced in `OidcGroupMapping.resolve` (**A14**; the class
is `auth/Oidc.kt:102`, `resolve` is `:103-108`,
`RESERVED_GROUP_PREFIX = "system:"` is `:111` and `isReservedGroupName` is
`:113`): an explicit `map` entry wins; otherwise the prefix is stripped and the
result is dropped when blank **or** when `isReservedGroupName(name)` —
`name.startsWith(RESERVED_GROUP_PREFIX, ignoreCase = true)`. So a raw
`groups: ["system:admin"]` claim with no `PM_OIDC_GROUP_MAP` cannot self-assign
admin, case-insensitively and including via prefix-stripping down into the
namespace. Only the operator-configured map may name a system group.
`OidcGroupMappingTest` case 6 and `BootstrapAdminDbTest` case 5 both pin it.
**This is a privilege-escalation gate that lives in another module — do not lose
it at the module seam.**

⚠️ **The gate stops the _unmapped_ path only; an explicit map entry naming a
`system:*` group that the seed did not install creates a NEW group with
`source = 'OIDC'`, not `SYSTEM`.** `OidcDirectoryProvisioner.ensureGroup`
(`:68-76`) inserts `source='OIDC'` unconditionally and does no reserved-name
check of its own, so `PM_OIDC_GROUP_MAP=idp-x=system:typo` mints an ordinary,
freely SCIM-/admin-mutable group sitting inside the reserved namespace. It
confers nothing (no `group_role` link), so this is a naming/immutability wart
rather than an escalation — but a port must not "improve" it into a hard reject
without checking that every deployed `PM_OIDC_GROUP_MAP` targets a seeded name,
or first logins start failing. §Open questions Q10.

#### SCIM user upsert / replace

##### `upsertScimUser(externalId, principal, email, displayName, active): AppUser` (5-arg convenience)

Delegates to the 8-arg overload, self-constructing `TokenStore(dataSource)`,
`AccessStore(dataSource)`, `PrincipalSessionStore(dataSource, null)`. Reason
quoted: _"a revoke needs only that DataSource — no crypto … No 'half-safe'
upsert path tombstones without revoking."_ `ProvisionMergeDbTest` case 9 exists
solely to prove the convenience overload still tears down.

##### `upsertScimUser(externalId, principal, email, displayName, active, tokenStore, accessStore, daemonSessionStore): AppUser`

Behavior:

1. **Match order, each on its own connection, OUTSIDE the transaction**
   (`Users.kt:405-407`): `findUserIdByExternalId(externalId)` ?:
   `email?.let { findUserIdByEmail(it) }` ?: `userIdForPrincipal(principal)`.
2. `inTx`: `current = existingId?.let { lockCurrentPrincipal(c, it) }` →
   `releaseTombstone(c, principal, existingId)` → if `existingId != null`
   `updateScimAppUserRow` else `insertScimAppUserRow` → rename branch →
   deactivate branch (the standard skeleton).
3. `updateScimAppUserRow` sets
   `principal, display_name, email, source='SCIM', external_id, active`.
   `insertScimAppUserRow` inserts the same with `source='SCIM'`.
4. Returns `getUser(id)!!`.

🔒 **INV-A3-31 — the match order external_id → email → principal is the
anti-duplication rule.** Reason: "so a prior JIT (`source=OIDC`) row is
reconciled to `source=SCIM` instead of duplicated once the IdP starts managing
the principal via SCIM." `external_id` first, because the IdP may have changed
both userName and email on the same identity (`ProvisionMergeDbTest` case 6).

⚠️ Step 1 is **not** inside the transaction, and the Groups twin was
deliberately hardened the other way (see `upsertScimGroup`). `email` also has
**no unique index** (F23) — with two rows sharing an email and no `ORDER BY`,
the match is nondeterministic. Recorded as F23/F34.

##### `replaceScimUserById(id, principal, email, displayName, externalId, active, tokenStore, accessStore, daemonSessionStore): AppUser?`

The SCIM PUT path. Identical skeleton, but resolves **nothing**: it mutates the
row at `id`.

🔒 **INV-A3-32 — PUT addresses THIS id and must never re-discover a different
row.** Quoted: _"a PUT whose body fields happen to match some other existing row
must not silently mutate THAT row instead of the one at this URI — that's not a
'replace', it's an accidental cross-resource write."_ `ScimUsersDbTest` case 9
constructs exactly the trap (a second row owning the email the PUT body reuses)
and asserts the other row is untouched. **This is the sharpest behavioural
difference between POST and PUT and the easiest thing to "simplify" wrongly in a
port.**

#### SCIM group upsert / replace

##### `upsertScimGroup(externalId, displayName): AppGroup`

Behavior — everything inside **one** `inTx`:

1. `existingId = groupIdByExternalId(c, externalId) ?: groupIdByName(c, displayName)`
   — the **connection-scoped** resolvers, on the transaction's own connection.
2. If found: `lockGroupSource(c, existingId)` =
   `SELECT source FROM app_group WHERE id=? FOR UPDATE`; `"SYSTEM"` ⇒ **throw
   `SystemGroupImmutableException`**. Else
   `UPDATE app_group SET name=?, source='SCIM', external_id=? WHERE id=?` on
   that same id.
3. Else
   `INSERT INTO app_group (name, source, external_id) VALUES (?, 'SCIM', ?) RETURNING id`.
4. `getGroup(id)!!`.

🔒 **INV-A3-33 — resolve, check, and mutate must target ONE id inside ONE
transaction under a row lock.** The reason is a fixed TOCTOU, quoted in full
because a port that moves the guard back to the route reintroduces an
admin-conferring bug: _"A route-level guard that resolved external_id→name on
its own connection and then let this method re-resolve on another was defeatable
by a TOCTOU: a concurrent `PUT /Groups/{id}` moving an external_id off an
ordinary group BETWEEN the two resolutions made the guard inspect the ordinary
group (pass) while this method then re-resolved to the seeded `system:admin` by
name and flipped it to source=SCIM — conferring admin and defeating every
source-based guard."_ `BootstrapAdminDbTest` case 6 asserts both resolution keys
(by name **and** by planted external_id) are refused and leave the row
untouched.

🔒 **INV-A3-34 — the seeded `system:admin` group always matches by NAME, so it
can never be created or hijacked here.** Combined with INV-A3-33, that is the
complete argument. The private `groupIdByExternalId` / `groupIdByName` /
`lockGroupSource` are connection-scoped **on purpose**; the source warns that
the standalone `findGroupIdByExternalId` / `findGroupIdByName` "each open their
own connection and must NOT be mixed into the atomic path."

##### `replaceScimGroupById(id, externalId, displayName): AppGroup?`

`getGroup(id) == null` ⇒ `null`; else
`UPDATE app_group SET name=?, source='SCIM', external_id=? WHERE id=?` **on its
own connection, with no transaction and no `FOR UPDATE`**, then re-read.

⚠️ Asymmetric with `upsertScimGroup`: no SYSTEM check here. The route checks
`isSystemGroup(existing.id)` _before_ calling (`Scim.kt:524`) — i.e. the very
route-level, separate- connection pattern INV-A3-33 was hardened away from,
still in place on the PUT path. It is narrower (PUT addresses an id, so there is
no re-resolution to race) but it is not the same guarantee. Recorded in §Open
questions Q2.

#### Group / membership / role-map writes

| Method                                  | SQL                                                                                                     | Returns                               |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `createGroup(input[, c])`               | `INSERT INTO app_group (name, description) VALUES (?, ?) RETURNING id` — `source` defaults to `'LOCAL'` | the group                             |
| `updateGroup(id, input[, c])`           | existence check, then `UPDATE app_group SET name=?, description=?`                                      | group or `null`                       |
| `deleteGroup(id[, c])`                  | `DELETE FROM app_group WHERE id=?` — **hard delete**, CASCADEs `group_member` and `group_role`          | `rows > 0`                            |
| `addMember(groupId, userId[, c])`       | `INSERT INTO group_member … ON CONFLICT DO NOTHING`                                                     | `rows > 0` (false = already a member) |
| `removeMember(groupId, userId[, c])`    | `DELETE FROM group_member WHERE group_id=? AND user_id=?`                                               | `rows > 0`                            |
| `addGroupRole(groupId, roleId[, c])`    | `INSERT INTO group_role … ON CONFLICT DO NOTHING`                                                       | `rows > 0`                            |
| `removeGroupRole(groupId, roleId[, c])` | `DELETE FROM group_role WHERE group_id=? AND role_id=?`                                                 | `rows > 0`                            |

**INV-A3-35 — `ON CONFLICT DO NOTHING` on both maps makes re-adds idempotent,
and the boolean return means "did this call change anything", not "is the
mapping present".** The SCIM PATCH/PUT membership reconcilers rely on the
idempotence; `UserAdminDeprovisionDbTest` case 10 relies on it under genuine
thread concurrency.

⚠️ **`deleteGroup` is the only hard delete in the area** and it silently
CASCADE-drops every `group_role` row for that group — i.e. it revokes roles from
every member with no audit record and no undo, while users are never
hard-deleted (INV-A3-19). Recorded as F26.

#### `isSystemGroupByName(name): Boolean`

`SELECT source = 'SYSTEM' FROM app_group WHERE name = ?`; absent ⇒ `false`.

⚠️ Its kdoc says it "Guards the SCIM POST upsert". Verified: it does **not** —
the guard is `lockGroupSource` inside `upsertScimGroup` (INV-A3-33). No
production caller exists; the only references are `BootstrapAdminDbTest` case 4.
Dead in production, stale kdoc (F27). The _behaviour_ the kdoc describes
("without this, `POST /Groups {displayName:"system:admin"}` would flip the
seeded SYSTEM group to source=SCIM and defeat every other immutability guard")
is real and **is** enforced — just elsewhere.

#### `class SystemGroupImmutableException : RuntimeException("system-managed group is immutable")`

🔒 Raised **inside** the resolve/check/mutate transaction "so the check is
atomic with the write"; the SCIM route catches it and returns 409 `mutability`.
A Go port must keep the throw inside the transaction boundary — returning a
sentinel from a helper that runs outside it re-opens INV-A3-33.

#### `SQLException.isUniqueViolation(): Boolean` · internal ext fn

`sqlState == "23505"` (`Users.kt:890`, top-level, outside the store class).
Called only from `Scim.kt` (four sites: `380`, `428`, `503`, `540`). The same
literal is hand-repeated **twice** in A11 — `ManagementServices.kt:726` inside
the `unique(resource, name)` helper (declared at `:723`) and again at `:505` in
`PolicyManagementService` — so the codebase has three copies of the SQLSTATE
check.

**Go shape:** the port needs a driver-level "is this a unique-violation"
predicate on Postgres SQLSTATE `23505` ⟦LIB⟧ (driver choice deferred). Note
`23503` (foreign-key violation) is **not** matched — see F29.

#### Private JDBC helpers

`userGroups(userId?[, c])` (688/690), `memberCounts(groupId?)` (704),
`groupRoles(groupId?)` (718) — each builds SQL with an optional `WHERE` and
returns a `LinkedHashMap` grouping, always with a trailing `ORDER BY` (`g.name`
/ `r.name`) or `GROUP BY group_id`. Plus `userIdForPrincipal` (735),
`principalForUserId(id, c)` (743), `findUserIdByExternalId` (832),
`findUserIdByEmail` (839), `findGroupIdByExternalId` (846),
`updateScimAppUserRow` (466), `insertScimAppUserRow` (487), `updateAppUserRow`
(238), the two row mappers `ResultSet.toUser` (666) / `ResultSet.toGroup` (678),
and the tiny `query` (872) / `queryOne` (875) / `exec` (881) / `execUpdate`
(884) wrappers. Of those four wrappers only three are live: `query`
(listUsers/listGroups), `exec` (`replaceScimGroupById`), `execUpdate`
(`setUserActive`).

⚠️ **Dead:** `groupIdsForUser` (355), `findGroupIdByName` (853),
`ensureGroupByName` (866) — and `insertReturningId` (878), which is _not_ a
consumer of `ensureGroupByName` but the helper `ensureGroupByName` calls, so it
dies with it (note `Policies.kt` has a **separate**
`Connection.insertReturningId` extension that is very much alive — do not
conflate the two). Also `role` (660) / `roleExists` (663), and with them
`queryOne` (875), whose only call site is `role`. `findUserByExternalId` (565) /
`findGroupByExternalId` (566) are public but have no production caller either.
All are leftovers from the era before `provisionFromOidc` delegated to
`OidcDirectoryProvisioner`. **F27 (index F80) — OMIT**, but only for the symbols
with no call path in main _or_ test: those have no observable behaviour, so
dropping them changes nothing. `findUserByExternalId` / `findGroupByExternalId`
are **not** in that set — they are the subject of three named cases
(`ScimUsersDbTest` 6, `ScimGroupsDbTest` 3, `ProvisionMergeDbTest` 15) plus a
fixture use at `ProvisionMergeDbTest:302`, so they are **REPRODUCE as a
test-visible Go equivalent**, not deletion. The same caveat governs
`setUserActive` (see above): production-dead, fixture-live in nine suites. OMIT
never means "delete and move on" for a symbol a test still calls.

---

### `Scim.kt` — gate, validator, mappers, routes

#### `ApplicationCall.requireScimAuth(config: Config): Boolean` · suspend

Contract: `true` iff SCIM is configured, the request demonstrably arrived over
TLS, and the bearer matches. Fail-closed at every step, with the SCIM-shaped
body.

Behavior, in this exact order:

1. `config.scimToken == null` ⇒ **501**
   `ScimError("501", detail = "SCIM provisioning is not configured")`, `false`.
2. `!isScimTls(config)` ⇒ **403** `("403", "SCIM requires TLS")`, `false`.
3. `provided = request.headers[Authorization]?.removePrefix("Bearer ")?.trim()`;
   `null` or `!constantTimeEquals(provided, expected)` ⇒ **401**
   `("401", "invalid bearer token")`, `false`.
4. Else `true`.

🔒 **INV-A3-36 — an unconfigured token means NO provisioning surface at all, not
an open one.** 501 is the fail-closed answer; `docs/auth-model.md:140-143` — "a
deployment that never sets the token has no provisioning surface at all —
JIT-on-login covers the directory on its own." `ScimAuthTest` case 6 pins it.

🔒 **INV-A3-37 — the TLS check precedes the bearer check.** Over plaintext the
request is rejected _before_ the secret is compared, so a correct bearer sent in
the clear still 403s and no comparison is performed on a wire-visible secret.
`ScimAuthTest` cases 1 and 2 assert 403 **with the correct bearer**. Reordering
these two steps is a real regression, not a style change.

🔒 **INV-A3-38 — `requireScimAuth` has NO `PM_AUTH_DEBUG` bypass, unlike the
other three gates.** Verified: no `authDebug` reference anywhere in `Scim.kt` or
`Users.kt`, and `ScimAuthTest`'s `testScimConfig` sets `authDebug = true`
(`ScimAuthTest.kt:106,111`) while still asserting 501/403/401. `AGENTS.md` ("a
route states its requirement by which gate helper it calls (`requireApi`,
`requireAdmin`, `requireAuthz`, `requireScimAuth`), and `PM_AUTH_DEBUG`
short-circuits all four") and `docs/authz-model.md:363` ("`PM_AUTH_DEBUG`
short-circuits all four to allow") both claim it — **the docs are wrong and the
code is right.** F21. A Go port must not "fix" the inconsistency by adding the
bypass: it would make a dev-mode control-plane accept unauthenticated directory
writes over plaintext.

⚠️ `removePrefix("Bearer ")` is **case-sensitive** and does not strip a
lowercase `bearer `; RFC 7235 declares the scheme case-insensitive. A client
sending `bearer <tok>` gets 401. Untested; F33-adjacent.

**Go shape:** the constant-time compare needs a byte comparison that does not
short-circuit on content. Note Java's `MessageDigest.isEqual` folds the length
difference into the accumulator, whereas Go's
`crypto/subtle.ConstantTimeCompare` returns 0 immediately on a length mismatch —
a length oracle the Kotlin does not have. Compare fixed-size digests of both
strings, or accept the divergence knowingly. ⟦LIB⟧ constant-time comparison
primitive.

#### `ApplicationCall.isScimTls(config): Boolean` · private

```kotlin
resolveScimTls(
  directScheme  = request.origin.scheme,
  peerAddress   = request.local.remoteAddress,
  forwardedProto = request.headers.getAll("X-Forwarded-Proto")?.lastOrNull(),
  trustedProxies = config.trustedProxies,
)
```

The source states why the peer comes from `request.local`:
_"`request.local.remoteAddress` is the raw socket peer (the same source
`httpRequesterIp` uses, and the reason it is not `origin.remoteAddress`: origin
is header-influenced, so it is not the TCP-level fact the trusted-edge test
needs)."_

⚠️ **But `directScheme` DOES come from `request.origin.scheme`.** Today that is
safe only because no `ForwardedHeaders`/`XForwardedHeaders` plugin is installed
(verified: `App.kt` installs `ContentNegotiation`, `CallLogging`, `StatusPages`,
`Sessions`, `Authentication` and nothing else — A12 INV-A12-11). Installing one
would make `origin.scheme` honour a client's `X-Forwarded-Proto` from **any**
peer and step 1 of `resolveScimTls` would return `true` before `isTrustedEdge`
is ever consulted — the standing SCIM bearer then travels in the clear. **A Go
port must take the scheme from the listener/TLS state, never from a
header-derived value.** Escalates A12 INV-A12-11 from "don't enable
forwarded-header middleware" to "enabling it silently disables the SCIM TLS
gate."

Note the double "rightmost": `getAll(...).lastOrNull()` takes the last **header
instance**, then `resolveScimTls` takes the rightmost **entry within it**. Go's
`Header.Values(...)` preserves instance order; `Header.Get` returns the first
and would be wrong.

#### `resolveScimTls(directScheme, peerAddress, forwardedProto, trustedProxies): Boolean` · internal

Kotlin:
`internal fun resolveScimTls(directScheme: String?, peerAddress: String?, forwardedProto: String?, trustedProxies: Set<String>): Boolean`

Behavior:

1. `directScheme.equals("https", ignoreCase = true)` ⇒ `true`. (Kotlin's
   `String?.equals` — a `null` scheme is simply not equal, no NPE.)
2. `!isTrustedEdge(peerAddress, trustedProxies)` ⇒ `false`. **A12's function** —
   INV-A12-1.
3. `asserted = forwardedProto?.split(',')?.lastOrNull()?.trim()`.
4. `asserted.equals("https", ignoreCase = true)`.

🔒 **INV-A3-39 — the third `X-Forwarded-*` consumer, and it MUST share A12's one
`isTrustedEdge`.** A12 INV-A12-1 tabulates all three consumers; the source
comment there warns that _"a second hand-rolled copy of this test is how a
header ends up honored from an untrusted peer."_ Here the consequence is the
worst of the three: without the gate "any direct plaintext caller could assert
`https` about itself and send the standing bearer in the clear."
`ScimTlsGateTest` case 4 is the named regression
(`forwardedProtoFromUntrustedPeerIsIgnored`).

🔒 **INV-A3-40 — rightmost entry wins, and absent/blank/non-`https` is NOT
TLS.** Only the last hop was appended by the trusted edge; "a client-supplied
leading https must not override the edge's own http" (`ScimTlsGateTest` case 6
asserts both directions of `"http, https"` vs `"https, http"`).

🔒 **INV-A3-41 — with `PM_TRUSTED_PROXIES` unset, NO peer is trusted, so a
TLS-terminating edge must be listed or SCIM stays 403.** Stated twice in the
source and pinned by `ScimTlsGateTest` case 5. The deployment corollary from A12
(`Config.kt:77-82`) matters most here: a listed edge must **overwrite**
`X-Forwarded-Proto` from its own view of the connection. An edge that _relays_
the client's value lets a plaintext request satisfy this gate.

#### `constantTimeEquals(a, b): Boolean` · private

`MessageDigest.isEqual(a.toByteArray(UTF_8), b.toByteArray(UTF_8))`. Source
comment: _"do NOT replace with `==`/`!=` (see Tokens.kt's ingest-token check for
the naive version this deliberately avoids; a standing SCIM secret is a juicier
timing target)."_ Cross-ref A4.

#### `object ScimPatchValidator`

`fun validate(operations: List<ScimPatchOperation>): ScimPatchAction`

Contract: a **pure** function — no I/O, no store access; routes apply the
returned action themselves. Throws `ScimPatchInvalidException` for anything
outside the core subset.

Behavior:

1. `operations.size != 1` ⇒
   `ScimPatchInvalidException("invalidPath", "exactly one Operations entry is supported")`.
   Covers both empty and multi-op bodies.
2. `path = op.path?.trim()` — trimmed; `op.op` matched **case-insensitively**.
3. `op == "replace"` && `path == "active"`:
   `(op.value as? JsonPrimitive)?.booleanOrNull` else
   `("invalidValue", "path 'active' requires a boolean value")`. ⇒
   `SetActive(active)`. Note `booleanOrNull` on `JsonPrimitive("yes")` is null
   (test case 7 pins it) — a JSON _string_ `"true"` is likewise rejected, since
   `booleanOrNull` only accepts an unquoted literal.
4. `op == "add" | "remove"` && `path == "members"`: `(op.value as? JsonArray)`
   else `("invalidValue", "path 'members' requires a value array of {value}")`;
   then
   `mapNotNull { (it as? JsonObject)?.get("value")?.let { (it as? JsonPrimitive)?.contentOrNull } }`
   ⇒ `MemberOp(op.op.lowercase(), values)`. **Non-object or `value`-less array
   entries are silently dropped**, not rejected.
5. Anything else ⇒
   `("invalidPath", "unsupported PATCH op/path '<op>'/'<path>' — only replace:active (Users) and add|remove:members (Groups) are supported")`.
   Note the message interpolates the **untrimmed** `op.path`.

🔒 **INV-A3-42 — the subset is exactly two shapes and everything else is a SCIM
400, never a silent accept.** Reason from `docs/auth-model.md:147-150`: the
subset "is small and near-identical across IdPs, so it is cheap and portable";
implementing a filter-path grammar (`members[value eq "..."]`) was declined.
`ScimPatchValidatorTest` case 8 pins that filter-path syntax is **rejected**,
not partially honoured — a partial parse would let an IdP think it removed a
member when it did not. **Never guess at an unsupported path.**

**INV-A3-43 — op/path pairing is enforced, not just the path.**
`replace:members` and `add:active` are both `invalidPath` (test cases 9, 10),
even though each token is individually valid.

**INV-A3-44 — the validator returns an action; the routes decide whether it
applies to their resource type.** `SetActive` on Groups ⇒ 400 `invalidPath`
"path 'active' is only valid on Users"; `MemberOp` on Users ⇒ 400 `invalidPath`
"path 'members' is only valid on Groups". Keeping the validator
resource-agnostic is what lets one implementation serve both routes; the cost is
these two extra route branches, which must not be dropped.

**Go shape:** pure function over a decoded operations slice → a tagged union.
`value` must stay a raw JSON value (not a pre-decoded bool/array) so steps 3–4
can distinguish "wrong JSON type" from "absent". ⟦LIB⟧ none beyond the JSON
decoder.

#### Mappers

`AppUser.toScim()`: `id = id.toString()`, `externalId`, `userName = principal`,
`name = displayName?.let { ScimName(formatted = it) }`,
`emails = email?.let { listOf(ScimEmail(value = it, primary = true)) } ?: emptyList()`,
`active`,
`groups = groups.map { ScimUserGroupRef(value = it.id.toString(), display = it.name) }`.

`AppGroup.toScim(members)`: `id`, `externalId`, `displayName = name`,
`members = members.map { ScimMemberRef(value = it.userId.toString(), display = it.principal) }`.

`ScimUser.primaryEmail()`:
`emails.firstOrNull { it.primary == true }?.value ?: emails.firstOrNull()?.value`
— first `primary == true`, else the first entry's value; may be `null`.

⚠️ `ScimName` models **only** `formatted`. An IdP pushing
`givenName`/`familyName` and no `formatted` yields `displayName = null` silently
(`ignoreUnknownKeys = true`). Okta sends `formatted`; other IdPs may not. §Open
questions Q5.

⚠️ `AppUser.email` round-trips as a **single** `primary: true` email. A
multi-valued push is lossy: only `primaryEmail()` survives, and a subsequent GET
shows one address. Deliberate (one `email` column) but worth stating.

#### `respondScimError(status, scimType, detail)` · private suspend

`respond(status, ScimError(status = status.value.toString(), scimType = scimType, detail = detail))`.
The **only** deliberate error path in the file — INV-A3-2.

#### `Route.scimRoutes(config, userGroupStore, tokenStore, accessStore, daemonSessionStore, log)`

Route-level behaviour beyond the table above, in the order it matters:

1. **POST /Users** — `externalId` blank/absent ⇒ 400;
   `principal = body.userName.ifBlank { body.primaryEmail().orEmpty() }`, still
   blank ⇒ 400. Then the 8-arg `upsertScimUser` inside a
   `try/catch(SQLException)`; `isUniqueViolation()` ⇒ 409 `uniqueness`. Logs
   `"SCIM: provisioned user principal={} externalId={}"`. 201 with the mapped
   user. Reason for the 409, quoted: _"a POST whose externalId is new but whose
   email/principal match resolves to a row already owning a DIFFERENT
   external_id collides here rather than silently producing a split-brain
   external_id."_
2. **PUT /Users/{id}** — unparseable id ⇒ 404; row absent ⇒ 404. Then, **field
   by field**: `externalId = body.externalId ?: existing.externalId` (blank ⇒
   400); `principal = body.userName.ifBlank { existing.principal }` — **no email
   fallback**, unlike POST; `email = body.primaryEmail() ?: existing.email`;
   `displayName = body.name?.formatted ?: existing.displayName`;
   `active = body.active` — **taken verbatim, and its default is `true`.** ⇒
   `replaceScimUserById`; `null` ⇒ 404; unique violation ⇒ 409 `uniqueness`. ⚠️
   So PUT is a **merge** for the four scalar fields and a **verbatim replace**
   for `active`: a body omitting `active` silently REACTIVATES a deprovisioned
   user. Untested. F22.
3. **PATCH /Users/{id}** — id unparseable **or** row absent ⇒ 404; validate;
   `SetActive` ⇒ `setActiveById(id, active, …)`, `null` ⇒ 404, logs
   `"SCIM: deactivated user principal={}"` when deactivating, 200 with the
   updated user; `MemberOp` ⇒ 400 `invalidPath`.
4. **DELETE /Users/{id}** — `id?.let { setActiveById(it, false, …) } ?: 404` —
   the elvis covers both an unparseable id and a missing row. Logs
   `"SCIM: deprovisioned user principal={}"` with the **re-read** principal.
   204, no body.
5. **POST /Groups** — `externalId` blank ⇒ 400; `displayName` blank ⇒ 400;
   `upsertScimGroup` in `try/catch`: `SystemGroupImmutableException` ⇒ 409
   `mutability`, unique violation ⇒ 409 `uniqueness`. **Then**
   `body.members.forEach { m -> m.value.toLongOrNull()?.let { addMember(group.id, it) } }`
   — **outside the try, one statement per member, not in a transaction, and
   ADD-only** (a POST onto an existing group never removes). Logs
   `"SCIM: provisioned group name={} externalId={}"`. 201 with
   `group.toScim(listMembers(group.id))` — the member list is **re-read after**
   the adds, so the response is fresh, but the `AppGroup` scalars (and its
   now-stale `memberCount`) come from the pre-add `getGroup`. Only
   `id`/`externalId`/`displayName` survive into `ScimGroup`, so the staleness is
   invisible on the wire today; it stops being invisible the moment `ScimGroup`
   grows a `meta`.
6. **PUT /Groups/{id}** — id/row absent ⇒ 404; `isSystemGroup(existing.id)` ⇒
   409 `mutability`; `externalId = body.externalId ?: existing.externalId`
   (blank ⇒ 400); `displayName = body.displayName.ifBlank { existing.name }`;
   `replaceScimGroupById` (unique violation ⇒ 409). **Then a true membership
   replace**:
   `desired = body.members.mapNotNull { it.value.toLongOrNull() }.toSet()`,
   `current = listMembers(...)`, add `desired - current`, remove
   `current - desired`. ⚠️ So a PUT omitting `members` reconciles to the
   **empty** set and removes everyone — while the scalar fields merge. Both
   halves are real; replicate exactly.
7. **PATCH /Groups/{id}** — id/row absent ⇒ 404; SYSTEM ⇒ 409 `mutability`;
   validate; `MemberOp` ⇒
   `userIds = action.values.mapNotNull { it.toLongOrNull() }` then add-or-remove
   each, and respond with `existing.toScim(listMembers(existing.id))` —
   **`existing` is the pre-mutation group row**, but the member list is re-read,
   so scalars are stale-by-one and members are fresh. Harmless today (PATCH
   cannot change scalars) but do not "tidy" it into re-reading the row without
   checking `web/`. `SetActive` ⇒ 400 `invalidPath`.
8. **DELETE /Groups/{id}** — unparseable id ⇒ 404; `isSystemGroup(id)` ⇒ **409
   with `scimType = null`** (every sibling uses `"mutability"` — F26);
   `deleteGroup(id)` ⇒ 204 else 404.

🔒 **INV-A3-45 — the SYSTEM-group guard exists on all four Group mutations, but
by two different mechanisms.** POST goes through the store's in-transaction
`FOR UPDATE` check (INV-A3-33); PUT, PATCH, and DELETE do a route-level
`isSystemGroup` on a separate connection. The store-side one is the hardened
path; the three route-level ones are only safe because they address an immutable
id rather than re-resolving. A port must not "unify" them by moving POST's check
up to the route.

⚠️ **INV-A3-46 — every membership id is parsed with `toLongOrNull()` and a
non-numeric value is SILENTLY DROPPED**, on all three membership paths. A
_numeric but nonexistent_ user id instead hits the `group_member → app_user`
foreign key, raising SQLSTATE **23503** — which `isUniqueViolation()` does not
match and which is raised outside the `try` on POST — so it escapes to
`StatusPages` and returns a **500 with an `ApiError` body on a SCIM route**. Two
different wrong answers for one class of bad input. F29 + F30.

---

## Invariants index

Security invariants: INV-A3-3, -4, -5, -6, -7, -8, -9, -10, -16, -17, -18, -19,
-21, -23, -24, -25, -27, -28, -29, -30, -33, -34, -36, -37, -38, -39, -40, -41,
-42, -45. Non-security: -1, -2 (contract), -11 (warning), -12, -13, -14, -15,
-20 (correctness-critical), -22, -26, -31, -32, -35, -43, -44, -46.

The three that a port is most likely to lose, in order: **INV-A3-24** (the
`principal_role` purge order — invisible unless you read the comment),
**INV-A3-16** (the two revoke branches are not if/else), and **INV-A3-4** (the
advisory-lock key must be computed by Postgres).

---

## Test inventory — 12 files, 2,074 LOC, **105 cases**

Counted with `grep -rhoE '@Test\b' <file> | wc -l` per file; each per-file count
**equals** the number of enumerated case names below. **Independently re-counted
and re-verified case-name-by-case-name in a second audit pass**: all twelve
per-file counts and all 105 case names match the source exactly, and the LOC
column sums to 2,074. 🔒 marks security-critical cases.

⚠️ **7 of these 105 are also claimed by `14-auth.md` (`OidcGroupMappingTest`)**
— see that suite's entry and F35. If the reconciliation assigns them to A14, A3
becomes **98 cases across 11 suites, 2,023 LOC**.

Kinds: 3 unit (no DB), 1 route (`ktor-server-test-host`), 8 DB (Testcontainers
Postgres via `support/TestDatabases.kt`'s `SharedPostgres` +
`requireDockerOrSkip`).

### `ScimTlsGateTest.kt` — 72 LOC, 8 cases · unit

Pure `resolveScimTls`. Mixed naming — case 4 uses a plain camelCase identifier.

1. `direct https is TLS regardless of the trusted-edge set` (also pins
   case-insensitive scheme compare) — INV-A3-39 step 1
2. `direct http with no forwarded header is not TLS`
3. `forwarded proto from a trusted edge is honored` (also case-insensitive
   header compare)
4. 🔒 `forwardedProtoFromUntrustedPeerIsIgnored` — **the named vulnerability
   this gate closes** — INV-A3-39
5. 🔒 `an empty trusted-edge set trusts no peer` — INV-A3-41
6. 🔒 `a multi-hop value takes the rightmost entry` — asserts both
   `"http, https"` ⇒ true and `"https, http"` ⇒ false — INV-A3-40
7. 🔒 `absent or blank forwarded proto is not TLS` (null, `""`, `"   "`) —
   INV-A3-40
8. 🔒 `a null peer never passes on a header alone`

### `ScimAuthTest.kt` — 121 LOC, 6 cases · route (`testApplication`, a `/probe` stand-in route)

Drives `requireScimAuth` through real Ktor plumbing. **Every case runs with
`authDebug = true`** — which is what makes this suite the proof of INV-A3-38.

1. 🔒 `plaintext request is rejected regardless of the bearer token` ⇒ 403 —
   INV-A3-37
2. 🔒 `forwarded proto from an untrusted peer does not satisfy the TLS gate` ⇒
   403 **with the correct bearer** — INV-A3-39
3. `https-asserted request with the wrong bearer is unauthorized` ⇒ 401
4. `https-asserted request with no bearer header is unauthorized` ⇒ 401
5. `https-asserted request with the correct bearer succeeds` ⇒ 200
6. 🔒 `an unconfigured SCIM token disables the endpoint fail-closed` ⇒ 501 —
   INV-A3-36

Fixture:
`internal fun testScimConfig(scimToken, trustedProxies = emptySet()): Config`
(`ScimAuthTest.kt:106`) — a full `Config` where every field but
`scimToken`/`trustedProxies` is inert. **Port this fixture; it is the only place
a minimal valid `Config` is constructed for a gate test.**

### `ScimPatchValidatorTest.kt` — 117 LOC, 14 cases · unit

Pure `ScimPatchValidator`; asserts the exact `scimType` on every rejection.

1. `accepts replace active true`
2. `accepts replace active false`
3. `op is case-insensitive for replace active` (`"REPLACE"`)
4. `accepts add members with a value array` ⇒ `MemberOp("add", ["1","2"])`
5. `accepts remove members with a value array`
6. `rejects an unsupported path` (`replace:userName`) ⇒ `invalidPath`
7. `rejects a non-boolean active value` (`JsonPrimitive("yes")`) ⇒
   `invalidValue`
8. 🔒 `rejects filter-path grammar on members` (`members[value eq "2"]`) ⇒
   `invalidPath` — INV-A3-42, **the no-partial-parse rule**
9. `rejects replace on members (wrong op for that path)` ⇒ `invalidPath` —
   INV-A3-43
10. `rejects add on active (wrong op for that path)` ⇒ `invalidPath` — INV-A3-43
11. `rejects a members value that is not an array of objects` ⇒ `invalidValue`
12. `rejects multiple operations` ⇒ `invalidPath`
13. `rejects an empty Operations list` ⇒ `invalidPath`
14. `rejects a missing path` (`path = null`) ⇒ `invalidPath`

### `ScimUsersDbTest.kt` — 312 LOC, 14 cases · **DB**

1. `upsertScimUser provisions a source=SCIM row keyed on externalId`
2. `upsertScimUser is idempotent on repeated pushes for the same externalId`
3. `upsertScimUser active=false deactivates the row`
4. `upsertScimUser reconciles an existing OIDC-provisioned row instead of duplicating it`
   — INV-A3-31
5. `upsertScimUser never clobbers a SCIM row's source`
6. `findUserByExternalId finds a provisioned user and is null for an unknown id`
7. `setUserActive toggles active and persists`
8. `distinct externalIds never collide into the same row`
9. 🔒
   `replaceScimUserById mutates the row AT this id — never a different row a body-key match would have resolved`
   — **INV-A3-32, the cross-resource-write regression**
10. `replaceScimUserById rejects an externalId that already belongs to a DIFFERENT row`
    (expects a raw `SQLException`)
11. 🔒
    `a retired principal's direct principal_role grant does not silently transfer to whoever reuses the string`
    — **INV-A3-24, privilege escalation via principal recycling**
12. `replaceScimUserById is null (404) for a nonexistent id`
13. 🔒
    `a retired (tombstoned) principal can be reused by a later rename — no permanent unique-constraint block`
    — INV-A3-25
14. `replaceScimUserById can rename BACK onto its own just-retired principal string`
    — INV-A3-25/-26

### `ScimGroupsDbTest.kt` — 91 LOC, 6 cases · **DB**

1. `upsertScimGroup provisions a source=SCIM group keyed on externalId`
2. `upsertScimGroup is idempotent on repeated pushes for the same externalId`
3. `findGroupByExternalId finds a provisioned group and is null for an unknown id`
4. `distinct externalIds never collide into the same group row`
5. `SCIM group membership PATCH reuses addMember-removeMember (group_member)` —
   no SCIM-specific membership table
6. 🔒
   `a group with roles mapped via group_role is unaffected by SCIM provisioning`
   — the IdP supplies membership only, never roles

### `ProvisionMergeDbTest.kt` — 398 LOC, 18 cases · **DB** (2 cases use real concurrency)

The area's centre of gravity: JIT↔SCIM reconciliation plus the atomic-teardown
matrix.

1. `provisionFromOidc creates a new source=OIDC user and mirrors the claim's groups`
   (JIT-created groups are `source=OIDC`)
2. 🔒
   `re-provisioning SYNCS group membership to the latest claim (drops removed groups)`
   — INV-A3-28
3. `provisionFromOidc reuses an existing group's source, whatever it is` (a
   `LOCAL` group stays `LOCAL`)
4. 🔒 `JIT never clobbers a source=SCIM user's fields` — INV-A3-27, incl. an
   attacker-supplied email
5. `upsertScimUser matches an existing JIT user by email and reconciles it to SCIM`
   — INV-A3-31
6. `upsertScimUser matches by external_id first, even if principal or email changed at the IdP`
   — INV-A3-31
7. 🔒
   `a SCIM rename retires the old principal string so it cannot keep authenticating`
   — INV-A3-21
8. 🔒
   `a SCIM rename atomically revokes the old principal's active credentials — tokens, grants, and daemon session window`
   (also asserts `ENDED_DEACTIVATED` on the web row) — INV-A3-5/-6
9. 🔒
   `the public 5-arg upsertScimUser rename revokes the old principal credentials`
   — proves the convenience overload is not "half-safe"
10. 🔒
    `upsertScimUser active=false atomically revokes the principal credentials` —
    INV-A3-6
11. 🔒
    `setActiveById deactivates and revokes atomically by id (SCIM PATCH SetActive false, and DELETE)`
    — INV-A3-19
12. 🔒
    `setActiveById re-reads the current principal under the lock — deactivates the row's real identity, not a stale snapshot (SCIM PATCH-DELETE)`
    — **INV-A3-20**; holds `pg_advisory_xact_lock(hashtext('sa-old@…'))` from a
    raw connection, renames uncommitted, asserts the call **blocks**, then that
    the re-read `mid` principal is the one revoked
13. 🔒
    `a blocked rename retires the principal carried by the row after lock release`
    — **INV-A3-20**, the rename twin of case 12
14. `upsertScimGroup matches an existing group by external_id then by name`
    (incl. a JIT group later claimed by SCIM)
15. `findUserByExternalId and findGroupByExternalId round-trip`
16. `setUserActive and isDeactivated`
17. 🔒 `isDeactivated is false for a principal with no app_user row at all` —
    INV-A3-10
18. `upsertScimUser matches by principal when external_id and email are both new`
    (a `LOCAL` admin-made row reconciles to SCIM)

Cases 12 and 13 are the hardest to port: they need a second, independent
connection holding a transaction-scoped advisory lock while the code under test
blocks, plus an assertion that it **has not** completed after ~300 ms. Any Go
harness must be able to hold a raw transaction outside the pool.

### `DeprovisionDbTest.kt` — 231 LOC, 8 cases · **DB**

Its header (`DeprovisionDbTest.kt:22-38`) carries a warning worth carrying into
the Go docs verbatim: `RoleResolver.resolve` returning `emptySet` is _necessary
but NOT sufficient_ — "`decideQuery` only builds column MASK/DENY actions from
role-attached policies, and **`PolicyEvaluator`** ALLOWs when no masks result,
so an empty role set alone **actually flips** a deactivated principal's masked
query to cleartext ALLOW (more access after deprovision)". Note the attribution:
the permissive default is `PolicyEvaluator`'s, not `decideQuery`'s. The
authoritative end-to-end check is A6's `DeactivationEnforcementDbTest` — the
explicit structural DENY `decideQuery` now emits, exercised through
`runEnforcedForTest`; this file covers only the layers below it.

1. `revokeAllForPrincipal revokes every active token for that principal only`
   (A4's store)
2. `revokeAllForPrincipal is a no-op on an already-revoked or expired token`
3. `AccessStore revokeAllForPrincipal revokes every active grant for that principal only`
   (A6's store)
4. 🔒
   `revokeActiveCredentials sums tokens grants daemon windows and web sessions`
   — asserts the exact sum **6**, a bystander's web session untouched, and
   idempotence (second call ⇒ 0) — INV-A3-5
5. 🔒
   `revokeActiveCredentials closes the principal's daemon session windows so a renewal secret can't survive`
   — INV-A3-5
6. 🔒
   `RoleResolver resolve is fail-closed to empty for a deactivated principal, across every role source`
   — direct ∪ group ∪ JIT all present, then all gone, then restored on
   reactivation — **INV-A3-9**
7. 🔒
   `a principal with no app_user row at all is unaffected by the deactivation gate`
   — INV-A3-10
8. 🔒
   `mintForActivePrincipalLocked refuses when a concurrent teardown deactivates first`
   — **INV-A3-7**; the same held-lock harness as `ProvisionMergeDbTest` 12/13

### `UserAdminDeprovisionDbTest.kt` — 270 LOC, 10 cases · **DB**

Store/primitive level, deliberately not route level ("equivalent coverage, no
HTTP/admin-gate scaffolding needed"). Helpers
`seedCredentials(principal, roleName)` (mints one of every credential class),
`assertWebEnded`, `assertWebLive` — port these first.

1. 🔒
   `PUT rename atomically retires the old principal — tombstoned, token + grant + session revoked`
   — INV-A3-21/-6
2. 🔒
   `PUT active flip (true to false, no rename) revokes token + grant + session in the same transaction`
   — INV-A3-6
3. 🔒
   `PUT rename and deactivate revokes credentials held by both principal strings`
   — **INV-A3-16**, the not-if/else case
4. 🔒
   `createUser with active=false revokes credentials held before the row existed`
   — **INV-A3-18**
5. `createUser with active=true does not touch an unrelated principal's credentials`
   — the negative half of INV-A3-18
6. `PUT with no rename and no active flip does not revoke anything` — the no-op
   guard
7. 🔒
   `DELETE tombstones (never hard-deletes) and revokes token + grant + session atomically`
   — INV-A3-19
8. `DELETE on a nonexistent id returns false (404 at the route)`
9. `REST-shaped ID deprovision still targets the original row after a principal rename`
   — id-stability through `IdentityManagementService.deprovisionUser(id)` (A11)
10. `concurrent REST-shaped group role additions retain both mappings` — two
    real threads on a `CountDownLatch` through `management.addGroupRole`; pins
    INV-A3-35 against A11's `lockMutableGroup`

### `BootstrapAdminDbTest.kt` — 172 LOC, 8 cases · **DB**

The first-admin bootstrap end to end. Fixture:
`adminMap = OidcGroupMapping(mapOf("proxy-monster-admin" to "system:admin"), "proxy-monster-")`.

1. `the seed installs the system-admin group (SYSTEM), the system-admin role, and their link`
2. 🔒
   `an IdP admin-group member resolves system-admin and loses it when the group is dropped (sync)`
   — INV-A3-28, the revoke-on-next-login path
3. `an unmapped IdP group is created by name with the prefix stripped` (and is
   not a SYSTEM group)
4. `isSystemGroup distinguishes the seeded system group from a user-created one`
   (also the only caller of `isSystemGroupByName`)
5. 🔒
   `a raw reserved-name claim without a mapping does not confer admin (escalation closed)`
   — **INV-A3-30**, "the privilege-escalation the gate caught"
6. 🔒
   `upsertScimGroup refuses to mutate the SYSTEM group atomically (by name and by externalId)`
   — **INV-A3-33/-34**; plants an `external_id` on the system row to exercise
   the by-extId resolution path a route-level guard would race on, and asserts
   the row is untouched afterwards
7. `isSystemRole protects the system-admin role wired into system-admin` — tests
   **A9/A11**'s `PolicyStore.isSystemRole` predicate (see the F6/F19 correction
   below)
8. `the seeded system-admin group carries only the intended wiring and no members`
   — builds its **own** fresh database because a sibling case provisions a
   member into the class-shared one; asserts no `external_id`, zero members,
   exactly one role link — INV-A3-12/-29

### `ResolveRolesTest.kt` — 100 LOC, 4 cases · **DB**

Class-level fixture wires all three role sources for one principal.

1. `resolve unions direct, group, and JIT grant roles`
2. `a revoked grant is excluded from resolve (activeOnly)`
3. `an expired grant is excluded from resolve (activeOnly)` — approves with
   `durationSec = -3600` so `expires_at <= now()`; pins that `resolve` fails
   closed on `expires_at`, not only `revoked_at`
4. 🔒 `unknown principal resolves to the empty set (fail-closed)`

### `ReadinessDiagnosticDbTest.kt` — 139 LOC, 2 cases · **DB** (+ `testApplication`)

✅ **Counted here, and only here — verified, no conflict.** Case 1 is pure
`RoleResolver`; case 2 also exercises A1's `/health` diagnostics list, but
`01-bootstrap.md` closed at 27 cases (ConfigGuardTest 25 +
MigrationSelfContainmentTest 2) and did not claim it.
`04-auth-session-tokens.md:1563` (its Q8) independently confirms A4 does not
claim it either and asks that someone must. A3 does. Its own kdoc cites
`docs/policy-store.md`, not `authz-model.md`.

1. 🔒 `hasActiveAssignee mirrors resolve across direct group and JIT role paths`
   — **ten** mirrored assertions through the `assertResolvedAndDiagnosed` helper
   (`ReadinessDiagnosticDbTest.kt:44,46,48,56,58,67,69,71,73,76`), each
   asserting
   `("system:admin" in resolve(p)) == hasActiveAssignee("system:admin")`, over:
   direct grant ± inactive row ± no row; group member ± inactive; JIT grant ±
   expired ± revoked ± inactive row. Plus **three** readiness-only `assertFalse`
   checkpoints (`:41,51,60`), the first of which is the seed's member-less link
   ⇒ false. Thirteen assertion points, ten mirrored — INV-A3-12/-13
2. `health stays ok and reports whether system-admin has an active assignee` —
   `/health` returns 200 with
   `diagnostics = ["system:admin role has no active assignee"]` on a clean
   install, and an empty list once a direct assignment exists. **Status stays
   `ok`** — an unopened install is reported, not marked down.

### `OidcGroupMappingTest.kt` — 51 LOC, 7 cases · unit

🚨 **DOUBLE-COUNTED — this is now a hard conflict, not an open question.**
`14-auth.md` has since been written and its §7 test inventory
(`14-auth.md:1009`) reads "**3 files, 302 LOC, 17 cases**", whose three files
are `McpOAuthStoreDbTest` (6), `TokenTtlTest` (4) and — at `14-auth.md:1057` —
**this suite, with the same 51 LOC / 7 cases**, numbered there as
INV-A14-33/-34. So A3's 105 and A14's 17 both include the same 7 cases: the
903-case reconciliation is **7 over** until exactly one doc drops them. (A14's
own "counted elsewhere" table at `:1076-1085` correctly cedes
`ProvisionMergeDbTest` to A3 and labels `BootstrapAdminDbTest` "A3/A4" — those
two are _not_ double-counted; only `OidcGroupMappingTest` is.)

**Recommendation: A14 keeps them, A3 drops to 98 across 11 suites** — the symbol
under test lives in `auth/`, A14 already gives it dedicated invariant numbers,
and A14's headline says the module "has no tests of its own", which is exactly
the gap these 7 close. A3 should then reference them the way it references
`DeactivationEnforcementDbTest`. **Do not act on that here** — the totals live
in `00-INDEX.md`, which this doc must not edit; A3's number stays 105 until the
reconciliation pass decides, so that the 7 cases are never owned by _nobody_.

⚠️ **Symbol ownership:** the class under test, `OidcGroupMapping`, is
`auth/src/.../Oidc.kt:102` (`resolve` at `:103-108`) — the `auth/` module. The
_test file_ lives in the control-plane tree, so its 7 cases are part of
control-plane's 847 (`00-INDEX.md:27`) either way. A3 originally claimed it
because A3 owns the identity semantics it enforces (INV-A3-30) and because
`00-INDEX.md:29,197` records `auth/` as having **0** test LOC — a claim
`14-auth.md` now contradicts, so the index line is stale too. **Port the symbol
with A14 and the test with whichever module carries it.** Same treatment A12
gave `RequesterIpParseTest`.

1. `parse reads idpGroup=pmGroup pairs and ignores malformed entries` —
   `"a=b, c=d ,junk,=x,y="` keeps only the two well-formed pairs
2. `an explicit mapping wins over the prefix rule`
3. `an unmapped group is taken by name with the prefix stripped`
4. `no prefix keeps unmapped names as-is`
5. `a group that is blank after stripping the prefix is dropped`
6. 🔒 `the reserved system namespace is unreachable via the unmapped fallback` —
   raw `system:admin`, prefix-stripped `proxy-monster-system:admin`, and the
   case-fold variants `System:Admin`/`SYSTEM:admin` are **all** dropped, while a
   non-reserved sibling still resolves — **INV-A3-30**
7. `an explicit mapping may target the reserved system namespace` — the
   operator-configured map IS the admin path

### Per-suite tally

| Suite                        | LOC       | Cases   | Kind                    |
| ---------------------------- | --------- | ------- | ----------------------- |
| `ScimTlsGateTest`            | 72        | 8       | unit                    |
| `ScimAuthTest`               | 121       | 6       | route                   |
| `ScimPatchValidatorTest`     | 117       | 14      | unit                    |
| `ScimUsersDbTest`            | 312       | 14      | DB                      |
| `ScimGroupsDbTest`           | 91        | 6       | DB                      |
| `ProvisionMergeDbTest`       | 398       | 18      | DB                      |
| `DeprovisionDbTest`          | 231       | 8       | DB                      |
| `UserAdminDeprovisionDbTest` | 270       | 10      | DB                      |
| `BootstrapAdminDbTest`       | 172       | 8       | DB                      |
| `ResolveRolesTest`           | 100       | 4       | DB                      |
| `ReadinessDiagnosticDbTest`  | 139       | 2       | DB                      |
| `OidcGroupMappingTest`       | 51        | 7       | unit                    |
| **Total**                    | **2,074** | **105** | 3 unit · 1 route · 8 DB |

Minus the disputed `OidcGroupMappingTest` (F35): **2,023 LOC · 98 cases · 11
suites**.

**Port order:** the 28 unit + route cases first (no container, they cover
INV-A3-36..-44 outright), then `ResolveRolesTest`/`DeprovisionDbTest` (the
`RoleResolver` + teardown contract A6/A7/A11 assume), then the three concurrency
cases (`ProvisionMergeDbTest` 12/13, `DeprovisionDbTest` 8) — those three decide
whether the Go advisory-lock plumbing is right, and everything else is
comparatively mechanical.

### Related coverage owned elsewhere (do not re-count)

- `DeactivationEnforcementDbTest` (4 cases, **A6**) — the end-to-end structural
  DENY that `DeprovisionDbTest`'s header says is the authoritative fail-closed
  check.
- `EffectiveRolesTest` (4, **A6**) — `effectiveRoles`, the union `resolve`
  delegates to.
- `RenewalWindowTest` (**A4**) — includes
  `revokeActiveCredentials itself blocks behind a concurrent holder of the SAME principal's advisory lock`,
  i.e. A3's INV-A3-3 tested from the renewal side.
- `WebSessionRoutesDbTest` (**A4**) — `RoleResolver.directRoles` through the
  web-session routes.
- `ApprovalResultDeactivationDbTest` (2, **A7**), `grpc` suites (**A10**) —
  further `isDeactivated` consumers.

### Coverage gaps in A3

**Security-relevant:**

1. 🔒 **SCIM PUT reactivation.** No test sends a `PUT /Users/{id}` body that
   omits `active` against a deprovisioned user. `ScimUser.active` defaults to
   `true`, so the row reactivates and — because the deactivate branch does not
   fire — its credential teardown is never re-run. F22. **Highest-value new test
   in the area.**
2. 🔒 **The two-lock deadlock.** Nothing exercises concurrent renames A→B and
   B→A. Every rename path locks `(current, target)` in that order, so the
   reverse pair deadlocks; Postgres aborts one with a deadlock error, which
   surfaces as a 500. F24.
3. 🔒 **`findUserIdByEmail` against duplicate emails.** `ScimUsersDbTest` case 9
   deliberately _creates_ two rows sharing an email, but only ever calls
   `replaceScimUserById` (which does not resolve by email). No test drives
   `upsertScimUser` into that ambiguity. F23.
4. 🔒 **`releaseTombstone`'s narrowness from the other side.** Cases 11/13/14
   prove a tombstone _is_ released; nothing proves a genuinely inactive real
   user (own `external_id`, or a local admin's deliberate deactivation) is
   **not** deleted when a rename targets its principal string. INV-A3-23 is
   asserted only in one direction.
5. 🔒 **`replaceScimGroupById` has no SYSTEM-mutation test** — only the
   route-level pre-check exists, and no suite drives PUT/PATCH/DELETE on a
   SYSTEM group at route level. `BootstrapAdminDbTest` case 6 covers the
   POST/store path only. INV-A3-45's weaker half is untested. 5b. 🔒 **Six of
   the seven seeded SYSTEM groups are untested entirely** (`system:developer`
   and the five `system:production-*`). Every SYSTEM assertion in the area names
   `system:admin`, while every guard is keyed on `source = 'SYSTEM'`. **New test
   to add: parameterise the immutability cases over all seven seeded rows.**
   F36. 5c. **The production `deleteUser` body is only covered indirectly.** The
   two store-level DELETE cases call the 4-arg wrapper (a `setActiveById` alias
   with no production caller); the 5-arg overload A11 actually calls — different
   body, extra `false` exit, no tombstone-release — is reached only via case 9's
   `management.deprovisionUser(id)`. F37.
6. 🔒 **No test drives a single SCIM route end to end.** `ScimAuthTest` uses a
   stand-in `/probe` route; the Db suites call the store directly. So every
   route-level branch in `Scim.kt:320-594` — the 400 validations, the 409
   mappings, the merge-vs-replace field semantics, the membership reconcilers,
   the 201/204 statuses, the `Resources` envelope — is **unasserted**. This is
   the largest untested surface in A3 and it is the wire contract
   `web/`-adjacent IdPs consume.

**Correctness / interop:** 7. `hasActiveAssignee` is covered by exactly one case
in a suite no other area claimed (see the ⚠️ above). If that suite is dropped in
the port, the predicate loses all coverage. 8. `provisionFromOidc`'s underlying
`OidcDirectoryProvisioner` is only tested through A3's store wrapper; its own
transaction/rollback behaviour is untested (A14 has zero tests of its own). 9.
Non-numeric and nonexistent SCIM member ids (F29) — neither the silent drop nor
the 500 is asserted. 10. `ScimName` with `givenName`/`familyName` only;
multi-valued email round-tripping. 11. Lowercase `bearer ` scheme (RFC 7235
case-insensitivity) — `removePrefix("Bearer ")` rejects it. 12.
`deactivatePrincipalTombstone`'s `ON CONFLICT` branch against a non-SCIM row
(Q3). 13. `listUsers` / `listGroups` read skew across their 2–3 connections. 14.
Unbounded list responses and `GET /Groups`' N+1 `listMembers` — no scale test.

### Corrections to `00-INDEX.md` (per its own "re-check gap claims" rule)

**Its test-accounting lines are stale in two places.** `00-INDEX.md:8` still
says "Areas A3–A12 are not yet written" and `:64-67` reports 443/903 with
`auth/` outstanding, yet `14-auth.md` exists and claims 17 cases; and
`:29`/`:197` record `auth/` as **0** test LOC / "`auth/` has no tests", which
`14-auth.md:1014-1015` itself qualifies ("The module itself has no tests
(`auth/src/test` does not exist). All three suites live in
`control-plane/src/test/…`"). Both statements are defensible separately — the
module directory is empty, the suites are counted — but as written the index
line reads as "zero cases attributable to `auth/`", which is what let A3 claim
`OidcGroupMappingTest` in the first place. See F35.

**F6 / F19 are partly resolved.** F6 says `isSystemRole` "has **no** test (see
F19)". It does: `BootstrapAdminDbTest` case 7 asserts `PolicyStore.isSystemRole`
returns true for the seeded `system:admin` role and false for a plain one, with
the reason recorded inline ("PUT/DELETE /api/roles can't rename it (breaks the
name-based admin policy) or delete it (CASCADE-drops the bootstrap link)"). What
remains untested is the **enforcement** —
`ManagementServices.kt:362,370,382,389` throwing `role.system_immutable`. So:
predicate covered, guard uncovered. F19's headline ("largest untested surface …
contains security guards") stands for `ManagementServices` as a whole.

---

## Candidate findings raised by A3

`00-INDEX.md` currently ends at F20; these are numbered **F21+** and are **not**
written into that file. F21–F34 were raised when A3 was first specified; F35–F39
were added by the audit pass that re-verified it.

| #       | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Where                                                             | Kind                  |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | --------------------- |
| **F21** | 🔒 `requireScimAuth` has **no** `PM_AUTH_DEBUG` bypass, while `AGENTS.md` and `docs/authz-model.md:363` both say "`PM_AUTH_DEBUG` short-circuits all four". The **code is right**; `ScimAuthTest` runs every case with `authDebug = true` and still expects 501/403/401. A port that "fixes" the docs' version makes a dev-mode control-plane accept unauthenticated directory writes over plaintext                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `Scim.kt:150`, `docs/authz-model.md:363`, `AGENTS.md`             | 🔒 stale doc          |
| **F22** | 🔒 `ScimUser.active` defaults to `true` and `PUT /Users/{id}` passes `body.active` verbatim, so a PUT body omitting `active` silently **reactivates** a deprovisioned user — and skips the deactivate branch, so no teardown re-runs. Untested                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `Scim.kt:54,420`                                                  | 🔒 possible live gap  |
| **F23** | 🔒 `findUserIdByEmail` matches on `app_user.email`, which has **no unique constraint and no index at all** — `app_user` gets a `UNIQUE` on `principal` (`V1__identity.sql:19`) and a partial unique index on `external_id` (`:41`), nothing on `email` — and the query has no `ORDER BY`, so `LIMIT`-less `if (rs.next())` takes an arbitrary row. V1's own comment (`:36-40`) explains exactly this hazard for `external_id` — "a later `active=false` push would deactivate whichever row Postgres returned first while the real one stayed credentialed" — yet email escapes it                                                                                                                                                                                                                                                                                                                                                                      | `Users.kt:839`, `V1__identity.sql:19,36-42`                       | 🔒 possible bug       |
| **F24** | Every rename path takes `advisoryLockPrincipal(current)` then `advisoryLockPrincipal(target)`. Two concurrent renames A→B and B→A acquire in opposite order and deadlock; Postgres aborts one → 500. Untested                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `Users.kt:173-174`, `411-412`, `454-455`                          | latent bug            |
| **F25** | 🔒 SCIM and local-admin identity mutations write **no** audit-trail row — only `log.info`. Provision, deprovision, rename, and group delete are invisible to the tamper-evident chain, while a Cedar SYSTEM policy toggle writes a sentinel record (INV-A2-22)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `Scim.kt`, `Users.kt`, `management/ManagementServices.kt:513-713` | 🔒 coverage gap       |
| **F26** | `DELETE /api/scim/v2/Groups/{id}` **hard-deletes**, CASCADE-dropping every `group_role` and `group_member` row — an IdP group delete silently revokes roles from every member, with no record and no undo, while users are never hard-deleted. Its 409 also omits `scimType` where every sibling sets `"mutability"`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `Users.kt:296`, `Scim.kt:581-593`                                 | 🔒 possible bug       |
| **F27** | Dead code in `Users.kt` — larger than first recorded: `groupIdsForUser` (355), `findGroupIdByName` (853), `ensureGroupByName` (866) + the helper it calls, `insertReturningId` (878), `role` (660) / `roleExists` (663) + the `queryOne` wrapper (875) whose sole call site is `role`; **plus, newly found, `findUserByExternalId` (565) / `findGroupByExternalId` (566) and the 4-arg `deleteUser` (191)**, all three public-but-production-dead (test-only callers). Plus production-dead `setUserActive` (638) and `isSystemGroupByName` (319), both carrying **kdocs that claim production roles they no longer have**. **Disposition split: OMIT** the truly call-path-free symbols; **REPRODUCE as test-visible helpers** the fixture-live ones — `setUserActive` (nine suites, five areas), `findUserByExternalId` / `findGroupByExternalId` (three suites), the 4-arg `deleteUser` (`UserAdminDeprovisionDbTest` 7–8). The stale kdocs are OMIT | `Users.kt`                                                        | dead code + stale doc |
| **F28** | `Scim.kt:377,426` cite migration "V14" for the `external_id` partial unique index and `Users.kt:800` cites "V6's own comment" for `principal_role` not being an FK target; both actually live in `V1__identity.sql` (`:41` and `:7` respectively — migrations are squashed to V1–V10, so there is no V14 at all). Also `V1`'s own column comments say `source` is `LOCAL \| SCIM` (`app_user` `:22`, `app_group` `:32`) while the code writes `OIDC` (`OidcDirectoryProvisioner:21,70`) and the seed writes `SYSTEM` (`V8__seed.sql:50-58`)                                                                                                                                                                                                                                                                                                                                                                                                             | `Scim.kt:377,426`, `Users.kt:800`, `V1__identity.sql:7,22,32,41`  | stale doc             |
| **F29** | SCIM membership ids: a **non-numeric** value is silently dropped by `toLongOrNull()`, while a **numeric but nonexistent** id raises an FK violation (SQLSTATE 23503) that `isUniqueViolation()` does not match and that on POST is raised outside the `try` — two different wrong answers for one class of bad input                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `Scim.kt:508,546,568`                                             | possible bug          |
| **F30** | 🔒 `StatusPages`' catch-all responds `ApiError("common.fallback")` for **any** uncaught exception, including on `/api/scim/v2/**` — breaking the documented SCIM error-body exemption (INV-A1-13 / INV-A3-2) exactly where an IdP is least able to parse it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `App.kt:452-462`                                                  | inconsistency         |
| **F31** | `RoleResolver.resolve` runs its four reads on four separate pooled connections with no transaction, so a deactivation committing mid-resolve yields a torn view. Contrast A2 INV-A2-10's single-snapshot rule for the consumer side                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `RoleResolver.kt:48-55`                                           | possible bug          |
| **F32** | `AppGroup.roles` is typed `List<GroupRef>` — a _group_ ref holding a **role** id/name — while the store's own accessor returns `GroupRoleEntry(roleId, roleName)`; `getGroup` maps one shape to the other. Two DTOs for one concept on one wire surface                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `Users.kt:56,259`                                                 | inconsistency         |
| **F33** | SCIM responses use `application/json`, not RFC 7644's `application/scim+json`; `201 Created` carries no `Location` header; `/Schemas` and `/ResourceTypes` return bare arrays instead of a `ListResponse`; the bearer prefix match is case-sensitive contra RFC 7235                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `Scim.kt`                                                         | interop deviation     |
| **F34** | `upsertScimUser` resolves `existingId` on three separate connections **outside** the transaction, then locks — while its Groups twin was deliberately hardened to resolve **inside** the transaction under `FOR UPDATE` after a real TOCTOU (INV-A3-33). The Users path never got the same treatment; `lockCurrentPrincipal`'s re-read loop mitigates but does not close it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `Users.kt:405-412` vs `512-531`                                   | inconsistency         |

### Added by this audit pass (F35–F39)

| #       | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Where                                                               | Kind            |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | --------------- |
| **F35** | 🚨 **`OidcGroupMappingTest`'s 7 cases are counted twice** — once in A3's 105 and once in `14-auth.md`'s 17 (`:1009` headline, `:1057` enumeration, INV-A14-33/-34). The 903-case reconciliation is 7 over until one doc drops them; recommended owner is A14 (the symbol is `auth/Oidc.kt:102`), which would make A3 **98 / 11 suites**. Compounding it, `00-INDEX.md:29,197` still records `auth/` as 0 test LOC / "no tests", which `14-auth.md` contradicts                                                                                                                                    | `03-identity-scim.md`, `14-auth.md:1009,1057`, `00-INDEX.md:29,197` | inconsistency   |
| **F36** | 🔒 **Six of the seven seeded SYSTEM groups are entirely untested.** `V8__seed.sql:48-58` installs `system:admin`, `system:developer` and five `system:production-*` groups, all `source=SYSTEM`; every immutability guard is keyed on the **column**, but every test (`BootstrapAdminDbTest` 1/4/6/8, and A3's whole SYSTEM story) uses only the string `system:admin`. A port that special-cases `"system:admin"` rather than `source='SYSTEM'` leaves six production-capability groups freely mutable through SCIM POST/PUT/PATCH/DELETE and the admin API, and no existing test would catch it | `V8__seed.sql:48-58`, `Users.kt:307`, `ManagementServices.kt:712`   | 🔒 coverage gap |
| **F37** | The two store-level DELETE tests (`UserAdminDeprovisionDbTest` 7 and 8, `:218,232`) call the **4-arg** `deleteUser`, which is a `setActiveById` wrapper with **no production caller**. The overload A11 actually invokes is the 5-arg one (`ManagementServices.kt:575,581`), whose distinct body — including its second `false` exit when `lockCurrentPrincipal` returns null, and its lack of a tombstone-release — is covered only indirectly by case 9                                                                                                                                         | `Users.kt:191` vs `194`, `UserAdminDeprovisionDbTest:218`           | coverage gap    |
| **F38** | An explicit `PM_OIDC_GROUP_MAP` entry may name a `system:*` group the seed never installed; `OidcDirectoryProvisioner.ensureGroup` then creates it with `source='OIDC'`, i.e. a mutable group inside the namespace `isReservedGroupName` exists to protect. It confers nothing (no `group_role` link) so it is not an escalation, but it means "reserved namespace" is enforced on the _unmapped_ path only                                                                                                                                                                                       | `auth/OidcDirectoryProvisioner.kt:68-76`, `auth/Oidc.kt:113`        | inconsistency   |
| **F39** | Three copies of the Postgres unique-violation SQLSTATE check: `Users.kt:890` (`isUniqueViolation`, used only by `Scim.kt`), `ManagementServices.kt:726` (inside `unique(...)`), and `ManagementServices.kt:505` (inline in `PolicyManagementService`). Also `23503` (FK violation) is matched by none of them — see F29                                                                                                                                                                                                                                                                           | `Users.kt:890`, `ManagementServices.kt:505,726`                     | duplication     |

**Live-gap candidates, ranked:** F22 (highest — a routine Okta PUT silently
reactivates a deprovisioned user), F36 (six untested SYSTEM groups — a
_coverage_ gap over a real, column-based guard, so a port defect rather than a
shipping bug), F23, F26, F24.

---

## Cross-area dependencies

| Direction | Area    | What                                                                                                                                                                                                  |
| --------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A3 →      | **A1**  | `Config.scimToken`, `Config.trustedProxies`, `ApiError`, `respondError`, `idParam`, the shared `Json` config (INV-A1-13, and F30's catch-all)                                                         |
| A3 →      | **A2**  | `requireAdmin(config, authz, ADMIN_IDENTITY)` on all 14 admin routes                                                                                                                                  |
| A3 →      | **A4**  | `TokenStore.revokeAllForPrincipal`, `PrincipalSessionStore.deactivateAllForPrincipal` / `endAllWebForPrincipal`, `ENDED_DEACTIVATED`, `LIVENESS_INACTIVE`, `Tokens.kt`'s naive-compare counterexample |
| A3 →      | **A6**  | `AccessStore.revokeAllForPrincipal`, `AccessStore.listGrants(activeOnly)`, `effectiveRoles` (`Query.kt:197`)                                                                                          |
| A3 →      | **A9**  | `PolicyStore` (roles), `app_role` / `principal_role` reads and the `principal_role` purge                                                                                                             |
| A3 →      | **A11** | `IdentityManagementService`, `ManagementException`, `DeleteResult`, `respondManagementError`, `group.system_immutable`                                                                                |
| A3 →      | **A12** | `isTrustedEdge` (INV-A12-1); INV-A12-11's no-forwarded-middleware rule, escalated                                                                                                                     |
| A3 →      | **A14** | `OidcDirectoryProvisioner`, `OidcGroupMapping` (INV-A3-30's escalation gate)                                                                                                                          |
| → A3      | **A2**  | `RoleSource { p -> roleResolver.resolve(p) }` (`ControlPlaneCore.kt:34`)                                                                                                                              |
| → A3      | **A4**  | `mintForActivePrincipalLocked` on every mint route; `isDeactivated(principal, c)` under the lock; `provisionFromOidc` from web/device/MCP login                                                       |
| → A3      | **A6**  | `isDeactivated` at `Query.kt:361,1130`; `resolve` for every decision (A6 INV-A6-7)                                                                                                                    |
| → A3      | **A7**  | `isDeactivated` at `Approvals.kt:800`                                                                                                                                                                 |
| → A3      | **A10** | `isDeactivated` at `grpc/ControlPlaneGrpcService.kt:123`                                                                                                                                              |
| → A3      | **A11** | `advisoryLockPrincipal` + `inTx` for `replaceDirectRoles` (INV-A11-30); the whole store surface for MCP's identity tools                                                                              |

---

## Open questions

| #   | Question                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Q1  | **F22 is a behaviour decision, not just a bug.** Should `PUT /Users` treat an absent `active` as "keep current" (consistent with how it treats the other four fields) or keep RFC 7644's strict-replace default of `true`? Whichever way, a test must pin it before the port.                                                                                                                                                                                                              |
| Q2  | `replaceScimGroupById` has no SYSTEM guard of its own; PUT/PATCH/DELETE rely on a route-level `isSystemGroup` on a separate connection — the pattern INV-A3-33 was hardened away from for POST. Is the id-addressing genuinely sufficient, or should the guard move into the store for all four verbs?                                                                                                                                                                                     |
| Q3  | `deactivatePrincipalTombstone`'s `ON CONFLICT` branch does not normalise `source` to `'SCIM'`, so a conflicting `LOCAL`/`OIDC` row is deactivated but can never match `releaseTombstone`'s narrow shape — permanently squatting the principal string. Reachable only via a concurrent third writer. Real, or provably impossible?                                                                                                                                                          |
| Q4  | Should `RoleResolver.resolve` become transactional (F31)? It would close a torn-read window but changes connection usage on the hottest read path in the system, and A2 already protects its own consumers with a single snapshot.                                                                                                                                                                                                                                                         |
| Q5  | `ScimName` models only `formatted`. Do any target IdPs push `givenName`/`familyName` without it? If so `displayName` silently stays null for every provisioned user.                                                                                                                                                                                                                                                                                                                       |
| Q6  | `ReadinessDiagnosticDbTest` is counted in A3 (see the ⚠️ in the inventory) because no other doc claimed it and `hasActiveAssignee` is A3's symbol; case 2 also covers A1's `/health`. Confirm during the 903-case reconciliation.                                                                                                                                                                                                                                                          |
| Q7  | ~~`OidcGroupMappingTest` is counted in A3 but its subject lives in `auth/`~~ — **ANSWERED, and it is a live defect.** `14-auth.md:1009,1057` counts the same 7 cases in its own 17, so A3 + A14 double-count them and the 903 total is 7 over. Decision needed in the reconciliation pass, not here: recommended resolution is A14 keeps them and A3 becomes **98 cases / 11 suites**. `00-INDEX.md:29,197` ("`auth/` has no tests", Test LOC 0) also needs updating to A14's 17. See F35. |
| Q8  | Should A3 grow an audit surface (F25)? Identity mutation is arguably the most audit-worthy event class in the system and is currently absent from the chain. Design decision, not a port question — but the port is the cheap moment to add it.                                                                                                                                                                                                                                            |
| Q9  | SCIM list endpoints have no pagination and `GET /Groups` is N+1. RFC 7644 pagination is optional but Okta will send `startIndex`/`count` if `ServiceProviderConfig` advertises support. Keep advertising `filter.supported = false` and no pagination, or add both in Go?                                                                                                                                                                                                                  |
| Q10 | An explicit `PM_OIDC_GROUP_MAP` entry may target a `system:*` name the seed never installed, and `OidcDirectoryProvisioner.ensureGroup` then creates it with `source='OIDC'` — a mutable group inside the reserved namespace. Should `ensureGroup` refuse to create (as opposed to reuse) a reserved name, or should the reserved namespace only ever be _matched_, never minted?                                                                                                          |
| Q11 | Six of the seven seeded SYSTEM groups (`system:developer`, the five `system:production-*`) have **no test at all** — every immutability case uses `system:admin`. Should the port's suite parameterise over `source = 'SYSTEM'` rather than the admin string, given the guards are column-based?                                                                                                                                                                                           |
