# MCP access-control server — OAuth-authenticated administration

## Decision

A remote Model Context Protocol (MCP) server is co-hosted inside the control
plane at `https://<public-origin>/mcp` (Streamable HTTP transport) that lets an
MCP client — Claude, an agent, an IDE — manage proxy-monster access control:
list datasources, browse catalog schema, view and edit column tags, view and
edit Cedar policies, and create roles and bind them to users/groups.

The MCP endpoint is a normal additive control-plane surface. It does not get its
own permission model, its own copy of the data, or a generic HTTP-to-REST proxy.
Every tool call runs through the same `RoleResolver.resolve()` + live-Cedar
`authz.authorize(...)` path the web/REST handlers use, inside the same
transactions, against the same validators. The MCP layer adds only transport +
authentication + a typed tool catalog; authority stays where it already is.

Authentication is OAuth 2.1 as required by the MCP spec (the MCP server is an
OAuth _resource server_). The control plane also hosts proxy-monster's OAuth
authorization-server routes because Okta does not provide the
client-registration surface MCP needs. Those routes use CIMD (Client ID Metadata
Documents) for client registration, run authorization-code + PKCE, and reuse the
control plane's signed session + Okta OIDC login. There is no internal HTTP or
service-auth hop. Access tokens are short-lived, opaque, hashed at rest, and
audience-bound to the MCP resource; OAuth scope is a consent ceiling only, never
a proxy-monster permission. The user's actual authority is resolved live from
roles + Cedar on every call.

`mcp` joins `wire | editor | workflow-executor | workflow-viewer` in
`context.channel` (`Channel.MCP` in `Query.kt`), so policies and the audit trail
can see that a change arrived over MCP.

MCP covers the access-control management surface only. Target-database query
execution, approvals, and audit-log tools are later MCP work tracked in
[backlog.md](./backlog.md), not architectural non-goals. proxy-monster has no
table-level tag store and does not add one, so MCP exposes only the column tags
that already exist. The `authDebug` bypass remains available for development.

## Why this shape

Three facts about the system force the design.

1. The authority already exists and is live-evaluated. Roles are resolved
   per-request by `RoleResolver.resolve(principal)` into a set of role _names_;
   authorization is a live Cedar evaluation via
   `authz.authorize(principal, action, resource, context)` (`authz/Authz.kt`).
   Nothing about an admin action is precomputed or cached into a credential. So
   the honest way to authenticate an MCP client is to establish _who the user
   is_, then run the exact same resolution the web console runs. Baking
   permissions into a token or keeping a parallel MCP-only ACL would be a
   second, drifting source of truth — the fail-open shape this project rejects.

2. There is no OAuth authorization-server surface with MCP client registration.
   Okta authenticates users but does not provide the registration surface MCP
   requires. So the control plane adds authorization-server routes: CIMD
   establishes the MCP client's identity, the existing control-plane session and
   OIDC flow authenticate the user, and the co-hosted AS issues the
   resource-bound MCP token.

3. The REST surface is id-keyed; Cedar is name-keyed. Datasources, policies,
   roles, users, groups are addressed by numeric `id` over REST, while Cedar
   entities are addressed by _name_ (`Role::"analyst"`,
   `Table::"<ds>/<cat>/<schema>/<table>"`, `Column::".../<col>"`,
   `Datasource::"<name>"`, `Tag::"pii"`). The MCP tools present stable
   name-shaped identifiers to the model and translate to ids internally, so an
   agent can say "grant `analyst` on `pii` columns of `sales.orders`" without
   holding a fragile integer.

## Boundaries (invariants)

- Cedar is the only authority. Every MCP tool call resolves the caller's current
  roles (`RoleResolver.resolve`) and calls `authz.authorize(...)` with the same
  `AuthzAction`/`AuthzResource` the equivalent REST route uses. A tool with no
  corresponding Cedar action does not ship. The OAuth token is never consulted
  for a permission decision.
- Scope ≤ authority, never scope ⇒ authority. OAuth scopes granted at consent
  are an _upper bound_ on what a token may attempt; they can only _narrow_. A
  token carrying `mcp:policies:write` still gets a live `admin.policies` Cedar
  check and is denied if the user lacks the role. A token _without_ that scope
  is rejected before Cedar runs. Scope subtracts, never adds.
- Development debug parity. When `config.authDebug` is on, MCP supports the same
  local-development authentication/authorization bypass as the other
  control-plane surfaces; developers do not need Okta to exercise MCP locally.
- Audience binding. Access tokens are bound to this resource (`resource` = the
  MCP endpoint's canonical URI, RFC 8707). A token minted for any other audience
  is rejected. proxy-monster never forwards a received token upstream (no
  confused-deputy / token-passthrough).
- Same validators, same transactions, same immutability. Policy edits go through
  the existing Cedar validator (400 on `{errors:[...]}`); SYSTEM policies and
  SYSTEM roles/groups stay immutable (409 `*.system_immutable`); soft-delete vs
  hard-delete semantics match REST exactly. MCP adds no new write path into the
  store.
- Completeness is explicit and fail-closed. The tool catalog is generated from a
  single capability registry keyed by `AuthzAction` (`McpCapabilityRegistry`).
  Startup fails if an in-scope action has no tool. Explicitly deferred
  capabilities — query execution, approvals, audit-log tools — are named
  exclusions from the required set.

## Architecture

```
   MCP client (Claude / agent / IDE)
        │
        │  1. discover resource → co-hosted AS metadata
        │  2. CIMD client identity + auth-code/PKCE
        ▼
┌──────────────────────────────────────────────────────────┐
│ Control plane (one Ktor process + public origin)         │
│                                                          │
│ /.well-known/oauth-authorization-server                  │
│ /oauth/authorize ── shared pm_session/OIDC ───────────────┼────► Okta
│ /oauth/token · /oauth/revoke · /oauth/consents           │
│ client registration: CIMD (no DCR endpoint)              │
│                         │ resource-bound bearer           │
│ /.well-known/oauth-protected-resource[/mcp]  (RFC 9728)  │
│ /mcp  ──► McpAuthorizer (bearer → principal + scope)     │
│            │                                             │
│            ▼                                             │
│         Tool dispatch ──► ManagementService(s)           │
│            │                     │                       │
│            │   RoleResolver.resolve(principal)           │
│            │   authz.authorize(action, resource, ctx)    │  ctx.channel = mcp
│            ▼                     ▼                       │
│         same stores the REST routes use (Postgres)       │
└──────────────────────────────────────────────────────────┘
        │ gRPC (unchanged)          │ SQL (later)
        ▼                           ▼
   wire proxy  ───────────────►  target DBs
```

The MCP endpoint sits _beside_ the REST routes and shares their services; it
never reaches around them. The authorization-server protocol is mounted as
`/oauth/*` inside the same control-plane process and shares its public origin,
DB pool, OIDC client, directory provisioning, and signed `pm_session`. OAuth and
MCP components call shared code directly — no internal endpoint authentication.
Okta remains the user identity provider, not the MCP authorization server.

## Co-hosted OAuth 2.1 authorization server

The MCP spec makes the MCP endpoint an OAuth resource server and requires a
discoverable authorization server. Okta cannot be that authorization server
because it does not expose the required client-registration flow, so the OAuth
routes are co-hosted inside the control plane in the
`com.ridi.oss.proxymonster.controlplane.oauth` package (`OAuthRoutes.kt`). They
use CIMD for MCP client registration, reuse the existing control-plane
login/session, and issue proxy-monster's own short-lived, resource-bound access
and refresh tokens. There is no RFC 7591 DCR endpoint.

### Endpoints and ownership

<!-- prettier-ignore -->
| Owner | Endpoint | Spec | Purpose |
| --- | --- | --- | --- |
| Control plane | `GET /.well-known/oauth-protected-resource` and `.../oauth-protected-resource/mcp` | RFC 9728 | Resource metadata; `resource` = exact `/mcp` URI; `authorization_servers` = the same origin. Path-insertion form for the `/mcp` resource, root as fallback. |
| Control plane | `GET /.well-known/oauth-authorization-server` | RFC 8414 | AS metadata: authorization, token, and revocation endpoints; PKCE `S256`; authorization-code + refresh grants; supported scopes. No DCR `registration_endpoint`. |
| Control plane | `GET /oauth/authorize` | OAuth 2.1 + CIMD | Treat the HTTPS CIMD URL as `client_id`, validate it, require PKCE `S256`, reuse `pm_session` or the existing OIDC login, then render consent. |
| Control plane | `POST /oauth/token` | OAuth 2.1 | Code→token exchange (verifies PKCE) and one-time refresh-token rotation. |
| Control plane | `POST /oauth/revoke` | RFC 7009 | Revoke an access or refresh token. |
| Control plane | `GET /oauth/consents`, `DELETE /oauth/consents/{id}` | Shared-session API/UI | List and revoke remembered client consent; revocation also invalidates that client's refresh-token chain for the principal. |

### CIMD client registration

There is no registration POST. The client's `client_id` is its HTTPS Client ID
Metadata Document URL. The AS fetches that document, validates the redirect URI
and declared metadata against the authorization request, and treats the document
as the client's registration. A cache may reduce fetches, but the URL document
is the authority; cached metadata cannot silently broaden redirect URIs or
scope.

### Discovery handshake

An unauthenticated `POST /mcp` returns `401` with
`WWW-Authenticate: Bearer resource_metadata="https://<resource-origin>/.well-known/oauth-protected-resource/mcp"`
(the header is optional in the spec; the `.well-known` path is the guaranteed
fallback). The client reads resource metadata → discovers the same-origin AS →
uses its CIMD URL as `client_id` → runs auth-code+PKCE → authenticates through
Okta → consents → calls `/mcp` with the bearer.

### Development bypass

With `PM_AUTH_DEBUG=true`, the authorization routes replace the Okta step with a
dev-only principal selection equivalent to the existing `/auth/debug` flow and
may auto-consent. It still issues a normal resource-bound bearer so MCP
discovery, PKCE, token validation, and tool dispatch are exercised locally; the
control plane then applies its existing authDebug authorization bypass.
Development needs no Okta connection and no second non-OAuth MCP transport.

### Tokens

- Opaque, random, hashed at rest via `McpTokenStore` + `sha256Hex()` (SHA-256)
  into the shared `proxy_token` table. MCP access and refresh tokens are rows
  with kinds `MCP_ACCESS` / `MCP_REFRESH` (V30). Access-token TTL clamps into
  the existing `[60s, 24h]` band (default access 600 s via
  `PM_OAUTH_ACCESS_TTL`; refresh default 21_600 s via `PM_OAUTH_REFRESH_TTL`);
  refresh rotates on every use and can be revoked.
- Bound to `{resource, client_id, scope, principal}` (RFC 8707 audience).
  Validation checks resource + expiry + revocation before anything else.
- Roles are NOT in the token. The token names the _principal_ only. Roles are
  re-resolved live per call, so a mid-session role change (grant, revoke, JIT
  expiry) takes effect on the next tool call — no stale authority frozen into a
  credential. This mirrors the web session model.

### Scopes (consent ceilings, not permissions)

Coarse, human-legible scopes that map 1:1 to the existing `AuthzAction`
families, so a consent screen reads honestly and a token can be _narrowed_ below
the user's authority (e.g. a read-only agent):

<!-- prettier-ignore -->
| Scope | Ceiling over | Cedar action still enforced |
| --- | --- | --- |
| `mcp:read` | all in-scope read tools | matching `admin.*` per tool |
| `mcp:datasources:write` | datasource + classification writes | `admin.datasources` |
| `mcp:policies:write` | Cedar policy + role + mask-fn writes | `admin.policies` |
| `mcp:identity:write` | users/groups/members/role-assignments | `admin.identity` |

Presenting a scope never grants the action; lacking a scope denies it up front.
A user who consents to `mcp:read` only can never mutate even if they hold
`admin.policies`.

## Tool catalog

Typed tools, not a generic REST passthrough — each tool has a JSON schema, maps
to one Cedar action, and returns name-shaped identifiers. Grouped by the service
they reuse.

### Datasources & catalog (read)

MCP tools name datasources by stable name and call the same management services
as REST. Every listed tool below is gated by its registry Cedar action (not
REST's session-only `requireApi` on some list routes).

- `list_datasources` (`admin.datasources`) — name, engine, host/port, dbName,
  tags, defaultSchemas, `catalogSyncedAt`, `lastSeenAt`, engineVersion.
- `get_datasource_liveness` (`admin.datasources`) — mirrors
  `GET /api/datasources/live` for one named datasource.
- `browse_catalog` (`admin.datasources`) — schemas → tables → columns.
- `get_table_detail` (`admin.datasources`) — columns with current tags + mask fn
  (REST: `GET /api/datasources/{id}/table-detail`).

### Column tags (read + write)

- `list_column_tags` (`admin.datasources`) — tags currently on a datasource's
  columns (from `column_classification`).
- `set_column_classification` (`admin.datasources`, scope
  `mcp:datasources:write`) — set
  `{schema?, table, column, tags[], maskFnName?}`. Enforces
  `RESERVED_TAG_PREFIX="system:"` exactly as REST does (REST:
  `PUT /api/datasources/{id}/classification`).
- `set_column_classifications` (`admin.datasources`, scope
  `mcp:datasources:write`) — the same write for many columns of one datasource:
  `{datasource, columns[{schema?, table, column, tags[], maskFnName?}]}`, at
  most `MAX_CLASSIFICATION_BATCH` (500) entries. Classifying a table column by
  column costs one round trip, one transaction, and one audit row each; a model
  labelling a freshly introspected schema does that dozens of times, and a
  failure partway leaves the table half-tagged with no single row saying so.
  All-or-nothing: every entry is validated — reserved tag, blank name, missing
  schema with no datasource default, unknown mask function, the same column
  twice — before the first write, so a rejected batch applies nothing. Two
  entries naming one column are an error rather than last-one-wins, because the
  response cannot say which tag set decided masking. The audit row names each
  column, so one row per batch stays as answerable as the single-column tool's.
  No REST equivalent — REST classifies one column per request.
- `clear_column_classification` (`admin.datasources`, scope
  `mcp:datasources:write`) — REST:
  `DELETE /api/datasources/{id}/classification`.

MCP exposes column tags only. There is no table-level tag store; tagging a whole
table is out of scope until/unless the backend grows one (a separate design).
Datasource tags are set only by the proxy's gRPC `Register`/`PushCatalog` —
there is no REST field to edit them (`DatasourceInput` has no `tags`) — so MCP
reports datasource tags but has no `set_datasource_tags` tool.

### Cedar policies (read + write)

All under `admin.policies` (write tools also require `mcp:policies:write`):

- `list_policies` / `get_policy` — id, origin, systemKey, name, `cedarSrc`,
  enabled, updatedBy/At.
- `validate_policy` — returns `{errors:[...]}` without writing.
- `get_policy_schema` — the Cedar schema, so the model writes valid
  entity/action references.
- `create_policy` / `update_policy` — validated on write; SYSTEM rows (negative
  ids) 409 `policy.system_immutable`.
- `enable_policy` / `disable_policy`.
- `delete_policy`.

### Roles, assignments, groups, memberships, mask fns (read + write)

- `list_roles` / `create_role` / `update_role` / `delete_role` →
  `admin.policies` (writes need `mcp:policies:write`); system role → 409
  `role.system_immutable`.
- `list_role_assignments` / `assign_role` / `unassign_role` → `admin.identity`
  (writes need `mcp:identity:write`).
- `list_users` / `create_user` / `update_user` / `deprovision_user` (soft
  delete) → `admin.identity`.
- `list_groups` / `create_group` / `update_group` / `delete_group` (hard),
  `add_group_member` / `remove_group_member`, `set_group_roles` →
  `admin.identity`; SYSTEM group → 409 `group.system_immutable`.
- `list_mask_fns` / `create_mask_fn` / `update_mask_fn` / `delete_mask_fn` →
  `admin.policies` (writes need `mcp:policies:write`).

### Deferred sibling surfaces

Workflow tools (requests, approvals, grants, result release/view), query
execution, and audit-log browsing are separate future MCP designs, tracked in
[backlog.md](./backlog.md). These are sequencing boundaries, not permanent
exclusions.

## Data model

New / changed

- Control-plane-hosted authorization routes reuse the existing login/session and
  issue proxy-monster MCP credentials.
- `proxy_token.kind`: `MCP_ACCESS`, `MCP_REFRESH` (V30) reuse the whole
  TokenStore hashing/TTL/expiry machinery; no new token table.
- `oauth_authorization_code` (short-lived): `code_hash`, CIMD `client_id`,
  `principal`, `resource`, `scope`, `code_challenge`, `expires_at`, plus a
  one-time-use marker. Pruned aggressively.
- `oauth_consent`: remembers a principal's approved
  `{client_id, resource, scope}` so repeat logins skip the screen. Revocable by
  the user/admin; revocation invalidates the client's refresh-token chain.
- Request channel: `Channel.MCP` (`Query.kt`), so `context.channel` reaches
  Cedar. Audit rows for MCP-driven changes carry `channel=mcp` and the acting
  principal.
- `mcp_mutation_idempotency` (V31) — optional client-supplied `idempotencyKey`
  on write tools.

Kept (reused unchanged): `RoleResolver`, `authz.authorize`, every
`ManagementService` and its validators/transactions, `OidcDiscovery` +
`IdTokenValidator`, the Cedar policy/role/mask stores, `column_classification`,
and the shared `proxy_token` table (MCP kinds via `McpTokenStore`).

Not added: no table-classification store, no `set_datasource_tags` write path,
no MCP-only permission table, no generic REST proxy tool, no DCR endpoint.

## Mutation safety

- Atomicity / validation / immutability: inherited from the reused routes.
- Idempotency: write tools accept an optional client-supplied idempotency key; a
  replay with the same key returns the prior result rather than double-applying.
- Concurrency: MCP retains the current REST last-write-wins behavior; a
  cross-surface optimistic-concurrency guard is a separate
  [backlog.md](./backlog.md) item.
- Annotations are untrusted: MCP tool "annotations" (`readOnlyHint`,
  `destructiveHint`) are advisory metadata for the client UI. The server never
  trusts them for a decision — a tool tagged `readOnly` that somehow reaches a
  write path is still gated by Cedar.
- Audit: every mutating tool call lands in the audit log with `channel=mcp`,
  principal, action, resource, and outcome — the same store the web mutations
  use.

## Errors & l10n

Tool errors map to the existing `ApiError` codes and carry both `en` and `ko`
messages (project hard rule). Cedar denials surface as a structured
`{code, message_en, message_ko}` payload, not a bare string, so an MCP client
can render either locale. Validation failures pass through the `{errors:[...]}`
shape from `/validate` verbatim.

## Security & failure modes

- `authDebug` on → local MCP calls use the existing debug principal/bypass with
  no Okta round trip. With debug off, canonical HTTPS MCP/OAuth origins are
  required; the authorization server rejects the public dev session secret and
  incomplete OIDC configuration.
- Token for wrong audience / expired / revoked → `401`, `WWW-Authenticate`
  points back at resource metadata (the client re-auths).
- Scope missing → tool error `mcp.insufficient_scope` _before_ Cedar (structured
  content with `code` + localized `message_en` / `message_ko`).
- Cedar denies → structured deny, audited, no partial write.
- Mid-session role loss → next call re-resolves and denies; no cached authority.
- Client compromise → revoke the remembered consent and access/refresh-token
  chain; refresh rotation caps the blast radius. CIMD metadata is revalidated
  before a new authorization.
- No token passthrough → received bearers are never forwarded upstream.

## Verification

DB-backed PostgreSQL Testcontainers coverage exercises resource discovery,
401/403 challenges, official-SDK tool listing/calls, Origin/authority rejection,
audience/PKCE/one-time codes, consent-tuple binding and revocation, refresh
replay-family revocation, scope ceilings, live Cedar role loss, shared
transactional mutations, idempotent replay, and `mcp` audit attribution.
Authority parity is pinned by fixture: a user with `admin.policies` but not
`admin.identity` can `create_policy` but is denied `assign_role`, matching REST;
a `mcp:read`-only token is denied every write regardless of role.

## Worked example

_Agent:_ "Give `analyst` read on the `pii`-tagged columns of `sales.orders` in
the `warehouse` datasource."

1. Client already holds an `mcp:policies:write` token (audience = `/mcp`).
2. `browse_catalog(datasource="warehouse")` → confirms `sales.orders` and its
   columns; `list_column_tags` shows which carry `pii`.
3. `get_policy_schema` → the Cedar shape; agent drafts a
   `permit(principal == Role::"analyst", action == Action::"sql.select", resource) when { resource in Tag::"pii" ... }`
   fragment.
4. `validate_policy(src=…)` → `{errors:[]}`.
5. `create_policy(name=…, src=…)` → the server resolves the caller's roles live,
   runs `authz.authorize(principal, admin.policies, …, ctx{channel=mcp})`,
   validates, writes inside the normal transaction, audits with `channel=mcp`,
   and returns the new policy id + name.

At no point did the token carry the permission; it carried the _identity_ and a
_consent ceiling_, and Cedar decided.

## Standards references

- MCP Authorization (spec 2025-11-25) — MCP server as OAuth 2.1 resource server.
- RFC 9728 (protected-resource metadata), RFC 8414 (AS metadata), RFC 8707
  (resource indicators / audience), RFC 7636 (PKCE), RFC 7009 (revocation), RFC
  8628 (device-auth — the existing `pmon` precedent, not used by MCP).
- CIMD (Client ID Metadata Documents) — the client-registration mechanism.
