# A11 — MCP Server, OAuth Authorization Server, Management Services

Files: `mcp/McpServer.kt` (766) · `management/ManagementServices.kt` (732) ·
`oauth/OAuthRoutes.kt` (411) · `oauth/Cimd.kt` (191) ·
`management/McpCapabilityRegistry.kt` (136). Total 2,236 LOC. Fully read.
Tables: `mcp_mutation_idempotency` (+ `oauth_*` owned by the `auth/` module).

FULL depth. ⚠️ **Lowest test density in the control-plane: 18 cases for 2,236
LOC (124 LOC/case), against A6's 11 LOC/case.** `ManagementServices.kt` — the
largest file here — has **no dedicated test file** at all. See §9.

## Purpose

Three co-hosted surfaces plus the service layer under them:

1. **MCP server** (`/mcp`) — 38 admin tools over Streamable HTTP,
   bearer-authenticated, Cedar-gated.
2. **OAuth 2.1 authorization server** (`/oauth/*`, `/.well-known/oauth-*`) —
   co-hosted in the same process, origin, DB pool, OIDC login, and signed
   session as the control plane. **There is no service-to-service auth hop.**
3. **Management services** — the transport-neutral layer both REST (A2/A3/A9)
   and MCP call, and the only place the SYSTEM-immutability guards live.

---

## 1. `McpCapabilityRegistry` — the tool/action/scope catalog

`enum CapabilityClassification { READ, WRITE }`
`data class McpToolAnnotations(readOnlyHint, destructiveHint)`
`data class McpCapability(toolName, action, resource = System, requiredScope, classification, annotations)`

**38 tools**, four scopes: `mcp:read`, `mcp:datasources:write`,
`mcp:policies:write`, `mcp:identity:write`. Every READ tool takes `mcp:read`;
each WRITE tool takes its domain's write scope. `destructiveHint = true` on the
10 delete/deprovision/remove tools.

Three Cedar actions are in scope (`ADMIN_DATASOURCES`, `ADMIN_POLICIES`,
`ADMIN_IDENTITY`); the other **21** are explicitly `excludedActions` — task
lifecycle, token, audit, result-read, and every `sql.*` action are _runtime_
authorization, not management tools.

### `verify()` — six startup assertions

```
inScopeActions ∩ excludedActions == ∅
inScopeActions ∪ excludedActions == AuthzAction.entries    // every action explicitly classified
every in-scope action has ≥1 tool
entries.size == byName.size                                 // unique tool names
every tool declares a non-blank scope
byName.keys == approvedToolNames                            // catalog matches the frozen approved set
```

Called from `installMcp` — a mismatch **aborts startup**.

🔒 **INV-A11-1 — every `AuthzAction` must be explicitly in-scope or explicitly
deferred.** Adding a new action to A2's enum fails `verify()` until someone
classifies it. This is the mechanism that stops a new Cedar action from silently
becoming un-exposed _or_ accidentally exposed. **Port it as a real startup
check, not a comment.**

🔒 **INV-A11-2 — `approvedToolNames` is a hardcoded duplicate of the catalog,
deliberately.** The check `byName.keys == approvedToolNames` means adding a tool
to `entries` alone fails boot: the tool surface is a reviewed artifact, and the
duplication is the review gate. Do not "DRY" it away.

⚠️ **Cross-area inconsistency worth noting (strengthens F5):** MCP's
`list_roles` requires `ADMIN_POLICIES`, but A9's REST `GET /api/roles` is gated
only `requireApi`. **The same data, two different authority levels**, depending
on transport.

---

## 2. The `/mcp` request pipeline

`installMcp` installs an `ApplicationCallPipeline.Plugins` interceptor scoped to
`path == "/mcp"`. Four ordered gates:

| #   | Gate                                                                                                                                                                                                     | Failure                                                                  |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| 1   | **Host check** — `resolveForwardedAuthority(directHost = call.request.host(), peer, X-Forwarded-Host, trustedProxies)` must equal the configured resource host, case-insensitive, both sides unbracketed | 403 `mcp.invalid_host`                                                   |
| 2   | **Origin check** — when `Origin` is present it must be `sameOrigin` with the resource origin                                                                                                             | 403 `mcp.invalid_origin`                                                 |
| 3   | **Bearer** — `Authorization: Bearer <t>` → `mcpTokenStore.resolveAccess(t, config.mcpResource)`; identity null **or** principal deactivated                                                              | 401 + `WWW-Authenticate: Bearer resource_metadata="…", scope="mcp:read"` |
| 4   | Store `McpRequestContext(principal, clientId, scopes, requesterIp)` in call attributes                                                                                                                   | —                                                                        |

🔒 **INV-A11-3 — the host check is the DNS-rebinding defence, and it reads
Ktor's protocol-neutral `host()`, not the literal `Host` header.** Ktor
normalizes HTTP/1.1 `Host` and HTTP/2 `:authority` through `host()`; reading the
raw header would reject **every HTTP/2 request**. Behind a reverse proxy that
authority is the _proxy's_, so a trusted edge's `X-Forwarded-Host` supersedes it
— honored only from a peer in `PM_TRUSTED_PROXIES` (A12 INV-A12-1), so a direct
caller cannot assert past it.

🔒 **INV-A11-4 — the SDK's own DNS-rebinding guard is deliberately DISABLED**
(`enableDnsRebindingProtection = false`) because it reads the HTTP/1.1 `Host`
header literally and rejects HTTP/2 `:authority` as missing. **The interceptor
above replaces it.** A Go port that adopts a Go SDK's built-in guard must verify
the same HTTP/2 behaviour, or re-disable and keep this interceptor.
`McpServerDbTest` cases 2–3 pin the two shapes (cleartext-forwarded Host with no
port; IPv6 literal).

🔒 **INV-A11-5 — Origin is validated BEFORE authentication.** Gate 2 precedes
gate 3, so a cross-origin browser request is rejected without its token ever
being resolved.

**INV-A11-6 — `sameOrigin` is strict**: scheme + host + `effectivePort()`
(defaulting 443/80) must match, **and** the origin must carry no `userInfo`, no
path, no query, no fragment. A11's note in A12 INV-A12-8 applies: the _port_ is
enforced here even though the host check ignores it.

**Java/URI trap:** Java exposes an IPv6 URI host **bracketed** (`[::1]`) while a
request authority resolves to the bare address, so both sides are
`removeSurrounding("[", "]")`-ed before comparison. Go's `net/url` behaves
differently (`u.Hostname()` strips brackets); the port must normalize
deliberately.

Two discovery routes, unauthenticated:
`GET /.well-known/oauth-protected-resource` and
`…/oauth-protected-resource/mcp`, both returning
`ProtectedResourceMetadata{resource, authorization_servers=[mcpIssuer], scopes_supported, bearer_methods_supported=["header"]}`.

`mcpJson = Json { encodeDefaults = true; explicitNulls = false }` — a **second**
JSON config alongside A1's `appJson`, with the same two flags (A1 INV-A1-4).

---

## 3. `McpAuthorizer` — two-stage gate

```kotlin
fun authorize(context, capability): Set<String> {
    if (capability.requiredScope !in context.scopes) throw McpAuthorizationException(mcp.insufficient_scope, ∅)
    val roles = core.roleResolver.resolve(context.principal)
    if (!config.authDebug) {
        authorizeAs(principal, roles, capability.action, capability.resource,
                    AuthzContext(channel = Channel.MCP.contextValue, requesterIp = context.requesterIp))
          is Deny -> throw McpAuthorizationException(common.forbidden{detail}, roles)
    }
    return roles
}
```

🔒 **INV-A11-7 — scope is necessary but never sufficient.** An OAuth scope is
what the _client_ was granted; Cedar decides what the _principal_ may do. A
broad consent scope cannot widen Cedar authority. `McpServerDbTest` case 6 is
named for this ("_Cedar authority remains narrower than a broad consent
scope_"), and case 4 asserts "_scope cannot grant a write_".

🔒 **INV-A11-8 — roles are resolved LIVE per tool call**, never carried on the
token. A role revoked after the access token was minted takes effect on the next
call.

**INV-A11-9** — the scope failure returns `roles = ∅` in the exception, so the
audit row for an insufficient-scope denial records no roles (they were never
resolved). Deliberate: the exception carries the roles precisely so the audit
row can be honest about what was known.

⚠️ Uses `authorizeAs` directly with a hand-built `AuthzContext`, **not**
`authorizeWithContext` — so **no `context.tags` are derived** for MCP calls (A2
INV-A2-14 needs a Datasource in scope; every MCP capability's resource is
`System`). A tag-conditioned policy therefore never fires on the MCP channel.
Consistent with A2's rule, but worth stating: **MCP is a tag-free channel.** §11
Q1.

---

## 4. `McpMutationExecutor` — idempotency + atomic audit

`execute(context, capability, arguments, datasource = "control-plane", detail, mutation: (Connection) -> JsonObject)`

Order:

1. `authorizer.authorize(...)` — on failure, audit `DENY` then throw
   `ManagementException`.
2. `validateArguments(...)` — on failure, audit `ERROR`/`mcp.invalid_request`
   then throw.
3. `key = arguments["idempotencyKey"]`;
   `requestHash = sha256Hex(canonicalJson(arguments − idempotencyKey))`.
4. Manual transaction (`autoCommit = false`):
   - If `key != null`: take
     `pg_advisory_xact_lock(hashtextextended(<principal|clientId|toolName|key>, 0))`,
     then `SELECT request_hash, response_json … FOR UPDATE`.
     - Prior row with a **different** `request_hash` ⇒
       `IdempotencyConflictException`.
     - Prior row matching ⇒ audit `ALLOW`/`IDEMPOTENT_REPLAY`, commit, **return
       the stored response**.
   - Run `mutation(connection)`.
   - `auditStore.insert(connection, … ALLOW/ALLOW)`.
   - If `key != null`, INSERT the idempotency row (`response_json` as
     `?::jsonb`).
   - Commit.
5. On success **and not a replay**, if the tool is in `POLICY_MUTATION_TOOLS`,
   call `cedarPolicyStore.markCommittedMutation()`.

🔒 **INV-A11-10 — the mutation and its audit row commit in ONE transaction.** A
failed audit insert rolls the mutation back. `McpServerDbTest` case 8 is exactly
this ("_a failed audit insert rolls back its management mutation_"). Same
principle as A7 INV-A7-28 and A2 INV-A2-22.

🔒 **INV-A11-11 — idempotency is keyed on (principal, clientId, toolName, key)
AND guarded by a request hash.** Replaying a key with _different_ arguments is a
**conflict**, not a silent replay of the old response. The advisory transaction
lock serializes concurrent first-attempts on the same key, so two racing calls
cannot both run the mutation.

🔒 **INV-A11-12 — `markCommittedMutation()` fires only on a real (non-replay)
policy mutation, and only after commit.** Both conditions matter: bumping on a
replay would needlessly invalidate every Cedar cache (A2 INV-A2-19's rule,
applied here).

⚠️ `canonicalJson` is a **hand-rolled deterministic serializer**: objects sorted
by key, keys re-encoded via `mcpJson.encodeToString(JsonPrimitive(key))`, arrays
in order, primitives via `toString()`. This is a **hash input**, so it is a
compatibility contract for any stored idempotency row. A Go port must reproduce
it byte-for-byte or every pre-existing `request_hash` becomes a spurious
conflict. §11 Q2.

⚠️ The lock key joins with the **literal 6-character string `\u0000`**
(`"\\u0000"` in Kotlin source), not a NUL byte. Almost certainly unintended, but
it is part of the hash input for the advisory lock — harmless in isolation, but
a Go port "fixing" it to `\x00` changes which calls serialize against each
other. Replicate as-is. §11 Q3.

Failure audit outcomes: `IDEMPOTENCY_CONFLICT`, `CEDAR_VALIDATION`,
`mcp.invalid_request`, `INTERNAL_ERROR`, plus the `ManagementException`'s own
code. `auditFailure` is wrapped in `runCatching` — an audit failure on an
already-failing path must not mask the original error.

`mcpAuditRecord(...)` sets `statement = "[MCP <toolName>]"`, `channel = "mcp"`,
`authzAction = capability.action.cedarId`,
`authzResource = "System::\"system\""`, `clientAddr = context.requesterIp`,
`roles = roles.sorted()`.

---

## 5. Tool dispatch

`createMcpServer(...)` builds a fresh
`Server("proxy-monster-access-control", "1.0.0")` **per request** (the stateless
Streamable HTTP model) with
`ServerCapabilities(tools = Tools(listChanged = false))`, then registers all 38
tools.

Per tool: `name`, `description = toolDescription(toolName, locale)` (from
`mcp_tools` ResourceBundle), `inputSchema = schemaFor(toolName)`, and
`ToolAnnotations(readOnlyHint, destructiveHint, idempotentHint = classification == READ, openWorldHint = toolName == "get_table_detail")`.

**INV-A11-13 — `openWorldHint` is true for exactly one tool**,
`get_table_detail`, because it reaches the live target database through the
proxy rather than reading the CP store.

Handler:

- READ ⇒ `authorizeRead(...)` (authorize, auditing a DENY on failure) →
  `validateArguments` → `executeRead(...)`
- WRITE ⇒ `executeWrite(...)`, which wraps everything in
  `mutations.execute(...)`

🔒 **INV-A11-14 — READ and WRITE have different audit shapes.** A successful
READ writes **no** audit row (only a denial does, via `authorizeRead`). A WRITE
always writes one — ALLOW, replay, or failure. Deliberate: `list_datasources` on
every tool refresh would flood the trail.

Result shape:
`CallToolResult(content = [TextContent(structured.toString())], structuredContent = structured)`
where `structured(value) = {"result": <encoded value>}`.

Error mapping in the handler's catch chain:

| Exception                            | Result                                                               |
| ------------------------------------ | -------------------------------------------------------------------- |
| `CedarValidationManagementException` | `isError = true`, body `{errors: [...]}` — the validator's raw array |
| `McpAuthorizationException`          | `localizedError(call, error, metadataUri)`                           |
| `ManagementException`                | `localizedError(call, error, metadataUri)`                           |
| `McpInputException`                  | `localizedError(call, mcp.invalid_request)`                          |
| any `Exception`                      | `localizedError(call, mcp.internal_error)`                           |

### `localizedError(call, error, metadataUri?)`

Sets HTTP **403** for `mcp.insufficient_scope` and `common.forbidden`; for
insufficient scope also emits
`WWW-Authenticate: Bearer error="insufficient_scope", scope="<s>", resource_metadata="<uri>"`.
Body carries `code`, `params`, **`message_en` AND `message_ko`** — both locales,
from the `mcp_errors` ResourceBundle, with `{param}` interpolation.

🔒 **INV-A11-15 — MCP errors ship BOTH locales inline, unlike REST.** REST
returns a bare `ApiError` code for `web/` to look up (A1 INV-A1-13); an MCP
client has no message catalog, so the server resolves both. `docs/l10n.md`'s
rule is satisfied differently on each transport. A Go port needs the two
`.properties` bundles (`mcp_errors_{en,ko}`, `mcp_tools_{en,ko}`,
`authorization_messages_{en,ko}`) carried over — **6 resource bundles**,
currently JVM `ResourceBundle`. `⟦LIB⟧` i18n message loading.

### `schemaFor(tool)` and `validateArguments`

`schemaFor` builds the JSON-Schema `properties`/`required` per tool by hand in a
`when`. Every WRITE tool gets an `idempotencyKey` string property (added twice
for most — once in the `when`, once by the trailing
`if (classification == WRITE)`; harmless, `putJsonObject` overwrites).

`validateArguments`: **unknown keys are rejected** (`arguments.keys - allowed`
non-empty ⇒ `McpInputException`), and `idempotencyKey` must be a non-blank
string ≤ 128 chars.

🔒 **INV-A11-16 — strict unknown-key rejection.** The tool surface is closed: a
client cannot smuggle an extra argument past the schema. Note this is enforced
**against `schemaFor`'s own property list**, so `schemaFor` is the authority for
both advertising and validating — they cannot drift.

### JSON accessor helpers

`requiredString` (blank ⇒ `common.field_required`), `string` (JsonNull → null,
wrong type ⇒ `McpInputException`), `boolean`, `stringSet` (missing ⇒
`common.field_required`), `has`.

**INV-A11-17 — `has(name)` vs `string(name)` distinguishes "absent" from
"explicitly null".** Update tools use
`if (args.has("x")) args.string("x") else current.x`, so a client can **clear**
a field by passing `null` and **preserve** it by omitting the key. A Go port
using a plain struct with pointer fields gets this for free; one using
`map[string]any` must keep the distinction.

`mutationDetail(tool, args)` builds the audit `detail` from a fixed key list
(`datasource, name, principal, groupName, roleName, table, column`) — never the
whole argument object, so a `cedarSrc` or `email` never lands in the audit trail
via this path.

`safeDatasource(capability, args)` returns the real datasource name **only** for
the two classification tools; everything else audits as `"control-plane"`.

---

## 6. OAuth 2.1 authorization server

`MCPA_SCOPES = {mcp:read, mcp:datasources:write, mcp:policies:write, mcp:identity:write}`

`installMcpOAuthProtocolGuard()` — intercepts `/oauth/*` to set
`Cache-Control: no-store` and `Pragma: no-cache`.

### Routes — 7

| Method | Path                                              | Notes                                                                         |
| ------ | ------------------------------------------------- | ----------------------------------------------------------------------------- |
| GET    | `/.well-known/oauth-authorization-server`         | `AuthorizationServerMetadata`, `client_id_metadata_document_supported = true` |
| GET    | `/oauth/authorize`                                | see below                                                                     |
| GET    | `/oauth/resume`                                   | post-OIDC-login continuation                                                  |
| POST   | `/oauth/consent`                                  | CSRF-checked form post                                                        |
| POST   | `/oauth/token`                                    | `authorization_code` + `refresh_token` grants                                 |
| POST   | `/oauth/revoke`                                   | RFC 7009; **always 200**, even for an unknown token                           |
| GET    | `/oauth/consents` · DELETE `/oauth/consents/{id}` | user-facing consent management                                                |

### `GET /oauth/authorize` — validation

All of: `response_type == "code"`, non-blank `client_id`/`redirect_uri`/`state`,
**`resource == config.mcpResource` exactly**, `code_challenge_method == "S256"`,
`isValidPkceChallenge(challenge)`, non-empty requested scopes, **all** requested
scopes ∈ `MCPA_SCOPES`. Any failure ⇒ 400 `invalid_request`.

Then `cimdResolver.resolve(clientId)` ⇒ 400 `invalid_client` on failure, and
`metadata.validateRequest(redirectUri, requestedScopes)` ⇒ 400 `invalid_client`.

🔒 **INV-A11-18 — `resource` must equal `config.mcpResource` exactly, at
authorize AND at both token grants.** This is the audience binding: an access
token minted for one resource cannot be exchanged against another.

**Debug branch** (`authDebug`): principal from `?principal=`, else the web
session, else `"debug-user"`. Then mint a **new** web session.

⚠️ 🔒 **INV-A11-19 — the debug mint inherits `debugRequesterIp` only when the
principal is unchanged.** `mintWeb` is newest-wins, so this _ends_ the console's
current session. Carrying the simulated address forward keeps the console's
authorization context stable; **not** carrying it would make every later console
decision silently fall back to the observed peer — an authorization change as a
side effect of an unrelated login. And it must **not** be carried when
`?principal=` switches identity: one identity's simulated network must not
follow another's. `OAuthRoutesDbTest` case 10 pins it.

Then auto-consent (when `mcpDebugAutoConsent` or `?auto_consent=true`) ⇒
find-or-remember consent and issue a code; else render the consent page.

**Production branch**: store the pending cookie; if no session ⇒ redirect to
`/auth/oidc/login?return_to=/oauth/resume`; else `continueAuthorization`.

🔒 **INV-A11-20 — one origin, one signed session, no service credential.**
Production OAuth reuses the control-plane's own OIDC login. There is no service
call and no service credential between the AS and the resource server — they are
the same process. `OAuthRoutesDbTest` cases 6–8 pin this.

### `GET /oauth/resume`

Upstream `error` handling: only `access_denied` and `server_error` are relayed,
and **only after re-validating the client**, then the pending cookie is cleared
and the error is redirected to the client. Otherwise: pending must exist, a
principal must exist, and **`pending.principal`, if already set, must match** —
else 400. On success the pending cookie is rewritten with a **fresh CSRF
token**.

🔒 **INV-A11-21 — CSRF is rotated at every authentication step**, and the client
is re-validated before any redirect back to it, so a stale/hostile pending
cookie cannot be used to bounce an error to an unregistered `redirect_uri`.

### `POST /oauth/consent`

Requires: pending cookie, a principal on it,
`call.userSession()?.principal == pending.principal`, **and
`form["csrf"] == pending.csrf`**. `decision != "approve"` ⇒ clear cookie,
redirect `error=access_denied`.

### `POST /oauth/token`

`authorization_code`: requires `code`, `client_id`, `redirect_uri`, `resource`,
`code_verifier`; resource mismatch ⇒ null ⇒ `invalid_grant`. `refresh_token`:
requires `refresh_token`, `client_id`, `resource`. Unknown grant ⇒
`unsupported_grant_type`. Null pair ⇒ `invalid_grant`.

**INV-A11-22 — every OAuth error is a 400 with an `OAuthError` body**, including
`invalid_grant`. Not 401. Uniform shape.

### Consent management

`GET /oauth/consents` returns the list plus a CSRF token;
`DELETE /oauth/consents/{id}` requires `X-PM-CSRF` compared with
**`MessageDigest.isEqual`** (constant-time).

🔒 **INV-A11-23 — the consent CSRF token is a keyed HMAC, not random state.**
`HMAC-SHA256(sessionSecret, "mcp-oauth-consent\u0000<principal>")`, base64url
unpadded. Stateless and per-principal, so it needs no server-side storage but
cannot be replayed across principals. Note this one **does** use a real NUL
separator (contrast §4's `\u0000` literal).

### `renderConsent` — the only server-rendered HTML

Sets
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Body
discloses client name, client id, **the redirect destination**, the scopes, and
— for a loopback redirect — a warning. Locale from `Accept-Language` (`ko`
prefix ⇒ Korean). `escapeHtml` covers `& < > " '`.

🔒 **INV-A11-24 — the consent page discloses the redirect destination and warns
on loopback.** A local listener means any process on the user's machine could
receive the code. `OAuthRoutesDbTest` case 5 pins both.

---

## 7. `Cimd.kt` — Client ID Metadata Documents (SSRF-hardened)

`CimdClientMetadata{client_id, client_name, redirect_uris, grant_types = ["authorization_code"], response_types = ["code"], token_endpoint_auth_method = "none", scope = ""}`

### `HttpCimdResolver.resolve(clientId)` — eight defences, in order

1. `client_id` must be **HTTPS**, have a host, a non-blank path, no `userInfo`,
   no fragment, and **no `.`/`..` path segments**.
2. `InetAddress.getAllByName(host)` must be non-empty.
3. When `productionChecks`: **no address may be special-use** — loopback,
   any-local, link-local, site-local, multicast, or in a 30-entry CIDR blocklist
   (RFC 1918/6598/5737/6890, IPv6 ULA/link-local/ documentation/6to4/NAT64…).
4. 🔒 **The HTTP client is DNS-pinned to the addresses that passed the check.**
5. `followRedirects = false` (both at the Ktor and OkHttp layers, plus
   `followSslRedirects(false)`).
6. Timeouts: connect 2s, request 5s, socket 5s.
7. Content-Type must be `application/json` or `application/*+json`.
8. Size cap **5 KiB**, enforced on `Content-Length` _and_ by reading `MAX+1`
   bytes and re-checking.

Then: `metadata.client_id == clientId`, non-blank `client_name`, non-empty
`redirect_uris` with no blanks, and every redirect URI passes
`validatedRedirectUri`.

🔒 **INV-A11-25 — DNS pinning closes the check/use gap.** _"Leaving DNS
resolution to the HTTP engine would create a check/use gap in which a rebinding
answer could reach localhost."_ Steps 3 and 4 are one defence, not two. **A Go
port must dial the vetted IPs** — e.g. a custom `DialContext` that ignores the
hostname's fresh resolution — not just pre-check and then `http.Get(url)`.

🔒 **INV-A11-26 — redirects are disabled at both layers.** A followed redirect
would re-resolve and escape the pin.

**INV-A11-27 — the size cap is enforced twice** because `Content-Length` is
advisory; the read-`MAX+1` check is the real bound.

`productionChecks = !config.authDebug`, so a dev box can point at localhost
metadata.

### `validateRequest(redirectUri, requestedScopes)`

`redirect_uris` must contain a `loopbackAwareRedirectUriMatch`;
`validatedRedirectUri(redirectUri)`; `"code" ∈ response_types`;
`"authorization_code" ∈ grant_types`; `token_endpoint_auth_method == "none"`
(**public clients only**); and if the metadata declares scopes, every requested
scope must be among them.

### `validatedRedirectUri(value)`

Absolute, has a host, no `userInfo`, no fragment, and **HTTPS unless it targets
loopback**. `isLoopbackRedirectHost`: `localhost`, `::1`, `[::1]`, or a dotted
quad whose first octet is `127`.

### 🔒 `loopbackAwareRedirectUriMatch(requested, declared)` — RFC 8252 §7.3

Exact match, **or**: `declared` is `http`, has a host, has **no port**, and is
loopback — then match on scheme + host + path + query, **ignoring the port**.

The rationale is worth carrying verbatim: a native/CLI client binds its loopback
listener to a port chosen at launch, so a CIMD document supporting this can only
declare a **portless** loopback redirect. Claude Code's own published metadata
declares exactly `http://localhost/callback` / `http://127.0.0.1/callback`, and
a plain string equality check **rejects every real `claude mcp login`**. A
declared loopback URI that _does_ specify a port stays exact-match (nothing
forces a client to omit it, and relaxing a deliberately fixed port would let a
request substitute an arbitrary one). Every HTTPS redirect is always
exact-match.

`Cidr` is a **third** hand-rolled CIDR implementation in this codebase
(alongside A12's `cidrContains` and… itself). Byte-compare + boundary mask,
identical logic. **REPRODUCE all three (F18).** Duplication is explicitly not
grounds for OMIT, "identical logic" is a claim about today that a single shared
implementation would silently freeze, and collapsing three gates onto one code
path is a refactor — which during a port is a fix during a port. Unify after
cutover, as its own reviewable change.

---

## 8. `ManagementServices.kt` — the transport-neutral layer

`ManagementException(val error: ApiError)` — transport-neutral, carries only a
stable code + params.
`CedarValidationManagementException(val errors: List<String>)` — preserves the
validator's raw array. Shared private helpers: `required(field, value)` (blank ⇒
`common.field_required`), `notFound(resource)`, `unique(resource, name) { }`
(SQLSTATE **23505** ⇒ `common.already_exists`).

### `DatasourceManagementService`

`listDatasources`, `getDatasource`, `getDatasourceLiveness` (joins
`eventsHub.attached()`), `browseCatalog`, `getTableDetail` (suspend;
`TableDetailExecException` ⇒ `datasource.table_introspection_failed`),
`listColumnTags`, `setColumnClassification` (×3 overloads),
`clearColumnClassification` (×3).

🔒 **INV-A11-28 — a reserved-prefix tag cannot be set through the management
API.** `tags.firstOrNull { it.startsWith(DatasourceStore.RESERVED_TAG_PREFIX) }`
⇒ `datasource.reserved_tag{tag}`. This is the **write-side** half of A2 INV-A2-7
(which enforces the same rule at Cedar marshalling). Both halves exist
deliberately — `PresetPolicyDbTest` case 9 proves the marshalling half still
holds even for a tag that somehow got stored.

**INV-A11-29** — a null `schema` requires a resolvable default schema, else
`datasource.schema_required`.

### `PolicyManagementService`

~28 methods over Cedar policies, roles, assignments, and mask functions — each
in name-keyed, id-keyed, and connection-taking variants (the MCP surface is
name-keyed, REST is id-keyed).

🔒 **INV-A11-30 — F6 RESOLVED: `isSystemRole` IS enforced.** Checked in
`updateRole(id)`:362, `updateRole(currentName)`:370, `deleteRole(id)`:382,
`deleteRole(name, c)`:389 — all throwing `role.system_immutable`. A9's
hypothesis was right: the guard lives here, not in `Policies.kt`.

🔒 **INV-A11-31 — every policy mutation calls `markCommittedMutation()` AFTER
the transaction commits**, and `deletePolicy` calls it **only when a row was
actually deleted**. Matches A2 INV-A2-19.

`mapPolicyErrors` translates: `InvalidCedarPolicyException` ⇒
`CedarValidationManagementException`, `ReservedPolicyNameException` ⇒
`policy.reserved_name`, `SystemPolicyImmutableException` ⇒
`policy.system_immutable`, SQLSTATE 23505 ⇒
`common.already_exists{resource: policy}`.

#### 🔒 `replaceDirectRoles(principal, roleNames, c)` — four invariants in one method

```kotlin
required("principal", principal)
c.advisoryLockPrincipal(principal)
val roles = roleNames.map { store.getRoleByName(it, c) ?: notFound("role '$it'") }
store.listAssignments(principal, null, c).forEach { store.deleteAssignment(it.id, c) }
return roles.map { store.createAssignment(RoleAssignmentInput(principal, it.id), c) }
```

1. **Resolve-all-before-delete-any.** An unknown name leaves the existing set
   untouched rather than stripping a principal's roles and then failing.
2. **Unknown names are rejected, never created.** A typo that silently became a
   real role would resolve fine and then deny every query, since no policy
   references it.
3. **The error names the offending role** (`"role '<name>'"`), because the
   caller asked for a _set_ and the whole request fails on any one member.
4. 🔒 **The advisory lock is mandatory — `inTx` alone is not enough.** At READ
   COMMITTED a list-delete-insert is a read-modify-write: two concurrent
   replacements each delete only the ids _they_ listed and then insert their
   own, committing the **UNION** rather than either caller's set. Same
   per-principal lock deprovisioning and SCIM take. _"The claim is the whole
   intended set"_ is only true if the sequence cannot interleave.

Only direct `principal_role` rows are touched — group-derived roles and active
JIT grants are separate sources and are deliberately left alone.

### `IdentityManagementService`

Users, groups, members, group→roles. Every mutating path threads `tokenStore`,
`accessStore`, and `daemonSessionStore` into the store call, so a rename or
deactivate atomically revokes credentials (A3).

🔒 **INV-A11-32 — three separate SYSTEM-immutability guards, each with a
different mechanism:**

- `rejectSystem(group, c)` — `store.isSystemGroup(group.id, c)` ⇒
  `group.system_immutable`. Used on update/delete group and add/remove member.
- `lockMutableGroup(id, c)` —
  `SELECT source FROM app_group WHERE id = ? **FOR UPDATE**` ⇒ throws when
  `SYSTEM`. Used on `addGroupRole`/`removeGroupRole`.
- `setGroupRoles` — inlines its own `SELECT id, source … FOR UPDATE` on the
  **name**.

The `FOR UPDATE` variants exist so a concurrent transaction cannot flip `source`
between check and mutate. `rejectSystem` has no lock — an asymmetry worth
flagging (§11 Q4).

`setGroupRoles` is a **diff, not a replace**: resolve every role name (any
unknown ⇒ `notFound`), then remove `current - requested` and add
`requested - current`. Returns the re-read list.

---

## 9. Test inventory — 2 files, 1,120 LOC, **18 cases**

### `McpServerDbTest.kt` — 587 LOC, 8 cases · DB + route

1. resource metadata and bearer failures are standards shaped
2. an https resource admits a cleartext-forwarded request whose Host carries no
   port (INV-A11-3/4)
3. an IPv6 literal resource host matches a forwarded authority (INV-A11-3)
4. 🔒 tool catalog is complete, localized, and **scope cannot grant a write**
   (INV-A11-1/2/7)
5. 🔒 mutations are atomic, idempotent, audited, and roles are resolved live
   (INV-A11-8/10/11)
6. 🔒 Cedar authority remains narrower than a broad consent scope (INV-A11-7)
7. representative tool families dispatch successfully with structured liveness
   and audit
8. 🔒 a failed audit insert rolls back its management mutation (INV-A11-10)

Eight cases for 38 tools. Case 7 covers "representative tool families" — i.e.
**most of the 38 tools have no individual test**.

### `oauth/OAuthRoutesDbTest.kt` — 533 LOC, 10 cases · DB + route

1. debug authorization code, PKCE, refresh, and discovery work end to end
2. the control-plane application mounts both OAuth AS and MCP resource discovery
   on one origin (INV-A11-20)
3. 🔒 CIMD validation accepts omitted scope but rejects unsafe client
   identifiers (INV-A11-25)
4. 🔒 CIMD validation matches a portless loopback `redirect_uri` against any
   request port, RFC 8252 §7
5. 🔒 consent discloses redirect destination and warns for loopback clients
   (INV-A11-24)
6. production OAuth reuses the existing control-plane user session without
   another auth boundary
7. production OAuth without a session enters the existing control-plane OIDC
   login
8. production OAuth resumes through the shared session and issues a code after
   consent (INV-A11-21)
9. production configuration rejects the public dev session secret and insecure
   origins (A1 V6/V10)
10. 🔒 debug authorize carries the simulated source address across its session
    remint (INV-A11-19)

### Owned elsewhere

`McpOAuthStoreDbTest.kt` (216 LOC, **6 cases**) tests `OAuthAuthorizationStore`,
which lives in the **`auth/` module** — counted in `14-auth.md`. Its cases are
the token-family security core (one-time PKCE-bound codes, audience binding,
refresh rotation with family revocation on replay, RFC 7009 scope of revocation,
consent-mismatch rejection, expired-code pruning) and matter a great deal; they
are simply not this area's. `ScimTlsGateTest` (8 cases) → A3.
`CedarPolicyRoutesTest` → A2. `UserAdminDeprovisionDbTest` → A3.

### ⚠️ The coverage gap

| Surface                          | LOC | Direct tests       |
| -------------------------------- | --- | ------------------ |
| `ManagementServices.kt`          | 732 | **none**           |
| `McpCapabilityRegistry.verify()` | 136 | indirectly, case 4 |
| `Cimd.kt`                        | 191 | cases 3–4 (2)      |
| `McpServer.kt`                   | 766 | 8                  |
| `OAuthRoutes.kt`                 | 411 | 10                 |

`ManagementServices.kt` is exercised only _through_ `McpServerDbTest` (8 cases),
`CedarPolicyRoutesTest` (A2), and `UserAdminDeprovisionDbTest` (A3). Nothing
directly tests:

- 🔒 `replaceDirectRoles`' four invariants — including the **advisory-lock
  concurrency** property, which is exactly the kind of thing that passes
  single-threaded and corrupts under load.
- 🔒 `isSystemRole` enforcement on `updateRole`/`deleteRole` (INV-A11-30) — the
  guard F6 was worried about is present but **unverified**.
- 🔒 `rejectSystem` / `lockMutableGroup` / `setGroupRoles`' three different
  SYSTEM guards.
- 🔒 `INV-A11-28`'s reserved-tag write rejection (only the _marshalling_ half is
  tested, in A2).
- `unique`'s SQLSTATE-23505 mapping, `setGroupRoles`' diff semantics, and ~28
  name-vs-id overload pairs.
- The `canonicalJson` hash stability (INV-A11-11's compatibility contract).
- 30 of 38 MCP tools individually.

**This is the largest untested surface in the control-plane**, and unlike A9
(F10) it contains security guards. Recorded as **F19**. Consequence for Step 3:
like A9, A11 cannot be validated by 1:1 test migration alone — the guards need
new tests.

---

## 10. Findings raised here

| #       | Finding                                                                                                                                                                                                                 |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **F18** | Three hand-rolled CIDR implementations: `Cimd.kt`'s `Cidr`, `RequesterIp.kt`'s `cidrContains`, with identical byte-compare + boundary-mask logic. **REPRODUCE** — duplication is not an OMIT case; unify after cutover. |
| **F19** | `ManagementServices.kt` (732 LOC) has no dedicated test, including `replaceDirectRoles`' advisory-lock invariant and all three SYSTEM-immutability guards. Largest untested surface in the CP.                          |
| **F20** | `McpMutationExecutor`'s advisory-lock key joins with the literal 6-char string `\u0000`, not a NUL byte. Almost certainly unintended; part of a hash input, so replicate as-is and fix deliberately.                    |
| F6      | **RESOLVED, false alarm** — `isSystemRole` is enforced at `ManagementServices.kt:362,370,382,389`.                                                                                                                      |
| F5      | **Strengthened** — MCP's `list_roles` requires `ADMIN_POLICIES` while REST `GET /api/roles` is `requireApi`. Same data, two authority levels by transport.                                                              |

---

## 11. Open questions

| #   | Question                                                                                                                                                                                                                                                                                            |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | MCP is a **tag-free channel**: `McpAuthorizer` uses `authorizeAs` with a hand-built context, so no `context.tags` are derived (every capability's resource is `System`, and tags need a Datasource). Intended, or should the two classification tools derive tags against their datasource?         |
| Q2  | `canonicalJson` is a hash input for stored `request_hash` values. Must the Go port be byte-compatible (preserving existing idempotency rows), or is a one-time table truncation at cutover acceptable?                                                                                              |
| Q3  | F20 — the `\u0000` literal in the advisory-lock key. Confirm unintended, then decide: replicate, or fix and accept that in-flight idempotency keys re-serialize differently?                                                                                                                        |
| Q4  | `rejectSystem` has no `FOR UPDATE` while `lockMutableGroup` and `setGroupRoles` do. Is the group-update/member path genuinely not racy, or is the lock missing there?                                                                                                                               |
| Q5  | Six JVM `ResourceBundle` files (`mcp_errors`, `mcp_tools`, `authorization_messages` × en/ko) need a Go equivalent. `⟦LIB⟧` — and note `mcp_tools` descriptions are part of the MCP tool contract, so they are wire-visible.                                                                         |
| Q6  | `schemaFor` adds `idempotencyKey` twice for most WRITE tools (in the `when` and again in the trailing `if`). Harmless but confirm before simplifying.                                                                                                                                               |
| Q7  | A Go MCP SDK will not have Kotlin's `mcpStatelessStreamableHttp`. Confirm the Go SDK's `StreamableHTTPHandler` supports a per-request server construction (the stateless model this depends on) and whether its DNS-rebinding guard has the same HTTP/2 problem (INV-A11-4). Ties to the MCP spike. |
