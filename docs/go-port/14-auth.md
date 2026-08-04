# A14 — `auth/` module: OIDC login primitives + the MCP OAuth authorization server

Files: `McpOAuth.kt` (480) · `Oidc.kt` (126) · `OidcDirectoryProvisioner.kt`
(85). Total 691 LOC (re-verified with `wc -l`). Fully read.

> **Audited.** Every symbol, `@Serializable` type, route (there are none) and
> test count in this document was independently re-derived from source in a
> second pass. Test counts and all cited line numbers hold; **seven substantive
> claims did not** and are corrected in place, each marked _"an earlier
> revision"_ at the point of use and listed together in §9's **Corrections made
> by the audit pass** table. Four findings (**F42**–**F44** plus a rewritten
> **F23**/**F29**), two open questions (**Q11**, **Q12**), two new invariants
> (**INV-A14-10b**, **INV-A14-29b**) and four coverage gaps (13–16) were added.
> Read §9's correction table before trusting any memory of the earlier draft.

Tables: `oauth_consent`, `oauth_authorization_code`, `proxy_token` (all V7) ·
`app_user`, `app_group`, `group_member` (all V1).

MEDIUM depth. ⚠️ **The module has zero tests of its own — `auth/src/test` does
not exist** (verified: `ls -d auth/src/test` → _No such file or directory_).
Every assertion about it lives in `control-plane/src/test`. Yet
`auth/build.gradle.kts:20-24,33-46` declares a **complete** test harness —
`kotlin("test")`, HikariCP, Testcontainers core + postgresql, a `tasks.test`
block with macOS Docker-socket discovery, `api.version` pinning and
`TESTCONTAINERS_RYUK_DISABLED` — all of it dead configuration. Tests were
planned here and never written. See §7 and finding **F26**.

## Purpose

This module is the **shared credential layer** that both login surfaces and the
MCP surface sit on. It owns three things and deliberately nothing else:

1. **The OAuth 2.1 authorization server's persistence and state machine** —
   authorization codes, the access/refresh token family, consent records, and
   the bearer-resolution query the `/mcp` gate calls. `OAuthAuthorizationStore`
   is the whole state machine; A11's `oauth/OAuthRoutes.kt` is a thin HTTP
   adapter over it that adds no security logic of its own beyond client-metadata
   validation and CSRF.
2. **OIDC primitives** — discovery-document fetch + caching, `id_token`
   verification, the IdP-group → local-group resolver. A4's login routes
   (`Oidc.kt` in the control-plane, `DeviceAuth.kt`, `DaemonSession.kt`) each
   call these; the module holds no route.
3. **JIT directory reconciliation** — `OidcDirectoryProvisioner`, the single
   writer of `app_user`/`app_group`/`group_member` on the login path.

`auth/` **does not depend on `control-plane/`** (verified:
`auth/build.gradle.kts:11-18` lists only ktor-client, nimbus-jose-jwt, slf4j and
the Postgres JDBC driver — no `project(...)`). That one-way dependency is the
reason for several apparent duplications in this file, and it is a _reason to
keep them_, not to unify: pulling A1's `inTx {}` helper or A4's `tokenHash` into
this module would invert the module graph. Where a duplication is genuinely
hazardous, it is flagged as a finding instead.

Why the provisioner lives here rather than in A3, quoted verbatim from
`OidcDirectoryProvisioner.kt:6-9`:

> _"Shared OIDC JIT directory reconciler used by every control-plane login
> surface, so `app_user`/`app_group`/`group_member` semantics cannot drift
> between web, device, and MCP OAuth flows."_

---

## 1. Wire contract

Four `@Serializable` types. Only **one** of them is a real HTTP response shape —
the other three are serializable for a reason unrelated to the public API, and
the distinction matters because a Go port should not invent JSON tags for shapes
that never reach a client.

### `OAuthConsent` · `McpOAuth.kt:91-100` — **on the wire**

Serialized directly inside A11's `ConsentListResponse.consents`
(`OAuthRoutes.kt:90-93`), so these camelCase names **are** the contract for
`GET /oauth/consents`. No `@SerialName` anywhere; Kotlin property names are the
JSON keys.

| JSON field  | Type         | Nullable | Default | Source column                     |
| ----------- | ------------ | -------- | ------- | --------------------------------- |
| `id`        | number (i64) | no       | —       | `oauth_consent.id`                |
| `principal` | string       | no       | —       | `principal`                       |
| `clientId`  | string       | no       | —       | `client_id`                       |
| `resource`  | string       | no       | —       | `resource`                        |
| `scope`     | string       | no       | —       | `scope` (canonical, space-joined) |
| `createdAt` | string       | no       | —       | `created_at`                      |
| `updatedAt` | string       | no       | —       | `updated_at`                      |

⚠️ `createdAt`/`updatedAt` are `getTimestamp(...).toInstant().toString()`
(`McpOAuth.kt:435-436`) — **Java `Instant.toString()` variable-precision
formatting**. Identical trap to A2's `CedarPolicy.updatedAt` (A2 §8, Q3), but
**the direction of the Go divergence is the opposite of what it looks like**, so
state it precisely:

- `Instant.toString()` is `DateTimeFormatter.ISO_INSTANT`, whose documented
  contract (`DateTimeFormatterBuilder.appendInstant()`) emits the nano-of-second
  in **0, 3, 6 or 9 digits** — it pads _up_ to the next group of three.
- Go's `time.RFC3339Nano` strips **every** trailing zero from the fraction.

`oauth_consent.created_at`/`updated_at` are `TIMESTAMPTZ` (V7:15-16), i.e.
**microsecond** precision, so Java emits 0, 3 or 6 digits and Go emits 0..6.

- **Zero fraction: they AGREE** — both render `2026-07-31T04:05:06Z` (Go drops
  the `.` when the fraction is empty). An earlier revision of this doc claimed
  the zero case was the divergence; it is not.
- **They diverge whenever the microsecond value has trailing zeros that Java
  pads back:** `.120000` ⇒ Java `…06.120Z`, Go `…06.12Z`. `.123400` ⇒ Java
  `…06.123400Z`, Go `…06.1234Z`.
- Forced-millisecond RFC3339 differs from both whenever precision exceeds ms.

(Derived from the two APIs' documented contracts — **not** measured here; no JVM
is installed in this environment, `java -version` ⇒ _"Unable to locate a Java
Runtime"_. Pin it with golden vectors in Step 3 rather than trusting either
stdlib.) Wire-visible; `web/` renders it.

### `OAuthTokenPair` · `McpOAuth.kt:82-89` — **NOT on the wire**

`@Serializable`, but A11 remaps it field-by-field to its own snake_case
`TokenResponse` (`OAuthRoutes.kt:400`:
`TokenResponse(accessToken, tokenType, expiresIn, refreshToken, scope)` →
`access_token`, `token_type`, `expires_in`, `refresh_token`, `scope`). These
camelCase names therefore never appear in any HTTP body. The `@Serializable` is
vestigial. **F27.**

| Field          | Type         | Nullable | Default    | Notes                                               |
| -------------- | ------------ | -------- | ---------- | --------------------------------------------------- |
| `accessToken`  | string       | no       | —          | plaintext `pma_…`, returned once                    |
| `refreshToken` | string       | no       | —          | plaintext `pmr_…`, returned once                    |
| `tokenType`    | string       | no       | `"Bearer"` | never varied                                        |
| `expiresIn`    | number (i64) | no       | —          | `clampTtlSeconds(accessTtlSeconds)` — see INV-A14-2 |
| `scope`        | string       | no       | —          | the canonical scope string carried from the consent |

### `McpAccessIdentity` · `McpOAuth.kt:45-52` — **NOT on the wire**

The resolved bearer identity. Consumed only by A11's `/mcp` interceptor, which
immediately maps it to its own `McpRequestContext` (`McpServer.kt:191`). Never
serialized. `@Serializable` is vestigial. **F27.**

| Field       | Type          | Nullable | Notes                                                  |
| ----------- | ------------- | -------- | ------------------------------------------------------ |
| `principal` | string        | no       | `proxy_token.principal`                                |
| `clientId`  | string        | no       | `proxy_token.client_id`                                |
| `resource`  | string        | no       | echoed back so a caller can assert the audience it got |
| `scopes`    | set of string | no       | `proxy_token.scope` split on `' '`, blanks filtered    |
| `consentId` | number (i64)  | no       | `proxy_token.consent_id`                               |

### `OidcDiscoveryDocument` · `Oidc.kt:25-33` — **inbound only**

Parsed _from_ the IdP. The snake_case names are OIDC Discovery 1.0's own field
names, which is why no `@SerialName` is needed. Deserialized with
`ignoreUnknownKeys = true` (`Oidc.kt:99`), so a provider's extra fields are
dropped rather than failing the fetch.

| JSON field                      | Type   | Nullable | Default |
| ------------------------------- | ------ | -------- | ------- |
| `issuer`                        | string | no       | —       |
| `authorization_endpoint`        | string | no       | —       |
| `token_endpoint`                | string | no       | —       |
| `userinfo_endpoint`             | string | **yes**  | `null`  |
| `jwks_uri`                      | string | no       | —       |
| `device_authorization_endpoint` | string | **yes**  | `null`  |

🔒 **INV-A14-1 — the four non-nullable fields are hard requirements.** A
discovery document missing `jwks_uri` (or any of the three endpoints) fails
deserialization, which propagates out of `document()` and fails the login.
Fail-closed: a partially-parsed document with a null `jwks_uri` would later NPE
deep inside signature verification, where the cause is unrecoverable from the
log.

### Non-serializable input/output shapes

| Type                            | Where                 | Fields                                                                                                                                         |
| ------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `AuthorizationCodeInput`        | `McpOAuth.kt:102-111` | `clientId`, `principal`, `redirectUri`, `resource`, `scopes: Collection<String>`, `codeChallenge`, `ttlSeconds: Long = 300`, `consentId: Long` |
| `ConsumeAuthorizationCodeInput` | `:113-121`            | `code`, `clientId`, `redirectUri`, `resource`, `codeVerifier`, `accessTtlSeconds`, `refreshTtlSeconds`                                         |
| `RefreshTokenInput`             | `:123-129`            | `refreshToken`, `clientId`, `resource`, `accessTtlSeconds`, `refreshTtlSeconds`                                                                |
| `ValidatedIdToken`              | `Oidc.kt:53-58`       | `subject`, `email: String?`, `groups: List<String>`, `nonce: String?`                                                                          |
| `OidcGroupMapping`              | `Oidc.kt:103`         | `map: Map<String,String>`, `prefix: String?`                                                                                                   |
| `CodeRow` / `RefreshRow`        | `McpOAuth.kt:453-475` | private row carriers; every field is read                                                                                                      |

⚠️ `ValidatedIdToken.nonce` is populated but **never read by any caller**
(verified: the only `.nonce` reads in the tree are `OAuthNonceSession?.nonce` at
`Oidc.kt:128` in the control-plane, which is the _expected_ nonce, not this
field). Dead field. **F28.**

---

## 2. Routes — none

This module declares no HTTP route. It is called from:

| Symbol                                                    | Caller                                                                                   | Area |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---- |
| `McpTokenStore.resolveAccess`                             | `/mcp` bearer gate, `McpServer.kt:132`                                                   | A11  |
| `OAuthAuthorizationStore.*`                               | `/oauth/*` routes, `OAuthRoutes.kt:185-305`                                              | A11  |
| `canonicalScopes`, `isValidPkceChallenge`, `randomSecret` | `GET /oauth/authorize`, `OAuthRoutes.kt:140,152,232`                                     | A11  |
| `sha256Hex`                                               | `McpMutationExecutor`'s idempotency `request_hash`, `McpServer.kt:250`                   | A11  |
| `clampTtlSeconds`                                         | `Config.fromEnv` for `PM_OAUTH_ACCESS_TTL` / `PM_OAUTH_REFRESH_TTL`, `Config.kt:249-250` | A1   |
| `OidcGroupMapping.parse`                                  | `Config.fromEnv` for `PM_OIDC_GROUP_MAP` / `PM_OIDC_GROUP_PREFIX`, `Config.kt:166`       | A1   |
| `OidcDiscovery`, `IdTokenValidator`, `oidcHttpClient`     | web callback `Oidc.kt:175`, daemon liveness `DaemonSession.kt:721`, device flow          | A4   |
| `OidcDirectoryProvisioner.provision`                      | `UserGroupStore.provisionFromOidc`, `Users.kt:350-351`                                   | A3   |

Three of these are re-exported into the `controlplane` package by shims so call
sites read unqualified: `typealias OidcGroupMapping` (`Config.kt:6`),
`typealias OidcDiscoveryDocument`/`OidcDiscovery` (`OidcDiscovery.kt:3-4`),
`typealias ValidatedIdToken`/`IdTokenValidator` (`IdTokenValidator.kt:3-4`), and
`fun oidcHttpClient()` (`OidcHttp.kt:3`). A Go port has one package boundary and
needs none of this — but be aware that a `controlplane`-package test referring
to `OidcGroupMapping` is exercising _this_ module.

---

## 3. Pure functions — `McpOAuth.kt`

These five are the highest-value symbols in the area per line of code: every one
of them is a **key input** to a database predicate, so a Go port that diverges
by one byte does not fail loudly — it silently stops matching rows.

### `TOKEN_MIN_TTL_SECONDS` / `TOKEN_MAX_TTL_SECONDS` · `const val`

Kotlin: `const val TOKEN_MIN_TTL_SECONDS = 60L` ·
`const val TOKEN_MAX_TTL_SECONDS = 24 * 3600L` (`McpOAuth.kt:15-16`)

⚠️ **Byte-identical duplicates of `Tokens.kt:75-76`** (A4), which also declares
`TOKEN_MIN_TTL_SECONDS`, `TOKEN_MAX_TTL_SECONDS` and `clampTtlSeconds`. **F21**
— details below.

`SESSION_TTL_SECONDS` (12h) and `DEFAULT_USER_TTL_SECONDS` (1h) do **not** live
here; they are `Tokens.kt:77-78`, i.e. A4. This document does not specify them.

### `clampTtlSeconds(ttlSeconds: Long): Long` · fn

Kotlin:
`fun clampTtlSeconds(ttlSeconds: Long): Long = ttlSeconds.coerceIn(TOKEN_MIN_TTL_SECONDS, TOKEN_MAX_TTL_SECONDS)`
(`McpOAuth.kt:18`)

**Contract:** returns a value in `[60, 86400]` for every input, including
negatives and `Long.MAX_VALUE`. Total, never throws.

**Behavior:**

1. `< 60` (including `0` and negative) ⇒ `60`.
2. `> 86400` ⇒ `86400`.
3. Otherwise unchanged.

**Deps:** none. **Go shape:** a two-sided clamp on `int64`. Do **not** use a
generic `min(max(x, lo), hi)` on an unsigned type — a negative request must
floor to 60, not wrap.

🔒 **INV-A14-2 — every credential this module issues expires, and no client is
ever told a longer lifetime than the row has.** The clamp is applied in **two**
places for one issuance: `insertToken` clamps the value that becomes
`expires_at` (`McpOAuth.kt:383`), and `issuePair` clamps the same value again
for the `expiresIn` it returns (`:359`). Both are needed: they are computed from
the same input but consumed by different parties (Postgres and the client), and
a single clamp at one site would let the other drift. Reason recorded in
`Tokens.kt:74`: _"No token is permanent; none lives past
[TOKEN_MAX_TTL_SECONDS]."_

**INV-A14-3 — the clamp is applied twice along the config path too,
deliberately.** A1's `Config.fromEnv` already clamps `PM_OAUTH_ACCESS_TTL` /
`PM_OAUTH_REFRESH_TTL` at parse time (`Config.kt:249-250`); the store clamps
again at insert. That is defence in depth against a caller that constructs
`ConsumeAuthorizationCodeInput` without going through `Config` — including every
test. Keep both.

⚠️ **Operational trap to carry over:** the _refresh_ TTL is capped at the same
24h. `Config`'s default is 21,600s (6h) so it is inside the window, but an
operator setting `PM_OAUTH_REFRESH_TTL=7d` silently gets 24h with no warning at
either clamp site. A Go port should reproduce the cap; whether to add a warning
is a product decision, not a port decision.

### `canonicalScopes(scopes: Collection<String>): String` · fn

Kotlin:
`fun canonicalScopes(scopes: Collection<String>): String = scopes.map(String::trim).filter(String::isNotEmpty).toSortedSet().joinToString(" ")`
(`McpOAuth.kt:20`)

**Contract:** a deterministic, order-independent, duplicate-free,
space-separated scope string. Empty input ⇒ `""`.

**Behavior:**

1. Trim each element with Kotlin `String.trim()`, which trims by
   `Char.isWhitespace()` — defined on the JVM as
   `Character.isWhitespace(c) || Character.isSpaceChar(c)`. That union is
   **not** the same set as Go's `unicode.IsSpace`; see §8 Q4.
2. Drop empties **after** trimming, so a whitespace-only element disappears.
3. `toSortedSet()` — natural `String` ordering (UTF-16 code-unit lexicographic)
   **and** dedupe.
4. Join with a single `' '`.

**Deps:** none. **Go shape:** trim → filter → sort → dedupe →
`strings.Join(_, " ")`. Go's `sort.Strings` compares by byte; Kotlin compares by
UTF-16 code unit. **These agree for all-ASCII inputs and disagree only above
U+FFFF** (surrogate pairs sort before U+E000..U+FFFF in UTF-16 but after in
UTF-8). Scope names are `mcp:read`, `mcp:datasources:write`,
`mcp:policies:write`, `mcp:identity:write` and A11's `/oauth/authorize` rejects
anything outside that set (`OAuthRoutes.kt:141`), so ASCII is guaranteed on the
route path — but `rememberConsent`/`findActiveConsent` are library calls with no
such guard.

🔒 **INV-A14-4 — the canonical scope string is a DATABASE JOIN KEY, and this is
the single most port-fragile function in the area.** Four separate predicates
compare `scope` as an opaque string:

| Site                            | Predicate                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------ |
| `McpTokenStore.resolveAccess`   | `JOIN oauth_consent c ON … AND c.scope = t.scope` (`:61`)                      |
| `createAuthorizationCode`       | `… AND scope = ?` in the consent-selecting INSERT (`:145`)                     |
| `consentActive`                 | `… AND scope = ?` (`:411`)                                                     |
| `oauth_consent_active_tuple_uq` | `UNIQUE (principal, client_id, resource, scope) WHERE revoked_at IS NULL` (V7) |

A canonicalization that differs in **order, dedupe, or whitespace** does not
raise an error. It makes `findActiveConsent` miss an existing consent (so every
login writes a new consent row and re-prompts), and it makes `resolveAccess`'s
five-column JOIN fail for tokens minted under the other form — i.e. **every MCP
request 401s** with a perfectly valid, unexpired, unrevoked token. Freeze this
function with a golden vector table in Step 3.

**Where canonicalization happens, and where it deliberately does not.**
Canonical form is imposed at exactly three boundaries — `rememberConsent`
(`:270`), `createAuthorizationCode` (`:135`) and `findActiveConsent` (`:297`).
`consumeAuthorizationCode` and `rotateRefresh` carry `row.scope` forward
**verbatim** (`:210`, `:259`) and never re-canonicalize. Correct, and
load-bearing: re-canonicalizing a stored value would silently _repair_ a legacy
row's non-canonical scope into a form that no longer joins to its own consent.

### `sha256Hex(value: String): String` · fn

Kotlin:
`MessageDigest.getInstance("SHA-256").digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }`
(`McpOAuth.kt:22-24`)

**Contract:** 64 lowercase hex characters. Total.

**Behavior:** UTF-8 encode → SHA-256 → lowercase hex, no separator, no prefix.

**Deps:** none. Writes into `proxy_token.token_hash`,
`oauth_authorization_code.code_hash`, and (via A11)
`mcp_mutation_idempotency.request_hash`. **Go shape:**
`h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:])` — `hex` is
lowercase, matching `%02x`; `[]byte(s)` is UTF-8, matching
`StandardCharsets.UTF_8`. ⚠️ The intermediate `h` is **required**:
`sha256.Sum256(x)` returns a `[32]byte` **value**, and Go cannot slice an
unaddressable value, so `hex.EncodeToString(sha256.Sum256(x)[:])` does not
compile. Same trap in `pkceS256` below.

🔒 **INV-A14-5 — three independent SHA-256-hex helpers write the SAME
`proxy_token.token_hash` column and MUST agree byte-for-byte.** `sha256Hex` here
(`Charsets.UTF_8` explicitly), `tokenHash` at `Tokens.kt:91-94` (A4), and a
private `sha256Hex` at `DaemonSession.kt:44-46` (A4, `Charsets.UTF_8`, its own
`daemon_session.renewal_token_hash` column).

⚠️ **Correction to an earlier revision of this line**, which said `Tokens.kt`'s
`token.toByteArray()` is "platform default = UTF-8 on JVM 18+". That is wrong
and it invents a JVM-version hazard that does not exist: `toByteArray` is
_Kotlin_ stdlib, declared
`fun String.toByteArray(charset: Charset = Charsets.UTF_8)`, so the charset is a
**default argument that is always UTF-8**, independent of `file.encoding` and of
the JDK version. All three helpers are unconditionally UTF-8; there is no
locale/JDK divergence to port around.

There is a **fourth** call site but not a fourth implementation:
`TokenStore.hash` (`Tokens.kt:104`) is
`private fun hash(token: String): String = tokenHash(token)` — a pure
delegation. Count three implementations, four names.

They agree today. `DaemonSession.kt:38-41` records why it is a copy and not a
call: _"the SAME idiom [TokenStore]'s private `hash()` uses for
`proxy_token.token_hash`, kept self-contained here rather than reaching into
[TokenStore] (that's a different part's file; this store persists its own hashed
secret in its own column)."_ A Go port has one package, so collapsing all three
into one function is tempting — and it is still **REPRODUCE**
(`14-auth.md:307-315`). Duplication is explicitly not grounds for OMIT, and the
only safety argument for the collapse is _"they agree today"_, which is a claim
about the present, not about the contract. Keep three call sites, each with its
own test. The collapse — and with it **F21**'s sibling risk — is a separate
decision after cutover.

🔒 **INV-A14-6 — no credential is ever stored in plaintext.** Every write is
`setString(_, sha256Hex(token))`; the plaintext is returned to the caller
exactly once and never read back. `McpOAuthStoreDbTest` case 1 asserts it
directly (_"the plaintext token must never be stored"_, `:73`). The consequence
a port must preserve: **there is no way to look a token up by anything but its
hash**, so no route can ever list or re-display a token value.

### `pkceS256(verifier: String): String` · fn

Kotlin:
`Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(StandardCharsets.US_ASCII)))`
(`McpOAuth.kt:26-28`)

**Contract:** the RFC 7636 `S256` challenge for `verifier` — 43 unpadded
base64url characters.

**Behavior:**

1. Encode the verifier as **US-ASCII**, not UTF-8. ⚠️ Java's
   `String.getBytes(US_ASCII)` is **lossy**: a non-ASCII char becomes `?` (0x3F)
   rather than throwing.
2. SHA-256.
3. base64**url** alphabet (`-`/`_`), padding **stripped**.

**Deps:** none. **Go shape:**
`h := sha256.Sum256(b); return base64.RawURLEncoding.EncodeToString(h[:])` —
again the intermediate variable is mandatory, not style: `sha256.Sum256(b)[:]`
is a compile error ("cannot slice unaddressable value"). `RawURLEncoding` is
base64url **without** padding, matching `getUrlEncoder().withoutPadding()`;
plain `URLEncoding` would add `=` and break every comparison. ⚠️ Go's
`[]byte(s)` is **UTF-8**, so a non-ASCII verifier hashes differently in Go than
in Kotlin. This is not exploitable (§8 Q1 works through why), but it is an
observable divergence and the two validators below are Unicode-permissive enough
to let a non-ASCII verifier reach this function.

### `isValidPkceChallenge(challenge: String): Boolean` · fn

Kotlin:
`challenge.length == 43 && challenge.all { it.isLetterOrDigit() || it == '-' || it == '_' }`
(`McpOAuth.kt:30-32`)

**Behavior:**

1. Length must be **exactly 43** UTF-16 code units — the length of unpadded
   base64url over 32 bytes.
2. Every character must be letter-or-digit, `-`, or `_`.

⚠️ **Kotlin's `Char.isLetterOrDigit()` is Unicode-aware**, so `ᄀ`, `é` and `٣`
all pass. A challenge of 43 Hangul jamo satisfies this predicate _and_ the DB
`CHECK (char_length BETWEEN 43 AND 128)`, so it is storable — but it can never
equal any `pkceS256` output, so the code is simply unredeemable. Fail-closed,
therefore not a vulnerability, but it **is** a divergence trap: a Go port
written as `strings.ContainsRune("A-Za-z0-9-_", r)` accepts a _strictly smaller_
set. Behaviourally that is an improvement; record it as a deliberate tightening
rather than let it be discovered as a diff. **F29.**

⚠️ Also note the app is **stricter than the schema**: the app demands exactly
43, the DB CHECK allows 43..128 and its comment claims it _"pins it to the RFC
7636 length range"_ (V7). Only the 43-char S256 shape is ever accepted, so the
44..128 range is unreachable through any code path. Inconsistency, not a bug.

### `isValidPkceVerifier(verifier: String): Boolean` · fn

Kotlin:
`verifier.length in 43..128 && verifier.all { it.isLetterOrDigit() || it == '-' || it == '.' || it == '_' || it == '~' }`
(`McpOAuth.kt:34-36`)

RFC 7636's `unreserved` charset plus the same Unicode-aware `isLetterOrDigit`
caveat. Called only from `consumeAuthorizationCode` (`:195`); public but with no
external consumer.

🔒 **INV-A14-7 — verifier validation is checked BEFORE the hash comparison and
is a separate rejection reason.** Both land in the same `if (…) return null`
(`:194-197`), so an invalid-shape verifier and a wrong verifier are
indistinguishable to the client. Deliberate: the token endpoint must not tell a
client _why_ an exchange failed beyond `invalid_grant`, or it becomes an oracle
for probing code state.

### `randomSecret(prefix: String, bytes: Int = 32): String` · fn

Kotlin:
`prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(bytes).also(secureRandom::nextBytes))`
(`McpOAuth.kt:40-43`), over a single process-wide
`private val secureRandom = SecureRandom()` (`:38`).

**Behavior:** `bytes` cryptographically-random bytes, unpadded base64url,
prefixed. 32 bytes ⇒ 43 chars after the prefix; 24 bytes ⇒ 32 chars.

**Deps:** the platform CSPRNG. **Go shape:** `crypto/rand.Read` +
`base64.RawURLEncoding`. Never `math/rand`. Go needs no shared-instance analogue
— `crypto/rand` is stateless and safe for concurrent use.

**Prefix registry (the whole module's, plus its collisions):**

| Prefix  | Bytes  | What                          | Site                    |
| ------- | ------ | ----------------------------- | ----------------------- |
| `pmc_`  | 32     | authorization code            | `:134`                  |
| `pma_`  | 32     | MCP access token              | `:355`                  |
| `pmr_`  | 32     | MCP refresh token             | `:356`                  |
| `pmf_`  | **24** | refresh-**family** id         | `:212`                  |
| `csrf_` | 18     | OAuth consent-form CSRF (A11) | `OAuthRoutes.kt:60,232` |

⚠️ **`pmf_` is not a credential.** It is stored in **cleartext** in
`proxy_token.refresh_family` and is the key `revokeFamily` deletes by. It must
never be accepted as a bearer token; it is minted from the CSPRNG only so it is
unguessable in logs, not because it authorizes anything.

⚠️ **Prefix collision with A4:** `DaemonSession.kt:33-36`'s `newRenewalToken()`
also mints **`pmr_`**-prefixed secrets, for daemon session renewal. Two
different credential classes, in two different tables (`proxy_token.token_hash`
vs `daemon_session.renewal_token_hash`), share a wire prefix. Neither lookup can
accept the other (different tables, and `revoke`'s kind filter — INV-A14-17), so
this is not an authentication hazard, but it defeats prefix-based classification
during incident response: a leaked `pmr_…` cannot be typed without trying both
tables. **F22.**

### `MCP_ACCESS_KIND` / `MCP_REFRESH_KIND` · `const val`

`"MCP_ACCESS"` / `"MCP_REFRESH"` (`McpOAuth.kt:13-14`).

Exact usage, re-counted (`grep -rn 'MCP_ACCESS_KIND\|MCP_REFRESH_KIND'` over
`auth/` **and** `control-plane/`): **five** reference sites, all inside
`McpOAuth.kt`, and **zero** outside this file — `:227` (the refresh-grant kind
gate), `:337`/`:338` (`revoke`'s kind dispatch), `:357`/`:358` (the `kind`
**bind parameter** passed to `insertToken`). Three **SQL string literals**
bypass the constants entirely: `:62` (`t.kind = 'MCP_ACCESS'`), `:322`
(`kind IN ('MCP_ACCESS','MCP_REFRESH')`), `:397` (same, in `revokeFamily`).
Half-applied constants: a rename compiles and silently mismatches those three
SQL strings. **F23.**

⚠️ An earlier revision of this section said "used at only three sites" and
listed `:357-358` under _"every SQL string hardcodes the literal"_. Both wrong:
there are five reference sites, and `:357-358` are **constant uses**, not
hardcoded literals. The hardcoded set is exactly `{:62, :322, :397}`.

🔒 **INV-A14-8 — MCP token kinds are unrepresentable in A4's type system, by
construction.** A4's `TokenKind` enum has exactly four values — `SESSION`,
`USER`, `EDITOR`, `APPROVER_EXEC` (`Tokens.kt:31-36`) — and **no MCP member**.
So no A4 code path can mint an MCP-kind row, and this module is the only writer
of them. The partition is enforced three ways at once:

- **type**: `TokenKind` cannot express `MCP_ACCESS`;
- **query**: A4's wire resolver filters
  `kind IN ('SESSION','USER','EDITOR','APPROVER_EXEC')` (`Tokens.kt:154`) and
  this module's filters `kind = 'MCP_ACCESS'` (`:62`) — disjoint;
- **schema**: V7's `proxy_token_mcp_metadata_ck` makes the two column shapes
  mutually exclusive (an MCP row _must_ carry
  resource/client_id/scope/refresh_family/consent_id and `roles = '[]'`; a
  non-MCP row must carry none of them).

**An MCP access token can therefore never be presented as a database wire
credential, and a daemon session token can never be presented to `/mcp`.** A Go
port that unifies token handling behind one `kind` string must reproduce all
three layers; dropping the query filter alone is enough to break it, because the
schema CHECK does not constrain _reads_.

⚠️ V7's own `kind` comment lists only
`SESSION | USER | MCP_ACCESS | MCP_REFRESH` and omits `EDITOR` and
`APPROVER_EXEC`, which exist in `TokenKind` and are written by A7. Stale
migration comment. **F24.**

---

## 4. `McpTokenStore` — the `/mcp` bearer gate

### `class McpTokenStore(private val dataSource: DataSource)` · `McpOAuth.kt:54`

Constructed once in A1's `ControlPlaneCore` (`ControlPlaneCore.kt:30`).
Stateless.

### `resolveAccess(token: String, expectedResource: String): McpAccessIdentity?` · method

Kotlin:
`fun resolveAccess(token: String, expectedResource: String): McpAccessIdentity?`
(`:55-79`)

**Contract:** returns the identity behind a valid, live, correctly-audienced MCP
access token, or `null`. Never throws for a bad token. **Non-null is the sole
authorization to enter the `/mcp` surface.**

**Behavior** — one SELECT, one connection, autoCommit (no transaction):

```sql
SELECT t.principal, t.client_id, t.resource, t.scope, t.consent_id
FROM proxy_token t
JOIN oauth_consent c ON c.id = t.consent_id
  AND c.principal = t.principal AND c.client_id = t.client_id
  AND c.resource  = t.resource  AND c.scope     = t.scope
WHERE t.token_hash = ? AND t.kind = 'MCP_ACCESS' AND t.resource = ?
  AND t.revoked_at IS NULL AND t.expires_at > now()
  AND c.revoked_at IS NULL
```

1. Bind `sha256Hex(token)` and `expectedResource`.
2. No row ⇒ `null`.
3. Otherwise map:
   `scopes = getString("scope").split(' ').filter(isNotBlank).toSet()`.

**Deps:** `proxy_token` ⋈ `oauth_consent`.

**Access paths (the schema objects a Go port must recreate — plan claims below
are `Unverified`; no `EXPLAIN` was run):** the driving lookup is
`proxy_token.token_hash`, which is `TEXT NOT NULL UNIQUE` (V7:60) — that
implicit unique index is what makes the predicate single-row without a `LIMIT`.
The join reaches `oauth_consent` by its primary key (`c.id = t.consent_id`).
**`proxy_token_mcp_consent_idx`
(`ON proxy_token (consent_id) WHERE kind IN ('MCP_ACCESS','MCP_REFRESH')`,
V7:98-99) is NOT plausibly used here** — it indexes the _wrong side_ of this
join; its consumer is `revokeConsent`'s `WHERE consent_id = ?` cascade (`:322`).
An earlier revision of this line credited it to `resolveAccess`. Recreate it
anyway: `revokeConsent` needs it.

⚠️ The scope split here is `filter(String::isNotBlank)` (`:74`) while
`canonicalScopes` filters `String::isNotEmpty` (`:20`). Equivalent on canonical
input (canonical form has no runs of spaces), so the asymmetry is invisible
today — but a port that unifies them should pick `isNotBlank` for the split
side, because that side parses _stored_ data that a legacy row could have left
non-canonical.

🔒 **INV-A14-9 — audience binding is a WHERE clause, not a caller's `if`.**
`t.resource = ?` is inside the query, so a token minted for one MCP resource
cannot resolve against another **even if the calling gate forgets to compare**.
A11 passes `config.mcpResource` (`McpServer.kt:132`). This is what makes a
stolen token useless against a second proxy-monster deployment.
`McpOAuthStoreDbTest` case 1 pins it
(`resolveAccess(pair.accessToken, "$RESOURCE/wrong")` ⇒ null, `:66`).

🔒 **INV-A14-10 — the JOIN re-verifies the FULL consent tuple, not just the
foreign key.** The token row carries a _denormalized copy_ of
`(principal, client_id, resource, scope)`. Joining on `c.id = t.consent_id`
alone would authorize a token whose copy has drifted from its consent — e.g.
after any future code path that edits either side. Five join columns means a
drifted token **fails closed** instead of authorizing under a grant it no longer
matches. This is the reason the predicate looks redundant; it is not.

🔒 **INV-A14-10b — the SIXTH predicate, `c.revoked_at IS NULL`, is the only
thing that closes a real revoke-versus-issue interleaving, and it is not
belt-and-braces.** `revokeConsent` revokes the consent row and then cascades
`revoked_at` onto the tokens that exist _at that moment_ (`:321-323`). A
`consumeAuthorizationCode` transaction that started before the revoke and
commits after it inserts **fresh `MCP_ACCESS`/`MCP_REFRESH` rows the cascade
already ran past** — those rows are live, unexpired, unrevoked, and point at a
revoked consent. Nothing rewrites them; no sweeper exists (Q9). They are
unusable _only_ because this query re-reads the consent's `revoked_at` on every
request. A Go port that "optimizes" the join down to `c.id = t.consent_id` and
trusts the cascade grants a live MCP token under a revoked consent for the full
access TTL. `consentActive`'s own `revoked_at IS NULL` read (`:410`) closes the
same window for the refresh grant.

🔒 **INV-A14-11 — scopes come from the TOKEN row, not the consent row.** By
INV-A14-10 they are equal, so the choice is invisible today — but it is the
correct one: the scope a request may act under is the scope _that token_ was
issued with, not whatever the standing consent now says. A consent widened after
issuance must not retroactively widen an outstanding token.

**INV-A14-12 — expiry is evaluated by the DATABASE clock (`now()`), not the
JVM's.** Issuance also computes `expires_at` in Postgres (`insertToken`,
`:378`), so issuance and validation share one clock and a token can never be
born expired by skew. ⚠️ **`rotateRefresh` breaks this symmetry** — see
INV-A14-16.

**What `resolveAccess` deliberately does NOT do:**

- **No `last_used_at` write.** Contrast A4's `TokenStore.validate`
  (`Tokens.kt:182`). The reason is stated for A4's own read-only variant at
  `Tokens.kt:145-150` and applies identically here: _"WITHOUT the `last_used_at`
  write, so many concurrent queries sharing one daemon/session token don't
  serialize on a single row's UPDATE lock (or generate WAL per query)."_ Since
  **every** `/mcp` request goes through `resolveAccess`, an UPDATE here would
  put a write on the hot path. Consequence to accept, not fix: an MCP token's
  `last_used_at` is **always NULL**.
- **No deactivation check.** A11's gate does it separately —
  `identity == null || core.userGroupStore.isDeactivated(identity.principal)`
  (`McpServer.kt:133`). 🔒 **INV-A14-13 — a Go port must not "helpfully" move
  the deactivation check into this query, and must not drop it from the gate.**
  Splitting it keeps this module free of any dependency on A3's identity tables;
  the cost is that the check is the _caller's_ obligation, and the gate is the
  only caller.
- **No scope check.** Scope enforcement is A11's `McpAuthorizer` (A11
  INV-A11-7).

**Go shape:** one prepared query, `sql.ErrNoRows` ⇒ `nil, nil` (not an error —
"no such token" is a normal outcome). Return a value struct; the scope set is a
`map[string]struct{}` or a sorted slice, but note A11 does
`capability.requiredScope in context.scopes`, a membership test.

---

## 5. `OAuthAuthorizationStore` — the authorization-server state machine

### `class OAuthAuthorizationStore(private val dataSource: DataSource)` · `McpOAuth.kt:131`

**Lifecycle — different from `McpTokenStore`'s, and the doc previously did not
say so.** It is **not** held on `ControlPlaneCore`;
`grep -rn 'OAuthAuthorizationStore('` finds exactly one construction site,
`OAuthRoutes.kt:111`, inside `installMcpOAuthRoutes` — i.e. one instance per
route installation, holding only the `DataSource`. Stateless, so the asymmetry
with `ControlPlaneCore.kt:30`'s `mcpTokenStore` is harmless; a Go port may put
both wherever its wiring prefers. Worth recording only so a port author does not
go looking for a `core.oauthStore` that does not exist.

### `private fun <T> inTransaction(block: (Connection) -> T): T` · `:439-451`

`autoCommit = false` → `block` → `commit()`; `catch (e: Exception)` →
`rollback()` + rethrow; `finally` `autoCommit = true`.

⚠️ **Hand-rolled, same idiom flagged as F14 in A7 (`AccessStore.approve`).**
Here it is **not** an inconsistency: A1's `inTx {}` helper (`Db.kt`) lives in
`control-plane`, and `auth/` does not depend on `control-plane`. Using it would
invert the module graph. Record the reason so a Go port — which _will_ have one
package — unifies deliberately rather than reflexively.

Two properties a port must keep:

1. **A `return@inTransaction` COMMITS.** Every `null` return in
   `consumeAuthorizationCode` / `rotateRefresh` is a _successful_ transaction
   that commits whatever it already wrote. This is load-bearing: it is how a
   burnt authorization code stays burnt after a failed exchange (INV-A14-15). A
   Go port using `defer tx.Rollback()` with commit-on-success **inverts this**
   and reintroduces the replayable-code bug. Structure it as: run, then commit
   on _every_ non-panic exit path.
2. `catch (e: Exception)` does not catch `Error`. An `OutOfMemoryError`
   mid-block skips the rollback and leaks a connection with `autoCommit = false`
   back to the pool. Same shape in `OidcDirectoryProvisioner`. Go's
   `recover()`-based equivalent should be total.

### `createAuthorizationCode(input: AuthorizationCodeInput): String` · method · `:132-165`

**Contract:** returns the plaintext authorization code. **Throws**
`IllegalArgumentException` on a bad challenge or a consent that does not match —
the only method in the store that signals failure by throwing rather than
returning `null`.

**Behavior:**

1. `require(isValidPkceChallenge(input.codeChallenge)) { "invalid PKCE challenge" }`.
   🔒 **INV-A14-14 — PKCE is mandatory at the STORE, not only at the route.**
   A11 also checks it (`OAuthRoutes.kt:140`), and the DB has a CHECK. Three
   layers, because `token_endpoint_auth_methods_ supported = ["none"]`
   (`OAuthRoutes.kt:122`) — there is **no client secret anywhere in this
   design**, so PKCE is the _only_ thing binding a code to the client that
   requested it. Losing it makes a leaked code redeemable by anyone.
2. `code = randomSecret("pmc_")`,
   `canonicalScope = canonicalScopes(input.scopes)`.
3. **Prune, on a separate statement on the same connection, outside any
   transaction:**
   `DELETE FROM oauth_authorization_code WHERE expires_at <= now() OR used_at IS NOT NULL`
   (`:138`). Global across all principals. This is the **only** sweeper for the
   table — A1's background purge loop (`App.kt:405-426`) covers `device_login`,
   query results, editor sessions and the connection catalog, and **not** this
   table. So issuance traffic is the sweeper. ⚠️ Three consequences a port must
   know: (a) it deletes **used** codes too, so a replay attempt after any later
   issuance takes the "row not found" path in `consumeAuthorizationCode` rather
   than the "not usable" path — same `null` answer, no forensic record that a
   replay occurred; (b) it is not in a transaction with the INSERT, so a prune
   can commit while the INSERT fails; (c) **the predicate is only
   half-indexed.** The table's sole non-constraint index is
   `oauth_authorization_code_expiry_idx ON (expires_at) WHERE used_at IS NULL`
   (V7:41-42) — a **partial** index whose predicate is the _negation_ of the
   `OR used_at IS NOT NULL` branch, so that branch has no index to use at all.
   `Unverified` (no `EXPLAIN` run), but structurally the `OR` forces a scan.
   Since the prune also deletes the used rows, the backlog it scans stays small
   in steady state; it is only a cost if issuance stops for a long time.
   Recreate the index in the partial form — the plain
   `CREATE INDEX … (expires_at)` a port would reach for is a different object.
   **F42.**
4. **The INSERT re-verifies the consent as its own SELECT source:**
   ```sql
   INSERT INTO oauth_authorization_code (…, consent_id)
   SELECT ?, ?, ?, ?, ?, ?, ?, now() + (?::bigint * interval '1 second'), id
   FROM oauth_consent
   WHERE id = ? AND principal = ? AND client_id = ? AND resource = ? AND scope = ?
     AND revoked_at IS NULL
   ```
   `require(executeUpdate() == 1) { "authorization code consent is absent, revoked, or mismatched" }`.
   🔒 **INV-A14-15a — the consent check IS the insert.** Doing it as the
   INSERT's SELECT source makes "consent is valid" and "code is bound to it" a
   single atomic statement with **no TOCTOU window**. A port that reads the
   consent, checks it in application code, then inserts, opens a window in which
   the consent is revoked between check and insert — and the resulting code is
   redeemable (`consumeAuthorizationCode` would still re-check, so the impact is
   bounded, but the code should never have existed). The five predicates also
   make this an **ownership** check: a caller cannot bind a code to _someone
   else's_ consent id. `McpOAuthStoreDbTest` case 5 pins both halves — a
   mismatched principal, and a revoked consent, each ⇒
   `IllegalArgumentException`.
5. TTL: `input.ttlSeconds.coerceIn(60, 600)` (`:155`). ⚠️ **Not
   `clampTtlSeconds`** — a separate, tighter window for codes (1..10 min;
   default 300 from `AuthorizationCodeInput`). The two bounds are **inline magic
   numbers** with no named constants, unlike `TOKEN_MIN/MAX_TTL_SECONDS`.
   **F25.**
6. Return the plaintext code.

**Deps:** `oauth_authorization_code` (DELETE, INSERT), `oauth_consent`
(SELECT-as-source).

**Schema facts this method relies on and the doc previously omitted (all V7):**

- `oauth_authorization_code.code_hash TEXT NOT NULL UNIQUE` (V7:28). Two things
  follow: a hash collision surfaces as a **constraint violation exception**, not
  a `null` (the astronomically-unlikely path, but a Go port must not swallow it
  into "issuance failed silently"); and `consumeAuthorizationCode`'s
  `WHERE code_hash = ? FOR UPDATE` is single-row **because of this constraint**,
  with no `LIMIT 1`.
- `oauth_authorization_code.consent_id BIGINT NOT NULL REFERENCES oauth_consent(id)`
  (V7:35) — **NOT NULL**, so a code with no consent is unrepresentable, and the
  FK is why `revokeConsent` can only ever stamp `revoked_at` and never `DELETE`
  a consent row. That FK, not the KDoc, is what makes "revocation is a
  timestamp" (V7:7-8) structurally true.
- `CHECK (char_length(code_challenge) BETWEEN 43 AND 128)` (V7:39) — the DB half
  of INV-A14-14.

⚠️ **The throw reaches A11 uncaught.** `issueAuthorizationCode`
(`OAuthRoutes.kt:325-348`) wraps nothing in `runCatching`, so a consent revoked
between `findActiveConsent` (`:320`) and `createAuthorizationCode` (`:335`)
surfaces as a 500 rather than an OAuth error response. Narrow race; recorded as
**F30**.

### `consumeAuthorizationCode(input): OAuthTokenPair?` · method · `:167-217`

**Contract:** exchanges a code for a fresh token family exactly once. `null` on
any failure, with no distinguishable reasons.

**Behavior** — one transaction:

1. `SELECT id, principal, client_id, redirect_uri, resource, scope, code_challenge, consent_id FROM oauth_authorization_code WHERE code_hash = ? FOR UPDATE`.
   No row ⇒ `null` (transaction commits, nothing written). **`FOR UPDATE`
   serializes concurrent redemptions of the same code.**
2. A **second** query re-reads usability:
   `SELECT used_at IS NULL AND expires_at > now() FROM oauth_authorization_code WHERE id = ?`.
   ⚠️ Redundant round-trip — both columns were available to step 1, and because
   Postgres' `now()` is _transaction start time_ and both statements share the
   transaction, the clock is identical either way. **F31** (index F65 —
   inefficiency, not a bug). **REPRODUCE:** inefficiency is not grounds for
   OMIT, and the round-trip is a second statement inside the same `FOR UPDATE`
   transaction, so removing it changes the statement sequence a differential
   harness (and any lock-wait observer) can see. Fold it into step 1 as a
   follow-up change.
3. Reject to `null` if **any** of: `!usable`, `row.clientId != input.clientId`,
   `row.redirectUri != input.redirectUri`, `row.resource != input.resource`,
   `!isValidPkceVerifier(input.codeVerifier)`,
   `pkceS256(input.codeVerifier) != row.challenge` (`:194-197`). Note what is
   _not_ compared: **principal** (none is supplied — the code carries it) and
   **scope** (likewise). The PKCE comparison is a plain `!=`, **not
   constant-time**. Acceptable and worth stating why: the challenge is not a
   secret — the client sent it in the clear in the authorize request. Contrast
   A11's consent-CSRF check, which _does_ use `MessageDigest.isEqual`
   (`OAuthRoutes.kt:301`) because that value _is_ a secret.
4. `UPDATE oauth_authorization_code SET used_at = now() WHERE id = ? AND used_at IS NULL`;
   `executeUpdate() != 1` ⇒ `null`. 🔒 **INV-A14-15 — single use is guaranteed
   by the CONDITIONAL UPDATE, not by the read at step 2.** Under the
   `FOR UPDATE` lock this is belt-and-braces, but it is the primitive that
   survives a port that loses or weakens the row lock (e.g. a different
   isolation level). `McpOAuthStoreDbTest` case 1 asserts the second exchange of
   the same code is `null` (_"an authorization code must be single-use"_,
   `:59`).
5. `consentActive(connection, row.consentId, row.principal, row.clientId, row.resource, row.scope)`
   ⇒ `null` if false. 🔒 **INV-A14-15b — the code is burnt BEFORE the consent is
   re-checked, on purpose.** A code that fails the consent check must not
   survive to be retried later; the exchange failing and the code surviving
   would let a client hold a redeemable code across a consent revoke/re-grant
   cycle. Because `return@inTransaction` commits (see `inTransaction` above),
   the `used_at` stamp **persists**. `McpOAuthStoreDbTest` case 3 pins the
   outcome.
6. `issuePair(family = randomSecret("pmf_", 24), rotatedFrom = null)` — **a
   fresh family per code exchange**, so two authorizations by the same
   principal+client are independent breach domains: a replay detected on one
   cannot revoke the other.

### `rotateRefresh(input: RefreshTokenInput): OAuthTokenPair?` · method · `:219-266`

**Contract:** rotate a refresh token exactly once, or `null`. On a **replay**,
additionally revoke the entire rotation family as a side effect.

**Behavior** — one transaction:

1. `SELECT id, kind, principal, client_id, resource, scope, refresh_family, consent_id, revoked_at, expires_at, rotated_at FROM proxy_token WHERE token_hash = ? FOR UPDATE`.
   No row **or `kind != MCP_REFRESH`** ⇒ `null` (`:227`). 🔒 Presenting an
   `MCP_ACCESS`, `SESSION`, `USER`, `EDITOR` or `APPROVER_EXEC` token to the
   refresh grant is rejected on kind — the read-side half of INV-A14-8.
2. Derive `expired = getTimestamp("expires_at").toInstant() <= Instant.now()`
   (`:237`). ⚠️ **JVM clock**, unlike `resolveAccess`'s `expires_at > now()`
   (Postgres clock) and unlike `insertToken`'s Postgres-computed `expires_at`.
   Two different clocks decide expiry on the same column. **INV-A14-16 — the
   skew window is real:** with a JVM clock behind the DB's, an expired refresh
   token rotates successfully; ahead of it, a live one is refused. Impact is
   bounded by the skew, and issuance uses the DB clock so nothing is born
   expired — but the disposition is **REPRODUCE + PIN** (**F32**, index F28):
   keep the JVM-clock read here and the Postgres-clock read in `resolveAccess`,
   and write a test asserting the two-clock behaviour. This is a token-expiry
   path, so unifying the clock decides who gets refused under skew — precisely
   the kind of change that has to be a visible, separate PR rather than a silent
   side effect of the rewrite.
3. `if (row.clientId != input.clientId || row.resource != input.resource) return null`
   (`:242`). 🔒 Refresh tokens are client-bound and audience-bound. ⚠️ **This
   check precedes the replay check.** A replay presented with a _wrong_
   `client_id` returns a plain `null` and does **not** trigger family
   revocation. The attacker gains nothing (both paths deny), but the
   breach-detection alarm can be side-stepped, so the family survives for the
   legitimate holder without any signal that a stolen token was seen. Ordering
   is defensible either way; recorded so a port's choice is deliberate. **F33.**
4. `if (row.rotated) { revokeFamily(connection, row.family); return null }`
   (`:243-246`). 🔒 **INV-A14-17 — replay of a rotated refresh token revokes the
   WHOLE family, not just the presented token.** `rotated_at != NULL` means this
   token was already exchanged, so _someone else_ holds its successor: either
   the legitimate client is replaying (a client bug) or the token was stolen.
   Both are indistinguishable, and the safe response is to invalidate every
   `MCP_ACCESS` and `MCP_REFRESH` sharing `refresh_family` and force a fresh
   authorization. This is OAuth 2.1 / RFC 6819 refresh-rotation breach
   detection, and it is the security core of the area. `McpOAuthStoreDbTest`
   case 2 pins it end to end, including that the _successor_ refresh token is
   also dead afterwards (_"replay must revoke the new refresh token too"_,
   `:89`).
5. `if (row.revoked || row.expired || !consentActive(…5-tuple…)) return null`
   (`:247-249`) — **no** family revocation on these. Correct: a
   revoked/expired/consent-less token is a normal end-of-life, not evidence of
   theft.
6. `UPDATE proxy_token SET revoked_at = now(), rotated_at = now() WHERE id = ? AND revoked_at IS NULL`;
   `!= 1` ⇒ `null` (`:250-253`). Sets **both** columns, so a normally-rotated
   token is simultaneously _revoked_ and _rotated_. Ordering matters: step 4's
   `rotated` test runs before step 5's `revoked` test, so a replay of a
   normally-rotated token hits the family-revocation branch and not the
   quiet-deny branch. **Reversing steps 4 and 5 silently disables breach
   detection.**
7. `issuePair(family = row.family, rotatedFrom = row.id)` — **same** family, and
   the new _refresh_ row records its predecessor.

⚠️ **The predecessor's ACCESS token is not revoked on a normal rotation.** Only
the refresh row is (`:250`). So after a rotation the old access token stays
valid until its own `expires_at` — deliberate (access TTL defaults to 600s) and
the reason access TTLs are short. **Untested** — see §7.

### `rememberConsent(principal, clientId, resource, scopes): OAuthConsent` · method · `:268-285`

**Behavior** — one transaction:

1. `canonical = canonicalScopes(scopes)`.
2. ```sql
   INSERT INTO oauth_consent (principal, client_id, resource, scope) VALUES (?,?,?,?)
   ON CONFLICT (principal, client_id, resource, scope) WHERE revoked_at IS NULL
   DO UPDATE SET updated_at = now() RETURNING id
   ```
3. `consent(connection, id)!!` — re-read the full row. The `!!` is safe: the row
   was upserted in this same transaction.

⚠️ **The `DO UPDATE` set-list is `updated_at` ONLY — `created_at` is
deliberately not touched**, so the wire-visible `OAuthConsent.createdAt` keeps
the timestamp of the **first** grant of that tuple while `updatedAt` tracks the
most recent re-consent. This is the mirror image of INV-A14-20's
`COALESCE(revoked_at, now())`: both exist so a timestamp records the _first_
time something happened, and both are the kind of set-list a port "completes" by
adding the other column. Adding `created_at = now()` here would silently rewrite
consent history on every login.

🔒 **INV-A14-18 — the conflict target is a PARTIAL unique index, and both halves
of that matter.** `oauth_consent_active_tuple_uq` is
`UNIQUE (…4-tuple…) WHERE revoked_at IS NULL` (V7).

- **Idempotent while live:** re-consenting to the same tuple returns the **same
  id** and only bumps `updated_at`. Minting a new id per authorization would
  create _two live consent rows for one tuple_, and since `revokeConsent`
  revokes exactly one id, revoking one would leave tokens on the other alive.
  The partial-unique index is what makes "revoke my consent" mean _all of it_.
- **Revoked rows do not block:** re-consenting after a revocation creates a
  **new row with a new id**, leaving the revoked row in place. That is
  intentional — `revoked_at` is a timestamp, not a delete, so _"an audit reader
  can still see a consent that once existed"_ (V7 comment).

**Go shape:** the partial-index `ON CONFLICT … WHERE` target is
Postgres-specific and must be reproduced exactly; `ON CONFLICT (cols)` without
the `WHERE` predicate **will not match this index** and errors at runtime.

### `findActiveConsent(principal, clientId, resource, scopes): OAuthConsent?` · method · `:287-300`

Plain SELECT on the 4-tuple with `canonicalScopes(scopes)` and
`revoked_at IS NULL`; at most one row by INV-A14-18. No transaction. Used by A11
to decide whether to skip the consent screen (`OAuthRoutes.kt:185,320`).

### `listConsents(principal): List<OAuthConsent>` · method · `:302-310`

`WHERE principal = ? AND revoked_at IS NULL ORDER BY updated_at DESC`. Served by
`oauth_consent_principal_idx`, which is **partial**:
`ON oauth_consent (principal) WHERE revoked_at IS NULL` (V7:22) — the predicate
matches this query's exactly. Recreate the `WHERE` clause; a plain
`CREATE INDEX … (principal)` is a different, larger object and stops matching
once revoked rows accumulate (and they always accumulate — nothing purges them,
Q9). `Unverified` as a plan claim; no `EXPLAIN` was run. ⚠️ No tiebreaker, so
rows sharing `updated_at` come back in an unspecified order. Minor wire
non-determinism on `GET /oauth/consents`. **REPRODUCE** (**F34**, index F67) —
the order is observable, and adding `, id DESC` during the port turns every
ordering difference the conformance harness sees into a triage item
indistinguishable from a real regression. Add the tiebreaker afterwards, on its
own.

### `revokeConsent(id: Long, principal: String): Boolean` · method · `:312-325`

**Behavior** — one transaction:

1. `UPDATE oauth_consent SET revoked_at = now(), updated_at = now() WHERE id = ? AND principal = ? AND revoked_at IS NULL`.
   `0` rows ⇒ return `false`.
2. `UPDATE proxy_token SET revoked_at = COALESCE(revoked_at, now()) WHERE consent_id = ? AND kind IN ('MCP_ACCESS','MCP_REFRESH')`
   — cascade to **every** token issued under the consent, across all families.
3. `true`.

🔒 **INV-A14-19 — the ownership check is a SQL predicate, so IDOR is impossible
even if a route forgets.** `AND principal = ?` means passing someone else's
consent id revokes nothing and returns `false`. A11's route supplies
`user.principal` from the session (`OAuthRoutes.kt:305`) _and_ requires a CSRF
header, but this store-level predicate is the one that cannot be bypassed. Same
architectural choice as A2 INV-A2-20 (origin guards in the store, under a lock).

🔒 **INV-A14-20 — `COALESCE(revoked_at, now())` preserves the FIRST revocation
timestamp.** A plain `SET revoked_at = now()` would rewrite history every time a
revoke re-ran, and the earliest revocation time is the audit-relevant one. Same
idiom in `revoke` (`:339`) and `revokeFamily` (`:397`) — all three must keep it.

**INV-A14-21 — revoking a consent does not delete outstanding authorization
codes, and does not need to.** `consumeAuthorizationCode`'s step 5 re-checks
`consentActive`, so an outstanding code becomes unredeemable.
`McpOAuthStoreDbTest` case 3 asserts all three effects together: the code cannot
be exchanged, the live access token stops resolving, and the refresh token
cannot rotate. A second `revokeConsent` returns `false` (`:105`) — idempotent,
not an error.

⚠️ The `kind IN ('MCP_ACCESS','MCP_REFRESH')` filter in step 2 is **provably
redundant today**: V7's CHECK forces `consent_id IS NULL` for every non-MCP
kind, so no other row can match `consent_id = ?`. Keep it — it documents intent
and survives a constraint relaxation — but do not read it as evidence that
non-MCP rows can carry a consent.

### `revoke(token: String)` · method · `:327-341`

KDoc, quoted verbatim (`:327`): _"RFC 7009: access closes only itself; refresh
closes its entire rotation family."_

**Behavior** — one transaction:

1. `SELECT id, kind, refresh_family FROM proxy_token WHERE token_hash = ? FOR UPDATE`.
   No row ⇒ `Unit`.
2. `kind == MCP_REFRESH` ⇒ `revokeFamily(family)`.
3. `else if (kind == MCP_ACCESS)` ⇒ revoke that one row with the `COALESCE`
   idiom.
4. **Any other kind ⇒ silent no-op.**

🔒 **INV-A14-22 — the `else if` is a containment boundary, not style.** A11's
`/oauth/revoke` is **unauthenticated** (`OAuthRoutes.kt:283-287`: it reads a
form parameter and calls straight through). A bare `else` branch — or a future
refactor to "revoke whatever row matched" — would let that endpoint revoke a
daemon `SESSION`, a `USER` PAT, an `EDITOR` or an `APPROVER_EXEC` token. The
caller must already hold the plaintext token, so it is not a blind DoS, but
restricting by kind means a leaked wire token cannot be destroyed through the
OAuth surface.

🔒 **INV-A14-23 — an unknown token is a silent success.** RFC 7009 requires
`200` for a token the server does not recognize, so revocation must not become
an existence oracle. The `?: return@inTransaction Unit` (`:336`) is that
requirement; A11's route always responds `200 {}` regardless (`:286`).

**INV-A14-24 — asymmetry between access and refresh revocation is the point.**
Revoking an access token must not log the client out (it can still refresh —
`McpOAuthStoreDbTest` case 4 asserts the rotation _succeeds_ after an access
revoke, `:116`); revoking a refresh token must end the whole grant. Collapsing
either direction breaks a documented RFC 7009 behaviour.

### `private fun issuePair(connection, principal, clientId, resource, scope, consentId, family, accessTtlSeconds, refreshTtlSeconds, rotatedFrom): OAuthTokenPair` · `:343-360`

1. `access = randomSecret("pma_")`, `refresh = randomSecret("pmr_")`.
2. `insertToken(access, MCP_ACCESS_KIND, ttl = accessTtl, rotatedFrom = null)`.
3. `insertToken(refresh, MCP_REFRESH_KIND, ttl = refreshTtl, rotatedFrom = rotatedFrom)`.
4. `OAuthTokenPair(access, refresh, expiresIn = clampTtlSeconds(accessTtlSeconds), scope = scope)`.

⚠️ `rotated_from` is recorded **only on the refresh row**. The rotation lineage
is therefore traceable through refresh tokens alone; the access token has no
predecessor of its own. Deliberate.

### `private fun insertToken(connection, token, kind, principal, clientId, resource, scope, family, consentId, ttlSeconds, rotatedFrom)` · `:362-392`

```sql
INSERT INTO proxy_token
  (token_hash, kind, principal, roles, expires_at, resource, client_id, scope, refresh_family, consent_id, rotated_from)
VALUES (?, ?, ?, '[]'::jsonb, now() + (?::bigint * interval '1 second'), ?, ?, ?, ?, ?, ?)
```

- `setLong(4, clampTtlSeconds(ttlSeconds))`.
- `roles` is the **literal** `'[]'::jsonb`, never a parameter.
- `name` and `last_used_at` are left at their defaults (NULL).
- `rotated_from` bound through `setNullableLong` (`:478-480`), `Types.BIGINT`
  for null. Column shape (V7:70):
  `rotated_from BIGINT REFERENCES proxy_token(id) ON DELETE SET NULL` — a
  **self-referencing** FK with `ON DELETE SET NULL`, so purging an ancestor
  token severs the lineage chain without cascading the delete through the whole
  family. A Go port that omits `ON DELETE SET NULL` turns any future
  `proxy_token` sweeper (Q9) into an FK-violation error instead of a lineage
  truncation.
- `consent_id BIGINT REFERENCES oauth_consent(id)` (V7:69) is **nullable at the
  column level** — nullability is forced per-kind by
  `proxy_token_mcp_metadata_ck` (NOT NULL for MCP kinds, NULL for the rest), not
  by the column type. That is why non-MCP kinds can coexist in this table at
  all.

🔒 **INV-A14-25 — an MCP token carries NO role snapshot.** `roles = '[]'` is
hardcoded, and V7's CHECK _requires_ `roles = '[]'::jsonb` for MCP kinds. An MCP
token's authority is (consent scope) ∧ (roles resolved **live** at each tool
call — A11 INV-A11-8). Baking roles into the token would make a role revocation
invisible until expiry. `McpOAuthStoreDbTest` case 1 asserts `roles == "[]"` on
the stored row (`:74`).

🔒 **INV-A14-26 — `expires_at` is computed by Postgres from `now()`, not by the
application.** One clock for issuance across all replicas; a JVM-computed
timestamp on a skewed host could mint a token that is already expired (or lives
longer than the policy). Keep the arithmetic in SQL.

**Go shape:** the `?::bigint * interval '1 second'` cast is required — binding
an interval directly is driver-dependent. Keep it as a bigint parameter
multiplied by a literal interval.

### `private fun revokeFamily(connection, family: String?)` · `:394-399`

`if (family == null) return` then
`UPDATE proxy_token SET revoked_at = COALESCE(revoked_at, now()) WHERE refresh_family = ? AND kind IN ('MCP_ACCESS','MCP_REFRESH')`.
Served by `proxy_token_mcp_family_idx`, again **partial** —
`ON proxy_token (refresh_family) WHERE kind IN ('MCP_ACCESS','MCP_REFRESH')`
(V7:96-97) — whose predicate is byte-for-byte the `kind IN (…)` filter in this
UPDATE. That is _why_ the redundant-looking `kind` filter is in the statement at
all: without it the partial index cannot be used. So the `kind IN (…)` here is
**not** the same "documents intent" redundancy as the one in `revokeConsent` —
dropping it costs the index. `Unverified` as a plan claim; no `EXPLAIN` was run.
The null guard exists because `revoke` reads `refresh_family` from a row of
_any_ kind, where it is NULL by the V7 CHECK — so a non-MCP row reaching here is
a no-op rather than a `WHERE refresh_family = NULL` full-table scan-and-miss.

### `private fun consentActive(connection, id, principal, clientId, resource, scope): Boolean` · `:401-420`

`SELECT revoked_at IS NULL FROM oauth_consent WHERE id = ? AND principal = ? AND client_id = ? AND resource = ? AND scope = ?`
→ `result.next() && result.getBoolean(1)`.

🔒 The same **five-column** tuple as `resolveAccess`'s JOIN (INV-A14-10), for
the same reason: a consent whose tuple no longer matches the token/code is
treated as _absent_, not as _present and active_. A missing row and a revoked
row both yield `false` — one predicate, two failure modes, fail-closed on both.

### `private fun consent(connection, id): OAuthConsent?` · `:422-427` · `private fun ResultSet.toConsent()` · `:429-437`

Row → DTO. `toConsent` is the single place `created_at`/`updated_at` are
rendered as `Instant.toString()` (see §1's formatting warning). Both are
declared on `java.sql.ResultSet` / `Connection` by fully-qualified name rather
than by import — cosmetic, no port consequence.

### `private fun java.sql.PreparedStatement.setNullableLong(index: Int, value: Long?)` · `McpOAuth.kt:478-480`

The area's only **top-level** (file-scope, outside any class) private
declaration besides `secureRandom`.
`if (value == null) setNull(index, Types.BIGINT) else setLong(index, value)`.
One caller: `insertToken`'s `rotated_from` bind (`:389`).

Why it must exist rather than being inlined: JDBC's `setLong` cannot express SQL
NULL (`Long` is a primitive), and `setNull` **requires the target SQL type**, so
`Types.BIGINT` is not decoration — passing the wrong type code to a Postgres
`BIGINT` column is a driver error, not a silent coercion. **Go shape:** this
helper disappears — `database/sql` maps a nil `*int64` (or `sql.NullInt64{}`) to
NULL with no type code. Do not port the function; port the _nullability_ of
`rotated_from`, which is the only thing it encodes.

---

## 6. `Oidc.kt` and `OidcDirectoryProvisioner.kt`

### `class OidcDiscovery(private val http: HttpClient, private val issuer: String)` · `Oidc.kt:35-51`

State: `private val mutex = Mutex()` (a **coroutine** mutex, not a JVM lock) +
`@Volatile private var cached: OidcDiscoveryDocument?`.

#### `suspend fun document(): OidcDiscoveryDocument`

1. `cached?.let { return it }` — lock-free fast path.
2. Under `mutex.withLock`, **re-check** `cached` (double-checked locking).
3. `http.get(discoveryUrl()).body()`.
4. `require(document.issuer.trimEnd('/') == issuer.trimEnd('/')) { "OIDC discovery issuer mismatch" }`.
5. Cache and return.

`discoveryUrl() = "${issuer.trimEnd('/')}/.well-known/openid-configuration"`
(`:50`).

🔒 **INV-A14-27 — the discovered `issuer` must match the configured one.** The
document dictates `token_endpoint` and `jwks_uri`; without this check a hijacked
or misconfigured discovery URL would point signature verification at
attacker-controlled keys. Trailing slashes are normalized on **both** sides
because IdPs are inconsistent about them.

**INV-A14-28 — the coroutine `Mutex` is required, not interchangeable with a JVM
lock.** `document()` is `suspend` and the guarded body performs suspending I/O.
A `synchronized` block around a suspension point either fails to compile or
blocks a shared dispatcher thread for the duration of a network call. **Go
shape:** `sync.Mutex` is fine (Go has no coloured functions), but the
double-check must stay — a plain `sync.Once` changes the failure semantics
below.

⚠️ **Cache lifetime is unbounded and there is no invalidation.** A change to the
_location_ of `jwks_uri` is never picked up without a restart. Key **rotation**
is still handled, because Nimbus's `RemoteJWKSet` refetches on an unknown `kid`
— but only within one validation call (see the next symbol). **F35.**

**Failure semantics to preserve:** all three failure modes throw and leave
`cached == null`, so the next call retries — (a) a non-2xx, because
`oidcHttpClient` sets `expectSuccess = true`; (b) a deserialization failure,
i.e. INV-A14-1's four missing-field cases; (c) the `require(issuer match)` at
`:44`, which throws `IllegalArgumentException` **inside** `mutex.withLock` —
`withLock` releases in a `finally`, so the lock is not leaked, and
`cached = document` at `:45` is never reached. A `sync.Once`-based Go port would
cache the _failure_ and never retry, which is a different product: it converts a
transient IdP blip into a login outage that survives until restart. There is
**no negative caching, no timeout, no retry, no backoff** at this layer. Note
also that `document()` propagates all three as exceptions into whatever called
it. There are exactly three call sites outside this module
(`grep -rn '\.document()'` over `control-plane/src`): `Oidc.kt:101`
(`GET /auth/oidc/login`), `Oidc.kt:160` (the callback's token exchange) and
`DaemonSession.kt:715` (daemon liveness). **None of the three wraps it** —
`IdTokenValidator.validate` swallows discovery failures because it calls
`document()` inside its own `try` (INV-A14-29), but `/auth/oidc/login` does not,
so a misconfigured `PM_OIDC_ISSUER` surfaces as a **500 on the login redirect**,
not as `common.oidc_not_configured`. Same shape as F30 one layer up.

### `class IdTokenValidator(discovery, issuer, clientId)` · `Oidc.kt:60-94`

#### `suspend fun validate(idToken: String, expectedNonce: String?): ValidatedIdToken?`

**Contract:** returns claims for a token that verifies against the IdP's JWKS
and satisfies issuer, audience, expiry and (optionally) nonce — otherwise
`null`. **Never throws.**

**Behavior:**

1. Entire body in
   `try { … } catch (e: Exception) { log.warn("id_token validation failed", e); null }`
   (`:89-92`). 🔒 **INV-A14-29 — fail closed, and log once.** No validation
   failure ever propagates into a login route; `null` means "not authenticated".
   Also: the _reason_ is logged server-side and never returned to the client, so
   the login endpoint is not an oracle for which check failed.
2. Inside `withContext(Dispatchers.IO)`: 🔒 **INV-A14-29b — the `Dispatchers.IO`
   hop is load-bearing and the reason is not written down in the source.** Two
   different kinds of I/O happen inside this block: `discovery.document()` is a
   _suspending_ ktor call (safe anywhere), but `RemoteJWKSet` +
   `processor.process` fetch the JWKS through Nimbus, which is a **blocking**,
   non-suspending Java API — the network round-trip happens on whatever thread
   calls it. Without `withContext(Dispatchers.IO)` that blocking fetch runs on a
   Ktor request-dispatcher thread and, under login bursts against a slow IdP,
   starves the server's event loop. `Hypothesis` on the specific mechanism: I
   did not inspect `nimbus-jose-jwt` 9.40's internals (the jar is not present in
   any local Gradle/Maven cache —
   `find ~/.gradle ~/.m2 -name 'nimbus-jose-jwt-9.40*.jar'` ⇒ no output), so
   treat "Nimbus blocks" as the strongly-implied-but-unverified reason for the
   dispatcher hop. **Go has no coloured functions and no dispatcher, so this
   line vanishes in the port — but the underlying fact must not: `validate`
   performs a synchronous outbound HTTP request and needs a context deadline.**
   - `RemoteJWKSet<SecurityContext>(URL(discovery.document().jwks_uri))` — ⚠️
     **constructed per call**, so Nimbus's internal JWK cache is thrown away
     every time and **every `id_token` validation refetches the JWKS**. A hot
     login path hammers the IdP's `jwks_uri`. Observable consequence to keep in
     mind: a rotated key takes effect _immediately_ here, where a caching port
     would lag. **F36.**
   - `jwsKeySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)`.
     🔒 **INV-A14-30 — the signature algorithm is PINNED to RS256.** An
     `alg: none` token, an HMAC-signed token (the classic algorithm-confusion
     attack, where the public key is used as an HMAC secret), and an
     `ES256`/`PS256` token are all rejected. A Go port must pin the same single
     algorithm; accepting "any asymmetric alg" widens the accepted set and
     reintroduces confusion attacks.
   - `jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(JWTClaimsSet.Builder().issuer(issuer).audience(clientId).build(), setOf("exp"))`
     (`Oidc.kt:73-76`). This is the **two-argument**
     `(exactMatchClaims, requiredClaims)` constructor — note which one, because
     the three-argument overload takes an `acceptedAudience` and has _different_
     audience semantics. Consequences, split by how well each is evidenced:
     - 🔒 `iss` must equal `issuer` exactly (no trailing-slash normalization
       here, unlike `OidcDiscovery.document()` which normalizes both sides — so
       a port must **not** normalize `iss`). Pinned by `IdTokenValidatorTest`
       case 5 (`a wrong issuer fails closed`).
     - `exp` is listed as required. `nbf`, `iat`, `sub` and `azp` are **not** in
       `requiredClaims` and are not exact-matched, so `azp` is never checked at
       all and `sub` is enforced only by the app-level `?: return null` at
       step 3.
     - ⚠️ `Hypothesis:` **audience is compared for EQUALITY against a
       single-element list, not "contains".**
       `JWTClaimsSet.Builder().audience(clientId)` stores `aud` as a one-element
       `List<String>`, and with no `acceptedAudience` the 2-arg constructor
       treats `aud` as just another exact-match claim. If that reading is right,
       an `id_token` carrying `aud: ["<clientId>", "<other>"]` — which **Okta
       and Entra do emit** when a second resource is requested — is
       **rejected**, and a Go port written with the usual
       `contains(aud, clientId)` semantics would _accept_ it: a widening
       divergence in an authentication path. I could **not** verify this against
       the library (jar absent from all local caches, see above) and the suite
       does not decide it either: `IdTokenValidatorTest.kt:83` defaults
       `audience: String = clientId` and case 4 only tries a _wrong single_
       audience (`IdTokenValidatorTest.kt:133-135`). **Resolve before porting —
       Q11, coverage gap 13, F43.**
     - `Unverified:` the "Nimbus default 60-second clock skew on `exp`/`nbf`"
       figure. In-repo circumstantial evidence only:
       `IdTokenValidatorTest.kt:146` builds its expired token with
       `expiresInSeconds = -60`, i.e. exactly on a 60-second skew boundary,
       which fails closed only if the default skew is **≤ 60s**. That constrains
       the value but does not establish it. Confirm against `nimbus-jose-jwt`
       9.40 and then set the Go verifier's leeway explicitly rather than
       inheriting a library default.
   - `processor.process(idToken, null)`. Only `jwsKeySelector` is set — no
     `jweKeySelector` — so per `DefaultJWTProcessor`'s contract an unsecured
     (`alg: none`) JWT and any JWE are rejected before key selection.
     `Unverified` (same missing-jar reason); it is the same fail-closed
     direction either way.
3. `subject = claims.subject ?: return null` — a token with no `sub` is
   rejected.
4. `actualNonce = claims.getClaim("nonce") as? String`;
   `if (expectedNonce != null && actualNonce != expectedNonce) return null`. 🔒
   **INV-A14-31 — the nonce is checked only when the caller supplies one.**
   `expectedNonce == null` skips the check entirely, and A4 uses both modes
   deliberately: the web authorization-code flow passes the session-stored nonce
   (`Oidc.kt:175` in the control-plane), while the daemon **liveness re-check**
   passes `expectedNonce = null` (`DaemonSession.kt:721`) because a
   refresh-grant `id_token` legitimately carries no nonce. Replay protection is
   therefore the **caller's** obligation, and a Go port must keep the parameter
   nullable rather than making the check unconditional — doing so breaks daemon
   liveness. A non-`String` nonce claim becomes `null` via `as?` and then
   mismatches ⇒ rejected. Comparison is a plain `!=`, not constant-time.
5. `email = claims.getClaim("email") as? String` — a non-string claim silently
   becomes `null`.
6. `groups = (claims.getClaim("groups") as? List<*>)?.mapNotNull { it as? String } ?: emptyList()`.

⚠️ 🔒 **INV-A14-32 — a `groups` claim of the wrong SHAPE silently becomes an
EMPTY list, and that is a live-gap candidate.** Some IdPs emit a single group as
a bare string rather than a one-element array; some emit a comma-joined string.
Either shape fails `as? List<*>` and yields `emptyList()`. Combined with
INV-A14-35 — `OidcDirectoryProvisioner` **reconciles** membership to exactly the
claim — an IdP claim-shape change **strips every group from every user on their
next login, including `system:admin`**, with no error anywhere:
`IdTokenValidatorTest`'s own case 8 (_"a missing groups claim resolves to an
empty list, not a failure"_) documents the intended behaviour for a _missing_
claim, and a _malformed_ one takes the same path. Non-string elements inside a
valid list are dropped individually by `mapNotNull`, which is the same hazard at
element granularity. **F37 — the highest-severity finding in this area.**

### `fun oidcHttpClient(): HttpClient` · `Oidc.kt:96-101`

`HttpClient(CIO) { expectSuccess = true; install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }`.

- `expectSuccess = true` ⇒ non-2xx throws (see `OidcDiscovery`'s failure
  semantics).
- `ignoreUnknownKeys = true` ⇒ provider-specific extra discovery fields do not
  fail the parse.
- ⚠️ **No timeout, no retry, no connection limits, no proxy or TLS
  configuration.** No `HttpTimeout` plugin is installed, so a hung IdP stalls
  whatever coroutine is fetching discovery or the token endpoint. **F38.**
- ⟦LIB⟧ **HTTP client with JSON decoding, configurable per-request timeout, and
  lenient unknown-field handling.**
- ⟦LIB⟧ **JWT signature verification with remote JWKS fetch, `kid` selection,
  and single-algorithm pinning** (what `nimbus-jose-jwt` provides today).

### `data class OidcGroupMapping(val map: Map<String, String>, val prefix: String?)` · `Oidc.kt:103-126`

#### `fun resolve(idpGroups: List<String>): Set<String>` · `:104-109`

`idpGroups.mapNotNullTo(LinkedHashSet()) { group -> map[group] ?: run { … } }`

1. **Explicit `map[group]` wins unconditionally** — including a target inside
   the reserved namespace.
2. Otherwise: strip `prefix` if `prefix != null && group.startsWith(prefix)`
   (**case-sensitive** strip).
3. `raw.ifBlank { null }` — drop a name that is blank after stripping.
4. `.takeUnless(::isReservedGroupName)` — drop anything starting `system:`,
   **case-insensitively**.
5. Collected into a `LinkedHashSet` ⇒ dedupe, order = first appearance in
   `idpGroups`.

🔒 **INV-A14-33 — the unmapped fallback can NEVER reach the `system:`
namespace.** Without this an IdP group literally named `system:admin` — or
`proxy-monster-system:admin` under a prefix — would self-assign the seeded admin
group on first login. The exclusion is case-insensitive so no fold variant slips
through. `OidcGroupMappingTest` case 6 pins all four sub-cases (raw,
prefix-stripped, case-folded, and "non-reserved group alongside a reserved one
still resolves").

🔒 **INV-A14-34 — but an EXPLICIT map entry MAY target `system:`, and that
asymmetry is the whole design.** `map` comes from `PM_OIDC_GROUP_MAP`, an
operator-set environment variable (`Config.kt:166`) — trusted input. The IdP's
claim is untrusted input. The trusted map **is** the admin path; the untrusted
claim is not. Case 7 pins it. A port that applies the reserved-name filter
uniformly to both branches locks operators out of ever granting `system:admin`
via SSO.

#### `companion object` · `:111-125`

- `const val RESERVED_GROUP_PREFIX = "system:"`.
- `fun isReservedGroupName(name) = name.startsWith(RESERVED_GROUP_PREFIX, ignoreCase = true)`.
  ⚠️ Note this is a **name-prefix** notion of "reserved", while A3's route-level
  guard uses a **column** notion (`isSystemGroupByName` tests
  `app_group.source = 'SYSTEM'`, `Users.kt:319-324`). Two independent
  definitions of "protected group" that happen to coincide for the seeded rows.
  Not a bug; a port should not merge them without checking both call sets.
- `fun parse(mapEnv: String?, prefixEnv: String?): OidcGroupMapping`:
  1. `mapEnv.orEmpty().split(',')`, per entry: `if ('=' !in entry) skip`.
  2. `idp = entry.substringBefore('=').trim()`,
     `local = entry.substringAfter('=').trim()` — so `a=b=c` ⇒ `a` → `b=c`
     (everything after the **first** `=`).
  3. Either side blank ⇒ skip. So `junk`, `=x`, `y=` are all dropped (case 1
     asserts exactly these).
  4. `.toMap()` — on a `List<Pair>`, **the last duplicate key wins**.
  5. `prefix = prefixEnv?.takeIf { it.isNotEmpty() }` — empty string ⇒ `null`.
     ⚠️ `isNotEmpty`, not `isNotBlank`: a prefix of `" "` survives, asymmetric
     with the `isBlank` check on map entries. Harmless, but replicate it or note
     the divergence. **F39.**
  6. No validation that `local` is a legal group name; internal whitespace is
     preserved.

**Go shape:** parse into `map[string]string` + `*string`. The `mapEnv == nil`
and `mapEnv == ""` cases must both produce an **empty map, not nil-deref** —
`"".split(',')` yields `[""]` in Kotlin, which then fails the `'=' !in entry`
test, so the result is an empty map. Go's `strings.Split("", ",")` also returns
`[""]`; the behaviour coincides, but only by accident.

### `class OidcDirectoryProvisioner(private val dataSource: DataSource)` · `OidcDirectoryProvisioner.kt:10`

**Lifecycle:** constructed **per call**, not once — `Users.kt:350` reads
`com.ridi.oss.proxymonster.auth.OidcDirectoryProvisioner(dataSource).provision(…)`,
so a fresh instance is allocated on every login
(`grep -rn 'OidcDirectoryProvisioner('` finds that one site only). Free, because
the class holds nothing but the `DataSource`, but it means there is **no place
to hang per-principal state** — which is exactly why the concurrency note at the
end of this section has no lock to point at.

#### `fun provision(principal, email: String?, idpGroups: List<String>, mapping = OidcGroupMapping(∅, null)): Long`

Returns the `app_user.id`. One hand-rolled transaction (`autoCommit = false` …
`commit` / `rollback` … `finally autoCommit = true`, `:17-59`) — same shape and
same caveats as `inTransaction` above.

**Behavior:**

1. **Upsert the user:**
   ```sql
   INSERT INTO app_user (principal, email, source, active) VALUES (?, ?, 'OIDC', TRUE)
   ON CONFLICT (principal) DO UPDATE
     SET email = COALESCE(EXCLUDED.email, app_user.email), source = EXCLUDED.source
     WHERE app_user.source <> 'SCIM'
   ```
   🔒 **INV-A14-35 — SCIM wins, and the conflict is ABSORBED rather than
   raised.** The `WHERE app_user.source <> 'SCIM'` on the `DO UPDATE` leaves a
   SCIM-managed row **completely** untouched (email, source, active) while still
   letting the login succeed. A3's doc states the rule: _"never clobbers a
   `source=SCIM` user — SCIM is authoritative once it manages a principal"_
   (`Users.kt:331-332`). 🔒 `email = COALESCE(EXCLUDED.email, app_user.email)` —
   a login whose `id_token` omits `email` must not **erase** a known address.
   (Note A4 derives the principal as `claims.email ?: claims.subject`
   (`Oidc.kt:182`, `DaemonSession.kt:726`), so an email-less token also changes
   the identity key; that is A4's concern, but it means this branch is
   reachable.) 🔒 **INV-A14-36 — `active` is set only on INSERT, so a JIT login
   CANNOT reactivate a deactivated account.** The `DO UPDATE` set-list is
   `email, source` and deliberately omits `active`. This is the containment for
   A3's deprovisioning: without it, anyone deactivated could simply log in again
   and resurrect themselves. ⚠️ **There is no comment saying so** — the
   invariant lives only in the shape of the set-list, which is exactly the kind
   of thing a port "tidies up". §8 Q2.
2. `userId = connection.userId(principal) ?: error("OIDC provision did not leave an app_user row for '$principal'")`
   (`:30-31`). A defensive assertion: after step 1 the row exists whether
   inserted, updated, or left alone (the SCIM case). Throwing
   `IllegalStateException` rolls the transaction back.
3. `targetGroups = mapping.resolve(idpGroups).mapTo(LinkedHashSet()) { connection.ensureGroup(it) }`.
4. `currentGroups = connection.groupIds(userId)` — **every** `group_member` row
   for the user, regardless of the group's `source`.
5. Batch
   `INSERT INTO group_member (group_id, user_id) VALUES (?, ?) ON CONFLICT DO NOTHING`
   for `targetGroups - currentGroups`.
6. Batch `DELETE FROM group_member WHERE group_id = ? AND user_id = ?` for
   `currentGroups - targetGroups`.
7. `commit()`, return `userId`.

🔒 **INV-A14-37 — membership is FULLY RECONCILED to the claim, not merged into
it.** Dropping a user from the IdP admin group revokes their `system:admin` on
their next login. A3's doc states the rule and its accepted cost verbatim
(`Users.kt:335-341`):

> _"[idpGroups] is resolved through [mapping] to the authoritative pm-group set,
> then the user's membership is reconciled to exactly it — added where missing,
> REMOVED where no longer claimed (so dropping someone from the IdP admin group
> revokes their `system:admin` on their next login). OIDC is authoritative for
> an OIDC user's membership; a manual/SCIM group assignment for that user is
> reconciled away (accepted for now — no membership-origin column yet; see the
> backlog)."_

⚠️ **A stale contradicting KDoc sits immediately above it.** `Users.kt:328-333`
— a _second_, earlier KDoc block on the same function — says _"additively mirror
`groups` into local group membership. **Never removes a membership** (SCIM push
is the only path that revokes `group_member` rows)"_. That is the pre-change
behaviour and is now false. Two consecutive KDoc blocks on one declaration;
Kotlin attaches the **last** one. A reader (or a port author) landing on the
first block will implement the wrong semantics. **F40.**

🔒 **INV-A14-38 — this path deliberately bypasses the route-level SYSTEM-group
immutability guard**, quoted from `Users.kt:341-342`: _"The internal add/remove
intentionally bypasses the route-level SYSTEM-group immutability guard:
membership of `system:admin` is system-managed here, not hand-edited."_ So a
port must **not** route these two writes through A3's guarded group-membership
service.

#### `private fun Connection.ensureGroup(name: String): Long` · `:68-76`

```sql
INSERT INTO app_group (name, source) VALUES (?, 'OIDC')
ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
RETURNING id
```

🔒 **INV-A14-39 — the `DO UPDATE SET name = EXCLUDED.name` is a deliberate NO-OP
self-assignment, and changing it to touch `source` is a privilege-escalation
bug.** Two things depend on the exact shape:

1. It exists only so `RETURNING id` fires on conflict —
   `ON CONFLICT DO NOTHING … RETURNING id` returns **no row** in Postgres, and
   the `!!`-style `result.next(); getLong(1)` at `:75` would then throw.
2. Because it does not touch `source`, an **existing** group keeps its own
   source. A group already `SCIM` or `SYSTEM` is **not** flipped to `OIDC`. A
   port "simplifying" to `DO UPDATE SET source = 'OIDC'` would flip the seeded
   `system:admin` group to `source = 'OIDC'` and defeat every A3 guard keyed on
   `source = 'SYSTEM'` (`Users.kt:315-324` names the exact attack for the SCIM
   path). A3's `ProvisionMergeDbTest` case _"provisionFromOidc reuses an
   existing group's source, whatever it is"_ pins this — counted in A3, not
   here.

⚠️ Minor cost: the no-op UPDATE still takes a row lock and writes a dead tuple
on every login for every claimed group.

⚠️ **Stale schema comment:** V1 documents `app_user.source` and
`app_group.source` as `-- LOCAL | SCIM` (`V1__identity.sql:22,32`), but this
module writes `'OIDC'` to both and A3 relies on `'SYSTEM'`. Four values, two
documented. **F41.**

#### `private fun Connection.userId(principal): Long?` · `:62-66` · `private fun Connection.groupIds(userId): Set<Long>` · `:78-84`

Straight lookups.

**Concurrency:** there is **no advisory lock and no row lock on the user**, so
two concurrent logins for the same principal can interleave their add/delete
deltas. With `ON CONFLICT DO NOTHING` on the insert and an idempotent delete,
two logins computing the _same_ target set are harmless; two logins with
_different_ claims can leave either result, and transiently a union or an
intersection. Untested — see §7. Contrast A11's `replaceDirectRoles`, which does
take an advisory lock (A11/F19).

**JDBC detail for the port:** `executeBatch()` with **zero** added batches is
legal and returns an empty array, so an empty delta is a no-op rather than an
error. A Go port building `IN (...)` or a `COPY` must handle the empty case
explicitly.

---

## 7. Test inventory — 3 files, 302 LOC, **17 cases**

Counted with `grep -rhoE '@Test\b' --include='*.kt' <file> | wc -l`. Per-file
counts (6 / 4 / 7) each equal the number of enumerated case names below — **the
counts agree.**

**Independently re-counted during the audit pass**, same command, plus `wc -l`
for LOC: `McpOAuthStoreDbTest.kt` 216/6 · `TokenTtlTest.kt` 35/4 ·
`OidcGroupMappingTest.kt` 51/7 ⇒ 302 LOC, **17 cases**, and all 17 enumerated
names below were matched one-for-one against
`grep -nE '@Test|fun \`'` output. None of the three suites appears in any other area's already-counted inventory. The adjacent-suite LOC/case figures in the table further down were re-verified too and are all correct (`IdTokenValidatorTest`163/8,`OidcDiscoveryTest`103/4,`ProvisionMergeDbTest`398/18,`BootstrapAdminDbTest`172/8,`DaemonSessionLivenessIdpTest`433/8,`PresetPolicyDbTest`286/9,`oauth/OAuthRoutesDbTest`533/10,`McpServerDbTest`587/8 — the last one lives at`control-plane/src/test/kotlin/com/ridi/oss/proxymonster/gocp/McpServerDbTest.kt`, **not** under a `mcp/`subdirectory, unlike`OAuthRoutesDbTest`).

⚠️ **The module itself has no tests** (`auth/src/test` does not exist). All
three suites live in
`control-plane/src/test/kotlin/com/ridi/oss/proxymonster/gocp/`.

### `McpOAuthStoreDbTest.kt` — 216 LOC, 6 cases · **DB** (Testcontainers Postgres + Flyway)

The token-family security core. Fixture:
`SharedPostgres.freshDatabase("pm_mcp_oauth")` + `Flyway…migrate()` +
`requireDockerOrSkip()`; `@TestInstance(PER_CLASS)`. Constructs
`OAuthAuthorizationStore` and `McpTokenStore` directly (via
`SharedPostgres.hikari(…)`) — **no routes, no Ktor**. Constants (`:208-215`):
`CLIENT_ID = "https://client.example/mcp.json"`,
`REDIRECT_URI = "http://127.0.0.1:43110/callback"` (a loopback URI — the only
redirect shape a public MCP client can use),
`RESOURCE = "https://proxy.example/mcp"`,
`SCOPES = setOf("mcp:read", "mcp:policies:write")`, `VERIFIER = "a".repeat(43)`,
`CHALLENGE = pkceS256(VERIFIER)`.

1. 🔒
   `authorization code is one-time PKCE-bound and access tokens are audience-bound`
   — pins INV-A14-15 (second exchange ⇒ null, `:59`), INV-A14-9
   (`resolveAccess(pair.accessToken, "$RESOURCE/wrong")` ⇒ null, `:66`),
   INV-A14-6 (`token_hash` does not contain the plaintext, `:73`), INV-A14-25
   (`roles == "[]"`, `:74`), and `McpAccessIdentity` field mapping (`:62-65`).
   ⚠️ **Two mappings an earlier revision of this list got wrong; do not carry
   them into Step 3:**
   - `:56` (`consume(code, resource = "$RESOURCE/wrong")`) exercises
     `consumeAuthorizationCode`'s `row.resource != input.resource` compare
     (`:194-197`), **not** INV-A14-9 — INV-A14-9 is the `t.resource = ?` WHERE
     clause and is pinned only by `:66`. Two different mechanisms in two
     different methods; the earlier text conflated them as "both at exchange and
     at `resolveAccess`".
   - `:57` (`consume(code, verifier = "b".repeat(43))`) does **not** pin
     INV-A14-7. `"b".repeat(43)` is a **structurally valid** verifier — 43
     chars, all letter-or-digit — so it satisfies `isValidPkceVerifier` and is
     rejected by the `pkceS256(…) != row.challenge` comparison instead. The
     _shape_ half of INV-A14-7 (`isValidPkceVerifier` returning false) is
     therefore reached by **no test in the repo**. See coverage gap 3.
   - Partial credit worth recording: `assertEquals(SCOPES, identity.scopes)`
     (`:64`) _does_ round-trip `canonicalScopes` → stored string → `split(' ')`
     for a two-element ASCII set, so coverage gap 1 is "no direct test", not "no
     coverage at all".
2. 🔒 `refresh rotates once and replay revokes the complete token family` —
   INV-A14-17. Asserts the successor's refresh token is dead too.
3. 🔒 `revoked consent blocks code exchange and revokes access plus refresh` —
   INV-A14-19/21 and `consentActive` on all three paths; second `revokeConsent`
   ⇒ `false`.
4. 🔒
   `RFC 7009 access revocation is local while refresh revocation closes the family`
   — INV-A14-22/24.
5. 🔒 `authorization codes cannot borrow a mismatched or revoked consent` —
   INV-A14-15a, both halves (`assertFailsWith<IllegalArgumentException>`).
6. `issuing a code prunes expired and already-used authorization codes` — the
   opportunistic prune at `McpOAuth.kt:138`.

### `TokenTtlTest.kt` — 35 LOC, 4 cases · unit

⚠️ **Correction to the area assignment.** This suite is in package
`com.ridi.oss.proxymonster.controlplane` with **no
`import com.ridi.oss.proxymonster.auth.*`**, so `clampTtlSeconds`,
`TOKEN_MIN_TTL_SECONDS`, `TOKEN_MAX_TTL_SECONDS`, `SESSION_TTL_SECONDS` and
`DEFAULT_USER_TTL_SECONDS` all resolve to the **same-package declarations in
`Tokens.kt:75-81` (A4)**, not to `McpOAuth.kt:15-18`. It is counted here per the
area assignment, and the two implementations are byte-identical
(`ttlSeconds.coerceIn(60L, 24 * 3600L)`), so it does constrain this module's
behaviour — but **A4 must not count it again**, and Step 3 should either move it
or duplicate it against both symbols. This is **F21**.

Suite KDoc: _"Wire tokens are always expiring and bounded (DESIGN.md — no
persistent secrets). Guards the TTL clamp so a regression can't reintroduce an
unbounded (or zero/negative) token lifetime."_

1. `requests within the window are unchanged` (900, `DEFAULT_USER_TTL_SECONDS`,
   `SESSION_TTL_SECONDS`)
2. 🔒 `over-long requests are capped at 24h` (999,999 and `Long.MAX_VALUE`) —
   INV-A14-2
3. 🔒 `tiny, zero, and negative requests are floored to the minimum` (1, 0,
   −100) — INV-A14-2
4. 🔒 `every clamped ttl is a bounded, positive lifetime` — a table sweep over
   `[-1, 0, 30, 60, 3600, 86400, 86401, Long.MAX_VALUE]`

### `OidcGroupMappingTest.kt` — 51 LOC, 7 cases · unit

Pure; no DB, no HTTP. Suite KDoc: _"Pure tests for the IdP-group → pm-group
resolver (docs/backlog.md)."_ Reaches `OidcGroupMapping` through A1's
`typealias` (`Config.kt:6`).

1. `parse reads idpGroup=pmGroup pairs and ignores malformed entries` — asserts
   `junk`, `=x`, `y=` are all dropped and surrounding whitespace trimmed
2. `an explicit mapping wins over the prefix rule`
3. `an unmapped group is taken by name with the prefix stripped`
4. `no prefix keeps unmapped names as-is`
5. `a group that is blank after stripping the prefix is dropped`
6. 🔒 `the reserved system namespace is unreachable via the unmapped fallback` —
   INV-A14-33; four sub-assertions (raw `system:admin`;
   `proxy-monster-system:admin` via prefix; `System:Admin` / `SYSTEM:admin` case
   folds; a non-reserved group alongside a reserved one)
7. 🔒 `an explicit mapping may target the reserved system namespace` —
   INV-A14-34

### Adjacent suites that test THIS module's symbols but are counted elsewhere

⚠️ Recorded so nothing is lost or double-counted. **Neither of the first two is
included in the 17 above.**

🚨 **Accounting hazard the audit pass flags, in the spirit of 00-INDEX.md's own
"the LOC arithmetic is the guard against this" note.** `IdTokenValidatorTest`
(8) and `OidcDiscoveryTest` (4) test symbols whose **source lives in this area's
own files** — `IdTokenValidator`, `OidcDiscovery` and `OidcDiscoveryDocument`
are all in `auth/src/main/kotlin/.../Oidc.kt:25-94`, which A14 claims in full.
They are deferred to A4 only because A4 owns the _call sites_. That is a
defensible split, but it is asymmetric with how A14 handles `TokenTtlTest`
(counted here even though it binds to A4's symbol) and it puts **12 cases in a
position where each area can point at the other**. 00-INDEX.md's A4 row still
reads `Cases: tbd`, so nothing has claimed them yet. **A4 must count both suites
(+12).** If A4 instead defers them back to A14 on the grounds that the symbols
are A14's, the 903 reconciliation silently loses 12 cases and the loss is
invisible in every per-area total. **F44.**

| Suite                             | LOC | Cases | Tests which of my symbols                                                        | Counted in             |
| --------------------------------- | --- | ----- | -------------------------------------------------------------------------------- | ---------------------- |
| `IdTokenValidatorTest.kt`         | 163 | **8** | `IdTokenValidator.validate` (`Oidc.kt:60-94`) — the entire symbol                | **A4** (assign there)  |
| `OidcDiscoveryTest.kt`            | 103 | **4** | `OidcDiscovery.document` + `OidcDiscoveryDocument` (`Oidc.kt:25-51`)             | **A4** (assign there)  |
| `oauth/OAuthRoutesDbTest.kt`      | 533 | 10    | the store, through `/oauth/*`                                                    | A11 ✅ already counted |
| `McpServerDbTest.kt`              | 587 | 8     | `McpTokenStore.resolveAccess`, through the `/mcp` gate                           | A11 ✅ already counted |
| `ProvisionMergeDbTest.kt`         | 398 | 18    | `OidcDirectoryProvisioner.provision`, through `UserGroupStore.provisionFromOidc` | **A3**                 |
| `BootstrapAdminDbTest.kt`         | 172 | 8     | `OidcGroupMapping.resolve` + the provisioner, end to end                         | **A3/A4**              |
| `DaemonSessionLivenessIdpTest.kt` | 433 | 8     | `IdTokenValidator` (`expectedNonce = null`) + the provisioner                    | **A4**                 |
| `PresetPolicyDbTest.kt`           | 286 | 9     | `provisionFromOidc` as a fixture                                                 | A2 ✅ already counted  |

For Step 3's benefit, the two A4-assigned suites' case names (**not** counted
here): `IdTokenValidatorTest` —
`a correctly signed, matching id_token validates and surfaces claims` ·
`a nonce mismatch fails closed` ·
`the nonce check is skipped when the caller expects none (device flow)` ·
`a wrong audience fails closed` · `a wrong issuer fails closed` ·
`an expired token fails closed` ·
`a token signed by an untrusted key fails closed (bad signature)` ·
`a missing groups claim resolves to an empty list, not a failure`.
`OidcDiscoveryTest` — `document parses every field, required and optional` ·
`optional fields default to null when the IdP omits them` ·
`a trailing slash on the configured issuer is tolerated` ·
`the document is fetched once and cached across repeated calls`.

### Coverage gaps in A14

Nothing here is covered by a test that lives in this module, so every gap below
is a gap in the _control-plane_ suites too.

1. **`canonicalScopes` has no direct test at all.** INV-A14-4 calls it the most
   port-fragile function in the area — a database join key — and no suite
   asserts sort order, dedupe, trimming, or the empty case.
   `McpOAuthStoreDbTest` even hand-rolls its own
   `SCOPES.sorted().joinToString(" ")` (`:206`) rather than calling it, so the
   two could diverge and the suite would still pass. **Highest-priority new
   test.**
2. **`clampTtlSeconds` in _this_ module is untested** — the suite that looks
   like its test binds to A4's copy (F21).
3. **`sha256Hex` / `pkceS256` / `randomSecret` / `isValidPkceChallenge` /
   `isValidPkceVerifier` have no unit tests.** `pkceS256` is exercised only as a
   _fixture helper_ in three suites, which means a bug in it would be invisible:
   both sides of every assertion would use the same wrong function.
4. **`isValidPkceChallenge`'s Unicode-permissive `isLetterOrDigit`** (F29) and
   the app-vs-schema length mismatch — nothing asserts what is rejected.
5. **A normal (non-replay) rotation's effect on the PREDECESSOR ACCESS token**
   is unasserted. `McpOAuthStoreDbTest` case 2 only checks `first.accessToken`
   _after_ the replay, so "does a clean rotation leave the old access token live
   until its own expiry?" is undecided by any test.
6. **`rotateRefresh`'s JVM-vs-DB clock split** (INV-A14-16 / F32) — no skew
   test.
7. **`rotateRefresh` with a mismatched `client_id` on a replayed token** (F33) —
   the ordering that lets family revocation be side-stepped is untested.
8. **Concurrency:** `consumeAuthorizationCode`'s `FOR UPDATE` +
   conditional-UPDATE double guard, and `rememberConsent`'s partial-index
   upsert, both have race-condition rationales and **no concurrent test**. Two
   simultaneous exchanges of one code is the canonical OAuth attack and is
   unasserted.
9. **`OidcDirectoryProvisioner` has no direct test** — only indirect coverage
   through A3's `UserGroupStore.provisionFromOidc`. Specifically untested
   anywhere: INV-A14-36 (a deactivated non-SCIM user is **not** reactivated by
   logging in — a security invariant with no comment _and_ no test) and
   concurrent logins for one principal.
10. **`listConsents` ordering** (F34) and `findActiveConsent`'s canonicalization
    round-trip.
11. **`OidcDiscovery`'s failure semantics** — that a failed fetch caches nothing
    and is retried. Case 4 of `OidcDiscoveryTest` covers the success-caching
    side only.
12. 🔒 **A malformed (non-array) `groups` claim** — INV-A14-32 / **F37**.
    `IdTokenValidatorTest` case 8 covers a _missing_ claim; a _wrong-shaped_ one
    takes the identical silent-empty path and, via INV-A14-37's reconciliation,
    strips every group. **Add this test before porting.**

Gaps added by the audit pass:

13. 🔒 **A MULTI-audience `id_token`** — F43 / Q11. `IdTokenValidatorTest.kt:83`
    hard-codes a single-element `aud` for every case, and case 4 varies only
    _which_ single audience. So the repo does not decide whether
    `DefaultJWTClaimsVerifier`'s 2-arg constructor accepts
    `aud: [clientId, other]` or rejects it — and the Kotlin and the obvious Go
    implementation would differ in opposite directions. **This is the test to
    write first in Step 3, before either implementation is trusted**, because it
    is the only one whose answer changes which behaviour is "correct".
14. 🔒 **The revoke-versus-issue interleaving** (INV-A14-10b). No test issues a
    token from a `consumeAuthorizationCode` transaction that overlaps a
    `revokeConsent`, so nothing pins that the `c.revoked_at IS NULL` join
    predicate — not the token cascade — is what makes such a token unusable.
    `McpOAuthStoreDbTest` case 3 revokes strictly _after_ issuance completes,
    which the cascade alone satisfies; it would still pass against a port that
    dropped the predicate.
15. **`isValidPkceVerifier`'s shape rejection is reached by no test** (see case
    1's corrected mapping). Every "bad verifier" case in the repo uses a
    structurally valid 43-char verifier, so the first half of the `:194-197`
    disjunction is never the reason for a `null`.
16. **`OidcDiscovery`'s issuer-mismatch path** — `require(…)` at `Oidc.kt:44`.
    `OidcDiscoveryTest` case 3 covers the _tolerated_ trailing-slash direction;
    nothing asserts that a genuinely different issuer throws, nor that the throw
    leaves the cache empty. It is the check that prevents pointing signature
    verification at attacker-controlled keys (INV-A14-27) and it is unasserted.

---

## 8. Open questions

| #   | Question                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | `pkceS256` encodes the verifier as **US-ASCII** (lossy `?` substitution) while `isValidPkceVerifier` accepts Unicode letters/digits. A non-ASCII verifier therefore hashes to a preimage containing `?`, which can never itself be a valid verifier — so no PKCE downgrade appears reachable. Confirm that reasoning — but the disposition is **REPRODUCE + PIN** either way: `pkceS256` is a security path, so the port keeps the lossy US-ASCII encoding and pins it with a test. Rejecting non-ASCII outright is a narrowing, and a narrowing is its own decision.                                                                                                                                                                                       |
| Q2  | `OidcDirectoryProvisioner`'s upsert omits `active` from its `DO UPDATE`, so a JIT login cannot reactivate a deactivated account (INV-A14-36). Confirm this is deliberate against A3's `Deprovision.kt`, then **add a comment and a test** — it is currently an unstated, untested security invariant.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Q3  | `TokenTtlTest` binds to A4's `clampTtlSeconds`, not this module's (F21, index F93). The port **REPRODUCEs** both copies — duplication is not grounds for OMIT. What stays open is whether anything depends on them being separately tunable, because that decides whether a post-cutover unification is safe.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Q4  | `canonicalScopes` uses Kotlin `String.trim()` = `Character.isWhitespace \|\| Character.isSpaceChar`; Go's `strings.TrimSpace` = `unicode.IsSpace` (the Unicode `White_Space` property). The two sets differ in **both** directions — Kotlin trims the Java-specific separator controls U+001C–U+001F, which Go does not; Go trims U+0085 (NEL), which Kotlin does not (it is category `Cc`, so neither Java predicate matches). Since the result is a DB join key (INV-A14-4), pin the intended trim set with golden vectors rather than assuming the stdlib defaults agree.                                                                                                                                                                                |
| Q5  | `OidcDiscovery` caches forever with no TTL (F35, index F61). **REPRODUCE** — a restart is how a moved `jwks_uri` is picked up today, and adding a TTL changes failure behaviour under IdP maintenance, so it is a post-cutover decision, not a port task. Open: is the restart deliberate or accidental?                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Q6  | `IdTokenValidator` constructs a fresh `RemoteJWKSet` per call, so every login refetches the JWKS (F36, index F62). **REPRODUCE** — caching is strictly better for load but _delays_ key-rotation pickup, i.e. it is a behaviour change on an auth path, not an implementation detail. Confirm which property the deployment needs, then add the cache as its own decision.                                                                                                                                                                                                                                                                                                                                                                                  |
| Q7  | `createAuthorizationCode` throws `IllegalArgumentException` where every sibling returns `null`, and A11 does not catch it (F30, index F49) — a consent revoked mid-flow yields a 500 instead of an OAuth error. **REPRODUCE**: the 500 is observable, and it is exactly the sort of "obvious improvement" that would show up as an unexplained diff in the conformance harness. A typed error mapped to `invalid_request` is the right fix, taken separately.                                                                                                                                                                                                                                                                                               |
| Q8  | The `pmr_` prefix is shared by MCP refresh tokens and A4 daemon renewal tokens (F22). Renumber one of them, or accept the collision? Changing a prefix is wire-visible to `pmon`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Q9  | Nothing purges expired/revoked `proxy_token` rows or revoked `oauth_consent` rows — A1's background loop (`App.kt:405-426`) does not cover them, and `oauth_authorization_code` is swept only opportunistically inside `createAuthorizationCode`. Is unbounded growth accepted (audit retention), or is a sweeper missing?                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Q10 | `isReservedGroupName` (name prefix `system:`, case-insensitive) and A3's `isSystemGroupByName` (`app_group.source = 'SYSTEM'`) are two independent notions of "protected group" that coincide only for the seeded rows. Should they be unified, and against which definition?                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Q11 | 🔒 **Does `id_token` audience validation mean "equals `[clientId]`" or "contains `clientId`"?** `Oidc.kt:73-76` uses `DefaultJWTClaimsVerifier`'s 2-arg `(exactMatchClaims, requiredClaims)` constructor with `aud` supplied via `JWTClaimsSet.Builder().audience(clientId)` and **no** `acceptedAudience`, which reads as list equality — meaning a multi-audience token from Okta/Entra is rejected. Unresolvable from this repo (no test varies the list size; the nimbus-jose-jwt 9.40 jar is not in any local cache). Settle it against the library, then make the Go verifier's audience rule **explicit** in code rather than inheriting a library default in either language. Whichever answer is right, the _tighter_ one is the safe port target. |
| Q12 | Nothing in the repo pins `Instant.toString()`'s exact fractional-second rendering for `OAuthConsent.createdAt`/`updatedAt`, and §1 now shows Java and Go's `RFC3339Nano` diverging on any microsecond value with trailing zeros. Should the port keep bug-compatible Java-style 0/3/6-digit padding (so `web/` sees no change), or normalize to a fixed precision and update the console? Decide once and apply to A2's `CedarPolicy.updatedAt` identically.                                                                                                                                                                                                                                                                                                |

---

## 9. Findings raised by this area

New; numbered from F21 per 00-INDEX.md's instruction. **Not edited into
00-INDEX.md by this document.**

| #       | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Where                                             | Kind                           |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ------------------------------ |
| **F21** | `clampTtlSeconds`, `TOKEN_MIN_TTL_SECONDS` and `TOKEN_MAX_TTL_SECONDS` are declared **twice**, byte-identically, in `auth/McpOAuth.kt:15-18` and `control-plane/Tokens.kt:75-81`. `Config.kt:3` explicitly imports the `auth` copy while `Tokens.kt` uses its own same-package one; the project compiles, and because the two bodies and both constants are identical, which candidate Kotlin resolves is unobservable today. That is exactly the hazard: changing the cap in one place silently splits TTL policy between MCP tokens and wire tokens with no compile error. `TokenTtlTest` binds to the A4 copy                                                                                                                                            | `McpOAuth.kt:15-18`, `Tokens.kt:75-81`            | duplication                    |
| **F22** | `pmr_` prefix collision: MCP refresh tokens (`McpOAuth.kt:356`) and A4 daemon renewal tokens (`DaemonSession.kt:33-36`). Different tables, no cross-acceptance, but a leaked `pmr_…` cannot be classified by prefix during incident response                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `McpOAuth.kt:356`                                 | inconsistency                  |
| **F23** | `MCP_ACCESS_KIND` / `MCP_REFRESH_KIND` are referenced at 5 sites (`:227`, `:337`, `:338`, `:357`, `:358`) and **nowhere outside `McpOAuth.kt`**, while 3 SQL strings hardcode the literal instead (`:62`, `:322`, `:397`). A rename compiles and silently mismatches those 3 strings. _(Counts corrected in audit: previously stated as "3 sites", with `:357-358` miscategorised as hardcoded literals when they are constant uses)_                                                                                                                                                                                                                                                                                                                       | `McpOAuth.kt:13-14,62,322,397`                    | inconsistency                  |
| **F24** | V7's `proxy_token.kind` comment lists only `SESSION \| USER \| MCP_ACCESS \| MCP_REFRESH`, omitting `EDITOR` and `APPROVER_EXEC`, which exist in `TokenKind` (`Tokens.kt:34-35`) and are written by A7                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `V7__tokens.sql`                                  | stale doc                      |
| **F25** | The authorization-code TTL window `coerceIn(60, 600)` uses **inline magic numbers**, unlike the named `TOKEN_MIN/MAX_TTL_SECONDS` right above it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `McpOAuth.kt:155`                                 | inconsistency                  |
| **F26** | `auth/build.gradle.kts` declares a complete test harness — kotlin-test, HikariCP, Testcontainers core + postgresql, and a `tasks.test` block with macOS Docker-socket discovery, `api.version` pinning and Ryuk disabled — but `auth/src/test` **does not exist**. Entirely dead build configuration                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `auth/build.gradle.kts:20-46`                     | dead code                      |
| **F27** | `OAuthTokenPair` and `McpAccessIdentity` are `@Serializable` but never serialized: A11 remaps the former to a snake_case `TokenResponse` (`OAuthRoutes.kt:400`) and the latter to `McpRequestContext` (`McpServer.kt:191`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `McpOAuth.kt:82,45`                               | dead code                      |
| **F28** | `ValidatedIdToken.nonce` is populated but read by no caller (verified across `control-plane/src` + `auth/src`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `Oidc.kt:57`                                      | dead code                      |
| **F29** | `isValidPkceChallenge` / `isValidPkceVerifier` use Kotlin's **Unicode-aware** `Char.isLetterOrDigit()`, so a 43-character non-base64url challenge is accepted and stored (unredeemable, so fail-closed). Two separate mismatches, which an earlier revision blurred into "stricter in one direction and looser in the other": (a) vs the **DB CHECK** the app is _only ever stricter_ — it demands `length == 43` where `CHECK (char_length BETWEEN 43 AND 128)` (V7:39) allows 43..128, so 44..128 is unreachable and the CHECK's own comment about "the RFC 7636 length range" overstates what is accepted; (b) vs the **base64url charset** the app is _looser_, since `isLetterOrDigit` admits `ᄀ`/`é`/`٣`. The app is never looser than the CHECK     | `McpOAuth.kt:30-36`                               | inconsistency                  |
| **F30** | `createAuthorizationCode` **throws** where every sibling returns `null`, and A11's `issueAuthorizationCode` catches nothing — a consent revoked between `findActiveConsent` and `createAuthorizationCode` yields a 500 rather than an OAuth error                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `McpOAuth.kt:133,161`, `OAuthRoutes.kt:335`       | possible bug                   |
| **F31** | `consumeAuthorizationCode` issues a **second** query for `used_at IS NULL AND expires_at > now()` on data the first `FOR UPDATE` SELECT already had; because Postgres `now()` is transaction-start time and both share the transaction, the extra round-trip buys nothing                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `McpOAuth.kt:188-193`                             | inefficiency                   |
| **F32** | Two clocks decide expiry on one column: `resolveAccess` uses Postgres `now()` (`:63`) and `insertToken` computes `expires_at` in SQL (`:378`), but `rotateRefresh` compares against the **JVM** `Instant.now()` (`:237`). Under skew, an expired refresh token can rotate, or a live one be refused                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `McpOAuth.kt:237`                                 | 🔒 possible bug                |
| **F33** | In `rotateRefresh` the client/resource mismatch check (`:242`) precedes the rotated-replay check (`:243`), so replaying a stolen rotated token with a **wrong `client_id`** returns a plain `null` **without** revoking the family — the breach-detection alarm can be side-stepped                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `McpOAuth.kt:242-246`                             | 🔒 possible gap                |
| **F34** | `listConsents` orders by `updated_at DESC` with **no tiebreaker** — rows sharing a timestamp come back in an unspecified order on `GET /oauth/consents`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `McpOAuth.kt:305`                                 | contract inconsistency         |
| **F35** | `OidcDiscovery` caches the document **forever** with no TTL and no invalidation; a moved `jwks_uri` requires a restart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `Oidc.kt:37-48`                                   | possible gap                   |
| **F36** | `IdTokenValidator.validate` constructs a fresh `RemoteJWKSet` **per call**, so Nimbus's key cache is discarded and every `id_token` validation refetches the IdP's JWKS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `Oidc.kt:70`                                      | inefficiency                   |
| **F37** | 🔒 A `groups` claim of the wrong **shape** (a bare string, or a comma-joined string — both shipped by real IdPs) fails `as? List<*>` and silently becomes `emptyList()`. Because `OidcDirectoryProvisioner` **reconciles** membership to exactly the claim (INV-A14-37), an IdP claim-shape change **strips every group from every user on next login, including `system:admin`**, with no error anywhere. Untested                                                                                                                                                                                                                                                                                                                                         | `Oidc.kt:86`, `OidcDirectoryProvisioner.kt:32-51` | 🔒 **possible live gap**       |
| **F38** | `oidcHttpClient` installs no `HttpTimeout` and no retry — a hung IdP stalls discovery and the token exchange indefinitely                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `Oidc.kt:96-101`                                  | possible gap                   |
| **F39** | `OidcGroupMapping.parse` uses `isNotEmpty` for the prefix but `isBlank` for map entries, so a prefix of `" "` survives while a blank map key is dropped                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `Oidc.kt:121,123`                                 | inconsistency                  |
| **F40** | `UserGroupStore.provisionFromOidc` carries **two consecutive KDoc blocks** that contradict each other: the first (`Users.kt:328-333`) says _"Never removes a membership"_, the second (`:334-343`) says membership is _"reconciled to exactly it — added where missing, REMOVED where no longer claimed"_. The second is current; Kotlin attaches the last block, but a reader hits the first                                                                                                                                                                                                                                                                                                                                                               | `Users.kt:328-343`                                | stale doc                      |
| **F41** | V1 documents `app_user.source` / `app_group.source` as `-- LOCAL \| SCIM`, but this module writes `'OIDC'` to both and A3 relies on `'SYSTEM'` — four values, two documented                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `V1__identity.sql:22,32`                          | stale doc                      |
| **F42** | `oauth_authorization_code`'s only non-constraint index is **partial** — `ON (expires_at) WHERE used_at IS NULL` (`V7:41-42`) — while the opportunistic prune's predicate is `expires_at <= now() OR used_at IS NOT NULL`. The `OR` branch is the index's exact negation, so half the sweeper's predicate has no index at all, and the sweeper runs on **every** authorization-code issuance. Self-limiting in steady state (it deletes the used rows it scans), but it makes the one table with no background purge also the one with a half-indexed sweep. `Unverified` as a plan claim — no `EXPLAIN` was run                                                                                                                                             | `McpOAuth.kt:138`, `V7__tokens.sql:41-42`         | inefficiency                   |
| **F43** | 🔒 `Hypothesis:` `IdTokenValidator` builds `DefaultJWTClaimsVerifier` with the **2-arg** `(exactMatchClaims, requiredClaims)` constructor and supplies `aud` through `JWTClaimsSet.Builder().audience(clientId)`. With no `acceptedAudience`, `aud` is an exact-match claim, i.e. the token's `aud` list must **equal** `[clientId]` — so a legitimate multi-audience `id_token` is rejected, and conversely a Go port using the conventional `contains` check would **widen** what authenticates. Unverifiable in this environment (nimbus-jose-jwt 9.40 absent from every local Gradle/Maven cache) and undecided by the suite (`IdTokenValidatorTest.kt:83` always signs a one-element `aud`). Either way an authentication-path divergence with no test | `Oidc.kt:73-76`                                   | 🔒 possible bug / coverage gap |
| **F44** | Test-accounting hazard: `IdTokenValidatorTest` (8) + `OidcDiscoveryTest` (4) directly test symbols **defined in this area's own source** (`Oidc.kt:25-94`) but are deferred to A4 for counting, while `TokenTtlTest` is counted _here_ despite binding to A4's symbol. Opposite conventions in one document. 00-INDEX.md's A4 row is still `Cases: tbd`, so if A4 defers them back, **12 of the 903 cases vanish with no per-area total looking wrong**                                                                                                                                                                                                                                                                                                     | `14-auth.md` §7, `00-INDEX.md` A4 row             | inconsistency                  |

**Live-gap candidates from this area:** **F37** (highest — silent total
group-membership loss on an IdP claim-shape change), F43, F32, F33, F30.

**Corrections made by the audit pass** (each is a place where the earlier text
would have misled a Go implementer, not a cosmetic fix):

| Where                              | Was                                                                          | Is                                                                                                                                                                                                                 |
| ---------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| §1 `createdAt`/`updatedAt`         | "Go's `RFC3339Nano` … differs on the zero-fraction case"                     | They **agree** on zero fraction; they diverge because Java pads to 0/3/6/9 digits and Go strips all trailing zeros (`.120000` ⇒ Java `.120`, Go `.12`)                                                             |
| §3 KIND constants / F23            | "used at only three sites", `:357-358` listed as hardcoded SQL literals      | Five reference sites; `:357-358` are constant _uses_; the hardcoded set is exactly `{:62, :322, :397}`                                                                                                             |
| §3 INV-A14-5                       | `Tokens.kt`'s `token.toByteArray()` is "platform default = UTF-8 on JVM 18+" | Kotlin stdlib default argument `Charsets.UTF_8` — unconditional, no JVM-version or `file.encoding` dependency. Also: 3 implementations but 4 names (`TokenStore.hash` at `Tokens.kt:104` delegates)                |
| §4 access paths                    | "`resolveAccess` … uses `proxy_token_mcp_consent_idx`"                       | That index is on `proxy_token.consent_id` — the wrong side of this join. Its consumer is `revokeConsent`'s cascade (`:322`)                                                                                        |
| §5 `listConsents` / `revokeFamily` | index names given without their `WHERE` clauses                              | Both are **partial** indexes (`V7:22`, `V7:96-97`); `revokeFamily`'s otherwise-redundant `kind IN (…)` filter exists **to match its index predicate**                                                              |
| §7 case 1                          | `:56` pinned INV-A14-9; `:57` pinned INV-A14-7                               | `:56` pins `consumeAuthorizationCode`'s resource compare (INV-A14-9 is `:66` only); `:57` uses a structurally **valid** verifier so it pins the hash compare, leaving `isValidPkceVerifier`'s reject path untested |
| F29                                | "stricter than the DB CHECK in one direction and looser in the other"        | Never looser than the CHECK; stricter on length vs the CHECK, looser on charset vs base64url                                                                                                                       |

**Correction to the area assignment, per 00-INDEX.md's "re-check gap claims"
rule:** `TokenTtlTest` was assigned here as a test of this module's
`clampTtlSeconds`; it is in fact bound to A4's identical copy (F21). Counted
here as instructed, but A4 must not count it again.

---

## 10. Library capabilities needed (deferred)

| Capability                                                                                                                                                                                | Used for                        | Marker            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- | ----------------- |
| HTTP client with JSON decoding, lenient unknown fields, per-request timeout                                                                                                               | OIDC discovery + token exchange | ⟦LIB⟧             |
| JWT verification with remote JWKS fetch, `kid` selection, **single-algorithm pinning** (RS256), and required-claim/clock-skew verification                                                | `IdTokenValidator`              | ⟦LIB⟧             |
| Postgres driver supporting `ON CONFLICT … WHERE <partial-index-predicate> DO UPDATE … RETURNING`, `SELECT … FOR UPDATE`, `INSERT … SELECT`, batched statements, and explicit transactions | the whole store                 | ⟦LIB⟧             |
| CSPRNG + unpadded base64url                                                                                                                                                               | `randomSecret`, `pkceS256`      | stdlib — no ⟦LIB⟧ |
| SHA-256 + lowercase hex                                                                                                                                                                   | `sha256Hex`                     | stdlib — no ⟦LIB⟧ |

No Cedar dependency: this module never authorizes. It authenticates and it
persists; A2 decides.
