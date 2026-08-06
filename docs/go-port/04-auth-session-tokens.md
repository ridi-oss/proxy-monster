# A4 — Auth, Sessions, Device Login, Tokens

Files: `DaemonSession.kt` (802) · `DeviceAuth.kt` (408) · `Tokens.kt` (328) ·
`Oidc.kt` (235) · `Auth.kt` (109) · `PrincipalSessionStorage.kt` (28) ·
`OidcHttp.kt` (3) · `OidcDiscovery.kt` (4) · `IdTokenValidator.kt` (4). **Total
1,921 LOC. Fully read.**

DB tables: **`principal_session`** (V6) · **`device_login`** (V6) ·
**`proxy_token`** (V7), plus `principal_session.debug_requester_ip` (V10).
Migration text read in full: `V6__sessions.sql` (72 lines), `V7__tokens.sql`
(113), `V10__debug_requester_ip.sql` (14).

**Second-highest-risk area after A2.** Every symbol here is a
credential-issuance, credential- validation, or session-termination control.
**44 of its 65 invariants are security invariants** (🔒), and at least seven of
those exist because a specific hole was closed once already — the source names
each hole, and this document quotes each reason verbatim per the fidelity rule.
FULL depth, matching `02-authz.md`.

**Audit status (second pass).** All 15 test-suite counts, the 4 030 test LOC,
the 1 921 source LOC, all 22 `@Serializable` types, all 11 routes, and every
`App.kt`/`V6`/`V7`/`V8`/`auth-module` line citation in this file were
re-verified against source. Corrections applied: INV-A4-1's rationale was
inverted (it is the **MCP/Zod** surface that is strict, not `web/`); INV-A4-19's
quote was mis-cited to `DaemonSession.kt` when it lives only in a **test** file
(F35); three test-case cross-references were off by one
(`PrincipalSessionStoreDbTest` 7↔8); four `Oidc.kt` line citations drifted.
Added: INV-A4-65 and findings F33–F38. Two structural defects that A4 cannot fix
alone are flagged for the index: `TokenTtlTest` is double-counted with
`14-auth.md` (F37) and the `F21+` id space collides across six docs (F36).

### The three 3–4 LOC files are typealias shims — verified

```kotlin
// OidcHttp.kt (3 LOC)
fun oidcHttpClient() = com.ridi.oss.proxymonster.auth.oidcHttpClient()
// OidcDiscovery.kt (4 LOC)
typealias OidcDiscoveryDocument = com.ridi.oss.proxymonster.auth.OidcDiscoveryDocument
typealias OidcDiscovery         = com.ridi.oss.proxymonster.auth.OidcDiscovery
// IdTokenValidator.kt (4 LOC)
typealias ValidatedIdToken  = com.ridi.oss.proxymonster.auth.ValidatedIdToken
typealias IdTokenValidator  = com.ridi.oss.proxymonster.auth.IdTokenValidator
```

All three delegate to `:auth` (`auth/src/main/kotlin/.../Oidc.kt`), whose spec
is `14-auth.md`. They exist only so control-plane call sites can name these
types without importing the `:auth` package — **the Go port needs no equivalent
at all**; the types come from whatever package holds the OIDC code.
`oidcHttpClient()` is a function, not a typealias, because Kotlin has no
typealias for a function.

---

## Purpose

A4 owns every way a principal becomes authenticated and every credential the
system issues.

Four distinct credential lifecycles live here. (1) **Web console session** — a
server-side `principal_session` row of `kind='WEB'` referenced by an HMAC-signed
`pm_session` cookie carrying only an opaque tracker id, bound to a `pm_did`
device cookie, governed by an immovable absolute deadline and a sliding idle
deadline, and terminated with a recorded reason. (2) **Daemon session** — a
`kind='DAEMON'` row created by the RFC 8628 device-authorization flow, whose
`absolute_expires_at` is the hard cap on silent wire-token renewal,
authenticated for renewal by a mint-once `pmr_` bearer secret stored only as a
SHA-256 hash. (3) **Wire tokens** — `proxy_token` rows in four kinds (`SESSION`,
`USER`, `EDITOR`, `APPROVER_EXEC`), always expiring, stored only as SHA-256
hashes, validated on two different predicates depending on whether the presenter
is opening a wire session or running one already-authorized query. (4) **IdP
liveness** — a single timer-driven sweep that is the **sole revalidator** of
both session kinds against the IdP's refresh grant.

It also owns the OIDC authorization-code flow (`state` + `nonce` cookies,
id_token-only identity), the device-verification anti-phishing cookie, and the
`pm_did` device cookie.

What it does _not_ own: role resolution (A3 `RoleResolver`), the deactivation
check and per-principal advisory lock (A3 `Deprovision.kt`), the id_token
cryptography (`:auth`, `14-auth.md`), the session UX routes hosted in `App.kt`
(A1 — but A4's test suites cover them, see §4.1), and `ResultCrypto` (A7).

---

## 1. Wire contract

Every `@Serializable` type in the area. **Application-wide serializer config
matters to this table** (`App.kt:340`):
`Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }`.

🔒 **INV-A4-1 — a null field is ABSENT from the JSON, not `null`.**
`explicitNulls = false` means `WireTokenInfo(name = null)` serializes as an
object with **no `name` key**. `encodeDefaults = true` means non-null defaults
(e.g. `roles: List<String> = emptyList()`) **are** emitted. A Go port using
`encoding/json` reproduces this with `omitempty` on pointer/optional fields
**only** — `omitempty` on a slice would also drop `roles: []`, which the console
requires to be present.

⚠️ **Correction to an earlier draft of this invariant: `web/` is _not_ the
strict consumer.** The source comment (`App.kt:325-339`, read in full) says the
opposite: _"Safe for the REST API: every TS consumer already types nullable
fields `T | null` and reads them via `??`/`!= null`, which treats an absent key
and an explicit `null` identically; only the encoded byte-shape of an
already-optional field changes."_ The **only** strict consumer is the official
MCP TypeScript SDK's Zod schemas on the co-hosted `/mcp` + `/oauth/*` surface
(A11), which model optional protocol fields as `.optional()` (key must be
ABSENT) and never `.nullable()`. `explicitNulls = false` was set
application-wide only because a route-scoped override "broke
`AuthAndIngestRoutesDbTest`'s catch-all coverage — a route registered via a
SEPARATE `routing {}` call outside `module()` didn't inherit it". The failure
mode that forced it is quoted in the source: _"confirmed against a real
`claude mcp login` session — every login failed with a bare client-side
`invalid_union` parse error and zero server-side signal, 2026-07-15."_ So for
A4's own DTOs the shape is a **compatibility carry-over, not a hard
requirement**; a Go port may emit explicit nulls on A4 routes without breaking
`web/`, but must omit keys on the A11 surface. Do not invert this reason: it
changes which area the constraint actually binds.

### 1.1 `DeviceAuth.kt` — the `pmon` + web `/device` contract

The file header calls this the "SHARED CONTRACT REGISTRY — pmon + web consume
these".

| DTO                   | Field                     | Type    | Nullable | Default                   |
| --------------------- | ------------------------- | ------- | -------- | ------------------------- |
| `DeviceStartInput`    | `ttlSeconds`              | Long    | yes      | `null`                    |
| `DeviceStartResponse` | `verificationUri`         | String  | no       | —                         |
|                       | `verificationUriComplete` | String  | no       | —                         |
|                       | `userCode`                | String  | no       | —                         |
|                       | `handle`                  | String  | no       | —                         |
|                       | `interval`                | Int     | no       | —                         |
| `DevicePollInput`     | `handle`                  | String  | no       | —                         |
| `DeviceConfirmInput`  | `userCode`                | String  | no       | —                         |
| `DeviceConfirmAck`    | `ok`                      | Boolean | no       | `true`                    |
| `DevicePollPending`   | `status`                  | String  | no       | `"authorization_pending"` |
| `DevicePollResult`    | `token`                   | String  | no       | —                         |
|                       | `expiresAt`               | String  | no       | —                         |
|                       | `principal`               | String  | no       | —                         |
|                       | `sessionExpiresAt`        | String  | no       | —                         |
|                       | `renewalToken`            | String  | no       | —                         |

`DevicePollResult.renewalToken` is the **only** time the `pmr_` secret is ever
visible (`DeviceAuth.kt:52-58`: "Returned EXACTLY ONCE, here — the control plane
persists only its SHA-256 hash and can never hand it back out again").
`expiresAt` and `sessionExpiresAt` are Java `Instant.toString()` — **variable
fractional-second precision** (`…:06Z` when zero, `…:06.123Z` otherwise). Same
wire-format hazard A2 §8 recorded for `CedarPolicy.updatedAt`.

### 1.2 `DaemonSession.kt`

| DTO                                  | Field               | Type   | Nullable | Default |
| ------------------------------------ | ------------------- | ------ | -------- | ------- |
| `RenewSessionResponse`               | `token`             | String | no       | —       |
|                                      | `expiresAt`         | String | no       | —       |
| `RefreshTokenResponse` **(private)** | `access_token`      | String | no       | —       |
|                                      | `refresh_token`     | String | yes      | `null`  |
|                                      | `id_token`          | String | yes      | `null`  |
| `RefreshErrorBody` **(private)**     | `error`             | String | yes      | `null`  |
|                                      | `error_description` | String | yes      | `null`  |

The two private DTOs are **inbound** shapes parsed from the IdP's token endpoint
— snake_case because that is OAuth's wire form, not this project's convention.
`error_description` is parsed and never read (only `error` is inspected,
`DaemonSession.kt:798`) — dead field, harmless, but do not invent a use.

🔒 **INV-A4-65 — `RefreshTokenResponse.access_token` is required-by-parse and
never read, and that turns a missing `access_token` into `Transient`, not
`Active`.** `access_token: String` has **no default** (`DaemonSession.kt:766`),
so kotlinx throws `MissingFieldException` when the IdP omits it; the shared
client installs only `Json { ignoreUnknownKeys = true }` (`auth/Oidc.kt:98`) —
**no `coerceInputValues`, no `isLenient`** — so there is no leniency to fall
back on. The throw is caught by `refreshGrant`'s generic `catch (e: Exception)`
⇒ `Transient` ⇒ last-known-good preserved and no `markCheck`. RFC 6749 §5.1
makes `access_token` REQUIRED so a compliant IdP always sends it, and the field
is otherwise unused — but a Go port that models the response with all-optional
fields would classify the same response as **`Active`** and then proceed to
validate a `null` `id_token`. Reproduce the required-ness, or reproduce the
`Transient` outcome explicitly. See F34.

Corroboration that this is load-bearing rather than theoretical: the fake IdP in
`DaemonSessionLivenessIdpTest` emits `{"access_token":"unused", "id_token":…}`
on **both** of its 200 branches (`:113`, `:123`) — the literal string `"unused"`
is there only because the parse demands the key. The suite would fail without
it.

### 1.3 `Tokens.kt`

| DTO                     | Field        | Type           | Nullable | Default                                                               |
| ----------------------- | ------------ | -------------- | -------- | --------------------------------------------------------------------- |
| `WireTokenInfo`         | `id`         | Long           | no       | —                                                                     |
|                         | `kind`       | String         | no       | —                                                                     |
|                         | `principal`  | String         | no       | —                                                                     |
|                         | `name`       | String         | yes      | `null`                                                                |
|                         | `createdAt`  | String         | no       | —                                                                     |
|                         | `expiresAt`  | String         | no       | — (comment: "always set — proxy-monster issues only expiring tokens") |
|                         | `revokedAt`  | String         | yes      | `null`                                                                |
|                         | `lastUsedAt` | String         | yes      | `null`                                                                |
| `IssuedToken`           | `token`      | String         | no       | —                                                                     |
|                         | `id`         | Long           | no       | —                                                                     |
|                         | `kind`       | String         | no       | —                                                                     |
|                         | `name`       | String         | yes      | `null`                                                                |
|                         | `expiresAt`  | String         | no       | —                                                                     |
| `WireIdentity`          | `principal`  | String         | no       | —                                                                     |
|                         | `roles`      | List\<String\> | no       | —                                                                     |
|                         | `kind`       | String         | no       | —                                                                     |
| `MintSessionTokenInput` | `ttlSeconds` | Long           | yes      | `null`                                                                |
| `CreateTokenInput`      | `name`       | String         | yes      | `null`                                                                |
|                         | `ttlSeconds` | Long           | yes      | `null`                                                                |

`IssuedToken.token` is the plaintext secret, "Returned exactly once at issuance
— the only time the plaintext token is visible" (`Tokens.kt:58`). All five
timestamp strings are `Instant.toString()`.

### 1.4 `Oidc.kt` + `Auth.kt` — cookie payloads and the session DTO

| DTO                           | Field           | Type           | Nullable | Default       | Carried in         |
| ----------------------------- | --------------- | -------------- | -------- | ------------- | ------------------ |
| `OAuthStateSession`           | `state`         | String         | no       | —             | `pm_oauth_state`   |
|                               | `returnTo`      | String         | yes      | `null`        |                    |
| `OAuthNonceSession`           | `nonce`         | String         | no       | —             | `pm_oauth_nonce`   |
| `DeviceVerifySession`         | `userCode`      | String         | no       | —             | `pm_device_verify` |
| `TokenResponse` **(private)** | `id_token`      | String         | **no**   | —             | inbound from IdP   |
|                               | `access_token`  | String         | yes      | `null`        |                    |
|                               | `refresh_token` | String         | yes      | `null`        |                    |
| `UserSession`                 | `principal`     | String         | no       | —             | response body only |
|                               | `roles`         | List\<String\> | no       | `emptyList()` |                    |
|                               | `requesterIp`   | String         | yes      | `null`        |                    |
| `WebSessionRef`               | `sessionId`     | Long           | no       | —             | `pm_session`       |
| `DebugLogin`                  | `principal`     | String         | no       | —             | request body       |
|                               | `roles`         | List\<String\> | no       | `emptyList()` |                    |
|                               | `requesterIp`   | String         | yes      | `null`        |                    |

⚠️ **Grep hazard when re-deriving this table.** `Auth.kt`'s three
(`UserSession`, `WebSessionRef`, `DebugLogin`) are annotated **fully-qualified**
as `@kotlinx.serialization.Serializable` (`Auth.kt:27,34,50`), so a plain
`grep -n '@Serializable'` over the area finds **19**, not the true **22**. The
complete inventory is 7 (`DeviceAuth.kt`) + 3 (`DaemonSession.kt`) + 5
(`Tokens.kt`) + 4 (`Oidc.kt`) + 3 (`Auth.kt`) = **22**, and all 22 are in
§1.1–§1.4 above.

`TokenResponse.id_token` is **non-nullable**, so an IdP response omitting it
throws inside the callback's `try` and lands on the `server_error` failure
redirect — deliberate: identity comes only from the id_token. (Same
required-by-parse mechanism as INV-A4-65, but here the outcome is the intended
one — contrast `RefreshTokenResponse.access_token`, where required-ness is
incidental.)

🔒 **INV-A4-2 — `UserSession` is a response DTO, never an authority.** It used
to _be_ the cookie payload; it no longer is. `Auth.kt:20-26`: "Roles remain a
response-compatibility field; authorization resolves effective roles
server-side." A cookie still holding the old `{principal, roles}` shape must
resolve to **unauthenticated**, not to a session with those roles — that is
`WebSessionRoutesDbTest` case 8, and it is why `webSession()` wraps the cookie
read in `runCatching`. `requesterIp` is populated only for a debug-login session
and only reported while the bypass is on (`App.kt:745`), "so the console never
shows a simulated address the decision path is in fact ignoring."

### 1.5 Constants that are part of the contract

| Constant                                  | Value                                          | File                     |
| ----------------------------------------- | ---------------------------------------------- | ------------------------ |
| `SESSION_COOKIE`                          | `"pm_session"`                                 | `Auth.kt:15`             |
| `DEVICE_COOKIE`                           | `"pm_did"`                                     | `Auth.kt:16`             |
| `DEVICE_COOKIE_MAX_AGE_SECONDS` (private) | `7_776_000` (90 d)                             | `Auth.kt:17`             |
| `OAUTH_STATE_COOKIE`                      | `"pm_oauth_state"`                             | `Oidc.kt:22`             |
| `OAUTH_NONCE_COOKIE`                      | `"pm_oauth_nonce"`                             | `Oidc.kt:39`             |
| `DEVICE_VERIFY_COOKIE`                    | `"pm_device_verify"`                           | `Oidc.kt:33`             |
| `WEB_SESSION_AUTH`                        | `"web-session"` (Ktor auth-provider name)      | `Auth.kt:37`             |
| `LIVENESS_ACTIVE` / `LIVENESS_INACTIVE`   | `"ACTIVE"` / `"INACTIVE"`                      | `DaemonSession.kt:52-53` |
| `ENDED_SIGNED_OUT`                        | `"SIGNED_OUT"`                                 | `DaemonSession.kt:54`    |
| `ENDED_DISPLACED`                         | `"DISPLACED"`                                  | `:55`                    |
| `ENDED_DEACTIVATED`                       | `"DEACTIVATED"`                                | `:56`                    |
| `ENDED_GROUP_REVOKED`                     | `"GROUP_REVOKED"`                              | `:57`                    |
| `ENDED_IDP_REJECTED`                      | `"IDP_REJECTED"`                               | `:58`                    |
| `ENDED_DEVICE_BIND_MISMATCH`              | `"DEVICE_BIND_MISMATCH"`                       | `:59`                    |
| `TOKEN_MIN_TTL_SECONDS`                   | `60`                                           | `Tokens.kt:75`           |
| `TOKEN_MAX_TTL_SECONDS`                   | `86_400` (24 h)                                | `:76`                    |
| `SESSION_TTL_SECONDS`                     | `43_200` (12 h)                                | `:77`                    |
| `DEFAULT_USER_TTL_SECONDS`                | `3_600` (1 h)                                  | `:78`                    |
| `DEV_PRINCIPAL` (private)                 | `"debug-user"`                                 | `DeviceAuth.kt:240`      |
| `DEVICE_POLL_INTERVAL_SEC` (private)      | `2`                                            | `DeviceAuth.kt:241`      |
| `DEVICE_LOGIN_TTL_SEC` (private)          | `600` (10 min)                                 | `DeviceAuth.kt:242`      |
| `USER_CODE_ALPHABET` (private)            | `"ABCDEFGHJKMNPQRSTUVWXYZ23456789"` (31 chars) | `DeviceAuth.kt:96`       |

⚠️ `DEV_PRINCIPAL = "debug-user"` (`DeviceAuth.kt:240`) is **dead** — nothing in
`DeviceAuth.kt` references it. The same literal is duplicated in `Tokens.kt:267`
(`principalOf`'s fallback) and `Datasources.kt:752`. Candidate finding.

🔒 **INV-A4-3 — the six `ENDED_*` reasons are a closed wire vocabulary, but only
three reach the client.** A1's `respondSessionUnauthorized` (`App.kt:242-253`)
collapses them into exactly four `SessionStatusError.reason` values: `"none"`
(no failed-session attribute at all), `"displaced"` (`ENDED_DISPLACED`),
`"bind_mismatch"` (`ENDED_DEVICE_BIND_MISMATCH`), and `"expired"` for
**everything else** — including `SIGNED_OUT`, `DEACTIVATED`, `GROUP_REVOKED`,
`IDP_REJECTED`, and a row that simply ran past a deadline. The three surfaced
reasons are the three the console must explain differently ("someone signed in
elsewhere", "this browser is not the one that signed in", "your session ran
out"). Deliberately _not_ surfacing `DEACTIVATED` avoids telling an
unauthenticated caller that a specific account was deprovisioned. The stored
reason keeps the full detail for operators. Reproduce the collapse exactly; a Go
port that leaks `DEACTIVATED` to the browser changes the disclosure surface.

---

## 2. Routes

### 2.1 A4-owned routes

| Method | Path                     | Gate                                                 | Success                                              | Error codes                                                                                                     |
| ------ | ------------------------ | ---------------------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| POST   | `/auth/device/start`     | **none**                                             | 200 `DeviceStartResponse`                            | —                                                                                                               |
| POST   | `/auth/device/confirm`   | **none**                                             | 200 `DeviceConfirmAck`                               | 400 `device.unknown_or_expired_login`                                                                           |
| GET    | `/auth/device/authorize` | `DEVICE_VERIFY_COOKIE` match **+** `webSession()`    | 302                                                  | (all failures are redirects, never a body)                                                                      |
| POST   | `/auth/device/poll`      | **none** (bearer = the `handle`)                     | 200 `DevicePollResult` / **202** `DevicePollPending` | 400 `device.unknown_or_expired_login`, 400 `device.login_already_completed`, 403 `auth.principal_deprovisioned` |
| POST   | `/auth/session/renew`    | `Authorization: Bearer <pmr_…>` **only**             | 200 `RenewSessionResponse`                           | 401 `auth.missing_renewal_token`, 401 `common.unauthenticated`, 401 `auth.session_window_expired`               |
| GET    | `/auth/oidc/login`       | **none**                                             | 302 to IdP                                           | 501 `common.oidc_not_configured`                                                                                |
| GET    | `/auth/oidc/callback`    | `state` + `nonce` cookies                            | 302                                                  | 501 `common.oidc_not_configured`; every other failure is a redirect                                             |
| POST   | `/api/wire-tokens`       | `requireAuthz(TOKEN_MINT, Token(self, SESSION))`     | 200 `IssuedToken`                                    | 403 `auth.principal_deprovisioned`; 401/403 from the gate; **framework 400 on a missing/malformed body**        |
| GET    | `/api/tokens`            | `requireAuthz(TOKEN_LIST, Token(target, kind=null))` | 200 `List<WireTokenInfo>`                            | 401/403 from the gate                                                                                           |
| POST   | `/api/tokens`            | `requireAuthz(TOKEN_MINT, Token(self, USER))`        | **201** `IssuedToken`                                | 403 `auth.principal_deprovisioned`; **framework 400 on a missing/malformed body**                               |
| DELETE | `/api/tokens/{id}`       | `requireAuthz(TOKEN_REVOKE, Token(owner, kind))`     | **204**                                              | 400 `common.bad_id`, 404 `common.not_found{resource:"token"}`                                                   |

**Body-parse strictness is NOT uniform across the eleven routes — reproduce each
one individually.** Three groups, verified call-site by call-site:

| Route                       | `receive` form                                                                                       | Missing / garbage body                                                                              |
| --------------------------- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `POST /auth/device/start`   | `runCatching { receive<DeviceStartInput>() }.getOrDefault(DeviceStartInput())` (`DeviceAuth.kt:271`) | **defaults** — `ttlSeconds = null` ⇒ `SESSION_TTL_SECONDS`                                          |
| `POST /auth/device/confirm` | `runCatching { receive<DeviceConfirmInput>().userCode }.getOrNull()` (`:293`)                        | **400 `device.unknown_or_expired_login`** (falls into the null-code branch — _not_ a framework 400) |
| `POST /auth/device/poll`    | bare `receive<DevicePollInput>()` (`:348`)                                                           | framework-level 400 from `ContentNegotiation`/`StatusPages`                                         |
| `POST /api/wire-tokens`     | bare `receive<MintSessionTokenInput>()` (`Tokens.kt:277`)                                            | framework-level 400                                                                                 |
| `POST /api/tokens`          | bare `receive<CreateTokenInput>()` (`Tokens.kt:304`)                                                 | framework-level 400                                                                                 |
| `POST /auth/session/renew`  | no body read at all                                                                                  | n/a — identity is the bearer header only                                                            |

⚠️ Note the ordering on both mint routes: **`requireAuthz` runs BEFORE
`receive`** (`Tokens.kt:276` then `:277`; `:303` then `:304`). So an
unauthorized caller with a garbage body gets the gate's 401/403, never the 400.
A Go port that parses the body first inverts the disclosure order — it tells an
unauthorized caller that its JSON was malformed.

🔒 **INV-A4-4 — `/auth/device/*` is deliberately unauthenticated, and that is
safe only because of what each step holds.** `start` mints nothing but a PENDING
row. `poll` is authenticated _by the 192-bit `handle`_ and yields a token only
after a browser session approved it, exactly once. `confirm`/`authorize` are the
browser half and carry the anti-phishing cookie. There is no principal in any
request body anywhere in this flow — see INV-A4-14.

**INV-A4-5** — `DELETE /api/tokens/{id}` loads the row **before** authorizing so
Cedar decides against the token's _real_ owner and kind, and a missing id is a
404 "before any authorization is revealed" (`Tokens.kt:320-323`). The ownership
`WHERE principal = ?` in `revoke` is now a belt-and-braces second check, not the
gate.

**INV-A4-6** — `GET /api/tokens` authorizes with `kind = null` because listing
is kind-agnostic; per A2's INV-A2-3 the Cedar `kind` attribute is then
**absent**, which is what lets a policy forbid long-lived PATs while permitting
session listing. The `?principal=` override exists for the identity-admin
oversight seed (`system:token-admin`, `V8__seed.sql:128`).

### 2.2 Routes hosted in `App.kt` (A1) that are pure A4 surface

Listed because A4's own suites (`WebSessionRoutesDbTest`,
`OidcWebSessionDbTest`, `AuthAndIngestRoutesDbTest`) test them and a Go port
must keep them wired to A4's store. Their DTOs (`SessionStatus`,
`SessionStatusError`, `LogoutRequest/Response`, `AuthConfigResponse`,
`SessionUxConfig`, `MePermissions`) are A1's — `App.kt:185-224`.

| Method | Path                      | Gate                                                         | Reads from A4                                                                              |
| ------ | ------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| GET    | `/auth/config`            | none (public)                                                | config only                                                                                |
| POST   | `/auth/debug`             | `config.authDebug` else **404** `common.not_found{endpoint}` | `mintWeb(…, debugRequesterIp)` in one tx with A3's `replaceDirectRoles`                    |
| GET    | `/auth/me`                | `authenticate(WEB_SESSION_AUTH)`                             | `WebSessionRow` principal + `debugRequesterIp`                                             |
| GET    | `/auth/session/status`    | `authenticate(WEB_SESSION_AUTH)`                             | `WebSessionRow` deadlines + `now`                                                          |
| POST   | `/auth/session/heartbeat` | `authenticate(WEB_SESSION_AUTH)`                             | **`touchWeb`** — the only idle-extending call                                              |
| POST   | `/auth/logout`            | none                                                         | `sessions.clear(SESSION_COOKIE)` → storage `invalidate` → `endWebBySessionKey(SIGNED_OUT)` |
| GET    | `/api/me/permissions`     | `requireApi`                                                 | `userSession()`                                                                            |

**INV-A4-7 — logout ends the row through Ktor's session-storage `invalidate`,
not a direct store call.** `App.kt:781` only clears the cookie; the end-write
happens in `PrincipalSessionStorage .invalidate`. A Go port with no equivalent
storage abstraction must call `endWebBySessionKey(key, ENDED_SIGNED_OUT)`
explicitly at logout, or logout stops ending rows.

### 2.3 Cookies A4 owns

A1's cookie table (`01-bootstrap.md:209-215`) covers the **five** cookies
registered in the Ktor `Sessions` block. `DEVICE_COOKIE` (`pm_did`) is a
**sixth** cookie, set by hand outside that block — A4 owns it entirely.

| Cookie   | Set by                                         | maxAge           | Attributes                                                                                  |
| -------- | ---------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------- |
| `pm_did` | `ensureDeviceCookie(secure)` (`Auth.kt:76-91`) | 7 776 000 (90 d) | `path=/`, `httpOnly`, `secure` per arg, `SameSite=Lax`. **Not signed, not a Ktor session.** |

🔒 **INV-A4-8 — `pm_did` is a bearer-free correlator, and its unsigned-ness is
fine because it is never trusted alone.** It carries a random UUID and is only
ever compared for **equality** with the `device_id` stored on the session row.
Forging it cannot authenticate anything; the only thing an attacker gains by
guessing it is _not_ being detected as a different device — and to use that they
need the signed `pm_session` too. Conversely a stolen `pm_session` replayed
without (or with a wrong) `pm_did` **ends the session** (INV-A4-13). `secure` is
`config.mcpIssuer.startsWith("https://")`, the same derivation the five signed
cookies use.

---

## 3. Symbols

### 3.1 `Auth.kt` — request-time identity

#### `UserSession` · `WebSessionRef` · `DebugLogin` · data classes

See §1.4. `WebSessionRef(sessionId: Long)` is the **entire** cookie payload.

#### `WEB_SESSION_AUTH`, `PRINCIPAL_SESSION_STORE`, `FAILED_WEB_SESSION` · top-level

```kotlin
const val WEB_SESSION_AUTH = "web-session"
val PRINCIPAL_SESSION_STORE = AttributeKey<PrincipalSessionStore>("principal-session-store")
val FAILED_WEB_SESSION      = AttributeKey<Long>("failed-web-session")
private val RESOLVED_IDENTITY = AttributeKey<ResolvedIdentity>("resolved-session-identity")
private data class ResolvedIdentity(val row: WebSessionRow?)
```

`PRINCIPAL_SESSION_STORE` is an **application**-scoped attribute (set at
`App.kt:399`); `FAILED_WEB_SESSION` and `RESOLVED_IDENTITY` are **call**-scoped.

**Go shape:** application attribute → a field on the server struct or an
injected dependency; call attributes → `context.Context` values, or better, an
explicit per-request struct. `RESOLVED_IDENTITY` must be able to hold "resolved
to nothing" distinctly from "not yet resolved" — a bare `*Row` in context
cannot, so carry a wrapper (that is exactly what
`ResolvedIdentity(row: WebSessionRow?)` is for).

#### `JsonSessionSerializer<T>` · class · `jsonSessionSerializer<T>()` · inline reified fn

```kotlin
class JsonSessionSerializer<T : Any>(serializer: KSerializer<T>, json: Json = Json) : SessionSerializer<T>
inline fun <reified T : Any> jsonSessionSerializer(): JsonSessionSerializer<T>
```

**Contract:** cookie payloads are kotlinx JSON, not Ktor's own format.
**Behavior/reason (quote, `Auth.kt:57-61`):** _"Ktor's bundled serializer
constructor shape has shifted across 3.x; delegating to kotlinx Json directly
keeps this stable and is what we already use on the wire."_ Note this instance
uses the **bare `Json` default**, not `App.kt`'s configured `appJson` — so
`explicitNulls` is **true** for cookie payloads (INV-A4-1 does not apply inside
cookies). `⟦LIB⟧` HMAC-signed cookie encoding; see A1.

#### `ApplicationCall.deviceCookieId(): String?`

`request.cookies[DEVICE_COOKIE]`. No validation.

#### `ApplicationCall.ensureDeviceCookie(secure: Boolean): String`

1. Read `pm_did`; keep it **only if it parses as a UUID**
   (`runCatching { UUID.fromString(it) }`).
2. Otherwise mint `UUID.randomUUID().toString()`.
3. **Always** re-append the `Set-Cookie` (sliding 90-day window), and return the
   value.

**INV-A4-9 — the device id is always re-issued, never merely read.**
Re-appending on every login refreshes the 90-day window so a regularly-active
browser never silently loses its binding and gets force-ended by INV-A4-13. The
UUID shape check means a garbage or attacker-planted non-UUID value is replaced
rather than adopted, so `device_id` is always a well-formed UUID at rest.
**Deps:** called from `Oidc.kt:198`, `App.kt:707` (`/auth/debug`),
`oauth/OAuthRoutes.kt:171` (A11).

#### `ApplicationCall.webSession(): WebSessionRow?`

**Contract:** the one authoritative "who is this request" for the browser
surface. Resolves liveness **and** device binding, and **never extends idle**.

1. Return the per-call `RESOLVED_IDENTITY` cache if present (including a cached
   `null`).
2. `ref = runCatching { sessions.get<WebSessionRef>() }.getOrNull()`.
3. `resolved = application.attributes.getOrNull(PRINCIPAL_SESSION_STORE)?.let { store -> ref?.let { store.resolveWeb(it.sessionId, deviceCookieId()) } }`.
4. If `ref != null && resolved == null` → put
   `FAILED_WEB_SESSION = ref.sessionId`.
5. Cache and return.

🔒 **INV-A4-10 — every cookie-read failure mode collapses to "unauthenticated",
never to a 500 and never to a partially-trusted identity.** `runCatching` at
step 2 swallows three distinct failures: (a) `PrincipalSessionStorage.read`
throwing `NoSuchElementException` for an unknown tracker id, (b) JSON
deserialization failing on a **pre-cutover `{principal, roles}` payload that is
HMAC-valid under the current key** (`WebSessionRoutesDbTest` case 8 — "A valid
HMAC over a wrong-shape payload must be treated as unauthenticated, never a
500"), and (c) a missing store attribute (a test app that never wired one).
Losing this `runCatching` turns a stale browser cookie into a 500 on every
request.

**INV-A4-11 — resolution is cached exactly once per request, and that is why
`webSessionIsLive` exists.** Caching prevents N store round-trips (and N
device-mismatch end-writes) per request, but it means a long request can act on
an identity the liveness sweep has since ended. Any action that _grants a new
credential_ off that identity re-checks `webSessionIsLive` immediately before
committing (`DaemonSession.kt:326-331`, used at `DeviceAuth.kt:335`).

#### `ApplicationCall.userSession(): UserSession?`

`webSession()?.let { UserSession(it.principal) }` — **roles are deliberately
empty here.** Callers that need roles resolve them from A3's `RoleResolver`.
`Tokens.kt:268`'s `rolesOf(call)` therefore always returns `emptyList()` for a
real session, which is why minted tokens carry an empty role snapshot and
effective roles are re-resolved at decide time. ⚠️ Not obviously intentional —
see §6 Q4.

### 3.2 `PrincipalSessionStorage.kt` — Ktor tracker-id ↔ row linkage

```kotlin
class PrincipalSessionStorage(store: PrincipalSessionStore, serializer: SessionSerializer<WebSessionRef>) : SessionStorage
```

Three methods, all suspend:

| Method             | Behavior                                                                                                                                                                 |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `write(id, value)` | deserialize to `WebSessionRef`, then `store.linkWebSessionKey(ref.sessionId, id)`                                                                                        |
| `read(id)`         | `store.webIdBySessionKey(id)` → serialize `WebSessionRef(it)`; **`null` ⇒ throw `NoSuchElementException("Unknown web session key")`** (Ktor's contract for "no session") |
| `invalidate(id)`   | `store.endWebBySessionKey(id, ENDED_SIGNED_OUT)`                                                                                                                         |

🔒 **INV-A4-12 — `read` deliberately returns refs for ENDED and EXPIRED rows.**
Class doc (`PrincipalSessionStorage.kt:6-11`): _"reading returns refs for live
or ended rows without sliding idle time, because request-time resolution owns
liveness, device binding, and the ended-reason surface; invalidation ends only
an active row and preserves a prior terminal reason."_ This is load-bearing for
INV-A4-3: if `read` filtered out ended rows, `webSession()` would never learn
the `sessionId`, `FAILED_WEB_SESSION` would stay unset, and every terminated
session would report `"none"` instead of `"displaced"` / `"bind_mismatch"`. A Go
port that "optimizes" the lookup by adding `AND ended_at IS NULL` silently
destroys the whole ended-reason UX.

**Go shape:** there is no Ktor `SessionStorage` in Go. The port needs an
explicit three-function seam — link, lookup, invalidate — invoked from the
cookie middleware at the same three moments (cookie write, cookie read, cookie
clear). The `NoSuchElementException` becomes a sentinel error.

### 3.3 `DaemonSession.kt` — row types

```kotlin
data class DaemonSessionRow(id, principal, handle: String?, refreshTokenEnc: ByteArray?,
    ttlSeconds: Long, sessionExpiresAt: Instant, lastIdpCheckAt: Instant?, livenessStatus: String,
    createdAt: Instant)
data class WebSessionRow(id, principal, createdAt, absoluteExpiresAt, idleExpiresAt, now: Instant,
    debugRequesterIp: String? = null)
data class LivenessCandidate(id, kind: String, principal, refreshTokenEnc: ByteArray?, lastIdpCheckAt: Instant?)
```

`DaemonSessionRow.sessionExpiresAt` maps the **`absolute_expires_at`** column —
the field is renamed, the column is shared with WEB rows. `WebSessionRow.now` is
`clock_timestamp()` **read on the same query**, so the client's countdown is
computed in the DB's clock domain, not the JVM's. `WebSessionRow` deliberately
carries **no ciphertext** (`DaemonSession.kt:311-315`), which is why
`webRefreshToken(id)` exists as a separate narrow read.

⚠️ `DaemonSessionRow` and `LivenessCandidate` hold `ByteArray` inside a
`data class` — so `equals`/ `hashCode` are **reference** comparisons on that
field. Nothing depends on it today; a Go port using `[]byte` in a comparable
struct has the same trap in reverse (Go structs with slices are not comparable
at all).

### 3.4 `class PrincipalSessionStore` — the central symbol of the area

```kotlin
class PrincipalSessionStore(
    internal val dataSource: DataSource,
    private val crypto: ResultCrypto?,
    private val webSessionIdleSeconds: Long = 900,
    private val webSessionSlideSeconds: Long = 120,
    private val onWebSessionEnded: ((String, Connection) -> Unit)? = null,
)
```

**One table, two kinds.** `kind='DAEMON'` backs CLI logins; `kind='WEB'` backs
console logins. Class doc (`DaemonSession.kt:95-113`): _"Daemon lookups and
renewal remain scoped `kind = 'DAEMON'`; web lifecycle methods remain scoped
`kind = 'WEB'`; only the liveness candidate query intentionally covers both
kinds."_

🔒 **INV-A4-13 — the `kind` scoping is a security boundary, not tidiness.** A
daemon row has `idle_expires_at IS NULL` and a `renewal_token_hash`; a web row
has neither and has a `device_id` and `session_key`. Drop the `kind` predicate
from `resolveWeb` and a daemon row becomes resolvable as a browser session (with
a NULL device binding, i.e. INV-A4-16's wildcard hole); drop it from
`withinWindow` and a still-open web row keeps a closed daemon renewal window
alive. `DaemonSessionStoreDbTest` cases 15 and 17, `PrincipalSessionStoreDbTest`
case 6, and `PrincipalSessionStorageDbTest` case 4 each pin one direction of
this.

🔒 **INV-A4-14 — no refresh token is ever persisted in plaintext, and no key
means no persistence.** `crypto == null` (`PM_RESULT_KEY` unset) makes
`refreshToken?.let { crypto?.encrypt(...) }` evaluate to `null`, so the column
stays NULL — the token is **dropped, not stored**. Consequence, stated in the
source: silent renewal and the session window still work, and the IdP liveness
recheck "degrades to _can't verify, leave cached status alone_".
`PrincipalSessionStoreDbTest` case 9 and `DaemonSessionStoreDbTest` case 2 pin
it. Same AES-256-GCM idiom as A7's `QueryResultStore`.

#### `CreatedDaemonSession(row: DaemonSessionRow, renewalToken: String)` · nested data class

The plaintext `pmr_` secret, "visible ONLY at creation time".

#### `newRenewalToken(): String` · private top-level

`"pmr_" + base64url-nopad(32 random bytes)` from a file-level `SecureRandom`.
256 bits.

#### `sha256Hex(s: String): String` · private top-level

SHA-256 hex. **Deliberate duplication of `Tokens.kt`'s `tokenHash`** — quote
(`DaemonSession.kt:39-43`): _"the SAME idiom [TokenStore]'s private `hash()`
uses for `proxy_token.token_hash`, kept self-contained here rather than reaching
into [TokenStore] (that's a different part's file; this store persists its own
hashed secret in its own column)."_ Two implementations of one algorithm,
intentionally. A Go port may share one helper — the _values_ must be
byte-identical either way.

#### `create(principal, handle, refreshToken, windowSeconds, ttlSeconds[, c]): CreatedDaemonSession`

1. Encrypt the refresh token if both it and `crypto` are present.
2. Mint a `pmr_` secret.
3. `INSERT INTO principal_session (principal, handle, refresh_token_enc, ttl_seconds, absolute_expires_at, liveness_status, renewal_token_hash, kind) VALUES (?,?,?,?, now() + make_interval(secs => ?), ?, ?, 'DAEMON') RETURNING id`.
   ⚠️ Only `kind` is a **literal**. `liveness_status` (`LIVENESS_ACTIVE`) and
   `renewal_token_hash` are **bound parameters** (`DaemonSession.kt:155-156`),
   and the hash is computed **in the JVM** by `sha256Hex(renewalToken)` — there
   is no SQL-side digest function anywhere in this area. A Go port must not
   "simplify" this into a `digest()`/`sha256()` SQL call: that would put the
   plaintext secret into the statement text and therefore into
   `pg_stat_statements` / query logs. Binding order:
   `1 principal, 2 handle, 3 refresh_token_enc (setNull(BINARY) when absent, never setBytes(null)), 4 ttl_seconds (setLong), 5 windowSeconds (setDouble), 6 liveness_status, 7 renewal_token_hash`.
4. Re-read the row **on the same connection** and return it with the plaintext
   secret.

**INV-A4-15 — the read-back must use the caller's connection.** Quote
(`:136-141`): _"Reads the row back on [c] (the just-inserted, still-uncommitted
row), never the plain [getById] which would open a second connection with a
different view."_ This matters because `respondWithMintedSession` composes
create + token issue inside `mintForActivePrincipalLocked`'s transaction; a
second pooled connection would see nothing and NPE on `!!`.

Note `idle_expires_at` and `device_id` are left NULL for DAEMON, and
`windowSeconds` is bound as a **double** into `make_interval(secs => ?)`.

#### `mintWeb(principal, refreshToken, absoluteSeconds, idleSeconds, deviceId, c = null, debugRequesterIp = null): Long`

The newest-wins web login. Body runs inside `dataSource.inTx {}` when
`c == null`, else on `c` (whose caller "must already be inside a transaction so
the principal advisory lock remains held through commit").

1. `connection.advisoryLockPrincipal(principal)` — **first statement**, A3's
   `pg_advisory_xact_lock(hashtext(principal))`.
2. INSERT via `WITH t AS (SELECT clock_timestamp() AS ts)`, writing
   `created_at = t.ts`, `absolute_expires_at = t.ts + absoluteSeconds`,
   `idle_expires_at = t.ts + idleSeconds`, `liveness_status='ACTIVE'`,
   `device_id`, `kind='WEB'`, `debug_requester_ip`. `RETURNING id`.
3. `UPDATE … SET ended_at = clock_timestamp(), ended_reason = 'DISPLACED', liveness_status='INACTIVE' WHERE principal = ? AND kind='WEB' AND ended_at IS NULL AND id <> <new id>`
   → `displaced` count.
4. `if (displaced > 0) onWebSessionEnded?.invoke(principal, connection)`.

🔒 **INV-A4-16 — the three timestamps come from ONE post-lock
`clock_timestamp()`, never `now()`.** The reason is quoted verbatim because a
"cleanup" to `now()` reintroduces a live bug (`DaemonSession.kt:181-186`):
_"Postgres freezes now()/transaction_timestamp() at the transaction's first
statement, which here is the advisory lock above — and that lock can block
behind a concurrent login for the full idle window. A now()-based
idle_expires_at would then be minted already in the past and 401 the very
session it just created. clock_timestamp() reflects the real current instant;
one CTE reading shares it across all three columns so the new row is internally
consistent."_ `PrincipalSessionStoreDbTest` **case 8**
(`web mint waits for the principal lock and leaves exactly one active web row`,
`:367`) holds the lock ~2 s and asserts full-duration deadlines measured from
completion — it is written specifically to fail a `now()` implementation.

🔒 **INV-A4-17 — newest-wins is scoped to (principal, kind='WEB') and excludes
the new row by id.** It ends the principal's other **web** sessions only:
sibling daemon rows and _other principals'_ web rows are untouched
(`PrincipalSessionStoreDbTest` case 2 asserts both). Excluding `id <> new` is
what stops the mint from ending itself. Postcondition: at most one row with
`principal = P AND kind='WEB' AND ended_at IS NULL`, which **case 8** asserts
directly.

🔒 **INV-A4-18 — displacement fires the end seam, on the mint's own
connection.** Quote (`:215-218`): _"Newest-wins displaced a prior WEB session …
Route it through the same end seam logout/deprovision use so the old session's
saved editor results are dropped — the new session starts clean. Composed onto
THIS connection (inside the mint tx) so a rolled-back mint reverts the cleanup
too, never displacing+deleting under a mint that aborts."_

#### `resolveWeb(id, deviceId): WebSessionRow?` (public, own connection) and `resolveWeb(id, deviceId, c)` (private)

1. `SELECT id, principal, created_at, absolute_expires_at, idle_expires_at, device_id, debug_requester_ip, clock_timestamp() AS db_now FROM principal_session WHERE id = ? AND kind='WEB' AND ended_at IS NULL AND absolute_expires_at > clock_timestamp() AND idle_expires_at > clock_timestamp()`.
2. No row ⇒ `null` (with **no** write of any kind).
3. Row found: if `storedDeviceId == null` **or** `storedDeviceId != deviceId` ⇒
   `endWeb(id, ENDED_DEVICE_BIND_MISMATCH, c)` then `null`.
4. Else return the `WebSessionRow`.

🔒 **INV-A4-19 — device binding fails closed in three ways, and a mismatch is
TERMINAL.** A live row presented with (a) a _different_ `pm_did`, (b) **no**
`pm_did` (`deviceId == null`), or (c) a `device_id` that is NULL in the database
(a pre-binding legacy row) is not merely rejected — it is **ended with
`DEVICE_BIND_MISMATCH`**, so even the correctly-bound browser cannot resurrect
it. ⚠️ **Citation corrected:** an earlier draft attributed the reason to
`DaemonSession.kt:295-298`. It is **not there** — `resolveWeb`
(`DaemonSession.kt:248-280`) carries **no explanatory comment at all**;
`DaemonSession.kt:295-298` is `endWeb`'s parameter binding. The reason exists
only in the **test**: `PrincipalSessionStoreDbTest.kt:295-297` — _"A live,
correctly-bound row presented with NO device id (null) must be rejected and
ended, not resolved: a stolen pm_session replayed without a pm_did is exactly
what device-binding defends against, so an absent device can never be treated as
a wildcard match."_ The companion assertion lives at
`WebSessionRoutesDbTest.kt:542` (_"…to bind_mismatch exactly like a wrong one,
never resolve as a wildcard match"_). This matters for the port in two ways: (a)
the warning is invisible to anyone editing `resolveWeb`, which is precisely the
function a "harmless" optimization would touch, and (b) if the Go port does not
carry the tests over, the reason is lost entirely — so **restate it as a comment
in the Go `resolveWeb`**. See F35. `PrincipalSessionStoreDbTest` case 5 pins all
three sub-cases and additionally asserts the mismatch **does not slide
`idle_expires_at`**. Making the mismatch terminal converts a silent theft into a
visible, self-reported session kill — the console gets `bind_mismatch` and the
legitimate user re-authenticates.

**INV-A4-20 — resolution never extends idle, and an expired clock never slides
back to life.** Neither branch writes `idle_expires_at` or `last_seen_at`.
`PrincipalSessionStoreDbTest` cases 1 and 6 assert both deadlines byte-identical
across repeated `resolveWeb` calls, and that a row whose idle or absolute clock
already passed keeps its expired deadline. Only `touchWeb` moves anything.

#### `touchWeb(id, deviceId): WebSessionRow?`

The session heartbeat, and the **only** idle-extending path.

1. `UPDATE principal_session SET idle_expires_at = now() + make_interval(secs => webSessionIdleSeconds), last_seen_at = now() WHERE id = ? AND kind='WEB' AND ended_at IS NULL AND absolute_expires_at > clock_timestamp() AND idle_expires_at > clock_timestamp() AND device_id = ? AND (last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => webSessionSlideSeconds))`.
2. Then `resolveWeb(id, deviceId, c)` on the **same** connection and return its
   result.

**INV-A4-21 — the slide is throttled, and the throttle is in the WHERE clause.**
Within `webSessionSlideSeconds` (default 120) of the last slide the UPDATE
matches zero rows, so a chatty client cannot write the row on every request; the
subsequent `resolveWeb` still returns the (unmoved) session, so the caller sees
success. `PrincipalSessionStoreDbTest` case 1 walks first-touch →
throttled-touch (identical deadlines _and_ identical `last_seen_at`) → backdated
→ slid.

**INV-A4-22 — `touchWeb` can never move `absolute_expires_at`.** It is not in
the SET list. Case 1 asserts the absolute cap is byte-identical across the
entire lifecycle. This is the whole point of having two clocks: idle is a
convenience, absolute is the security bound.

⚠️ **Note the mismatched idle source.** `mintWeb` takes `idleSeconds` as a
**parameter** while `touchWeb` reads the **constructor field**
`webSessionIdleSeconds`. Nothing enforces agreement; `App.kt:386` happens to
pass `config.webSessionIdleSeconds` to both. Also note `touchWeb`'s device
predicate is `device_id = ?` in SQL, which is NULL-unsafe: a NULL-`device_id`
row never matches — the same fail-closed outcome as INV-A4-19 but reached by a
different mechanism (SQL three-valued logic rather than an explicit branch).
Candidate finding.

#### `endWeb(id, reason, c = null): Boolean`

1. `UPDATE … SET ended_at = now(), ended_reason = ?, liveness_status='INACTIVE' WHERE id = ? AND kind='WEB' AND ended_at IS NULL RETURNING principal`.
2. If a principal came back ⇒
   `onWebSessionEnded?.invoke(principal, connection)`; return `true`.
3. No row ⇒ `false` and **no callback**.

**INV-A4-23 — the callback runs on the same connection as the end-write, and
only on a real transition.** Quote (`:283-285`): _"The cleanup callback runs on
the SAME connection as the end-write … so when [c] is a caller's transaction the
delete composes with it; when null it shares this auto-commit connection.
Invoked inside the `.use` block so the connection is still open."_ The
`ended_at IS NULL` guard makes a repeat end idempotent and preserves the
**first** reason — critical because a session ended `DISPLACED` must not be
relabelled `SIGNED_OUT` by a later logout, or INV-A4-3's UX inverts.
`PrincipalSessionStoreDbTest` case 3 asserts "a no-op end fires nothing".

#### `webEndedReason(id): String?`

`SELECT ended_reason … WHERE id = ? AND kind='WEB'`. Returns null for a daemon
row and for a nonexistent id (`PrincipalSessionStoreDbTest` **case 7** —
`web ended reason is returned only for web rows`, `:350-365` — checks both,
including `assertNull(store.webEndedReason(-1))`). Consumed only by A1's
`respondSessionUnauthorized`. Note it also returns null for a **live** web row
(whose `ended_reason` is NULL), which is what makes A1's `"expired"` fallback
the answer for a row that merely ran past a deadline — see INV-A4-3.

#### `webRefreshToken(id): String?`

`SELECT refresh_token_enc … WHERE id = ? AND kind='WEB' AND ended_at IS NULL` →
`decryptRefresh`.

🔒 **INV-A4-24 — the `ended_at IS NULL` filter here is a security check, not a
convenience.** Quote (`DeviceAuth.kt:331-333`): _"webRefreshToken() is read from
the STILL-LIVE row (`ended_at IS NULL`): a session the liveness sweep rejected
between resolve and here is already ended, so this returns null and the guard
below refuses to approve from it — a credential is never minted off an
authentication that was just invalidated."_

#### `webSessionIsLive(id): Boolean`

`SELECT 1 … WHERE id = ? AND kind='WEB' AND ended_at IS NULL AND absolute_expires_at > now() AND (idle_expires_at IS NULL OR idle_expires_at > now())`.
Purpose per doc: re-check _right now_, because "a request's resolved identity is
cached per call" (INV-A4-11).

⚠️ Two divergences from `resolveWeb` worth recording rather than smoothing over:
it uses `now()` instead of `clock_timestamp()`, and it tolerates
`idle_expires_at IS NULL` (which `resolveWeb` rejects). Neither can currently be
reached differently — the caller is inside a short auto-commit read, and WEB
rows always have an idle deadline — but they are inconsistencies. Candidate
finding.

#### `linkWebSessionKey(rowId, key)`

In one transaction: (1)
`UPDATE … SET session_key = NULL WHERE session_key = ? AND kind='WEB' AND id <> ?`
— steal a reused tracker id from its prior holder; (2)
`UPDATE … SET session_key = ? WHERE id = ? AND kind='WEB'`.

**INV-A4-25 — the steal must precede the claim, in one transaction.**
`idx_principal_session_session_key` is a **partial unique index**
(`WHERE session_key IS NOT NULL`, `V6__sessions.sql:71-72`), so claiming before
releasing would violate it. Both statements in one tx means a crash can never
leave the key orphaned on a stale row. `PrincipalSessionStorageDbTest` case 1
pins the steal.

#### `webIdBySessionKey(key): Long?`

`SELECT id … WHERE session_key = ? AND kind='WEB'`. **No `ended_at` filter** —
INV-A4-12.

#### `endWebBySessionKey(key, reason): Boolean`

`UPDATE … SET ended_at = now(), ended_reason = ?, liveness_status='INACTIVE' WHERE session_key = ? AND kind='WEB' AND ended_at IS NULL RETURNING principal`,
then the end-seam callback on that same auto-commit connection. Same
first-reason-wins guard as `endWeb`.

#### `getById(id)` · `getByPrincipal(principal)` · `getByHandle(handle)` · `getByRenewalTokenHash(hash)`

All four go through the private `SELECT` companion constant, which hard-codes
`WHERE kind = 'DAEMON'`. `getByPrincipal` orders
`created_at DESC, id DESC LIMIT 1` — "a principal may be logged in from more
than one daemon", so this is the _most recent_.

🔒 **INV-A4-26 — renewal resolves by hashed secret and by nothing else.** Quote
(`:394-398`): _"Resolve a session by the SHA-256 hash of its renewal bearer
secret — the ONLY lookup `POST /auth/session/renew` performs now. Never look
this up by a caller-supplied principal/handle; that was the
unauthenticated-renewal flaw."_ `RenewalWindowTest` case 2 is the named
regression: "a principal-only JSON body with no bearer is refused — the
unauthenticated-renewal attack".

#### `withinWindow(principal): Boolean`

`SELECT absolute_expires_at > now() AS within … WHERE principal = ? AND kind='DAEMON' ORDER BY created_at DESC, id DESC LIMIT 1`;
**no row ⇒ `false`**.

🔒 **INV-A4-27 — the window comparison runs in the DATABASE clock domain.**
Quote (`:402-408`): _"the `absolute_expires_at > now()` comparison runs in the
DATABASE clock domain — the SAME clock that STAMPS `absolute_expires_at` on
create/deactivate (`now()`) — so a CP-vs-DB clock skew can't make a window that
was just closed to `now()` momentarily read as still-open (the mixed
DB-timestamp-vs-JVM- `Instant.now()` compare this replaced could, under a
DB-ahead clock)."_ A Go port must not compare a scanned `time.Time` against
`time.Now()` here.

#### `markCheck(id, status[, c])`

`UPDATE … SET last_idp_check_at = now(), liveness_status = CASE WHEN ended_at IS NULL THEN ? ELSE liveness_status END WHERE id = ?`.
Note: **no `kind` filter** — deliberately covers both kinds.

🔒 **INV-A4-28 — stamping a check must never resurrect an ended row's
liveness.** The `CASE` is why: the sweep's Active branch calls
`markCheck(ACTIVE)` _after_ possibly having ended every web session for a
zero-role principal, and without the guard that write would flip the just-ended
row back to `ACTIVE`. `DaemonSessionStoreDbTest` case 9 ("preserves an ended row
status") and `DaemonSessionLivenessIdpTest` case 1 ("preserve inactive
liveness") both pin it.

#### `deactivateAllForPrincipal(principal[, c]): Int`

`UPDATE … SET liveness_status='INACTIVE', absolute_expires_at = now() WHERE principal = ? AND kind='DAEMON' AND absolute_expires_at > now()`
→ rows affected.

🔒 **INV-A4-29 — deprovision closes EVERY daemon window for the principal, and
the closure is durable.** Quote (`:438-448`): _"Deactivating by principal (not
by a single row id) is what closes the pull-deprovision hole completely: a
principal may hold more than one daemon session (multiple machines / re-logins),
and a liveness sweep that finds ONE of them inactive must tear down every
sibling too, else the untouched siblings' renewal secrets keep minting fresh
tokens. Dropping `absolute_expires_at` to now() means a subsequent
`/auth/session/renew` fails its window check as well (not just the
liveness-status check), and it stays failed across a later reactivation — the
deprovision is durable, not merely paused."_ Idempotent by the `> now()`
predicate. `RenewalWindowTest` cases 8 and 9 pin the sibling sweep and the
no-resurrection-after-reactivation property respectively.

#### `closeDaemonWindow(id)`

Same UPDATE, scoped to one id. Used by the sweep for a single `invalid_grant`
daemon row — `DaemonSessionLivenessIdpTest` case 4 asserts "closes only its
daemon row while a valid sibling and credentials survive". Note the asymmetry
with `deactivateAllForPrincipal`: an IdP rejection of one refresh token is
evidence about **that token**, not about the account, so it must not cascade.

#### `endAllWebForPrincipal(principal, reason[, c]): Int`

`UPDATE … SET ended_at = now(), ended_reason = ?, liveness_status='INACTIVE' WHERE principal = ? AND kind='WEB' AND ended_at IS NULL`;
then `if (ended > 0) onWebSessionEnded?.invoke(principal, c)`.

🔒 **INV-A4-30 — the bulk end composes into the caller's teardown transaction.**
Quote (`:491-497`): _"Deprovision + group-revocation both bulk-end here; route
through the same end seam as logout so the principal's saved editor results are
dropped. Composed onto the caller-supplied connection [c] so it is part of
deprovision's atomic teardown transaction — a later statement that aborts the
teardown rolls the result deletion back too, instead of a separate committed
delete orphaning a session the rollback keeps alive."_
`PrincipalSessionStoreDbTest` case 4 is the regression test: it aborts the tx
after the end and asserts the editor result **and** the live session both
survive.

#### `staleSessions(recheckIntervalSeconds): List<LivenessCandidate>`

The **only** query that spans both kinds:

```sql
WHERE (last_idp_check_at IS NULL OR last_idp_check_at < now() - make_interval(secs => ?))
  AND ((kind = 'DAEMON' AND absolute_expires_at > now())
    OR (kind = 'WEB' AND ended_at IS NULL AND absolute_expires_at > now() AND idle_expires_at > now()))
```

Never-checked rows (NULL) are included. Ended/expired rows are excluded, so the
sweep cannot resurrect or re-warn about a dead session.
`DaemonSessionStoreDbTest` case 10 enumerates the include/exclude matrix.

#### `updateRefresh(id, refreshToken)`

Re-encrypt and UPDATE. **No-op (early return) when `crypto == null`** — pinned
by `DaemonSessionStoreDbTest` case 12.

#### `decryptRefresh(row)` / `decryptRefresh(enc: ByteArray?)`

`null` when either the blob or `crypto` is absent; otherwise
`crypto.decrypt(blob)` as UTF-8.

#### `renewLocked(row, isDeactivated, mint): IssuedToken?`

The locked core of `/auth/session/renew`. Inside `dataSource.inTx`:

1. `c.advisoryLockPrincipal(row.principal)` — "may block for a while behind a
   concurrent teardown".
2. Re-`SELECT` the row **by id on `c`**; gone ⇒ `null`.
3. `if (!withinWindowOn(c, fresh.id) || isDeactivated(fresh.principal, c) || fresh.livenessStatus == LIVENESS_INACTIVE) return null`.
4. `mint(fresh, c)`.

🔒 **INV-A4-31 — every fail-closed check is re-run under the lock against a
fresh read.** Quote (`:550-556`): _"open a transaction, take the per-principal
advisory lock first, re-select [row] by id, and re-run every fail-closed check
against that fresh read. Authoritative deprovisioning takes the same lock, so it
either commits before this re-read or tears down the credential after this
transaction commits."_ The pre-lock `row` handed in by the route is **only** an
identifier carrier; none of its field values are trusted. `RenewalWindowTest`
cases 10, 11 and 12 pin the serialization (including that
`revokeActiveCredentials` itself blocks on the same lock).

#### `withinWindowOn(c, id): Boolean` · private

`SELECT absolute_expires_at > clock_timestamp() … WHERE id = ? AND kind='DAEMON'`.

🔒 **INV-A4-32 — `clock_timestamp()`, not `now()`, and the reason is the lock
wait.** Quote (`:576-583`): _"Postgres's `now()` is frozen at the enclosing
TRANSACTION's start, not the current instant — [renewLocked] takes the advisory
lock before this check and can block on it for a while, so `now()` here could
still reflect a moment BEFORE that wait, letting a window that has since
actually expired read as still open."_ This is the mirror image of INV-A4-16 and
the same class of bug; both must be replicated, and both are invisible in a test
that does not hold the lock.

#### `queryOne` / `queryOneOn` / `ResultSet.toRow` / `companion SELECT` · private

Mechanical. `SELECT` is
`id, principal, handle, refresh_token_enc, ttl_seconds, absolute_expires_at, last_idp_check_at, liveness_status, created_at FROM principal_session WHERE kind = 'DAEMON'`
— callers append `AND …`.

### 3.5 `sessionRenewRoutes` — `POST /auth/session/renew`

```kotlin
internal fun Route.sessionRenewRoutes(daemonSessionStore, tokenStore, userGroupStore)
```

Registered from `deviceSessionRoutes` (`DeviceAuth.kt:371`) — quote: _"so the
two files compose into one route group without either owning the other's
table."_

1. No `Authorization` header, or one not starting `"Bearer "` ⇒ **401**
   `auth.missing_renewal_token`.
2. `secret = header.removePrefix("Bearer ").trim()`;
   `getByRenewalTokenHash(sha256Hex(secret))` ⇒ null ⇒ **401**
   `common.unauthenticated`.
3. `renewLocked(row, isDeactivated = userGroupStore::isDeactivated(…, c), mint = tokenStore.issue(SESSION, principal, emptyList(), name=null, ttl = fresh.ttlSeconds, c))`.
4. `null` ⇒ **401** `auth.session_window_expired`; else **200**
   `RenewSessionResponse(token, expiresAt)`.

**INV-A4-33 — the renewed token's TTL comes from the ROW, and the roles list is
empty.** `ttlSeconds` is whatever `pmon` asked for at device-start (clamped
then, stored on the row), so renewal cannot lengthen a token beyond the original
request. `roles = emptyList()` because effective roles are re-resolved at decide
time.

🔒 **INV-A4-34 — renewal reads cached liveness and never calls the IdP.** Route
doc (`:621-632`): _"The timer sweep is the sole IdP revalidator; renewal only
reads the cached result."_ Two reasons: the renew path is on `pmon`'s critical
path and must not inherit IdP latency, and an IdP outage must not become a
fleet-wide logout. `DaemonSessionLivenessIdpTest` case 8 asserts the renew route
makes **zero** token-endpoint requests while the sweep makes them.

**INV-A4-35 — three distinct 401 codes, deliberately.**
`auth.missing_renewal_token` (no bearer at all — client bug),
`common.unauthenticated` (bearer present but unknown — wrong/rotated secret),
`auth.session_window_expired` (authentic secret, but the window closed /
deprovisioned / INACTIVE → `pmon` must re-run device-auth). Collapsing them
removes the only signal that distinguishes "retry with the right secret" from
"start a new login".

### 3.6 The liveness sweep

#### `sweepSessionLiveness(config, discovery, validator, http, sessionStore, userGroupStore, roleResolver, log)` · suspend

**Contract:** "The sole IdP revalidator: one timer-driven pass over every live
web or daemon session whose cached check is stale."

1. `if (config.oidc == null || discovery == null) return` — an unconfigured
   deployment sweeps nothing. ⚠️ **`validator` is NOT checked here**, only later
   per-row (see below).
2. For each `staleSessions(config.idpRecheckIntervalSeconds)`:
   `runCatching { revalidateSession(...) }.onFailure { log.warn(...) }`.

🔒 **INV-A4-36 — one row's failure never affects another's.** Per-row
`runCatching`, and per the doc: _"Each session's own refresh token determines
only that session's fate; transient failures leave its state and check timestamp
untouched. The IdP HTTP round-trip always completes before any principal lock is
taken; only the successful response's local DB phase is serialized."_ A sweep
that threw out of the loop would leave the tail of the list unchecked
indefinitely.

Launched from `App.kt:431-444` on a
`delay(config.idpRecheckIntervalSeconds.seconds)` loop, itself wrapped in
`runCatching` (A1).

#### `revalidateSession(row, …)` · private suspend

0. `val oidc = config.oidc ?: return` (`DaemonSession.kt:709`) — a **second**,
   per-row null check on the same field `sweepSessionLiveness` already gated on
   at its step 1. Unreachable in practice (the caller returned already) but it
   is what makes `oidc` smart-cast non-null for the rest of the body; in Go this
   is just "pass the resolved OIDC config in, non-nil". Do not mistake it for a
   real branch.
1. `refreshToken = sessionStore.decryptRefresh(row.refreshTokenEnc)`; **null ⇒
   debug-log and return** — no `markCheck`, so the row stays stale and is
   retried next sweep (`DaemonSessionLivenessIdpTest` case 7: "remain live and
   unstamped").
2. `document = discovery.document()`;
   `refreshGrant(http, document.token_endpoint, clientId, clientSecret, refreshToken)`.
3. **`Active`**: a. `outcome.rotatedRefreshToken != null` ⇒
   `updateRefresh(row.id, it)`. 🔒 **Ordering is load-bearing:** this write
   happens at `:718-720`, **before** the id_token validation at `:721` and
   before every early return below it. A rotating IdP invalidates the old
   refresh token the moment it issues the new one, so persisting the rotation
   first is what keeps the row usable even when the _rest_ of this revalidation
   bails out (no id_token, identity mismatch). Move the write after the
   validation and one malformed id_token permanently strands the session holding
   a dead refresh token — the next sweep gets `invalid_grant` and revokes a
   session that was never actually revoked at the IdP. Untested (§4.17 gap 17):
   the fake IdP never rotates. b.
   `claims = outcome.idToken?.let { validator?.validate(it, expectedNonce = null) }`;
   **null ⇒ warn and return** (again no `markCheck`). c.
   `refreshedPrincipal = claims.email ?: claims.subject`; `!= row.principal` ⇒
   **warn and return**. d.
   `userGroupStore.provisionFromOidc(row.principal, claims.email, claims.groups,    oidc.groupMapping)`
   (A3). e.
   `if (roleResolver.resolve(row.principal).isEmpty())    sessionStore.endAllWebForPrincipal(row.principal, ENDED_GROUP_REVOKED)`.
   f. `markCheck(row.id, LIVENESS_ACTIVE)`.
4. **`Inactive`**: warn, then by `row.kind`: `"WEB"` ⇒
   `endWeb(row.id, ENDED_IDP_REJECTED)`; `"DAEMON"` ⇒
   `closeDaemonWindow(row.id)`; anything else ⇒ warn "ignoring unknown principal
   session kind".
5. **`Transient`**: warn only. **No state change, no `markCheck`.**

🔒 **INV-A4-37 — a refresh success is trusted only after the id_token validates
AND resolves to the same principal.** Steps 3b and 3c. `expectedNonce = null`
because a refresh grant has no nonce (the `nonce` check only applies to an
interactive authorization-code response). Without 3c an IdP that returns a
_different_ subject for a rotated token would silently re-provision another
account's groups onto this row's principal.

🔒 **INV-A4-38 — group reconciliation is principal-global and ends only WEB
rows.** Quote (`:738-741`): _"Reconciliation is principal-global, so a zero-role
verdict ends every live web session for the principal regardless of which kind
produced this candidate. Daemon rows stay open; each daemon query re-resolves
roles and fail-closes on its own."_ `DaemonSessionLivenessIdpTest` cases 1–3 pin
it, including case 3: an **omitted** `groups` claim is authoritative-empty and
removes old membership.

🔒 **INV-A4-39 — a transient failure preserves last-known-good, including the
stale check timestamp.** Not stamping `last_idp_check_at` on `Transient` means
the next sweep retries instead of waiting a full interval — the recheck cadence
is preserved across IdP flakiness.

⚠️ **Consequence worth stating:** steps 1, 3b and 3c also skip `markCheck`, so a
session whose IdP never returns an `id_token` on the refresh grant (or which has
no stored refresh token) is re-selected and re-warned on **every** sweep,
forever. Tests treat "unstamped" as correct for case 1; for 3b/3c it is an
unbounded warn loop. Candidate finding.

#### `RefreshOutcome` · private sealed interface

`Active(rotatedRefreshToken: String?, idToken: String?)` ·
`Inactive(reason: String)` · `Transient(reason: String)`.

#### `refreshGrant(http, tokenEndpoint, clientId, clientSecret, refreshToken): RefreshOutcome` · private suspend

`submitForm` with `grant_type=refresh_token`, `refresh_token`, `client_id`,
`client_secret` → `Active(resp.refresh_token, resp.id_token)`.

🔒 **INV-A4-40 — only `invalid_grant` revokes; every other error is transient.**
Quote (`:792-796`): _"Only `invalid_grant` is the IdP's definitive 'this refresh
token/account is no longer valid' signal. The rest of the 4xx space —
`invalid_client` (a rotated `client_secret`), `unsupported_grant_type` (IdP-side
config drift), etc. — is OUR-side/config trouble, not proof the account is gone,
and must NOT revoke a live session (a transient IdP/config error keeps the
last-known-good, docs/auth-model.md 'Security invariants')."_ Mechanics: the
shared client has `expectSuccess = true` (`auth/Oidc.kt:97`), so 4xx raises
`ClientRequestException` → parse `RefreshErrorBody`, fall back to
`"http_<status>"` when the body will not parse, and compare to `invalid_grant`.
**5xx raises `ServerResponseException`, which is not a
`ClientRequestException`**, so it lands in the generic `catch (e: Exception)` ⇒
`Transient`. `DaemonSessionLivenessIdpTest` case 6 pins `invalid_client` (401)
and a raw 500 as transient.

**Go shape:** an HTTP client that does not auto-error on non-2xx must branch on
the status code explicitly: 4xx → parse body, `invalid_grant` ⇒ Inactive else
Transient; anything else (5xx, network, parse failure) ⇒ Transient. Getting this
inverted mass-logs-out a fleet during an IdP incident.

### 3.7 `DeviceAuth.kt` — RFC 8628 device authorization

#### `DeviceLoginRow` · data class

`(id, handle, userCode: String?, deviceCode: String?, intervalSec: Int, ttlSeconds: Long, status: String, principal: String?, refreshTokenEnc: ByteArray?, createdAt, expiresAt)`.
`status ∈ {PENDING, APPROVED, CONSUMED}` — the field comment says so
(`DeviceAuth.kt:78`); ⚠️ `V6__sessions.sql:21` still says only
`PENDING | APPROVED`. Stale migration comment, candidate finding.

#### `class DeviceLoginStore(dataSource, crypto: ResultCrypto? = null)`

🔒 **INV-A4-41 — the IdP's `device_code` never leaves the server, and `pmon`
only ever sees the opaque `handle`.** Class doc (`:85-90`). Under
`PM_AUTH_DEBUG` the column is simply NULL — "the dev-bypass short-circuit
pre-approves a synthetic row without ever hitting the IdP". Keeping the two
identifiers distinct (`V6__sessions.sql:12-14`) is why the polling secret never
rides in a browser URL.

##### `USER_CODE_ALPHABET` + `normalizeUserCode(raw)` · private companion

Alphabet `ABCDEFGHJKMNPQRSTUVWXYZ23456789` — 31 chars, **no ambiguous 0/O,
1/I/L** ("a human reads this code off the CP verification page").
`normalizeUserCode` uppercases, keeps only alphabet characters, and re-inserts a
single hyphen when exactly 8 survive: `"wdjbmjht"` and `"WDJB-MJHT"` both fold
to `"WDJB-MJHT"` (RFC 8628 §6.1). Note the fold-then-reformat is **not**
length-clamped: a 5-character input stays 5 characters and simply matches
nothing.

##### `newHandle(): String`

`"dvc_" + base64url-nopad(24 bytes)` = 192 bits — "the only device-login
identifier `pmon` ever sees".

##### `newUserCode(): String`

8 alphabet characters with a hyphen after the 4th → `XXXX-XXXX`. Entropy 31⁸ ≈
**39.6 bits** (the doc says "~40 bits"). Doc reason (`:112-116`): _"short-lived
and single-use, so it is safe to show a human even though it is the page's
approval key."_

##### `create(handle, deviceCode, intervalSec, ttlSeconds, expiresAt, userCode = null): DeviceLoginRow`

INSERT then `get(handle)!!`. `expiresAt` is bound as a JVM
`Timestamp.from(instant)` — the **only** place in this area where a deadline is
stamped from the JVM clock rather than the DB's.

##### `get(handle)` / `getByUserCode(userCode)`

Both full-row selects. `getByUserCode` normalizes first.

##### `createPending(intervalSec, ttlSeconds, expiresAt): DeviceLoginRow`

One `newHandle()` outside the loop; up to **5** attempts, retrying on SQLSTATE
**`23505`** (unique_violation) with a fresh `newUserCode()`; any other SQLState
or the 5th failure rethrows. Reason (`:164-168`): _"Retries the user_code on the
astronomically-rare unique-index collision (~40 bits, minutes-long TTL) rather
than surfacing a 500; the handle is 192-bit so it never collides."_ **Go
shape:** needs SQLSTATE inspection, not string matching on the driver's message
text `⟦LIB⟧`.

##### `markApproved(handle, principal, refreshToken = null): Boolean`

`UPDATE device_login SET status='APPROVED', principal = ?, refresh_token_enc = ? WHERE handle = ? AND status='PENDING' AND expires_at > now()`
→ `rows > 0`.

🔒 **INV-A4-42 — approval is a compare-and-set on (PENDING, unexpired), and the
return value is the truth.** Doc (`:181-185`): _"A CAS on (PENDING, unexpired) —
the return value is the truth."_ The route must branch on it, not assume
success. `DeviceLoginStoreDbTest` cases 4 and 5 pin approve-only-once and
refuse-expired.

##### `decryptRefresh(row): String?`

`row.refreshTokenEnc?.let { crypto?.decrypt(it) }` as UTF-8.

##### `consume(handle): Boolean`

`UPDATE device_login SET status='CONSUMED' WHERE handle = ? AND status='APPROVED' AND expires_at > now()`
→ `rows > 0`.

🔒 **INV-A4-43 — the one-time claim is what bounds a device handle to exactly
one credential set.** Quote (`:203-209`): _"Returns true only for the single
caller that wins the transition; false for any replay/race on an
already-consumed (or never-approved / expired) handle. The poll endpoint gates
minting on this, which is what makes a device handle yield EXACTLY one SESSION
token + one `pmr_` renewal secret — without it, re-polling an approved handle
re-mints a fresh renewal secret on every call, turning a short-lived login
handle into an unbounded credential-minting handle."_ `DeviceLoginStoreDbTest`
case 14 is the end-to-end regression.

##### `purgeExpired(): Int`

`DELETE FROM device_login WHERE expires_at <= now()`. Backed by
`idx_device_login_expires_at`. Run from A1's timer loop (`App.kt:408`) and
nowhere else.

##### `private fun ResultSet.toRow(): DeviceLoginRow`

Mechanical column mapping (`DeviceAuth.kt:225-237`). Column ↔ field names differ
in three places: `user_code → userCode`, `device_code → deviceCode`,
`interval_sec → intervalSec`, `refresh_token_enc → refreshTokenEnc`. Both
timestamps via `getTimestamp(...).toInstant()` — **neither is nullable**, which
is safe because `created_at` and `expires_at` are both `NOT NULL`
(`V6__sessions.sql:28-29`).

#### `deviceSessionRoutes(config, deviceLoginStore, daemonSessionStore, tokenStore, userGroupStore, log)`

⚠️ **`log: Logger` is accepted and never used.** `grep -n 'log\.' DeviceAuth.kt`
returns nothing — the whole device-auth surface (start / confirm / authorize /
poll) emits **zero log lines**, including on the security-relevant refusals
(`device.unknown_or_expired_login`, `device.login_already_completed`, the
no-confirm authorize bounce). Contrast `oidcRoutes`, which logs every failure
branch. **Disposition split (F33, index F53): OMIT the unused parameter,
REPRODUCE the silence.** An unread parameter has no call path and no observable
behaviour, so leaving it out of the Go signature changes nothing — confirm first
that no test passes a logger it then asserts on. Adding the missing warn-level
lines is the opposite case: it is a behaviour change on a security-relevant
surface, so it is a separate decision after cutover, not part of the port. Carry
the defect forward with a comment naming F33 — the device-auth flow is
unobservable in logs today, and the port must not quietly make it observable.

🔒 **INV-A4-44 — the IdP is reached only by the browser, never by the pmon↔CP
device flow.** Quote (`:257-258`): _"The IdP is reached ONLY by the browser SSO
choice (the auth-code flow); the pmon↔CP device flow is entirely CP-owned, so
`pmon login` has one code path whether the user then chooses SSO or debug."_
Consequence: the CP does **not** implement the RFC 8628 client side against the
IdP at all; `device_authorization_endpoint` is parsed by discovery and unused.
This is why `device_code` is always NULL in practice.

**`POST /auth/device/start`**

1. Body optional:
   `runCatching { receive<DeviceStartInput>() }.getOrDefault(DeviceStartInput())`
   — a missing/garbage body is _not_ a 400.
2. `ttl = clampTtlSeconds(input.ttlSeconds ?: SESSION_TTL_SECONDS)`.
3. `createPending(DEVICE_POLL_INTERVAL_SEC=2, ttl, Instant.now() + 600s)`.
4. `verifyUri = "${config.webBaseUrl}/device"`; respond
   `DeviceStartResponse(verifyUri, "$verifyUri?user_code=${userCode.encodeURLParameter()}", userCode, handle, 2)`.

**INV-A4-45 — the verification URI is the WEB origin, not the control plane's.**
Quote (`:275-277`): _"The verification page is a WEB route, so this must be the
console's origin — same as the control plane in the usual single-edge
deployment, or PM_WEB_ORIGIN when the console is served elsewhere."_
`DeviceLoginStoreDbTest` case 7 pins it. Note the TTL sent to `pmon` in
`interval` is the _poll_ interval (2 s), unrelated to the 600 s handle lifetime.

**`POST /auth/device/confirm`**

1. `userCode = runCatching { receive<DeviceConfirmInput>().userCode }.getOrNull()?.trim()`.
2. `row = userCode?.let { getByUserCode(it) }`.
3. If
   `row?.userCode == null || row.expiresAt.isBefore(now) || row.status != "PENDING"`
   ⇒ **400** `device.unknown_or_expired_login`.
4. `sessions.set(DeviceVerifySession(row.userCode))`; **200**
   `DeviceConfirmAck()`.

Note step 4 stores the **stored, normalized** code, while `authorize` compares
the raw query parameter with exact `!=`. See the finding in §5.

**`GET /auth/device/authorize`**

1. `userCode = query["user_code"]?.trim()`. Local `backToDevice()` = `/device`
   (+ the code when present).
2. **Blank code, or
   `sessions.get<DeviceVerifySession>()?.userCode != userCode`** ⇒ redirect
   `backToDevice()` — "not confirmed on /device in this browser".
3. `row = getByUserCode(userCode)`; missing / expired / not PENDING ⇒ clear the
   verify cookie, redirect `backToDevice()`.
4. `session = call.webSession()`; null ⇒ redirect
   `/login?return_to=<urlencoded /auth/device/authorize?user_code=…>` and
   **approve nothing**. 🔒 **This branch deliberately does NOT clear
   `pm_device_verify`** (`DeviceAuth.kt:321-326` — no `sessions.clear` before
   the redirect), unlike branches 3, 6 and 7. It must not: the user is being
   sent through `/login` and will land back on this exact URL, where step 2
   re-requires the cookie. Clear it here and the whole SSO-then-approve path
   (`OidcWebSessionDbTest` case 4, `DeviceLoginStoreDbTest` case 11) breaks —
   every first-time `pmon login` would loop between `/login` and `/device`
   forever. The cookie is not a one-shot _nonce_; it is one-shot with respect to
   **approval**, and step 4 is not an approval.
5. `refreshToken = daemonSessionStore.webRefreshToken(session.id)`.
6. `if (!daemonSessionStore.webSessionIsLive(session.id))` ⇒ clear the verify
   cookie, redirect to `/login?return_to=…`.
7. `approved = markApproved(row.handle, session.principal, refreshToken)`; clear
   the verify cookie; redirect `/device/success` when approved, else
   `backToDevice()`.

🔒 **INV-A4-46 — the device-verify cookie is the anti-phishing gate, and it is
single-use.** Quote (`:289-291`, `Oidc.kt:28-32`): _"validate it's a real
pending login and set the signed verify cookie binding THIS browser to the code.
/auth/device/authorize below requires that cookie, so an attacker's direct
authorize link (no /device confirm) cannot approve."_ The attack it stops: a
phisher who has started their own `pmon login` mails the victim a bare
`…/auth/device/authorize?user_code=XXXX-XXXX` link; the victim's live console
session would otherwise approve the _attacker's_ handle silently. The cookie is
cleared on every branch that **terminates the approval attempt** — 3 (row
gone/expired/not PENDING), 6 (session died between resolve and here), 7
(approval attempted, whether or not it won) — so it authorizes at most one
approval. It is **not** cleared on branch 2 (no cookie / code mismatch: there is
nothing to clear that belongs to this code) or branch 4 (login redirect: see
above). Precisely three `sessions.clear(DEVICE_VERIFY_COOKIE)` calls exist, at
`DeviceAuth.kt:316`, `:336` and `:341`. `DeviceLoginStoreDbTest` cases 9 and 10
and `OidcWebSessionDbTest` case 5 pin it — including that a confirm for **one**
code cannot authorize a **different** code.

🔒 **INV-A4-47 — the live re-check at step 6 runs AFTER the refresh-token read,
on purpose.** The per-call resolution cache (INV-A4-11) means `session` may be
stale; step 6 is the fresh read. Reading the refresh token first is harmless
because `webRefreshToken` itself filters `ended_at IS NULL` (INV-A4-24), so a
session ended in between yields `null` **and** fails step 6 — a credential is
never minted off a just-invalidated authentication.

**INV-A4-48** — the existing-session path deliberately does **not** re-login:
_"If the user already has a console session, we approve this pmon login with
that identity and land on success — no re-login, no session churn"_
(`:303-306`). This matters because a re-login would `mintWeb`, which is
newest-wins and would displace the very session doing the approving.

**`POST /auth/device/poll`**

1. `input = receive<DevicePollInput>()` — **not** wrapped in `runCatching`; a
   malformed body is a framework-level 400.
2. `row = get(input.handle)`; null or `expiresAt.isBefore(now)` ⇒ **400**
   `device.unknown_or_expired_login`.
3. `row.status == "PENDING" || row.principal == null` ⇒ **202**
   `DevicePollPending()`.
4. `!consume(row.handle)` ⇒ **400** `device.login_already_completed`.
5. `respondWithMintedSession(call, principal, row, refreshToken = decryptRefresh(row), …)`.

**INV-A4-49 — poll never contacts the IdP.** "The approval already resolved the
principal, so no IdP call happens here" (`:345-346`). And `principal == null` is
treated as pending even if the status somehow says APPROVED — belt and braces
against a partially-written row.

#### `respondWithMintedSession(call, principal, row, refreshToken, config, tokenStore, daemonSessionStore, userGroupStore)` · private suspend

```kotlin
tokenStore.dataSource.mintForActivePrincipalLocked(principal, userGroupStore) { c ->
    val created = daemonSessionStore.create(principal, row.handle, refreshToken,
        config.sessionWindowSeconds, row.ttlSeconds, c)
    val issued = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), null, row.ttlSeconds, c)
    DevicePollResult(issued.token, issued.expiresAt, principal,
        created.row.sessionExpiresAt.toString(), created.renewalToken)
}
```

`null` ⇒ **403** `auth.principal_deprovisioned`; else respond the result.

🔒 **INV-A4-50 — session creation and token issuance are ONE transaction under
the per-principal lock.** Quote (`:374-380`): _"re-checking deprovisioning,
creating the session, and issuing the token as ONE transaction under the
per-principal advisory lock. The IdP may have completed device-auth just as a
SCIM `active=false` teardown swept, so a check-then-create outside the lock
could persist a fresh renewal secret + SESSION token AFTER the sweep already
scanned — resurrectable on a later reactivation."_
`mintForActivePrincipalLocked` is A3's (`Deprovision.kt:99`).

**INV-A4-51** — the session **window** is `config.sessionWindowSeconds`
(`PM_SESSION_WINDOW`, default 2 h) while the **token** TTL is `row.ttlSeconds`
(what `pmon` asked for, clamped at start, default 12 h). The window is the cap
on _silent renewal_; the token TTL is the life of one wire credential. ⚠️ With
the shipped defaults the window (2 h) is **shorter** than the token TTL (12 h),
so the first token outlives the renewal window — renewal simply becomes
unavailable after 2 h while the original token stays valid for 12 h. Intentional
or not, replicate the arithmetic exactly; see §6 Q2.

### 3.8 `Tokens.kt`

#### `enum class TokenKind` — exactly four values

| Constant        | DB `proxy_token.kind` | Token prefix | Minted by                                  | Passes `validate`? | Passes `resolve`? | In `list`? |
| --------------- | --------------------- | ------------ | ------------------------------------------ | ------------------ | ----------------- | ---------- |
| `SESSION`       | `SESSION`             | `pmt_`       | device poll, renew, `/api/wire-tokens`     | ✅                 | ✅                | ✅         |
| `USER`          | `USER`                | `pmk_`       | `POST /api/tokens`                         | ✅                 | ✅                | ✅         |
| `EDITOR`        | `EDITOR`              | `pmk_`       | A7 `RunExecService.run/openSession`        | ❌                 | ✅                | ❌         |
| `APPROVER_EXEC` | `APPROVER_EXEC`       | `pmk_`       | A7 `RunExecService.run(approverExec=true)` | ❌                 | ✅                | ❌         |

⚠️ The area brief called the fourth kind "PAT"; the enum constant is **`USER`**
— "generated PAT, pasted / injected by the user" is only the comment. And the
prefix is derived by `if (kind == SESSION) "pmt_" else "pmk_"`, so **`EDITOR`
and `APPROVER_EXEC` tokens are prefix-indistinguishable from `USER` tokens** on
the wire. Do not infer kind from prefix.

`fromWire(value: String): TokenKind?` —
`entries.firstOrNull { it.name == value }`, "null on an unrecognized value, so
callers fail closed rather than throw" (`Tokens.kt:26-30`). ⚠️ At the one call
site that matters (`DELETE /api/tokens/{id}`, `Tokens.kt:324`) null does **not**
fail closed — see the finding in §5.

Two further kinds exist in the **database** but not in this enum: `MCP_ACCESS`
and `MCP_REFRESH` (`V7__tokens.sql:48-57`, owned by A11). The V7 `CHECK`
constraint `proxy_token_mcp_metadata_ck` makes the two shapes mutually
exclusive: MCP kinds **must** carry `resource`/`client_id`/`scope`/
`refresh_family`/`consent_id` and `roles = '[]'`; non-MCP kinds must carry
**none** of them (nor `rotated_from`/`rotated_at`). Reason quoted: _"So a
SESSION or USER token can never silently acquire resource-bound MCP authority,
and an MCP token can never carry a role snapshot."_ A4's `issue` binds only the
non-MCP columns, so it satisfies the constraint by construction. ⚠️ The same V7
comment enumerates only four kinds and **omits `EDITOR` / `APPROVER_EXEC`** —
stale doc, candidate finding.

#### TTL policy · top-level constants + `clampTtlSeconds(ttlSeconds: Long): Long`

`ttlSeconds.coerceIn(60, 86_400)`.

🔒 **INV-A4-52 — no token is permanent, and the clamp is the only enforcement.**
There is no no-expiry option anywhere: `expires_at` is `NOT NULL` in V7 and
every INSERT computes it as `now() + ttl`. The clamp also **floors** zero and
negative requests to 60 s rather than rejecting them, so a buggy client cannot
mint an already-expired token. `TokenTtlTest`'s four cases are the whole guard.

#### `tokenHash(token: String): String` · internal top-level

SHA-256 hex over `token.toByteArray()` (platform default charset — in practice
UTF-8; note `DaemonSession.sha256Hex` specifies `Charsets.UTF_8` explicitly,
this one does not).

🔒 **INV-A4-53 — one hash definition, shared by the token table and the
requester-IP carrier.** Quote (`:85-90`): _"the ONE hashing definition shared by
[TokenStore] (the `proxy_token.token_hash` column) and [RequesterIpRegistry]
(RunExec.kt): the CP-only decide-time carrier keys off this SAME hash so it
never stores a raw token at rest in a second map, and its key always matches the
token row's own `token_hash`."_ Two hashers would silently desynchronize A12's
requester-IP lookup from A4's token row. See A7/A12.

#### `class TokenStore(internal val dataSource: DataSource)`

Fields: **public** `sessionTtlSeconds = SESSION_TTL_SECONDS` (12 h) and
`defaultUserTtlSeconds = DEFAULT_USER_TTL_SECONDS` (1 h) — these two are public
because `tokenRoutes` reads them as the per-route TTL defaults; private
`json = Json`, `stringList = ListSerializer(String.serializer())`,
`rng = SecureRandom()`. `dataSource` is `internal` so
`mintForActivePrincipalLocked` call sites can reach the pool.

⚠️ **`json` is the bare `Json` default, not `App.kt`'s `appJson`**
(`Tokens.kt:97`). It is used only for the `roles` snapshot
(`encodeToString`/`decodeFromString` of `List<String>`), where the config
difference is unobservable — but do not read INV-A4-1 as applying to the column.

**Every store method that writes has an explicit two-overload shape** — a
no-connection form that opens its own pooled connection, and a
`Connection`-taking form that composes into a caller's transaction. `issue`
(`:115`/`:125`), `revokeAllForPrincipal` (`:242`/`:245`); the same pattern
recurs in `PrincipalSessionStore.create`, `markCheck`,
`deactivateAllForPrincipal`, `endAllWebForPrincipal`, and as a nullable-`c`
parameter in `mintWeb`/`endWeb`. The no-connection form is **always**
implemented as `dataSource.connection.use { c -> <same>(…, c) }` — never as a
duplicate SQL body. Reproduce that as one Go method taking an explicit
`execer`/`Tx` interface plus a thin pool-borrowing wrapper; duplicating the SQL
is how the two forms drift apart.

##### `hash(token): String` · private

`= tokenHash(token)`. A one-line private delegate (`:104`) so every in-class
call site reads `hash(…)` while the definition stays the single shared top-level
`tokenHash`. Not a second algorithm — see INV-A4-53.

##### `randomToken(prefix): String` · private

`prefix + base64url-nopad(32 bytes)` = 256 bits.

##### `issue(kind, principal, roles, name, ttlSeconds[, c]): IssuedToken`

`INSERT INTO proxy_token (token_hash, kind, principal, roles, name, expires_at) VALUES (?,?,?, ?::jsonb, ?, now() + (?::bigint * interval '1 second')) RETURNING id, expires_at`.

**INV-A4-54 — `expires_at` comes back from `RETURNING` on the same connection.**
Quote (`:118-124`): _"`expires_at` comes back from `RETURNING` on this SAME
connection (never the plain no-connection [get], which would open a second
connection and could read a different/uncommitted view of the row)."_ Same
reasoning as INV-A4-15.

Note the roles snapshot is `json.encodeToString(stringList, roles)` bound as
`?::jsonb` — the `?::jsonb` cast idiom, not `PGobject` (F16's inconsistency,
third instance).

##### `resolve(token): WireIdentity?`

`SELECT principal, roles, kind FROM proxy_token WHERE token_hash = ? AND kind IN ('SESSION','USER','EDITOR','APPROVER_EXEC') AND revoked_at IS NULL AND expires_at > now()`.

**INV-A4-55 — `resolve` is `validate` minus the write, for the per-query hot
path.** Quote (`:145-151`): _"same existence/revocation/expiry predicate as
[validate] but WITHOUT the `last_used_at` write, so many concurrent queries
sharing one daemon/session token don't serialize on a single row's UPDATE lock
(or generate WAL per query). `last_used_at` is stamped once per session by
[validate] at the handshake, which is freshness enough for a 'recently used'
signal."_ `roles` defaults to `"[]"` when the column reads NULL.

##### `validate(token): WireIdentity?`

`UPDATE proxy_token SET last_used_at = now() WHERE token_hash = ? AND kind IN ('SESSION','USER') AND revoked_at IS NULL AND expires_at > now() RETURNING principal, roles, kind`.

🔒 **INV-A4-56 — the two ephemeral kinds are excluded from the wire-session
handshake.** Quote (`:178-182`): _"A transient editor/approver-exec token
authorizes exactly ONE proxy-mediated query via the per-query `resolve` path —
it must NOT pass the wire-session handshake, so a leaked ephemeral token can't
open a native MySQL/PG session as that principal within its short TTL. Both
ephemeral kinds (editor and approver-exec) are excluded here."_ This is the
sharpest kind-scoping rule in the area: the _only_ difference between `resolve`
and `validate` besides the write is that four-kind vs two-kind `IN` list, and
widening `validate` turns every editor query token into a full wire credential.
⚠️ **No test in A4 covers it** — see §4.3.

##### `list(principal): List<WireTokenInfo>`

`WHERE principal = ? AND kind IN ('SESSION','USER') ORDER BY created_at DESC` —
"excluding transient editor-channel credentials", and implicitly excluding the
MCP kinds.

##### `get(id): WireTokenInfo?`

`WHERE id = ?` — **no kind filter at all**, unlike `list`. This asymmetry is the
root of the `DELETE /api/tokens/{id}` finding in §5.

##### `revoke(id, principal): Boolean`

`UPDATE … SET revoked_at = now() WHERE id = ? AND principal = ? AND revoked_at IS NULL`
→ `rows > 0`. Idempotent; a second revoke returns `false` → 404.

##### `revokeAllForPrincipal(principal[, c]): Int`

`UPDATE … SET revoked_at = now() WHERE principal = ? AND revoked_at IS NULL AND expires_at > now()`.

🔒 **INV-A4-57 — the deprovisioning backstop kills live credentials
mid-window.** Quote (`:236-241`): _"a SCIM `active=false` push or a failed IdP
liveness recheck kills live credentials mid-window, without waiting for natural
expiry."_ The `expires_at > now()` predicate makes it idempotent and keeps
already-expired rows untouched, so the returned count is "how many live
credentials did this deprovision actually kill". **Note it revokes every kind,
including `MCP_ACCESS`/`MCP_REFRESH`** — correct for a deprovision, and the one
place the MCP kinds are handled by A4 code.

##### `ResultSet.toInfo()` · private

All four timestamps via `getTimestamp(...)?.toInstant()?.toString()`.

#### `tokenRoutes(config, store, userGroupStore, authz)`

Helpers: `principalOf(call) = call.userSession()?.principal ?: "debug-user"` and
`rolesOf(call) = call.userSession()?.roles ?: emptyList()` — the latter is
**always empty** for a real session (INV-A4-2 / §3.1).

🔒 **INV-A4-58 — credential issuance is a Cedar decision AND a locked
deactivation check.** Both mint routes call
`requireAuthz(TOKEN_MINT, Token(self, <kind>))` **and then** wrap the INSERT in
`mintForActivePrincipalLocked`. Quote (`:279-282`): _"A deprovisioned principal
must not mint fresh wire credentials, even mid-session — and the check + the
INSERT run on ONE transaction under the per-principal advisory lock, so a
concurrent SCIM/liveness teardown can't slip its revoke between them and leave a
token that survives the deprovision (resurrectable on a later reactivation)."_
The Cedar resource carries the concrete kind so a kind-scoped forbid can bar a
role from long-lived PATs while still permitting sessions (A2 INV-A2-3).
`TokenRoutesDeactivationTest`'s two cases pin the 403.

`POST /api/tokens` responds **201**; `POST /api/wire-tokens` responds **200** —
an inconsistency, but a _wire_ one that `web/` and `pmon` already depend on.
`input.name?.ifBlank { null }` normalizes a blank name to NULL.

**The two TTL defaults differ, and neither route clamps explicitly.**

| Route                   | TTL expression                                                                    | Default when the client omits `ttlSeconds` |
| ----------------------- | --------------------------------------------------------------------------------- | ------------------------------------------ |
| `POST /api/wire-tokens` | `receive<MintSessionTokenInput>().ttlSeconds ?: store.sessionTtlSeconds` (`:277`) | **43 200 s (12 h)**                        |
| `POST /api/tokens`      | `input.ttlSeconds ?: store.defaultUserTtlSeconds` (`:305`)                        | **3 600 s (1 h)**                          |

Neither route calls `clampTtlSeconds` itself — the clamp lives **inside**
`TokenStore.issue` (`:126`), so it is applied exactly once, on every path,
including the two A7 ephemeral kinds and the renew route. That single choke
point is what makes INV-A4-52 hold globally. A Go port that clamps at the route
instead must clamp at **all six** issuance call sites (`/api/wire-tokens`,
`/api/tokens`, `/auth/session/renew`, device poll, `RunExecService.run`,
`RunExecService.openSession`) or it loses the invariant on whichever one it
forgets. Keep the clamp in `issue`.

Also note `principalOf`/`rolesOf` are **file-private top-level** functions
(`Tokens.kt:267-268`), not methods on `TokenStore` — and they take a
fully-qualified `io.ktor.server.application.ApplicationCall` because the file
imports no Ktor application package. Cosmetic in Kotlin, but it is why they do
not appear as store members.

---

## 4. Test inventory — 15 files, 4,030 LOC, **110 cases**

Counted with `grep -rhoE '@Test\b' --include='*.kt' <file> | wc -l` per file.
**Every per-file count equals the number of enumerated case names below**, and
every enumerated name is the verbatim backticked `fun` name in source order —
re-verified file by file in an independent audit pass
(`grep -oE 'fun \`[^\`]+\`'`per suite). LOC re-verified with`wc -l`:
346+433+498+116+65+339+598+381+ 292+103+163+330+109+35+222 = **4 030**. Cases:
17+8+9+4+1+14+8+5+8+4+8+12+2+4+6 = **110**. None of the 15 appears in the
areas-already-counted exclusion list (A1/A2/A6/A7/A8/A9/A11/A12).

🚨 **RECONCILIATION CONFLICT — `TokenTtlTest` (4 cases) is counted TWICE across
the doc set.** `14-auth.md:1038-1046` has its own
`### TokenTtlTest.kt — 35 LOC, 4 cases` section which states, in bold: _"**A4
must not count it again**"_ (and records the same observation as its own
**F21**). `14-auth.md` nevertheless includes those 4 in its stated total
(`3 files, 302 LOC, 17 cases` = `McpOAuthStoreDbTest` 6 + `TokenTtlTest` 4 +
`OidcGroupMappingTest` 7). A4 also counts them here. Both docs agree on the
_technical_ fact — the suite is in package
`com.ridi.oss.proxymonster.controlplane` with no `import …proxymonster.auth.*`,
so all five symbols resolve to `Tokens.kt:75-81` (A4), not
`auth/McpOAuth.kt:15-18` — they disagree only on who counts it. **Arithmetic:**
the six not-yet-excluded areas currently claim A3 105 + A4 110 + A5 69 + A10
104 + A13 56 + A14 17 = **461** against a target of **460**, i.e. exactly
**+1**, so the 4-case double-count is _not_ the only discrepancy — at least
three cases are also unclaimed somewhere (A4's Q8 names two candidates:
`MePermissionsRouteTest` 7 and `ReadinessDiagnosticDbTest` 2; a full
unclaimed-suite sweep belongs to `00-INDEX.md`, not here). **A4's number is 110
as written and as counted; if the index resolves the collision in A14's favour
A4 becomes 106 (14 files, 3 995 LOC).** Do not silently drop it here — that
would hide the remaining ±3 rather than expose it.

**Suite-assignment reasoning.** Four suites the brief flagged as ambiguous are
**not** A4's: `TrustChainInspectionTest` (7) exercises `grpc/inspectTrustChain`
over datasource certificate chains → A5; `WireCertRouteDbTest` (5) exercises the
datasource wire-certificate download route (it merely uses A4's
`webSessionCookie` fixture to authenticate) → A5; `SchemaKeyWiringTest` (3)
exercises analyzer catalog-key wiring → A5/A6; `ReadinessDiagnosticDbTest` (2)
exercises `RoleResolver.hasActiveAssignee` and `/health` → A3/A1. Two
reassignments in the other direction, both stated so the index can dedupe:
**`TokenTtlTest` (4) IS A4's** — the brief marked it "auth module", but the file
is `control-plane/src/test/.../TokenTtlTest.kt` and every assertion calls
`clampTtlSeconds`, `TOKEN_MIN/MAX_TTL_SECONDS`, `SESSION_TTL_SECONDS`,
`DEFAULT_USER_TTL_SECONDS` — all `Tokens.kt:75-81`.
**`AuthAndIngestRoutesDbTest` (6) is counted here** because 3 of its 6 cases are
A4 surfaces (`/auth/me` unauthenticated, `/auth/debug` 404 when the bypass is
off, wire-token Bearer on datasource discovery); the other 3 (audit ingest ×2,
`StatusPages` fallback) are A8/A1 and **no completed area doc claimed the
file**. `MePermissionsRouteTest` (7) is _not_ counted here — it tests A1's
`/api/me/permissions` (`App.kt:292-294`, gated by `requireApi`) and A2's
`computeMePermissions` (`App.kt:255`), using A4's cookie fixture only as
scaffolding. `OidcDiscoveryTest` (4) and `IdTokenValidatorTest` (8) test the
`:auth` implementations reached through A4's typealias shims; they live in the
control-plane test tree and A4 is the only consumer, so they are counted here.
✅ **Confirmed non-conflicting:** `14-auth.md:1078-1079` lists both suites in
its own deferral table with the explicit owner column value **"A4 (assign
there)"**, so A14 does _not_ count them. That earlier hedge ("if `14-auth.md`
also claims them, drop them from A4") is now resolved and no longer conditional.
The only real collision is `TokenTtlTest`, above.

### 4.1 `DaemonSessionStoreDbTest.kt` — 346 LOC, 17 cases · **DB**

1. create round-trips and encrypts the refresh token at rest (INV-A4-14)
2. 🔒 no crypto configured means the refresh token is never persisted, not even
   plaintext (INV-A4-14)
3. no refresh token at all round-trips as null (device flow without
   offline_access)
4. `getByHandle` finds the exact session
5. `getByPrincipal` returns the most recent session
6. `withinWindow` is true right after create and false once the window has
   passed (INV-A4-27)
7. 🔒 `withinWindow` is false, fail-closed, for a principal with no session at
   all
8. `markCheck` stamps `last_idp_check_at` and the liveness status
9. 🔒 `markCheck` connection overload stamps within the transaction and
   preserves an ended row status (INV-A4-28)
10. `staleSessions` returns live stale daemon and web rows and excludes fresh
    ended or expired rows
11. `updateRefresh` rotates the stored ciphertext
12. `updateRefresh` is a no-op when no crypto is configured
13. 🔒 `getByRenewalTokenHash` resolves the session by the hashed bearer secret,
    and a wrong hash finds nothing (INV-A4-26)
14. 🔒 `deactivateAllForPrincipal` closes EVERY in-window session for the
    principal and marks them INACTIVE (INV-A4-29)
15. 🔒 daemon lookups stay isolated while liveness operations cover web rows
    (INV-A4-13)
16. `endAllWebForPrincipal` ends only live web rows for one principal and is
    idempotent
17. 🔒 `withinWindow` ignores a still-open WEB row once the daemon window has
    closed (INV-A4-13)

### 4.2 `DaemonSessionLivenessIdpTest.kt` — 433 LOC, 8 cases · **DB + embedded fake IdP**

Fixture worth porting first: a real Netty server on an ephemeral port serving
`/.well-known/openid-configuration`, `/jwks` (a generated RSA JWK), and
`/token`, which selects its response from the presented `refresh_token` string
(`rt-invalid-grant`, `rt-invalid-client`, `rt-http-500`, `rt-no-groups:<p>`,
`rt-active:<p>:<groups>`), plus an `AtomicInteger` counting token requests.
`⟦LIB⟧` a signed-JWT builder for the test IdP.

1. 🔒 fresh fewer groups end only the zero-role web session and preserve
   inactive liveness (INV-A4-38, INV-A4-28)
2. still-grouped and direct-role web users survive with fresh checks
3. 🔒 omitted groups claim is authoritative empty and removes old membership
   (INV-A4-38)
4. 🔒 invalid grant closes only its daemon row while a valid sibling and
   credentials survive (INV-A4-40)
5. 🔒 all rejected session tokens retire every row in one sweep without
   principal teardown
6. 🔒 transient invalid client and server errors preserve both session kinds and
   credentials (INV-A4-40, INV-A4-39)
7. sessions without stored refresh tokens remain live and unstamped (INV-A4-14)
8. 🔒 renew route never revalidates and only the timer sweep reaches the token
   endpoint (INV-A4-34)

### 4.3 `PrincipalSessionStoreDbTest.kt` — 498 LOC, 9 cases · **DB**

1. web session lifecycle separates validation from idle touch without moving the
   absolute cap (INV-A4-20, 21, 22)
2. 🔒 newest web session displaces only same-principal web siblings (INV-A4-17)
3. the session-end seam invokes the editor-cleanup callback on every ending path
   (INV-A4-18, 23, 30)
4. 🔒 deprovision-composed cleanup rolls back with an aborted teardown
   transaction (INV-A4-30)
5. 🔒 device mismatch ends a live web row permanently without sliding idle
   (INV-A4-19 — all three sub-cases)
6. 🔒 resolve web requires both live clocks and excludes daemon rows
   (INV-A4-13, 20)
7. web ended reason is returned only for web rows
8. 🔒 web mint waits for the principal lock and leaves exactly one active web
   row (INV-A4-16, 17)
9. 🔒 web refresh token is omitted when encryption is unavailable (INV-A4-14)

Case 8 is the single most valuable test in the area: it holds the principal
advisory lock for ~2 s from another connection and then asserts the delayed
mint's deadlines are **full-duration measured from completion**. A `now()`-based
implementation passes every other test and fails only this one. ⚠️ `webRowCount`
(`PrincipalSessionStoreDbTest.kt:449`) is a private helper with **no caller** —
dead test code.

### 4.4 `PrincipalSessionStorageDbTest.kt` — 116 LOC, 4 cases · **DB**

1. write links a web row and steals a reused key from its prior holder
   (INV-A4-25)
2. 🔒 read returns live ended and expired refs without changing idle state
   (INV-A4-12)
3. 🔒 invalidate signs out only active rows and preserves an existing terminal
   reason (INV-A4-23)
4. 🔒 daemon rows cannot be linked or reached through web session keys
   (INV-A4-13)

### 4.5 `PrincipalSessionSchemaDbTest.kt` — 65 LOC, 1 case · **DB (schema)**

1. the session table carries its indexes and a partial-unique session key
   (INV-A4-25)

### 4.6 `DeviceLoginStoreDbTest.kt` — 339 LOC, 14 cases · **DB + route**

1. create then get round-trips a pending row
2. unknown handle is absent
3. a login is retrievable by its `user_code` and a fresh one is well-formed
4. 🔒 `markApproved` sets status and principal, only once (INV-A4-42)
5. 🔒 `markApproved` refuses an expired handle (INV-A4-42)
6. `purgeExpired` removes only expired rows
7. the verification URL points at the web console origin, not the control plane
   (INV-A4-45)
8. confirm accepts a real pending code and rejects an unknown one
9. 🔒 authorize without a prior confirm approves nothing and bounces back to the
   device page (INV-A4-46)
10. 🔒 a confirm for one code cannot authorize a different code (INV-A4-46)
11. 🔒 authorize with no session sends the user to login and approves nothing
    yet
12. an existing console session approves the login without re-authenticating
    (INV-A4-48)
13. a login mints a wire token end-to-end via start, confirm, authorize, then
    poll
14. 🔒 a device handle mints exactly once — a replayed poll is refused and mints
    no second session (INV-A4-43)

### 4.7 `WebSessionRoutesDbTest.kt` — 598 LOC, 8 cases · **DB + route (`testApplication`, full `module()`)**

1. auth config exposes default session UX timings
2. auth config normalizes a mixed-unit absolute cap to minutes
3. 🔒 debug login resolves through the database and logout ends the row
   (INV-A1-6, INV-A4-7; also asserts `pm_session` `Max-Age` =
   `PM_WEB_SESSION_ABSOLUTE`, and `pm_did`
   `Max-Age=7776000`/`Path=/`/`HttpOnly`/`SameSite=Lax` — INV-A4-9)
4. conditional logout ends only the session id observed by the client (INV-A1-9)
5. 🔒 expired and ended web rows fail closed (INV-A4-20)
6. session observation and ordinary authenticated routes never slide idle while
   heartbeat does (INV-A4-20, 21)
7. 🔒 session status and me surface displacement and bind mismatch reasons
   (INV-A4-3, 19 — includes `/auth/me` as the **first** mismatching request, and
   an **absent** `pm_did`)
8. 🔒 a pre-cutover principal-roles cookie fails closed to unauthenticated
   (INV-A4-2, 10)

Case 3 also encodes A3 behaviour the port must not lose: a claimed role must
exist (404 naming it), the claim REPLACES the direct set, an empty claim is a
deliberate wipe, and a failed claim leaves **neither** roles nor a session row
behind.

### 4.8 `OidcWebSessionDbTest.kt` — 381 LOC, 5 cases · **DB + route**

1. oidc callback mints web row and stores refresh only when encrypted offline
   access is available (INV-A4-14, INV-A4-61)
2. 🔒 oidc callback denies a principal with zero effective roles without minting
   a session (INV-A4-60)
3. oidc callback returns a successful popup reauth to its landing route
4. a device login with no session logs in via SSO and comes back to approve the
   handle (INV-A4-59)
5. 🔒 a direct authorize link with no device-page confirm approves no handle
   (INV-A4-46)

### 4.9 `OidcCallbackTest.kt` — 292 LOC, 8 cases · route (`testApplication`)

1. 🔒 OIDC continuation accepts only the co-hosted resume and reauth routes
   (INV-A4-59)
2. unconfigured oidc degrades both routes to 501
3. provider error param redirects to `error=oidc`
4. provider error preserves the popup reauth continuation
5. state failure preserves the popup reauth continuation
6. provider error returns to the co-hosted OAuth resume route
7. 🔒 state mismatch redirects to `error=state`, and the state cookie is
   one-time-use (INV-A4-62)
8. 🔒 invalid id_token redirects to `error=nonce`, and the nonce cookie is
   one-time-use (INV-A4-62)

### 4.10 `OidcDiscoveryTest.kt` — 103 LOC, 4 cases · unit + embedded IdP (tests `:auth`)

1. document parses every field, required and optional
2. optional fields default to null when the IdP omits them
3. a trailing slash on the configured issuer is tolerated
4. the document is fetched once and cached across repeated calls

### 4.11 `IdTokenValidatorTest.kt` — 163 LOC, 8 cases · unit + embedded JWKS (tests `:auth`)

1. a correctly signed, matching id_token validates and surfaces claims
2. 🔒 a nonce mismatch fails closed
3. the nonce check is skipped when the caller expects none (device flow) — this
   is what makes `revalidateSession`'s `expectedNonce = null` legitimate
   (INV-A4-37)
4. 🔒 a wrong audience fails closed
5. 🔒 a wrong issuer fails closed
6. 🔒 an expired token fails closed
7. 🔒 a token signed by an untrusted key fails closed (bad signature)
8. a missing groups claim resolves to an empty list, not a failure

### 4.12 `RenewalWindowTest.kt` — 330 LOC, 12 cases · **DB + route**

1. renew with the correct bearer secret inside the window mints a fresh token
2. 🔒 a principal-only JSON body with no bearer is refused — the
   unauthenticated-renewal attack (INV-A4-26)
3. 🔒 a wrong or garbage bearer secret is refused
4. 🔒 missing Authorization header entirely is refused (INV-A4-35)
5. 🔒 renew after the window closed is refused even with the correct secret
   (INV-A4-27, 32)
6. 🔒 renew for a deprovisioned principal is refused even inside the window
   (INV-A4-31)
7. 🔒 renew for a liveness-INACTIVE session is refused even inside the window
   (INV-A4-31)
8. 🔒 authoritative principal deprovision refuses renewal on every sibling
   session (INV-A4-29)
9. 🔒 a deprovision-then-reactivate cannot resurrect the old renewal secret
   (window stays closed) (INV-A4-29)
10. 🔒 renew mints under the lock, so an immediately-following teardown sweeps
    up the just-minted token (INV-A4-31)
11. 🔒 a renew blocks behind a concurrent holder of the SAME principal's
    advisory lock, then observes its committed state (INV-A4-31)
12. 🔒 `revokeActiveCredentials` itself blocks behind a concurrent holder of the
    SAME principal's advisory lock (A3 cross-check)

### 4.13 `TokenRoutesDeactivationTest.kt` — 109 LOC, 2 cases · **DB + route**

1. 🔒 `POST /api/wire-tokens` for a deactivated principal is refused before
   minting (INV-A4-58)
2. 🔒 `POST /api/tokens` for a deactivated principal is refused before minting
   (INV-A4-58)

### 4.14 `TokenTtlTest.kt` — 35 LOC, 4 cases · unit (no DB)

1. requests within the window are unchanged
2. 🔒 over-long requests are capped at 24h (INV-A4-52)
3. 🔒 tiny, zero, and negative requests are floored to the minimum (INV-A4-52)
4. 🔒 every clamped ttl is a bounded, positive lifetime (INV-A4-52)

Cheapest possible signal in the area — port first, no container needed.

### 4.15 `AuthAndIngestRoutesDbTest.kt` — 222 LOC, 6 cases · **DB + route** (mixed A4/A8/A1)

1. 🔒 auth me without a session is unauthenticated _(A4)_
2. 🔒 auth debug is a 404 endpoint when `PM_AUTH_DEBUG` is off _(A4)_
3. ingest with a wrong token is an invalid ingest token _(A8)_
4. an unhandled exception is caught by the `StatusPages` fallback without
   leaking the cause _(A1)_
5. ingest with the correct token and a minimal record is accepted _(A8)_
6. 🔒 datasource discovery accepts a wire-token Bearer and rejects missing or
   bad auth _(A4 `TokenStore.resolve` + A5 route)_

### 4.16 Kind and fixture summary

| Kind                                  | Suites                                                                                                                                                                                      | Cases   |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| unit (no DB, no container)            | `TokenTtlTest`                                                                                                                                                                              | 4       |
| unit + embedded HTTP IdP              | `OidcDiscoveryTest`, `IdTokenValidatorTest`                                                                                                                                                 | 12      |
| DB (Testcontainers Postgres)          | `DaemonSessionStoreDbTest`, `PrincipalSessionStoreDbTest`, `PrincipalSessionStorageDbTest`, `PrincipalSessionSchemaDbTest`                                                                  | 31      |
| DB + route (`testApplication`)        | `DeviceLoginStoreDbTest`, `WebSessionRoutesDbTest`, `OidcWebSessionDbTest`, `RenewalWindowTest`, `TokenRoutesDeactivationTest`, `AuthAndIngestRoutesDbTest`, `DaemonSessionLivenessIdpTest` | 55      |
| route only (`testApplication`, no DB) | `OidcCallbackTest`                                                                                                                                                                          | 8       |
| **total**                             | **15 files**                                                                                                                                                                                | **110** |

Fixtures: `support/TestDatabases.kt` (`SharedPostgres.freshDatabase`,
`requireDockerOrSkip`) and `support/WebSessionTestSupport.kt` — the latter is
**A4-owned** (its single symbol is `fun SessionsConfig.webSessionCookie(…)`,
`WebSessionTestSupport.kt:13`, registering a `pm_session` cookie backed by
`PrincipalSessionStorage` with the HMAC transform). **Port it early.** The
complete consumer list, from `grep -rln webSessionCookie test/` (11 suites, 7
areas other than A4):

| Area     | Suites                                                          |
| -------- | --------------------------------------------------------------- |
| A1       | `MePermissionsRouteTest`                                        |
| A2       | `AdminContextAuthzTest`                                         |
| A5       | `WireCertRouteDbTest`                                           |
| A6       | `EditorSubmitRouteDbTest`, `ElevationContextRouteAuthzDbTest`   |
| A7       | `ApprovalExecuteRouteDbTest`, `ApprovalResultViewContextDbTest` |
| A8       | `AuditReadRoutesDbTest`                                         |
| A11      | `oauth/OAuthRoutesDbTest`                                       |
| A4 (own) | `DeviceLoginStoreDbTest`, `OidcWebSessionDbTest`                |

⚠️ An earlier draft listed the consumers as "A2, A5, A6, A7, A11" — that
enumeration **omits A1 and A8** even though the same sentence correctly said
"seven other areas". The table above is the checked list.

### 4.17 Coverage gaps in A4

1. 🔒 **`TokenStore.validate`'s two-kind `IN` list (INV-A4-56) is untested.**
   Nothing asserts that an `EDITOR` or `APPROVER_EXEC` token is refused at the
   wire-session handshake while passing `resolve`. This is the single
   highest-value new test in the area: widening the list is a one-word change
   that turns every editor query token into a full native-wire credential, and
   no test would fail.
2. 🔒 **`resolve`'s exclusion of `MCP_ACCESS`/`MCP_REFRESH` is untested** — an
   MCP token must not be usable as a wire credential either.
3. `normalizeUserCode` has no direct unit test. Case-folding, punctuation
   stripping, and the 8-character re-hyphenation are only exercised
   incidentally.
4. `createPending`'s SQLSTATE-23505 retry loop is untested (it needs an induced
   unique violation). A Go port that matches on driver message text instead of
   SQLSTATE would pass every existing test.
5. `sweepSessionLiveness`'s early return when `config.oidc == null` /
   `discovery == null` is untested.
6. `revalidateSession`'s **identity-mismatch** branch (INV-A4-37 step 3c) is
   untested — the fake IdP never returns a different subject than the row's
   principal.
7. `endWeb`'s `first-reason-wins` guard is covered for `endWeb`/`invalidate` but
   **not** for the interaction that matters most: a `DISPLACED` row later logged
   out must keep `DISPLACED`.
8. `linkWebSessionKey` under concurrency (two requests claiming the same tracker
   id) is untested.
9. `webSessionIsLive`'s `idle_expires_at IS NULL` tolerance is unreachable in
   tests and unasserted.
10. `TokenStore.get`'s missing kind filter (§5 finding) has no test in either
    direction.
11. `ensureDeviceCookie`'s non-UUID replacement path (INV-A4-9) is untested.
12. `DeviceStartInput`'s tolerant body parse (a garbage body defaulting instead
    of 400) is untested.
13. The **body-parse asymmetry** across the five body-taking routes (§2.1) is
    untested in every direction: nothing asserts that `/auth/device/poll`,
    `/api/wire-tokens` and `/api/tokens` reject a missing body while
    `/auth/device/start` accepts one. A Go port is free to make all five
    tolerant (or all five strict) and every existing test still passes.
14. 🔒 **Gate-before-parse ordering on the two mint routes** (`requireAuthz` at
    `Tokens.kt:276`/`:303` _before_ `receive` at `:277`/`:304`) is untested.
    Nothing asserts that an unauthorized caller with a malformed body gets
    401/403 rather than 400 — i.e. nothing stops a port from leaking "your JSON
    is wrong" to a principal that was never allowed to mint.
15. `RefreshTokenResponse`'s required `access_token` (INV-A4-65 / F34) is
    untested — the fake IdP's `/token` always includes one
    (`DaemonSessionLivenessIdpTest.kt:113,123`), so neither the current
    `Transient` behaviour nor an all-optional Go rewrite would be caught.
16. `TokenStore.list`'s **exclusion of the MCP kinds** is untested. `list`
    filters `kind IN ('SESSION','USER')`, so an `MCP_ACCESS` row must never
    appear in `GET /api/tokens`; no case inserts an MCP row and asserts its
    absence. Pairs with gaps 2 and 10 — all three are the same missing fixture
    (a seeded MCP token) and should be closed together.
17. 🔒 **Refresh-token rotation is untested through the sweep.**
    `revalidateSession` step 3a calls `updateRefresh` when the IdP returns a
    rotated `refresh_token`, but the fake IdP **never sends a `refresh_token`**
    on either 200 branch (`DaemonSessionLivenessIdpTest.kt:113,123`) — so
    `outcome.rotatedRefreshToken` is always `null` in every test. Rotation is
    covered only at store level (`DaemonSessionStoreDbTest` cases 11 and 12).
    Nothing asserts that a rotated token is persisted **before** the id_token is
    validated (it is: `DaemonSession.kt:718-720` runs ahead of `:721`), which
    matters because a rotating IdP invalidates the old token on issue — skip the
    write and the very next sweep gets `invalid_grant` and revokes a session
    that was never revoked at the IdP. This is the highest-value missing
    liveness test after gap 6.

Gaps 1, 2, 10, 14, 16 and 17 are **security** gaps and the prime Step 3
hardening targets. Gaps 2, 10 and 16 share one cheap enabler: a fixture that
inserts a valid `MCP_ACCESS` row (it must satisfy `proxy_token_mcp_metadata_ck`,
so it needs a real `oauth_consent` row plus
`resource`/`client_id`/`scope`/`refresh_family` and `roles = '[]'` — see
`V7__tokens.sql:76-93`).

---

## 5. Candidate findings

🚨 **The `F21+` numbering in this file COLLIDES with five other area docs.**
Verified with `grep -ohE '\bF[0-9]{1,3}\b' <doc>` across the set:
`03-identity-scim.md` uses F21–F34, `04` (this file) F21–F32,
`05-datasources-catalog.md` F21, `10-grpc.md` F21–F30, `13-engine.md` F21–F31,
`14-auth.md` F21–F41. All six "remaining" areas independently started at F21
because each was told "number as F21+ — I did not edit `00-INDEX.md`", and
`00-INDEX.md` contains no `F`-number registry at all (`grep` for
`F2[0-9]`/`F3[0-9]` there returns nothing). So **A4's F21 (token kind filter)
and A14's F21 (duplicate `clampTtlSeconds` / `TokenTtlTest` assignment) are
different findings with the same id**, and so are F22–F32 across every pair of
these docs. Until the index assigns disjoint ranges, cite findings from this
area as **`A4-F21`…`A4-F38`**, never bare `F21`. This is itself finding **F36**.

| #       | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Where                                             | Kind                             |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | -------------------------------- |
| F21     | 🔒 `TokenStore.get(id)` has **no kind filter** while `list` restricts to `('SESSION','USER')`, so `DELETE /api/tokens/{id}` can target an `MCP_ACCESS`/`MCP_REFRESH`/`EDITOR`/`APPROVER_EXEC` row. For the MCP kinds `TokenKind.fromWire` returns **null**, so the Cedar resource is built with `kind` **absent** — and per A2 INV-A2-3 absence is the _permissive_ direction for a kind-scoped forbid. `Tokens.kt:26-30` claims null makes "callers fail closed"; at this call site it does the opposite. **Reachability, now checked:** the shipped `system:token-admin` seed permits `token.revoke` on _any_ principal's tokens (`V8__seed.sql:128-129`), and the neighbouring hard forbid `system:token-no-cross-mint` covers **`token.mint` only** (`:136-137`) — its own comment says _"Listing metadata and revoking stay cross-user, for that admin oversight"_. So an admin today can already revoke another principal's `MCP_ACCESS` or in-flight `EDITOR` token through this route. No shipped seed forbids by kind (`V8__seed.sql:121-123` only _suggests_ one: _"Tighten per deployment, e.g. a forbid on resource.kind == \"USER\""_), so the **authorization** hole is latent; the **cross-kind reachability** is live | `Tokens.kt:216,324`; `V8__seed.sql:121-137`       | 🔒 latent bug                    |
| F22     | `POST /auth/device/confirm` stores the **normalized** user code in the verify cookie (`DeviceVerifySession(row.userCode)`) while `GET /auth/device/authorize` compares it to the **raw** `?user_code=` query parameter with exact `!=`. A lowercase or punctuated URL therefore never authorizes, even after a successful confirm of the same code. `getByUserCode` normalizes; the cookie comparison does not                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `DeviceAuth.kt:299,310`                           | inconsistency                    |
| F23     | `runTokenTtlSeconds = max(900, queryTimeout + 180)` (A7) is passed through `clampTtlSeconds`, which caps at `TOKEN_MAX_TTL_SECONDS` (24 h), while `Config`'s only bound on `PM_QUERY_TIMEOUT` is an overflow guard (`MAX_QUERY_TIMEOUT_SECONDS = 9_223_372_006`). A query timeout above ~23 h 57 m yields a run token that is **silently clamped to expire mid-statement** — exactly the failure `TOKEN_TTL_GRACE_SECONDS` exists to prevent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `Tokens.kt:81`, `RunExec.kt:648`, `Config.kt:138` | possible bug                     |
| F24     | `revalidateSession` skips `markCheck` on three paths (no refresh token, no/invalid id_token, principal mismatch), so such a row stays permanently stale and is re-selected and re-warned on **every** sweep. Correct-by-design for the no-token case (pinned by a test); an unbounded warn loop for the other two                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `DaemonSession.kt:710-735`                        | inefficiency                     |
| F25     | `V6__sessions.sql:21` documents `status TEXT … -- PENDING \| APPROVED` but the code writes and reads a third value, `CONSUMED` (`DeviceLoginStore.consume`), which `DeviceLoginRow`'s own comment lists                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `V6__sessions.sql:21`                             | stale doc                        |
| F26     | `V7__tokens.sql:48-52` enumerates `kind` as SESSION / USER / MCP_ACCESS / MCP_REFRESH and **omits `EDITOR` and `APPROVER_EXEC`**, both of which are inserted by `RunExecService`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `V7__tokens.sql:48`                               | stale doc                        |
| F27     | `Oidc.kt:58` documents "A 32-byte random, URL-safe-ish opaque token" over an implementation that allocates `ByteArray(24)` (192 bits). Both `state` and `nonce` are affected. 192 bits is ample; the comment is simply wrong                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `Oidc.kt:58-62`                                   | stale doc                        |
| F28     | `private const val DEV_PRINCIPAL = "debug-user"` in `DeviceAuth.kt` is never referenced. The same literal is hard-coded twice more (`Tokens.kt:267`, `Datasources.kt:752`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `DeviceAuth.kt:240`                               | dead code + duplication          |
| F29     | The idle window is specified twice — `mintWeb(idleSeconds)` as a parameter vs `touchWeb` reading the constructor field `webSessionIdleSeconds` — with nothing enforcing agreement. `App.kt:386` happens to pass the same config value to both                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `DaemonSession.kt:117,166,229`                    | duplication                      |
| F30     | `webSessionIsLive` uses `now()` and tolerates `idle_expires_at IS NULL`, while `resolveWeb`/`touchWeb` use `clock_timestamp()` and require a live idle deadline. Same for `endWeb`(`now()`) vs `mintWeb`'s displacement (`clock_timestamp()`). Neither divergence is currently reachable differently, but the file's own comments argue at length that the choice is load-bearing                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `DaemonSession.kt:206,289,332`                    | inconsistency                    |
| F31     | `PrincipalSessionStoreDbTest.kt:449`'s private `webRowCount` helper has no caller                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | test file                                         | dead code                        |
| F32     | `RefreshErrorBody.error_description` is parsed and never read                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `DaemonSession.kt:772`                            | dead field                       |
| **F33** | `deviceSessionRoutes(…, log: Logger)` accepts a logger and **never uses it** — `grep -n 'log\.' DeviceAuth.kt` returns nothing. Consequence beyond the dead parameter: the entire device-auth surface emits **zero** log output, including on `device.unknown_or_expired_login`, `device.login_already_completed`, and the no-confirm authorize bounce (the anti-phishing refusal, INV-A4-46). A device-phishing attempt against a real user is therefore **forensically invisible** — nothing in the CP logs distinguishes it from an abandoned login. `oidcRoutes` logs every comparable failure branch (`Oidc.kt:134,144,149,154,177,189,209`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `DeviceAuth.kt:266`                               | 🔒 dead code + observability gap |
| **F34** | `RefreshTokenResponse.access_token: String` has **no default** and is **never read**, so an IdP token response omitting it fails kotlinx deserialization → generic `catch (e: Exception)` → `Transient`. `oidcHttpClient()` configures only `Json { ignoreUnknownKeys = true }` (`auth/Oidc.kt:98`) — no `coerceInputValues` — so nothing softens it. Harmless against a compliant IdP (RFC 6749 §5.1 makes it REQUIRED) and arguably fail-safe, but it is an **undocumented** required field on a liveness path whose whole design is "transient failures change nothing", and a Go port with all-optional fields diverges to `Active` + a nil `id_token`. See INV-A4-65                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `DaemonSession.kt:766`                            | possible bug                     |
| **F35** | 🔒 The reason device-binding treats an **absent** `pm_did` as a mismatch rather than a wildcard exists **only in test comments** (`PrincipalSessionStoreDbTest.kt:295-297`, `WebSessionRoutesDbTest.kt:542`). Production `resolveWeb` (`DaemonSession.kt:248-280`) carries **no comment at all** on the branch — the single most security-load-bearing three-way condition in the file is unannotated in the code a maintainer would edit. (An earlier draft of this document mis-cited the quote as `DaemonSession.kt:295-298`, which is `endWeb`'s parameter binding — the mis-citation is itself evidence of how easy the comment is to lose)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `DaemonSession.kt:274-279`                        | 🔒 undocumented invariant        |
| **F36** | `F21+` finding ids collide across all six not-yet-indexed area docs (A3, A4, A5, A10, A13, A14) because each began numbering at F21 and `00-INDEX.md` holds no finding registry. Six distinct findings currently share the id `F21`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `00-INDEX.md`, all six area docs                  | doc process defect               |
| **F37** | `TokenTtlTest` (4 cases) is counted in **both** `04` §4.14 and `14-auth.md` §7, the latter while explicitly instructing _"A4 must not count it again"_. The six remaining areas therefore claim 461 against a 460 target                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `14-auth.md:1038-1046`                            | inconsistency                    |
| **F38** | `device_login.interval_sec` is declared `INTEGER NOT NULL DEFAULT 5` (`V6__sessions.sql:19`) but every insert path binds `DEVICE_POLL_INTERVAL_SEC = 2` explicitly (`DeviceAuth.kt:241,273`), and `create` always passes the parameter — the DB default is unreachable, and it disagrees with the value `pmon` is actually told to poll at (`DeviceStartResponse.interval = 2`). A Go port that omits the column on insert would silently ship a 5-second poll interval                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `V6__sessions.sql:19`                             | stale default                    |

Also carried forward, not new: `?::jsonb` vs `PGobject` (F16) gains a third
instance at `Tokens.kt:131`.

**Findings the audit pass CHECKED and did NOT confirm** (recorded so nobody
re-opens them): `DeviceStartResponse.interval` is _not_ the handle TTL (already
noted correctly under INV-A4-45); `webSessionIsLive`'s `now()` is _not_
reachable inside a lock wait (its caller `GET /auth/device/authorize` step 6
runs on a fresh auto-commit connection with no advisory lock, so F30 remains an
inconsistency and not a live bug); `TokenStore.hash` is _not_ a third hash
implementation (it delegates to `tokenHash`); and
`PrincipalSessionStorage.read`'s missing `ended_at` filter is deliberate
(INV-A4-12), not an oversight.

---

## 6. Remaining symbols — `Oidc.kt` (authorization-code flow)

### `randomOpaqueToken(): String` · private top-level

`base64url-nopad(ByteArray(24))` = **192 bits**, used for **both** `state` and
`nonce` (`Oidc.kt:59-63`). ⚠️ Two things a port must not copy: (a) the KDoc says
"A 32-byte random" over a 24-byte body — see F27; (b) it constructs a **fresh
`SecureRandom()` on every call** (`:61`), unlike
`Tokens.kt`/`DaemonSession.kt`/`DeviceLoginStore`, which each hold one
long-lived instance. Harmless on the JVM (seeding is cheap after first use) and
irrelevant in Go, where `crypto/rand.Read` is the only correct call — recorded
so nobody reads the difference as significant.

### `oidcRoutes(config, discovery, validator, http, userGroupStore, roleResolver, store, log)`

🔒 **INV-A4-59 — `return_to` is an allowlist, never an echo.**
`oidcReturnTarget(raw)` accepts exactly three shapes: `"/oauth/resume"`,
`"/auth/reauth-complete"`, and
`Regex("/auth/device/authorize\\?user_code=[A-Za-z0-9-]{1,16}")`. Everything
else becomes `null`. Quote (`Oidc.kt:95-96`, and the second comment at
`:217-218`): _"Only the co-hosted OAuth resume and popup re-auth landing routes
are valid continuations. Treat every other value as absent, so this can never
become an open redirect."_ `OidcCallbackTest` case 1 pins it. Note the regex is
anchored by `matches` (whole-string) and permits only `[A-Za-z0-9-]` in the code
— so a user code containing anything else silently loses its continuation and
the user lands on `/` instead of completing the device login.

**`GET /auth/oidc/login`**

1. `config.oidc == null || discovery == null || validator == null` ⇒ **501**
   `common.oidc_not_configured`. All three are checked so an unconfigured
   deployment "never NPEs".
2. `state = randomOpaqueToken()`, `nonce = randomOpaqueToken()` (192 bits each).
3. `returnTo = oidcReturnTarget(query["return_to"])`.
4. Set `OAUTH_STATE_COOKIE = OAuthStateSession(state, returnTo)` and
   `OAUTH_NONCE_COOKIE = OAuthNonceSession(nonce)`.
5. Redirect to `document.authorization_endpoint` with `client_id`,
   `response_type=code`, `scope`, `redirect_uri`, `state`, `nonce` — each
   `encodeURLParameter()`'d individually.

⚠️ No PKCE on this flow (contrast A11's MCP AS, where V7's `CHECK` makes
`code_challenge` mandatory). This is a confidential client with a
`client_secret`, so PKCE is optional per OAuth 2.1; recorded so the port does
not "restore" it and break the redirect-URI registration.

**`GET /auth/oidc/callback`**

1. Same 501 guard.
2. Read `code`, `state` from the query;
   `stateSession = sessions.get<OAuthStateSession>()`;
   `expectedNonce = sessions.get<OAuthNonceSession>()?.nonce`.
3. 🔒 **Clear BOTH cookies immediately, before any validation** (INV-A4-62).
4. `state == null || expectedState == null || state != expectedState` ⇒ log,
   then redirect: to `oidcFailureTarget(access_denied, "state")` **only when**
   `returnTo == "/auth/reauth-complete"`, otherwise the flat
   `"/login?error=state"`.
5. `query["error"] != null` ⇒ `oidcFailureTarget(access_denied, "oidc")`.
6. `code == null` ⇒ `oidcFailureTarget(server_error, "state")`.
7. `expectedNonce == null` ⇒ `oidcFailureTarget(access_denied, "nonce")`.
8. Inside `try`:
   `submitForm(document.token_endpoint, grant_type=authorization_code, code, redirect_uri, client_id, client_secret)`
   → `TokenResponse`.
9. `claims = validator.validate(token.id_token, expectedNonce)`; null ⇒
   `oidcFailureTarget(access_denied, "nonce")`.
10. `principal = claims.email ?: claims.subject`.
11. `userGroupStore.provisionFromOidc(principal, claims.email, claims.groups, oidc.groupMapping)`
    (A3).
12. `if (roleResolver.resolve(principal).isEmpty())` ⇒ log,
    `oidcFailureTarget(access_denied, "no_access")` — **before minting
    anything**.
13. `refreshToken = token.refresh_token?.takeIf { "offline_access" in oidc.scopes.split(whitespace) .filter(isNotBlank) }`.
14. `deviceId = call.ensureDeviceCookie(config.mcpIssuer.startsWith("https://"))`.
15. `sessionId = store.mintWeb(principal, refreshToken, config.webSessionAbsoluteSeconds, config.webSessionIdleSeconds, deviceId)`.
16. `sessions.set(WebSessionRef(sessionId))`; redirect
    `stateSession?.returnTo ?: "/"`.
17. `catch (e: Exception)` ⇒ log error,
    `oidcFailureTarget(server_error, "oidc")`.

🔒 **INV-A4-60 — identity comes from the id_token only, and a zero-role
principal never gets a session.** Quote (`Oidc.kt:72-74` — the `oidcRoutes`
KDoc; an earlier draft cited `:83-86`, which is the parameter list): _"Identity
is established from the **id_token** (validated signature + issuer + audience +
expiry + nonce via [validator]), never from the userinfo endpoint or
client-asserted claims — userinfo is optional/absent on some providers and was
never signed to begin with."_ Step 12 gates before step 15, so a principal with
no effective roles reaches the no-access screen with **no `principal_session`
row created** — pinned by `OidcWebSessionDbTest` case 2. Ordering matters:
minting first and then checking would leave a live cookie for an unauthorized
user.

🔒 **INV-A4-61 — the refresh token is kept only when `offline_access` was
actually requested.** Step 13 filters on the configured scope string,
whitespace-split and blank-filtered — an IdP that returns a refresh token
unbidden does not get one persisted. Combined with INV-A4-14 (no key ⇒ no
persistence), `OidcWebSessionDbTest` case 1's title states the full condition:
"stores refresh only when encrypted offline access is available".

🔒 **INV-A4-62 — `state` and `nonce` are one-time, cleared before validation,
and check different things.** Quote (`:129`): _"One-time use: drop both cookies
regardless of the outcome below."_ Quote (`:41-46`): the nonce is _"bound into
the authorize request and echoed back inside the id_token; [IdTokenValidator]
checks the two match, which is what actually defends against authorization-code
injection — `state` alone only proves the response came back to the browser that
started the flow."_ `OidcCallbackTest` cases 7 and 8 assert each cookie is
consumed even on failure — which is what stops a replay of a failed callback.

**INV-A4-63 — group membership is SYNCED, not merely added, and deactivation is
not OIDC's job.** Quote (`Oidc.kt:183-185`): _"membership is reconciled to the
mapped claim set — added AND removed — so IdP group changes (including admin,
via system:admin) take effect on the next login. Deactivation stays SCIM's
job."_ (A3 owns `provisionFromOidc`.)

### `oidcFailureTarget(state: OAuthStateSession?, oauthError: String, consoleError: String): String` · internal

| `state?.returnTo`         | Result                                                                                     |
| ------------------------- | ------------------------------------------------------------------------------------------ |
| `"/oauth/resume"`         | `/oauth/resume?error=<oauthError>` (the OAuth AS resume needs an **OAuth** error code)     |
| `"/auth/reauth-complete"` | `/login?error=<consoleError>&callbackUrl=%2Fauth%2Freauth-complete` (literal, pre-encoded) |
| any other non-null        | `/login?error=<consoleError>&return_to=<encoded returnTo>`                                 |
| `null`                    | `/login?error=<consoleError>`                                                              |

**INV-A4-64 — a recoverable failure keeps its continuation.** Quote
(`Oidc.kt:229-231`): _"A device login that hit a recoverable failure (a
cancelled consent, a transient token-endpoint error) keeps its continuation, so
retrying the sign-in still completes the pmon login instead of silently becoming
an ordinary console login and stranding the handle until it expires."_ This is
why the function takes **two** error vocabularies: `oauthError` for the OAuth AS
resume (RFC-shaped) and `consoleError` for the console login screen (an i18n key
fragment). `OidcCallbackTest` cases 3–6 cover the matrix.

---

## 7. Cross-area dependencies

| Direction | What                                                                                                                                                                                                                                                | Area                       |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| A4 →      | `advisoryLockPrincipal`, `inTx`, `mintForActivePrincipalLocked`, `revokeActiveCredentialsTx`                                                                                                                                                        | **A3** (`Deprovision.kt`)  |
| A4 →      | `UserGroupStore.isDeactivated`, `provisionFromOidc`; `RoleResolver.resolve`                                                                                                                                                                         | **A3**                     |
| A4 →      | `ResultCrypto` (AES-256-GCM at rest)                                                                                                                                                                                                                | **A7**                     |
| A4 →      | `OidcDiscovery`, `IdTokenValidator`, `oidcHttpClient`, `OidcGroupMapping`                                                                                                                                                                           | **`:auth`** (`14-auth.md`) |
| A4 →      | `Config` fields: `sessionSecret`, `oidc`, `authDebug`, `sessionWindowSeconds`, `webSessionAbsolute/Idle/Slide/Heartbeat/…Seconds`, `idpRecheckIntervalSeconds`, `webBaseUrl`, `mcpIssuer`, `trustedProxies`                                         | **A1**                     |
| A4 →      | `ApiError` + `badId`/`notFound` helpers; `requireAuthz`/`requireApi`                                                                                                                                                                                | **A1**, **A2**             |
| → A4      | `respondSessionUnauthorized`, the five Ktor session cookies, the two background timer loops, `/auth/debug`, `/auth/me`, `/auth/session/*`, `/auth/logout`                                                                                           | **A1** (`App.kt`)          |
| → A4      | `RunExecService` mints `EDITOR`/`APPROVER_EXEC` via `TokenStore.issue` under `mintForActivePrincipalLocked`; depends on `runTokenTtlSeconds` outliving the dial + exchange (see F23); `closeSessionsForPrincipal` is wired into `onWebSessionEnded` | **A7**                     |
| → A4      | `QueryResultStore.deleteEditorResultsForPrincipal(p, conn)` is the other half of `onWebSessionEnded`                                                                                                                                                | **A7**                     |
| → A4      | `RequesterIpRegistry` keys off `tokenHash` (INV-A4-53); `isStorableIpLiteral` validates `/auth/debug`'s `requesterIp`; `httpRequesterIp` reads `WebSessionRow.debugRequesterIp`                                                                     | **A12**                    |
| → A4      | `bearerWirePrincipal` (`Datasources.kt:729`) authenticates datasource **discovery** with `TokenStore.resolve`, restricted to `SESSION`/`USER` and re-checking `isDeactivated`                                                                       | **A5**                     |
| → A4      | `mcpOAuthRoutes` calls `mintWeb` (newest-wins, so it **replaces** the console session) and `ensureDeviceCookie`                                                                                                                                     | **A11**                    |
| → A4      | gRPC `Decide` resolves wire tokens through `TokenStore.resolve`                                                                                                                                                                                     | **A10**                    |

`onWebSessionEnded` (wired at `App.kt:392-395`) is the single most important
seam to reproduce: it composes an A7 delete **on A4's connection** and an A7
in-memory session close, fired from four distinct A4 paths (`mintWeb`
displacement, `endWeb`, `endWebBySessionKey`, `endAllWebForPrincipal`).

---

## 8. Open questions

| #   | Question                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | Every timestamp on the wire is Java `Instant.toString()` (variable fractional precision). Same question as A2's Q3, but here it covers `DevicePollResult.sessionExpiresAt`, `IssuedToken.expiresAt`, `RenewSessionResponse.expiresAt`, `WireTokenInfo`'s four, and A1's `SessionStatus`. Is `web/` or `pmon` sensitive to the format, or may the Go port emit fixed-precision RFC3339?                                                                                                                                             |
| Q2  | Shipped defaults put the daemon **session window** (`PM_SESSION_WINDOW` 2 h) _below_ the default **token TTL** (`SESSION_TTL_SECONDS` 12 h), so the first minted token outlives its own renewal window. Intended (the window bounds _renewal_, not the first token), or a defaults mismatch?                                                                                                                                                                                                                                       |
| Q3  | Is `device_code` ever non-NULL in any deployment? INV-A4-44 says the CP never runs the RFC 8628 client side against the IdP, so the column and `OidcDiscoveryDocument.device_authorization_endpoint` look vestigial. If so, drop both.                                                                                                                                                                                                                                                                                             |
| Q4  | `userSession()` always returns `roles = emptyList()`, so `tokenRoutes`' `rolesOf(call)` writes an empty `proxy_token.roles` snapshot for every REST-minted token, while A7 writes a real `assumeRoles` list for `APPROVER_EXEC`. Is the empty snapshot deliberate (roles re-resolved at decide time) or a leftover from the cookie-carried-roles era? It determines whether the Go port keeps the column for non-ephemeral kinds.                                                                                                  |
| Q5  | Ktor's `SessionTransportTransformerMessageAuthentication` defines the exact `pm_session` cookie encoding (MAC algorithm, separator, and the tracker-id format). A Go port must either reproduce it byte-for-byte or accept that all live sessions end at cutover. Which? (A1's Q3 asks the same from the other side.)                                                                                                                                                                                                              |
| Q6  | Does any deployment run with `PM_RESULT_KEY` unset in production? INV-A4-14 then silently disables **all** IdP liveness revalidation (no stored refresh token ⇒ `revalidateSession` returns early), which is a materially weaker deprovisioning posture than the docs describe. Should boot warn?                                                                                                                                                                                                                                  |
| Q7  | F21: is a kind-scoped `forbid` on `token.revoke` ever intended? If yes, the `fromWire`-null-⇒-absent path must become an explicit deny before the feature ships.                                                                                                                                                                                                                                                                                                                                                                   |
| Q8  | ~~`McpOAuthStoreDbTest` is claimed by no completed area doc~~ — **resolved by the audit pass:** `14-auth.md:1017` claims it (`### McpOAuthStoreDbTest.kt — 216 LOC, 6 cases`), and the file does contain 6 `@Test`. Still genuinely unclaimed: `MePermissionsRouteTest` (7) and `ReadinessDiagnosticDbTest` (2). Someone must claim them or the 903 total will not reconcile — see the reconciliation box in §4, where the six remaining areas currently claim 461 against 460. Not A4's, but flagged here because I checked them. |
| Q9  | Which area counts `TokenTtlTest`? A4 and A14 both do (F37), and A14's own text forbids A4 from doing so while still counting it itself. The index must pick one; A4's total is 110 with it and 106 without.                                                                                                                                                                                                                                                                                                                        |
| Q10 | `F21+` ids collide across six area docs (F36). Should the index retro-assign disjoint ranges, or re-key every finding as `<area>-F<n>`? Until then no cross-doc finding reference is unambiguous.                                                                                                                                                                                                                                                                                                                                  |
| Q11 | Should the device-auth surface log at all (F33)? It currently emits nothing, so a device-phishing attempt is indistinguishable from an abandoned login in the CP logs. If yes, decide the level and fields before the port, because adding them later means the Go and Kotlin audit surfaces differ.                                                                                                                                                                                                                               |
