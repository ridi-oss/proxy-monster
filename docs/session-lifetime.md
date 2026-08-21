# Session lifetime — one row, two clocks, ≤5-min IdP revalidation

Server-side console sessions with idle + absolute expiry and background IdP
identity re-checks. A consumer of [`auth-model.md`](./auth-model.md)'s OIDC +
`RoleResolver`: AUTHN owns _who you are_ + login + provisioning; this owns _how
long a login lasts and how often identity is re-checked mid-session_.

## Decision (TL;DR)

A conventional server-side console session policy, tightened on one axis:

1. Console sessions are server-side rows, not a bare signed cookie. A session id
   in the cookie resolves to a row on every request, so the policy below is
   expressible at all.
2. One unified session table. The proxy/daemon session and the console session
   share the same `principal_session` row shape with a `kind` discriminator
   (`WEB` | `DAEMON`); the differences are code invariants keyed on `kind`, not
   two tables. This lets one timer revalidator scan both kinds and lets
   authoritative deprovision end every applicable row through the same store.
3. Two clocks on the web session (server-authoritative; client is UX only):
   - Idle, sliding — default 15m, extended on activity. The inactivity
     auto-logout.
   - Absolute, hard cap — default 2h from login, activity-independent; only
     re-login resets it. The re-login-every-N-hours bound and the outer bound on
     identity staleness.
4. ≤5-min silent IdP revalidation that catches group removal, not just
   deactivation. The timer sweep refreshes the grant, validates the fresh
   id-token, re-reads the `groups` claim, and re-runs login's provisioning and
   role mapping — so "removed from a group in the IdP" takes effect within
   `PM_IDP_RECHECK_INTERVAL` (default 300s) without SCIM.
5. One active web session per principal (newest-wins displace) + device-bind.
   Proxy/daemon logins stay multi-session — a second browser signs the old one
   out, while multiple local proxy logins are fine — which falls straight out of
   the `kind` split.
6. Client `SessionGuard`: near-expiry warning toast, idle auto-logout, and a
   popup re-auth that resets the absolute clock without navigating the main
   window, so in-progress work is preserved.

A single short absolute TTL could fold identity re-validation in (bounce through
the IdP every 15m, re-running the domain + group gate), same security end-state,
but a 15-min interactive bounce is a lot of friction. Splitting the clocks — a
silent ≤5-min recheck plus a longer 2h interactive re-login — gives the same
"revoked within minutes" guarantee with far less interruption. The rule that
keeps it honest: the 5-min recheck must be silent (background refresh-grant /
local re-resolve), never an interactive re-login; interactive re-login is only
the absolute clock.

## Context — the two surfaces

The two authenticated surfaces share identity but have different runtime needs
([auth-model.md](./auth-model.md)):

- Console / web — a person in a browser. `web/` is a thin Next.js client; the
  control-plane's opaque `pm_session` tracker resolves a durable `kind='WEB'`
  row on every authenticated request. That row carries the idle and absolute
  clocks, device binding, refresh token, and explicit end reason.
- Local proxy / wire — a SQL client presents an expiring wire token as its
  password; the Go proxy resolves it via the control-plane's gRPC
  `validateToken` / `Decide`. Its `kind='DAEMON'` row bounds renewal, and `pmon`
  re-mints the token shortly before expiry while that row remains open. The
  current token remains valid to its own TTL after the renewal window closes;
  live role resolution keeps every query fail-closed after group loss
  ([auth-model.md](./auth-model.md#cli--daemon-login--control-plane-brokered-device-authorization)).

Both need current IdP identity without shortening the interactive 2-hour cap to
5 minutes. The single timer sweep refreshes stale rows, validates a fresh
id-token, and reconciles the `groups` claim through the same provisioning and
role-resolution path as login. Authoritative SCIM/local-admin deprovision
remains a separate push path and ends all active credentials, including web
rows.

## Data model

The `principal_session` table (`V6__sessions.sql`) carries both kinds.
WEB-specific columns are NULL for DAEMON rows:

<!-- prettier-ignore -->
| Column | Notes |
| --- | --- |
| `kind` | `'WEB'` \| `'DAEMON'`. |
| `absolute_expires_at` | `WEB` = the hard cap, `created_at + PM_WEB_SESSION_ABSOLUTE`. `DAEMON` = the end of the renewal window (`PM_SESSION_WINDOW`); it caps renewal only, not the wire token, which expires on its own TTL. |
| `idle_expires_at` | WEB only. The sliding idle deadline. |
| `ended_at` / `ended_reason` | Explicit server-side end. Reasons: `SIGNED_OUT` · `DISPLACED` · `DEACTIVATED` · `IDP_REJECTED` · `GROUP_REVOKED` · `DEVICE_BIND_MISMATCH`. Distinguishable reasons let the client route displaced→interstitial vs expired→login. |
| `device_id` | WEB only. Opaque value of the `pm_did` HttpOnly cookie, for device-bind. |
| `last_seen_at` | WEB only. Heartbeat-throttle / idle bookkeeping. |
| `session_key` | WEB only. Nullable Ktor tracker id linked to the row; partial-unique for non-NULL values. |
| `refresh_token_enc` | AES-256-GCM via `ResultCrypto`, present only with `offline_access` + `PM_RESULT_KEY`. Stored for WEB too, so the console session is IdP-revalidated the same way daemon sessions are. |
| `last_idp_check_at` / `liveness_status` | IdP revalidation bookkeeping (`ACTIVE` \| `INACTIVE`). |

`proxy_token` (wire credentials) and `device_login` (the RFC-8628 handshake)
stay separate — they are derived credentials / handshake state, not sessions.

`pm_session` carries only Ktor's opaque tracker id (HMAC-signed), not a
serialized principal or row id. `PrincipalSessionStorage.write` links the
tracker id into `principal_session.session_key`; `read` maps the tracker id back
without checking liveness or sliding idle; the row resolution with the request's
device cookie performs the liveness/bind check. The `roles` field is absent
(roles come from `RoleResolver`).

## The two clocks

Server-authoritative. The control-plane distinguishes _observing_ a session from
_recording human activity_, and the client schedules only from durations
reported in the server's clock domain.

- Idle (sliding). `idle_expires_at = now + PM_WEB_SESSION_IDLE` (15m). Only
  `POST /auth/session/heartbeat` can advance it, throttled to at most once per
  `PM_WEB_SESSION_SLIDE` (2m; the slide interval must be `< idle` or it never
  extends). `SessionGuard` drives the heartbeat from visible-tab activity
  (`mousemove`/`mousedown`/`keydown`/`scroll`/`touchstart`/`visibilitychange`).
  Ordinary authenticated traffic, including `/auth/me` and every `/api/**`
  route, validates the row without sliding idle — periodic application polling
  cannot keep an abandoned tab alive.
- Absolute (hard cap).
  `absolute_expires_at = created_at + PM_WEB_SESSION_ABSOLUTE` (2h). Activity
  never moves it; only a fresh login (new `created_at`) resets it.
- Effective death = `min(idle, absolute)`, enforced in the shared validate-only
  resolver called by Ktor's `web-session` auth provider. Storage lookup only
  recovers the row reference; it never decides liveness or extends idle.

`GET /auth/session/status` is a non-sliding observation endpoint under required
session-auth. It returns
`{ now, idleExpiresAt, absoluteExpiresAt, principal, sessionId }` when active,
or `401 { reason }` (`displaced` | `bind_mismatch` | `expired` | `none`). `now`
is stamped with PostgreSQL `clock_timestamp()` in the same query and clock
domain as the stored deadlines; the client computes each remaining duration as
`deadline - now` at response receipt and schedules it against a local monotonic
anchor, never comparing a server deadline to the browser wall clock. `no-store`.

`POST /auth/session/heartbeat` has the same 200/401 shapes and is the sole
idle-extending operation. Its validate step first performs a non-sliding
liveness/device-bind check; the handler then performs the guarded,
server-throttled idle touch and returns fresh server time and deadlines. A row
that dies between validate and touch returns the same reason-aware 401.

### Worked example — one console session's life (defaults)

<!-- prettier-ignore -->
| t | Event | Server state | Client |
| --- | --- | --- | --- |
| 0m | OIDC login | row minted: `idle=+15m`, `absolute=+2h`, refresh token stored | — |
| 0–115m | user active | each ≥2m gap, heartbeat slides `idle`; `absolute` unchanged | quiet |
| ~5m cadence | liveness sweep | refresh-grant → fresh id-token → groups re-mapped; still ACTIVE | quiet |
| 40m | removed from `system:admin` group in IdP | next sweep (≤5m) re-reads groups → 0 roles → `ended_reason=GROUP_REVOKED` | next heartbeat 401 → `/login` |
| (alt) 100m | user walks away | at 100m+15m idle with no activity | 1m before: idle warn toast; at deadline: server-confirmed `signOutForIdle` → `/login?reason=session_expired` |
| (alt) 115m | still working at 2h−5m | absolute warn toast → popup re-auth → new row, `absolute` resets | main window keeps its state |

## ≤5-min IdP revalidation with group re-read

The single timer sweep scans stale active rows of both kinds. It is the sole
revalidator: requests never kick a competing background refresh, so single-use
refresh-token rotation is serialized in-process. Per row:

1. Use the stored refresh token at the IdP token endpoint and require a fresh
   `id_token`. Validate its signature, issuer, audience, and expiry with
   `expectedNonce=null`.
2. Run login's `provisionFromOidc` path, resolve effective roles, end every live
   `WEB` row as `GROUP_REVOKED` when that role set is empty, then stamp the
   completed check. A missing `groups` claim is an empty set, removing all prior
   OIDC memberships. A `DAEMON` row stays open after a zero-role verdict, but
   every query fail-closes because live role resolution returns no roles.
3. `invalid_grant` is per-session, never a principal-wide teardown from the
   sweep. For `WEB`, end only that row as `IDP_REJECTED`; for `DAEMON`, close
   only that row's renewal window. Other active rows, wire tokens, and grants
   are untouched. Closing the daemon window prevents pmon's next renewal but
   does not revoke the already-issued wire token: it stays valid to its TTL, and
   only role reconciliation (step 2) or an authoritative deprovision cuts access
   ([KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md#daemon-session-renewal-and-revocation)).
4. Network failures, 5xx, non-`invalid_grant` OAuth errors, validation failures,
   and provisioning failures are transient: keep the cached state and leave the
   row active for a later sweep.

Principal-wide teardown remains exclusively on the authoritative
SCIM/local-admin deprovision path. Its `revokeActiveCredentialsTx` chokepoint
takes the same advisory lock and fans out to active `WEB` rows, ending them
`DEACTIVATED` alongside daemon sessions, wire tokens, and grants.

The login callback is the eligibility gate: after provisioning it resolves the
principal's effective roles and redirects a zero-role (or deactivated) principal
to the no-access screen before minting a session. This check is not serialized
against the sweep, so a narrow login-vs-sweep race can mint a live web session
whose roles the sweep has just reconciled away. That race is harmless — every
query and wire path re-resolves roles and re-checks deactivation, wire-token
minting is itself role-gated, and the session self-heals at the next sweep or
the absolute cap — and is accepted under the single-instance topology
([KNOWN_LIMITATIONS.md, Web session lifecycle](../KNOWN_LIMITATIONS.md#web-session-lifecycle)).

A session with no stored refresh token (no `offline_access`, or `PM_RESULT_KEY`
unset) cannot be IdP-pulled; the sweep leaves it alone, so its identity
staleness is bounded by the absolute cap (2h), not 5 minutes.

## Single active web session + device-bind

- Displace on mint (newest-wins). On a `WEB` login, end the principal's other
  active `WEB` rows (`ended_reason=DISPLACED`) under a row lock. `DAEMON` rows
  are untouched, so multiple proxy logins stay valid — a `WHERE kind='WEB'`
  clause, not new machinery.
- Device-bind. A `pm_did` HttpOnly cookie (opaque, minted at login) is stored as
  `device_id`; the session-auth validate step calls the shared resolver with
  that cookie. A mismatch ends the row `DEVICE_BIND_MISMATCH` and forces
  re-login. Defense-in-depth against cookie theft on top of single-session.
- Reason surface. Storage `read` returns refs for ended rows, so validate can
  cache the failed row id and map `DISPLACED` / `DEVICE_BIND_MISMATCH` / other
  ended-or-expired state to the 401 reason contract; an unknown tracker id maps
  to `none`. `/auth/me` (and the heartbeat 401 `reason`) report `displaced`, and
  the console shows a "you signed in on another device" screen rather than a
  silent bounce.

## Client `SessionGuard` + popup re-auth + profile menu

`SessionGuard` is mounted once in the `web/` app shell. All timings come from
the server (derived from env) as props — single source of truth.

- Activity → throttled `POST /auth/session/heartbeat` slides the idle clock and
  refreshes the server-relative deadline anchors. A different `principal` on the
  response ⇒ full reload (account switch via popup re-auth).
- Server-relative scheduling. Each status/heartbeat response supplies
  `{now, deadlines}`; the guard computes remaining durations at receipt and
  schedules against a local anchor, so browser/server wall-clock skew cannot
  create a false expiry or an absolute-cap confirmation loop.
- Idle warn toast at `PM_WEB_SESSION_IDLE_WARN_LEAD` (1m) before idle expiry —
  no action button (any activity extends and dismisses it).
- Absolute warn toast at `PM_WEB_SESSION_ABSOLUTE_WARN_LEAD` (5m) before the
  cap, with a "re-login" button →
  `window.open('/login?callbackUrl=/auth/reauth-complete')` inside the click
  gesture (popup-blocker-safe). The popup completes OIDC, lands on
  `/auth/reauth-complete`, `postMessage`s the opener, and closes; the main
  window observes the fresh session without navigation, preserving in-progress
  work.
- Re-auth-safe 401 handling. While the popup is pending, a 401 defers to a short
  non-sliding status recheck instead of reloading or logging out. Completion
  advances a re-auth epoch so responses from requests issued before the fresh
  login are discarded.
- Expiry is always server-confirmed: on the deadline timer,
  re-`GET /auth/session/status`; only a current-epoch non-displaced `401` starts
  conditional logout. `POST /auth/logout {sessionId}` ends the session only if
  the cookie still maps to the observed row; `{ended:false}` means popup re-auth
  already minted a replacement and the guard adopts it. Menu logout omits
  `sessionId` and is unconditional.
- Profile menu: remaining time · "re-authenticate now" (same popup) · "log out".
- l10n (hard rule, [l10n.md](./l10n.md)): every toast/label/`?reason=` is en/ko
  via the `ApiError` code+params model — no English prose baked in.

## Config knobs

`PM_WEB_SESSION_*` are parsed with a duration grammar (`2h`, `1h30m`, `900`), in
`Config.kt`.

<!-- prettier-ignore -->
| Env | Default | Meaning |
| --- | --- | --- |
| `PM_WEB_SESSION_IDLE` | `15m` | Sliding idle window (inactivity logout). |
| `PM_WEB_SESSION_SLIDE` | `2m` | Min re-extend interval (must be `< idle`). |
| `PM_WEB_SESSION_ABSOLUTE` | `2h` | Hard cap from login (interactive re-login). |
| `PM_WEB_SESSION_IDLE_WARN_LEAD` | `1m` | Idle warn toast lead. |
| `PM_WEB_SESSION_ABSOLUTE_WARN_LEAD` | `5m` | Absolute re-login warn toast lead. |
| `PM_WEB_SESSION_HEARTBEAT` | `90s` | Client activity heartbeat throttle. |
| `PM_IDP_RECHECK_INTERVAL` | `300` | Timer-driven IdP identity/group recheck interval (both kinds). |
| `PM_SESSION_WINDOW` | `2h` | Daemon renewal window — how long `POST /auth/session/renew` accepts pmon's renewal token. The daemon renews shortly before wire-token expiry while this window is open; after it closes, the current token remains valid to its own TTL (`pmon login --ttl`, default 12h). |

## Fail-closed and failure modes

- Transient IdP failure during a timer recheck → cached state kept, the row left
  active for a later sweep. Network, server, token-validation, provisioning, and
  non-`invalid_grant` OAuth errors do not cause mass logout.
- `invalid_grant` is row-local: the revalidated `WEB` row ends `IDP_REJECTED`;
  only the revalidated `DAEMON` row's renewal window closes. The sweep never
  calls principal-wide revocation, and closing a daemon window does not revoke
  the wire token already issued under it.
- No refresh token (no `offline_access` / no `PM_RESULT_KEY`) → the timer leaves
  the row alone; web staleness is bounded by the absolute cap, not the recheck
  interval.
- Missing `groups` claim on a refreshed id-token → empty membership, not stale
  membership: the sweep reconciles, resolves roles, and ends every live `WEB`
  row as `GROUP_REVOKED` when the role set is empty. `DAEMON` stays open but
  fails closed per query.
- Login with zero roles or a deactivated principal → the callback redirects to
  the no-access screen before minting. The narrow login-vs-sweep race is
  harmless and self-heals
  ([KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md#web-session-lifecycle)).
- Authoritative deprovision (SCIM/local admin) → principal-wide revocation,
  including all active `WEB` rows as `DEACTIVATED`.
- Heartbeat and observation are separate: ordinary authenticated requests and
  status checks never slide idle; only the activity-driven heartbeat does.
- Expiry is re-confirmed server-side and logout is row-conditional: a stale
  timer or pre-reauth 401 cannot end a fresh popup-minted session.
- Debug bypass: `PM_AUTH_DEBUG` (default on in dev, fail-closed guard in prod,
  `Config.kt`) mints a real `principal_session` row, so dev exercises the same
  path. The login page honors `callbackUrl` for the debug form, so debug login
  reaches `/auth/reauth-complete` and completes the popup flow like OIDC.

## Boundaries / invariants

- Single-instance deployment. The sole timer revalidator serializes
  refresh-token use within one control-plane process. Multi-replica coordination
  and leader election are out of scope by design.
- Session owns lifetime only. _Who you are_ and _what you may do_ stay in
  AUTHN + `RoleResolver` / Cedar. Roles are never baked into the session (the
  cookie's `roles` is ignored).
- The wire contract is unaffected. The proxy still re-validates every query via
  `Decide`; nothing here sends statement-meaning to the proxy.
- `kind` is the only fork. Single-session, idle, device-bind, and popup re-auth
  are all `WEB`-only invariants; `DAEMON` stays multi-session. No behavior
  branches on anything but `kind`.
- MCP OAuth co-hosting reuses `pm_session` (`oauth/OAuthRoutes.kt`,
  `oauth/Cimd.kt`) and resolves through the server-side session. Its own
  `PM_OAUTH_ACCESS_TTL` / `REFRESH_TTL` are separate and unchanged.
