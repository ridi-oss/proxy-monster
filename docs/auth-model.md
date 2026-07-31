# Auth model — OIDC authentication + JIT provisioning (SCIM optional); roles resolved locally

The peer of [`authz-model.md`](./authz-model.md): this owns _who you are_
(authentication) and the directory (provisioning); authz owns _what you may do_.
Session lifetime — the two clocks, IdP revalidation, and displacement — is
[`session-lifetime.md`](./session-lifetime.md).

## Decision (TL;DR)

Three pillars, cleanly split, with the ownership line between the IdP and the
deployment as the spine:

- Authenticate (who) — OIDC. Web = authorization-code (confidential client,
  `id_token`-validated); CLI/daemon = control-plane-brokered
  device-authorization (the RFC 8628 device-code shape). Output: a verified
  principal, nothing more. Provider-agnostic — standard OAuth2/OIDC with
  endpoints resolved from discovery
  (`${issuer}/.well-known/openid-configuration`). Okta is the reference/tested
  IdP (and SCIM client when SCIM is enabled), but any OIDC provider (Azure AD,
  Google, Auth0, Keycloak) works.
- Provision (directory) — JIT-on-login is the default, always-on path: the first
  OIDC login provisions the user and maps the login's `groups` claim into the
  local identity tables, so nobody is role-less. SCIM 2.0 is an opt-in add-on,
  off by default — its routes return `501` until `PM_SCIM_TOKEN` is set; once
  enabled the IdP pushes users / groups / memberships and becomes authoritative
  for the directory and deprovisioning.
- Resolve (roles) — local. `RoleResolver.resolve` reads _local_ identity
  (`principal_role` ∪ group membership ∪ active JIT grants) → roles → Cedar.
  group→role is the deployment's `group_role` map (admin-configured); the IdP
  never mints roles.

The IdP owns authentication and group membership. The deployment owns group→role
and policy. Login proves identity; JIT/SCIM fills the local directory; authz
reads only the local directory. A compromised IdP group grants exactly what the
deployment mapped it to — no more.

## Web login — OIDC authorization-code (confidential client)

Endpoints (authorize / token / userinfo / jwks / device) are resolved from OIDC
discovery (`OidcDiscovery.kt`), so the flow is provider-agnostic:

```
/auth/oidc/login    → mint state + nonce (+ PKCE code_verifier) in short-lived signed cookies
                      → 302 to the IdP /authorize
                      (scope: openid profile email groups; response_type=code;
                       code_challenge + code_challenge_method=S256 when discovery advertises S256)
/auth/oidc/callback → verify state → exchange code (+ client_secret, + code_verifier if one was
                      issued) at the IdP /token
                      → VALIDATE id_token (IdTokenValidator): JWKS signature, iss, aud, exp, AND nonce
                      → principal = email ?? sub
                      → JIT-provision the app_user (+ map groups claim → local groups)
                      → set signed-cookie session { principal }
```

- The security floor is `id_token` validation with `nonce` plus `state` (CSRF)
  on the confidential client. PKCE is OAuth-2.1 defense-in-depth on top of that
  (it guards a `client_secret` leak); `nonce`, not the challenge, is what
  defeats authorization-code injection here.
- PKCE is negotiated, not assumed: a challenge is sent only when the discovery
  document advertises `S256` in `code_challenge_methods_supported`. Sending it
  unconditionally would break an IdP that rejects unknown authorize parameters,
  and omitting it entirely locks out providers configured to require PKCE —
  Okta's "Require PKCE as additional verification" answers `invalid_request`
  before it ever renders a login form. `plain` is never sent.
- The `groups` claim feeds JIT provisioning (local group membership), _not_
  roles. Roles come from `RoleResolver` over the local directory, never from the
  token.

## CLI / daemon login — web verification page

`pmon login` follows the familiar device-code flow: the user confirms a short
code on the **web console's `/device` page**, and the login completes with
whatever identity the console already has — or, if they aren't signed in,
through the **same `/login` page** the console uses. `pmon` is a thin client
that only starts the flow and polls; the IdP is reached in the browser via the
ordinary auth-code flow, never a device grant.

```
pmon:  POST /auth/device/start
cp:    → mint a PENDING login: an opaque handle (pmon polls it) + a short user_code (shown to the human)
       → return { verificationUri={origin}/device, verificationUriComplete={origin}/device?user_code=…, userCode, handle, interval }
pmon:  print the plain URL + the code (best-effort auto-open uses the complete URL, which prefills it),
       then POST /auth/device/poll { handle } every interval
user:  open /device (web) → the code field is prefilled when auto-opened, typed by hand when the link was
       clicked → Continue
web:   POST /auth/device/confirm { userCode }   → CP validates it's a live pending login, sets the verify cookie
       → GET /auth/device/authorize?user_code=…
cp:    signed in already? → approve the handle with that session's principal   → 302 /device/success
       not signed in?     → 302 /login?return_to=… → SSO or debug → back to authorize → approve → /device/success
cp:    → /auth/device/poll: 202 while PENDING; once approved, mint a wire SESSION token (one-time claim per handle)
pmon:  store the wire token; open the loopback brokers (one per datasource) immediately
```

- **The IdP does the SSO authentication.** Signing in sends the user's **real
  browser** through the ordinary auth-code flow, so their normal auth just works
  — **YubiKey, passkeys, 1Password, MFA** — and `pmon` never handles
  credentials. It reuses the **same web OIDC (confidential) client**; no
  separate CLI app and no device-authorization grant (the IdP's device-grant
  support is irrelevant).
- **One login page.** The device flow does not carry its own sign-in UI: it
  reuses `/login` (SSO, plus the debug affordance where `PM_AUTH_DEBUG` allows
  it) with a `return_to` back to the device authorization, so there is exactly
  one place login can happen and `pmon` carries no dev-only code.
- **An existing console session is reused, not disturbed.** If the browser
  already has a console session, the approval uses it directly — no re-prompt,
  and nothing displaces or ends that session.
- **Remote-safe by design.** The pmon↔CP flow uses no redirect URI, and `pmon`
  is commonly driven on a different host than the user's browser, so it **always
  prints the verification URL + code**. Auto-open is a best-effort convenience
  for a local run: it opens the _complete_ URL (code prefilled), while the
  printed URL is the plain one, so a hand-opened link makes the user type the
  code — the step that ties the code they approve to the terminal in front of
  them.
- **Confirm-before-approve.** Approval requires a signed cookie that
  `POST /auth/device/confirm` sets, so a direct `/auth/device/authorize` link
  can't approve a code the victim never confirmed on `/device` (device-phishing
  defense). The residual (a victim who confirms someone else's code anyway) is
  tracked in `docs/backlog.md`.
- **Session renewal (decided).** A login opens a **session window**
  (`PM_SESSION_WINDOW`, default 2h). _Within_ it the daemon **silently
  re-mints** its wire SESSION token — **no re-prompt**. _After_ it, renewal is
  refused and the daemon **re-runs device-auth** (re-prompt), `aws sso`-style.
- **Liveness — timer-driven revalidation (decided).** A single background timer
  is the **sole** revalidator; requests never trigger a revalidation (a decision
  _or_ a renewal serves on the cached liveness status only). Each interval
  (`PM_IDP_RECHECK_INTERVAL`, default 5 min) the sweep re-checks every live web
  and daemon session whose `last_idp_check_at` is stale by running **that
  session's own** stored refresh token through a refresh grant and re-validating
  the returned `id_token` (signature + iss/aud/exp). Each session's own refresh
  decides only **that** session's fate — never the principal's other
  credentials:
  - A **definitive** `invalid_grant` retires just that row: a **web** row is
    ended `IDP_REJECTED`; a **daemon** row has only its own renewal window
    closed. Wire tokens, JIT grants, and sibling sessions are untouched (each is
    probed by its own refresh next pass).
  - A successful refresh whose freshly-synced groups resolve the principal to
    **zero effective roles** ends the principal's **web** rows (`GROUP_REVOKED`)
    — web endpoints have no per-request fail-close — while daemon rows stay open
    and fail closed per query.
  - A **transient** IdP error (`invalid_client`, 5xx, network) keeps the
    last-known-good and leaves the check timestamp untouched, so it retries next
    pass (a brief IdP outage never drops live sessions). Principal-wide teardown
    is **not** the sweep's job — that lives on the authoritative SCIM /
    local-admin deprovision path (§ SCIM), which revokes wire tokens, JIT
    grants, daemon windows, and web rows together. Bounded staleness = the
    interval; the session window is the hard cap.

## SCIM 2.0 provisioning — IdP → local directory (opt-in)

SCIM is off by default. Until `PM_SCIM_TOKEN` is configured every SCIM route
returns `501` (`SCIM provisioning is not configured`), so a deployment that
never sets the token has no provisioning surface at all — JIT-on-login covers
the directory on its own. Setting the token turns SCIM on.

- Endpoints: `/api/scim/v2/Users`, `/api/scim/v2/Groups`
  (GET/POST/PUT/PATCH/DELETE) + `ServiceProviderConfig` / `ResourceTypes` /
  `Schemas` (`Scim.kt`). PATCH handles only the core provisioning subset — user
  `active` replace (deactivate) and group `members` add/remove — not a full SCIM
  filter-path engine. That subset is small and near-identical across IdPs, so it
  is cheap and portable; anything outside it is rejected with a SCIM `400`.
- Auth: a long-lived SCIM bearer token (`PM_SCIM_TOKEN`, also configured in the
  IdP), constant-time compared, and rejected over plaintext. Separate from the
  always-expiring wire tokens. The TLS check (`resolveScimTls`) accepts a direct
  HTTPS connection, or an `X-Forwarded-Proto: https` from a socket peer listed
  in `PM_TRUSTED_PROXIES` — never a header a direct caller asserts about itself.
  A listed edge must overwrite that header from its own view of the connection;
  one that relays a client's value would let a plaintext request pass the gate
  ([`authz-context.md`](./authz-context.md#requester_ip--attestation)).
- Mapping: SCIM `User` → `app_user` (`source=SCIM`, `external_id`, `active`);
  SCIM `Group` → `app_group` (`source=SCIM`, `external_id`) + members →
  `group_member`. `active=false` → soft deprovision.
- Roles are not provisioned — the deployment's `group_role` map (admin UI) maps
  (SCIM or local) groups → roles; `RoleResolver` resolves. The IdP supplies
  membership only.
- SCIM vs JIT: SCIM is authoritative for the directory and deprovisioning.
  JIT-on-login provisions a user and their claimed groups when SCIM has not yet
  (or is not deployed). A `source=SCIM` user is never clobbered by JIT; a JIT
  (`source=OIDC`) user is reconciled to `SCIM` when the IdP later manages it via
  SCIM.

## Token & session model

- Web session: a signed cookie `pm_session` (HMAC via `PM_SESSION_SECRET`)
  carries an opaque tracker id that resolves to a server-side
  `principal_session` row. Lifetime policy — two clocks, displacement,
  device-bind — is [`session-lifetime.md`](./session-lifetime.md). A refresh
  token is encrypted at rest only when OIDC grants `offline_access` and
  `PM_RESULT_KEY` is set.
- Wire tokens (`proxy_token`): SHA-256-hashed, always expiring, `SESSION`
  (daemon) / `USER` (paste). Minted from a web session or from device-auth. The
  proxy validates → principal.
- No roles in tokens/sessions for authz — `RoleResolver` resolves server-side.
  The `roles` field on a session/token is ignored by the decision path.

## Data model

- **Identity tables:** `app_user` and `app_group` are the provisioned entities —
  each carries `source` (`LOCAL` | `OIDC` | `SCIM` | `SYSTEM`) and
  `external_id`, so a row's origin decides who may edit it. `group_member`,
  `group_role`, and `principal_role` are the mappings between them and hold no
  provisioning columns of their own.
- **Sessions:** `principal_session` unifies `WEB` and `DAEMON` rows.
  `absolute_expires_at` is the hard cap; daemon-only
  `handle`/`ttl_seconds`/`renewal_token_hash` stay nullable for web rows, while
  explicit web logout records `ended_at`/`ended_reason`. Device-auth poll state
  remains in short-lived `device_login` rows.
- **Config:** generic OIDC — `PM_OIDC_ISSUER` / `CLIENT_ID` / `CLIENT_SECRET` /
  `REDIRECT_URI` / `SCOPES` (today's Okta-named `PM_OKTA_*`), endpoints from
  discovery — the browser auth-code flow reuses this one confidential client (no
  device grant, no separate CLI client) + `PM_SCIM_TOKEN` +
  `PM_WEB_SESSION_ABSOLUTE`.

## Security invariants

- Fail-closed: unauthenticated → no session/token; an unknown/deprovisioned
  principal → zero roles (`RoleResolver` invents nothing).
- `PM_AUTH_DEBUG` MUST be off in production — it is a full authentication bypass
  (`/auth/debug` sets any principal) and defaults on for dev. The server refuses
  to start with it on unless a dev marker is set, and warns loudly.
- `id_token` fully validated (JWKS sig + `iss`/`aud`/`exp` + `nonce`); `state`
  on every auth-code flow; `state`/`nonce`/`code_verifier` are one-time.
- All wire credentials expire — no permanent tokens. The only standing secrets
  are `client_secret` and `PM_SCIM_TOKEN`, env-provided, never in the DB or
  logs; a server-held refresh token is encrypted at rest.
- The IdP cannot mint roles — only group membership; group→role is local admin
  config.
- Deprovisioning propagates two ways: (push) SCIM `active=false` / group removal
  → `RoleResolver` returns nothing next decision + revoke that principal's
  active wire tokens and JIT grants; (pull) the daemon's in-window IdP liveness
  check cuts a live CLI session mid-window even without a SCIM push. Neither
  waits for expiry.
- SCIM endpoint: bearer-token auth, constant-time compare, TLS-only; reject over
  plaintext.

## Open questions

None blocking — the design is complete. Residual choices are implementation
details noted inline (the IdP-liveness call: refresh-grant vs userinfo; the
exact SCIM PATCH subset + SCIM error bodies).
