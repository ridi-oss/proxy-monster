# Installing, running, and deploying proxy-monster

A policy-enforcing data-plane proxy for SQL. Clients speak the native
MySQL/PostgreSQL wire protocol to a proxy; a control plane authorizes and masks
every statement; a tamper-evident audit trail records each decision.

This guide covers every config variable (with examples and defaults), then two
deployments: [running locally](#running-locally) for development, and
[deploying on AWS](#deploying-on-aws-ecs-fargate--s3--aurora) (ECS Fargate + S3

- Aurora). It's a generic reference — substitute your own hosts, ARNs, region,
  and IdP. What the components are and how they communicate is
  [ARCHITECTURE.md](./ARCHITECTURE.md).

## What you are installing

Five long-running server components — the proxy (one per datasource), the
control plane, the web console, auditmon, and the control-plane store — plus
pmon, the static binary each user runs locally to reach a proxy. You bring the
target databases the proxy protects, which may be MySQL or PostgreSQL; the
control-plane store is PostgreSQL only. What each one does, how they talk, which
ports and protocols to open, and which paths need to be public is
[ARCHITECTURE.md](./ARCHITECTURE.md); read that first if the layout is new to
you. This guide is the config surface and the two deployments.

## Configuration

`required` = must be set · `optional` = has a default · `dev-only` = never in
production. Examples are generic.

### Control plane

The control-plane store is PostgreSQL only — there is no MySQL-store option, and
`PM_DB_URL` must be a PostgreSQL JDBC URL. This is independent of the target
databases the proxy protects, which may be MySQL or PostgreSQL and are
configured per proxy under `PM_TARGET_*`.

- `PM_DB_URL` / `PM_DB_USER` / `PM_DB_PASSWORD` — _required_. The PostgreSQL
  control-plane store (JDBC URL + credentials). The URL must begin
  `jdbc:postgresql://` — `Db.kt` hardcodes `org.postgresql.Driver`, which
  rejects any other scheme, and `Main.kt` builds the pool and migrates before it
  opens a port, so a non-PostgreSQL URL fails startup rather than degrading.
  Example:
  `jdbc:postgresql://pm.cluster-xxxx.ap-northeast-2.rds.amazonaws.com:5432/proxymonster`
- `PM_HTTP_PORT` / `PM_GRPC_PORT` — _optional_. HTTP (web/auth/MCP) and gRPC
  (proxies) listen ports. Defaults: `8080` · `9090`.
- `PM_OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URI` —
  _required for SSO_ (all four). Redirect must equal
  `<public-origin>/auth/oidc/callback`. Example issuer
  `https://your-org.okta.com`, redirect
  `https://console.example.com/auth/oidc/callback`.
- `PM_OIDC_SCOPES` / `_GROUP_MAP` / `_GROUP_PREFIX` — _optional_. Scopes
  (default `openid profile email groups offline_access`); map IdP groups → local
  groups/roles (explicit map to target `system:*`). Example:
  `PM_OIDC_GROUP_MAP=okta-admins=system:admin,okta-devs=developers`
- `PM_SESSION_SECRET` — _required (prod)_. Signs web sessions; ≥32 chars,
  non-default (enforced when debug is off). Example:
  `$(openssl rand -base64 48)`
- `PM_RESULT_KEY` — _required for approval-result storage_. Encrypts saved query
  results (approval flow); 32-byte key, base64. Unset refuses approver-exec
  result storage fail-closed. Example: `$(openssl rand -base64 32)`
- `PM_SECRET_TOKEN` — _required_. The single shared secret gating all proxy↔CP
  gRPC + the HTTP ingest routes. Same value on the CP and every proxy; unset ⇒
  the gate is open (dev only). Example: `$(openssl rand -hex 32)`

  **Holding this is equivalent to administering policy.** `Register` lets a
  caller set a datasource's tags, every table and column under it inherits them,
  and a tag the shipped presets key on changes what those presets grant —
  `system:catalog` matches an enabled bare-principal unmasked-read permit.
  Registration is keyed on the datasource name with no per-datasource binding,
  so one proxy's secret can retag a datasource it does not front. Handle it like
  `PM_SESSION_SECRET`, and do not give it to anything you would not let edit
  policy ([ARCHITECTURE.md](./ARCHITECTURE.md#what-pm_secret_token-authorizes)).

- `PM_MCP_RESOURCE` — _optional_. Public MCP resource URL; required only if MCP
  is used. Example: `https://console.example.com/mcp`
- `PM_TRUSTED_PROXIES` — _optional, set behind an LB_. Comma-separated
  socket-peer addresses or CIDR blocks of the edges trusted to assert forwarded
  headers about a request: `X-Forwarded-For` for client-IP attestation,
  `X-Forwarded-Proto` for the SCIM TLS gate, and `X-Forwarded-Host` for the host
  the `/mcp` check compares. Empty (default) ignores all three and uses the
  socket's own facts, so SCIM then requires direct HTTPS and `/mcp` sees the
  proxy's authority. Example: `10.20.1.15,10.20.2.15`, or `10.20.0.0/16` for an
  autoscaled edge whose address is not knowable in advance. A block must cover
  only hops you operate — anything inside it can assert its own client IP, so
  prefer the narrowest prefix that covers the edge. Entries that are neither an
  address nor a valid block are ignored and logged at startup.

  An edge you list here must **overwrite** the forwarded headers it asserts,
  from its own view of the connection — never relay a client-supplied value. An
  edge that passes an inbound `X-Forwarded-Proto: https` through lets a
  plaintext request satisfy the SCIM TLS gate, sending the standing
  `PM_SCIM_TOKEN` in the clear. ALB and CloudFront overwrite by default; a
  hand-rolled nginx or Envoy hop needs
  `proxy_set_header X-Forwarded-Proto $scheme` (or the equivalent), not a
  pass-through of the request header.

- `PM_WEB_SESSION_ABSOLUTE` / `_IDLE` / `_SLIDE` / `_IDLE_WARN_LEAD` /
  `_ABSOLUTE_WARN_LEAD` / `_HEARTBEAT` — _optional_. Two-clock console session
  timings. Defaults: `2h` · `15m` · `2m` · `1m` · `5m` · `90s`.
- `PM_SESSION_WINDOW` / `PM_IDP_RECHECK_INTERVAL` — _optional_. Daemon renewal
  window; IdP group re-read cadence. Defaults: `2h` · `300` (s). Raising
  `PM_SESSION_WINDOW` does not lengthen a live `pmon` session — `pmon` never
  calls the renew route, so a login lasts one wire token TTL and then needs a
  fresh `pmon login`. For long-running sessions raise that TTL with
  `pmon login --ttl` (default 12h, clamped server-side to 24h) instead.
- `PM_QUERY_TIMEOUT` — _optional_. CP-side ceiling on async execute. Bare
  integer seconds (no unit). Default `600`.
- `PM_OAUTH_ACCESS_TTL` / `PM_OAUTH_REFRESH_TTL` — _optional_. MCP OAuth token
  lifetimes (seconds). Defaults `600` · `21600`.
- `PM_SCIM_TOKEN` — _optional_. SCIM provisioning bearer (OIDC just-in-time is
  the default).
- `PM_SLACK_BOT_TOKEN` / `PM_SLACK_APP_TOKEN` — _optional_. Slack notifications
  for the approval workflow ([docs/notifications.md](./docs/notifications.md)).
  The bot token (`xoxb-`) authorizes the Web API and the app token (`xapp-`)
  opens the Socket Mode WebSocket. The workspace whose button clicks are honored
  is derived from the bot token itself (`auth.test`), not configured — a token
  belongs to exactly one workspace. **Both tokens are required** — either absent
  leaves the whole layer inert and the workflow unchanged, never a
  half-configured mode. Socket Mode means the CP dials out; no inbound ingress
  is added. Set `PM_WEB_ORIGIN` too, or the message's "open request" link points
  at the control plane rather than the console.
- `PM_NOTIFY_STATEMENT` / `PM_NOTIFY_STATEMENT_MAX` — _optional_. How much of a
  requester's SQL a notification may carry: `truncated` (default, first
  `PM_NOTIFY_STATEMENT_MAX` characters, default `200`), `full`, or `omit`. A
  statement's literals can be the very values a policy protects — masking acts
  on results, not predicates — so `omit` is the setting for data that must not
  leave in query text. Approve-and-run is offered only when the message carries
  the whole statement, whatever the mode.
- `PM_NOTIFY_LOCALE` — _optional_. Fallback language (`en` · `ko`) for a
  recipient who has not set one in the console. Default `en`.
- `PM_AUTH_DEBUG` / `PM_DEV` / `PM_OAUTH_DEBUG_AUTO_CONSENT` — _dev-only_.
  Defaults: `PM_AUTH_DEBUG=true`, `PM_DEV=false`,
  `PM_OAUTH_DEBUG_AUTO_CONSENT=true`. The CP refuses to boot when debug auth is
  on and (real OIDC is configured or a non-default `PM_SESSION_SECRET` is set),
  unless `PM_DEV` is explicit — the "forgot to unset debug in prod" guard.

### Proxy — one set per datasource

- `PM_ENGINE` — _optional_. The target database's engine, and so the wire
  dialect this proxy speaks: `postgres` or `mysql`. Default `mysql`. Unrelated
  to `PM_DB_URL`, which is always PostgreSQL.
- `PM_DATASOURCE_NAME` / `PM_DATASOURCE_TAGS` — _name required_. Logical id
  (must match the CP's) + the tags policy keys off. Example: `analytics-prod` ·
  `system:production`. These reach Cedar as written and every table and column
  under the datasource inherits them, so a name the shipped presets key on
  decides for the whole datasource — set the posture here and leave column
  classification to the console.
- `PM_PROXY_PORT` — _optional_. The wire port clients connect to. Defaults:
  `6033` (MySQL) · `6432` (PG).
- `PM_TARGET_HOST` / `_PORT` / `_DB` / `_USER` / `_PASSWORD` — _optional with
  local defaults_ (`localhost` · engine default port · `acme` · `acme` ·
  `acme`). In production set all five to the backend this proxy fronts (VPC
  peering in the AWS layout below). Example: `prod-db.prod-vpc.internal` ·
  `5432` · `appdb` · `pmproxy`
- `PM_CONTROL_PLANE_GRPC` — _optional_. CP gRPC address `host:port`. Default
  `localhost:9090`. Production example: `pm-cp.pm.internal:9090`
- `PM_ADVERTISE_ADDR` — _optional, no default_. The client-facing `host:port` a
  wire client dials to reach _this_ proxy — distinct from `PM_TARGET_*` (the
  upstream backend). The proxy registers it with the CP, which hands it to pmon
  as each datasource's connect address. The proxy cannot guess it, so there is
  no default: leave it unset and pmon discovers the datasource but cannot broker
  it (`pmon status` lists it with the reason "no advertised proxy address"). It
  must parse as `host:port` with a port in 1-65535 or the proxy refuses to
  start. Example: `127.0.0.1:6033` locally ·
  `analytics-prod.pm.example.com:6432` in production
- `PM_TLS_CERT` / `PM_TLS_KEY` — _optional (both or neither; one alone ⇒ refuses
  to start)_. TLS cert+key file paths for the wire listener. Wire TLS is
  optional — the cleaner pattern is a private transport (peered VPC,
  PrivateLink, or a VPN/tailnet) and plaintext wire (unset). Set them only for
  an untrusted client↔proxy path (or an encrypt-everywhere policy); then the
  _proxy_ terminates TLS — a generic NLB/ALB can't, because SQL negotiates TLS
  in-band. With TLS on, the proxy computes its leaf cert's SHA-256 and
  advertises it at registration (it refuses to boot if it cannot), and pmon pins
  each connection to exactly that leaf — no CA and no hostname check — so a
  self-signed cert works and nothing has to reach the client's trust store. Any
  cert the proxy can present the private key for is therefore fine; ACM Private
  CA (exportable, unlike public ACM certs) via Secrets Manager is one convenient
  source. Rotating the cert re-advertises the new fingerprint on the next
  register, so clients pick it up without redistribution.
- `PM_SECRET_TOKEN` — _required_. The shared gRPC secret; must equal the CP's.

### Web console

- `PM_PROXY_TARGET` — _required for `next dev`; build-time only for the
  container image_. CP HTTP base URL — target for the `/api` + `/auth`
  server-side rewrites. `next.config.ts` reads it while the config evaluates, so
  `next dev` picks it up per boot, but `next build` bakes the resolved
  destination into `.next/routes-manifest.json`. Under `output: "standalone"`
  the runtime image ships no `next.config.ts` and cannot re-evaluate it, so
  setting this as a container env var has no effect — see
  [Web console rewrites](#web-console-rewrites) for the deployment consequence.
  Example: `http://pm-cp.pm.internal:8080`
- `NEXT_PUBLIC_API_URL` — _optional_. Public API base; default `""`
  (same-origin).
- `AUTH_RECHECK_MS` / `AUTH_SETTLE_GRACE_MS` / `AUTH_CALLBACK_PATH` /
  `AUTH_COMPLETE_MESSAGE_TYPE` — _optional_. Client SessionGuard tuning (re-auth
  cadence, popup callback).
- `PM_WEB_DEV_ORIGINS` — _dev-only_. HMR cross-origin allowlist for local dev.

### pmon — client-side, per user

pmon takes no proxy address of its own: its daemon discovers every datasource
the logged-in principal may connect to and dials each one's `PM_ADVERTISE_ADDR`.

- `--url` (on `pmon login`) — _required once_. The control-plane base URL. It is
  saved to the config file and reused by later logins that omit it. Example:
  `pmon login --url https://console.example.com`
- `--ttl` (on `pmon login`) — _optional_. Wire-token lifetime in seconds.
  Default `43200` (12h).
- local broker port — _not configurable_. The daemon assigns each datasource the
  next free loopback port at or above `6100` and persists it, so a datasource
  keeps the same port across restarts. `pmon status` prints the assignments;
  `pmon show <datasource> [--url | --jdbc | --go-dsn | --cli]` prints one ready
  connection string (`--url` is the default).

### auditmon — YAML file + env overlays

Secret-free YAML (path via `AUDITMON_CONFIG`); every field also overridable by
an `AUDITMON_MONITOR_*` env var. The DB DSN is referenced by env-var name.

```yaml
# auditmon.yaml
monitor:
  db_dsn_env: AUDITMON_DB_DSN # read-only DSN
  bucket: pm-audit-worm # S3 Object-Lock bucket
  endpoint: https://s3.ap-northeast-2.amazonaws.com
  poll_interval: 90s
  sign_interval: 1h
  full_verify_interval: 1h
  signer:
    type: kms # prod signer (dev: filekey + key_path)
    key_id: alias/pm-audit-signer
rules:
  mass_export:
    { window: 10m, heuristic_max_broad_reads: 50, default: { rows: 100000 } }
  bulk_pii: { window: 5m, max_pii_decisions: 200, max_distinct_pii_columns: 20 }
  off_hours:
    { business_hours: "09:00-19:00 Asia/Seoul", applies_to: [pii_read, write] }
  repeated_deny: { window: 5m, max_deny: 20 }
alerts:
  dedup_window: 15m
  sinks:
    - { type: webhook, url_env: SECOPS_WEBHOOK_URL, min_severity: warn }
```

- `AUDITMON_DB_DSN` — _required_. Read-only Postgres DSN (named by
  `monitor.db_dsn_env`). Example:
  `postgres://audit_reader:****@pm-ro.cluster-xxxx.ap-northeast-2.rds.amazonaws.com:5432/proxymonster?sslmode=require`
- `AWS_REGION` + task IAM role — _required_. For S3 + KMS. On ECS use the task
  role, not static `AWS_*` keys.

## Running locally

One task brings up the whole stack — the PostgreSQL control-plane store, the
control plane, a sample MySQL and PostgreSQL target database with a wire proxy
in front of each, and the web console:

```sh
mise run dev
```

That is the fast path, and what most contributors want. It prints the URL and
port of every piece it started; Ctrl-C stops them and leaves the datastores
running (`mise run down` stops those too).

The rest of this section is the same walkthrough component by component, for
when you want to run one piece by hand, change a variable, or understand what
`dev` does. Each step names only the vars that matter locally; the full
reference is [Configuration](#configuration). `mise tasks ls` lists the
per-component tasks (`up`, `control-plane`, `proxy-mysql`, `proxy-postgres`,
`web`) that mirror these steps.

Getting from a clean checkout to a masked or denied query is
[First login and first query](#first-login-and-first-query); an
OAuth-authenticated MCP client is
[Connect an MCP client](#connect-an-mcp-client-optional).

### Prerequisites

- JDK, Gradle, Go, Node, pnpm — all pinned in `mise.toml` (temurin-24, Gradle
  8.14.5, Go 1.23, Node 24.18.0, pnpm 10.22.0 — matching `web/Dockerfile`'s base
  image + corepack pin). Run `mise install` from the repo root, or use your own
  matching toolchain. JDK 24 is the floor: the Gradle build compiles with
  `--release 24` and targets JVM 24, so an older JDK fails with
  `release version 24 not supported`.
- Docker — for the three local datastores (below).
- A TLS cert/key pair — only if you want the wire proxy's client-facing TLS on
  (recommended once you connect a real SQL client off-loopback; skippable for a
  pure loopback smoke test — see [Run a wire proxy](#run-a-wire-proxy)). A
  self-signed pair is enough when clients connect through pmon, which pins the
  advertised leaf rather than checking a CA. A client that dials the proxy
  directly instead verifies per its own TLS settings, so give that one a cert it
  trusts.

### Datastores

```
mise run up
```

Three containers (`docker-compose.yml`, repo root), started and waited on until
each reports healthy. Re-running it against a healthy stack is a no-op. One is
proxy-monster's own store; the other two are sample target databases.

- pm-postgres (`:5442`) — the control-plane store (catalog, policy, roles,
  audit). PostgreSQL because that is the only store engine there is. Empty on
  first boot; control-plane migrates it (Flyway) on startup.
- target-mysql (`:31307`, db `acme` / user `acme` / password `acme`) — a sample
  target database on the primary target engine, pre-seeded
  (`deploy/seed/target-seed-mysql.sql`) with a small OLTP schema (`users`,
  `orders`, `payments`, `addresses`, ...) carrying realistic PII columns
  (`email`, `phone`, `name`, `rrn`, `card_number`, ...) to classify/mask
  against.
- target-postgres (`:5433`, db `acme` / user `acme` / password `acme`, trust
  auth) — the same schema (`deploy/seed/target-seed.sql`) as a sample target
  database on the experimental target engine. A separate container from
  pm-postgres, and unrelated to it.

These are not the datasources proxy-monster protects by default — they're just
sample targets to point a proxy at in [Run a wire proxy](#run-a-wire-proxy).

### Run control-plane

```
mise run control-plane
```

That is
`PM_DB_URL="jdbc:postgresql://localhost:5442/proxymonster" ./gradlew --no-daemon :control-plane:run`,
and it starts the datastores first if they are not up. Flyway migrates the
schema automatically on boot. The defaults you're implicitly relying on here
(`Config.kt`):

<!-- prettier-ignore -->
| Var | Default | What it is |
| --- | --- | --- |
| `PM_HTTP_PORT` | `8080` | the web-facing JSON API |
| `PM_GRPC_PORT` | `9090` | the proxy-facing gRPC surface (register, decide, catalog push) — never expose publicly |
| `PM_DB_USER` / `PM_DB_PASSWORD` | `proxymonster` / `proxymonster` | matches `docker-compose.yml` |
| `PM_AUTH_DEBUG` | `true` | a full auth bypass (`/auth/debug` logs in as ANY principal) — trusted machine only |
| `PM_SECRET_TOKEN` | unset → gate OPEN | the shared proxy↔control-plane secret; set it once you're off a trusted loopback |
| `PM_MCP_RESOURCE` | `http://127.0.0.1:8080/mcp` | MCP resource URI; its origin doubles as the co-hosted OAuth issuer |

Full descriptions and every other variable are in
[Configuration](#configuration).

Confirm it's up: `curl http://localhost:8080/health` → `{"status":"ok",...}` (a
`diagnostics` array may list non-fatal notes like "system:admin role has no
active assignee" — expected until you log in once, per
[First login and first query](#first-login-and-first-query)).

### Run a wire proxy

Run one proxy per datasource. There is no "create datasource" step. The
data-plane proxy is the Go `goproxy` module. A proxy instance registers itself
with control-plane on boot (by name), introspects its own target connection, and
pushes the resulting catalog — control-plane never holds credentials to, or
opens a connection to, any target datasource
([docs/datasource-registration.md](docs/datasource-registration.md)). Point a
proxy at a target and it appears in the admin UI on its own within a few
seconds.

MySQL, fronting target-mysql from [Datastores](#datastores) —
`mise run proxy-mysql`, which is:

```
PM_ENGINE=mysql \
PM_DATASOURCE_NAME=acme-mysql \
PM_CONTROL_PLANE_GRPC=127.0.0.1:9090 \
PM_PROXY_PORT=6033 \
PM_TARGET_HOST=127.0.0.1 PM_TARGET_PORT=31307 PM_TARGET_DB=acme PM_TARGET_USER=acme PM_TARGET_PASSWORD=acme \
go run ./goproxy/cmd/goproxy
```

Postgres, fronting target-postgres — `mise run proxy-postgres`, which is:

```
PM_ENGINE=postgres \
PM_DATASOURCE_NAME=acme-target \
PM_CONTROL_PLANE_GRPC=127.0.0.1:9090 \
PM_PROXY_PORT=6432 \
PM_TARGET_HOST=127.0.0.1 PM_TARGET_PORT=5433 PM_TARGET_DB=acme PM_TARGET_USER=acme PM_TARGET_PASSWORD=acme \
go run ./goproxy/cmd/goproxy
```

Both run from the repo root: the committed `go.work` makes
`./goproxy/cmd/goproxy` resolve there, so no `cd` is needed.

Neither task sets `PM_ADVERTISE_ADDR`, so the datasource registers without a
client-facing address — enough for the web console and the walkthrough below,
which reach the proxy over the control plane's own gRPC channel. Add
`PM_ADVERTISE_ADDR=127.0.0.1:6033` (matching `PM_PROXY_PORT`) when you want pmon
to broker the datasource; without it `pmon status` lists it with the reason "no
advertised proxy address".

`PM_DATASOURCE_NAME` is the stable identity Cedar policies key on
(`Datasource::"acme-target"`, etc.) — pick any name; it doesn't have to match
the target's real db name. Optional: `PM_DATASOURCE_TAGS` (comma-separated tags
— the recognized posture tags are `system:development` and `system:production`,
per [docs/policy-store.md](docs/policy-store.md); the list is otherwise
free-form: any name that is not an invented `system:` one reaches Cedar as
itself, so a policy may match it and every table and column under the datasource
inherits it. It is the same tag vocabulary column classifications use, so
reusing one of those names here decides for the whole datasource: `pii` both
masks every column under the shipped presets and hands cleartext on every column
to any role a `Tag::"pii"` permit grants. Name a datasource tag for the
datasource — `analytics-prod`, `pci-zone` — not for a column classification).
Leave it unset and the datasource carries no posture, which is the production
floor either way — Cedar's deny-by-default plus the shipped forbids give an
untagged datasource that floor with no posture tag required. Tag it
`system:development` to opt a datasource into the permissive development preset.

Client-facing TLS (`PM_TLS_CERT` + `PM_TLS_KEY`, both-or-neither) is recommended
but not required for this loopback walkthrough — without it the proxy runs
plaintext, which is fine on `127.0.0.1` but must never be exposed beyond a fully
trusted network (the wire token rides the password field in the clear).

Confirm registration: `curl http://localhost:8080/api/datasources` should list
both, each with a non-null `catalogSyncedAt` and `lastSeenAt`. This route isn't
public — it requires an authenticated session — but works unauthenticated here
because `PM_AUTH_DEBUG` (default `true`) skips that check; against a real
deployment (`PM_AUTH_DEBUG=false`) the same bare `curl` gets a `401`, and you'd
need a session cookie from the [login step](#first-login-and-first-query) first.

### Run the web UI

```
mise run web
```

→ http://localhost:41300. That is `pnpm -C web install` then `pnpm -C web dev`
with `PM_PROXY_TARGET=http://127.0.0.1:8080`. The web dev server rewrites `/api`
and `/auth` to `PM_PROXY_TARGET`, which defaults to `http://127.0.0.1:41390`
(`web/next.config.ts`) while control-plane defaults to `:8080` — so one has to
point at the other, and the task does that for you. Running web by hand, either
set the same variable or run control-plane with `PM_HTTP_PORT=41390`:

```
PM_PROXY_TARGET=http://127.0.0.1:8080 pnpm -C web dev
```

Serving over a real network (not just `localhost`)? Next.js blocks cross-origin
dev requests by default. Add your hostname via `web/.env.local` (gitignored,
never committed) rather than editing `next.config.ts`:

```
# web/.env.local
PM_WEB_DEV_ORIGINS=your-real-hostname.example.com
```

Comma-separate multiple hosts. `next.config.ts`'s `allowedDevOrigins` reads this
at boot.

### Connect an MCP client (optional)

`/mcp` is a Streamable HTTP MCP resource server for access-control
administration, co-hosted in control-plane — no separate process. It exposes the
same Cedar-authorized datasource/catalog/classification, policy, role,
assignment, user/group, and mask-function operations as the Admin REST API. It
does not execute SQL, manage workflows, or browse audit history. Every MCP call
is OAuth 2.1-authenticated, then authorized through the same Cedar action and
validators as the REST surface — OAuth scopes are only a consent ceiling, never
an extra source of permission.

Control-plane serves the MCP resource, OAuth discovery (RFC 8414/9728), the
`/oauth/authorize` + `/oauth/token` + `/oauth/revoke` endpoints, and — since
it's the OIDC relying party too — `/auth/oidc/callback`, all from one origin:
`PM_MCP_RESOURCE`'s origin is always the OAuth issuer, derived automatically,
never separately configured. For a loopback-only local client, the control-plane
you already started is enough — just add `PM_MCP_RESOURCE`:

```
PM_MCP_RESOURCE="http://127.0.0.1:8080/mcp" mise run control-plane
```

With the local `PM_AUTH_DEBUG=true` default, `/oauth/authorize` uses a debug
principal and auto-consents (`PM_OAUTH_DEBUG_AUTO_CONSENT`, default `true`) with
no Okta round-trip — it still mints normal audience-bound OAuth bearer tokens,
so discovery and client behavior stay identical to production. Add and authorize
the user-scoped Claude Code connection:

```
claude mcp add --scope user --transport http proxy-monster http://127.0.0.1:8080/mcp
claude mcp login proxy-monster
claude mcp get proxy-monster
```

`claude mcp login` needs a real interactive terminal — it holds a local callback
listener open while your browser completes the redirect, so it can't run from a
non-interactive script or a background job. Run it yourself directly; it opens
the authorize URL, debug mode auto-consents, and the browser redirects straight
back with no clicking required.

For a network-reachable deployment, route the exact same origin for all of
`/mcp`, `/.well-known/oauth-protected-resource*`,
`/.well-known/oauth-authorization-server`, `/oauth/*`, and `/auth/oidc/*` to
control-plane — this is one canonical HTTPS host, not a separate authorization
server. Set `PM_MCP_RESOURCE="https://<host>/mcp"` to that public origin. With
`PM_AUTH_DEBUG=false` it must be HTTPS, and you additionally need a non-default
32+ character `PM_SESSION_SECRET`, all `PM_OIDC_*` values, and an OIDC redirect
URI exactly equal to `https://<host>/auth/oidc/callback`. If a reverse proxy
terminates TLS in front of control-plane (as any real deployment's will), the
host the backend sees must equal the host `PM_MCP_RESOURCE` declares:
control-plane's `/mcp` guard compares that host strictly, and only the host. The
port is never compared — behind a TLS-terminating edge the backend is reached on
its own cleartext port, and a client's `Host` omits the port whenever it is the
scheme default, so requiring one would reject every such request. It reads the
literal `Host` (or HTTP/2 `:authority`) the backend receives, plus
`X-Forwarded-Host` when the socket peer is listed in `PM_TRUSTED_PROXIES`; there
is no `ForwardedHeaders`/`XForwardedHeaders` plugin, so nothing else is derived
from `X-Forwarded-*`. A proxy that forwards the original client-facing hostname
satisfies this already, whether or not it keeps the port. One that substitutes
its own backend address in `Host` — an AWS ALB does this unless
`preserve_host_header` is enabled — must either be fixed to preserve it or send
`X-Forwarded-Host` from a trusted peer, or every `/mcp` call gets a fail-closed
`403 mcp.invalid_host` instead of the expected `401` OAuth challenge. Configure
the MCP client with the resource URL only — never a separate
authorization-server URL, there isn't one — and it discovers OAuth through
protected-resource metadata automatically.

### First login and first query

With `PM_AUTH_DEBUG=true` (the default), open http://localhost:41300/login and
use the debug-login option to sign in as any principal (e.g. `you@example.com`)
— no IdP needed. This also grants admin UI access outright: `PM_AUTH_DEBUG`
bypasses the admin-route gate itself (`requireAdmin` short-circuits true), not
Cedar — real per-query authorization is never bypassed, debug or not.

A clean principal has zero usable query access until roles are assigned
(deny-by-default). Migrations do ship SYSTEM roles and preset policies (e.g.
`system:development-*` for a `system:development`-tagged datasource —
[docs/policy-store.md](docs/policy-store.md)); for a first custom grant, create
at minimum:

1. A role: `POST /api/roles {"name": "analyst"}`.
2. A role assignment:
   `POST /api/role-assignments {"principal": "you@example.com", "roleId": <id>}`.
3. Cedar policies granting it something. A policy row holds exactly one
   `permit`/`forbid` statement: `cedarSrc` is validated as a single Cedar
   policy, so a body carrying two or more statements is rejected with HTTP 400
   and an "unexpected token permit" parse error. Send three separate
   `POST /api/policies {"name": ..., "cedarSrc": ..., "enabled": true}` calls,
   each under its own name (names are unique per row):

   `analyst-connect`:

   ```
   permit(principal in Role::"analyst", action in [Action::"datasource.connect", Action::"sql.select"], resource == Datasource::"acme-mysql");
   ```

   `analyst-read-unmasked`:

   ```
   permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Datasource::"acme-mysql")
       unless { resource in Tag::"pii" };
   ```

   `analyst-read-masked`:

   ```
   permit(principal in Role::"analyst", action == Action::"result.read.masked", resource in Datasource::"acme-mysql")
       when { resource in Tag::"pii" };
   ```

Per-column reads resolve unmasked first, then masked, then deny, so the
`unless`/`when` pair is what makes a classified column mask instead of coming
back in the clear: an unqualified `result.read.unmasked` grant wins over the
masked one for every column, tagged or not. Scope it and the same role reads
ordinary columns plainly while `pii`-tagged ones come back masked.

The Admin UI (`/admin/policies` for roles/assignments,
`/admin/policies/cedar-policies` for Cedar policy text) does all three
interactively if you'd rather not hand-curl it. To see that masking, classify a
column — create a mask fn (`POST /api/mask-fns {"name":"fixed","kind":"FIXED"}`)
and tag a column with it:

```
PUT /api/datasources/{id}/classification
{"schema":"acme","table":"payments","column":"card_number","tags":["pii"],"maskFnId":<id>}
```

With debug auth on, the principal these API calls authorize as is `debug-user`,
not the address you typed at the login screen — assign the role to that
principal too if you're driving the walkthrough with `curl`.

### Verify it works

In the web UI's Query page, pick a datasource and run `select * from payments`.
With `card_number` classified `pii` and the tag-scoped policy pair from
[First login and first query](#first-login-and-first-query) in place, expect a
`MASK` decision, `card_number` rendered `####` (the `FIXED` mask) and the other
columns plain. Classify nothing and the same query is a plain `ALLOW`. Run a
query against a nonexistent table to see a fail-closed `DENY`. The Logs tab
(first, non-closable tab in the result strip) shows a plain console-style line
per statement.

### Troubleshooting

- A proxy logs "could not register + catalog push after N attempts" —
  control-plane isn't reachable at `PM_CONTROL_PLANE_GRPC` (default
  `localhost:9090`), or its gRPC port differs from what you passed. The proxy
  still starts and serves, but every query fails closed (`NOT_FOUND`) until a
  push succeeds — it keeps retrying in the background.
- Two proxies registering under the same `PM_DATASOURCE_NAME` silently merge
  into one datasource row (whichever pushed last "wins" the catalog) — a known,
  bounded residual of the shared-secret trust model
  ([docs/datasource-registration.md](docs/datasource-registration.md)), not a
  bug. Use distinct names.
- `/health`'s `diagnostics` mentions "system:admin role has no active assignee"
  — nobody has logged in yet to claim the seeded admin role/group
  (`V8__seed.sql`); harmless before your first login, self-resolves after. Under
  real OIDC (not debug auth), admin membership comes from the IdP's group claim
  via `PM_OIDC_GROUP_MAP`, not this endpoint.
- Port already in use — this doc's ports (`5442`/`31307`/`5433` for Docker,
  `8080`/`9090` for control-plane, `6432`/`6033` for the two proxies, `41300`
  for web) are this doc's own choices, not hardcoded anywhere; override any of
  them via the env vars listed above if they clash with something already
  running.

## Deploying on AWS (ECS Fargate + S3 + Aurora)

proxy-monster runs in its own VPC, VPC-peered to the (separate) production and
development database VPCs — the common enterprise layout. Compute on Fargate,
one ECS service per component (the proxy fans out to one service per
datasource). An ALB for HTTP, an NLB for the SQL wire + internal gRPC. Aurora
for the store; S3 Object Lock for the WORM trail.

### VPC topology

- pm-vpc (e.g. `10.20.0.0/16`): all ECS services, the ALB (public subnets), the
  NLB, and the Aurora cluster.
- Peering to `prod-db-vpc` and `dev-db-vpc`: a peering connection to each, a
  route for `PM_TARGET_HOST` traffic, and the backend DB security group opened
  to the _proxy_ subnets' CIDRs only. CIDR blocks must not overlap.
- A `system:production`-tagged proxy targets a DB in `prod-db-vpc`; a
  `system:development` proxy targets `dev-db-vpc` — same image, different
  `PM_TARGET_*` + peering route + tag.
- VPC endpoints in pm-vpc: S3 gateway (auditmon WORM), interface endpoints for
  KMS + Secrets Manager; a NAT only for the outbound OIDC IdP call.

### Managed services

- Aurora PostgreSQL (Serverless v2 or provisioned) — the CP store, which is
  always PostgreSQL regardless of what the proxied target databases run.
  `PM_DB_URL` → writer endpoint. Give auditmon the reader endpoint + a
  `SELECT`-only role.
- S3 bucket, Object Lock — auditmon's WORM store. Retention is the bucket's own
  default policy; the monitor sets none per object. Reached via the S3 gateway
  endpoint.
- KMS — an asymmetric key for auditmon's anchor signer (`signer.type: kms`).
- ACM / wire TLS — a public ACM cert on the ALB (console HTTPS). For the SQL
  wire, prefer a private transport (internal NLB via PrivateLink or the peered
  VPC) and skip TLS. If you require wire encryption, the _proxy_ terminates it
  with an ACM Private CA cert (exportable) via Secrets Manager — public ACM
  can't be used (no key export) and a generic NLB/ALB can't terminate the
  in-band SQL TLS.

### ECS services and load balancing

<!-- prettier-ignore -->
| Component | ECS service | Exposed via | Reachability |
| --- | --- | --- | --- |
| Web | 1 service | ALB → `/` | public (console users) |
| CP · HTTP | 1+ service | ALB → `/api /auth` (+ `/oauth /mcp` if used) | private unless pmon-login/MCP used |
| CP · gRPC | same tasks | internal NLB / Service Connect | internal only |
| Proxy | 1 / datasource | NLB TCP listener per datasource | internal / peered clients |
| auditmon | 1 service | none (no inbound) | outbound: Aurora reader, S3, KMS |

- ALB (public ACM cert), path-routed on one console host: `/` → Web;
  `/api/* /auth/*` (+ `/oauth/* /mcp` when used) → CP. Set
  `PM_OIDC_REDIRECT_URI=https://<host>/auth/oidc/callback`,
  `PM_MCP_RESOURCE=https://<host>/mcp`, and `PM_TRUSTED_PROXIES` to the ALB peer
  address(es) the CP sees.
- NLB (TCP passthrough): one listener per datasource → proxy; an internal
  listener (or Service Connect) for CP gRPC — never public.

### Health checks and probes

The images are deploy-target agnostic — the same env contracts run on EKS, with
Kubernetes `Secret`s in place of ECS task secrets and a
`livenessProbe`/`readinessProbe` in place of the ECS task-definition and
target-group health checks.

- Control plane — `GET /health` on `PM_HTTP_PORT` (`8080`) returns
  `{"status":"ok"}` once the HTTP listener is up. Flyway has already migrated by
  then; a migration failure stops the process before this point. It's a liveness
  signal (process + listener up), not a deep readiness check. On EKS use an
  `httpGet` probe against `/health` — kubelet reaches it over the pod network,
  so the image needs nothing extra installed.
- Proxy — no HTTP surface (a raw wire broker). `goproxy/Dockerfile`'s
  `HEALTHCHECK` opens a bare TCP connection to `PM_PROXY_PORT`; on EKS use a
  `tcpSocket` probe against the same port. This proves only that the process
  accepts connections — not that `PM_TARGET_HOST` or the control plane are
  reachable; those surface as per-session query errors, not an unready process.
- Web — `GET /` on `41300` counts as alive for any response, including the
  redirect to `/login`. There is no dedicated web health endpoint.

### Secrets

Every secret lives in Secrets Manager and is injected as an ECS task _secret_
(never plaintext env): `PM_DB_PASSWORD`, `PM_SESSION_SECRET`, `PM_RESULT_KEY`,
`PM_SECRET_TOKEN`, `PM_OIDC_CLIENT_SECRET`, each proxy's `PM_TARGET_PASSWORD`,
the auditmon DSN + webhook URL, and the wire TLS cert/key material (issued by
ACM Private CA). Non-secret config (hosts, ports, issuer, redirect URI) stays in
plain `environment`.

### Build and push images

Four images. proxy and control-plane build from the repo root — they pull in
sibling modules (`mysqlwire` + `analyzer` for the proxy, both resolved through
`replace` directives in `goproxy/go.mod`; `:engine`/`:auth`/`:analyzer`/`:proto`
for the control plane, whose image also compiles the cgo `c-shared` analyzer
native lib). web and auditmon are self-contained and build from their own
directory. The control-plane and proxy images build for both `linux/amd64` and
`linux/arm64` (Graviton/Fargate) via
`docker buildx build --platform linux/amd64,linux/arm64`, with no extra flags.

Published images are on Docker Hub, built for both platforms by
`.github/workflows/server-images.yml` on every `server-v*` tag — pull these
rather than building your own. `latest` tracks the newest release; a version tag
pins one:

```bash
docker pull ridi/pm-goproxy:0.1.0
docker pull ridi/pm-control-plane:0.1.0
docker pull ridi/pm-web:0.1.0
docker pull ridi/pm-auditmon:0.1.0
```

The same images are mirrored on ECR Public, which is worth preferring from AWS —
pulls do not count against Docker Hub's rate limits and need no account:

```bash
docker pull public.ecr.aws/w1t1s2q1/pm-goproxy:0.1.0
docker pull public.ecr.aws/w1t1s2q1/pm-control-plane:0.1.0
docker pull public.ecr.aws/w1t1s2q1/pm-web:0.1.0
docker pull public.ecr.aws/w1t1s2q1/pm-auditmon:0.1.0
```

To build them yourself — note the context differs per image, and is not
interchangeable:

```bash
# proxy + control-plane — build context = repo root
docker build -f goproxy/Dockerfile       -t pm-goproxy:dev        .
docker build -f control-plane/Dockerfile -t pm-control-plane:dev  .
# web + auditmon — build context = their own directory
docker build -t pm-web:dev        web/
docker build -t pm-auditmon:dev   auditmon/
```

To host them in your own registry, retag and push there; the ECS task
definitions below reference `<acct>.dkr.ecr…` for exactly that case.

pmon is not containerized — it's a client binary users install
(`brew install ridi-oss/tap/pmon`, or `go build -o pmon ./pmon`).

### ECS task definitions

control-plane (excerpt):

```json
{
  "family": "pm-cp",
  "cpu": "1024",
  "memory": "2048",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "executionRoleArn": "arn:aws:iam::<acct>:role/pm-cp-exec",
  "taskRoleArn": "arn:aws:iam::<acct>:role/pm-cp-task",
  "containerDefinitions": [
    {
      "name": "cp",
      "image": "<acct>.dkr.ecr.ap-northeast-2.amazonaws.com/pm-control-plane:0.1.0",
      "portMappings": [
        { "containerPort": 8080 },
        { "containerPort": 9090, "name": "grpc" }
      ],
      "environment": [
        { "name": "PM_HTTP_PORT", "value": "8080" },
        { "name": "PM_GRPC_PORT", "value": "9090" },
        {
          "name": "PM_DB_URL",
          "value": "jdbc:postgresql://pm.cluster-xxxx.ap-northeast-2.rds.amazonaws.com:5432/proxymonster"
        },
        { "name": "PM_OIDC_ISSUER", "value": "https://your-org.okta.com" },
        {
          "name": "PM_OIDC_REDIRECT_URI",
          "value": "https://console.example.com/auth/oidc/callback"
        },
        {
          "name": "PM_MCP_RESOURCE",
          "value": "https://console.example.com/mcp"
        },
        { "name": "PM_TRUSTED_PROXIES", "value": "10.20.1.15,10.20.2.15" }
      ],
      "secrets": [
        {
          "name": "PM_DB_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/db-password"
        },
        {
          "name": "PM_SESSION_SECRET",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/session-secret"
        },
        {
          "name": "PM_RESULT_KEY",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/result-key"
        },
        {
          "name": "PM_SECRET_TOKEN",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/grpc-token"
        },
        {
          "name": "PM_OIDC_CLIENT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/oidc-client-secret"
        }
      ]
    }
  ]
}
```

proxy (excerpt, one per datasource; TLS material from Secrets Manager, written
to file by the entrypoint):

```json
{
  "family": "pm-proxy-analytics-prod",
  "cpu": "512",
  "memory": "1024",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "containerDefinitions": [
    {
      "name": "proxy",
      "image": "<acct>.dkr.ecr.ap-northeast-2.amazonaws.com/pm-goproxy:0.1.0",
      "portMappings": [{ "containerPort": 6432 }],
      "environment": [
        { "name": "PM_ENGINE", "value": "postgres" },
        { "name": "PM_DATASOURCE_NAME", "value": "analytics-prod" },
        { "name": "PM_DATASOURCE_TAGS", "value": "system:production" },
        { "name": "PM_PROXY_PORT", "value": "6432" },
        // the NLB listener a client dials for THIS datasource — omit it and pmon cannot broker this proxy
        {
          "name": "PM_ADVERTISE_ADDR",
          "value": "analytics-prod.pm.example.com:6432"
        },
        { "name": "PM_TARGET_HOST", "value": "prod-db.prod-vpc.internal" },
        { "name": "PM_TARGET_PORT", "value": "5432" },
        { "name": "PM_TARGET_DB", "value": "appdb" },
        { "name": "PM_CONTROL_PLANE_GRPC", "value": "pm-cp.pm.internal:9090" },
        { "name": "PM_TLS_CERT", "value": "/etc/pm/tls/wire.crt" },
        { "name": "PM_TLS_KEY", "value": "/etc/pm/tls/wire.key" }
      ],
      "secrets": [
        {
          "name": "PM_TARGET_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/target-analytics-prod"
        },
        {
          "name": "PM_SECRET_TOKEN",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/grpc-token"
        },
        {
          "name": "WIRE_TLS_CRT",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/wire-tls-crt"
        },
        {
          "name": "WIRE_TLS_KEY",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/wire-tls-key"
        }
      ]
      // entrypoint writes $WIRE_TLS_CRT/$WIRE_TLS_KEY to the PM_TLS_CERT/KEY paths, then execs the proxy
    }
  ]
}
```

auditmon (excerpt; task role grants S3 + KMS + Aurora-reader):

```json
{
  "family": "pm-auditmon",
  "cpu": "512",
  "memory": "1024",
  "taskRoleArn": "arn:aws:iam::<acct>:role/pm-auditmon-task", // kms:Sign, s3:PutObject(+lock), rds-db:connect
  "containerDefinitions": [
    {
      "name": "auditmon",
      "image": "<acct>.dkr.ecr.ap-northeast-2.amazonaws.com/pm-auditmon:0.1.0",
      "environment": [
        { "name": "AWS_REGION", "value": "ap-northeast-2" },
        { "name": "AUDITMON_CONFIG", "value": "/etc/auditmon/auditmon.yaml" }
      ],
      "secrets": [
        {
          "name": "AUDITMON_DB_DSN",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/auditmon-dsn"
        },
        {
          "name": "SECOPS_WEBHOOK_URL",
          "valueFrom": "arn:aws:secretsmanager:...:secret:pm/secops-webhook"
        }
      ]
    }
  ]
}
```

web (excerpt; no secrets — it proxies `/api` + `/auth` to the CP). Note there is
no `PM_PROXY_TARGET` here: it is baked in at `docker build` time, so a task-
definition entry would be ignored — see
[Web console rewrites](#web-console-rewrites):

```json
{
  "family": "pm-web",
  "cpu": "512",
  "memory": "1024",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "executionRoleArn": "arn:aws:iam::<acct>:role/pm-web-exec",
  "containerDefinitions": [
    {
      "name": "web",
      "image": "<acct>.dkr.ecr.ap-northeast-2.amazonaws.com/pm-web:0.1.0",
      "portMappings": [{ "containerPort": 41300 }]
      // no "environment": PM_PROXY_TARGET is build-time (see below), and the console's own
      // API calls are browser-side, path-routed to the CP by the ALB
      // no "secrets": the web holds none — it forwards to the CP, which owns identity + policy
    }
  ]
}
```

#### Web console rewrites

`next.config.ts` reads `PM_PROXY_TARGET` while the config evaluates, and
`next build` freezes the resolved destination into `.next/routes-manifest.json`.
Because `output: "standalone"` ships a server bundle with no `next.config.ts`,
the runtime container cannot re-read the variable — set it as an ECS
`environment` entry and the rewrites still point at the build-time default
`http://127.0.0.1:41390`, inside the container's own network namespace, so every
console API call through the container returns a 500. The Dockerfile declares no
matching `ARG` either, so `--build-arg` does not reach the build as things
stand.

The ALB layout above sidesteps this: `/api/*` and `/auth/*` are path-routed
straight to the CP, and the console's API calls are same-origin browser
requests, so they never traverse the web container's rewrites. Keep that routing
and the container needs no CP address at all. Only front the console some other
way (a single upstream to the web container, no path routing) and the rewrites
become load-bearing — then bake the target in per environment by adding
`ARG PM_PROXY_TARGET` + `ENV PM_PROXY_TARGET` to `web/Dockerfile`'s builder
stage, giving you one image per CP address.

Local `next dev` is unaffected — it evaluates the config on every boot, which is
why `PM_PROXY_TARGET=http://127.0.0.1:8080 pnpm -C web dev` works.

### Create the resources

A starting-point AWS CLI sequence with the recommended settings. Substitute
account, region, subnet, and ARN placeholders; run behind your own IaC in
practice.

```bash
# --- Aurora PostgreSQL (Serverless v2), encrypted, master password in Secrets Manager ---
aws rds create-db-cluster --db-cluster-identifier pm \
  --engine aurora-postgresql --engine-version 16.4 \
  --serverless-v2-scaling-configuration MinCapacity=0.5,MaxCapacity=8 \
  --master-username pmadmin --manage-master-user-password \
  --db-subnet-group-name pm-db-subnets --vpc-security-group-ids sg-pmdb \
  --storage-encrypted --backup-retention-period 14

# --- S3 WORM bucket: Object Lock (compliance) + default retention + block public ---
aws s3api create-bucket --bucket pm-audit-worm --object-lock-enabled-for-bucket \
  --region ap-northeast-2 --create-bucket-configuration LocationConstraint=ap-northeast-2
aws s3api put-object-lock-configuration --bucket pm-audit-worm \
  --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Days=730}}'
aws s3api put-public-access-block --bucket pm-audit-worm \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# --- KMS asymmetric key for auditmon anchor signing ---
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY --description "pm-audit anchor signer"
aws kms create-alias --alias-name alias/pm-audit-signer --target-key-id <key-id>

# --- All secrets in Secrets Manager (KMS-encrypted at rest) ---
for s in db-password session-secret result-key grpc-token oidc-client-secret \
         target-analytics-prod auditmon-dsn secops-webhook wire-tls-crt wire-tls-key; do
  aws secretsmanager create-secret --name pm/$s --secret-string "REPLACE_ME"
done

# --- ACM: public cert for the ALB; ACM Private CA cert (exportable) for the proxy wire ---
aws acm request-certificate --domain-name console.example.com --validation-method DNS
aws acm-pca issue-certificate --certificate-authority-arn <pca> --csr fileb://wire.csr \
  --signing-algorithm SHA256WITHRSA --validity Value=365,Type=DAYS   # export → pm/wire-tls-*

# --- VPC peering to a backend-DB VPC + route ---
aws ec2 create-vpc-peering-connection --vpc-id vpc-pm --peer-vpc-id vpc-proddb
aws ec2 create-route --route-table-id rtb-pm-private \
  --destination-cidr-block 10.30.0.0/16 --vpc-peering-connection-id pcx-xxxx

# --- ECS cluster + a service (proxy shown; repeat per component/datasource) ---
aws ecs create-cluster --cluster-name pm --capacity-providers FARGATE
aws ecs register-task-definition --cli-input-json file://pm-proxy-analytics-prod.json
aws ecs create-service --cluster pm --service-name pm-proxy-analytics-prod \
  --task-definition pm-proxy-analytics-prod --desired-count 2 --launch-type FARGATE \
  --network-configuration 'awsvpcConfiguration={subnets=[subnet-pm-a,subnet-pm-b],securityGroups=[sg-pm-proxy]}' \
  --load-balancers targetGroupArn=<proxy-tg>,containerName=proxy,containerPort=6432

# --- NLB (L4 passthrough) for the wire; the ALB (HTTP path-routing) is created similarly ---
aws elbv2 create-load-balancer --name pm-wire --type network --scheme internal --subnets subnet-pm-a subnet-pm-b
aws elbv2 create-target-group --name pm-proxy-analytics-prod --protocol TCP --port 6432 --vpc-id vpc-pm --target-type ip
aws elbv2 create-listener --load-balancer-arn <nlb> --protocol TCP --port 6432 \
  --default-actions Type=forward,TargetGroupArn=<proxy-tg>
```

### Production checklist

- `PM_AUTH_DEBUG` / `PM_DEV` unset — real OIDC only.
- CP gRPC never on a public listener; wire TLS at the proxy for any untrusted
  client path.
- auditmon: `signer.type: kms`, Object-Lock bucket whose retention outlives your
  audit window.
- Non-default `PM_SESSION_SECRET` (≥32) + strong `PM_RESULT_KEY`; all secrets
  via Secrets Manager; task IAM roles over static `AWS_*` keys.
- Backend-DB security groups admit only the proxy subnets over the VPC peering.
