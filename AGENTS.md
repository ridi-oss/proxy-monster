# AGENTS.md — proxy-monster

Entry point for anyone picking up this project. Read this first.

## What it is

proxy-monster is a self-hosted, open-source database access-control proxy for
MySQL and PostgreSQL. It enforces column-level access control — deterministic,
role-based masking and deny — and is lineage-aware: it follows sensitive values
through SQL expressions, functions, subqueries, and joins. Clients connect with
their normal tools (psql, mysql, JDBC) over the native wire protocol; the proxy
masks per role and denies anything it cannot prove safe (**fail-closed**).

The goal is a transparent, in-VPC, self-hostable access-control proxy you own
and can extend, friendly to CLIs and native clients.

## Engine priority

MySQL is the primary target and the correctness bar for shipping — build and
verify it first. PostgreSQL support is experimental and developed alongside;
today PostgreSQL also serves as proxy-monster's own control-plane store.
PostgreSQL-only edge cases — its transactional-DDL behaviors (in-transaction DDL
visibility, Sync/implicit-transaction rollback, deferred-constraint COMMIT
failure) — may be carried as documented known limitations rather than block a
MySQL milestone. Keep MySQL and PostgreSQL separate when splitting work or
weighing review findings, and weight MySQL accordingly.

## Layout

Modules:

- `goproxy/` — Go data-plane wire proxy: MySQL/PostgreSQL codecs, token auth,
  the per-statement `Decide` call, inline result masking, and the backend
  broker.
- `control-plane/` — Kotlin control plane: identity and roles, Cedar
  authorization, the catalog, the per-statement decision, and the admin +
  console API (HTTP and gRPC).
- `analyzer/` — the Go sqlglot-go lineage probe (`probe/`) and its JVM FFM
  binding (`jvm/`); emits each statement's required grants.
- `engine/` — shared Kotlin enforcement code the control plane calls: the
  JVM-side wrapper around the sqlglot-go analyzer, system classification (the
  dangerous-function and system-catalog manifests), SQL normalization, and the
  mask functions used when a stored approval result is viewed.
- `auth/` — Kotlin OIDC login and the MCP OAuth authorization server.
- `auditmon/` — Go audit-trail monitor: verifies the hash chain, anchors
  off-box, detects anomalies, and exports to a SIEM.
- `pmon/` — Go client daemon: connect with a saved password while it brokers a
  short-lived token upstream.
- `mysqlwire/` — Go MySQL wire-protocol codec library (shared by `goproxy` and
  `pmon`).
- `proto/` — protobuf contracts: the proxy↔control-plane gRPC surface and the
  analyzer FFM boundary.
- `web/` — the Next.js console (editor, policies, access, audit, admin).
- `deploy/` — sample seed SQL for the compose backends.
- `docs/` — per-workstream design docs.

Key docs:

- [`README.md`](./README.md) — project front door.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the components, topology, trust
  boundaries, and ports.
- [`DESIGN.md`](./DESIGN.md) — the design decisions and the
  decision-to-enforcement flow.
- [`INSTALL.md`](./INSTALL.md) — install, run locally, and deploy (local + AWS).
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to build, test, and contribute.
- [`SECURITY.md`](./SECURITY.md) — how to report a vulnerability.
- [`KNOWN_LIMITATIONS.md`](./KNOWN_LIMITATIONS.md) — accepted caveats and gaps.
- [`docs/README.md`](./docs/README.md) — the design-doc index, plus a summary of
  what's built.

## Stack

- The control-plane is Kotlin/JVM; the wire proxy and the lineage analyzer are
  Go. Kotlin/JVM was the original choice, for an in-process JVM lineage engine;
  after the engine moved to sqlglot-go the system is being ported to Go
  incrementally, and the control-plane is the last Kotlin component. The
  analyzer still runs inside the JVM through a Foreign Function & Memory binding
  to a Go c-shared library (JDK 24 — the Java compiler is pinned to
  `--release 24` and every module targets JVM 24).
- Lineage: the sqlglot-go probe in `analyzer/` resolves column lineage — it
  parses each statement and traces which source columns every output and
  predicate derives from. proxy-monster owns the probe; sqlglot-go is a library
  dependency.
- Enforcement: masking and deny. When a query touches masked columns the
  analyzer rewrites `SELECT *` to an explicit column list (a faithful,
  semantically-identical rewrite) so mask ordinals are fixed; the proxy then
  masks those columns inline on the result stream. Anything the analyzer cannot
  prove safe is denied. Masking is result-stream rewriting — the query is not
  rewritten to inject mask expressions.
- Identity: OIDC. The IdP's group claim provisions local group membership (via
  SCIM or JIT on first login); local groups map to roles through the
  `group_role` map. The IdP never mints roles directly. Okta is the reference
  provider; any OIDC IdP works ([docs/auth-model.md](./docs/auth-model.md)).
- Wire auth: SSO login plus a local broker daemon (`pmon`). Saved connections
  use a fixed localhost password while the daemon injects a short-lived token on
  the upstream hop. The daemon does not renew that token — a login lasts one
  token TTL, then `pmon login` again (see
  [DESIGN.md](./DESIGN.md#identity-and-broker)).
- JIT elevation: a time-boxed, revocable grant of a role to a user (an
  `access_grant`). The grant just adds to the user's effective roles, so the
  same per-query decision applies — the engine has no separate elevation path
  (see [DESIGN.md](./DESIGN.md#jit-elevation-and-approval)).
- Planes: the Kotlin control-plane owns a Postgres store (identity, policy,
  catalog, grants, audit); the Go data-plane proxy holds no store — it connects
  only to its target backend and reads each decision from the control-plane over
  gRPC.
- Web console (`web/`): a SQL editor plus admin for datasources, policies,
  access, and audit, in Next.js.

## Control-plane HTTP API

There is no API reference and no OpenAPI spec. The routes are the surface and
the `@Serializable` Kotlin data classes in each owning file are the
request/response reference. Handler names do not track their path prefixes, so
the map of which file owns which prefix — and the gate each one calls — is in
[docs/authz-model.md](./docs/authz-model.md#http-auth-gates).

An authenticated session alone is never authorization. A route states its
requirement by which gate helper it calls (`requireApi`, `requireAdmin`,
`requireAuthz`, `requireScimAuth`), and `PM_AUTH_DEBUG` short-circuits all four.

Errors are never English prose on the wire: a route responds
`ApiError(code, params)` with a stable dot-namespaced code the web looks up as
an i18n message key. `Scim.kt` is exempt — its body follows the SCIM 2.0 spec.
See [docs/l10n.md](./docs/l10n.md).

## Conventions

Full list in [CONTRIBUTING.md](./CONTRIBUTING.md#conventions). The three that
most often get violated:

- Comments and docs are not a diary, and this is a **security** rule before it
  is a style one: this repository is public. A comment explains what the code
  cannot say — an outside constraint, a non-obvious failure mode, why not the
  obvious alternative. It must not narrate how the code came to be: no review
  findings, no what-was-tried, no "previously X", no debugging account. That
  narration is what carries host names, paths, internal tooling, and topology
  into a public repository. History goes in the commit message, which is also
  public — the same rule about naming internal systems applies there.
- l10n is non-negotiable. Every user-facing string is localized (English and
  Korean today). The server returns a stable dot-namespaced code via `ApiError`,
  never English prose; every message key must exist in every locale under
  `web/messages/<locale>/` ([docs/l10n.md](./docs/l10n.md)).
- Fail-closed through Cedar, not a hardcoded deny. When the analyzer cannot
  prove a statement safe, route it through the deny-by-default gate
  (`exception.unanalyzable` / `exception.unmaskable`) so a datasource can
  override it while the production floor stays closed. Coverage gaps are
  security gaps.

## Build, test, run

The toolchain is pinned via mise (`mise.toml`), which also defines the tasks:

```sh
mise run dev      # the whole local stack
mise run verify   # the whole gate: lint, JVM tests, Go tests, web tests + build
```

`mise tasks ls` lists the rest, including per-component tasks for running one
piece against a stack you started by hand. The gate is mandatory before pushing
and its DB-backed tests need Docker — details, and the flags that change that,
in [CONTRIBUTING.md](./CONTRIBUTING.md#build-test-run). Install and deploy:
[INSTALL.md](./INSTALL.md).

## Design docs

Index and what's built: [docs/README.md](./docs/README.md). House style:
[CONTRIBUTING.md](./CONTRIBUTING.md#conventions).
