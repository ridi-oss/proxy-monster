# DESIGN.md — proxy-monster

The one-page map of how proxy-monster fits together. The authoritative
per-workstream designs live in [docs/](./docs/README.md);
[AGENTS.md](./AGENTS.md) covers intent and target-engine priority.

## Summary

A self-hosted OSS proxy that speaks the native MySQL and PostgreSQL wire
protocols and enforces column-level access control per role: it parses each
query, resolves column lineage (which source columns every output and predicate
derives from), and masks or denies accordingly. Native clients (psql, mysql,
JDBC) work unchanged. Fail-closed: anything it cannot prove safe is denied. The
target databases it protects are MySQL — the primary, fully-enforced target —
and PostgreSQL, which is experimental. Its own control-plane store is a separate
matter: PostgreSQL only. See
[AGENTS.md](./AGENTS.md#two-independent-engine-axes).

## Goals and non-goals

Goals

- Transparent proxy in front of MySQL and PostgreSQL target databases; native
  clients unchanged.
- Deterministic, role-based column masking
  (`datasource/catalog/schema/table/column → role → action`).
- Lineage-aware enforcement (through functions, expressions, subqueries, joins,
  `SELECT *`).
- Fail-closed on un-resolvable queries; a policy grant is the only way to widen
  access.
- Full audit — hash-chained on the decision path (principal, query, decision,
  result volume). Tamper-_evidence_ needs the separately-deployed `auditmon` to
  verify the chain and anchor it off-box
  ([docs/audit-trail-hardening.md](docs/audit-trail-hardening.md)).
- Self-hosted, in-VPC, OSS.

Non-goals

- Sharding / read-write-splitting / large-scale pooling.
- NoSQL / warehouses as target databases (MySQL and PostgreSQL first).
- Content-based PII detection as the _primary_ mechanism — deterministic column
  policy is the boundary. A local PII-NER content backstop over unclassified
  columns is a planned defense-in-depth, never the boundary (see
  [Enforcement: mask, deny, allow](#enforcement-mask-deny-allow)).

## Architecture

A split control plane (Kotlin/JVM) and data plane (Go) talking over gRPC. The
proxy terminates the SQL wire connection and can relay and mask but never
decides; the control plane decides every statement and never opens a connection
to a target database. Around them sit the web console, the PostgreSQL
control-plane store, auditmon, and pmon on the client side.

The component roster, the topology diagram, the port/protocol matrix, and where
each step of enforcement happens are in [ARCHITECTURE.md](./ARCHITECTURE.md).
The rest of this document is the design on top of that shape.

## Policy catalog (data model)

Authoritative model: [docs/authz-model.md](docs/authz-model.md). In brief, the
control-plane store — PostgreSQL, always — holds:

- `policy` — grants held as Cedar policy text (roles/tags/resources referenced
  as entities inside the source); there are no generated `role_statement` rows,
  so a role's grants are the enabled policies that mention it, and system
  policies live in a reserved negative id space. Schema:
  [docs/policy-store.md](docs/policy-store.md#target-schema).
- `column_classification(datasource, schema, table, column, tags[], mask_fn_id)`
  — per-column tags (`pii`, `system:*`, `preset:*`) + the mask function; these
  tags are what Cedar conditions on.
- `mask_fn(name, kind)` — masking transforms (`FIXED` / `LAST_N` /
  `FORMAT_PRESERVING` / `NULL`; unknown kinds fall back to a fixed `****`
  redaction). The transform is fixed by kind.
- Roles + identity — `app_role`, `principal_role`, `app_group`, `group_member`,
  `group_role`, `app_user`.
- JIT elevation — `access_request` +
  `access_grant(role, expires_at, revoked_at)`: a time-boxed, revocable grant of
  a role that widens the effective role set for its window. Who may approve is
  Cedar (`task.approve`), not a separate approval-config table.
- `audit_event` — the chained, heterogeneous event log (`decision` /
  `completion` / `approval_lifecycle`); the single audit chokepoint.

## Enforcement: mask, deny, allow

Per statement, the analyzer emits `StatementFacts` and the control-plane walks
it through Cedar:

1. Parse + lineage (sqlglot-go). A statement the analyzer cannot safely resolve
   is `resolved=false` → routes through the `exception.unanalyzable` Cedar gate
   (fail-closed by default, grant-overridable).
2. Required grants — the analyzer emits, per statement: the `sql.<kind>` grant;
   a `result.read` grant per output column (with a mask vs deny disposition); a
   `result.read` grant per scanned table with zero traced columns (closes the
   zero-column existence oracle); and function / utility grants for dangerous
   calls and session-critical commands.
3. Cedar grant-walk — each grant is a Cedar `authorize` verdict over the
   principal's roles + resource tags + request context. A maskable column deny →
   mask that output column; a non-maskable deny (a sensitive column in a
   predicate / join / aggregate / non-whitelisted derivation, where masking
   cannot preserve correctness) → DENY the whole statement. Session-privilege /
   lexer-mutation commands ride a `system:critical` Cedar forbid.
4. Enforce — goproxy applies the decision: star-expansion rewrite so ordinals
   bind by construction, inline result-stream masking of flagged output columns
   by ordinal, forward an `ALLOW`, or return a protocol error on `DENY`.
   (Row-level `WHERE` injection is not implemented; there is no row-level policy
   table.)
5. Audit the decision.

The guarantee lives in mask + deny (fail-closed): the analyzer's star-expansion
rewrite binds mask ordinals, the proxy masks classified columns on the result
stream, and the cases masking cannot make safe — a sensitive value in a
predicate / aggregate / derived expression, an unparseable or unresolvable
statement — are exactly the DENY cases.

Content-detection backstop (planned defense-in-depth, not the boundary). A local
PII-NER model (GLiNER-class, ONNX on the JVM — no hosted model ever sees a
value) over unclassified / free-text columns that carry no
`column_classification`, catching residual leaks the deterministic engine cannot
see. It is not a boundary against inference (a WHERE/aggregate already ran on
real data); the guarantee stays in mask + deny. Hits double as classification
suggestions. Local-only by construction — this is a PII proxy, so no result
value leaves the trust boundary ([docs/backlog.md](docs/backlog.md)).

## Identity and broker

Separate **who you are** (identity source) from **how you prove it over the
wire** (auth mechanism). Authoritative: `docs/auth-model.md`.

- **Identity source — OIDC (Okta), canonical:** the source of truth for
  principal + group membership; groups map to proxy **roles** and approval
  groups (§7). Roles are resolved server-side on every decision.
- **Wire auth — SSO login + short-lived token.** A `pmon` daemon (single static
  **Go** binary) runs the OIDC device-auth flow and the control-plane mints a
  **short-lived opaque, revocable credential** bound to principal + roles.
  - **Default — background daemon + local broker:** `pmon` runs stable loopback
    listeners, opened as soon as credentials exist; saved psql/DataGrip
    connections use a never-changing localhost password while the daemon injects
    the current token on the upstream hop and silently renews it (no terminal,
    no browser day-to-day).
  - **One daemon, two front ends:** the daemon owns all state and exposes a
    **local control socket** (a unix socket in a 0700 dir — filesystem
    permissions are the authentication, and it is not a loopback TCP port
    because the API can start a login). The CLI and the menu-bar app are
    **symmetric peers** over it: neither is privileged, both start and stop the
    daemon, both work when it is down. The daemon runs the login itself, so
    there is one implementation and no two-device-flow race. It is spawned
    detached and outlives whichever peer started it, so stopping is always
    explicit — and a peer that crashes leaves it brokering, to be adopted by the
    next one.
  - **One-shot token:** the web **Tokens** page mints a short-lived password the
    user pastes into any client (headless/CI, or a client the broker daemon does
    not front).
  - **Expiring-only** — every credential has a server-set expiry (TTL clamped
    `[60s, 24h]`); there are no persistent tokens.
  - The token rides in the password field (PG `AuthenticationCleartextPassword`,
    MySQL `mysql_clear_password`), so the hop needs wire TLS or a private
    transport. Wire TLS is optional (`PM_TLS_CERT` + `PM_TLS_KEY`, both or
    neither): with it set the proxy rejects a client that does not upgrade, and
    without it the proxy listens in plaintext and the token crosses in the clear
    — acceptable only on a trusted network. The cert needs no publicly-trusted
    CA, because the proxy distributes its own trust material (see below).
  - **Cert distribution (no MDM CA):** the proxy advertises the certificate
    CHAIN a client should trust — leaf first, plus any intermediates and root —
    to the control plane on register, along with a separate boolean saying
    whether it serves TLS at all. `pmon` fetches
    `{datasource → address, chain, wire-TLS}` at login (over the CP's own
    trusted HTTPS, scoped to `?connectable=true`) and verifies the proxy the
    ORDINARY way: that chain as its root pool, with the advertised host checked
    against the certificate. A self-signed cert is simply its own anchor, so
    nothing has to be hand-distributed or enter a system trust store. Direct
    clients get the same bytes as a download (`psql`/`mysql`/DataGrip via
    `sslrootcert` / `--ssl-ca` with `verify-full`), so there is one trust
    mechanism rather than a separate pinning path. A datasource whose proxy
    serves TLS but greets without it is refused rather than downgraded to
    plaintext — keyed on the TLS boolean, not on whether a chain happens to be
    published, because a publicly-trusted proxy publishes none. **Trust
    anchor:** the chain is only as trustworthy as the register credential and
    the pmon↔CP channel — a holder of the gRPC register secret can overwrite a
    datasource's advertised address and chain together (see
    `KNOWN_LIMITATIONS.md`; registrar-identity hardening is backlogged). A
    rotated leaf re-advertises on the next register/reconnect resync (immediate
    rotation-refresh is a follow-up).
- **Broker:** goproxy reaches the target DB with a per-datasource **service
  account**; the token only proves _who you are_, never _what you can see_ —
  enforcement (§5) and JIT (§7) are independent of how it was obtained.

Separate who you are (identity source) from how you prove it over the wire (auth
mechanism). Authoritative: [docs/auth-model.md](docs/auth-model.md).

- Identity source — OIDC (Okta), canonical: the source of truth for principal +
  group membership; groups map to proxy roles. Roles are resolved server-side on
  every decision.
- Wire auth — SSO login + short-lived token. A `pmon` daemon (single static Go
  binary) runs the OIDC device-auth flow and the control-plane mints a
  short-lived opaque, revocable credential bound to principal + roles.
  - Default — background daemon + local broker: the daemon opens one loopback
    listener per MySQL datasource on a sticky port as soon as credentials exist
    (`pmon login` is the only step), so a saved `mysql` or JDBC connection keeps
    a fixed `127.0.0.1:<port>` and a localhost password that never rotates,
    while the daemon injects the current token on the upstream hop. Only MySQL
    is brokered — a PostgreSQL datasource is discovered then skipped, so `psql`
    connects to the proxy directly with a token as its password. Renewal is
    server-side only: the control plane serves `POST /auth/session/renew`, but
    `pmon` stores the renewal token from device login and never calls it, so a
    login lasts one token lifetime (12h default) and then needs a fresh
    `pmon login`.
  - One-shot token: the console's Access page (`/access`) mints a short-lived
    password (`POST /api/tokens`) the user pastes into any client.
  - Expiring-only — every credential has a server-set expiry (TTL clamped
    `[60s, 24h]`); there are no persistent tokens.
  - The token rides in the password field (PG `AuthenticationCleartextPassword`,
    MySQL `mysql_clear_password`). Wire TLS is optional (`PM_TLS_CERT` +
    `PM_TLS_KEY`, both or neither): with it set the proxy rejects a client that
    does not upgrade, and unset the proxy listens in plaintext, so the token
    crosses the network in the clear. Plaintext is therefore only acceptable on
    a trusted network — a private transport such as a peered VPC, PrivateLink,
    or a VPN/tailnet. Configuration:
    [INSTALL.md](INSTALL.md#proxy--one-set-per-datasource). Where pinning does
    and does not cover this hop:
    [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md#wire-cert-pinning-pmon--proxy).
- Broker: goproxy reaches the target DB with a per-datasource service account;
  the token only proves _who you are_, never _what you can see_ — enforcement
  and JIT elevation are independent of how it was obtained.

Web session lifetime, IdP revalidation, and device-binding:
[docs/session-lifetime.md](docs/session-lifetime.md).

## JIT elevation and approval

Baseline roles are static (OIDC group → role). Beyond baseline, a principal can
request time-boxed elevation subject to approval — the only human-in-the-loop
path; the per-query engine stays deterministic and never blocks on a human.
Authoritative: [docs/approval-workflow.md](docs/approval-workflow.md) +
[docs/authz-model.md](docs/authz-model.md).

Elevation is an identity-layer mutation. The engine is a pure function of
`(statement-facts, effectiveRoles, catalog, policy)`; a grant only widens the
effective role set it sees for the grant's window, so the same per-query
decision applies with no separate elevation path in the engine. An approved
grant takes effect on the principal's next query (roles re-resolved per
decision), and expiry/revocation reverts subsequent queries with no reconnect.

Query approval runs a query under a role `R`, once, via an approver
(`task.approve`, requester ≠ approver): the approver executes the approved
statement under `R` and releases the result, masked exactly as `R` would see it.
A single execution path; who may approve is Cedar, not a config table.

Control / data plane split — control-plane (Kotlin: catalog + policy + grants +
REST/console + the FFM analyzer) and data-plane (Go goproxy) are logically
separate; the proxy reads each decision over gRPC. See
[docs/datasource-registration.md](docs/datasource-registration.md).

Console (Next.js + Tailwind + shadcn/ui, `web/`) — requester (request elevation
/ my grants), approver (inbox; approve/reject; execute-under-`R`), admin
(classifications, Cedar policies, mask fns, datasources, audit). See
[docs/web-console.md](docs/web-console.md).

## Risks

- Analyzer parse/lineage coverage drives the DENY rate — a construct sqlglot-go
  can't resolve fails closed. Mitigated by golden-parity tests and a
  grant-overridable `exception.unanalyzable`.
- Rewrite correctness — masking mutates the result stream. Mitigated: prefer
  deny over a risky rewrite; ordinal-bound masking with fail-closed `SELECT *`
  expansion; large DB-backed test suites.
- Performance — analysis per statement adds latency. Mitigated: per-connection
  catalog caching; the Go proxy relays hot bytes.
- Prepared statements / binary protocol — PG extended-query is enforced. MySQL
  `COM_STMT_*` is decided and relayed, but binary-protocol results cannot be
  masked: a MASK verdict without `exception.unmaskable` fails closed
  ([KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md)).
- Coverage gaps = security gaps — anything not analyzed defaults to DENY.

## Roadmap

Planned and deferred work — including the content-detection masking backstop and
the agentic "auto mode" stretch — lives in [docs/backlog.md](docs/backlog.md).
