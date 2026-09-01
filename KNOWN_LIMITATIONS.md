# Known limitations

A single register of proxy-monster's known limitations, accepted caveats, and
deferred gaps — what the system does not guarantee, where it deliberately
over-denies, and what's tracked for later. This is the one place to look;
detailed design/tracking lives in the linked docs.

Severity legend: 🟢 fail-safe over-deny (a legitimate query may DENY, never a
wrong-ALLOW) · 🟡 fail-closed deny of a legitimate case (feature intentionally
unavailable) · 🔴 known disclosure/leak (not fail-safe — a real gap).

The overriding invariant is fail-closed: a cleartext PII leak is the worst
outcome, over-denying is acceptable. Everything below is consistent with that
except the items explicitly marked 🔴.

Every engine, MySQL, and PostgreSQL mention below is about a **target database**
— what the proxy protects and enforces against. None of it concerns the
control-plane store, which is PostgreSQL only and carries no portability caveat
([`docs/migrations.md`](./docs/migrations.md)).

## Web session lifecycle

- A web session without a stored refresh token cannot be revalidated against the
  IdP mid-session. This occurs when `offline_access` is absent or
  `PM_RESULT_KEY` is unset. The timer sweep leaves that session alone; identity
  staleness is bounded by the configured absolute cap
  (`PM_WEB_SESSION_ABSOLUTE`, default 2h), not the 5-minute IdP recheck
  interval.
- proxy-monster is a single-instance system. Timer-sweep serialization,
  refresh-token use, migrations, and runtime guards assume one control-plane
  process. Multi-replica coordination and leader election are out of scope by
  design; do not deploy multiple active replicas.

## Daemon session renewal and revocation

- 🟡 Silent `pmon` renewal is bounded by `PM_SESSION_WINDOW` (default 2h): the
  daemon's renew loop re-mints ~30 min before token expiry, but with the default
  12h TTL that first attempt lands long after the window closed — so a
  default-config login still lasts one TTL, then needs `pmon login` again. Raise
  the window (or shorten `--ttl`) to get continuous renewal.
- 🔴 Closing a daemon renewal window does not revoke the wire token issued under
  it (token TTL, 12h default, outlives the 2h window). The exposure is a
  revocation the IdP signals _only_ as `invalid_grant`: group-removal
  revocations empty the role set and every statement DENYs, and SCIM
  `active=false` / local deactivate revoke the tokens outright
  (`revokeActiveCredentialsTx`). Detail:
  [`docs/auth-model.md`](./docs/auth-model.md#security-invariants).

## Audit trail

- 🟡 OIDC group reconciliation (`provisionFromOidc`) commits before, and
  separately from, the login-audit transaction: a session mint that then fails
  leaves the reconciled membership in place; the next login re-reconciles.
  OIDC-reconciled membership changes are recorded in no audit trail (only
  manual-admin and SCIM membership changes are); the `auth` event covers the
  login itself.

## Identifier handling (schema-aware enforcement)

- 🟡 Identifiers containing `.` or `/` cannot be authorized normally. Both are
  legal inside a _quoted_ identifier but are the key/EUID delimiters (analyzer
  keys join on `.`, Cedar EUIDs on `/`), so a component containing one either
  fails identity rendering or is denied during Cedar resource binding.
  Production denies; an explicit `exception.unanalyzable` grant may relay a
  statement whose dotted identity failed before resource facts were emitted.

## Live namespace tracking

Decisions resolve against each connection's live probed namespace (PostgreSQL
probe-always; MySQL per-statement re-probe). The session settings the masker
depends on are pinned fail-closed:

- 🟡 MySQL `character_set_results` must stay UTF-8 — anything else fails the
  session closed. Exception: the Connector/J (DBeaver) session-init
  `SET character_set_results = NULL` is rewritten to `utf8mb4` so those clients
  work.
- 🟡 The injected namespace probe consumes a transaction's first-statement slot,
  so `SET TRANSACTION` right after `BEGIN` fails with SQLSTATE 25001.
  Suppressing the probe for a "bare opener" would be a wire-signature guess a
  stored `CALL` can mimic while moving `search_path` — fail-open. Use
  `BEGIN ISOLATION LEVEL …` instead.
- 🟡 `client_encoding` must remain UTF8 — under another encoding the same bytes
  bind different objects on each side, so a non-ASCII identifier could dodge its
  mask. It is `GUC_REPORT`: a switch is observed before the next statement and
  the relay fails closed.
- 🟡 `standard_conforming_strings` must remain on — with it off, a
  backslash-escape literal can hide a statement boundary the admission lexer
  cannot see. `GUC_REPORT`: a session turning it off fails closed (SQLSTATE
  `0A000`).

## Catalog freshness

Enforcement decides against a per-connection catalog captured on the
connection's own held target-DB connection (design:
[`docs/per-connection-catalog.md`](./docs/per-connection-catalog.md)) — the
control plane always decides against exactly what that connection's target DB
binds. The datasource-global catalog is now config-only (catalog browser,
tagging, table detail) and never feeds an enforcement decision.

- Enforcement-path residuals (detail + severities in
  [`docs/per-connection-catalog.md`](./docs/per-connection-catalog.md)): 🔴
  rename/redefinition launders name-keyed classifications (re-tag is the admin's
  job); an approval grant not bound to the resolved resource; DDL inside a
  DML-fired trigger unflagged; a bounded external `A→B→A` revert window; 🟡
  MySQL temp-table shadowing; PostgreSQL transactional-DDL probe edges. External
  out-of-band DDL is corrected on the next re-check past the staleness bound,
  not immediately.
- 🟡 A UDF whose BODY reads a masked column leaks it: `SELECT my_udf(id) FROM t`
  where `my_udf` internally reads `ssn` returns ssn in the clear — the read
  happens on the service-account connection the proxy never sees. Passing the
  column as an argument is still caught (`SELECT custom_udf(ssn)` DENYs,
  [`docs/derived-masking.md`](./docs/derived-masking.md)). Accepted because
  functions are admin-authored (creating one is DDL a restricted principal can't
  run); a UDF on a masking datasource must not read PII. Auto-closing is
  backlogged ([`docs/backlog.md`](./docs/backlog.md)).

## Query coverage

- 🟢 sqlglot-go parser gaps route through `exception.unanalyzable` (production
  denies; a development exception may relay). Bare `SELECT *` over a
  table-function / `LATERAL` / `VALUES` source follows the same gate.
- 🟡 `RENAME TABLE a TO b` is denied — sqlglot-go leaves it an unmodeled
  `Command`, and matching the verb would also match `RENAME USER` (privilege
  management). Use `ALTER TABLE a RENAME TO b`.

## Authz / policy

- 🟡 A stored FAILED query's diagnostic re-decides against the CURRENT catalog,
  not an execution-time snapshot (unlike rows, #229). Example: `users.ssn` is
  masked, a write fails with `DETAIL: Failing row contains (1, 010-…)`, then ssn
  is dropped — a later view re-decides all-unmasked and releases the raw text.
  Needs DDL within the 24h retention window
  ([`docs/diagnostic-redaction.md`](./docs/diagnostic-redaction.md)).
- 🟡 The analyzer's diagnostic leak set covers only the statement's own tables.
  `DELETE FROM orders …` whose FK `ON DELETE CASCADE` hits a constraint on
  `order_items` dumps THAT table's row in the `DETAIL` — a column set the check
  never considered
  ([`docs/diagnostic-redaction.md`](./docs/diagnostic-redaction.md)).
- 🟡 A PostgreSQL DEFERRABLE constraint fails at `COMMIT`, and the sanitize flag
  is per statement: the `UPDATE` that violated it was marked sanitizing, but the
  `COMMIT` (empty leak set) is not, so its
  `DETAIL: Key (ssn)=(…) is still referenced` relays raw. The known
  transactional-deferral class
  ([`docs/diagnostic-redaction.md`](./docs/diagnostic-redaction.md)).
- 🟡 Run-as-approver checks the approver's active status at `/execute`, not the
  requester's: a requester deprovisioned after approval still has the task
  execute (they can't view the result — `/result` checks `isDeactivated`).
  Whether the task should run at all is unresolved, flagged rather than silently
  decided. Detail: [`docs/task-execution.md`](./docs/task-execution.md).
- 🟡 Open presets — curation is load-bearing. Under `system:development` (and
  the permit-by-default system posture), a data-reading system object that the
  shipped `system:` classification _forgets to tag_ is exposed. The curated
  classification must be thorough + version-maintained. Detail:
  [`docs/access-model.md`](./docs/access-model.md).
- 🟡→🔴 No fail-closed manifest-completeness guard: an un-manifested system
  table gets no `system:` tag, so a datasource-wide read grant or a
  `system:development` permit could read it (config-dependent). Deferred —
  [`docs/backlog.md`](./docs/backlog.md).

## Data plane

- 🟡 Binary/prepared results (every JDBC/ORM client) cannot be masked: they deny
  by default under a MASK verdict, unless `exception.unmaskable` grants the
  unmasked relay. PostgreSQL `COPY` is always denied. Detail:
  [`docs/access-model.md`](./docs/access-model.md).
- 🟡 A shutdown drain landing between a pipelined PostgreSQL `Execute`'s relayed
  `CommandComplete` and its buffered `Sync` rolls the statement back — a client
  that treated `CommandComplete` as commit believes a rolled-back write
  succeeded. Narrow window; MySQL's analogue is benign (skipped and retried on
  reconnect). Fix (bounded reads through the pending `Sync`) is a follow-up.

## Wire-cert distribution (direct clients and `pmon`)

A proxy advertises its wire-TLS certificate chain at `Register`;
`GET /api/datasources/{id}/wire-cert` serves it for `psql`/`mysql`/DataGrip
(`verify-full`), and `pmon` uses the same bytes as its upstream root pool.

- 🔴 The advertised chain's root of trust is the shared `PM_SECRET_TOKEN`, not a
  proxy identity: whoever holds it can re-register any datasource's address and
  chain and capture its wire tokens. Fix is a datasource-bound registrar
  identity (per-datasource credential / proxy mTLS). Production requires the
  secret at startup; its admin-equivalent scope is the remaining gap
  ([`docs/datasource-registration.md`](./docs/datasource-registration.md)).
- 🟡 Every certificate in the advertised file becomes a `pmon` trust anchor — a
  bundle contaminated with an unrelated CA widens trust instead of failing
  closed (refusing at registration would mean no datasource, no catalog, total
  outage). Publish only the certificates the proxy actually presents; narrowing
  to the verified path is tracked in [`docs/backlog.md`](./docs/backlog.md).
- 🟡 Certificate expiry is never checked before advertising — the client's error
  is authoritative — so the console can offer a certificate no client will
  accept.

## SQL editor

The web SQL editor executes over the proxy-dialed `RunExec` channel through the
proxy's normal `Decide`; a persistent per-session stream holds one target-DB
connection so `SET`/`USE`/temp/`BEGIN` persist across queries.

- 🟡 No concurrent-editor-session cap (auth'd DoS surface): each session pins
  one unpooled target-DB connection until explicit close or the idle sweep
  (30-min cutoff on a 15-min tick → up to ~45 min), so an authenticated user
  opening many sessions can exhaust the target's `max_connections`. A
  per-principal cap is a follow-up.

---

_Add an entry here whenever a fix ships with an accepted caveat or a deferred
gap, rather than burying it in a design doc. Keep detail/tracking in the linked
docs; this file is the index._
