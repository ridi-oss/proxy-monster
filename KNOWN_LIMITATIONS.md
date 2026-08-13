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
- Okta's groups claim must be configured for refresh-grant id-tokens. A groups
  claim can be present in the initial id-token yet be dropped from refreshed
  id-tokens when its claim filter is configured as Userinfo/id_token request.
  You MUST configure the filter as Always, then empirically verify that
  refreshed id-tokens retain `groups` and reflect current membership. A missing
  `groups` claim on refresh is treated as an empty set (full group removal). The
  `>100` groups distributed-claim pointer behavior belongs to Azure/Entra, not
  Okta: Okta fails the token request instead, and that error is transient — it
  is never interpreted as `invalid_grant` or deactivation.
- A login-vs-sweep race can briefly mint a zero-role (or just-deactivated) web
  session. The OIDC callback resolves the principal's roles and then mints the
  session as two separate steps; if the ≤5-minute liveness sweep reconciles that
  principal to empty groups (or deactivation) in between, the callback can still
  mint a live web session whose effective roles are already gone. This is
  harmless for direct data access and is not fixed by design. Every query and
  wire-protocol path re-resolves roles server-side and re-checks deactivation,
  so a zero-role or deactivated principal DENYs and reads nothing. Self-service
  control-plane actions whose shipped policies do not require a role remain
  reachable: an active zero-role principal may mint its own token, and
  `task.request` permits request creation by default. The token still has no
  effective query access, and deactivated principals cannot mint new tokens. The
  session self-heals at the next sweep (≤5 min) or, at the latest, the absolute
  cap (`PM_WEB_SESSION_ABSOLUTE`, default 2h). Accepted under the
  single-instance topology (the login role check and the sweep are not
  serialized). Detail: [`docs/session-lifetime.md`](./docs/session-lifetime.md).

## Daemon session renewal and revocation

- 🟡 A `pmon` login is not renewed silently. The control plane serves
  `POST /auth/session/renew` and `pmon login` stores the renewal token the
  device-login result returns, but no pmon code path calls that route. A login
  therefore lasts exactly one wire token TTL (`pmon login --ttl`, default 12h,
  clamped server-side to 24h) and then needs a fresh `pmon login`.
  `PM_SESSION_WINDOW` (default 2h) bounds only how long the unused renew route
  would accept a renewal token; raising it cannot extend a live session.
- 🔴 Closing a daemon renewal window does not revoke the wire token issued under
  it. Because the token TTL (12h default) outlives the window (2h default) and
  the wire path validates only `proxy_token`, a definitive IdP rejection during
  the liveness sweep — which for a `DAEMON` row only calls `closeDaemonWindow` —
  leaves that principal's already-issued token authorizing queries until its own
  TTL expires. It is not a full gap: the sweep's group reconciliation runs
  first, so a revocation expressed as group removal (or a missing `groups`
  claim) empties the role set and every subsequent statement DENYs. The exposure
  is a revocation the IdP signals _only_ as `invalid_grant` while local group
  membership still maps to roles. The authoritative deprovision path (SCIM
  `active=false`, local-admin deactivate) has no such gap —
  `revokeActiveCredentialsTx` revokes the wire tokens outright. Detail:
  [`docs/auth-model.md`](./docs/auth-model.md#security-invariants).

## Audit trail

- 🟡 OIDC group reconciliation is not part of the login-audit transaction. On a
  successful login the session mint and its `auth.oidc.login` event commit
  together, but the preceding `provisionFromOidc` — adding and removing local
  group memberships to match the IdP claim — commits on its own connection
  first. It is directory reconciliation, not the login event, so a session mint
  that then fails leaves the reconciled membership in place; the next login
  re-reconciles it. Membership changes are covered by the `admin` config-change
  trail, not the `auth` login event.

## Identifier handling (schema-aware enforcement)

- 🟡 Identifiers containing `.` or `/` cannot be authorized normally. Both are
  legal inside a _quoted_ identifier but are the key/EUID delimiters (analyzer
  keys join on `.`, Cedar EUIDs on `/`), so a component containing one either
  fails identity rendering or is denied during Cedar resource binding.
  Production denies; an explicit `exception.unanalyzable` grant may relay a
  statement whose dotted identity failed before resource facts were emitted.

## Live namespace tracking

PostgreSQL wire decisions resolve against the connection's probed effective
`search_path`. MySQL re-probes `DATABASE()`, the connection character sets, and
`sql_mode` before every statement; prepared execution uses the namespace and
`ANSI_QUOTES` mode captured at prepare time.

The Go PostgreSQL broker (`goproxy/pgproxy`) uses probe-always: it re-probes the
effective `search_path` and the session-temp overlay after every completed
client statement rather than classifying SQL, so a persistent mid-session change
is picked up by the next statement's probe regardless of how it was made, at the
cost of one extra probe round-trip per statement. On the extended-query path,
PostgreSQL resolves and plans a portal under the `search_path` in force at Bind
(plancache re-resolves a named statement whose path changed after Parse), so the
broker captures the namespace and temp overlay immediately before forwarding
each Bind and re-decides every `Execute` against that snapshot — the PostgreSQL
analog of MySQL's Prepare-time freeze. No control-plane decision is ever stored.

- `COM_INIT_DB` audit boundary. The MySQL database switch is enforced (dirty →
  re-probe) but is not audited as a statement because it carries no SQL text;
  the follow-on query's audit records the new effective namespace.
- MySQL result charset is pinned to UTF-8. Masking decodes each result value as
  UTF-8, so `character_set_results` must stay `utf8mb4`/`utf8`/`utf8mb3`; a
  client that moves it elsewhere fails the session closed. The analyzer
  recognizes a single, session-scoped `SET character_set_results = NULL` — the
  default MySQL Connector/J (and so DBeaver) session-init, which requests each
  column in its own charset for client-side decoding — and rewrites it to
  `utf8mb4`, so those clients connect and results stay maskable. The client's
  original statement is authorized and audited; only the bytes sent to the
  target DB are pinned. (A prepared-statement form is pinned too, but its
  execute-time audit records the pinned statement.) Any other results charset —
  an explicit non-UTF-8 one — is not rewritten and fails the session closed, and
  returning results in a non-UTF-8 charset is not supported.
- `DISCARD` routes through the datasource-wide `exception.unanalyzable` gate.
  The production posture denies it; a development datasource may relay it.
- 🟡 First-in-transaction probe injection breaks `SET TRANSACTION` after an
  opener. Because the namespace probes are injected as ordinary simple queries,
  they consume a transaction's first-statement slot. Under probe-always, a
  `SET TRANSACTION …` issued as the first statement after `BEGIN` /
  `START TRANSACTION` (or a `COMMIT AND CHAIN` / `ROLLBACK AND CHAIN` opener)
  hits the injected probe and fails with SQLSTATE 25001
  (`SET TRANSACTION must be called before any query`). Suppressing the probe for
  a "bare opener" would need either SQL classification or a wire-signature guess
  — both rejected (the latter is a fail-open: a stored `CALL` can mimic the
  bare-opener wire signature while moving `search_path`). Strictly fail-safe: an
  extra probe, never a skipped one — no leak; a client that needs a non-default
  isolation level should use `BEGIN ISOLATION LEVEL …` instead of a separate
  `SET TRANSACTION`.
- 🟡 `client_encoding` must remain UTF8. The engine and control plane read the
  client's SQL bytes as UTF-8 to resolve identifiers. A target-DB session that
  switches `client_encoding` to another encoding would let the same bytes bind
  different objects on each side (a non-ASCII identifier could dodge its
  mask/deny — verified against real PostgreSQL). `client_encoding` is
  `GUC_REPORT`, so the change is observed before the next statement runs and the
  relay fails closed; a client that needs a non-UTF8 session encoding is refused
  rather than served with a binding-confusion hole.
- 🟡 `standard_conforming_strings` must remain on. The control-plane admission
  lexer parses string literals assuming standard-conforming strings; with it
  off, PostgreSQL's backslash-escape parsing lets a crafted literal hide a
  statement boundary the lexer cannot see (a multi-statement slip — verified
  against real PostgreSQL). It is `GUC_REPORT`, so a session turning it off is
  observed and the relay fails closed (SQLSTATE `0A000`) rather than proxying
  under a divergent lexer.
- 🟡 A `search_path` change made _inside_ Bind parameter coercion is not tracked
  (extended path). `Bind` runs parameter input/coercion — input functions and
  domain `CHECK`s — before it plans the portal, so a domain whose check calls
  `set_config('search_path', <bound value>, false)` moves the path during
  `Bind`, and the portal resolves under a path the pre-`Bind` namespace probe
  never saw. Only user-defined code can change `search_path` mid-coercion, so
  this is the same accepted case as a data-reading UDF: a domain or function
  with a side effect is user code the operator vouches for, not a boundary the
  proxy enforces. Reproduced against PG16 by
  `pgproxy.TestExtendedBindCoercionSetConfigLeaksAcrossSchema`.

## Catalog freshness

Enforcement decides against a per-connection catalog captured on the
connection's own held target-DB connection (design:
[`docs/per-connection-catalog.md`](./docs/per-connection-catalog.md)) — the
control plane always decides against exactly what that connection's target DB
binds. The datasource-global catalog is now config-only (catalog browser,
tagging, table detail) and never feeds an enforcement decision.

- Enforcement-path residuals (per-connection model; full detail and severities
  in [`docs/per-connection-catalog.md`](./docs/per-connection-catalog.md)): 🔴
  rename/redefinition launders name-keyed classifications (admin's
  responsibility to re-tag); an approval grant not bound to the resolved
  resource; DDL inside a DML-fired trigger unflagged; a bounded external `A→B→A`
  hash/columns revert window; 🟡 MySQL temp-table shadowing (invisible to
  `information_schema`); and, on the experimental PostgreSQL transactional-DDL
  path, held-connection-probe edges. `CALL`/routine after-refetch is
  unreachable: the analyzer classifies `CALL` as an unanalyzable
  `stmt.kind.call`, which the control plane denies before execution, so the
  `after_statement` refetch — which only rides an ALLOW/MASK verdict — never
  fires; a denied `CALL` doesn't run, so not a leak. A closed/forged
  `connection_id` can be resurrected by Decide's restart-recovery (no tombstone
  / mint-evidence to distinguish a closed or forged id from a genuine
  post-restart id; no cross-principal escalation — recovery binds to the
  re-validated token's principal). The one time-bounded residual is external /
  out-of-band DDL — a change made outside the proxy is corrected on the next
  re-check past the staleness bound, not immediately.
- 🟡 Config-catalog PushCatalog ordering across replicas (bounded, self-healing)
  — CONFIG path only. With gRPC self-registration
  ([`docs/datasource-registration.md`](./docs/datasource-registration.md)) each
  proxy replica introspects + PushCatalogs the datasource-global config catalog
  independently; across replicas an older capture can briefly regress the stored
  config catalog (self-heals on the ~12-min ambient re-push + admin Refresh).
  This affects only config surfaces — enforcement is per-connection and
  unaffected. A `db_name` retarget invalidates the config catalog fail-closed;
  an engine change is rejected; host is advisory.
- 🟡 A UDF that reads a masked/PII column _inside its body_ — never as a visible
  argument — returns it in the clear; only _known-dangerous_ functions are
  classified. The control-plane function gate always forbids `system:critical`;
  `system:data-leak` is forbidden on the production posture but relaxed on
  `system:development`. `BaselineDangerousFunctions` supplies a
  version-independent floor; every unclassified function in a FROM-backed query
  — a safe builtin or a user-defined function — passes the function gate.
  Passing a masked/PII column as a visible argument is still caught by the core
  lineage: a transforming projection like `SELECT custom_udf(ssn)` traces `ssn`
  as a derived output, and an arbitrary `custom_udf` is not on the
  provably-total redaction whitelist, so it is DENIED
  ([`docs/derived-masking.md`](./docs/derived-masking.md)) — only a
  provably-total builtin string transform (`upper`/`substr`/`concat`/…) is
  redacted in full (kind NULL); a direct projection `SELECT ssn` is masked with
  the column's kind; a masked column in a row-shaping position
  (predicate/join/order/group/distinct) still DENYs. So none of these paths
  leak. The residual gap is a function body that reads a masked/PII column
  internally, on the target DB service-account connection unseen by the proxy,
  when that column never appears as an argument: `SELECT my_udf(id) FROM t`,
  where `id` is not sensitive and `my_udf` internally reads `ssn`, returns `ssn`
  in the clear. Operational rule: a UDF on a masking datasource must not read
  PII / masked columns — a "pure" UDF that only transforms its arguments (reads
  no data) is safe; keeping a data-reading UDF clean is an admin responsibility.
  Acceptable for the same reason the rename residual above is: creating a
  function is access-controlled `sql.ddl` a restricted principal can't run, so
  functions are admin-authored — a masked principal can't introduce a leaking
  one. Auto-closing it (deny data-reading UDF output unless vouched,
  auto-clearing declared-no-data functions) is out of scope; the concept is
  backlogged low priority ([`docs/backlog.md`](./docs/backlog.md)), to be
  designed when needed.

## Query coverage

- 🟢 sqlglot-go parser gaps route through `exception.unanalyzable`. The
  production posture denies them; an explicit development exception may relay
  them verbatim. Parser coverage includes `JSON_TABLE` / `LATERAL VALUES` /
  `SIMILAR TO`, MySQL `MATCH … AGAINST` / `GROUP_CONCAT(… SEPARATOR …)`, MySQL
  `INSERT … SET` / `REPLACE`, and structural PostgreSQL `EXPLAIN`. The MySQL
  write forms use the ordinary `Insert` shape and are analyzable through the
  proxy's INSERT conservation paths; `REPLACE` still emits an unspecified
  datasource action and is denied. Bare `SELECT *` over a table-function /
  `LATERAL` / `VALUES` source is unresolved and follows the same
  `exception.unanalyzable` gate; that is a masking/lineage limitation, not a
  parse gap.
- 🟡 `RENAME TABLE a TO b` is denied. It is ordinary MySQL table DDL, but
  sqlglot-go leaves it as an unmodeled `Command` node, and classification is
  taken only from what the parser resolves structurally — a `Command` carries
  the verb as text with the remainder unparsed. Matching that verb would also
  match `RENAME USER`, which is privilege management rather than schema DDL, so
  the over-deny is deliberate. The structured equivalent is permitted:
  `ALTER TABLE a RENAME TO b`.
- 🟢 Zero-column table scans require a table grant. A query that names no column
  of a table — `SELECT count(*) FROM t`, `SELECT 1 FROM t`,
  `EXISTS(SELECT 1 FROM t)`, a cross-join side that only multiplies cardinality
  — emits every scanned physical relation as `StatementFacts.sources` from the
  analyzer's resolution report (a shadowed CTE emits nothing; a CTE body that
  reads the real table does) and requires `result.read.unmasked` or
  `result.read.masked` on every uncovered scan (`Authz.authorizeTables`), DENY
  otherwise. Coverage is per table: a table with any traced column fact is
  already exposed through that column, so it needs no separate table grant; only
  a table with zero traced columns and no table grant is denied. Verified on
  PostgreSQL (`KnownGapsTest`) and MySQL (`ScannedTableMySqlTest`).
- 🟡 Whole-database `ANALYZE` forms are gated by statement kind, not per-table
  reads. A table-targeted `ANALYZE TABLE t` (MySQL) / `ANALYZE t` (PostgreSQL)
  carries its target's result-read grant, so a principal who cannot read the
  table cannot ANALYZE it. The forms that name no single table — bare PostgreSQL
  `ANALYZE` (every accessible table), `ANALYZE INDEX`/`DATABASE`/`CLUSTER` —
  carry only the `analyze_table` statement kind, so `stmt.cat.admin.maintenance`
  gates them but no per-table read does. They name no table to probe, so they
  are not a single-table existence oracle; a maintenance-privileged principal
  running one can still surface an unreadable table's name through a forwarded
  target-DB notice (the shared target-DB account, tracked in
  [`docs/backlog.md`](./docs/backlog.md)).

## Authz / policy

- 🟡 An IPv6-literal `PM_MCP_RESOURCE` is reachable only behind a trusted edge.
  The `/mcp` host gate resolves the client-addressed host through Ktor's
  `host()`, which splits a direct `Host: [::1]` at the literal's first colon and
  yields `[` — so the comparison fails and every direct request gets
  `403 mcp.invalid_host`. `X-Forwarded-Host` from a peer in `PM_TRUSTED_PROXIES`
  is parsed by proxy-monster's own bracket-aware path and works. Use a hostname,
  or front the control plane with a trusted edge.
- 🟡 The MCP/workflow channel forbid on session statements covers only the
  benign `stmt.cat.session` kinds. A connection-state-mutating statement
  classified under an admin category — `SET sql_log_bin` (`admin.replication`),
  `SET GLOBAL` (`admin.server`) — relies on that admin gate instead: the
  production floor holds no admin category, so it denies there regardless, but a
  `system:development` admin-holder may issue it on a non-persistent channel,
  where a fresh connection per query discards the session change with no lasting
  effect. The benign session statements the forbid does deny (`SET NAMES`,
  `BEGIN`, `SET @var`) are otherwise ungated, which is why they are the ones
  that need the channel rule.
- 🔴 `system:admin` immutability assumes single-instance, migrate-before-serve.
  The `system:admin` group is immutable through the API and SCIM via runtime
  guards inside `UserGroupStore`, which are in-process: they serialize
  concurrent writers within one control plane, not across a fleet. Flyway's
  migration lock serializes only _migrators_, not live API traffic. Under a
  rolling multi-instance deploy an old instance still serving could interleave a
  SCIM PUT with a future migration that rewrites the system row and re-open the
  admin escalation the guards close. Inert under the current topology (single
  control-plane instance, `Main.kt` migrates before opening the port). Must be
  hardened — fleet-stopped migration or `source`-predicated transactional writes
  on the system row — before enabling any rolling/multi-instance deployment.
  Tracked: [`docs/backlog.md`](./docs/backlog.md).
- 🟡 A saved result is fixed to the executor's masking — a more-trusted viewer
  cannot widen it. A saved workflow result is stored as R's execution-enforced
  output: masked per exactly `{R}` in the executor's context, encrypted at rest.
  Viewing re-decides under `{R}` in the viewer's live context, which can mask a
  column further where that context is more restrictive, but can never reveal a
  column the execution masked — there is no re-widening beyond what was stored.
  So a viewer whose context is _more_ trusted than the executor's (e.g. the
  executor ran off-network, the viewer reads from a 망분리 node) sees the
  executor's masking, not their own potential unmasking: a column the run masked
  stays masked. Choose the execution context deliberately — it sets the widest
  form any later view can show. Detail:
  [`docs/task-execution.md`](./docs/task-execution.md),
  [`docs/authz-context.md`](./docs/authz-context.md).
- 🔴 A saved result's view re-decision is not bound to the execution's namespace
  or physical lineage. `decideResultView` re-analyzes the task's stored SQL
  against the current per-datasource catalog and cross-checks the stored bytes
  against the live verdict only by output-column name equality — it does not pin
  the namespace (search_path / default schema) or the schema-qualified physical
  lineage the execution resolved against. If the schema resolution changes
  between execution and view — an admin re-points the datasource default schema,
  or a migration shadows the table so the same unqualified SQL resolves to a
  different physical column bearing the same output name — the stored cleartext
  bytes (produced for column A) can be released under a mask plan computed for
  column B. Example: `SELECT ssn FROM users` executed with `users` resolving to
  a PII `ssn` in schema A, then viewed after the default schema moves to a
  non-PII `users.ssn` in schema B — the view unmasks (schema B is non-PII), the
  output name `ssn` matches, and schema A's PII is released. The fix is saved
  lineage: persist the execution namespace + physical lineage per result child
  and re-decide pinned to it, so output-name equality stops being the
  confidentiality boundary. Tracked as a high-priority follow-up in
  [`docs/backlog.md`](./docs/backlog.md). Detail:
  [`docs/task-execution.md`](./docs/task-execution.md),
  [`docs/approval-workflow.md`](./docs/approval-workflow.md).
- 🟡 Run-as-approver checks the approver's active status at execute, not the
  requester's (unresolved). An approved query is executed as the approver
  (`run(principal = executor)`, with the approver pinned as the executor by the
  approver=executor gate). So the identity whose deprovision/deactivation status
  governs whether the run proceeds at `/execute` is the approver's, not the
  requester's: a requester who is deprovisioned _after_ their task is approved
  still has that task execute when an active approver runs it. The requester
  remains blocked from viewing the result — `/result` gates the viewer through
  the `isDeactivated` deprovisioning check — so a deprovisioned requester never
  reads the rows; the open question is only whether their already-approved task
  should still _run_ at all. Whether this is a genuine limitation or the
  intended behavior (the approver, not the requester, is accountable for the
  run) is unresolved — flagged here rather than silently decided. Detail:
  [`docs/task-execution.md`](./docs/task-execution.md).
- 🟡 Open presets — curation is load-bearing. Under `system:development` (and
  the permit-by-default system posture), a data-reading system object that the
  shipped `system:` classification _forgets to tag_ is exposed. The curated
  classification must be thorough + version-maintained. Detail:
  [`docs/access-model.md`](./docs/access-model.md).

## System classification (`system:` facts — [`docs/system-classification.md`](./docs/system-classification.md))

The runtime classification core is shipped (bundled manifests → `system:` tag →
the shipped forbids/permit). Two completeness/curation surfaces are deferred —
they refine the "Open presets" caveat above:

- 🟡→🔴 No fail-closed manifest-completeness guard (defense-in-depth). A touched
  system table with no governing manifest gets _no_ `system:` tag — not a hard
  DENY. With only per-resource read grants it stays deny-by-default (🟡,
  fail-safe); but no _unconditional_ forbid closes an un-manifested system
  schema, so a datasource-wide read grant or a `system:development` permit
  _could_ read it (🔴, config-dependent). Deferred —
  [`docs/backlog.md`](./docs/backlog.md).
- 🟡 No per-version golden inventory + release-diff gate. Only the manifests
  (the classification _rules_) ship — there's no committed snapshot of each
  engine version's system objects and no CI diff against the live catalog, so a
  manifest can silently fall behind a new engine minor that adds a dangerous
  object. Deferred — [`docs/backlog.md`](./docs/backlog.md).
- 🟢 The catalog API doesn't surface computed `system:` tags (display gap, not
  enforcement). The shipped `system:` tags are computed on the fly by
  `SystemClassificationService` from the bundled manifests (keyed by the
  datasource's engine version); they are not stored per column.
  `DatasourceStore.catalog` returns `CatalogColumn` with only the user-authored
  `classification` (a `LEFT JOIN` on `column_classification`), so the catalog
  browser shows user tags but never the shipped ones — e.g. it won't show that
  `pg_catalog.pg_authid` is `system:critical` per the manifest, only that it's
  an unclassified column. Enforcement is unaffected (it resolves the tags at
  decision time); this is purely observability/UX. To fix, resolve each
  system-schema column through `SystemClassificationService` when building the
  catalog response and annotate it (tag + `source=shipped` + manifest version).
  Deferred — [`docs/backlog.md`](./docs/backlog.md).

(Not limitations: reserved-`system:`-tag writes are rejected at classification
write time; the loaded manifest set + each datasource's resolved manifest are
logged at boot / proxy catalog-push.)

## Data plane

- 🟡 Unmaskable paths are fail-closed. PostgreSQL `COPY` and function-call
  fast-path have no relay and are always denied. MySQL binary/prepared results
  and PostgreSQL binary-format results cannot be masked; they deny by default,
  but a MASK verdict carrying `unmaskable_permitted` may relay them unmasked
  when `exception.unmaskable` is granted. Detail:
  [`docs/access-model.md`](./docs/access-model.md).
- 🟡 A graceful-shutdown drain can report a pipelined PostgreSQL statement as
  failed. On a rolling redeploy the data plane drains: it stops accepting, lets
  an in-flight statement finish, then hands each idle connection a
  protocol-level shutdown notice (MySQL `ER_SERVER_SHUTDOWN`, PostgreSQL
  `FATAL 57P01`) so the client's pool reconnects onto the replacement task.
  Draining forces the client read deadline, which preempts a read even when the
  next message already sits in the kernel buffer. So a pipelined
  extended-protocol `Execute` whose `CommandComplete` was relayed but whose
  `Sync` had not yet been read is not answered with `ReadyForQuery`: the
  un-synced statement rolls back when the connection closes, and a client seeing
  FATAL reconnects and retries it — but a client that had treated
  `CommandComplete` as commit could believe a rolled-back operation succeeded.
  The window is narrow (the drain must land between relaying `CommandComplete`
  and reading the buffered `Sync`) and PostgreSQL is experimental. MySQL's
  analogue is benign: a command still in the kernel buffer at drain is skipped
  and retried on reconnect, with no completed-then-rolled-back ambiguity. A
  deterministic fix — bounded reads through the pending `Sync` to a transaction
  boundary before the notice — is a follow-up.

## Wire-cert distribution (direct clients and `pmon`)

A proxy with wire TLS advertises the certificate CHAIN a client should trust at
`Register` — PEM, leaf first, plus any intermediates and root. The control plane
stores it on the datasource row, `GET /api/datasources` surfaces it, and
`GET /api/datasources/{id}/wire-cert` serves it as a file for `psql`, `mysql`,
and DataGrip (`sslrootcert` / `--ssl-ca` with `verify-full`). `pmon` uses the
same bytes as the root pool for its upstream hop with the advertised host
checked, so there is one trust mechanism rather than a separate pinning path.
Registration also carries `advertise_wire_tls`, a separate boolean saying
whether the proxy serves TLS at all: `pmon` refuses to send the token to a proxy
that offers no TLS whenever that is set. `pmon` brokers MySQL only, so a
PostgreSQL client verifies with the downloaded file instead.

- 🔴 The advertised chain's root of trust is the `Register` credential, not a
  proxy identity. One system-wide shared secret (`PM_SECRET_TOKEN`)
  authenticates every proxy RPC and `Register` accepts a caller-asserted
  datasource name, so whoever holds that secret can re-register any datasource's
  advertised address and chain, serve a matching cert, and capture that
  datasource's wire tokens. The fix is a datasource-bound registrar identity (a
  per-datasource register credential, proxy mTLS bound to the permitted name, or
  an admin-owned trust record), not a change to how the chain is verified.
  Production startup requires `PM_SECRET_TOKEN` (it is rejected when
  `PM_AUTH_DEBUG` is false), so the gate can no longer be left open by omission;
  the admin-equivalent scope of that one shared secret is the remaining gap.
  Trust boundary:
  [`docs/datasource-registration.md`](./docs/datasource-registration.md).
- 🟡 Every certificate in the advertised file becomes a trust anchor for `pmon`,
  including the leaf: it loads the whole PEM into a Go root pool, and Go trusts
  a certificate found directly in that pool. So a bundle contaminated with an
  unrelated CA widens trust rather than failing closed — anyone able to obtain a
  certificate for the advertised hostname from that CA could impersonate the
  proxy. The control plane inspects the chain at registration and warns when it
  cannot verify a path through it, but by design it stores and serves the
  material anyway: refusing would mean the datasource is never created, so no
  catalog is pushed and every decision fails closed — a total outage in place of
  one client's TLS error. Publish only the certificates the proxy actually
  presents. Narrowing the served file to the verified path is tracked in
  [`docs/backlog.md`](./docs/backlog.md).
- 🟡 Chain verification is not strictly stronger than the leaf pinning it
  replaced. It gains the hostname binding that pinning had to give up
  (`InsecureSkipVerify` disabled the hostname check, so a stolen leaf replayed
  on another host satisfied the pin), but identity widens from one exact leaf to
  any valid certificate for that name under the advertised anchors. For the
  common self-signed case those are the same set.
- 🟡 Certificate expiry is never checked before advertising. An expired leaf is
  published like any other, and the client reports it. This is deliberate — the
  client's error is the authoritative one — but it means the console can offer a
  certificate that no client will accept.
- 🟡 A rotated cert re-advertises on the proxy's next register, not instantly.
  The proxy re-reads the chain at every `Register` — at startup and on each
  Events-stream reconnect resync — and `pmon` re-lists datasources every 30
  seconds. Between a rotation and both sides converging, handshakes fail closed:
  an availability cost, never a leak. A file already downloaded for a direct
  client is invalidated by rotation and has to be downloaded again.

## SQL editor

The web SQL editor executes over the proxy-dialed `RunExec` channel (the
control-plane never dials the target); its query runs through the proxy's normal
`Decide`, same as a native-wire client. The interactive editor drives a
persistent per-session stream (`RunExecService.openSession`/`runOnSession`, the
`editorSessionRoutes` behind `POST /api/editor/sessions`), holding one target-DB
connection so `SET`/`USE`/temp/`BEGIN` persist across queries. The one-shot
`RunExecService.run` (open → one statement → `Close`) backs the approval-execute
path and `POST /api/datasources/{id}/query`, not the interactive editor.

- 🟡 Editor statements decide as `Channel.EDITOR`, so `SESSION` statements
  passthrough-ALLOW. Benign `SET`, `BEGIN`, and `USE` are allowed on the editor
  channel; classified privileged `SET` forms still pass their Utility gate,
  `ANALYZE` is gated by its statement kind and its target's read, and session
  statements stay denied on the workflow executor/viewer channels. Because a
  persistent session holds ONE target-DB connection across MANY statements, a
  session mutation can affect a later query on the same connection; its safety
  rests on per-statement re-decide — every statement round-trips to the proxy's
  `Decide` against that connection's live per-connection catalog, so a mutated
  namespace is re-authorized rather than carried silently, and a multi-statement
  `SET; SELECT` batch is rejected at admission so passthrough only ever sees a
  pure session statement. Hard gate: per-statement re-decide (or an explicit
  session-mutation refusal) must remain the standing mitigation.
- 🟡 Catalog adoption assumes one target DB behind a datasource. On MySQL a new
  connection may start from catalog content the control plane already holds
  rather than measuring the target DB itself, so its first statement decides
  without a round-trip. That is sound because every target-DB session for a
  datasource is opened by one proxy process against one target with one service
  account, which is what makes a catalog scan the same for every connection —
  MySQL temporary tables never appear in `information_schema` and reach a
  decision through the per-request overlay instead. Two changes would break it
  silently: running several proxies for one datasource against target DBs that
  can disagree (a replica behind a load balancer, mid-failover), or varying
  target DB credentials per session, since `information_schema` is
  privilege-filtered and two accounts legitimately see different columns. An
  adopting connection would then decide against structure its own target DB
  never had. PostgreSQL never adopts: its `pg_temp_*` schemas are per-session
  and catalog-visible, so a fragment there is only true for the connection that
  measured it.
- 🟡 No concurrent-editor-session cap (auth'd DoS surface). Each open session
  pins ONE unpooled target-DB connection on the proxy for the life of its run
  stream. That stream has no fixed lifetime cap — so an active editor is never
  cut mid-session — which means the connection is held until the stream closes:
  by an explicit close, a subsequent failed query, or the idle sweep. That sweep
  has two separate numbers: a 30-minute idle cutoff
  (`EDITOR_SESSION_MAX_IDLE_MS`) evaluated by the housekeeping loop on its
  15-minute tick (`RESULT_PURGE_INTERVAL_MS`), so an idle session is reaped up
  to ~45 minutes after its last use; a continuously-used session lives until its
  token TTL. An authenticated user opening many sessions can exhaust the
  target's `max_connections` within that window. Bounded by auth; a
  per-principal / per-datasource cap is a follow-up.
- Ephemeral EDITOR token, TTL-bounded not scope-bounded. The control-plane mints
  an `EDITOR` wire token per session with a generous absolute TTL, revoked on
  idle sweep, explicit close, or cleanup after a failed query. Neither TTL is a
  flat constant: both are floors that grow with `PM_QUERY_TIMEOUT` so a token
  never expires under the statement it authorizes. The editor session token
  requests max(8h, `PM_QUERY_TIMEOUT` + 180s); the one-shot `run` token — the
  approval-execute path and `POST /api/datasources/{id}/query` — requests
  max(900s, `PM_QUERY_TIMEOUT` + 180s), so at the default 600s timeout it is
  900s, the floor. The floor covers a full-length dial plus a full-length
  exchange, so a short `PM_QUERY_TIMEOUT` cannot leave an opening session's
  token expiring mid-statement. `TokenStore.issue` then clamps every request
  into [60s, 24h], which is the real ceiling on both. A run-stream timeout or
  canceled HTTP query does not itself revoke it. It is barred from the
  wire-session handshake (`TokenStore.validate` rejects `kind='EDITOR'`), so a
  leak can't open a native session; within its TTL it could still drive extra
  `Decide` calls, but only over the secret-gated control-plane↔proxy channel.
  Revoked `EDITOR` token rows accumulate with no purge sweep (cosmetic).
- Untested paths (analyzed-correct): run-stream timeout and Ktor cancellation
  leave token cleanup to explicit close, the next failed query, or the idle
  sweep; those cleanup paths are verified by inspection, not dedicated tests
  (the token TTL is the fail-safe).

---

_Add an entry here whenever a fix ships with an accepted caveat or a deferred
gap, rather than burying it in a design doc. Keep detail/tracking in the linked
docs; this file is the index._
