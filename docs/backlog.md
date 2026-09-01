# Roadmap

Planned and deferred work, grouped by theme. Accepted caveats and the gaps their
fixes close are described in
[`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md); this file names the
forward work. MySQL leads PostgreSQL in priority.

## Deployment & operations

- Explicit production mode: refuse startup when any debug bypass
  (`PM_AUTH_DEBUG`, a committed session-secret fallback) is enabled, instead of
  inferring production from a heuristic.
- Per-datasource authorization for posture. A proxy's `Register` currently
  overwrites a datasource's tags gated only by the shared proxy token; gate
  posture mutation behind admin authz, and forbid `Register` from overwriting an
  existing datasource's posture.
- Multi-instance support. The system runs single-instance today. Before any
  rolling or multi-replica deploy: harden the `system:admin` bootstrap against a
  migrate-while-serving interleave (fleet-stopped migration, or
  source-predicated writes on the system row), replace the in-process
  task/approval completion hub with Postgres `LISTEN`/`NOTIFY`, and resolve
  config-catalog PushCatalog ordering across replicas.

## Authentication & identity

- Local id/password login: password hashing and storage, a login endpoint, a web
  login form, and session issuance (the only auth paths today are OIDC web and
  device-auth).
- Break-glass local admin (`PM_BOOTSTRAP_ADMIN_EMAIL`): for orgs without OIDC,
  seed a local admin with a generated password at boot. Depends on local login.
- Mixed-source group membership: record a per-membership source so OIDC login
  sync reconciles only OIDC-sourced rows and stops removing SCIM or
  manually-assigned memberships.
- SCIM group create races a concurrent delete. `upsertScimGroup` resolves an
  existing group id, then locks and updates that row; if a `DELETE` removes it
  in between, the update matches nothing and the follow-up read dereferences a
  group that is gone, so the request fails with a 500. Fall through to an insert
  (a true upsert) or return a clean 404/409. Availability, not authorization.
- MySQL `caching_sha2_password` target-DB auth. PostgreSQL SCRAM-SHA-256 is
  done; the MySQL service user still uses `mysql_native_password`.
- pmon HTTP API auth: today the CLI presents its wire token as a bearer to the
  read-only datasource discovery routes only. Make it a first-class client —
  either an OAuth bearer client of its own, or a reuse of the web session — so
  the whole API is reachable under one authentication model.
- Headless token mint for CI: every `pmon` login goes through the browser device
  flow, so an unattended runner has no non-interactive path. A
  client-credentials grant or a pre-issued personal access token would cover it;
  the console Tokens page is the one-shot workaround meanwhile.
- Device-login hardening: fold the approved-code consume and the token mint into
  one transaction (a crash between them strands the login with no credential, so
  the user must log in again); carry the console session's refresh token onto a
  session-reuse device approval so the daemon session revalidates IdP liveness
  on its own; show device and context details on the confirm page behind an
  explicit "this is my terminal" step; and rate-limit both unauthenticated login
  starts and user-code attempts.

## Authorization & network conditions

- Tailscale-attested network conditions: replace `requester_ip` CIDR matching
  with a `tailscale_caps` (whois/ACL capability) input, and migrate the
  `trusted-network` tag rule from IP range to capability. Needs a Tailscale
  plumbing and key-custody design.
- Disable-and-log an invalid enabled Cedar policy at boot rather than
  hard-failing startup — an invalid policy grants nothing, and a hard fail also
  takes down the policy UI needed to fix it.
- Audit `context_tags` on the deny and passthrough paths. A decision records its
  derived context tags on ALLOW and MASK; the deny and passthrough helpers carry
  the channel but not the tags, so an audit reader cannot see which tag rules
  were in force for a refusal. No practical effect until a tag rule ships, since
  the set is empty everywhere until then.
- Reconcile the channel an approval execution audits. The enforced-query path
  and the task lifecycle each write a decision row for one execution and stamp
  different channels, so the audit shows one run under two channels.
- Scope the system-catalog read permit away from PII. The system-object floor
  permits unmasked result reads on any `system:catalog` resource, and unmasked
  is checked before masked, so a column that is both under a `system:catalog`
  table and tagged `pii` would read cleartext. Safe only because the shipped
  manifests classify value-bearing system tables as data-leak or critical rather
  than catalog; add a `pii` exclusion for defense in depth.
- Split the `exception.unanalyzable` relay by admitted statement kind. On a
  development datasource the relay is role-agnostic, so a read-only role can
  submit a data-modifying CTE that admission classifies as a select, and the
  relay executes the write. Scope the permit to a role that legitimately writes,
  or decide the relay per statement kind. Bites only on a development posture,
  which carries no PII by definition.
- Regression guards for stored-tag type scoping. A hand-written posture tag on a
  column is proven stripped; there is no equivalent adversarial test for a
  stored tag on a table or a function. Not reachable today — neither takes a
  direct stored-tag input — but a marshalling change could regress it silently.

## Approval automation

- Broaden predicate-literal detection past direct comparison. A value also
  reaches a predicate through a function, a `CASE`, a subquery, or a bound
  parameter, and none of those are reported today. The consumer already fails
  toward hiding, so each addition narrows over-hiding rather than closing a
  leak.
- Per-user notification opt-out. Language is stored per user
  (`app_user.locale`); a mute switch is the same shape.
- Email as a second notification transport. The seam exists
  ([notifications.md](./notifications.md)); it needs an SMTP adapter and a
  message renderer, and it does not support editing a message in place.
- Auto mode (stretch): release a narrow set of deny reasons without a human
  approver. Two questions decide whether it is safe — which deny reasons are
  ever eligible for auto-release, and whether the reasoning input is the AST and
  lineage only. Feeding raw query text to a model is the riskier choice, because
  literals in the statement can themselves carry sensitive values.

## Task execution

- Retry a task whose execution never reached the target DB. A definite refusal
  marks the task failed, which is correct, but a transient pre-dial transport
  failure does the same and permanently burns the approval, forcing a fresh
  request and approval. Add a retry affordance, or restore the approved state on
  the path where provably nothing was dialed.
- Link each audited decision to its task. A decision records the request and
  principal context but carries no foreign key to the task, so the audit cannot
  be read task-first. Add the column and populate it when auditing a task's
  decisions.
- Stop stamping a creation time as an execution time. The result child's
  `executed_at` is nullable but still defaults to the row's creation, so a
  never-run child looks executed; the authoritative "not run" signal is a null
  status. Drop the default so the column reads as "when it ran".
- Tighten the completion stream's authorization to a per-event context. Each
  pushed event is filtered through the live read gate and the web session is
  re-checked, but that decision reuses the connect-time context and a revoked
  session is caught on the next event or the periodic re-check, so one further
  notification can land. The payload is bounded metadata only, and the data path
  stays gated.
- Precompute a task's decision at approval time and skip the run-time round-trip
  while the connection's catalog is unchanged. Deliberately not the base design,
  which always round-trips for one enforcement path with no stored plan and no
  staleness. Worth building only if round-trip latency becomes a bottleneck, and
  it buys that at the cost of two decision paths plus a reliable drift trigger.
- Finish the task-execution console details: backfill the stored column list for
  results migrated from the pre-task schema (the view works from the stored
  payload; only the preview's column header is empty), localize the run-status
  label instead of rendering the raw enum, and surface a forbidden response on
  the result fetch rather than swallowing it.

## Audit trail

- Decide whether machine-driven SCIM re-syncs should suppress no-op audit
  events. The console admin paths record only when a mutation actually changed a
  row; the SCIM handlers instead record one `kind="admin"` event per
  provisioning directive, so an idempotent IdP re-`POST`/`PUT` or an
  activate-already-active still writes an event. Matching the console would need
  field-diff detection in the SCIM upsert/replace path (the store returns the
  row, not a changed/unchanged verdict). Audit-every-directive is kept for now —
  an IdP-sourced directive is itself an auditable action — but at high re-sync
  volume it inflates the trail.
- Decide where an acceptance record belongs. Recovery honors signed acceptance
  records under the write-once bucket, which is what lets a separate operator
  process resume a running monitor — but it also makes an object in the bucket
  govern whether the monitor halts, turning bucket-write from "forge a witness"
  into a halt-suppression lever. Signature verification is the mitigation: an
  acceptance that does not validate under a configured key is ignored and
  logged. The alternative is the monitor-owned state directory beside the
  signing key, the same trust domain deliberately kept out of the database so
  the control plane cannot reach it. Either way the monitor still needs a
  durable path a separate process can write.
- Sign acceptances with their own key. Acceptances share the anchor key, so
  anything able to sign an anchor can waive a finding, and the allowlist kept
  for verifying anchors across a rotation means a retired key validates
  acceptances forever. A distinct key with its own allowlist — ideally
  human-held or offline — separates witnessing the trail from waiving a finding.
- Bind an acceptance to its install. The acceptance digest covers the divergence
  but not the deployment, so a staging acceptance would validate in production
  if the two ever share a key. Mixing in the per-install genesis seed scopes it.
- Version the acceptance digest. The signature covers a digest over the
  divergence fields, so changing that construction invalidates every record an
  earlier build wrote. That fails closed, but a stale record and a forged one
  log the same line, so an operator cannot tell "signed before the format
  changed" from "planted". A digest-version field makes the difference legible
  and allows a deliberate re-sign path.
- Give anchors a content-addressed, version-aware identity. One object per
  checkpoint forces a choice between overwriting a witness and refusing to
  write; the write refuses, which is the safe half, but a conflicting or
  unreadable object at a checkpoint key wedges signing at that point until a
  human clears it. Anchor reads also see only current object versions, so a
  retained prior version is evidence no code path can reach. Content-addressed
  keys plus version enumeration make every historical witness independently
  readable and remove the collision.
- Restore forward coverage after accepting a consistent rewrite. The acceptance
  is honored and the halt clears, but the incremental baseline stays floored at
  the head the old anchor witnessed, which the rewritten chain does not link to
  — so the monitor verifies and exports nothing while reporting itself healthy.
  Every other break class recovers. The fix is to re-baseline onto the accepted
  resume head, which needs the anchor identity above so the old witness survives
  beside the new one.
- Make the anchor write atomic. It reads and then writes with no conditional
  put, so two writers could both observe an absent key. Unreachable on a single
  instance, and the object-store interface has no compare-and-swap to express it
  — closing it properly means adding a conditional-create operation rather than
  widening the read-then-write.
- Persist the export watermark. It is in-memory, so a restart re-exports from
  the last anchor (the SIEM deduplicates by id) and a per-event rule can
  re-alert once across a restart.
- Distinguish verify's failure kinds by exit status. An integrity break and a
  database, storage, or configuration failure both exit non-zero, so automation
  has to parse logs to tell "the trail is broken" from "I could not check".

## Enforcement completeness

Fixes for gaps documented in
[`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md):

- Bind a saved result's view to the execution's namespace and physical lineage
  (saved lineage), so an output-name match can no longer release stored
  cleartext under a mask plan computed for a different physical column. High
  priority.
- Fail-closed manifest-completeness guard: deny a touched system schema that has
  no governing manifest, plus a version-independent system-table floor (the
  analog of the dangerous-function floor), so completeness doesn't depend on
  grant hygiene.
- Per-engine-version golden inventory of system objects plus a CI release-diff
  gate, so a manifest can't silently fall behind a new engine minor.
- Canonicalize introspected schema names on the proxy side (case-fold-aware),
  removing the interim MySQL lowercase fold in the control plane.
- Broker a per-user target DB login so `SET PASSWORD` / `SET GLOBAL` stop
  mutating a shared service account.
- UDF-output vouching: gate a data-reading UDF's output on a masking datasource
  behind an admin assertion, auto-clearing declared-pure functions (low
  priority).
- Surface computed `system:` tags in the catalog browser (display only).
- Clear the config catalog and re-introspect when a datasource's identity
  changes through the admin API. A retarget of the target database invalidates
  it; other updates leave a stale catalog behind the config surfaces.
- Tombstone a closed `connection_id` and require mint evidence. A closed or
  forged connection id is indistinguishable from a genuine post-restart id, so
  the decide path re-establishes it as restart recovery. No cross-principal
  escalation — recovery binds to the re-validated token's principal.
- Bind a catalog refetch to the command that requested it. The pending mark
  matches any outstanding refetch for a schema rather than the specific command,
  and the full-push arm skips the expected-hash check, so a duplicated push
  could satisfy a newer refetch. Unreachable today because nothing re-sends a
  push; it becomes a live wrong-allow the moment a push retry, gRPC retries, or
  any re-send is introduced, so the nonce lands with that change.
- Make `CALL` a first-class admittable statement kind, or drop the routine
  refetch flag it feeds. Admission classifies `CALL` as an unrecognized kind and
  denies it, and the refetch only rides an allow or mask verdict, so the flag
  never fires. A denied `CALL` does not run, so this is dead weight rather than
  a gap.
- Prune bound portals at transaction end. PostgreSQL destroys a non-holdable
  portal when its transaction ends; the proxy prunes only on an explicit close
  or a name reuse, so a long-lived connection cycling unique portal names grows
  proxy memory. There is no data path — a stale entry re-decides and then hits
  the target DB's own error. Clearing on transaction end needs either SQL
  classification in the proxy, which the stateless-relay contract forbids, or it
  breaks `WITH HOLD` cursors.
- Validate that the extended protocol's temp-table overlay comes from the
  bind-time snapshot rather than the live one. The namespace capture at bind is
  covered; the temp overlay mirrors it structurally with no dedicated
  regression.
- Full-stack end-to-end coverage of the proxy against a real control plane. Both
  sides are covered at component level — the Go proxy suites drive real engines
  against a fake control plane, and the control-plane suites drive real Cedar
  and metadata against real engines — leaving the cross-language glue: launch
  the proxy binary against a real control-plane gRPC server and drive a native
  client through it. This adds integration confidence, not a missing enforcement
  assertion.
- Backfill DB-backed regression tests for enforcement invariants whose code is
  confirmed correct but only covered indirectly: the editor's refusal of
  session-mutating and transaction-control statements, the editor's fail-closed
  mask bind, and the approval route's conflict and not-found cases. Also: that a
  deny under the approval role stores no result, and that a group-member
  approver lacking a role-scoped approve permission is refused at execute.
- Diagnostic-redaction corpus probe. A test that builds a corpus from each
  engine's full error-code catalog plus adversarial constraints, conversions,
  functions, and raised errors, replays it against every supported engine
  version on a redacted connection, and asserts no stored value survives in any
  passed-through wire field. Because the strip is fail-closed this bounds the
  residual and catches regressions rather than being what makes the system safe;
  the cost is a live engine-version matrix in CI.
- Provenance deny for temp tables. Deny a read of a temp table whose creation
  lineage touched a masked or denied source. Not needed on any current path —
  the deny on a write referencing a masked source already stops a temp from
  holding data its creator could not read — and becomes required only if a
  connection stateful across principals is ever introduced.
- Emit facts for utility commands and retire the blanket read-only-metadata
  passthrough, so a utility command goes through resource authorization instead
  of a short-circuit. The known-dangerous commands are already emitted and
  locked fail-closed by a coverage test, so this is consolidation rather than a
  security fix.

## Data plane

- Unmaskable-feature relay: a verbatim passthrough for `COPY OUT`, PostgreSQL
  fast-path, and similar features so a trusted datasource can opt in (denied
  today; MySQL and PostgreSQL binary-result relay is built). Each feature is a
  per-protocol implementation gated by a real-client end-to-end test.
- Honor `character_set_results` instead of pinning it to UTF-8. Masking decodes
  each result value as UTF-8, so the proxy requires the result charset to stay
  UTF-8 and rewrites only a single session-scoped
  `SET character_set_results = NULL` (MySQL Connector/J's default) to `utf8mb4`;
  any other non-UTF-8 results charset fails the session closed. To let a client
  receive results in each column's own charset — or `NULL` for raw per-column
  bytes — make the row masker charset-aware: decode each value by its column's
  result charset from the field metadata, mask, and re-encode, and only then
  relax the UTF-8 session invariant. See KNOWN_LIMITATIONS.md (Live namespace
  tracking).
- Re-probe the session invariants before every `COM_STMT_EXECUTE`. The prepared
  path authorizes against the prepare-time namespace/`ANSI_QUOTES` snapshot (by
  design) but never runs the live charset/`sql_mode` probe that `COM_QUERY`
  runs, so a client that first defeats `SESSION_TRACK` and then flips to an
  unsafe charset/`sql_mode` can run an already-prepared statement past the
  invariant. Not a cleartext leak today — a binary-protocol `MASK` is refused
  and MySQL does not accept a prepared generic `SET` — but the fail-closed
  invariant should hold on this path too: live-probe before EXECUTE for the
  invariant check while keeping the frozen snapshot for authorization.
- Proxy-side cancel brokering: issue synthetic `TargetDbKeyData` and broker
  cancels proxy-side, so `CancelRequest` can require TLS without breaking psql's
  Ctrl-C.
- Wire-cert rotation refresh: a rotated proxy leaf cert is only re-advertised on
  the next reconnect resync. Push the new chain on rotation so a verifying
  client is never left with stale trust material.
- PostgreSQL brokering in `pmon`: the daemon fronts MySQL only, so PostgreSQL
  datasources are discovered but skipped and their connection strings are
  rendered without a broker behind them.
- Bound the native-wire relay by `PM_QUERY_TIMEOUT`. The control-plane-driven
  editor and workflow runs honor it; the wire relay passes no execution guard
  and keeps a fixed socket-inactivity cap, so a direct statement through `pmon`
  is not bounded by it. The relay is a streaming passthrough with no discrete
  per-statement execution to guard, so this needs a per-statement watchdog plus
  a target DB cancel wired into the relay loop, not a value threaded through.
- Surface a contended daemon lock distinctly. `EnsureDaemon` connects first and
  spawns only on failure, and a daemon that loses the lock exits silently, so
  the caller sees a generic "did not come up" timeout. A caller in a loop
  therefore re-spawns a doomed daemon per attempt with nothing self-limiting.
  Have the losing daemon exit with a status the start path reports as "another
  daemon holds the lock", add a short spawn backoff, and let a test override the
  state directory so test daemons cannot contend with a real one.
- Push-based datasource discovery for `pmon`. Rediscovery polls every 30
  seconds, so a revoked datasource keeps its broker open for up to that long. A
  per-principal stream would cut revocation latency to sub-second and carry a
  rotated certificate chain; the poll stays the authoritative backstop, since a
  dropped stream must never read as "no change". Waits on the pmon API
  authentication decision — the existing event stream is cookie-authenticated
  and `pmon` holds no cookie.
- Menu-bar app signing and distribution. The tray app is built and ad-hoc
  signed, which Gatekeeper blocks once downloaded rather than built locally.
  Shipping it needs a Developer ID signature, notarization, and a distribution
  channel. App Store distribution would additionally force the control transport
  off the unix socket, which a sandboxed app cannot reach.
- Localize the `pmon` CLI. Its operator-facing messages are English-only; the
  localization rule targets the console and the server's error codes, so whether
  a developer-facing CLI is in scope, and which Go localization path it would
  use, is an open call.
- MySQL binary / prepared-statement (`COM_STMT_*`) result masking. `COM_STMT_*`
  is decided and relayed, but a binary-protocol result set cannot be masked, so
  a MASK verdict without `exception.unmaskable` fails closed. Masking it means
  decoding the binary row format per column type, applying the mask, and
  re-encoding — including the length-encoding and null-bitmap changes that
  follow from a changed value.

## Management over MCP

- Workflow tools: access requests and grants, query approvals, approve / reject
  / revoke, and result view.
- Query tool: target-database query execution through the proxy enforcement
  path.
- Audit browsing: read tools over the decision feed, preserving the all-vs-own
  split.
- Optimistic concurrency: resource versions and conditional writes across REST
  and MCP, starting with Cedar policies.

## Analyzer & masking

- Reconsider redacting, rather than denying, a masked column used only in
  `GROUP BY` / `DISTINCT`; `DISTINCT` is the more defensible loosening.
- Validate that a bare column's inferred source actually exposes it before
  binding, so the relation resolver stops emitting schema-invalid phantom
  references. The resolver picks the nearest single-source ancestor without
  checking that the source carries the column. Inert today — a phantom is not a
  policy column at evaluation, and the real column is added alongside it.
- Widen the mask-function set. A `mask_fn` kind is a fixed transform today
  (`FIXED`, `LAST_N`, `FORMAT_PRESERVING`, `NULL`), so a classification picks a
  kind rather than parameterizing one. Deciding which further transforms to add
  (a keyed hash, a partial-domain email mask, a date truncation) also decides
  whether a kind stays a fixed transform or takes per-classification parameters.
  Any addition has to land identically in both masking implementations — see
  [Refactoring](#refactoring).
- Content-detection backstop: catch sensitive values in columns no
  classification covers, by inspecting result values rather than the schema.
  Open decisions — whether a detection masks synchronously on the result stream
  or only raises an audit finding; the sampling rate and per-statement latency
  budget a named-entity pass may spend; and which model, if any, can be bundled.

  A bundled model's license is a hard gate, independent of accuracy. It must
  permit commercial use and derivative works, since proxy-monster ships to
  self-hosted commercial installs and fine-tuning is expected. A NonCommercial
  or NoDerivatives license disqualifies a model no matter how well it scores; a
  permissive license such as Apache-2.0 clears the bar. Re-check licenses at
  adoption time and check them separately for the weights, the training data,
  and the inference code: a permissively-licensed library can publish
  restrictively-licensed weights, and a restriction on any of the three is a
  restriction on the whole.

## Refactoring

- Make Go the canonical implementation for logic that lives in both languages,
  and call it from Kotlin over FFM instead of hand-maintaining byte-identical
  copies. Masking is the clearest case: `Masking.kt` and `Masks.kt` under
  `engine/src/main/kotlin/com/ridi/oss/proxymonster/probe/` versus
  `goproxy/engine/masking.go`, which must stay identical by hand. The analyzer
  already reaches Go through an FFM binding, so the same Go implementation could
  serve the JVM side. Medium priority.
- Structural de-duplication: shared route-CRUD helpers, web CRUD tabs, JDBC
  helpers, relative-time formatting, and reject dialogs.
