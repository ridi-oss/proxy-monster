# Audit-trail hardening — tamper-evident trail + audit monitor

The audit trail records every audited action. This design makes it
_trustworthy_, _watched_, and _exportable_ in two parts: a tamper-evident hash
chain written on insert, and one control-plane-independent process that verifies
and signs off-box anchors, detects abuse patterns, and exports events to a SIEM.
The integrity design assumes an adversary with database access, so it is
fail-closed throughout.

The baseline it builds on: the `audit_event` table, whose chain columns and
`audit_chain_head` singleton come from
`control-plane/src/main/resources/db/migration/V4__audit.sql`; the record shape
`AuditEvent` (`Decision.kt`); the single write chokepoint `AuditStore.insert`
(`AuditStore.kt`); and the read feed `AuditRoutes.kt` (`GET /api/audit`,
`/api/audit/{id}`), Cedar-gated by `audit.read` (see
[authz-model.md](./authz-model.md)).

## Decision

`audit_event` is the single record of every audited action — not just decisions
but completion, lifecycle, management, and policy-mutation events. All writers
funnel through `AuditStore.insert` (wire/editor via `ConnectionDecide`, approval
lifecycle via `Approvals`, MCP management via `McpServer`, policy mutation via
`CedarPolicyStore`). We harden that one stream.

Tamper-evident trail. Every row joins a hash chain written at insert time: a
gap-free `id`, the `prev_hash` it builds on, and
`row_hash = H(chain_version ‖ id ‖ canonical(row) ‖ prev_hash)`. Hashing happens
app-side in `AuditStore.insert` under a chain-head lock, so the chain and `id`
are allocated in commit order, over a language-agnostic canonical byte format
locked by golden vectors — a Go monitor re-verifies what Kotlin wrote. Narrowing
the app's DB role to INSERT + SELECT on the audit tables (no `UPDATE`/`DELETE`)
is a deployment step, not something a migration does — the control plane writes
as whatever `PM_DB_USER` you give it, which also owns the migrations. And a
keyless chain cannot catch a _complete_ rewrite, so the real guarantee is an
off-box signed anchor the DB-writer cannot erase. Detection plus off-box anchor
is the boundary; DB prevention is depth.

The audit monitor. One control-plane-independent Go process, with its own IAM
principal, reads the committed trail and does three jobs over it:

1. verify + anchor — re-walk the tail from the last WORM anchor and periodically
   sign a new one;
2. detect + alert — config-driven rules (mass export, bulk PII, off-hours,
   repeated DENY/bypass) delivered by webhook plus the WORM/SIEM feed;
3. export — write batched `events/` objects to a WORM object store the SIEM
   ingests via S3 notification-pull.

It polls fast (verify + detect + export) and signs slow (hourly anchor). Only
the monitor holds KMS-sign and bucket access; the control plane holds neither. A
compromised control plane cannot sign anchors, blind the detector, reach the
bucket, or hide a bad pattern without making a hole the same monitor's
chain-walk catches.

## Why this shape

- One stream, one chokepoint. Every writer already goes through
  `AuditStore.insert`, so integrity attaches at one place and covers every event
  kind with no per-writer plumbing.
- Detection over prevention, for a real threat model. "Make the table
  append-only" via DB grants is bypassable (superuser, direct DB access, a
  compromised migration). Tamper-_evidence_ is the goal: you may not stop every
  actor from altering the store, but you must be able to _prove_ it was altered.
  A signed hash chain with an off-box anchor delivers that; DB grants are a
  cheap first wall on top.
- Sign slow, hash fast. Per-row work is a single hash. Signing is amortized to
  periodic anchors, so tamper-evidence costs the write path almost nothing.
- Delegate export to the object store. The monitor writes immutable objects to a
  WORM bucket; the SIEM ingests them with its standard S3 connector. The same
  bucket is both the SIEM feed and the integrity anchor — no per-vendor
  forwarders to maintain.

## Tamper-evident trail

Target: any modification, deletion, or reordering of a historical row is
detectable, and detection cannot be defeated by an actor with DB write who lacks
the signing key. Verification is cheap enough to run continuously and on boot.

Chain columns on `audit_event` (or a sidecar keyed 1:1 by `id`):

- `id BIGINT` — the PK, allocated app-side under the chain-head lock
  (`head.last_id + 1`), not by a `BIGSERIAL` default. Gap-free and monotonic
  with commit order, so it doubles as the export cursor (`id > cursor` cannot
  skip a late-committing row). `prev_hash` provides tamper-evidence; `id` is the
  ordinal and cursor, not a second integrity mechanism.
- `prev_hash BYTEA` — the `row_hash` of the previous appended row. Row 1 uses
  the genesis: `SHA-256("pm-audit-genesis")`, written into `audit_chain_head` by
  the audit migration and compiled into the monitor.
- `row_hash BYTEA` —
  `SHA-256(DOMAIN_SEP ‖ u32be(chain_version) ‖ u64be(id) ‖ fields(event) ‖ prev_hash)`
  with `DOMAIN_SEP = "pm-audit-event"` (`AuditCanonical` / `auditmon/canon`).
- `chain_version INT` — the canonical-format version that produced this row's
  hash, persisted per row (current writers stamp `1`). The verifier reads it to
  pick the field set before recomputing, so a bumped version never falsely flags
  older segments and later refactors can add fields without invalidating old
  segments. Pre-chain historical rows keep these columns NULL and are skipped by
  from-genesis verify.

Canonical format is a cross-language contract. `canonical(row)` is an explicit,
versioned byte serialization (fixed field order; defined encoding of
ints/timestamps/JSON/array columns; separators; domain-sep) — not "whatever the
language serializes." The Kotlin write path and the Go monitor must produce
byte-identical input, so it is locked by a shared golden-vector unit-test suite
run in both Kotlin and Go CI: a byte-level drift fails CI, not production.

App-side serialized append, no trigger. `AuditStore.insert` does the whole link
inside the caller's transaction: `SELECT … FROM audit_chain_head FOR UPDATE`,
read `last_id`/`head_hash`, set `id = last_id + 1` and `prev_hash = head_hash`,
compute `row_hash` (shared canonicaliser), `INSERT`, update `audit_chain_head`.
Doing it in the app rather than a PL/pgSQL trigger keeps only two hash
implementations (Kotlin write, Go verify) byte-identical instead of adding SQL
as a third. Because every writer funnels through `AuditStore.insert`, this
covers all paths, including the same-transaction `insert(conn, rec)` overload,
so the link commits atomically with the audited state change. The `FOR UPDATE`
lock is held to commit, so ids are allocated in commit order, gap-free.

The DB-role narrowing above, where it is applied, stops accidental and
low-privilege tampering but not a superuser, so it is depth, not the boundary —
and on a default install, where the app writes as the migration owner, it is not
in place at all.

The guarantee — and the complete-rewrite defense. A hash chain proves nothing on
its own against an attacker who rewrites _every_ row consistently. The guarantee
comes from binding the chain to storage the DB-writer cannot erase, realized by
the monitor's anchors, in layers:

- Out-of-custody signing forces compromising the _live signing path_, not just
  the DB (KMS/HSM sign is IAM-gated; the private key is unextractable).
  Residual: a compromised running monitor can get a forged head signed during
  the compromise window.
- Write-once off-box witness. Anchors go to an S3-compatible Object-Lock bucket
  in compliance mode (not even the account root can delete before retention)
  under separate IAM. The authentic prefix then survives a full local rewrite; a
  rewrite diverges at the fork `id`. The check is proven, not asserted: a
  previously-witnessed `head_hash` must still be an ancestor of the current
  head.
- Irreducible residual: the unwitnessed tail. Events since the last off-box
  anchor can be rewritten without external contradiction, bounded by anchor
  cadence (hourly anchor → up to an hour), never eliminated.

Failure modes. The link cannot be computed (DB error) → the insert fails → the
decision that depends on being audited fails closed (see
[Cross-cutting: fail-closed](#cross-cutting-fail-closed)). Signing unavailable →
rows still chain (hashes need no key); anchoring pauses and alerts; the unsigned
tail is hash-verifiable but not yet off-box-witnessed until signing resumes.

## The audit monitor

Target: one control-plane-independent process continuously proves the trail
intact, raises actionable alerts on abuse patterns, and lands every event
off-box in a SIEM-ingestable, immutable form — without ever blocking or slowing
a decision, and without the control plane being able to disable, forge, or reach
any of it.

The process. A single Go service, deployed as a separate ECS container / k8s pod
with its own task role / ServiceAccount (IRSA) carrying exactly KMS-sign + WORM
`PutObject` (no delete) + read-only `SELECT` on the audit tables. The control
plane holds none of these. It is the watcher, deliberately outside the watched.

The loop — poll fast, sign slow. Each poll (e.g. every 90 s):

1. Read the last anchor from the WORM bucket; verify its signature. (First run:
   no anchor yet, so the walk starts at the genesis constant.)
2. Read the tail — `audit_event WHERE id > anchor.up_to_id ORDER BY id` (clean
   because `id` is gap-free and commit-ordered) — and re-walk the chain from the
   anchored head, recomputing each `row_hash`. A break raises an integrity
   alert. Incremental, so O(rows/poll), not O(history).
3. Evaluate the anomaly rules over the same rows.
4. Export the new rows as batched `events/` objects to the bucket.

Periodically (e.g. hourly) sign the new head and append a new anchor
`{up_to_id, head_hash, signature, key_id}` to WORM. A fuller `verifyChain` from
genesis runs on boot and on a schedule to catch retroactive edits to
already-anchored rows. No anchor, event, or alert is stored in the DB — the DB
shares the attacker's trust boundary, so a DB copy would prove nothing; WORM is
the sole authority, and the monitor stays read-only on the DB.

### Detection and alerting

Signals come from the audit row (`principal`, `decision`, `datasource`,
`statement`, `masked_columns`, `pii_touched`, `channel`, `ts`, `client_addr`,
`latency_ms`) plus one added signal: result volume.

`pii_touched` holds every **tagged** column a statement touched, whatever those
tags are named — a deployment classifying with `pci` or `confidential` populates
it the same as one using `pii`. The column keeps its original name; renaming it
is pending a migration. The decision event is emitted at decide time
(pre-execution), so it cannot carry a row count. Rather than mutate the
immutable decision row, the data-plane proxy emits a post-execution completion
event — its own append-only, chained `audit_event` (`kind = "completion"`) via
gRPC `ReportCompletion`, referencing the decision `id` as `decision_id`,
carrying `rows_returned` + `bytes_returned` (rows catch "many records," bytes
catch "few wide rows / big blob"), terminal status in `outcome`
(`ok|error|canceled`), and relay wall time in `latency_ms`. The proxy tallies as
it relays. One completion is emitted at statement end, so mass-export is caught
after the rows left, which is fine for alerting (Cedar is the enforcement gate).
DENY → no completion; error/cancel → a completion with `outcome` + partial
counts.

<!-- prettier-ignore -->
| Rule | Fires on | Primary signal |
| --- | --- | --- |
| `mass-export` | rows/bytes over a per-datasource threshold in a window | completion-event volume (degrades to statement shape) |
| `bulk-pii` | count of PII-touching decisions / distinct PII columns over threshold per window | `pii_touched`, `masked_columns` |
| `off-hours` | PII read or any write outside a configured business-hours window | `ts`, `pii_touched`, sql-kind |
| `repeated-deny` | N `DENY`/`ERROR` (or unsafe-construct denials) per principal per window | `decision`, `failed_stage` |

Windowed rules recompute from the durable trail each poll (not from in-memory
counters), so a restart loses no state and nothing is double-counted.
Detect-and-alert only — inline response (block a query, kill a session) is out
of scope; Cedar is the per-query gate. Because the detector _is_ the
chain-verifier, hiding an anomaly requires tampering the monitor also catches:
delete the rows that evidence a mass export and the chain breaks.

Alerts (anomaly and integrity, emitted the same way): out-of-band via webhook
(per-sink routing by severity/rule; timeout + retry-with-backoff) and as
immutable `alerts/` objects in the WORM bucket (tamper-evident + SIEM-ingested).
There is no web-console Alerts surface today — WORM + webhook/SIEM are the
readers. Alerts are deduplicated / rate-limited and non-recursive (an alert
never triggers a rule). If a webhook ultimately fails, the alert is still
durable in WORM — the webhook is a notification, not the system of record.

### SIEM export

The monitor writes batched, immutable `events/` objects (NDJSON / OCSF / CEF,
new key per batch — never overwrite) to the same WORM bucket; the SIEM
subscribes via the standard notification-pull path (S3 event → SNS/SQS → its S3
connector: Splunk, Elastic `aws-s3`, Sentinel, Sumo, Chronicle, Security
Lake/OCSF). One sink, both gates — the SIEM feed and the off-box anchor. The
monitor writes files, so it need not speak any SIEM's wire protocol;
vendor-neutral for self-hosting (MinIO on-prem, GCS retention lock). Object Lock
and ingestion do not conflict: ingestion is a read; the lock only blocks
delete/overwrite; new-key-per-batch is append-only.

- Statement is exported as a hash only. The off-box object carries
  `SHA-256(statement)`, never the text, so a statement literal can never reach
  the permanent WORM/SIEM. The full SQL stays in the in-VPC `audit_event` row
  (behind the `audit.read` Cedar gate) for auditors/requester/approver, and the
  hash is the correlation key an authorized auditor uses to pull the actual
  query from there. Other exported fields carry column _identities_
  (`pii_touched`), not values. Diagnostic text is separately governed by
  [diagnostic-redaction.md](./diagnostic-redaction.md). proxy-monster is a PII
  proxy: do not exfiltrate PII to the SIEM is a first-class constraint.
- Boundary. Our responsibility ends at durable, immutable, redacted objects in
  the bucket. SIEM ingestion is its S3 connector. A push-only / on-prem syslog
  SIEM uses a commodity S3→syslog shipper (Vector, Fluent Bit), not our code.
- Latency to the SIEM is a couple of minutes (poll + S3 notification) — fine,
  because alerting is in-monitor and out-of-band; the SIEM is the correlation /
  system-of-record layer, not the alert path.

### Configuration — non-DB, monitor-owned

Config lives in a file the monitor owns and the control plane cannot write — a
security property, not a preference: config in the DB would let a compromised
control plane raise every threshold to infinity or repoint the webhook to
silence the watcher. Format: YAML via koanf, layered with an `AUDITMON_` env
overlay so secrets never touch the file; `0600`, monitor principal; validate on
load (fail-closed). Hot-reload on file-change is not implemented — restart the
monitor to pick up config changes.

```yaml
monitor:
  poll_interval: 90s # verify + detect + export
  sign_interval: 1h # WORM anchor cadence
  full_verify_interval: 1h
  bucket: audit-worm-example
  endpoint: http://localhost:9000 # optional S3-compatible endpoint (e.g. MinIO)
  db_dsn_env: AUDITMON_DB_DSN
  # exported statement is always SHA-256 (never text); full SQL stays in the DB row
  signer:
    type: filekey # or kms
    key_path: /var/lib/auditmon/signer.key
    # key_id: alias/pm-audit-signer  # when signer.type = kms
rules:
  mass_export:
    window: 10m
    heuristic_max_broad_reads: 50
    default: { rows: 100000 }
    per_datasource:
      example-mysql: { rows: 50000, bytes: 1073741824 }
  bulk_pii:
    window: 5m
    max_pii_decisions: 200
    max_distinct_pii_columns: 20
  off_hours:
    business_hours: "09:00-19:00 Asia/Seoul"
    applies_to: [pii_read, write]
  repeated_deny: { window: 5m, max_deny: 20 }
alerts:
  dedup_window: 15m
  sinks:
    - {
        type: webhook,
        url_env: SECOPS_WEBHOOK_URL,
        min_severity: warn,
        rules: ["*"],
        timeout: 5s,
        max_retries: 3,
      }
    - {
        type: webhook,
        url_env: SLACK_WEBHOOK_URL,
        min_severity: critical,
        format: slack,
      }
```

`url_env` names the env var (from a mounted secret) holding the webhook URL, so
the file is secret-free and gitops-reviewable.

Failure modes. Monitor down → no verify / anchor / detect / export while out,
but decisions and the trail are unaffected (it is read-side); on restart it
resumes from the last WORM anchor and recomputes windows from the trail. A
silently-dead monitor is the real risk, so monitor liveness is itself monitored
(missing heartbeat / anchor grown too old → alert). Missing/late completion
event → mass-export falls back to the heuristic. Webhook outage → the alert
still lands in WORM + SIEM.

## Data model

- `audit_event` is a heterogeneous event log (decision / completion / lifecycle
  / management / auth), discriminated by a `kind` column. `id` is app-allocated
  `BIGINT` (gap-free, lock-ordered, no `BIGSERIAL` default), plus
  `prev_hash BYTEA` and `row_hash BYTEA` (or a sidecar `audit_chain` 1:1 by
  `id`). No separate `seq` — `id` is ordinal and cursor.
- `audit_chain_head(last_id BIGINT, head_hash BYTEA)` — singleton,
  `FOR UPDATE`-serialized append point. Write-path coordination only, not a
  trust anchor — corrupting it just makes the next row chain onto a wrong head,
  a detectable break; verification never trusts it.
- Completion event — an append-only audit event kind (`rows_returned`,
  `bytes_returned`, `decision_id`, `outcome`, `latency_ms`) written after relay
  by the proxy (`ReportCompletion` → same chained `AuditStore.insert`).
- All result-lifecycle events (executed / viewed) are ordinary audit events
  (`kind = approval_lifecycle` for workflow execute/view): `audit.read`-gated,
  chained, and exported like any other kind, marked by `kind`.
- WORM object store (infra, not a table) — one Object-Lock bucket with three
  prefixes: `checkpoints/` (signed anchors, `checkpoints/<up_to_id>.json`),
  `events/` (batched NDJSON audit events the SIEM ingests,
  `events/<firstID>-<lastID>.ndjson`), `alerts/` (immutable alert objects). The
  monitor's export position is derived from the bucket (last `events/` object)
  plus its own local state, no DB cursor. Retention is the bucket's own default
  Object-Lock policy — the monitor sets none per object, so the mode and
  duration are declared where the bucket is.
- DB roles — a runtime role you provision (audit tables: `INSERT, SELECT`)
  distinct from the migration owner. No migration creates or grants it;
  unconfigured, `PM_DB_USER` is both writer and owner.

`AuditStore.insert` stays the single chokepoint and now also links the chain
app-side. The gRPC `Decide` / `ReportCompletion` write contract allocates `id`
and the chain columns in `AuditStore.insert`; the proxy still leaves `id`/`ts`
null on decision records. The read feed (`/api/audit[/{id}]`) and its
`audit.read` Cedar gate are unchanged; chain columns are internal and
verification is the monitor's separate surface.

## Worked example — tamper attempt is detected

```
id   principal  decision  statement                     row_hash(≈)  prev_hash(≈)
101  analyst    MASK      SELECT email FROM users        9af3…        1c02…
102  analyst    ALLOW     SELECT id FROM orders          77b1…        9af3…   ← chains on 101
103  pm-admin   DENY      SELECT ssn FROM users          ee40…        77b1…
      └─ signed anchor in WORM @id 103: sig(ee40…) by key_id=kms-2026-a
```

Attacker with DB write deletes row 102 (it evidenced their bulk read):

- The monitor recomputes id 103's expected `prev_hash` = `row_hash(102)`. Row
  102 is gone, so the actual predecessor (id 101, `row_hash` `9af3…`) fails to
  match 103's stored `prev_hash` `77b1…` → divergence at id 103.
- To hide it, the attacker must recompute 103…head and re-sign the anchor, which
  needs the KMS-held `key_id=kms-2026-a` that only the monitor holds. Without
  it, the anchor signature fails.
- Even with a forged key, the local head diverges from the anchor already
  written to the Object-Lock bucket → caught off-box, and the locked copy cannot
  be deleted before its retention expires.

## Cross-cutting: fail-closed

- Local audit is synchronous and on the decision path. `ConnectionDecide`
  inserts the decision record as part of serving the `Decide` RPC; a failed
  insert (including a failed chain link) surfaces as an RPC error, and the proxy
  treats a decision it cannot obtain as DENY/ERROR. So "the trail could not be
  written" can never mean "the query ran unlogged."
- The monitor is async and best-effort-_durable_. It must never fail-close a
  decision (that would couple query availability to the monitor / SIEM), but it
  must never silently drop either — the DB is the durable buffer, the monitor
  resumes from the last anchor, and liveness is alerted. The local chained trail
  plus the off-box signed anchor remain the boundary of record.
