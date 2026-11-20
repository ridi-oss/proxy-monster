# auditmon — the audit monitor

`auditmon` is a standalone Go module: a control-plane-independent process that
reads the committed audit trail read-only, re-verifies its tamper-evident hash
chain, exports redacted event batches to a WORM object store the SIEM ingests,
and periodically signs an off-box anchor. It is the _watcher_, deliberately
separate from the _watched_ — a compromised control plane can neither sign
anchors, blind the monitor, nor reach the bucket.

It is a separate module (its own `go.mod`, importing no other in-repo module).
The one cross-language coupling is the canonical byte format: `canon`
re-implements what the Kotlin control plane writes, and `canon`'s golden-replay
test asserts the _same_ fixture bytes the Kotlin CI asserts
(`control-plane/src/test/resources/atrail/canonical-golden.json`). If that test
passes, Kotlin-write and Go-verify agree byte-for-byte.

## Packages

<!-- prettier-ignore -->
| Package | Responsibility |
| --- | --- |
| `canon` | The canonical serializer + row-hash, frozen by the golden-vector suite. |
| `store` | Read-only pgx reader over `audit_event` / `audit_chain_head`. |
| `verify` | Re-walks the chain and reports the first divergence. |
| `sign` | `Signer` with a dev filekey (ed25519) and a prod AWS KMS impl. |
| `worm` | `ObjectStore` (S3/MinIO + in-memory fake), signed anchors, and the hashed-event export encoder. |
| `config` | koanf YAML + env overlay, validated on load. |
| `detect` | The config-driven anomaly rules (mass_export, bulk_pii, off_hours, repeated_deny). |
| `alert` | Out-of-band alert delivery: WORM `alerts/` object first, then routed webhook POSTs. |
| `monitor` | The poll → verify → export → sign loop plus a full re-verification (boot + interval), with the `Detector` and `IntegrityReporter` hooks wired to `detect`/`alert`. |
| `cmd/auditmon` | The daemon entrypoint, plus the `verify` / `accept-break` operator commands. |

The monitor verifies at two cadences: a fast incremental **tail** walk each poll
(rows past the last anchor), and a full **from-genesis** re-verification on boot
and on `full_verify_interval` that re-walks every chained row and cross-checks
the recomputed head at the newest valid signed anchor against the head that
anchor witnessed. The full pass is what catches a rewrite of a row at or below
an already-anchored head — including an internally-consistent rewrite from the
public genesis, which only the off-box signed anchor contradicts. A full-pass
finding halts export and signing so the monitor never witnesses a chain it has
proven tampered. See [When the chain breaks](#when-the-chain-breaks) for what an
operator does next.

Each row's hash covers the row before it, so the newest valid anchor witnesses
every row at or below it: one anchor is enough to catch a rewrite or a
truncation anywhere beneath it. The full pass therefore checks that anchor, any
invalid anchors above it, and the anchors a signed acceptance names. Only when
it finds a divergence does it check every anchor, to report the lowest anchor
the rewrite reaches and to honor every acceptance; if that second check fails,
the pass reports what the first one found. An invalid object at an older anchor
key does not keep a halt latched; one above the newest valid anchor still does.

Each poll reuses the signature verdicts the process already holds, so it reads
and verifies only anchors it has not seen. The full pass asks the signer about
the anchors it checks and every acceptance again. A key that is disabled, or
dropped from `allowed_key_ids` and restarted, therefore stops vouching for its
anchors within one `full_verify_interval`, not on the next poll.

Exported events carry `SHA-256(statement)` only — never the SQL text — so a
statement literal can never reach the permanent WORM/SIEM store; the full SQL
stays in the in-VPC `audit_event` row behind the `audit.read` gate, and the hash
is the correlation key.

## When the chain breaks

A break means the trail no longer matches what the monitor witnessed. The
monitor **halts**: it stops exporting to the SIEM and stops signing anchors, so
it can never lend its signature to a chain it has proven tampered. It keeps
running and it never blocks a query — enforcement is unaffected, only the audit
guarantee is. A `critical` alert with rule `integrity` lands in the WORM
`alerts/` prefix, and the log says which row diverged and why.

Recovery is a human decision, made on this host. There is deliberately **no API
and no console button**: the monitor watches a system it does not trust, so if
the control plane could resume it, a compromised control plane could tamper with
the trail and then silence the monitor that noticed.

**1. Find out what happened.** Read-only, safe to repeat, changes nothing — it
does not write, sign, or alert, and it will not create a signing key (a missing
one means the wrong `key_path`, so it errors instead):

```
auditmon verify -config /etc/auditmon/auditmon.yaml
```

It names the divergent row id and the reason, and exits non-zero on a break:

<!-- prettier-ignore -->
| Reason | What it means |
| --- | --- |
| `row_hash_mismatch` | a row's content no longer matches its own hash — that row was edited in place |
| `prev_hash_mismatch` | a row's link to its predecessor is broken — rows were deleted, reordered, or inserted |
| `anchor_row_missing` | a signed anchor witnessed rows the trail no longer reaches — rows were deleted or truncated |
| `anchor_head_mismatch` | the chain recomputes cleanly but disagrees with a signed anchor — the trail was rewritten wholesale, and the off-box signature is what proves it |
| `missing_chain_version` | a chained row carries no `chain_version` — a pre-chain row appears after an anchored head |
| `anchor_signature_invalid` | no signed anchor validates — with no usable witness the trail cannot be judged intact, because a rewritten chain verifies clean on its own |
| `anchor_verify_error` | an anchor's signature could not be checked at all (signer or store failure) — evidence is incomplete, so a halted monitor stays halted |

**2. Decide whether it is an incident.** The monitor cannot tell an attack from
a restore-from-backup or a test harness rewriting the chain; a human has to.
Treat it as an incident until something explains it — a DB restore, a migration
that rewrote rows, or a test pointed at the wrong database. The divergent id
tells you _where_ in the timeline to look, and the rows around it are still
readable.

**3. Restore, or accept the break.** Nothing repairs a chain: the hashes that
diverged are diverged.

- _Restore_ the trail from a backup taken before the divergence, if you have one
  and it matters. The monitor re-verifies on its next full pass and resumes once
  that pass finds nothing unaccepted.
- _Accept_ the break, when the cause is understood or the history is not
  recoverable:

  ```
  auditmon accept-break -config /etc/auditmon/auditmon.yaml
  ```

  This records a **signed acceptance** of that one divergence off-box, exports
  the rows that arrived while the monitor was halted, and signs a fresh anchor.
  It does not undo anything: the tampered rows stay tampered, the `integrity`
  alert stays in the bucket, and the acceptance itself is a permanent record of
  the decision. What it buys back is forward coverage — a halted monitor
  witnesses nothing, so leaving it halted means an incident that began with
  tampering is followed by an unmonitored window, which is worse.

  Because the acceptance lives in the object store rather than in one process's
  memory, a **running monitor resumes on its own next full verification** — no
  restart needed, and the operator command does not have to be the daemon.

  An acceptance is scoped to the exact bytes that diverged, so it waives that
  one divergence and nothing else. A later edit to the same row produces
  different bytes, is not covered, and halts the monitor again — including an
  edit to the _contents_ of a row whose broken link was accepted, and a deeper
  truncation after a shallower one was accepted. Verification also continues
  _past_ an accepted divergence, so tampering above it is still caught.

  One exception, and it is a real limitation rather than a caveat: accepting an
  `anchor_head_mismatch` — a wholesale rewrite from genesis ending at the same
  head id — clears the halt but does **not** restore forward coverage. The tail
  is still measured against the head the signed anchor witnessed, which the
  rewritten chain does not link to, so the monitor verifies and exports nothing
  further while reporting itself un-halted. A rewrite of that kind needs a
  deliberate re-baseline, not an acceptance; treat a cleared halt with a static
  export feed as unresolved.

  **`auditmon verify` keeps reporting the divergence afterwards, and that is
  intended.** Verification always re-walks from genesis, so a break that
  happened stays visible forever — it is reported as _accepted_ rather than as
  an outstanding break. Accepting it resumes monitoring; it does not make the
  history look clean.

**Restarting the process is not a recovery step.** A restart clears the
in-memory halt, but the boot-time full verification immediately re-derives the
same finding from the same on-disk evidence and halts again. Anything that looks
like "restarting fixed it" means the underlying divergence is gone, not that it
was resolved.

Only the signing key can waive a break: an acceptance object whose signature
does not validate under a configured key is ignored and logged. Anyone able to
write the bucket cannot silence the monitor by forging one.

**An acceptance signed by an older build can stop validating.** The signature
covers a digest over the divergence fields, so changing that construction
invalidates every record written before the change. The monitor then logs
`ignoring an acceptance whose signature does not validate` for each one, on
every full pass. That is fail-closed and safe — a waiver that cannot be verified
is not honored — but note what it looks like to an operator: a stale record and
a forged one produce the identical line, and the records carry no version field
to tell them apart. If the underlying divergence is gone (the trail was
restored), the leftovers are inert and the noise is the only cost. If it is not,
that break is unwaived again and the monitor halts until someone re-runs
`accept-break` under the current build. There is no migration path for in-flight
acceptances.

## Tests

From the repo root — the root `go.work` makes every Go command here
root-relative, so no `cd` is needed:

```sh
go test ./auditmon/...
```

DB-backed tests (`store`, `verify`, `detect`, `monitor`) use Testcontainers and
require Docker — they fail (not skip) if no Docker provider is available. Each
test carves out a fresh database in one reused Postgres 16 container. The `worm`
logic is covered against the in-memory fake; there is no real-S3/MinIO
round-trip test.

## Dev run

Config file (`auditmon.yaml`) — secret-free; the DB DSN is referenced by env-var
name:

```yaml
monitor:
  poll_interval: 90s # verify (tail) + detect + export
  sign_interval: 1h # WORM anchor cadence
  full_verify_interval: 1h # from-genesis re-verify + anchor cross-check (also on boot)
  bucket: audit-worm-example
  endpoint: http://localhost:9000 # MinIO for local dev (path-style)
  db_dsn_env: AUDITMON_DB_DSN # names the env var holding the read-only DSN
  signer:
    type: filekey # dev: ed25519 key on disk (0600, generated if absent)
    key_path: ./auditmon-signer.key
    # key_id: alias/pm-audit-signer  # kms only: the active signing key
    # allowed_key_ids: []            # kms only: prior keys still trusted for verifying old anchors (rotation)
# rules: / alerts: — anomaly thresholds and webhook sinks (see config/testdata/monitor.yaml).
```

Also from the repo root, with the config path pointing at wherever you keep the
file:

```sh
export AUDITMON_DB_DSN='postgres://audit_reader:...@localhost:5432/pm?sslmode=disable'
# MinIO (dev WORM): the AWS SDK reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION from the env.
go run ./auditmon/cmd/auditmon --config ./auditmon/auditmon.yaml
```

A deployment usually holds the connection details as separate values already, so
it can pass them as separate values instead of composing a DSN:

```sh
export AUDITMON_DB_HOST=db.internal
export AUDITMON_DB_PORT=5432          # optional, defaults to 5432
export AUDITMON_DB_NAME=proxymonster
export AUDITMON_DB_USER=pmadmin
export AUDITMON_DB_PASSWORD=...
export AUDITMON_DB_SSLMODE=require    # optional, defaults to require
```

Only the password is a secret, so only the password needs secret plumbing; the
rest are ordinary configuration. The password is percent-encoded when the DSN is
built, so characters like `@` and `/` are safe. `sslmode` defaults to `require`
rather than pgx's `prefer` — a monitor reading an audit trail across a network
should not have to be told to encrypt.

A whole DSN in `AUDITMON_DB_DSN` still wins when set, which is the convenient
form for a local run.

A fixed set of `AUDITMON_MONITOR_*` variables overrides the file — the explicit
`envKeyMap` in [`config/config.go`](./config/config.go), covering the
`monitor.*` keys plus `signer.type` / `signer.key_path` / `signer.key_id`. For
example `AUDITMON_MONITOR_POLL_INTERVAL=30s` overrides `poll_interval`.
Everything else is file-only: keys under `rules:` and `alerts:`, and
`signer.allowed_key_ids`. An unmapped `AUDITMON_` variable is ignored silently,
so set those in the YAML.

For production, set `signer.type: kms` with `key_id: alias/<your-signing-key>`
and give the monitor an IAM principal holding exactly KMS-sign + WORM
`PutObject` (no delete) + read-only `SELECT` on the audit tables.

## Open questions

- Signing algorithm. The KMS signer uses `ECDSA_SHA_256` over the 32-byte head
  digest (`MessageType: DIGEST`). Confirm against the provisioned key spec.
- `chain_version` NULL in the tail. Greenfield rows all carry a non-null
  `chain_version`; a NULL in the verified tail is treated as an anomaly
  (`missing_chain_version`), not silently skipped.
