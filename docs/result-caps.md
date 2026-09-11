# Result caps — per-statement row caps and per-principal volume budgets

Bounds how much result data one principal can pull through the proxy, so a
stolen credential or a scripted dump yields a bounded slice per statement and
per day instead of a whole table. Alerting on volume already exists
(`mass_export` in auditmon); this makes volume an enforcement input.

## Decision (TL;DR)

Two layers, both resolved by the same `Decide` call that authorizes the
statement, both lifted by one Cedar action that is granted only by approval.

**Per-statement cap.** The control plane names _what_ a statement returns, the
proxy owns _how much_. Every non-DENY verdict carries `unbounded` and
`unmasked_tags`: the classification tags whose values this statement returns to
the client in the clear. The proxy resolves them against its own cap table,
`PM_RESULT_CAPS`, counts relayed rows and bytes (it already does, for
completions), and when the cap is crossed it stops relaying, cancels the
statement on the target, and ends the result with an error the client sees as
the terminator. The session, transaction, and temp tables survive.

```sh
PM_RESULT_CAPS=5000/50MB,pii:500/5MB,pci:300
```

| entry         | meaning                                                             |
| ------------- | ------------------------------------------------------------------- |
| `5000/50MB`   | the default: every statement, 5,000 rows or 50 MB                   |
| `pii:500/5MB` | a statement returning a `pii`-tagged value in the clear: 500 / 5 MB |
| `pci:300`     | a `pci`-tagged value in the clear: 300 rows, bytes from the default |

The tightest applicable rows and bytes win, so a statement returning both a
`pii` and a `pci` value gets 300 rows and 5 MB. A masked read is not tightened:
the mask is already what the policy lets that principal see. The default when
unset is `5000/50MB,pii:500/5MB`.

**Per-principal budget.** Rows and bytes actually relayed to a principal are
summed over rolling windows from the audit trail's completion events and passed
to Cedar as context. A connection's next `Decide` waits for its previous
statement's completion report, so a sequential script is charged before its next
statement is authorized (parallel connections can overshoot by up to one
statement cap each, see `KNOWN_LIMITATIONS.md`). Shipped forbids deny a read
once a window is spent:

| window   | rows   | bytes  |
| -------- | ------ | ------ |
| 1 hour   | 10,000 | 100 MB |
| 24 hours | 50,000 | 500 MB |

**Unbounded by approval.** `result.read.unbounded` on the Datasource resource
lifts both. It is decided first; when permitted the verdict carries no cap and
the budget attributes are left out of the context, so the shipped forbids do not
fire. No shipped policy permits it, and it must not be conditioned on network: a
fresh VM inside the VPC satisfies any CIDR rule. It is granted through the
existing JIT `access_grant` (a time-boxed role) or by running the statement as
an approved workflow. A dump script therefore goes: request the role with a
reason, get a time-boxed grant, run over the wire during the window, every
completion audited under the elevated role.

**Stored results re-decide.** A workflow executed unbounded stores up to the run
channel's 5,000-row ceiling; a larger export goes over the wire. The proxy's
whole cap table is frozen with the result. Viewing re-runs `Decide` under the
viewer's context (already the case for masks) and resolves the viewer's
`unbounded` / `unmasked_tags` against that frozen table, not the proxy's current
one: a viewer without `result.read.unbounded` receives the longest prefix within
the resolved rows and bytes and a truncation notice, the rest stays encrypted at
rest. The released rows are charged to the viewer's budget, as an editor or
workflow result is charged to whoever ran it.

## Why not

- A server-load threshold: paced extraction stays under it. Volume is
  pacing-proof.
- Silent truncation: a client that receives OK after N rows believes the set is
  complete. An error terminator is what a DB itself sends when a query is killed
  mid-stream (MySQL 1317, PG `57014`).
- Closing the session on a cap hit: the proxy knows exactly where the stream is,
  unlike a mask-binding failure. Closing would punish a mis-sized query with
  lost transaction state.
- A fixed cap: full-table reads are legitimate under control. Whether a cap
  applies at all is part of the decision, so role and channel decide it.
- Cap numbers in the control plane: the proxy is per-datasource already, so its
  config is per-datasource config, and a table keyed by tag is more expressive
  than a fixed pair of buckets.
- A trusted-network exemption: the attacker in the reference breach ran from a
  VM inside the production VPC.

## Mechanism

### Control plane

`decideQuery` (Query.kt), after the existing statement decision and before
building the verdict:

1. Decide `result.read.unbounded` for the principal on the Datasource with the
   same request context. ALLOW → `unbounded = true`.
2. Otherwise collect `unmasked_tags`. The analyzer's `returned_columns`
   ([facts-emission.md](./facts-emission.md)) lists, from the SQL alone, each
   base column whose value reaches the result set and the output ordinals it
   feeds; a predicate, sort, or group read is not in it. A returned column
   contributes its classification tags when this principal reads it unmasked and
   it feeds an output the final mask list leaves bare (a write's `RETURNING` has
   no ordinals and counts as bare), or when it is masked but
   `exception.unmaskable` lets the proxy relay it raw. Everything else
   contributes nothing.

   `SELECT id, upper(ssn) FROM users`: the analyzer returns `id`@0 and `ssn`@1.
   A role that reads `ssn` unmasked leaves ordinal 1 bare, so the verdict names
   `pii` and the proxy applies its `pii` entry; a role that reads it masked gets
   ordinal 1 masked, the tag set is empty, and the default applies. Nobody
   counts rows here: the proxy does that as it relays.

3. Otherwise read the principal's budget:
   `SELECT sum(rows_returned), sum(bytes_returned) FROM audit_event WHERE kind = 'completion' AND principal = ? AND ts >= ?`
   for the 1h and 24h windows, and add `budget_rows_1h`, `budget_bytes_1h`,
   `budget_rows_24h`, `budget_bytes_24h` to the Cedar context of the statement
   decision. The context is built before the column decisions, so this read
   happens once per statement.

`DecisionContext` gains `unbounded: Boolean` and `unmaskedTags: Set<String>`;
`Verdict` gains `bool unbounded = 14; repeated string unmasked_tags = 15;`.
`RunDecision` echoes both plus the rows/bytes the proxy resolved, so the console
can tell a result the cap cut short from one the client's own page size ended
(`truncated_by_cap`). `RunDone` carries the proxy's whole cap table
(`ResultCaps`), which `StoredResult.caps` freezes with the rows.

`decideResultView` (Approvals.kt) resolves the viewer's `unbounded` /
`unmaskedTags` against the stored table the same way the proxy does
(`resolveCaps` mirrors `ResultCaps.Resolve`), releases the longest prefix within
rows and bytes, and `ResultViewDecision.Allowed` carries `truncatedAt`. A result
stored without a table is refused: every run freezes one.

### Cedar

Schema: action `result.read.unbounded` on `[Datasource]`; `RequestContext` gains
`budget_rows_1h?: Long`, `budget_bytes_1h?: Long`, `budget_rows_24h?: Long`,
`budget_bytes_24h?: Long`. Shipped system policies (`policy-store.md` id space,
toggle-only), one per window and dimension, of the form

```cedar
forbid(principal,
       action in [Action::"result.read.unmasked", Action::"result.read.masked"],
       resource)
  when { context has budget_rows_24h && context.budget_rows_24h >= 50000 };
```

An admin who wants another number toggles the shipped row off and writes their
own. An example permit for the elevation role ships as a documented snippet, not
as a policy row:

```cedar
permit(principal in Role::"unbounded-reader",
       action == Action::"result.read.unbounded",
       resource == Datasource::"prod-mysql");
```

### Migration

`audit_event (principal, ts) WHERE kind = 'completion'` is indexed for the
budget read. Nothing about caps is stored per datasource.

### Proxy

`PM_RESULT_CAPS` is parsed at boot (`engine.ParseResultCaps`, fail-closed on a
malformed or non-positive value) and every decoded verdict resolves its
`unbounded` / `unmasked_tags` to `engine.Decision.MaxRows` / `MaxBytes`
(`ResultCaps.Resolve`: none when unbounded, else the minimum over the default
and each named tag's entry). In `relayResultSet` (mysqlproxy/relay.go) and
`streamResult` (pgproxy) the row tally already runs before the row is written;
when it crosses the cap the relay:

1. stops writing rows to the client;
2. cancels the statement on the target: PG `CancelRequest` with the backend key;
   MySQL `KILL QUERY <connection id>` over the broker's side connection, falling
   back to draining the remaining result without forwarding it;
3. drains the target stream to its terminator so the connection is reusable;
4. sends the client one error as the result terminator: MySQL ERR `1317`
   (`70100`) with message
   `proxy-monster: result exceeds the row cap (N rows); request unbounded access`,
   PG `ErrorResponse` SQLSTATE `57014` with the same message and hint;
5. reports the completion with the rows actually relayed and status `error`.

A PostgreSQL extended-protocol portal accumulates its relayed volume across
Executes, so a client paging a suspended portal is bound by the cap over the
portal's whole output; each page still audits its own completion.

The MySQL run-channel path (`run_session.go`) already sets
`SQL_SELECT_LIMIT maxRows+1`; it takes the verdict cap into the same limit and
reports `truncated_by_cap` instead of an error, since the console renders the
notice itself.

### Web

- Editor: the page-size selector offers nothing above the shipped default row
  cap; a `truncated_by_cap` result shows a notice with the cap and a link to
  request access.
- Stored result view: the same notice when the view truncated (`truncatedAt`) or
  the execution that stored the rows did (`truncatedByCap`, kept with the result
  — a stored prefix is indistinguishable from a complete result once the
  viewer's own cap matches its size).

### Audit and auditmon

A cap hit is visible as a completion with `outcome = error` and
`rows_returned = cap`. `mass_export` keeps working unchanged and, at its sample
thresholds (100k rows / 10m), sits above the daily budget; deployments should
lower it so alerts precede denials. A budget denial is a DENY decision whose
`deny_reason` names the spent window, so `repeated_deny` also fires on a
principal that keeps retrying.

## Tests

- Proxy: `PM_RESULT_CAPS` grammar and resolution (min over tags, unknown tag →
  default, unbounded → none); DB-backed (Testcontainers, MySQL and PG): a
  10,000-row table read under a 500 cap returns exactly 500 rows then the error,
  the session stays usable and an open transaction survives; completion reports
  500/`error`; an unbounded verdict relays all rows.
- Control plane: `unmasked_tags` per statement shape (unmasked tagged → the tag;
  masked → empty; predicate-only → empty; `RETURNING` of a tagged column → the
  tag; `exception.unmaskable` on a masked read → the tag; unbounded permitted →
  `unbounded`); budget context values from seeded completions; shipped forbid
  denies at the threshold and not below; unbounded skips the budget; a result
  view resolves the viewer's caps from the frozen table and releases fully with
  `result.read.unbounded`.
- Run channel: `RunDone` carries the cap table; a capped result carries
  `truncated_by_cap` and the resolved cap.
- Web: the truncation notice renders.
