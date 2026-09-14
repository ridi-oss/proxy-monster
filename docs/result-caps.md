# Result caps — per-statement and per-window limits on relayed results

Bounds how much result data one principal can pull through the proxy, so a
stolen credential or a scripted dump yields a bounded slice per statement and
per day instead of a whole table. `mass_export` in auditmon already alerts on
volume; this enforces it.

## Decision

A limit is a `@cap` annotation on a `permit` for one dedicated Cedar action,
`result.cap`. No enforcement path consults the action, so permitting it grants
nothing and the shipped read permits stay read-only. A `forbid` on it clears
every limit for whoever it names.

```cedar
@cap("500, 5MB")
permit(principal, action == Action::"result.cap", resource)
  when { resource is Column && resource.tagged && context has masked && !context.masked };

@cap("5000, 50MB, 10000/1h, 50000/1d, 100MB/1h, 500MB/1d")
permit(principal, action == Action::"result.cap", resource);

forbid(principal in Role::"system:production-exporter", action == Action::"result.cap", resource);
```

`@cap` holds a comma-separated list. An amount is rows, or bytes with a
`KB`/`MB`/`GB` suffix (10^3; a bare `K`/`M`/`G` is refused, it reads as rows as
easily as bytes). An entry that is just an amount is a **cap** on one result;
`<amount>/<window>` is a **rate**, the principal's total relayed volume over a
rolling `<n>m`, `<n>h`, or `<n>d`, at most `31d`. Cedar allows one annotation
per name, hence the list.

After the statement's read decisions pass, the control plane asks `result.cap`
on the datasource and on every returned column, table, function, and utility,
then folds:

1. a DENY on any ask (a `forbid` matched) → uncapped, no rate check;
2. else the tightest cap rows and bytes across the permits that matched; a
   dimension no permit mentions gets the constant default, 5,000 rows / 50 MB,
   so toggling every row off still caps;
3. then each rate is compared with the principal's relayed volume over its
   window, summed from the audit trail's completion events; a spent one denies
   with `rate 10000/1h spent`.

A column's ask carries `context.masked` (`true` when this principal reads it
masked; `false` when it reaches the client in the clear, which includes a read
`exception.unmaskable` may relay raw). `Column.tagged` says whether it carries
any classification tag. So the `-306` row above means "a tagged value in the
clear", whatever the tag is named.

`SELECT id, upper(ssn) FROM users`: reading `ssn` unmasked matches `-306`, 500
rows; reading it masked matches only `-305`, 5,000; `SELECT id FROM users`,
5,000.

**Rates** count everything the principal relays, whatever permit carries them,
so scope a rate by role or datasource, not by tag. A spent rate denies
statements that return rows; `COMMIT`, `ROLLBACK`, `SET`, and `USE` still pass.
A connection's next `Decide` waits for its own previous completion report;
parallel connections can overshoot by up to one statement cap each
(`KNOWN_LIMITATIONS.md`). A rate is reset by a marker row (`result_rate_reset`),
never by touching the audit trail: an admin writes it from the principal's
access page, or the user files a `RATE_RESET` request through the approval
workflow. A reset clears every window; it never touches a cap.

**Unbounded** is the shipped `forbid` for `system:production-exporter`, a
pii-accessor with no cap or rate: request it in a workflow, or hold it for a
window through a JIT `access_grant`. No group maps to it by default, and it is
never earned by network: a VM inside the VPC satisfies any CIDR rule.

**Enforcement** is the proxy's. The verdict carries the resolved `max_rows` /
`max_bytes`; the relay counts rows and bytes as it streams, and at the cap it
stops, cancels the statement on the target (`KILL QUERY` on MySQL,
`CancelRequest` on PG), drains, and ends the result with an error the client
sees as the terminator (MySQL `1317`, PG `57014`). The session and any open
transaction survive. The run channel narrows its page to the cap and reports
`truncated_by_cap` instead. A stored result is re-decided at view under the
viewer, released as the longest prefix within the viewer's own caps, and charged
to the viewer's rates.

## Why not

- A server-load threshold: paced extraction stays under it.
- Silent truncation: a client that gets OK after N rows believes the set is
  complete. A killed query's own error is what a DB sends.
- Closing the session on a cap hit: the proxy knows where the stream is; closing
  would cost a mis-sized query its transaction.
- Annotating the read permit: ties a cap to access, and the shipped read presets
  are read-only.
- A proxy config or datasource column: outside the policy store, unaudited, not
  scopable by role.
- A trusted-network exemption: the reference breach ran from a VM inside the
  production VPC.

## Mechanism

- `Authz.resolveResultCaps` asks `result.cap` per resource, reads the
  annotations of the policies `getReason()` names (parsed once beside the cached
  policy set), and folds as above. `Query.kt` stamps `maxRows` / `maxBytes` on
  every non-DENY exit; a malformed `@cap`, or one on a policy whose action is
  not `result.cap`, is refused at save.
- Relayed volume:
  `SELECT sum(rows_returned) FILTER (WHERE ts >= ?), … FROM audit_event WHERE kind = 'completion' AND principal = ? AND ts >= GREATEST(?, last reset)`,
  one `FILTER` pair per distinct window, run only when a rate was collected.
- Schema: `action "result.cap"` on
  `[Column, Table, Tag, Datasource, Function, Utility]`; `Column.tagged: Bool`;
  `RequestContext.masked?: Bool` ([authz-context.md](./authz-context.md)).
- Shipped rows `-305`/`-306`/`-307` ([policy-store.md](./policy-store.md));
  `audit_event (principal, ts) WHERE kind = 'completion'` indexed;
  `result_rate_reset(principal, reset_at, reset_by, reason)`; `RATE_RESET` joins
  the `access_request` kinds.
- Proxy: `engine.Decision.MaxRows` / `MaxBytes` (0 = uncapped, negative denies);
  `relayResultSet` (mysqlproxy) and `streamResult` (pgproxy) enforce; a PG
  portal's volume accumulates across Executes.
- Web: the editor's page sizes stop at the default cap; a capped or truncated
  result shows a notice; a spent-rate denial offers a `RATE_RESET` request.
- auditmon: a cap hit is a completion with `outcome = error`; a spent rate is a
  DENY whose reason names it, so `repeated_deny` fires on retries. Keep
  `mass_export` below the daily rate so alerts precede denials.

## Tests

- Control plane: the fold per statement shape (untagged → default; unmasked
  tagged → `-306`, under any tag name; masked → default, or an admin
  `masked = true` row; predicate-only → default; `max(ssn)` and `RETURNING ssn`
  unmasked → `-306`; a `forbid` → uncapped; both rows off → the constant); save
  rejects a malformed entry and a `@cap` off `result.cap`; a rate denies at its
  threshold from seeded completions and not below; an admin `3h` window is
  honoured; a reset clears the window and leaves the cap; a `RATE_RESET`
  approval writes the reset; a view truncates to the viewer's caps.
- Proxy, DB-backed on MySQL and PG: a 10,000-row read under a 500 cap returns
  exactly 500 rows then the error, the session and an open transaction survive,
  the completion reports 500/`error`; an uncapped verdict relays all rows.
- Run channel: a capped result carries `truncated_by_cap`.
