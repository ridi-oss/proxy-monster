# The access model — the engine states facts, Cedar sets policy

The system decides access in two cleanly separated halves:

- The engine states **facts**. The analyzer classifies a statement — the
  resources it touches and their tags, its SQL kind, whether it is analyzable,
  whether its result is maskable. The engine makes no allow/deny decision.
- **Cedar** sets policy. Every decision — mask / deny / relay, fail-open /
  fail-closed, who sees the catalog, whether a dangerous function runs — is
  Cedar over those facts, per principal and per datasource.

From that one split everything follows: no hardcoded allow/deny. A datasource
that masks PII and a dev datasource that allows everything are the same engine
running two policy sets — the difference lives entirely in policy, not in any
code path.

This generalizes [authz-model.md](./authz-model.md), whose Cedar RBAC spine is
the _policy_ half. This doc adds the _facts_ half, makes every accessed thing a
tagged resource, and moves every allow/deny out of code into per-datasource
Cedar policy. Catalog introspection, column masking, and function control become
the same mechanism.

## The facts the engine emits

`StatementFacts` (analyzer → control-plane) carries these per statement. All
facts, zero policy:

<!-- prettier-ignore -->
| fact | from | example |
| --- | --- | --- |
| resources touched + their tags | catalog + analyzer | `Column::"acme-pg/acme/public/users/ssn"` tagged `pii`; `Function::"acme-pg/pg_read_file"` tagged `system:data-leak` |
| statement kind | analyzer | `stmt.kind.select` / `insert` / `update` / `delete` / `create_table` / … (Cedar maps each to a `stmt.cat.*` category) |
| analyzable? | analyzer | false → `exception.unanalyzable` (PIVOT, NATURAL JOIN, unsupported root) |
| maskable? | proxy/control-plane | false → `exception.unmaskable` (COPY bulk stream, fast-path calls, MySQL binary result — the proxy can't rewrite the result) |
| lineage | analyzer | per output column: origin columns (maskable identity) vs reference columns + context (DERIVED → unmaskable) |

The lineage fact is what the authz layer turns into per-column verdicts.

## Resources and tags

Every accessed thing is a Cedar resource: Column, Table, Function (built-in and
UDF), system-catalog objects, and Utility for the few commands with no mirrored
object. Database-object keys are fully qualified —
`Column::"<datasource>/<catalog>/<schema>/<table>/<column>"`,
`Table::"…/<schema>/<table>"` (canonical `acme-pg/acme/public/users/ssn`;
construction in
[mapping-schema-construction.md](./mapping-schema-construction.md)). Functions
and utilities are name-keyed only — `Function::"<datasource>/<name>"`,
`Utility::"<datasource>/<command>"` (e.g. `Function::"acme-pg/pg_read_file"`,
`Utility::"acme-mysql/SHOW_PROCESSLIST"`). That is what makes system-catalog
introspection safe: `public.tables` is a different resource from
`information_schema.tables`. It holds on both engines (a MySQL database is a
schema).

Tags classify resources:

- User tags — admin-applied to user objects: `pii`, `sensitive`, custom.
- `system:` tags — auto-applied from a shipped, curated per-version
  classification, so no one hand-tags `pg_class` or `dblink`:

<!-- prettier-ignore -->
| tag | contents | shipped default policy |
| --- | --- | --- |
| `system:catalog` | structure — names, types, indexes, constraints, view/function/trigger defs | permit (browsing works) |
| `system:activity` | `PROCESSLIST`/`INNODB_TRX`, statement history, query logs; PG `pg_stat_activity` | forbid, unless `system:development` |
| `system:data-leak` | histograms (`pg_stats`/`COLUMN_STATISTICS`), large objects, data-reading functions (`dblink`, `pg_read_file`, `lo_get`, `LOAD_FILE`) | forbid, unless `system:development` |
| `system:critical` | `pg_shadow`, `pg_authid`, `mysql.user`, FDW conn strings, `pg_hba`; privileged mutation — `SET PASSWORD`, `SET GLOBAL`/`ALTER SYSTEM` (via the command map) | forbid — an admin may permit |

Untagged system resources (a safe builtin like `format_type`, ordinary
structural columns) are open — only the dangerous set is tagged, and only those
tags are forbidden. Nothing is hard-excluded: credentials are a tracked, tagged
(`system:critical`), forbidden resource, not an invisible one, so an admin can
grant them if truly needed, and a missed classification is the failure mode to
guard.

Utility commands map to the resource they expose. `SHOW`/`DESCRIBE` read no
table, so the analyzer maps each to a canonical command id and the shipped
manifest tags it: `SHOW [FULL] PROCESSLIST` → `SHOW_PROCESSLIST` /
`system:activity`, `SHOW CREATE TABLE` / `DESCRIBE` → `system:catalog`,
`SHOW BINLOG EVENTS` → `system:data-leak`. A command uses the real
Table/Function when one exists; a command with no mirrored SQL object uses a
dedicated `Utility::"<datasource>/<command>"` resource. Either way the same tag
policy decides it. This command→resource map is a small, declarative part of the
classification — the one place a resource is named rather than derived from
lineage.

Only dangerous-classified functions are marshalled as Function resources (safe
builtins and ordinary UDFs are not gated on this path). General UDF-output
vouching is out of scope — see Known gaps.

Datasources are tagged too — posture tags carry shipped policy. A datasource is
a resource with tags, same as a column. Each posture tag ships with a Cedar
policy set keyed on it, so an admin applies a tag instead of writing Cedar:

<!-- prettier-ignore -->
| tag | on | activates (shipped policy) |
| --- | --- | --- |
| `system:development` | datasource | permissive — `system:activity`/`system:data-leak` visible, `exception.unanalyzable`/`exception.unmaskable` relayed, cleartext reads (dev holds no real PII) |
| `system:production` | datasource | strict package (disabled by default until toggled on) — role-gated connect/sql.*, PII masked, cleartext PII only on `trusted-network` |

User columns use freeform tags such as `pii` (not a reserved `system:` prefix);
the production package masks `Tag::"pii"` and unmasks only for
`system:production-pii-accessor` when `context.tags` contains `trusted-network`.

Placement is not enforced: any resource may carry any tag, and marshalling
attaches it as written. What is enforced is the NAME — the `system:` namespace
belongs to the product, so an operator cannot coin `system:whatever`, while the
six names it defines are writable anywhere. A posture tag therefore decides for
whatever carries it: on a datasource, for everything beneath it.

Tagging any datasource `system:development` gives it the whole dev posture with
no per-datasource policy; tagging a column `pii` plus the production package
masks it with no hand-written rule. Custom needs still use your own tags and
policies; the posture tags are the working defaults, one tag away.

## Policy: Cedar decides, per datasource

Because every resource carries its datasource, catalog, and schema
(`Table::"ds/catalog/schema/…"`), one policy set expresses any posture per
datasource:

- Masking is the per-column verdict the authz layer computes
  (`result.read.unmasked` / `masked` / deny). "No masking" is
  `permit(result.read.unmasked)` granted broadly on that datasource.
- Catalog / activity / data-leak / critical are permit/forbid on the `system:`
  tags.
- Fail-open vs fail-closed on `exception.unanalyzable` / `exception.unmaskable`
  is policy: relayed under `system:development`, denied under the production
  floor.
- A datasource's whole posture is its posture tag; an untagged datasource falls
  back to the production-safe floor (system forbids + deny-by-default reads). A
  datasource with special needs drops the posture tag and carries hand-written
  policy.

Catalog structure is open under every posture — browsing always works; the
posture governs only the dangerous surface
(`system:activity`/`data-leak`/`critical`) and masking.

```cedar
// structure is browsable everywhere, under any posture
permit (principal, action == Action::"result.read.unmasked", resource)
  when { resource in Tag::"system:catalog" };

// system:development — cleartext reads; activity + data-leak forbids relax
permit (principal, action == Action::"result.read.unmasked", resource)
  when { resource in Tag::"system:development" }
  unless { resource in Tag::"system:critical" };
permit (principal, action == Action::"exception.unanalyzable", resource)
  when { resource in Tag::"system:development" };
permit (principal, action == Action::"exception.unmaskable", resource)
  when { resource in Tag::"system:development" };

// production-safe floor — dangerous tags stay forbidden unless development
forbid (principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource)
  when   { resource in Tag::"system:activity" }
  unless { resource in Tag::"system:development" };
forbid (principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource)
  when   { resource in Tag::"system:data-leak" }
  unless { resource in Tag::"system:development" };

// critical (credentials + privileged ops) — forbidden under every posture
forbid (principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource)
  when { resource in Tag::"system:critical" };

// pii columns under system:production — masked; unmasked only on trusted-network
// (the production package also role-gates these; simplified here)
permit (principal, action == Action::"result.read.masked", resource)
  when { resource in Tag::"system:production" && resource in Tag::"pii" };
permit (principal, action == Action::"result.read.unmasked", resource)
  when {
    resource in Tag::"system:production" &&
    resource in Tag::"pii" &&
    context has tags &&
    context.tags.contains("trusted-network")
  };
// other user columns stay deny-by-default (no base permit).
```

System and user policies share one table, two id spaces. The shipped policies
above (the postures, the `system:` rules, the bootstrap grants) are system
policies: they live in the same `policy` table as user-authored ones but are not
user-editable — the console can toggle them off (`enabled`), never rewrite their
`cedar_src` — so a later migration updates them in place. They occupy a reserved
id space disjoint from user policies, so a migration UPSERTs a system policy by
id and never collides with user additions/deletions. Bootstrap is the same
mechanism: a migration seed installs the system policy set plus a first admin
role on a clean DB, so a fresh install is governed from boot. See
[policy-store.md](./policy-store.md).

## What is not policy

Three things never become Cedar, correctly:

- Wire protocol / auth structure — a valid protocol version and auth handshake
  are always enforced, and a proxy configured with TLS refuses a client that
  does not upgrade. Not authz.
- Connection / namespace / catalog plumbing — the per-connection model
  enforcement resolves against ([connection-model.md](./connection-model.md)) is
  a data-plane mechanism. Cedar decides over the resolved key; the connection
  model only makes that key match what the target DB binds.
- Data-plane capability — Cedar can _permit_ an unmaskable feature (COPY,
  fast-path) on a development datasource, but the proxy must be _able_ to relay
  it verbatim. Where it can't, the feature stays denied regardless of policy
  (fail-closed).

## Worked applications (all one mechanism)

- Catalog browsing (JDBC/DBeaver/psql). System relations auto-tagged
  `system:catalog` → open → schema tree + DDL/function depth work. `pg_get_*def`
  reconstruction is structure → allowed; histograms/credentials are
  `system:data-leak`/`system:critical` → forbidden.
- Watch live queries on dev. `PROCESSLIST`/statement text/logs are
  `system:activity` → forbidden in prod, permitted when the datasource carries
  `system:development`.
- Dangerous functions. `dblink`/`pg_read_file`/`lo_get`/`LOAD_FILE` are
  `system:data-leak` → forbidden, grantable where policy relaxes
  (`system:development` or a hand-written permit).
- Allow everything on a dev DB (auth + audit, no masking). A permissive policy
  set: broad `result.read.unmasked` + `permit(exception.unanalyzable)` + permit
  the `system:` tags — one `system:development` tag away.

## Known gaps

- Open system catalogs make curation load-bearing. A new object in a covered
  system schema that the shipped manifest does not classify defaults to
  `system:catalog` and is open. The per-version inventory/review is the safety
  property; runtime emits stale-classification health/audit but does not
  silently switch the accepted posture. `system:critical` misses are the worst
  case.
- General UDF-output vouching is out of scope. Resolving every call BUILTIN vs
  UDF and vouching a data-reading UDF's output is not built; only the
  known-dangerous function set is gated, so a non-dangerous data-reading UDF's
  output passes unmasked ([KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md);
  backlogged).
- Shared service account. Permitting `SET PASSWORD`/`SET GLOBAL`
  (`system:critical`) mutates the _shared_ target DB account for everyone; it is
  fully isolated only once the proxy brokers a per-user target DB login. The
  admin owns the call until then.
- Data-plane passthrough for unmaskable features (COPY / fast-path) must be
  built for a Cedar permit to take effect; until then capability denial wins
  regardless of policy.
- First principal assignment is identity bootstrap. The migration creates the
  governed policy set and `system:admin` role but does not invent a principal;
  the install/auth runbook assigns the first real principal or IdP group, and
  until then admin routes correctly deny.

## Related docs

- [mapping-schema-construction.md](./mapping-schema-construction.md) — building
  the depth-3 sqlglot mapping for a datasource's catalog.
- [schema-threading-problem.md](./schema-threading-problem.md) — the
  fully-qualified key, static resolver, and exact catalog matching.
- [connection-model.md](./connection-model.md) — resolving that key against a
  connection's live namespace.
- [per-connection-catalog.md](./per-connection-catalog.md) — keeping the
  enforcement catalog transactionally current per connection.
- [policy-store.md](./policy-store.md) — the one-table/two-id-space policy store
  and bootstrap seed.
- [system-classification.md](./system-classification.md) — the per-engine
  `system:` classification, dangerous set, and command map.
- [facts-emission.md](./facts-emission.md) — Function/UDF/scanned-Table facts
  and the `exception.unanalyzable`/`exception.unmaskable` contract.
- [statement-facts-contract.md](./statement-facts-contract.md) — the full
  `StatementFacts` grant contract between the analyzer and Cedar.
