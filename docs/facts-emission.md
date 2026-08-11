# Facts emission — resources, function output, and capability gates

The analyzer states facts; Cedar sets policy. For every statement the Go
analyzer emits one complete set of authorization facts — the columns read or
written, every physical table scanned, named function calls the parser can
classify, classified utility commands, required datasource actions, and whether
the statement is resolved. The control-plane enriches those resource identities
with catalog, user, and shipped `system:` tags, assembles Cedar entity graphs,
and makes every policy decision there. A missing required fact is a security
bug.

This doc defines the facts and the Cedar resource semantics over them. The wire
contract that carries the facts and the rule that Kotlin never parses or
classifies SQL live in
[statement-facts-contract.md](./statement-facts-contract.md). Which objects
receive shipped tags lives in
[system-classification.md](./system-classification.md); the Cedar RBAC spine and
the shipped policies live in [authz-model.md](./authz-model.md) and
[policy-store.md](./policy-store.md).

## The facts

For each statement the analyzer emits, in `StatementFacts`
(`proto/src/main/proto/analyzer.proto`):

1. the fully-qualified Column grants read or written, with `MaskedDisposition`
   and output ordinals;
2. every physical Table scanned, including scans that touch zero columns, each
   marked `covered` or not;
3. distinct named `Anonymous` function calls, plus explicit Function grants for
   non-allowlisted no-FROM calls;
4. classified Utility commands (SHOW/SET forms and unsafe cast/subquery forms);
5. the single `statement_exec` grant naming the statement's kind
   (`stmt.kind.<k>`) — the single per-statement authorization signal, which
   Cedar's schema maps to a category; and
6. whether the statement is resolved, and if not, its `FailureClass`
   (`INADMISSIBLE` hard-deny, or `UNANALYZABLE` → the `exception.unanalyzable`
   gate).

Wire-path masking capability is decided after these facts (see
[Unmaskable wire paths](#unmaskable-wire-paths)).

## Predicate literals — an advisory disclosure fact

`predicate_literals` reports, for each `WHERE` / `HAVING` / `QUALIFY` / join
predicate that compares a **literal** against a column, the resolved base column
and its clause. A column-to-column comparison emits nothing.

It is the one fact that is not authorization. It gates whether a statement's
TEXT may be shown outside the console — `WHERE ssn = '987-65-4320'` puts the
protected value in the query itself, where masking cannot reach it, since
masking rewrites results and not predicates. It can only ever HIDE text: it
never denies a statement, and an unparseable identity is skipped rather than
failing the statement.

The analyzer states the fact and stops. It has no role context and must never
acquire one — whether a column is protected is the control plane's decision,
made against classification. Emission is best-effort by construction (a value
also reaches a predicate through a function, a `CASE`, a subquery, or a bound
parameter), so a consumer treats absence as unknown, never as proof of safety.

## Cedar resource graph and actions

The Cedar schema (`control-plane/src/main/resources/authz/schema.cedarschema`)
models each resource type as an entity with `Datasource` and `Tag` parents:

```cedar
entity Datasource in [Tag] = { name?: String };
entity Table in [Datasource, Tag];
entity Column in [Table, Datasource, Tag];
entity Function in [Datasource, Tag];
entity Utility in [Datasource, Tag];
```

The data actions are `datasource.connect`, the per-statement `stmt.kind.<k>`
(each a member of one `stmt.cat.<category>` in the schema, so a category preset
covers it), `result.read.unmasked`/`result.read.masked`, and the two
datasource-level exception gates
`exception.unanalyzable`/`exception.unmaskable`. `Function` and `Utility` appear
on the result-read actions alongside `Table` and `Column`.

The request graph is assembled from live data on every decision:

- catalog and connection state provide the fully-qualified identity;
- user classification provides ordinary direct Column tags;
- [system-classification.md](./system-classification.md) provides one immutable
  shipped tag on each classified Table, Function, or Utility (a Column inherits
  its Table's system tag rather than receiving a second direct system tag); and
- the datasource provides every tag it carries — no filtering, whatever the tag
  is named — each usable as a policy match and each inherited by every
  Table/Column/Function beneath it. The posture tags are what the shipped
  presets match.

### Result-read semantics per resource

- Column: unchanged — an unmasked permit wins; otherwise a masked permit masks
  the output; otherwise denied. The masked disposition (`MASK_OUTPUT`,
  `REDACT_OUTPUT_NULL`, or `DENY_STATEMENT`) comes from the analyzer per grant.
  A masked column in a write or a reference position (predicate/join/subquery)
  cannot be masked and denies (see [derived-masking.md](./derived-masking.md)
  for the redactable-transform exception).
- Table (uncovered scan): either `result.read.unmasked` or `result.read.masked`
  permits the scan — a masked reader already observes the table's existence and
  row count through masked projections. No permit denies.
- Function: called-function names are classified before marshalling.
  `system:critical` is always forbidden; `system:data-leak` is forbidden on the
  production posture and relaxed on `system:development`. Unclassified FROM'd
  calls are not marshalled. An explicit no-FROM Function grant must classify; an
  unclassified grant hard-denies.
- Utility: a read permit covering the tagged `Utility` resource permits use; the
  shipped `system:` forbids deny dangerous commands. A recognized Utility with
  no governing manifest classification hard-denies before Cedar.

Cedar's entity hierarchy keeps table-scoped policy ergonomic: a policy on a
Table covers its Column children, and the Table entity itself satisfies the same
selector. There is no separate `table.scan` or `function.call` action — result
visibility is one capability across every data-producing resource.

### Reserved names, not reserved placements

`system:` is the product's namespace: an operator may not coin a name in it, and
the six the product defines — the four shipped classification tags and the two
datasource postures — are writable on any resource. Marshalling filters nothing
by resource type, so a tag reaches policy from wherever it sits.

Shipped classification does not come from a tag row. It is resolved from the
manifest per statement and attached to the Table, Function, or Utility; a Column
inherits its Table's tag. Cedar sees one `Tag::` entity either way, so a policy
cannot tell a manifest tag from a stored one — a column classified
`system:critical` reaches the shipped critical forbid and is denied, and one
classified `system:development` reaches the development permit. Both take the
`admin.datasources` authority the classification API requires.

## Scanned Tables — the zero-column gap

A physical table with zero traced columns must still be authorized:
`SELECT count(*) FROM orders`, `SELECT 1 FROM orders`,
`SELECT EXISTS(SELECT 1 FROM orders)`, and `SELECT u.id FROM users u, orders o`
each read `orders` and expose at least its existence and cardinality, so
`orders` must be a Table resource even when no Column fact covers it.

The analyzer walks each resolved scope's source map and emits a Table fact only
when the source resolves to a physical target-DB relation. A CTE, derived table,
table-valued expression, or alias is not a physical Table; the walk recurses
into its scope and emits the physical relations it reads. This reuses the
analyzer's scope resolution (`analyzer/probe/relation.go`) rather than
collecting SQL names and subtracting a CTE-name set — that distinction is the
safety property:

```sql
-- The outer orders is a CTE; the target-DB table is not read → no Table fact.
WITH orders AS (SELECT 1) SELECT count(*) FROM orders;

-- The CTE body resolves orders against the target-DB table → it is emitted.
WITH orders AS (SELECT count(*) AS c FROM orders) SELECT c FROM orders;
```

Physical reads are included in every scope: set-operation branches, expression
subqueries (`EXISTS`, `IN`), CTE bodies, `UPDATE ... FROM`, `DELETE ... USING`,
and read-side sources synthesized for write analysis. A write target is not a
scanned Table solely because it is the target — `INSERT INTO t VALUES (...)` is
gated by its kind (`stmt.kind.insert` ∈ `stmt.cat.write.insert`), not a new
result-read grant. Any target data actually read (`RETURNING`, `ON CONFLICT`,
expressions reading old values, write-payload lineage) already emits Column or
physical-read facts.

`covered` is computed from the final emitted facts: a table with any traced
column is already exposed through it and needs no separate Table grant; a scan
with no covering column fact requires `result.read.unmasked` or
`result.read.masked` on the Table.

<!-- prettier-ignore -->
| statement | facts | result |
| --- | --- | --- |
| `SELECT ssn FROM users` | `users.ssn`; `users` covered by the column | column verdict |
| `SELECT count(*) FROM users` | uncovered `users` scan | require read on `Table::.../users` |
| `SELECT u.id FROM users u, orders o` | `users` covered; `orders` uncovered | require `users.id` and `orders` |
| `WITH orders AS (SELECT 1) SELECT count(*) FROM orders` | no physical Table | no table-read gate |

Verified by `KnownGapsTest` and `ScannedTableMySqlTest` (control-plane) and
`scanned_sources_test.go` (analyzer, both engines).

## Functions — dangerous-call gating

The analyzer emits distinct lowercased bare names for function calls represented
as `Anonymous` nodes. Standard built-ins with dedicated node kinds such as
`count`, `cast`, and `substring` are not emitted. The control-plane classifies
the names it receives and marshals only the dangerous set. A FROM'd dangerous
call emits its name even when later analysis is unresolved. `system:critical`
always denies; `system:data-leak` denies on production and may pass under
`system:development`.

For a governed datasource, `SystemClassificationService.tagForFunction` uses the
governing manifest plus `BaselineDangerousFunctions`. With no governing manifest
it uses the strongest classification across every shipped manifest for that
engine, again with the baseline floor. The function gate runs before the column
and uncovered-table gates, so a legitimate table-read grant cannot punch a
classified function through.

The no-FROM function allowlist lives in the analyzer
(`analyzer/probe/facts.go`): any non-allowlisted anonymous call, or an untrusted
qualified call, emits a Function grant. An unclassified grant hard-denies;
classified grants follow their shipped system policy. Allowlisted no-FROM calls
and dedicated safe built-ins emit no Function grant.

Resolving every call as built-in vs UDF against a datasource function catalog,
and vouching a data-reading UDF's output, is out of scope. A non-dangerous UDF
in a FROM-backed query that reads a masked/PII column inside its body — never as
a visible argument (an argument is already denied by the derived-expression
rule) — passes unmasked, held by the operational rule that a UDF on a masking
datasource must not read PII ([KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md)).

## Analyzable

`resolved=false` means the analyzer cannot prove complete resource/lineage facts
— because of configuration validation, parse coverage, an unsupported analyzer
root or data-modifying CTE, PIVOT, NATURAL JOIN, or an unresolved relation
shape. Such a statement routes through the `exception.unanalyzable` datasource
gate:

1. `datasource.connect` and every emitted datasource action must still pass; an
   unspecified action denies.
2. If the analyzer reports `UNANALYZABLE`, the control-plane authorizes
   `exception.unanalyzable` on the Datasource.
3. Permit → relay the original statement verbatim, no rewrite or masks, with a
   recorded reason.
4. No permit / Cedar error / `INADMISSIBLE` → deny.

An unanalyzable statement cannot claim that no sensitive resources were touched,
so the exception is datasource-wide and explicit — suitable for a permissive
development datasource, not a way to punch a single unknown query through
production masking.

`exception.unanalyzable` is a superset of write/exec authorization for the
unanalyzable class. The class is not just weird reads: a data-modifying CTE
(`WITH a AS (DELETE … RETURNING …) SELECT * FROM a`) is classified `SELECT` but
rejected by the probe as unanalyzable, so a datasource granting the read
category + `exception.unanalyzable` but not `stmt.cat.write.delete` still
executes the embedded DELETE, unmasked. This is the intended
`system:development` posture (relay everything unanalyzable verbatim);
production is deny-by-default. Enabling `exception.unanalyzable` therefore also
enables writes/exec hidden in unanalyzable constructs, not a read-only
convenience.

The structural floor stays outside policy. Protocol framing/authentication and
multi-statement ambiguity are hard denies that policy and query grants never
override. MySQL executable comments are decoded and analyzed when the server
version is known; a missing or invalid MySQL engine configuration routes through
`exception.unanalyzable`.

## Unmaskable wire paths

`StatementFacts` has no maskability Boolean or reason enum. The control-plane
computes the ordinary query verdict without knowing which result format a later
wire execution will use.

On a `MASK` verdict the control-plane sets `Verdict.unmaskable_permitted` when
the datasource grants `exception.unmaskable`
(`authorizeDatasourceAction(EXCEPTION_UNMASKABLE)`). The proxy relays the
binary/prepared result unmasked only when that flag is set — checked in
`goproxy/mysqlproxy/conn.go` and `goproxy/pgproxy/extended.go` — and otherwise
refuses fail-closed. MySQL binary/prepared-statement results and PostgreSQL
binary-format results have a relay path; COPY and fast-path do not and stay
denied even where policy permits `exception.unmaskable`. That is an honest
fail-closed capability gap, not a policy exception the proxy silently ignores.

A plan-only `EXPLAIN` returns the query plan, not rows, so the analyzer emits
its projected columns as read-required with no output ordinal (and empty
`output_columns`): an authorized `result.read.masked` references a column that
is never returned, so nothing is masked and the plan relays as-is. A masked
column in a PREDICATE still denies unless the reader holds
`result.read.unmasked` (its selectivity leaks — exact under `ANALYZE`); an
`EXPLAIN ANALYZE` of a write carries the write's own kind and denies as that
write.

## End-to-end flow

`decideQuery` runs, in order: analyze and hard-deny `INADMISSIBLE`; reject a
deactivated principal; resolve roles and context; validate the facts contract;
authorize `datasource.connect`; authorize classified Utility grants; handle
zero-resource metadata/session passthrough; authorize each emitted datasource
action; apply the dangerous-function and `exception.unanalyzable` gates for an
unresolved statement; then authorize classified functions, Columns, and
uncovered Tables. For any remaining MASK verdict, the control-plane checks
`exception.unmaskable` and carries the result as a capability flag for the
proxy. Every gate runs before the target DB receives the statement.

Assuming `datasource.connect` and the `stmt.kind.select` gate pass:

<!-- prettier-ignore -->
| query / feature | emitted facts | production masking datasource | development datasource |
| --- | --- | --- | --- |
| `SELECT count(*) FROM orders` | uncovered Table `orders` | DENY without a Table read grant | permit if policy grants broad read |
| `SELECT lower(email) FROM users` | derived Column `email`; no Function fact | masked output is redacted to NULL | ALLOW unmasked under dev posture |
| `SELECT dblink(…) FROM t` | named Function `dblink` (`system:data-leak`) | DENY (function forbid) | ALLOW under the dev relaxation |
| `SELECT * FROM information_schema.tables` | system Table/Columns tagged `system:catalog` | catalog permit | catalog permit |
| `SHOW FULL PROCESSLIST` | Utility → activity resource | DENY | dev activity policy may permit |
| `SET GLOBAL general_log=ON` | critical Utility | DENY | DENY |
| unsupported analyzer shape | `resolved=false` | DENY | relay only with `exception.unanalyzable` |
| PG COPY OUT | unsupported root (`resolved=false`) | DENY | proxy still DENYs COPY after any exception permit |

## Contract and version skew

The analyzer↔JVM boundary and the control-plane↔proxy boundary are both protobuf
(`proto/src/main/proto/analyzer.proto`, `controlplane.proto`). Generated
bindings catch incompatible source changes at build time, but deployed protobuf
peers can ignore unknown fields. Zero-value sentinels, required-resource checks,
and absent-false capability flags therefore deny missing or malformed contract
data at runtime. The control-plane is the only Cedar evaluator. The proxy's
local admission remains a strict structural backstop: it rejects
framing/engine-safety inputs and may over-deny a statement a newer control-plane
would permit, but it must never under-deny one.

## Conservation invariants

1. A physical read omitted from the sources is a leak. The scope-graph sweep and
   the zero-column adversarial suite are release gates.
2. A dangerous named function call omitted from `functions` or an explicit
   Function grant is a leak. Dedicated safe built-ins are intentionally absent.
3. A classified utility omitted is a leak. Every recognized command id is either
   a mapped resource fact or an explicit metadata/session operation.
4. Unknown identity is never safe: an unknown relation resolution makes the
   statement unanalyzable.
5. Unknown lineage context is never dropped: it requires unmasked permission.
6. Missing `unmaskable_permitted` is false; unsupported relay paths deny.
7. Policy cannot create a data-plane capability: a permit plus an unsupported
   relay still denies.
8. A DENY names the resource/gate and reason; an unanalyzable exception ALLOW
   records the exception fact and reason.
