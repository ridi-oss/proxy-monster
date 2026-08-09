# The relation model: whole-row and composite values

How the analyzer resolves a relation used where a value is expected — a whole
row or a composite field — so a protected column can never slip through. This is
the deep-dive for one bug-prone subsystem; the whole-analyzer overview is
[analyzer/README.md](../analyzer/README.md), and the resolver itself is
`analyzer/probe/relation.go`.

Schema throughout: `users(id,email,phone,name,ssn,region,created_at)` with `ssn`
= PII (masked), `orders(id,user_id,…)`, `sink(id,data,data2)`.

## 1. The problem in one paragraph

SQL lets a relation be used where a value is expected — `to_jsonb(u)`,
`SELECT u`, `u AS sub`, `(u).ssn`, `row(u.*)`. Such an expression carries
_every_ column of the relation (including protected ones) but produces no
per-column lineage node the analyzer would otherwise see. PostgreSQL also
resolves a bare identifier column-first and walks the scope chain (inner → outer
for correlation), so a decoy table _aliased with the name of a protected column_
can be mistaken for that column, or vice-versa. Get either wrong and a protected
value reaches the client (or a persisted column) in cleartext while the analyzer
says ALLOW. One PG-faithful relation resolver, invoked at every site that
consumes a relation, handles all of these shapes uniformly — instead of a
separate guard per syntactic form.

## 2. What PostgreSQL does (the ground truth to match)

Two PG rules drive everything. Both are verified against live PG in a
rolled-back transaction, never inferred from reading sqlglot alone.

(R1) Column-first, chain-walked. A bare identifier `x` resolves to a column if
any table in the scope chain (innermost query level, then outer levels for
correlation) has a column `x`. Only if `x` is a column _nowhere_ does it resolve
to a relation (a range-table alias used as a whole-row composite value).

```sql
-- users has column ssn; orders is aliased `ssn`. PG binds the bare ssn COLUMN-FIRST -> users.ssn:
UPDATE users u SET name = (SELECT ssn) FROM orders ssn WHERE u.id = ssn.user_id;
-- live PG writes cleartext 987-65-4320 into users.name.
```

(R2) A relation-as-value is its whole tuple; field access drills in.
`to_jsonb(u)` serializes the whole `u` row; `(u).ssn` extracts one field — the
same value PG's `u.ssn` denotes. Composite access chains: `((region).sub).ssn`
where `sub`'s value is the `users` row resolves to `users.ssn`.

The analyzer resolves that field precisely — `(u).ssn` yields `users.ssn` alone,
not the whole row — but routes it to `references` rather than to a maskable
output identity, so a protected column reached that way denies:

```sql
SELECT (u).ssn FROM users u;    -- users.ssn, as a reference -> DENY (not masked)
SELECT (u).id  FROM users u;    -- users.id alone, non-PII -> ALLOW
SELECT to_jsonb(u) FROM users u;-- whole row incl. ssn, as one blob -> DENY
```

Masking needs an ordinary column identity: `SELECT u.ssn FROM users u` masks at
ordinal 0, while `SELECT (u).ssn FROM users u` denies.

## 3. The model: three operations, no whole-row special case

A relation handle is one of:

- a physical table (columns come from the schema catalog),
- a scope — a CTE / derived table / subquery / set-op (columns are its output
  projections, resolved recursively),
- a relation-valued column — the subtle one: `SELECT users AS sub …` makes `sub`
  a _column whose value is the `users` relation_; downstream `(x.sub).ssn` must
  thread through it.

Given that handle, three operations cover every representation:

1. A bare relation in value position expands to its tuple.
   `to_jsonb(u) ≡ f(u.id, u.ssn, …)` — an ordinary function over all of `u`'s
   columns → a _derived_ value → not maskable → its columns route to
   `references` → DENY if any is protected.
2. `SELECT x AS sub` produces a relation-valued column, threaded through however
   many hops of later field access. Defining one sweeps the whole row:
   `SELECT users AS sub` reads every `users` column, whatever a later
   `(x.sub).col` narrows to.
3. Composite field access `(x).col` resolves to the same base column `x.col`
   does. Resolve `x` to its relation, then `col` is that column — routed to
   `references`, so a protected `col` denies rather than masks.

Once "a bare name → (a column | a relation)" is decided correctly and in one
place, every one of `to_jsonb(x)`, `SELECT x`, `x AS sub`, `(x).col`,
`row(x.*)`, `RETURNING x.*` falls out of ordinary column resolution + function
derivation. There is no separate whole-row code path to keep in sync across
representations.

### The resolver (`analyzer/probe/relation.go`)

- `relationOf(name, chain, depth)` applies R1: walk the scope chain
  column-first, and the first source exposing `name` as a column wins — a scalar
  column (its base columns) or a relation-valued column (its underlying
  relation). Only a name that is a column nowhere in the chain is a bare
  relation alias. It returns a `relResult` carrying either the scalar bases or
  the relation. `depth` bounds recursion through relation-valued columns
  (overflow fails closed).
- `relationOfNode(node, depth)` resolves a node _used as a relation_ to its
  underlying relation: a physical `exp.Table` or a derived `*optimizer.Scope`. A
  scalar column or an unresolvable node returns `found=false` → the caller fails
  closed.
- `relationField(rel, field)` resolves `rel.field` (scalar composite access) to
  its specific base column(s). `found=false` → the caller fails closed (treat as
  reading the whole relation → DENY).
- `relationColumns(rel)` expands a relation used as a whole-row value to _all_
  its base columns, following a relation-valued projection through to its
  underlying relation.

Four invariants every call site honors:

- Full-chain column-first (R1). The column check walks the _same_ chain as the
  relation lookup. Checking only the innermost scope while the relation lookup
  walks parents is a leak.
- A relation-valued column beats a same-named alias. The per-scope _column_
  check (which finds a relation-valued column) runs before the _alias_ check.
- Quoted identifiers keep their case. Match a scope's projection aliases with
  the identifier's own (already-folded) casing; do not re-lowercase — a
  case-sensitive PG alias `"U"` must not match `u`. (Schema/table lookups still
  lowercase, because the catalog is lowercased.)
- Fail closed on an unresolved field. If `relationField` returns `found=false`
  (unknown / not reasonable — e.g. a function's composite return type the schema
  doesn't capture), route the _whole_ relation (DENY if protected), never an
  empty set (→ ALLOW).

## 4. The shapes that carry a relation as a value

Five syntactic shapes push a relation into value position through a different
sqlglot node. The resolver handles all of them uniformly; each must DENY when it
reaches a protected column.

<!-- prettier-ignore -->
| # | PoC (live-verified to leak cleartext `ssn` unless noted) | node shape |
| --- | --- | --- |
| 1 | `UPDATE users u SET name=(SELECT ssn) FROM orders ssn WHERE u.id=ssn.user_id` | bare `Column` in a write scalar subquery |
| 2 | `UPDATE users u SET name=(SELECT ssn FROM orders ssn LIMIT 1) WHERE u.id=1` | `TableColumn` (qualify's whole-row form when the subquery has its _own_ FROM) |
| 3 | `UPDATE sink SET data=((d."U").ssn)::text FROM (SELECT users AS "U" FROM users) d` | quoted Dot field |
| 4 | `UPDATE sink SET data=((sub).ssn)::text FROM orders sub CROSS JOIN (SELECT users AS sub FROM users) d` | alias vs. relation-valued column |
| 5 | (read mirror of #2) `SELECT (SELECT ssn FROM orders ssn LIMIT 1) AS x FROM users u` | `TableColumn` in a read |

The same area over-denies in two ways, both fail-safe and both accepted for now.
Composite field access resolves field-precise but routes to `references`, so
`SELECT (u).ssn FROM users u` denies where `SELECT u.ssn FROM users u` masks.
And defining a relation-valued column sweeps the whole row, so `(d.sub).id` over
`(SELECT users AS sub FROM users) d` denies on `users.ssn` even though only the
non-PII `id` is read — `TestRelationValuedOverDeny` in
`analyzer/probe/relation_test.go` pins that behavior. Narrowing either is
unimplemented analyzer precision work.

The safety property is conservation, not enumeration: one resolver at every
consumption site. The analyzer consumes relations at several sites — the
whole-row / composite sweep over `TableColumn` and `Dot` nodes in `lineage()`,
and the write-side conservation sweep — all delegating to `relation.go`. A
per-site guard drifts; a single resolver cannot.

## 5. Worked examples (each resolved by the single resolver)

- #1 `(SELECT ssn) FROM orders ssn` (users in the write scope): chain =
  [subquery scope, write scope]. The subquery has no `ssn` column; walk to the
  write scope → `users` has column `ssn` → COLUMN (`users.ssn`) → a write reads
  a protected column → DENY. The `orders ssn` alias never wins.
- #4 `((sub).ssn)` with `orders sub` + derived `d(sub=users row)`:
  `relationOf("sub", …)` → in the write scope, the per-scope column check finds
  `d.sub` is a relation-valued column (the users row) → returns the `users`
  relation _before_ the `orders sub` alias check. Then `.ssn` → `users.ssn` →
  DENY.
- `SELECT (u).ssn`: `relationOf("u")` → `u` is a relation alias, no column `u`
  anywhere → the `users` relation. `.ssn` via `relationField` → `users.ssn`,
  `found=true` → field-precise (`users.ssn` alone, not the whole row), but it
  lands in `references` → DENY.
- `(d.sub).id` where `d.sub` = the users row: `relationOf("sub")` → the `users`
  relation; `.id` → `users.id`. The field resolves precisely, but defining
  `users AS sub` already swept the whole row into `references`, so `users.ssn`
  is there and the statement denies.
- `to_jsonb(u)`: `u` → `users` relation → tuple-expands to all users columns as
  function inputs → derived → `references` has `users.ssn` → DENY.

## 6. Data structures

- Relation handle — in Go, an `any` holding an `exp.Table` (physical) or an
  `*optimizer.Scope` (derived); a relation-valued column resolves _to_ one of
  those. `relResult` carries either the scalar base columns or that relation.
- Scope chain — `scopeChainFor(node)`: the node's own scope, otherwise its
  enclosing SELECT, then parents (correlation), then the native DML-root scope.
  One walk serves reads and write clauses such as SET and RETURNING.
- DML roots are complete-or-none. For UPDATE / DELETE / MERGE,
  `optimizer.BuildScope` builds a native root scope over the original DML AST
  that binds the write target plus every supported `FROM` / `USING` / `JOIN`
  source, with CTE, derived-table, and nested-query child scopes attached — so
  the same chain walk serves reads and writes without a synthesized `SELECT`. It
  yields a root only when the entire source graph is representable; a `nil` root
  (any source shape malformed or unsupported) is treated as DENY, because using
  a child scope as the statement scope would omit write sources and violate
  conservation. INSERT is not part of the native DML root; it flows through the
  SELECT / VALUES conservation paths over its query islands.
- The lineage output is unchanged by all of this — a maskable output stays a
  scalar identity in `origins`; a relation-as-value bottoms out into a set of
  `table.col` base strings in `references`. "Relation handle" and
  "relation-valued column" are purely _internal_ resolver concepts; the
  `ProbeResult` contract (`origins` / `references` / `isWrite` / `rewrittenSql`)
  does not change.

## 7. Tests

- `columnfirst_test.go` — the R1 column-first PoCs and variants.
- `relation_test.go`, `redteam_test.go` — whole-row / composite /
  relation-valued shapes. Every case touches `users.ssn`, so it must DENY, fail
  closed, or MASK — a case that resolves with `ssn` nowhere is a candidate
  cleartext leak.
- `cte_decoy_test.go` — a CTE name that _also_ exists as a physical decoy table
  binds to the CTE lineage, not the decoy.
- `probe/` golden + parity (against the Python sqlglot oracle), plus the
  `SELECT *` expansion suite.
- `GateSqlglotRegressionTest` in `:control-plane` is the end-to-end verdict
  coverage, driving the probe over a large SQL corpus.

Each PoC is cross-checked against live PG in a rolled-back transaction to
confirm PG actually streams or persists `ssn`.
