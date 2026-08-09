# Go emits the complete facts contract; Kotlin is a pure Cedar policy enforcer

All SQL understanding lives in Go. Kotlin never parses or classifies SQL — it
evaluates Cedar policy over a fully-formed facts contract Go emits: _"to run
this query the user needs `select`, and columns `a.b.c` and `d.e.f`, which bind
to output columns 0 and 1."_ Go provides the required grants; Kotlin follows the
list. No allowlists, no denylists, no token-level pattern matching, no
dialect-specific lexing on the Kotlin side. This is
[access-model.md](./access-model.md)'s "the engine states facts, Cedar sets
policy" principle taken to its full conclusion.

Kotlin does no SQL lexing or classification of any kind —
`grep -rn "SqlToken\|TokenKind\|tokenizeSql" engine/src` returns nothing. The
complete facts model and the Cedar resource semantics over it are in
[facts-emission.md](./facts-emission.md); this doc covers the contract Go emits
and how Kotlin walks it.

## The contract — no new Cedar vocabulary

Cedar's existing action ids (`sql.select`, `sql.insert`, `result.read.unmasked`,
`result.read.masked`, `datasource.connect`, `sql.unanalyzable`, …) and resource
EUID shapes (`Table::"ds/cat/schema/tbl"`, `Column::"…/col"`,
`Function::"ds/name"`, `Utility::"ds/command"`) already say everything needed.
Nothing new is invented in Cedar or in policy files. What changes from a
hand-written evaluator is who computes the list of things to check: Go emits the
complete list once, and Kotlin's entire job is a generic walk over it.

### Wire format — protobuf both directions

The analyzer↔JVM boundary (`cmd/libsqlglot` ↔ the `analyzer/jvm` FFM binding) is
real proto messages, one byte buffer in and one out, both directions — no
hand-rolled JSON at this boundary. `protoc-gen-go` generates the Go bindings and
the `com.google.protobuf` Gradle plugin generates the Kotlin ones from the same
`proto/src/main/proto/analyzer.proto`, so schema drift is a compile-time
mismatch, not a silent runtime one. The catalog crossing the boundary is a flat
`repeated ColumnSpec` (matching what Kotlin already holds), not a nested tree,
so Go builds its own `schema.Mapping` from the flat list directly.

### Message shape

Both request and response messages live in `proto/src/main/proto/analyzer.proto`
— read it directly rather than a copy here that could drift. In short:

- Request: `AnalyzeRequest` carries `sql`, `namespace` (catalog + search_path),
  the flat `catalog`, and `engine_config` (engine identity, version string,
  MySQL's `lower_case_table_names` — built once and reused for parsing,
  normalization, qualification, and generation).
- Response: `StatementFacts` carries `resolved`, `failure_class`,
  `statement_class`, `required_grants`, `output_columns`, `is_write`,
  `rewritten_sql`, `explain_of_query`, `catalog_changing`, and the physical
  `sources`/`functions`. Each `RequiredGrant` is a `GrantAction` plus a `oneof`
  resource (Column/Table/Function/Utility/Datasource), a `MaskedDisposition`,
  and the `output_ordinals` it gates.

### Worked examples

1. An ordinary masked, joined SELECT with a predicate:
   `SELECT users.ssn, orders.amount FROM users JOIN orders ON users.id = orders.user_id WHERE users.region = 'KR'`.
   `users.ssn` is PII (masked), `users.region` is used only in a predicate
   (non-output, non-maskable — a masked predicate value cannot be evaluated),
   `orders.amount` is ordinary (no grant emitted for it — absence of a
   requirement, not a satisfied one). Go emits `sql.select` on the datasource, a
   `result.read` on `Column users.ssn` with disposition `MASK_OUTPUT` gating
   output ordinal 0, and a `result.read` on `Column users.region` with
   disposition `DENY_STATEMENT` gating no output. Kotlin's walk: `sql.select`
   allowed; `users.ssn` denied but maskable → mask output column 0;
   `users.region` denied and non-maskable → whole query denied. No further
   grants need checking once a non-maskable deny is hit.

2. A session-privilege change — `SET ROLE analyst`. This is not a special Kotlin
   code path. Go recognizes the shape and emits a `Utility` grant naming the
   command (`Utility::"ds/SET_ROLE"`). Kotlin hands it to `authorizeUtilities`;
   the system-classification manifest tags the command `system:critical`, and
   the shipped bootstrap forbid
   (`forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource) when { resource in Tag::"system:critical" }`)
   denies it — a forbid that wins over any read grant. Same outcome as a hard
   deny, but the decision lives entirely in Cedar. Because `system:critical` is
   never relaxed (even on a `system:development` datasource, unlike
   `system:activity`/`system:data-leak`), a session-privilege escalation or
   lexer mutation is denied everywhere.

3. A genuinely unresolvable statement — MySQL's `EXPLAIN FOR CONNECTION 7`. It
   is a valid server command that sqlglot-go does not structure, so Go emits
   `resolved=false`, `failure_class=UNANALYZABLE`, `failed_stage=PARSE`,
   `detail="unsupported command EXPLAIN"`, and no grants at all. With nothing to
   walk, Kotlin routes it through the `sql.unanalyzable` gate like any other
   unresolvable statement (fail-open on `system:development`, fail-closed on
   production, grant-overridable).

4. A structurally-safe passthrough — `BEGIN`. No table, column, or function
   touched, so Go emits `resolved=true`, `required_grants=[]`,
   `statement_class=SESSION`. Kotlin's loop has nothing to check and falls
   through to ALLOW. "No grants required" _is_ the passthrough signal,
   generically — no SQL-shape knowledge in Kotlin.

## The deny taxonomy

Authorization belongs to Cedar. `decideQuery` may deny in code only for genuine
impossibility; every policy decision is a Cedar verdict. Four outcomes:

- Authorized / masked — the grant walk. Each `RequiredGrant` is a Cedar
  `authorize*` verdict (datasource connect, `sql.<kind>`, column/table
  `result.read`, utility, function). A maskable column deny masks; a
  non-maskable deny fails the query. (Examples 1, 4.)
- Danger → a `system:critical` Cedar forbid. Session-privilege / lexer-mutation
  SETs, user-type/DOMAIN casts, and data-reading SET/SHOW emit a `Utility` grant
  with a fixed command id (`SET_ROLE`, `SET_SESSION_AUTHORIZATION`,
  `SET_SQL_MODE`, `SET_STANDARD_CONFORMING_STRINGS`, `USER_TYPE_CAST`,
  `SET_SUBQUERY`, `SHOW_SUBQUERY`) the manifest tags `system:critical`; the
  shipped bootstrap forbid denies it unconditionally. These deliberately do not
  use the Function path — an arbitrary user type or function is in no manifest,
  so a Function grant would hit the no-classifier deny rather than the
  `system:critical` floor; a fixed Utility command routes straight to the floor.
  Never a Kotlin hard-deny, never a new resource kind or tag. (Example 2.)
- Uncertainty → `sql.unanalyzable`. Anything Go cannot analyze — an
  unknown-but-engine-valid command, a `Command`/parse-error, a catalog gap, or
  an infra failure (analyzer build, catalog-coverage, mask-fn load) — is
  `resolved=false` and routes through the `sql.unanalyzable` gate: fail-closed
  by default, grant-overridable, fail-open on dev. An admin holding
  `sql.unanalyzable` can relay a valid command Go does not recognize — the
  engine-forward case is a policy grant, not a code wall. Catalog-coverage is
  decided by this gate too, so relaying an unclassified column requires the
  grant. (Example 3.)
- Genuine impossibility → a structural code deny. Only a malformed / corrupt
  analyzer output — a grant with no resource, an out-of-range mask ordinal, a
  missing disposition. A resolved analyzer never emits these; the structural
  deny is a fail-closed defense against an analyzer/wire bug. This is the only
  legitimate code deny.

Multi-statement batch (`SELECT 1; SELECT 2`) is currently a structural deny —
the analyzer processes one statement at a time. It should route through Cedar
like everything else once multi-query support lands; tracked as a limitation,
not the intended end-state.

## What Kotlin does

`decideQuery` (`Query.kt`) has no `SqlKind` enum, no passthrough class, no
token-level pattern matching. It analyzes the statement in one Go call, then
walks the emitted grants:

```kotlin
val facts = analyzeStatement(sql, namespace, catalog, engineConfig) // one Go call
if (!facts.resolved) return unanalyzableOrInadmissible(facts)       // sql.unanalyzable gate, or hard deny
// datasource.connect, then each required grant against Cedar:
//   column deny + maskable  -> add a mask for its output ordinals
//   column deny + non-maskable, or table/function/utility deny -> deny the statement
// no denies -> ALLOW (or MASK if any masks were collected)
```

`decideQuery` groups the grants by resource type and authorizes them through
`authorizeColumns` / `authorizeTables` / `authorizeFunctions` /
`authorizeUtilities` and `authorizeDatasourceAction`, but the shape is one
uniform, Go-computed list rather than fields hand-assembled from several probe
outputs.

## How Go classifies notable statement shapes

Most checks are plain structural facts read off the parse tree: the coarse
statement kind (`root.Kind()`), REPLACE INTO and MERGE, upsert
(`ON DUPLICATE KEY UPDATE` / `ON CONFLICT … DO UPDATE`), temporary DDL,
`SELECT … INTO`, transaction boundaries, and every function call (a visible node
→ a function fact → the dangerous-function gate). A few shapes need specific
handling:

### Executable comments and optimizer hints

MySQL's `/*! … */` executable version comments are analyzed normally, not
rejected. With the real `Dialect.MySQLVersion` set (from `engine_config`),
`SELECT 1 /*!50700 , ssn */ FROM users` regenerates as
`SELECT 1, ssn FROM users` — `ssn` becomes a real, traceable column, and the
normal lineage/grant machinery decides. `/*+ … */` optimizer hints are inert
comments to sqlglot-go: their content round-trips untouched and is never
inspected, exactly like any other comment.

### EXPLAIN / DESCRIBE

`EXPLAIN ANALYZE` executes its inner query, so an EXPLAIN-of-a-query is decided
on that inner statement (inheriting its DENY/MASK/ALLOW), while a
DESCRIBE-of-a-table is table metadata. The leading keyword does not distinguish
them — on MySQL `EXPLAIN`/`DESCRIBE`/`DESC` are synonyms, so `EXPLAIN users`
describes the table and `DESCRIBE SELECT …` explains a query. Both parse to a
`Describe` node; the classifier reads two args in order:

1. `Describe.kind == "TABLE"` → EXPLAIN of a query, not a table describe.
   MySQL's `TABLE t` is shorthand for `SELECT * FROM t`, so `EXPLAIN TABLE t`
   scans `t`. Checking `this.Kind()==Table` alone would misclassify this as
   harmless metadata and let the scan bypass lineage — a leak. So
   `kind=="TABLE"` is decided first and routed as a query-explain over the
   scanned table.
2. else `Describe.this.Kind() == Table` → describe of a table (metadata; allow),
   including the column/wildcard forms `DESCRIBE tbl col` /
   `DESCRIBE tbl 'wild%'`. The column slot is a single identifier only:
   `DESCRIBE t (SELECT …)`, a function, a cast, `a.b`, or a reserved word all
   fail closed to `Command`, so no subquery can hide behind `this:Table`.
3. else `Describe.this.Kind()` is a statement kind
   (Select/Insert/Update/Delete/Merge/…) → EXPLAIN of a query → decide on that
   inner statement.
4. else → fail closed.

A few valid spellings degrade to `Command` rather than a `Describe` node
(`EXPLAIN FOR CONNECTION n`, PostgreSQL `EXPLAIN EXECUTE stmt`) and land in the
fail-closed bucket — an accepted over-deny, never a leak.

### Privilege-escalation SETs — two spellings, both required

A privileged SET can reach the session two ways, and both must deny. Both now
structure as a `Set` node (sqlglot-go structures the keyword forms too); Go
handles them in `sessionIdentitySetCommand` on the structured-Set path:

- Keyword form (`SET ROLE`, `SET DEFAULT ROLE`, `SET SESSION AUTHORIZATION`) — a
  `SetItem` whose `kind` is `ROLE` / `DEFAULT ROLE` / `SESSION AUTHORIZATION`.
  Emits `SET_ROLE` / `SET_DEFAULT_ROLE` / `SET_SESSION_AUTHORIZATION`.
- GUC-alias form (`SET role = x`, `SET session_authorization = x`,
  `SET SESSION role = x`, `SET LOCAL session_authorization = x`) — a structured
  `Set` whose assignment LHS variable name (case-insensitive, so quoted `"role"`
  too) is `role` or `session_authorization`/`authorization`. Same command ids as
  the keyword forms.

A `SET` that still degrades to `Command` (sqlglot-go did not structure it) is
fail-closed as INADMISSIBLE on both engines — never a privileged-keyword scan of
`Command.expression`. Benign structured SETs (`SET TIME ZONE 'UTC'`,
`SET CONSTRAINTS …`) stay SESSION passthrough.

### Unicode-escape identifiers

PostgreSQL's `U&'…'` / `U&"…"` literals are decoded by sqlglot-go's tokenizer,
so the escaped spelling and the plain one analyze identically.
`SELECT U&"ssn" FROM users` emits the same masked `result.read` on `users.ssn`
as `SELECT ssn FROM users`, and `SELECT ssn FROM U&"users"` resolves the same
table. Nothing is special-cased in Go: the decoded name enters the ordinary
lineage and function machinery.

The security consequence is that an escaped dangerous-function name cannot hide.
`SELECT U&"set_confi\0067"('search_path','x',false)` decodes to `set_config`,
resolves (`resolved=true`, `statement_class=ANALYZED`), and emits a real
`Function` grant naming `set_config`. The PostgreSQL classification manifest
(`engine/src/main/resources/system-classification/postgres/17.json`) tags
`pg_catalog.set_config` `system:critical`, so `authorizeFunctions` marshals the
`system:critical` tag as a Cedar parent and the shipped `system:critical-guard`
forbid denies it — the same path any unescaped `set_config` call takes.

### Fail-closed shapes

`Command` means sqlglot-go did not structurally understand the statement;
`Command.this` is the uppercased leading keyword and `expression` the raw tail.
`CALL`, MySQL `RESET MASTER`/`RESET BINARY LOGS AND GTIDS`, and unstructured
`Command`-SET are not recognized safe roots and fail closed. PostgreSQL
Unicode-escape literals are not on this list: sqlglot-go decodes them, so
`U&'…'` and `U&"…"` analyze normally and their decoded identifiers are gated
like any other name (see
[Unicode-escape identifiers](#unicode-escape-identifiers)). MySQL
`SHOW CREATE USER` is a structured `Show` and emits `SHOW_CREATE_USER`.
PostgreSQL `RESET ALL` is a benign SESSION passthrough (structured `Reset` or
Command-RESET on PostgreSQL).

## Verification

- `go test ./analyzer/probe/...` and the full DB-backed gate
  (`mise run verify`).
- The documented leak cases each deny under the grant walk:
  `SELECT query_to_xml('SELECT ssn FROM users')`,
  `SET @x = (SELECT ssn FROM users)`, `DESC ANALYZE SELECT …`, MySQL
  `RESET MASTER`, `SHOW WARNINGS` surfacing an unmasked prior value,
  `EXPLAIN TABLE t` as a row-scanning query-explain, and the GUC-alias privilege
  SETs `SET session_authorization = attacker` / `SET SESSION role = attacker` /
  `SET role = attacker` / `SET LOCAL session_authorization = attacker` (denied
  via the LHS-variable-name check).
- `U&"set_confi\0067"(…)` denies by a different mechanism, not fail-closed
  uncertainty: the identifier decodes to `set_config`, the statement resolves,
  and the emitted `Function` grant is denied by the `system:critical` forbid
  (see [Unicode-escape identifiers](#unicode-escape-identifiers)).
  `GateSqlglotRegressionTest` asserts the end-to-end deny.
- Live re-check against the running demo stack: masking works,
  `BEGIN`/`SET`/ordinary passthrough statements relay, deny cases deny.
