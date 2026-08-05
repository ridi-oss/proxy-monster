# Statement classification — design proposal

Status: **proposal**, not built. This replaces the way a statement's kind is
decided and gated today. It does not change masking, lineage, or the Cedar
principal/role model — only how "what kind of statement is this" is represented
and authorized.

## The problem

There is no explicit statement kind. A statement's kind is whatever sqlglot's
parser node happens to be (`Select`, `Command`, `Transaction`, `Alias`), which
is a parser taxonomy — incomplete (`Command` is a catch-all), leaky (the
`Alias`/`Column`/`Transaction` misparses), and not ours to own.

And the "category" is smeared across three fields of `StatementFacts`:

- `GrantAction` — the five `sql.*` verbs, on a datasource grant;
- `StatementClass` — `session` / `metadata` / `analyzed`, a separate field;
- a `Utility` resource tag (`SET_ROLE`, `SHOW_PROCESSLIST`) — a third mechanism.

So "what kind of statement is this?" has no single answer, and sensitivity is
decided per statement, inline in `facts.go`: `SET ROLE` gets a utility tag and
is gateable, `SET NAMES` gets nothing and is a bare `session` passthrough. The
consequence is that **"silently allowed" is a reachable state** — a statement
the analyzer does not explicitly recognize lands in a passthrough and runs with
connect only. `START REPLICA` reaching that state (a parser misparse into
`Transaction`) is not a one-off; it is what this design removes.

## The model

Two layers.

**Statement kind** — a single, exhaustive, flat, granular enum PM owns. One kind
per statement, with content distinctions baked in rather than carried as flags:
`select` and `select_into_outfile` are separate kinds, so are `insert` and
`insert_on_dup`. The parse feeds the classification; anything PM cannot classify
is `stmt_unknown`. Fail-closed is structural, not luck.

**Category** — a declarative `kind → category` map, the coarse policy handle. A
category is the statement's **domain** — `read`, `write`, `ddl`, `session`,
`metadata`, `admin` — so sensitivity is a property of the domain, not a
hand-labeled `benign`/`sensitive` tier. `admin` has no loose members: it nests
sub-families for accounts, replication, process control, server config,
maintenance, plugins, locking, file I/O, dynamic execution, and unanalyzable
primitives. Every kind belongs to exactly one category, and a category may nest
(`write.insert` within `write`, `admin.account` within `admin`), so a policy
gates one kind, a leaf category, or a whole domain.

A statement is authorized against **both**: its kind and its category are in
scope, and a policy may target either.

## The kind enum, by category

Flat granular — the content distinctions are kinds, so the `kind → category` map
below is a pure lookup with no logic. Representative, not the full set; the
coverage test (`analyzer/probe/mysql_statement_coverage_test.go`) is the
authority and enforces exhaustiveness.

<!-- prettier-ignore -->
| Category | Kinds |
| --- | --- |
| `read` | `select`, `table`, `values`, `with_select`, `set_op` (union/intersect/except) |
| `write.insert` | `insert`, `insert_select`, `insert_on_dup` (also `write.update`) |
| `write.update` | `update` |
| `write.delete` | `delete`, `replace` (delete+insert) |
| `ddl` | `create_table`, `create_view`, `create_index`, `alter_table`, `drop_table`, `truncate_table`, `rename_table`, … (every CREATE/ALTER/DROP/TRUNCATE of a schema object) |
| `session` | `start_transaction`, `commit`, `rollback`, `savepoint`, `set_transaction`, `set_var`, `set_names`, `set_charset`, `use` — connection-local, exposes no rows/credentials, changes no privilege |
| `metadata` | `show_tables`, `show_columns`, `show_create_table`, `describe`, `explain_table`, … — schema introspection that exposes no rows, credentials, or topology |
| `admin.account` | `create_user`, `alter_user`, `drop_user`, `rename_user`, `create_role`, `drop_role`, `grant_priv`, `grant_role`, `revoke_priv`, `revoke_role`, `set_password`, `set_role`, `set_default_role`, `show_grants`, `show_create_user` |
| `admin.replication` | `change_replication_source`, `start_replica`, `stop_replica`, `reset_replica`, `start_group_replication`, `purge_binary_logs`, `reset_master`, `set_sql_log_bin`, `binlog`, `show_master_status`, `show_binary_logs`, `show_binlog_events`, `show_replica_status`, `show_replicas` |
| `admin.process` | `kill`, `show_processlist`, `show_engine_status` — the MySQL PROCESS privilege: inspect and terminate other sessions |
| `admin.server` | `shutdown`, `restart`, `flush`, `clone`, `set_global`, `set_persist`, `set_resource_group` — lifecycle, reload, and global/persistent config |
| `admin.maintenance` | `analyze_table`, `check_table`, `optimize_table`, `repair_table`, `cache_index` — table upkeep |
| `admin.plugin` | `install_plugin`, `install_component` (and their uninstall forms) — server extensions |
| `admin.lock` | `lock_tables`, `unlock_tables`, `lock_instance`, `unlock_instance` — explicit locking |
| `admin.file` | `select_into_outfile`, `select_into_dumpfile`, `load_data`, `load_xml` — FILE-privilege I/O across the server-filesystem boundary: export of query results (a data-exfil path) and import into a table (`load_data` also writes rows) |
| `admin.exec` | `prepare`, `execute`, `call`, `do` — dynamic execution: they run SQL or code the analyzer cannot see (a prepared string, a stored routine, an expression) |
| `admin.unanalyzable` | `handler`, `xa` — opaque primitives the analyzer cannot decompose (`handler` = raw storage-engine row read that bypasses masking; `xa` = distributed-transaction control) |
| `sql.unanalyzable` | `stmt_unknown` — anything the analyzer could not classify; gated by the deny-by-default `sql.unanalyzable` exception, not a `stmt.cat.*` category |

A domain holds both reads and writes of its resource — `show_grants` and
`grant_priv` are both `admin.account`; `show_master_status` and `start_replica`
both `admin.replication`. That is deliberate: both need the same entitlement.
For finer control a policy targets the kind (`stmt.kind.show_grants`); an
`admin.account.read` / `admin.account.write` split can come later if a real
policy needs one.

## How Cedar gates on either

Cedar action-group membership is transitive, so the kind→category hierarchy is
modelled directly. Each **kind is an action** `stmt.kind.<kind>`; each
**category is an action group** `stmt.cat.<path>`; every level nests into its
parent — a kind into its category, a sub-category into its domain:

```cedarschema
action "stmt.kind.insert"      in ["stmt.cat.write.insert"];
action "stmt.cat.write.insert" in ["stmt.cat.write"];
```

A policy targets any level — one kind, a leaf category, or a whole domain — and
transitivity carries it down the tree:

```cedar
// coarse: forbid every write
forbid(principal, action in Action::"stmt.cat.write", resource);

// narrower: only inserts
forbid(principal, action in Action::"stmt.cat.write.insert", resource);

// precise: permit exactly INSERT for one role
permit(principal in Role::"loader", action == Action::"stmt.kind.insert", resource);
```

The `stmt.kind.` / `stmt.cat.` split keeps the two layers legible in a policy —
`stmt.kind.*` is one concrete statement, `stmt.cat.*` is a domain — and both
stay in the `stmt` namespace, distinct from `result.read.*` / `datasource.*`.
This is native Cedar: `action in <group>` is how the shipped `result.read.*`
forbids already work, just several levels deep, so it validates on the same
cedar-java path. Policies gate on `stmt.cat.*` / `stmt.kind.*` directly; there
is no separate `sql.<verb>` vocabulary, so a policy that names one fails
validation rather than validating and then silently matching nothing.

## Where each layer lives

- **Kind** — a `StatementKind` enum, a new field on `StatementFacts`
  (`proto/…/analyzer.proto`). The parse and the disambiguation that already
  distinguishes `SET ROLE` from `SET NAMES` both happen in the Go analyzer, so
  the kind is assigned there and carried across the FFM/proto boundary. Additive
  — no wire break.
- **Category** — the `kind → category` map is data in the control-plane, and the
  schema's action-group membership. One table, one place.

## Fail-closed, and grantable

`STMT_UNKNOWN` is not a hardcoded deny, and it gets no category of its own: it
is gated by the existing `sql.unanalyzable` exception — the same
deny-by-default, per-datasource-overridable gate an unanalyzable statement
takes. The production floor carries no `sql.unanalyzable` permit, so it denies;
a datasource that permits it (a dev datasource, a trusted operator) runs it.
`GRANT_ACTION_UNSPECIFIED` (the REPLACE/CALL sentinel) folds into the same gate.
Reusing the existing exception rather than a distinct `stmt.cat.unknown` keeps
an existing `sql.unanalyzable` policy working and leaves one fewer domain to
reason about. A `forbid` would be wrong: it cannot be overridden by a permit,
which would make an unclassified statement permanently un-grantable.

The gain over today is structural. The current design lets an _unrecognized_
statement reach a benign passthrough and run with connect only; here an
unclassified statement is `stmt_unknown`, which denies by default like every
other gated kind unless a policy grants it. The analyzer never enumerates the
dangerous statements to be safe — it enumerates the safe ones to be permissive,
the correct direction. The coverage test guards the enum: a MySQL statement kind
with no `StatementKind` fails the build.

## Migration

1. Add `StatementKind` to the proto; the Go analyzer assigns it alongside the
   grants it already emits (no removal yet — both coexist).
2. Add the `kind → category` map and the action-group schema in the CP.
3. Move the shipped presets from the `sql.*` actions to the category groups; the
   effective decisions are unchanged (verified by the policy-posture digest
   test).
4. Once policies are on the new actions, retire `StatementClass`'s use as a
   category signal and the per-statement utility-tag sensitivity hacks. The
   `Utility` resource stays for the genuine resource-bearing commands.

## Open questions

- **Kind assignment for the still-unsupported statements** — the ones sqlglot
  parse-errors on today become `stmt_unknown` unless sqlglot grows to parse
  them. That is correct (they deny by default), but it means some
  `admin.account`/`admin.replication` kinds only populate once sqlglot emits a
  `Command` (or a typed node) for them. The pending sqlglot fixes move several
  from parse-error to `Command`, at which point PM can classify them.
