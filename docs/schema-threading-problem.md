# Schema-aware enforcement keys ("schema threading")

Every physical column has one five-part resource identity that the mapping,
analyzer lineage, catalog lookup, classification, audit, and Cedar all share.
This doc defines that key and the fail-closed resolver that produces it.
[mapping-schema-construction.md](./mapping-schema-construction.md) builds the
depth-3 mapping this uses; [connection-model.md](./connection-model.md) and
[per-connection-catalog.md](./per-connection-catalog.md) resolve the key against
a connection's live namespace and catalog.

## The key

```
<datasource>/<catalog>/<schema>/<table>/<column>
```

The analyzer works in `catalog.schema.table.column`; the control plane prepends
the datasource name when constructing Cedar EUIDs:

```
Table::"<datasource>/<catalog>/<schema>/<table>"
Column::"<datasource>/<catalog>/<schema>/<table>/<column>"
```

- PostgreSQL: `acme-pg/acme/public/users/ssn`
- MySQL: `acme-mysql/def/app/users/ssn`

The sqlglot mapping is depth 3 (`catalog → schema → table → column`). The
analyzer resolves every physical table exactly once during sqlglot qualification
and emits only fully-qualified lineage keys. Kotlin builds the same normalized
keys from structured catalog fields; it never parses, truncates, or guesses from
analyzer strings. Every emitted key must match exactly one catalog row or the
query is denied.

## End-to-end contract

### Introspection owns the static namespace

Each successful datasource introspection atomically replaces the catalog and
records:

- PostgreSQL: `defaultSchemas` = the fresh connection's ordered
  `current_schemas(true)`; catalog = the datasource's bound `dbName`;
  `mysqlLowerCaseTableNames = null`.
- MySQL: `defaultSchemas` = the one-element current-database list; catalog =
  `"def"`; `mysqlLowerCaseTableNames` = the server's `@@lower_case_table_names`.

`CatalogColumn` exposes the real levels — PostgreSQL its bound database + real
schema; MySQL `def` + the real database name as schema (no MySQL database is
relabeled `public`). Until an existing datasource is re-introspected under this
metadata, schema-aware analysis has no valid namespace snapshot and fails
closed.

A classification write that omits `schema` targets the datasource's first
non-system schema from that captured `defaultSchemas`; it never defaults to
`public`, and fails closed with `datasource.schema_required` when no default has
been captured. The catalog level is derived, never caller-selectable.

### Analyzer inputs are structured protobuf

The analyzer boundary (`AnalyzeRequest` in `analyzer.proto`) receives four
inputs: SQL, a `Namespace` descriptor (`catalog` + ordered `search_path`), a
flat `repeated ColumnSpec` catalog (Go nests it into the depth-3 mapping), and
an `EngineConfig` (engine identity, version, and — for MySQL —
`mysql_lower_case_table_names` / `mysql_ansi_quotes`). Each catalog column
carries structured `catalog`, `schema`, `table`, `column`, and SQL-type fields.
The namespace descriptor is the namespace observed at introspection (or the
connection's live path on the wire), not a claim about an arbitrary long-lived
backend session.

### Go resolves physical tables once

During sqlglot qualification the analyzer fills a resolution report and stamps
each physical table exactly once:

- `catalog.schema.table` must match that exact catalog row.
- `schema.table` uses the captured default catalog + the explicit schema.
- bare `table` walks the ordered `search_path` under the captured default
  catalog (first schema that holds the table wins).
- CTEs, derived tables, and aliases stay scoped logical relations; they are not
  rebound as same-named physical tables.
- an unknown schema/table, a foreign catalog, or any name that cannot resolve to
  exactly one physical table is an analysis failure → DENY.

The resolver stamps the selected catalog/schema onto the physical table node.
Downstream lineage reads the stamped identity instead of re-resolving bare
names.

### Analyzer output is fully qualified

Origins and references expose only `catalog.schema.table.column`. No output uses
`table.column`, and no downstream caller shortens a key — this applies to
outputs, predicates, joins, grouping/ordering/aggregates, stars, writes, and DML
clauses.

### The control plane exact-matches catalog rows

The control plane builds a normalized catalog key from the row's structured
fields and looks up each analyzer key directly — no `split('.').takeLast(...)`,
alias text, or fallback scan by bare table/column. Conservation is fail-closed:

```
every emitted lineage key -> exactly one catalog row -> Cedar resource
anything else             -> DENY
```

Cedar entities then use the datasource's stable name plus all four physical
parts, e.g. `Column::"acme-pg/acme/public/users/ssn"` and
`Column::"acme-mysql/def/app/users/ssn"`.

## Worked example

`SET search_path = restricted, public; SELECT ssn FROM users` on `acme-pg`. The
resolver takes the connection's effective path (`restricted, public`), resolves
bare `users` to the first schema that holds it — `restricted.users` — and stamps
it. Lineage emits `acme/restricted/users/ssn`. The control plane matches that to
exactly one catalog row and asks Cedar about
`Column::"acme-pg/acme/restricted/users/ssn"`. If `restricted.users.ssn` is PII,
the verdict masks or denies it — not the `public.users` a datasource-global
default would have authorized.

## Identifier normalization

One shared contract across introspection, mapping construction, Go output,
Kotlin key construction, and catalog lookup:

- PostgreSQL: unquoted identifiers fold to lowercase; quoted identifiers
  preserve exact spelling.
- MySQL columns: compare case-insensitively.
- MySQL schemas/tables: follow the introspected `lower_case_table_names` mode —
  `0` preserves case-sensitive identity; `1` and `2` compare through lowercase
  keys.

The proxy never infers MySQL behavior from its own OS; the target server's
captured mode decides it. goproxy normalizes every catalog identity at
introspection (`NormalizeRelation`) before the control plane stores it; key
matching concatenates already-canonical parts.

## Security invariants

1. One identity everywhere — mapping, analyzer lineage, catalog lookup,
   classification, audit, and Cedar all name the same
   `catalog.schema.table.column`.
2. Resolve physical relations once — every downstream path consumes the stamped
   identity; no path re-derives schema/catalog from alias or token text.
3. Exact match or DENY — unknown, foreign-catalog, ambiguous, missing, or stale
   identities never fall back to a shorter key.
4. Real MySQL database names — `app.users` and another database's `users` are
   distinct resources under the same `def` catalog.

## Verification

Live PG/MySQL DB-backed tests cover qualified and bare names, same-named tables
across schemas/databases, foreign catalogs, CTE/derived-table shadowing, DML and
stars, MySQL case modes, exact catalog matching, and migration re-introspection.

## Live-connection resolution

The static resolver produces correct keys against a snapshot namespace — the
schema captured at introspection and a fixed default path. A long-lived wire
connection diverges from that snapshot through `SET search_path` / `USE`,
`pg_temp`, and post-introspection DDL.
[connection-model.md](./connection-model.md) resolves each statement against the
connection's live namespace, and
[per-connection-catalog.md](./per-connection-catalog.md) keeps the enforcement
catalog transactionally current per connection, so the same fully-qualified key
stays correct on the wire.

## Known limitations

Accepted caveats (`.`/`/`-bearing identifiers denied) and residual gaps
(zero-column system-table scans, catalog freshness on upgrade/datasource change,
request-EUID uniqueness) are recorded in
[KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md).
