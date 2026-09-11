# Constructing the sqlglot MappingSchema for a datasource's catalog

Given a datasource's full, multi-schema catalog, the analyzer builds a faithful
depth-3 sqlglot `MappingSchema` for PostgreSQL and MySQL. This doc owns
construction; [schema-threading-problem.md](./schema-threading-problem.md) owns
physical-name resolution and key construction, and
[connection-model.md](./connection-model.md) owns the live per-connection
namespace.

## The level model

Datasource, catalog, and schema are three distinct levels. The resource key is
five-part:

```
<datasource>/<catalog>/<schema>/<table>/<column>
```

Canonical: a PG datasource `acme-pg` bound to database `acme`, schema `public`,
table `users` → `acme-pg/acme/public/users`; MySQL is
`acme-mysql/def/app/users`. `<datasource>` is a proxy label you choose;
`<catalog>` is the real database name a query would write (`acme.public.users`).

On PG and MySQL a datasource maps to one sqlglot catalog (PG: the bound
database; MySQL: the singleton `def`), so `<catalog>` is constant. The level
that actually disambiguates is the schema (sqlglot `db` = a PG schema or a MySQL
database). Modeling `<catalog>` as its own level anyway means adding a federated
engine later — Athena/Trino, where one connection spans many catalogs — is a
data change (the catalog gains real values and cross-catalog joins resolve
natively), not a key or Cedar-policy migration.

Concept alignment across systems:

<!-- prettier-ignore -->
| level | ANSI SQL | sqlglot | proxy-monster | PostgreSQL | MySQL | Athena / Trino |
| --- | --- | --- | --- | --- | --- | --- |
| (connection) | — | — | `<datasource>` | the connection | the connection | the connection (workgroup) |
| top container | catalog | `catalog` | `<catalog>` | database (bound, isolated) | `def` (singleton) | catalog = connector (`awsdatacatalog` + federated, many) |
| namespace | schema | `db` | `<schema>` (disambiguator) | schema (`public`/`pg_catalog`/`information_schema`/user) | database (bound db/`information_schema`/`mysql`) | schema (Athena calls it "database") |
| relation | table | `this` | `<table>` | table | table | table |
| attribute | column | — | `<column>` | column | column | column |
| cross-catalog in one connection? | — | — | — | no (needs FDW) | n/a (one catalog) | yes (federation) |

Two confusions this kills: a PG "database" is a _catalog_ while a MySQL
"database" is a _schema_; and sqlglot names the middle level `db` even though it
is the ANSI schema level.

`datasource = catalog` is engine-specific, not a law. The deciding question is
whether one connection can query across top-level containers: isolated-catalog
engines (PostgreSQL, Oracle — one database per connection, crossing needs
FDW/db-links); single-catalog multi-schema (MySQL — one `def` catalog,
cross-database queries work); federated multi-catalog
(Athena/Trino/BigQuery/Snowflake/SQL Server — one connection spans many
catalogs, cross-catalog is a feature). All share the same depth-3 shape; the
difference is a single-valued vs multi-valued catalog, which the mapping already
accommodates.

## Depth-3 mapping

Build `{ <catalog> : { <schema> : { <table> : { <column> : <type> } } } }`,
matching the key. `<catalog>` is PG's bound db name or MySQL's `def`; `<schema>`
uses the real MySQL database names (no `"public"` relabel). Modeling the catalog
— rather than stamping a constant — buys:

- Uniform resolution. sqlglot carries `catalog` through like `schema`; the probe
  reads `catalog.schema.table` off the resolved node — one code path, no
  constant-stamping special case.
- Fail-closed on a foreign catalog, for free. `wrongdb.public.users` won't
  resolve unless `wrongdb` is the datasource's catalog → sqlglot errors → DENY.
  No separate catalog-validation step.

Include every introspected schema: user schemas plus the exposed system schemas
(`information_schema`, `pg_catalog`, …).

Introspection also captures a static namespace descriptor — `catalog` and the
ordered `searchPath` — plus, separately on `EngineConfig`, MySQL's
`mysqlLowerCaseTableNames` (and engine version / ANSI_QUOTES). The analyzer
receives those alongside the flat catalog column list, builds the depth-3
mapping in Go, resolves each physical table once during qualification, stamps
its catalog+schema, and then emits only `catalog.schema.table.column` lineage
keys.

## Construction

Input: the curated catalog as flat `Column` rows
`(catalog, schema, table, column, dataType)` across every introspected schema;
an empty catalog means the namespace catalog (which system relations are
included is the access-model curation's call —
[access-model.md](./access-model.md)). Go nests them into a depth-3
`schema.Mapping` (`analyzer/probe/wire.go`):

```
mapping := schema.NewMapping()                     // sqlglot-go schema pkg — depth-3
for each Column col:
    schemas := getOrNewMapping(mapping, col.catalog)
    tables  := getOrNewMapping(schemas, col.schema)
    cols    := getOrNewMapping(tables,  col.table)
    cols.Set(col.column, col.dataType)
// normalize = eng.NormalizeCatalogOnBuild(): true for MySQL, false for PostgreSQL
ms, _ := schema.NewMappingSchema(mapping, dialect, normalize)

namespace := {
    catalog:    catalogName,
    searchPath: introspectedOrderedSchemas,
}
// engine_config carries mysqlLowerCaseTableNames (MySQL) / version / ansi_quotes.
// Qualify + the resolution report stamp physical tables; lineage emits FQ keys.
```

Two rules the construction must hold:

- Register every column, whatever its type. Pass the real `dataType` strings —
  sqlglot parses them per dialect for column existence, `SELECT *` expansion,
  and validation. On push, the control-plane maps raw DB type names through
  `sqlTypeFor` (unknown/unparseable types fall back to `VARCHAR`); never
  silently drop a column, because a dropped real column (especially PII) goes
  unrecognized → fail-open leak. For lineage the type is cosmetic; the column's
  presence is load-bearing.
- Normalize once, shared. `NormalizeCatalogOnBuild` with the correct dialect
  plus the introspected case mode. PostgreSQL folds unquoted identifiers to
  lowercase at query time and preserves quoted spelling; the catalog itself is
  not re-folded on build. MySQL column names are case-insensitive; schema/table
  matching follows `@@lower_case_table_names` — mode `0` preserves
  case-sensitive identity, modes `1` and `2` compare through lowercase keys.
  goproxy normalizes catalog identities at introspection via
  `NormalizeRelation`; the same canonical parts feed mapping construction,
  analyzer output keys, and Kotlin catalog-key matching — not one lookup site.

## Engine specifics

- PostgreSQL: `<catalog>` = the bound database; `<schema>` = real PG schema
  names (`public`, exposed system schemas, user schemas). Introspection records
  the fresh connection's bound database and ordered `current_schemas(true)`
  path.
- MySQL: `<catalog>` = `def`; `<schema>` = real database names (bound db +
  `information_schema` + any others exposed); no `"public"` relabel.
  Introspection records the current database and `@@lower_case_table_names`, so
  the resolver uses the target server's case semantics rather than the proxy
  host's filesystem.

Cross-database MySQL joins (`db1.t JOIN db2.t`) resolve as two schemas under the
one `def` catalog; PG never legitimately spans catalogs.

## Scope

In: turning the full catalog into a nested `MappingSchema`, and supplying the
static namespace metadata captured at introspection. Out: resolving physical
names and constructing lineage/Cedar keys
([schema-threading-problem.md](./schema-threading-problem.md)); a connection's
live effective path, temp namespace, and fresh catalog
([connection-model.md](./connection-model.md),
[per-connection-catalog.md](./per-connection-catalog.md)).

## Verification

Live DB-backed tests cover a same-named table in two schemas,
cross-schema/cross-database joins, system-schema references,
wrong-schema/foreign-catalog denial, and server-specific MySQL case modes, so
the catalog and rollback checks cannot silently skip.
