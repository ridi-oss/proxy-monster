# System classification — the shipped `system:` facts

System classification is the curation behind open catalog browsing: which engine
objects are ordinary catalog structure and which are dangerous. It defines the
shipped facts; policy over those facts lives in
[access-model.md](./access-model.md) and [policy-store.md](./policy-store.md).

Classification ships as immutable, versioned JSON manifests bundled with the
product, one manifest per engine major version: `postgres/16`, `postgres/17`,
`mysql/8.0`, `mysql/8.4` under
`engine/src/main/resources/system-classification/`. They cover both vanilla and
Aurora deployments of those series — Aurora PostgreSQL 16 and 17, Aurora MySQL
3.x (MySQL 8.0-compatible) and Aurora MySQL 8.4. (The repo's
`docker-compose.yml` vanilla PostgreSQL 17 / MySQL 8.4 are the offline CI
substrate; the manifests are keyed by engine major series, so the same manifest
serves a vanilla and an Aurora target DB of that series.) The format supports
additional release series without code changes.

Aurora is not vanilla, so each manifest also classifies the Aurora-proprietary
system surface vanilla PostgreSQL/MySQL lacks. Aurora MySQL: the `mysql.rds_*`
procedure family (`rds_set_configuration`, `rds_kill`, the replication controls)
as one `system:critical` function family. Aurora PostgreSQL:
`aurora_replica_status`, `aurora_stat_activity`, `aurora_global_db_status`,
`aurora_global_db_instance_status`, and the `aurora_stat_*` relation/function
families, all `system:activity`. These are curated from AWS documentation.
Omitting them would leave a dangerous Aurora-specific object defaulting to
`system:catalog` (open).

At boot the control-plane loads and validates every manifest — a malformed
manifest aborts startup. At query decision time the selected manifest classifies
fully-qualified Tables and Functions and maps utility commands to the resource
they expose (`SystemClassificationStore`, `SystemClassifier` in `engine/`, and
`SystemClassificationService.tagForTable`/`tagForFunction`/`tagForCommand` in
the control-plane). System facts are computed from the manifest; they are not
editable rows and never share provenance with user tags.

Each exposed system schema defaults to `system:catalog`. The manifest enumerates
only the dangerous overrides:

- `system:activity` — live sessions, queries, transactions, statement history,
  and logs;
- `system:data-leak` — server-file/database readers, histograms/value samples,
  large-object contents, and equivalent data-bearing surfaces; and
- `system:critical` — credentials/security configuration and privileged
  mutation.

A new object in an already-covered system schema that is absent from the shipped
manifest is `system:catalog` and open. That is the access model's explicit
open-by-default posture, and it makes manifest curation load-bearing: nothing
automated detects a newly dangerous engine object. Reviewing each engine
release's system surface by hand is the only control, and it is a human process,
not a gate — see [Curation is the control](#curation-is-the-control). Runtime
does not reclassify an unmatched object into a forbidden class.

## Version resolution and unsupported-version fallback

Manifests are keyed by engine major. A new minor (Aurora PostgreSQL 17.7 → 17.9,
Aurora MySQL 3.10 → 3.12) is an exact match to its major's manifest; minors
almost never add or remove system objects. Resolution for a datasource's
detected engine version:

1. Exact major match → use that manifest. The normal path.
2. No manifest for the major → fall back to the nearest supported major of the
   same engine (the highest supported major ≤ the datasource's major; if the
   datasource is older than all supported majors, the lowest). So a datasource
   on Aurora PostgreSQL 18 is governed by the PostgreSQL 17 manifest until an 18
   manifest ships, rather than losing all system classification.

The fallback is opt-in, not silent: it is off by default
(`SystemClassificationService.allowFallback`), and the safe default is
deny/unclassified — system schemas stay unavailable on an uncertified major
until you turn fallback on. Boot logs the loaded manifest set, the combined
manifest checksum, and the fallback switch;
`SystemClassificationService.describeManifestFor` reports exact vs fallback vs
no-manifest for a datasource, logged when the proxy pushes that datasource's
catalog. There is no per-decision health signal or audit field for a fallback
hit, and no `/health` diagnostic for one — the two log lines are the whole
observability surface.

The fallback is fail-safe in the same sense the open default is: the nearest
manifest still enforces every dangerous tag it knows, so nothing it covers is
widened. Its only residual is that a dangerous object introduced in the newer,
uncertified major is absent from the older manifest and defaults to
`system:catalog` (open) — the identical, already-accepted missed-classification
caveat, now scoped to the major-version delta and equally undetected. A fallback
never silently forbids a newly-safe object nor permits a newly-dangerous one
beyond that open default.

Objects in system schemas the manifest does not expose are not introspected into
the MappingSchema. They remain unavailable and fail closed through ordinary
schema resolution. The open default applies inside the system surface
intentionally exposed, not to every internal storage schema an engine has.

The manifest and the system policy store are deliberately different mechanisms:

- classification is a product fact — immutable, binary-versioned,
  release-reviewed;
- policy is an admin control — database-backed, enabled/disabled,
  migration-updated.

## Scope

This doc owns which system schemas are exposed, the manifest format and
matching, the curated PostgreSQL and MySQL dangerous sets, the utility-command →
resource map, shipped-tag provenance and reserved-namespace enforcement, and how
a new engine version gets curated.

It does not own schema-aware key construction or namespace resolution (the
schema-threading and connection-model docs); Function/scanned-Table emission and
Cedar marshalling ([facts-emission.md](./facts-emission.md)); the Cedar source
or migration mechanics ([policy-store.md](./policy-store.md)); or COPY /
fast-path relay.

Schema-aware identity is a hard prerequisite. The classifier receives the
already-resolved `datasource/catalog/schema/object` identity; it never guesses a
missing schema. A user `public.tables` and `information_schema.tables` are
different resources
([schema-threading-problem.md](./schema-threading-problem.md)).

## Why a bundled manifest

A database table is the wrong source of truth for system classification. These
tags describe what a shipped engine surface is, not what an admin wants to
permit. Making them editable would let a policy admin rewrite a security fact,
let environments drift, and weaken review exactly where a missed entry is a
leak. A migration-seeded table would still require a product release for every
safe update while adding row provenance, edit guards, and reconciliation failure
modes.

A repository manifest instead gives one reviewed diff per change (object
additions, removals, category changes), deterministic pairing with the analyzer
version that consumes it, a checksum logged at boot, and no runtime mutation
path. The tradeoff — correcting a classification requires a product release — is
acceptable because a missed dangerous object is already a security release.

## Manifest format

Layout:

```text
engine/src/main/resources/system-classification/
  postgres/16.json
  postgres/17.json
  mysql/8.0.json
  mysql/8.4.json
```

`SystemClassificationStore.load` names that set explicitly, so adding a series
means adding the file and the entry. One manifest artifact serves relation,
function, and command classification — no copied lists in the control-plane and
analyzer. A manifest is declarative:

```json
{
  "engine": "postgres",
  "series": "17",
  "manifestVersion": 1,
  "curatedThrough": "17.9",
  "systemSchemas": [
    { "catalog": "*", "schema": "pg_catalog" },
    { "catalog": "*", "schema": "information_schema" }
  ],
  "logicalFunctionSchemas": [],
  "relations": [
    {
      "schema": "pg_catalog",
      "name": "pg_stat_activity",
      "tag": "system:activity"
    },
    { "schema": "pg_catalog", "name": "pg_stats", "tag": "system:data-leak" },
    { "schema": "pg_catalog", "name": "pg_authid", "tag": "system:critical" }
  ],
  "relationFamilies": [
    {
      "schema": "pg_catalog",
      "prefix": "pg_stat_progress_",
      "tag": "system:activity"
    }
  ],
  "functions": [{ "schema": "*", "name": "dblink", "tag": "system:data-leak" }],
  "functionFamilies": [
    { "schema": "pg_catalog", "prefix": "pg_read_", "tag": "system:data-leak" }
  ],
  "commands": [
    {
      "id": "SHOW_PROCESSLIST",
      "resource": "information_schema/PROCESSLIST",
      "tag": "system:activity"
    }
  ]
}
```

### Validation

Boot validation rejects a manifest whose declared engine/series disagrees with
its file path; a duplicate manifest for one engine/series; any tag outside the
four `system:` tags; a wildcard schema on a relation rule (only a function rule
may be cross-schema); duplicate exact identities with different tags;
overlapping prefix families with different tags; and an exact rule weaker than a
family prefix it matches — a category downgrade that would depend on match
ordering. Anything rejected throws `SystemManifestException`, which aborts
startup.

Validation does not check command ids against the analyzer: nothing verifies
that a manifest command id is one `analyzer/probe/facts.go` can actually emit,
or that every emitted id has a manifest entry. `ManifestCommandCoverageDbTest`
covers the second direction at test time (see [Verification](#verification)).

The classifier returns exactly one `system:` tag. It collects every matching
exact/family/default rule and takes the strongest:

```text
system:critical > system:data-leak > system:activity > system:catalog
```

Only the tag is returned — the classifier does not report which rule matched. A
weaker exact rule can never downgrade a stronger family rule; boot validation
rejects a manifest that appears to rely on such ordering. Manifests prefer exact
rules; prefixes exist for stable engine families such as `events_statements_*`
or `pg_stat_progress_*`. There are no general regular expressions — exact/prefix
matching keeps review diffs and overlap validation understandable.

### Identifier matching

The classifier receives an already schema-resolved `(catalog, schema, object)`
identity and compares it case-insensitively — an ASCII lower-case fold on both
sides. System schemas and their objects are conventionally lower-case, and
matching is scoped to the manifest's own schemas, so folding cannot catch a user
object. Manifests may therefore store the canonical server spelling
(`information_schema.USER_PRIVILEGES`) and still match a lower-cased identity.

- A PostgreSQL manifest uses `catalog: "*"`, which matches any catalog:
  PostgreSQL system schemas are repeated inside each database and a query cannot
  name a different database. The resolved resource key still carries the actual
  database name.
- MySQL pins the literal catalog `def`; MySQL databases — including `mysql`,
  `information_schema`, `performance_schema`, and `sys` — occupy the schema
  component. The resource-only `def/__builtin__` entry lives in
  `logicalFunctionSchemas`, not `systemSchemas`, so introspection never queries
  it as a real database. Nothing validates the wildcard per engine: a `"*"`
  catalog in a MySQL manifest would be accepted and would simply match every
  catalog.
- A function rule may use `schema: "*"` for a cross-schema extension/loadable
  function that can be installed into any schema. A matching user function is
  then over-classified — safe (a deny), and the reason `schema: "*"` is refused
  on a relation rule.

Relations are classified whole. A Column receives the owning Table's system
class through its Cedar Table parent; it is not independently default-tagged
`system:catalog`. Otherwise a column of `pg_authid` would inherit
`system:critical` and carry a direct catalog permit at once, and disabling or
exempting the stronger guard would accidentally create access without an
ordinary grant. Several security surfaces (`pg_settings`, grant tables) mix
benign and sensitive rows/columns; with no row-conditional system tags, the
whole relation takes the strongest necessary class. Over-denying beats exposing
a credential-bearing row.

## Exposed system surface and catalog boundary

### PostgreSQL

Expose `pg_catalog` and `information_schema`. Do not expose internal storage
schemas such as `pg_toast`. User and temporary schemas are cataloged by the
connection/schema model, not because they are system schemas.

### MySQL

Expose real schemas `information_schema`, `performance_schema`, `sys`, and
`mysql`. Also register the logical Function namespace `def/__builtin__` with
default `system:catalog`: it is not introspected as a MySQL schema, it is the
classifier namespace for built-ins such as `lower`, `now`, and `concat`.
Dangerous exact/family entries such as `LOAD_FILE` override that default.
Without this logical default, Function enforcement would deny every ordinary
MySQL built-in because no shipped permit matched.

Every exposed real schema defaults to `system:catalog`; the dangerous objects
below override it. The whole `mysql`, `performance_schema`, or `sys` schema is
not classified dangerous — the model enumerates the dangerous set and leaves the
rest open.

### What `system:catalog` means

Catalog is structure: database/schema/table/column names and types; indexes,
constraints, keys, partitions, and dependency metadata; view, trigger, event,
routine, and generated-column definitions; engine/build capabilities; and
DDL-reconstruction functions and commands. PostgreSQL `pg_get_*def`,
`pg_get_expr`, and `format_type`, and MySQL `SHOW CREATE ...`, are catalog even
when their returned definition contains SQL expressions or literal constants.
Treating definitions as structure is the deliberate browsing boundary — do not
embed credentials in DDL/routine source; if you do, the catalog-open posture can
expose them.

The boundary changes when a surface reports data-derived values rather than
structure. Histograms, most-common values, sampled SQL text, diagnostic buffers,
large-object bytes, server files, and logs are not catalog.

The curation reads from the engine manuals: PostgreSQL's System Catalogs,
Statistics Views, System Information/Admin Functions, `dblink`, and
`pg_stat_statements` pages, and MySQL 8.4's Grant Tables, `INFORMATION_SCHEMA`,
Performance Schema statement tables, sys schema, `LOAD_FILE()`, and
SHOW-statement pages. Those manuals plus a human's reading of them are the whole
authority — there is no generated inventory to check them against.

## PostgreSQL dangerous set

The sections below describe what the shipped manifests classify; the JSON files
are the authority. Pattern notation means one validated prefix family, not an
unreviewed regex.

### `system:critical` — credentials, security configuration, privileged mutation

Relations/views:

<!-- prettier-ignore -->
| object | why |
| --- | --- |
| `pg_catalog.pg_authid`, `pg_catalog.pg_shadow` | password verifiers and privileged role attributes |
| `pg_catalog.pg_user_mapping`, `pg_catalog.pg_user_mappings` | user-mapping options can include remote credentials |
| `pg_catalog.pg_foreign_server`, `pg_catalog.pg_foreign_data_wrapper` | server/wrapper options can include connection and handler configuration |
| `information_schema.user_mapping_options` | user-mapping option view |
| `information_schema.foreign_server_options`, `information_schema.foreign_data_wrapper_options` | FDW option views |
| `pg_catalog.pg_subscription` | logical-subscription connection string (`subconninfo`) |
| `pg_catalog.pg_hba_file_rules`, `pg_catalog.pg_ident_file_mappings` | authentication/identity-map configuration |
| `pg_catalog.pg_config`, `pg_catalog.pg_file_settings`, `pg_catalog.pg_settings`, `pg_catalog.pg_db_role_setting` | build/config paths, source files, pending values, per-role/database settings, and potentially sensitive connection/config values |

Privileged functions:

- configuration read/mutation: `set_config`, `current_setting` (relation-level
  `pg_settings` is critical for the same reason);
- backend/session control: `pg_cancel_backend`, `pg_terminate_backend`,
  `pg_log_backend_memory_contexts`;
- configuration/log control: `pg_reload_conf`, `pg_rotate_logfile`;
- WAL/backup/restore-point mutation: `pg_create_restore_point`, `pg_switch_wal`,
  `pg_backup_start`, `pg_backup_stop`;
- replication-slot mutation: `pg_create_physical_replication_slot`,
  `pg_create_logical_replication_slot`, `pg_drop_replication_slot`,
  `pg_replication_slot_advance`;
- large-object/server-file mutation: `lo_unlink`, `lo_export`; and
- remote mutation: `dblink_exec` (a cross-schema rule).

Utility command ids: `PG_ALTER_SYSTEM`, `PG_ALTER_ROLE_PASSWORD`,
`PG_CREATE_USER_MAPPING`, `PG_ALTER_SERVER`, and `PG_COPY_PROGRAM` — the
server-file/program forms of `COPY`, which are also `exception.unmaskable`,
since policy cannot make an unimplemented relay work.

`SET_ROLE` and `SET_SESSION_AUTHORIZATION` are `system:critical` because they
change which target DB identity and namespace future statements bind under
([statement-facts-contract.md](./statement-facts-contract.md)).
`SET_STANDARD_CONFORMING_STRINGS` joins them: it changes how the server lexes
string literals, which changes what a later statement means. `USER_TYPE_CAST`
and `SET_SUBQUERY` are critical for a different reason — a cast to a user domain
runs that type's coercion function, and a subquery on the right-hand side of a
`SET` reads data outside any analyzed query.

### `system:data-leak` — values, files, large objects, remote data

Relations/views:

<!-- prettier-ignore -->
| object/family | why |
| --- | --- |
| `pg_catalog.pg_statistic`, `pg_catalog.pg_statistic_ext_data` | internal histogram/sample data |
| `pg_catalog.pg_stats`, `pg_catalog.pg_stats_ext`, `pg_catalog.pg_stats_ext_exprs` | most-common values, histogram bounds, and extended statistics |
| `pg_catalog.pg_largeobject` | large-object byte contents |

Functions/families:

- remote reads, each an exact cross-schema rule: `dblink`, `dblink_open`,
  `dblink_fetch`, `dblink_get_result`, `dblink_send_query`, `dblink_get_notify`
  (there is no `dblink_*` family — a new result-producing `dblink_` function
  needs its own entry);
- arbitrary server files/directories: the `pg_read_*` and `pg_ls_*` families
  (`pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_ls_waldir`,
  `pg_ls_logdir`, …) plus exact `pg_stat_file`;
- large objects: `lo_get`, `lo_import`, `loread`;
- XML table/database/schema readers: the `query_to_xml`, `table_to_xml`,
  `database_to_xml`, `schema_to_xml`, and `cursor_to_xml` families, plus exact
  `xpath_table`;
- logical decoding output: `pg_logical_slot_get_changes`,
  `pg_logical_slot_peek_changes`, and their binary variants; and
- raw-page inspection when the standard `pageinspect` extension is present:
  exact `get_raw_page`, `page_header`, `fsm_page_contents`, `tuple_data_split`,
  and the `heap_page_*`, `bt_page_*`, `brin_page_*`, `brin_metapage_*`,
  `gin_page_*`, `gin_leafpage_*`, `gin_metapage_*`, `gist_page_*`,
  `hash_page_*`, and `hash_metapage_*` decoding families. These are cross-schema
  rules, since `pageinspect` can be installed into any schema.

### `system:activity` — sessions, query text/history, locks, logs

Relations/views:

- `pg_catalog.pg_stat_activity`;
- `pg_catalog.pg_stat_replication`, `pg_stat_wal_receiver`,
  `pg_stat_subscription`, `pg_stat_subscription_stats`;
- `pg_catalog.pg_stat_ssl`, `pg_stat_gssapi`;
- the `pg_catalog.pg_stat_progress_*` family;
- `pg_catalog.pg_prepared_statements`, `pg_cursors`, `pg_locks`;
- extension relations `pg_stat_statements`, `pg_stat_statements_info`; and
- Aurora `pg_catalog.aurora_replica_status`, `aurora_stat_activity`,
  `aurora_global_db_status`, `aurora_global_db_instance_status`, and the
  `aurora_stat_*` family.

Functions:

- `current_query`;
- `pg_blocking_pids`, `pg_safe_snapshot_blocking_pids`;
- `pg_current_logfile`;
- the `pg_stat_get_*` family — the internal getters behind the statistics views;
  and
- Aurora `aurora_replica_status`, `aurora_stat_activity`, and the
  `aurora_stat_*` family.

Log content reached through a generic file reader is `system:data-leak`, so
`pg_ls_logdir` is data-leak through the `pg_ls_*` family rather than activity;
log-specific discovery/state such as `pg_current_logfile` is `system:activity`.
When both could apply the stronger tag wins, which is why the family placement
matters more than the intent behind an individual name.

### Explicit catalog examples

These stay `system:catalog` unless a version manifest names a stronger override:
`pg_class`, `pg_attribute`, `pg_type`, `pg_namespace`, `pg_proc`, `pg_index`,
`pg_constraint`, `pg_depend`, `pg_views`, `pg_roles`, `pg_user`, `pg_group`, and
ordinary information-schema structure views (the public role/user views mask
password data; `pg_authid`/`pg_shadow` stay critical); `pg_get_viewdef`,
`pg_get_ruledef`, `pg_get_indexdef`, `pg_get_constraintdef`,
`pg_get_functiondef`, `pg_get_triggerdef`, `pg_get_expr`, `format_type`; and
definition columns such as `pg_views.definition` and routine source/definition
metadata.

## MySQL dangerous set

### `system:critical` — grant/auth tables, sensitive configuration, privileged mutation

Relations/views:

<!-- prettier-ignore -->
| object/family | why |
| --- | --- |
| `mysql.user`, `mysql.global_grants`, `mysql.db` | account authentication/authorization state |
| `mysql.tables_priv`, `mysql.columns_priv`, `mysql.procs_priv`, `mysql.proxies_priv` | object/proxy grants |
| `mysql.role_edges`, `mysql.default_roles`, `mysql.password_history` | role graph and password history |
| `mysql.servers`, `mysql.slave_master_info` | remote/replication connection configuration and credentials |
| `mysql.component`, `mysql.plugin`, `mysql.func` | privileged loadable code/component configuration |
| `mysql.audit_log*`, `mysql.firewall*` when installed | security-control configuration |
| `information_schema.USER_PRIVILEGES`, `SCHEMA_PRIVILEGES`, `TABLE_PRIVILEGES`, `COLUMN_PRIVILEGES`, `ROUTINE_PRIVILEGES` | grant-table views |
| `information_schema.USER_ATTRIBUTES`, `ENABLED_ROLES`, `APPLICABLE_ROLES`, `ADMINISTRABLE_ROLE_AUTHORIZATIONS` | account attributes and role authorization |
| `performance_schema.replication_connection_configuration` | replication identity/TLS configuration |
| `performance_schema.global_variables`, `session_variables`, `persisted_variables`, `variables_info` | conservative treatment of sensitive server configuration |

Functions: the `keyring_*` family — the keyring components'
fetch/store/generate/ remove functions — and, for Aurora MySQL, the
`mysql.rds_*` procedure family.

Utility command ids:

- account administration: `SET_PASSWORD`, `CREATE_USER`, `ALTER_USER`,
  `DROP_USER`, `RENAME_USER`, `GRANT`, `REVOKE`, `SET_DEFAULT_ROLE`, `SET_ROLE`;
- credential-bearing reads: `SHOW_CREATE_USER` (an account's stored password
  hash), `SHOW_GRANTS`;
- server-state mutation: `SET_GLOBAL`, `SET_PERSIST`, `SET_PERSIST_ONLY`,
  `RESET_PERSIST`, `ALTER_INSTANCE`, `CLONE_INSTANCE`, `RESTART`, `SHUTDOWN`;
- replication and binary log: `CHANGE_REPLICATION_SOURCE`, `RESET_REPLICA`,
  `PURGE_BINARY_LOGS`;
- code loading: `INSTALL_PLUGIN`, `UNINSTALL_PLUGIN`, `INSTALL_COMPONENT`,
  `UNINSTALL_COMPONENT`, `CREATE_FUNCTION_SONAME`, `DROP_FUNCTION_SONAME`;
- server-side file IO: `INTO_OUTFILE`, `INTO_DUMPFILE`, `LOAD_DATA`, `LOAD_XML`;
  and
- statement-meaning changes: `SET_SQL_MODE` (the lexer's quoting and escaping
  rules), `USER_TYPE_CAST`, `SET_SUBQUERY`, `SHOW_SUBQUERY`.

`SHOW VARIABLES` / `SHOW STATUS` and PostgreSQL `SHOW <guc>` appear in the
manifests as `SHOW_VARIABLES` / `SHOW_STATUS` / `PG_SHOW_GUC` but are
intentional passthroughs: the analyzer emits no command for them, because
ordinary clients issue them at connect and gating would break psql and mysql.
The manifest entries are inert — `ManifestCommandCoverageDbTest` lists all three
as documented passthroughs. Where several spellings mean one operation the
analyzer folds them onto one id: `SET @@GLOBAL.x` and `SET GLOBAL x` both emit
`SET_GLOBAL`, and `SHOW REPLICA STATUS` and `SHOW SLAVE STATUS` both emit
`SHOW_REPLICA_STATUS`.

### `system:data-leak` — files, histograms/value distributions, data-bearing diagnostics

Relations/views:

<!-- prettier-ignore -->
| object/family | why |
| --- | --- |
| `information_schema.COLUMN_STATISTICS` | JSON histograms and bucket/value distributions |
| `mysql.innodb_index_stats`, `mysql.innodb_table_stats` | data-derived cardinality/statistics |
| `sys.schema_table_statistics*`, `sys.schema_index_statistics*` | data-derived table/index distributions and counts |

Functions: `LOAD_FILE`, the manifests' one exact function entry, under the
logical `__builtin__` schema.

Utility command ids:

- `SHOW_BINLOG_EVENTS`, `SHOW_RELAYLOG_EVENTS`;
- `SHOW_ENGINE_STATUS` — the InnoDB diagnostic can include record and query
  data; and
- `SHOW_WARNINGS`, `SHOW_ERRORS` — the session diagnostic buffer can repeat
  values and SQL fragments from a prior statement, so permitting it on a masking
  datasource can bypass that statement's mask.

MySQL 8.4 exposes column histograms through
`information_schema.COLUMN_STATISTICS`. A future sys or performance-schema
wrapper over equivalent bucket/sample values belongs in this category too — it
must be added by hand, since living under `sys` is not what makes a relation
safe and nothing detects the new wrapper.

### `system:activity` — live work, statement history, transactions, logs

Relations/views and prefix families:

- `information_schema.PROCESSLIST`, `information_schema.INNODB_TRX`;
- `performance_schema.processlist`, `threads`, `prepared_statements_instances`;
- the `performance_schema.events_statements_*` family, including the
  summary/digest tables carrying digest or sample SQL;
- the `performance_schema.events_transactions_*` and `events_stages_*` families;
- `performance_schema.data_locks`, `data_lock_waits`, `metadata_locks`;
- `performance_schema.error_log`;
- `mysql.general_log`, `mysql.slow_log`;
- `sys.processlist`, `sys.session`, and their `x$` forms;
- `sys.innodb_lock_waits` and `sys.x$innodb_lock_waits`;
- the `sys.statement_analysis`, `sys.statements_with_*` families and their `x$`
  forms; and
- the `sys.host_summary_by_statement` and `sys.user_summary_by_statement`
  families and their `x$` forms.

The `sys.io_*` and latest-file-I/O views are not classified, so they are
`system:catalog`.

Utility commands: `SHOW [FULL] PROCESSLIST` (`SHOW_PROCESSLIST`) and
`SHOW REPLICA STATUS` / `SHOW SLAVE STATUS` (`SHOW_REPLICA_STATUS`).
`SHOW_STATUS` carries this tag in the manifest but is a passthrough the analyzer
never emits.

### Explicit catalog examples

These stay `system:catalog` unless overridden: `information_schema.TABLES`,
`COLUMNS`, `STATISTICS`, `KEY_COLUMN_USAGE`, `TABLE_CONSTRAINTS`,
`REFERENTIAL_CONSTRAINTS`, `VIEWS`, `ROUTINES`, `PARAMETERS`, `TRIGGERS`,
`EVENTS`, `PARTITIONS`; ordinary performance-schema setup/capability metadata
without statement/value/session content; `SHOW DATABASES`, `SHOW TABLES`,
`SHOW FULL TABLES`, `SHOW COLUMNS|FIELDS`, `SHOW INDEX|KEYS`,
`SHOW CHARACTER SET`, `SHOW COLLATION`, `SHOW ENGINES`; and
`SHOW CREATE TABLE|VIEW|TRIGGER|PROCEDURE|FUNCTION|EVENT`, `DESCRIBE`, and
`DESC`.

## Utility command → resource map

Utility commands and embedded system-variable reads expose resources with no
lineage Table/Function node, so admission emits one or more canonical Utility
utility grants (command id). The manifest maps each command id to a tag (and
optional resource slug). This is the only place a command is classified rather
than derived from the resolved analyzer scope.

Admission emits a `Utility` grant whose command id the manifest tags. The
manifest's `resource` string is descriptive only — nothing reads it; the Cedar
EUID is always `Utility::"<datasource>/<command>"`:

<!-- prettier-ignore -->
| statement | emitted command id | tag |
| --- | --- | --- |
| MySQL `SHOW [FULL] PROCESSLIST` | `SHOW_PROCESSLIST` | `system:activity` |
| MySQL `SHOW BINLOG EVENTS` | `SHOW_BINLOG_EVENTS` | `system:data-leak` |
| MySQL `SHOW WARNINGS` / `SHOW ERRORS` | `SHOW_WARNINGS` / `SHOW_ERRORS` | `system:data-leak` |
| MySQL `SHOW CREATE USER u` | `SHOW_CREATE_USER` | `system:critical` |
| MySQL `SET PASSWORD` | `SET_PASSWORD` | `system:critical` |
| MySQL `SET GLOBAL x` / `SET @@GLOBAL.x` | `SET_GLOBAL` | `system:critical` |
| MySQL `SET PERSIST x` / `SET PERSIST_ONLY x` | `SET_PERSIST` / `SET_PERSIST_ONLY` | `system:critical` |
| MySQL `SET ROLE` / `SET DEFAULT ROLE` | `SET_ROLE` / `SET_DEFAULT_ROLE` | `system:critical` |
| PostgreSQL `SET ROLE` / `SET SESSION AUTH…` | `SET_ROLE` / `SET_SESSION_AUTHORIZATION` | `system:critical` |
| MySQL `SET sql_mode` / PostgreSQL lexer-mode GUC | `SET_SQL_MODE` / `SET_STANDARD_CONFORMING_STRINGS` | `system:critical` |
| MySQL `SHOW CREATE TABLE users`, `DESCRIBE users` | metadata passthrough (no utility grant) | — |
| PostgreSQL `SHOW ALL` / `SHOW <guc>` | intentional passthrough (`PG_SHOW_GUC` never emitted) | — |

```text
Utility::"acme-mysql/SET_GLOBAL"
Utility::"acme-pg/PG_ALTER_SYSTEM"
Utility::"acme-mysql/SHOW_PROCESSLIST"
```

The key is datasource / canonical command id, outside the SQL catalog/schema
namespace, so a quoted user schema or function cannot collide with it. The
resource is logical only and is never passed to the target DB as an object name.
Transaction control and connection plumbing stay in their own structural path.
Ordinary metadata SHOWs (`SHOW TABLES`, `SHOW CREATE TABLE`, …) carry no utility
grant; their kind (a metadata kind Cedar maps to `stmt.cat.metadata`) is
authorized, then the statement relays verbatim once `datasource.connect`
succeeds.

The manifests carry more command ids than the analyzer emits. `CREATE_USER`,
`GRANT`, `RESTART`, `INTO_OUTFILE`, `PG_ALTER_SYSTEM` and their neighbors are
classified there, but those statements are denied by the statement-kind gate
(`stmt.kind.<k>`) or by a structural admission deny before any utility grant
would matter — `ManifestCommandCoverageDbTest` proves each one denies, without
asserting which gate did it. The manifest entry is the classification of record
for the day one of them gains a utility grant; it is not evidence that the
utility path is what currently stops the statement.

## Loading, applying, and tag provenance

### Boot

The control-plane loads all bundled manifests before serving, validates them,
computes a checksum over the bundle, and compiles exact identities into hash
maps plus schema-scoped prefix lists. Query decisions classify each distinct
resource key once and reuse the result across its Columns; they do not linearly
scan every manifest rule per fact. Boot logs the loaded engine/series set, the
checksum prefix, and the fallback switch. Invalid or conflicting classification
aborts startup, like a failed Flyway migration. `manifestVersion` and
`curatedThrough` are manifest fields, read at deserialization but not surfaced
at runtime.

### Version selection

Catalog introspection records the target DB's parsed engine release. Selection
is by release series: PostgreSQL major (`17`) and MySQL LTS/release family
(`8.4`).

- exact supported series → select its manifest;
- newer patch/minor within the series → use the series manifest; unmatched new
  objects default catalog (`curatedThrough` records the release a human
  reviewed);
- unsupported major/release family → no manifest, so no system tag: system
  objects carry no shipped classification until that series has a manifest (or
  you enable fallback). User schemas continue under ordinary deny-by-default
  access.

This separates the explicitly accepted new-object open posture from pretending
that an untested engine major is certified.

### Introspection

The proxy introspects every schema the target DB reports — a plain
`information_schema.columns` scan with no exclusions, system schemas included —
and pushes the columns over gRPC `PushCatalog` into
`DatasourceStore.storePushedCatalog`, which persists the real
catalog/schema/table/column identities the MappingSchema needs. Excluding a
system schema here would be the shadowing leak
[schema-threading-problem.md](./schema-threading-problem.md) describes: a system
table absent from the mapping resolves to a user table of the same name while
the target DB binds the system one. Refresh follows the connection-model
snapshot/SWR path; system-schema breadth never adds a synchronous per-query
catalog scan or blocks existing connections on a full refresh. The manifest does
not write system tags into `column_classification`; the object identity is
enough.

There is no function catalog. Functions are classified from the bare name the
analyzer emits, against the manifest rules — no routine introspection, no stored
function inventory ([facts-emission.md](./facts-emission.md)).

### Decision time

For each Table/Function/Utility fact the control-plane asks
`SystemClassificationService.tagForTable` / `tagForFunction` / `tagForCommand`,
which returns exactly one system tag or none. A Table in an exposed system
schema gets at least `system:catalog`; a recognized cross-schema dangerous
function can get a shipped tag outside a system schema. A Column inherits its
owning Table's system tag through the Cedar entity graph and receives no
separate shipped system parent; user column tags stay direct Column parents.

Admin write APIs reject `system:*`: a classification write carrying any tag with
that prefix fails with `datasource.reserved_tag`
(`DatasourceStore.RESERVED_TAG_PREFIX`). The marshaller strips nothing — a tag
is a tag — so a column row may carry `system:critical` and it reaches policy as
`Tag::"system:critical"`. It does not forge shipped provenance: the shipped
forbids are keyed on the classification the manifest resolves at decision time,
never on a tag row. The catalog API does not return computed system tags at all
— `DatasourceStore.catalog` carries only the user-authored classification, so
the console's catalog browser shows a system column as unclassified. Enforcement
resolves the tags at decision time and is unaffected; the display gap is
recorded in [`KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md).

### No-manifest floor

Where no manifest governs a datasource,
`SystemClassificationService.tagForFunction` unions
`SystemClassifier.classifyBareFunction` across every shipped manifest of the
engine (`SystemClassificationStore.classifiersForEngine`), taking the strongest
tag per name. This is a version-independent floor derived from the manifests
themselves, so a dangerous built-in stays gated on a datasource that has no
certified manifest, at parity-or-stronger with the certified path.
`BaselineDangerousFunctions` is a belt-and-suspenders floor for an engine with
zero shipped manifests.

## Curation is the control

Open-by-default puts manifest curation inside the security boundary, and that
curation is entirely manual. What ships is the four JSON manifests and the tests
listed under [Verification](#verification) — nothing more. In particular:

- there is no committed inventory of any engine version's system objects;
- no test enumerates a live server's catalog and compares it against a manifest;
  the DB-backed tests exercise specific statements against a Testcontainers
  target DB, they do not sweep the engine's system surface; and
- no CI job diffs a manifest against a new engine release. The only
  classification-related CI is `mise run verify`, which runs those same tests.

So a new engine minor that adds a dangerous system view or function is
classified `system:catalog` and open, and nothing surfaces that. Finding it
depends on a maintainer reading the release notes.
[`KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) records the gap; a golden
per-version inventory plus a release-diff gate is the intended closer
([`backlog.md`](./backlog.md)).

`curatedThrough` in each manifest is the honest statement of that boundary: the
patch release whose surface a human last read. It is metadata, not an assertion
anything verified.

Adding PostgreSQL 18, MySQL 9.x, or another series today means: read that
version's system-catalog, statistics, admin-function, and SHOW-statement
documentation; write the manifest; add it to
`SystemClassificationStore.BUNDLED`; set `curatedThrough` to the release you
read; and extend the decision tests with whatever the new version introduced.

A dangerous command or function in no shipped manifest relays as
`system:catalog` — `SHOW MASTER STATUS` / `SHOW BINARY LOG STATUS` (binlog
position, replica topology) is the concrete example, absent from the MySQL
manifests and from the analyzer's emitted command set alike. That
manifest-coverage boundary is inherent to enumerating the dangerous rather than
the safe; closing an instance of it is a curation decision, not an enforcement
bug.

## Worked decisions

Assume ordinary `datasource.connect` / `stmt.kind.select` grants pass and system
policies are enabled:

<!-- prettier-ignore -->
| statement | resource fact | production posture | development posture |
| --- | --- | --- | --- |
| `SELECT relname FROM pg_catalog.pg_class` | Table `system:catalog` | ALLOW | ALLOW |
| `SELECT definition FROM pg_views` | Table `system:catalog` — a definition is structure | ALLOW | ALLOW |
| `SELECT query FROM pg_stat_activity` | Table `system:activity` | DENY | dev policy may permit |
| `SELECT most_common_vals FROM pg_stats` | Table `system:data-leak` | DENY | dev policy may permit |
| `SELECT rolpassword FROM pg_authid` | Table `system:critical` | DENY | DENY — critical is never relaxed by the dev preset |
| `SELECT LOAD_FILE('/etc/passwd')` | Function `system:data-leak` | DENY | dev policy may permit |
| `SHOW FULL PROCESSLIST` | Utility `SHOW_PROCESSLIST`, `system:activity` | DENY | dev policy may permit |
| `SHOW CREATE TABLE users` | no grant at all (metadata passthrough) | ALLOW | ALLOW |
| `SHOW BINLOG EVENTS` | Utility `SHOW_BINLOG_EVENTS`, `system:data-leak` | DENY | dev policy may permit |
| `SET GLOBAL general_log = ON` | Utility `SET_GLOBAL`, `system:critical` | DENY | DENY — critical is never relaxed by the dev preset |

The `system:critical` rows are unconditional: `ManifestCommandCoverageDbTest`
asserts that `SHOW CREATE USER` and `SHOW GRANTS` deny even on a
`system:development` datasource, while `SHOW REPLICA STATUS` (`system:activity`)
relaxes to ALLOW there. Relaxing a critical tag takes an admin editing or
disabling the shipped forbid, not a preset.

Two things the table's shape can mislead about. First, catalog policy does not
bypass the statement-kind gate: a principal still needs `stmt.kind.select` (or
the appropriate kind) on the datasource before reading a catalog resource.
Second, a system relation with no manifest — an uncertified engine version — is
not `system:catalog`, it is untagged, and `SELECT relname FROM pg_class` then
denies along with everything else.

A no-FROM call carries its own gate. `SELECT pg_get_viewdef('v')` emits a
`pg_get_viewdef` Function grant, because the analyzer's no-FROM allowlist covers
session/time/math builtins and not the DDL-reconstruction functions. Nothing
classifies that name, so `decideQuery` hard-denies the unclassified Function
grant. Add a FROM — `SELECT pg_get_viewdef(oid) FROM pg_class` — and no Function
grant is emitted and the statement allows on `system:catalog`. Calling a
catalog-class function with no FROM is therefore denied in practice, which is
why the [catalog boundary](#what-systemcatalog-means) describes what the tag
means rather than which statements pass.

## Data model

- immutable JSON manifest files per engine release series;
- a validated in-process `SystemClassifier` per series, and a combined checksum
  over the bundle;
- `datasource.engine_version`, the raw target DB version string the proxy
  pushed, which is what manifest resolution keys off;
- canonical Utility grants and manifest command/tag mappings;
- `catalog_column` as the physical column inventory, including the system
  schemas; and
- `column_classification.tags` as user/admin tags only.

## Failure modes

1. Missed dangerous object in an exposed supported schema: classified catalog
   and possibly exposed. This is the chosen failure mode, and it is undetected —
   manual curation is the only control.
2. Malformed/conflicting manifest: startup aborts; no policy evaluation runs
   with partial facts.
3. Unsupported engine series: system schemas are not exposed until a manifest
   exists.
4. New object after `curatedThrough`: defaults catalog. No health signal, no
   audit field, no test failure.
5. Unknown extension function in a user schema: unclassified, so no Function
   forbid applies to it; a data-reading UDF's output passes unmasked (the UDF
   gap in [facts-emission.md](./facts-emission.md)). Known dangerous
   cross-schema names match the shipped `schema: "*"` rules.
6. Invented `system:` user tag: rejected at classification write time, so only
   the six names the product defines can be stored. Those are marshalled as
   written — a stored `system:critical` reaches the shipped critical forbid and
   denies — and writing one takes the same `admin.datasources` authority as the
   rest of classification.
7. Same name in two schemas: relations match on the fully-qualified identity.
   Functions are the exception — sqlglot drops the schema qualifier, so a bare
   name resolves against every system and logical schema the manifest governs,
   which can over-classify a same-named user function (a deny).
8. Rule overlap: overlapping families with different tags fail boot; an exact
   rule weaker than a family it matches fails boot. A surviving overlap resolves
   to the strongest tag.
9. Policy disabled: the fact stays attached and audited. Disabling or replacing
   a system policy is an explicit admin action, not a reclassification.

## Verification

Four test classes cover classification. They test the rules, not the engines'
surfaces:

- `SystemClassificationTest` (`engine/`) — manifest validation (bad tag,
  duplicate identity, overlapping family, downgrade-by-ordering, wildcard
  relation), the strongest-wins combinator, version resolution and fallback, and
  that all four bundled manifests load and classify a spot-checked set of real
  PostgreSQL and MySQL objects including the Aurora ones.
- `ManifestCommandCoverageDbTest` (`control-plane/`) — the fail-closed
  completeness guard in the direction that can be automated: every dangerous
  command id in every shipped manifest must either DENY through the real
  `decideQuery` on a representative statement, or hold an explicit passthrough
  entry with a reason. A new manifest command id with neither fails the test.
- `BaselineDangerousFunctionEnforcementDbTest` — dangerous functions deny on
  both a governed and a no-manifest datasource, and safe functions and user UDFs
  are untouched.
- `SystemClassificationEnforcementDbTest` — Cedar decision matrices on a real
  PostgreSQL 17 datasource: catalog structure browses, the dangerous tags deny,
  the forbid beats a broad datasource grant, and a missing engine version keeps
  system schemas closed.

Nothing here would catch a dangerous object the manifests never mention. That is
the gap [Curation is the control](#curation-is-the-control) describes.
