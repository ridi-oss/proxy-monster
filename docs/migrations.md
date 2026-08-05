# DB migrations — install & upgrade

The control-plane owns the Postgres schema and auto-migrates on boot with
Flyway. A clean database gets the full schema; an upgraded binary applies the
pending migrations. Each migration runs in its own Postgres transaction, and any
failure aborts startup so the API never serves on a half-migrated schema
(fail-closed).

## How it works

- `control-plane/build.gradle.kts` pins Flyway 11.1.0 and declares two runtime
  dependencies: `flyway-core` and `flyway-database-postgresql`. There is no
  MySQL Flyway module and no MySQL migration set, because the control-plane
  store is PostgreSQL only. The migrations declare `JSONB` columns with
  `jsonb_typeof` check constraints and `::jsonb` casts, and the runtime queries
  add `RETURNING` and `ON CONFLICT … DO UPDATE` upserts — MySQL accepts none of
  it. (MySQL is a target engine proxy-monster protects, never a store it runs
  on: the two are independent, see
  [`../AGENTS.md`](../AGENTS.md#two-independent-engine-axes).)
- `Db.kt` builds a HikariCP pool with
  `driverClassName = "org.postgresql.Driver"` hardcoded — the store engine is
  not configurable — and runs
  `Flyway.configure().dataSource(ds).load().migrate()`. `PM_DB_URL` must
  therefore be a `jdbc:postgresql://` URL.
- `Main.kt` calls `db.migrate()` before it starts the gRPC and HTTP servers. A
  migration exception propagates out of `main()` and the process exits without
  opening a port.
- Runtime migrations are plain SQL under `resources/db/migration/`, named
  `V{n}__desc.sql` and numbered sequentially from `V1__identity.sql`.

On an empty database Flyway creates `flyway_schema_history` and applies every
migration in order. On an upgrade it applies only migrations newer than the
recorded version.

## The layout

One file per coherent subject, in dependency order — a table's foreign keys
point only at tables an earlier file created. Each file declares its tables in
their final shape: every column is inline in its `CREATE TABLE`, so there is no
`ALTER TABLE` and no intermediate state to read past.

<!-- prettier-ignore -->
| File | Owns |
| --- | --- |
| `V1__identity.sql` | `app_role`, `app_user`, `app_group`, `group_member`, `group_role`, `principal_role` |
| `V2__catalog.sql` | `datasource`, `catalog_column`, `mask_fn`, `column_classification` |
| `V3__policy.sql` | `policy` (the Cedar store, with its origin constraints), `allowlist` |
| `V4__audit.sql` | `audit_event`, `audit_chain_head` and its genesis row |
| `V5__tasks.sql` | `access_request`, `access_grant`, `query_result`, `query_history` |
| `V6__sessions.sql` | `device_login`, `principal_session` |
| `V7__tokens.sql` | `oauth_consent`, `oauth_authorization_code`, `proxy_token`, `mcp_mutation_idempotency` |
| `V8__seed.sql` | The shipped starter package: predefined roles, protected groups, and the SYSTEM Cedar policies |
| `V13__classification_profile.sql` | `classification_profile`, `classification_profile_rule`, `datasource_classification_profile` — shared column classification |

`V8` comes last because it seeds rows into tables the earlier files create, and
it is the only file with no DDL. Everything it writes is SYSTEM-owned — a
negative id from the reserved blocks, a write-once `system_key`,
`origin='SYSTEM'` — so an administrator may toggle `enabled` but never edit the
source ([`policy-store.md`](./policy-store.md)).

A schema change is a new `V9__…`, grouped the same way: a whole new subject gets
its own file, while a column on an existing table is an `ALTER TABLE` in a file
named for the change.

## Postgres DDL in transactions

Postgres wraps each migration in a transaction and rolls it back on failure, so
the schema never lands half-applied. `CREATE/ALTER/DROP TABLE|INDEX|TYPE|VIEW`,
column add/drop, and constraints all run transactionally.

Per-migration is the right granularity: a failed migration rolls back cleanly
while already-applied ones stay recorded. A few statements cannot run inside a
transaction — `CREATE INDEX CONCURRENTLY`, `ALTER TYPE … ADD VALUE`, `VACUUM`,
`CREATE/DROP DATABASE`, `ALTER SYSTEM`, `REINDEX CONCURRENTLY`. A migration that
needs one marks itself non-transactional with
`-- flyway:executeInTransaction=false` at the top and must be idempotent, since
it can partially apply on failure and has to be safe to re-run. Every migration
here is ordinary transactional DDL.

## Rules

- Never edit an applied migration. Flyway checksums applied migrations and fails
  `validateOnMigrate` at boot if one changes. To change the schema, add a new
  `V{n+1}__…`. This covers even a comment fix on a shipped `V*.sql`.
  [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) enforces this: the
  `migrations` job fails a pull request that modifies, renames, or deletes a
  file under `resources/db/migration/`.
- Forward-only. Flyway Community has no down-migrations; to revert, write a new
  forward migration.
- No baseline — the schema is greenfield, built from `V1` on a clean database.

## Multiple instances

The system runs single-instance, where migrate-on-boot is correct and needs
nothing extra. Two safe options exist for a fleet:

- Keep migrate-on-boot. Flyway takes a Postgres advisory lock on
  `flyway_schema_history`, so concurrent instances serialize: one migrates, the
  rest wait and then see the up-to-date schema. Every instance then needs DDL
  privileges and boots serialize briefly.
- Run a dedicated migrate step before the app fleet starts (an init-job that
  constructs the same pool and calls `Db.migrate()`, or an equivalent wrapper).
  No `--migrate-only` flag exists today — it would be a small Main entry
  addition. App instances then connect read/write only.
