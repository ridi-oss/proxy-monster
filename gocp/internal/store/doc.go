// Package store owns the database handle: the pooled PostgreSQL connection and the migration runner.
// It is the Go equivalent of Db.kt (48 LOC).
//
// Area doc: plans/proxy-monster-go-port/01-bootstrap.md §2 ("Db").
//
// # Pool (D3)
//
// pgx/v5 native (pgxpool), pinned v5.7.1 to match goproxy's require — go.work resolves one version per
// module across the whole workspace, so bumping it here rebuilds goproxy too. pgxpool.Config.MaxConns
// = 10 is the one-line equivalent of HikariCP's maximumPoolSize = 10; the pool name is
// pm-control-plane and the driver is hardcoded.
//
// PM_DB_URL is a JDBC URL (jdbc:postgresql://host:port/db). Deploy docs, docker-compose and the mise
// tasks all set that exact shape, so the Go port must accept or translate it rather than demand a
// libpq DSN.
//
// Two pgx properties are load-bearing downstream and are why the driver was chosen:
// *pgconn.PgError.Code is a direct port of SQLException.sqlState, keeping "23505 matched, 23503
// deliberately NOT matched" exactly that narrow (03-identity-scim.md:878,
// 04-auth-session-tokens.md:1003); and pgx's type map infers the jsonb parameter OID, the analogue of
// the Kotlin's PGobject, whose two idioms F16 requires be kept distinguishable.
//
// The single biggest mechanical hazard in the whole port lives in this package's callers: JDBC's
// positional `?` becomes `$1…$n`, and a mis-numbered argument is a SILENT wrong-value bug, not a
// compile error.
//
// # Migrations (D4)
//
// Hand-rolled runner over Flyway's OWN flyway_schema_history table. No migration library: golang-
// migrate, goose and Atlas each own their own history table, and the constraint here is the opposite
// one — migrating an existing deployment means READING the table Flyway already wrote
// (01-bootstrap.md §2). build.gradle.kts:12 pins Flyway 13.0.0 (docs/migrations.md:11 says 11.1.0 and
// is stale), so the checksum reimplementation must target 13.0.0.
//
// The runner must:
//
//   - read the success = true rows and apply only files newer than the highest applied version;
//   - run each migration in its own transaction and ABORT STARTUP on failure;
//   - honour `-- flyway:executeInTransaction=false`;
//   - recompute the checksum of every already-applied file and REFUSE TO BOOT on a mismatch — this is
//     Flyway's validateOnMigrate, the behaviour ci.yml:91-96 protects;
//   - run PM_DB_REPAIR_CHECKSUMS=true as a pre-migrate repair that rewrites flyway_schema_history rows
//     ONLY (no SQL applied, no schema or data touched). REPRODUCE that this is the one env var read
//     outside Config.fromEnv;
//   - append rows in Flyway's exact column shape, so rolling back to the Kotlin binary is a deploy
//     rather than a restore.
//
// It fails closed in both directions: too strict refuses a healthy control plane, too lax lets an
// edited migration through silently.
//
// # Shared transaction primitives (03-identity-scim.md §"Deprovision.kt")
//
// InTx and AdvisoryLockPrincipal live here rather than in A3 because A4, A6, A7 and A11 all consume
// them and every area assumes the same semantics. AdvisoryLockPrincipal issues exactly
// `SELECT pg_advisory_xact_lock(hashtext($1))` — the key is computed BY POSTGRES (INV-A3-4), never in
// Go, or a rolling cutover loses mutual exclusion against a still-running Kotlin instance. It is a
// transaction-scoped Postgres lock, NOT an in-process mutex: cross-instance exclusion is the point.
//
// IsUniqueViolation matches SQLSTATE 23505 and nothing else. 23503 (foreign-key violation) is
// deliberately NOT matched (03-identity-scim.md:878, F29) — this package therefore ships no
// foreign-key predicate at all.
//
// # Increment 1 status
//
// Landed: TranslateJDBCURL, the pool (MaxPoolSize = 10), Migrate with the Flyway-compatible runner
// and PM_DB_REPAIR_CHECKSUMS, InTx/InTxDo, AdvisoryLockPrincipal, IsUniqueViolation. Tests cover
// everything that needs no database.
//
// 🔴 TODO(A1): the Flyway checksum and history-table DDL are ⚠️ Unverified reimplementations. Run the
// docker-compose parity gate (99-library-decisions.md §5) — migrate a clean database with the Kotlin
// stack, dump flyway_schema_history, and assert FlywayChecksum reproduces all ten stored values —
// before pointing this runner at any real deployment.
// The DB-backed harness this package's remaining tests need now exists: internal/dbtest (D13,
// testcontainers-go v0.34.0, fail-not-skip). Its MigratedStore runs THIS runner against a live
// PostgreSQL on every DB-backed test, and internal/dbtest/migrations_smoke_test.go already covers
// the first two cases — the ten history rows in Flyway's column shape, and a re-run applying nothing.
//
// TODO(A1): the rest of the runner's DB-backed cases, in internal/dbtest terms: corrupt a stored
// checksum and assert the boot refusal, then assert PM_DB_REPAIR_CHECKSUMS=true realigns it and
// touches no schema or data. Then the advisory-lock tests 03-identity-scim.md:1247/1256 describe —
// hold the lock from a raw connection and assert the call under test BLOCKS.
// TODO(A1): the ~17 stores hanging off ControlPlaneCore (auditStore, datasourceStore, policyStore,
// accessStore, userGroupStore, tokenStore, mcpTokenStore, …) belong to their own areas, not here.
// INV-A1-1 requires ONE ControlPlaneCore shared by the HTTP and gRPC surfaces: CedarEngine caches its
// compiled PolicySet and rebuilds only when CedarPolicyStore.stateVersion() moves, and that counter is
// per-instance — two graphs means a policy edited over HTTP never invalidates the gRPC-side engine.
package store
