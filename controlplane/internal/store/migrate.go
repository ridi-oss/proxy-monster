package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/migrations"
)

// historyTable is Flyway's own table, adopted unchanged. D4 (99-library-decisions.md §5): every Go
// migration library owns its own history table, and the constraint here is the opposite one —
// "migrating an existing deployment means the Go runner must read the table Flyway already wrote"
// (01-bootstrap.md:124-128). Keeping the table is also what makes a rollback to the Kotlin binary a
// deploy rather than a restore.
const historyTable = "flyway_schema_history"

// migrationDir is the subdirectory of internal/migrations.FS holding V1..V10.
const migrationDir = "sql"

// repairChecksumsEnv is read HERE, in the migration runner, and nowhere else.
//
// ⚠️ 01-bootstrap.md §1 flags it as the ONLY environment variable read outside Config.fromEnv —
// Db.kt calls System.getenv directly inside migrate(). REPRODUCE the seam: do not tidy it into
// internal/config. internal/config/doc.go carries the same instruction from the other side.
const repairChecksumsEnv = "PM_DB_REPAIR_CHECKSUMS"

// createHistoryTableSQL is Flyway's PostgreSQL schema-history DDL.
//
// ⚠️ Unverified — reconstructed from the documented column shape, not dumped from a Flyway-migrated
// database (there is no Flyway jar on this machine; 99-library-decisions.md §5 records the same
// limitation for the checksum algorithm). It matters on a CLEAN database only: an existing
// deployment already has the table Flyway created and this is a no-op. It is covered by the same
// mandatory docker-compose parity gate as FlywayChecksum.
const createHistoryTableSQL = `
CREATE TABLE IF NOT EXISTS ` + historyTable + ` (
    installed_rank INT NOT NULL,
    version VARCHAR(50),
    description VARCHAR(200) NOT NULL,
    type VARCHAR(20) NOT NULL,
    script VARCHAR(1000) NOT NULL,
    checksum INTEGER,
    installed_by VARCHAR(100) NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT now(),
    execution_time INTEGER NOT NULL,
    success BOOLEAN NOT NULL,
    CONSTRAINT ` + historyTable + `_pk PRIMARY KEY (installed_rank)
);
CREATE INDEX IF NOT EXISTS ` + historyTable + `_s_idx ON ` + historyTable + ` (success);
`

const (
	selectHistorySQL = `SELECT installed_rank, version, checksum, success FROM ` + historyTable +
		` WHERE version IS NOT NULL ORDER BY installed_rank`

	maxInstalledRankSQL = `SELECT COALESCE(MAX(installed_rank), 0) FROM ` + historyTable

	repairChecksumSQL = `UPDATE ` + historyTable + ` SET checksum = $1 WHERE installed_rank = $2`

	insertHistorySQL = `INSERT INTO ` + historyTable + ` ` +
		`(installed_rank, version, description, type, script, checksum, installed_by, execution_time, success) ` +
		`VALUES ($1, $2, $3, $4, $5, $6, current_user, $7, TRUE)`
)

// appliedMigration is one row of flyway_schema_history.
type appliedMigration struct {
	installedRank int32
	version       string
	checksum      *int32 // nullable in Flyway's schema; a NULL is "no checksum recorded"
	success       bool
}

// ChecksumMismatchError is the boot refusal Flyway's validateOnMigrate raises when an already-applied
// migration file has changed since it ran.
//
// docs/migrations.md "Rules": never edit an applied migration — "this covers even a comment fix on a
// shipped V*.sql", and .github/workflows/ci.yml fails a pull request that modifies, renames or
// deletes a file under resources/db/migration/. PM_DB_REPAIR_CHECKSUMS is the escape hatch for the
// one release that legitimately edited applied files.
type ChecksumMismatchError struct {
	Script   string
	Version  string
	Stored   int32
	Computed int32
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf(
		"migration %s (version %s) has changed since it was applied: stored checksum %d, computed %d; "+
			"add a new migration instead, or set %s=true for one boot to realign the recorded checksums",
		e.Script, e.Version, e.Stored, e.Computed, repairChecksumsEnv)
}

// Migrate applies pending migrations. Call once at startup before serving traffic — A1's boot
// sequence is Config → banner → Db → migrate → ControlPlaneCore, and a migration failure must
// propagate out of main() so the process exits without opening a port (docs/migrations.md).
//
// It is the port of Db.migrate(), which is `flyway.repair()` (conditionally) then `flyway.migrate()`.
// PM_DB_REPAIR_CHECKSUMS=true realigns the stored checksums of already-applied migrations to the
// files on disk BEFORE migrating. Repair rewrites flyway_schema_history rows only: it applies no SQL
// and touches no schema or data. It is off by default and deliberately not a permanent setting —
// leaving it on would mean a modified migration silently becomes the new expected state, which is the
// guarantee the flag exists to restore, not to discard.
func (d *Db) Migrate(ctx context.Context) error {
	return runMigrations(ctx, d.Pool, migrations.FS, migrationDir, repairChecksumsRequested())
}

// repairChecksumsRequested ports `System.getenv("PM_DB_REPAIR_CHECKSUMS")?.equals("true",
// ignoreCase = true) == true`. os.Getenv returns "" when unset, which EqualFold rejects, so an unset
// variable is false exactly as a null is in the Kotlin.
func repairChecksumsRequested() bool {
	return strings.EqualFold(os.Getenv(repairChecksumsEnv), "true")
}

// runMigrations is the runner D4 chose over golang-migrate, goose and Atlas — all three own their own
// history table, and none can read Flyway's.
//
// Order, from 99-library-decisions.md §5 "What the runner must do":
//
//  1. read flyway_schema_history; the applied set is the version column where success = true;
//  2. repair first if asked, rewriting checksums only;
//  3. recompute the checksum of every already-applied migration and refuse to boot on a mismatch
//     (Flyway's validateOnMigrate);
//  4. apply only files above the recorded version, each in its own transaction, aborting startup on
//     failure;
//  5. honour `-- flyway:executeInTransaction=false`;
//  6. append rows in Flyway's exact column shape.
//
// ⚠️ What it deliberately does NOT validate, and why: Flyway's validate also fails on a description
// mismatch, a type mismatch, and an applied migration that no longer resolves locally. Each of those
// depends on a derivation this port cannot verify against a real Flyway (see parseMigrationName), and
// a wrong derivation would refuse to boot a HEALTHY control plane — the worse half of D4's two-sided
// fail-closed risk. Checksum is the one rule the area docs state, so it is the one rule enforced.
//
// TODO(A1): extend to full validate parity once the docker-compose gate in 99-library-decisions.md
// §5 has produced a real flyway_schema_history dump to compare against.
//
// ⚠️ It also takes NO advisory lock on the history table. Flyway serialises concurrent migrators with
// one (docs/migrations.md:96-99), but whether the Go runner would derive the SAME key is Unverified,
// and a mismatched key means two migrators that cannot see each other — strictly worse than none,
// because it looks like it works. 99-library-decisions.md §5 dispositions this: run migrations as one
// discrete step at cutover rather than relying on migrate-on-boot across a fleet. Concurrent Go
// boots still fail closed (the installed_rank primary key and the DDL itself conflict), they do not
// corrupt.
//
// TODO(A1): the `--migrate-only` entry point docs/migrations.md:102 notes does not exist yet.
func runMigrations(ctx context.Context, db DB, fsys fs.FS, dir string, repair bool) error {
	all, err := loadMigrations(fsys, dir)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		return fmt.Errorf("no migrations found under %s", dir)
	}
	byVersion := make(map[string]migration, len(all))
	for _, m := range all {
		byVersion[m.version] = m
	}

	if _, err := db.Exec(ctx, createHistoryTableSQL); err != nil {
		return fmt.Errorf("create %s: %w", historyTable, err)
	}

	history, err := readHistory(ctx, db)
	if err != nil {
		return err
	}

	if repair {
		if err := repairChecksums(ctx, db, history, byVersion); err != nil {
			return err
		}
		if history, err = readHistory(ctx, db); err != nil {
			return err
		}
	}

	if err := validateChecksums(history, byVersion); err != nil {
		return err
	}

	pending := pendingAfter(all, highestAppliedVersion(history, byVersion))
	if len(pending) == 0 {
		slog.Info("migrations up to date", "pool", PoolName, "applied", len(history))
		return nil
	}

	rank, err := nextInstalledRank(ctx, db)
	if err != nil {
		return err
	}
	for _, m := range pending {
		if err := applyMigration(ctx, db, m, rank); err != nil {
			// Fail-closed: a migration failure aborts startup so the API never serves on a
			// half-migrated schema (docs/migrations.md).
			return fmt.Errorf("migration %s failed: %w", m.script, err)
		}
		rank++
	}
	return nil
}

func readHistory(ctx context.Context, db Queryer) ([]appliedMigration, error) {
	rows, err := db.Query(ctx, selectHistorySQL)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", historyTable, err)
	}
	defer rows.Close()

	var out []appliedMigration
	for rows.Next() {
		var r appliedMigration
		if err := rows.Scan(&r.installedRank, &r.version, &r.checksum, &r.success); err != nil {
			return nil, fmt.Errorf("read %s: %w", historyTable, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", historyTable, err)
	}
	return out, nil
}

// repairChecksums realigns the recorded checksum of every successfully-applied migration that still
// ships as a file. It writes the checksum column and nothing else — no schema, no data, and not the
// description or type either, because those derivations are Unverified (see parseMigrationName) and
// repair is the one place a wrong one would be written back as the new truth.
func repairChecksums(ctx context.Context, db Queryer, history []appliedMigration, byVersion map[string]migration) error {
	for _, row := range history {
		if !row.success {
			continue
		}
		m, ok := byVersion[row.version]
		if !ok {
			continue
		}
		if row.checksum != nil && *row.checksum == m.checksum {
			continue
		}
		if _, err := db.Exec(ctx, repairChecksumSQL, m.checksum, row.installedRank); err != nil {
			return fmt.Errorf("repair %s: %w", m.script, err)
		}
		slog.Warn("repaired migration checksum",
			"env", repairChecksumsEnv, "script", m.script, "version", m.version, "checksum", m.checksum)
	}
	return nil
}

func validateChecksums(history []appliedMigration, byVersion map[string]migration) error {
	var errs []error
	for _, row := range history {
		if !row.success || row.checksum == nil {
			// A NULL checksum is Flyway's "nothing recorded to compare"; it is not a mismatch.
			continue
		}
		m, ok := byVersion[row.version]
		if !ok {
			continue
		}
		if *row.checksum != m.checksum {
			errs = append(errs, &ChecksumMismatchError{
				Script: m.script, Version: m.version, Stored: *row.checksum, Computed: m.checksum,
			})
		}
	}
	return errors.Join(errs...)
}

// highestAppliedVersion returns the parsed order of the newest successfully-applied migration, or nil
// when nothing has been applied. Rows whose version does not resolve to a shipped file are skipped:
// their order cannot be parsed from a file that is not there, and 99-library-decisions.md §5 rule 1
// defines the applied set by the version column, not by what the binary happens to ship.
func highestAppliedVersion(history []appliedMigration, byVersion map[string]migration) []int64 {
	var highest []int64
	for _, row := range history {
		if !row.success {
			continue
		}
		m, ok := byVersion[row.version]
		if !ok {
			continue
		}
		if highest == nil || compareVersions(m.order, highest) > 0 {
			highest = m.order
		}
	}
	return highest
}

func nextInstalledRank(ctx context.Context, db Queryer) (int32, error) {
	var maxRank int32
	if err := db.QueryRow(ctx, maxInstalledRankSQL).Scan(&maxRank); err != nil {
		return 0, fmt.Errorf("read %s installed_rank: %w", historyTable, err)
	}
	return maxRank + 1, nil
}

// applyMigration runs one migration and records it.
//
// The transactional path puts the migration body AND its history row in one transaction, so a
// failure leaves neither behind — which is why a Postgres deployment never accumulates success=false
// rows and why the runner does not need to clean them up.
//
// The non-transactional path (`-- flyway:executeInTransaction=false`) cannot offer that: the file
// must be idempotent because it can partially apply and has to be safe to re-run
// (docs/migrations.md). No shipped migration takes this path.
func applyMigration(ctx context.Context, db DB, m migration, rank int32) error {
	slog.Info("applying migration",
		"pool", PoolName, "script", m.script, "version", m.version, "description", m.description,
		"inTransaction", m.inTransaction)

	if !m.inTransaction {
		start := time.Now()
		if _, err := db.Exec(ctx, string(m.body)); err != nil {
			return err
		}
		return recordMigration(ctx, db, m, rank, time.Since(start))
	}

	return InTxDo(ctx, db, func(ctx context.Context, tx pgx.Tx) error {
		start := time.Now()
		// No bind parameters: pgx uses the simple protocol when len(args) == 0
		// (pgx/v5@v5.7.1 conn.go, "Always use simple protocol when there are no arguments"), which is
		// what lets one Exec carry a whole multi-statement migration file.
		if _, err := tx.Exec(ctx, string(m.body)); err != nil {
			return err
		}
		return recordMigration(ctx, tx, m, rank, time.Since(start))
	})
}

// recordMigration appends the row in Flyway's exact column shape. installed_on comes from the
// column's `DEFAULT now()` and installed_by from `current_user`, which is what Flyway records when
// configuration.installedBy is unset.
func recordMigration(ctx context.Context, c Queryer, m migration, rank int32, took time.Duration) error {
	_, err := c.Exec(ctx, insertHistorySQL,
		rank, m.version, m.description, migrationType, m.script, m.checksum,
		int32(took.Milliseconds()))
	if err != nil {
		return fmt.Errorf("record %s in %s: %w", m.script, historyTable, err)
	}
	return nil
}
