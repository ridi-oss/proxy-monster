package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// flywayRow is one flyway_schema_history row, read back in Flyway's own column shape.
type flywayRow struct {
	InstalledRank int32
	Version       *string
	Description   string
	Type          string
	Script        string
	Checksum      *int32
	InstalledBy   string
	InstalledOn   time.Time
	ExecutionTime int32
	Success       bool
}

// wantHistory is what the ten shipped migrations must produce, in order. Written out literally rather
// than derived from the file names, because deriving it would make the test agree with the runner by
// construction — the description column in particular is an ⚠️ Unverified derivation
// (store/migration_files.go's parseMigrationName), and the point of pinning it here is that a change
// to that derivation shows up as a diff instead of as a silently different history table.
var wantHistory = []struct{ version, description, script string }{
	{"1", "identity", "V1__identity.sql"},
	{"2", "catalog", "V2__catalog.sql"},
	{"3", "policy", "V3__policy.sql"},
	{"4", "audit", "V4__audit.sql"},
	{"5", "tasks", "V5__tasks.sql"},
	{"6", "sessions", "V6__sessions.sql"},
	{"7", "tokens", "V7__tokens.sql"},
	{"8", "seed", "V8__seed.sql"},
	{"9", "datasource cert chain", "V9__datasource_cert_chain.sql"},
	{"10", "debug requester ip", "V10__debug_requester_ip.sql"},
	{"11", "result deny context", "V11__result_deny_context.sql"},
	{"12", "format policy source", "V12__format_policy_source.sql"},
}

// TestMigrations_EverySuccessRowInFlywayShape is the harness's own smoke test AND the first real
// exercise of internal/store's Flyway-compatible migration runner against a live PostgreSQL — the
// TODO(A1) internal/store/doc.go leaves open.
//
// It starts (or reuses) the shared container, creates a fresh database, runs all ten migrations
// through the PRODUCTION runner, and asserts flyway_schema_history came out in Flyway's own shape.
// The database is dropped at cleanup.
//
// ⚠️ What this does NOT prove: that the checksums equal what a real Flyway 13.0.0 would write. That
// needs the docker-compose parity gate (99-library-decisions.md §5) — migrate with the Kotlin stack,
// dump the table, compare. This proves the runner is internally consistent and Flyway-SHAPED.
func TestMigrations_EverySuccessRowInFlywayShape(t *testing.T) {
	ctx := context.Background()
	db, name := MigratedStore(t)
	t.Logf("migrated control-plane store on database %s (image %s, server %s)",
		name, Postgres(t).Image, Postgres(t).Series(t))

	rows, err := db.Pool.Query(ctx,
		`SELECT installed_rank, version, description, type, script, checksum,
		        installed_by, installed_on, execution_time, success
		   FROM flyway_schema_history
		  ORDER BY installed_rank`)
	if err != nil {
		t.Fatalf("read flyway_schema_history: %v", err)
	}
	defer rows.Close()

	var history []flywayRow
	for rows.Next() {
		var r flywayRow
		if err := rows.Scan(&r.InstalledRank, &r.Version, &r.Description, &r.Type, &r.Script,
			&r.Checksum, &r.InstalledBy, &r.InstalledOn, &r.ExecutionTime, &r.Success); err != nil {
			t.Fatalf("scan flyway_schema_history: %v", err)
		}
		history = append(history, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read flyway_schema_history: %v", err)
	}

	if len(history) != len(wantHistory) {
		t.Fatalf("flyway_schema_history has %d rows, want %d", len(history), len(wantHistory))
	}

	for i, want := range wantHistory {
		got := history[i]
		// installed_rank is 1-based and dense: Flyway's PRIMARY KEY, and what the runner's
		// nextInstalledRank derives the next value from.
		if int(got.InstalledRank) != i+1 {
			t.Errorf("row %d: installed_rank = %d, want %d", i, got.InstalledRank, i+1)
		}
		if got.Version == nil || *got.Version != want.version {
			t.Errorf("row %d: version = %v, want %q", i, got.Version, want.version)
		}
		if got.Description != want.description {
			t.Errorf("row %d: description = %q, want %q (underscores become spaces)",
				i, got.Description, want.description)
		}
		if got.Script != want.script {
			t.Errorf("row %d: script = %q, want %q", i, got.Script, want.script)
		}
		if got.Type != "SQL" {
			t.Errorf("row %d (%s): type = %q, want \"SQL\"", i, want.script, got.Type)
		}
		if !got.Success {
			t.Errorf("row %d (%s): success = false — a failed migration must abort startup, "+
				"never land as a row", i, want.script)
		}
		if got.Checksum == nil {
			t.Errorf("row %d (%s): checksum is NULL — validateOnMigrate has nothing to compare and "+
				"an edited migration would boot silently", i, want.script)
		}
		// installed_by comes from the column's `current_user`, which is what Flyway records when
		// configuration.installedBy is unset.
		if got.InstalledBy != Postgres(t).User {
			t.Errorf("row %d (%s): installed_by = %q, want %q (current_user)",
				i, want.script, got.InstalledBy, Postgres(t).User)
		}
		if got.InstalledOn.IsZero() {
			t.Errorf("row %d (%s): installed_on is zero", i, want.script)
		}
		if got.ExecutionTime < 0 {
			t.Errorf("row %d (%s): execution_time = %d, want >= 0", i, want.script, got.ExecutionTime)
		}
	}

	// Every checksum distinct: ten identical values would mean the checksum is not a function of the
	// file, and every mismatch check would be vacuous.
	seen := map[int32]string{}
	for i, r := range history {
		if r.Checksum == nil {
			continue
		}
		if prev, dup := seen[*r.Checksum]; dup {
			t.Errorf("checksum %d is shared by %s and %s — the checksum is not file-dependent",
				*r.Checksum, prev, wantHistory[i].script)
		}
		seen[*r.Checksum] = wantHistory[i].script
	}

	assertFlywayTableShape(t, db.Pool)
	assertSchemaObjectsExist(t, db.Pool)
}

// wantFlywayColumns is Flyway's PostgreSQL schema-history column shape: name -> information_schema
// data_type, in ordinal order.
var wantFlywayColumns = []struct{ name, dataType string }{
	{"installed_rank", "integer"},
	{"version", "character varying"},
	{"description", "character varying"},
	{"type", "character varying"},
	{"script", "character varying"},
	{"checksum", "integer"},
	{"installed_by", "character varying"},
	{"installed_on", "timestamp without time zone"},
	{"execution_time", "integer"},
	{"success", "boolean"},
}

// assertFlywayTableShape pins the table's own columns. "In Flyway's own shape" is the property that
// makes a rollback to the Kotlin binary a deploy rather than a restore — the Kotlin's Flyway has to be
// able to read what the Go runner wrote — and the shape is the half of that a test can check on a
// machine with no Flyway jar (99-library-decisions.md §5 owns the other half).
func assertFlywayTableShape(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT column_name, data_type FROM information_schema.columns
		  WHERE table_name = 'flyway_schema_history' ORDER BY ordinal_position`)
	if err != nil {
		t.Fatalf("read flyway_schema_history shape: %v", err)
	}
	defer rows.Close()

	var got []struct{ name, dataType string }
	for rows.Next() {
		var c struct{ name, dataType string }
		if err := rows.Scan(&c.name, &c.dataType); err != nil {
			t.Fatalf("read flyway_schema_history shape: %v", err)
		}
		got = append(got, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read flyway_schema_history shape: %v", err)
	}

	if len(got) != len(wantFlywayColumns) {
		t.Fatalf("flyway_schema_history has %d columns, want %d: %+v", len(got), len(wantFlywayColumns), got)
	}
	for i, want := range wantFlywayColumns {
		if got[i].name != want.name || got[i].dataType != want.dataType {
			t.Errorf("flyway_schema_history column %d = %s %s, want %s %s",
				i, got[i].name, got[i].dataType, want.name, want.dataType)
		}
	}

	// The PRIMARY KEY is what makes two concurrent migrators conflict instead of interleaving — the
	// runner takes no advisory lock and relies on exactly this to fail closed (store/migrate.go).
	var pk string
	err = pool.QueryRow(context.Background(),
		`SELECT constraint_name FROM information_schema.table_constraints
		  WHERE table_name = 'flyway_schema_history' AND constraint_type = 'PRIMARY KEY'`).Scan(&pk)
	if err != nil {
		t.Fatalf("flyway_schema_history has no PRIMARY KEY: %v", err)
	}
	if pk != "flyway_schema_history_pk" {
		t.Errorf("primary key is %q, want %q (Flyway's own name)", pk, "flyway_schema_history_pk")
	}
}

// migratedTables is one table from each migration that creates tables, so the test proves the
// migrations really ran rather than only that ten history rows were appended.
var migratedTables = map[string]string{
	"V1__identity.sql": "app_role",
	"V2__catalog.sql":  "catalog_column",
	"V3__policy.sql":   "policy",
	"V4__audit.sql":    "audit_event",
	"V5__tasks.sql":    "access_request",
	"V6__sessions.sql": "principal_session",
	"V7__tokens.sql":   "proxy_token",
}

// assertSchemaObjectsExist spot-checks that the migrations created the schema, not merely the history
// rows. A runner that recorded ten rows and executed nothing would pass every assertion above.
func assertSchemaObjectsExist(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for script, table := range migratedTables {
		var exists bool
		err := pool.QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
			                 WHERE table_schema = 'public' AND table_name = $1)`, table).Scan(&exists)
		if err != nil {
			t.Fatalf("probe table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("%s recorded a history row but its table %q does not exist", script, table)
		}
	}

	// V8__seed.sql installs seven source=SYSTEM groups (F34, 00-INDEX.md:220) — the finding that a
	// port special-casing the string "system:admin" leaves six production-capability groups mutable.
	// Asserting the count here is what keeps that finding visible in the harness the suites build on.
	var systemGroups int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM app_group WHERE source = 'SYSTEM'`).Scan(&systemGroups); err != nil {
		t.Fatalf("count SYSTEM groups: %v", err)
	}
	if systemGroups != 7 {
		t.Errorf("V8__seed.sql installed %d source=SYSTEM groups, want 7 (F34: the guards key on the "+
			"COLUMN, not on the string \"system:admin\")", systemGroups)
	}
}

// TestMigrations_SecondRunAppliesNothing pins the runner's idempotence: a re-migrate over an
// already-migrated database must apply no file and append no row.
//
// The checksum validation runs on that second pass too, so this is also the only test that exercises
// validateChecksums against checksums the runner itself wrote — the "recompute every applied file and
// refuse to boot on a mismatch" rule, in its passing direction.
func TestMigrations_SecondRunAppliesNothing(t *testing.T) {
	ctx := context.Background()
	db, _ := MigratedStore(t)

	var before []int32
	rows, err := db.Pool.Query(ctx, `SELECT checksum FROM flyway_schema_history ORDER BY installed_rank`)
	if err != nil {
		t.Fatalf("read checksums: %v", err)
	}
	for rows.Next() {
		var c *int32
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("read checksums: %v", err)
		}
		before = append(before, *c)
	}
	rows.Close()

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate over an up-to-date database: %v", err)
	}

	var after int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM flyway_schema_history`).Scan(&after); err != nil {
		t.Fatalf("count history: %v", err)
	}
	if after != len(before) {
		t.Errorf("second Migrate changed flyway_schema_history from %d to %d rows", len(before), after)
	}
}
