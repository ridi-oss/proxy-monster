package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/migrations"
)

// ⚠️ PM_DB_REPAIR_CHECKSUMS is the ONLY environment variable read outside Config.fromEnv
// (01-bootstrap.md §1) — Db.kt calls System.getenv directly inside migrate(). REPRODUCE the seam.
// Kotlin: `System.getenv("PM_DB_REPAIR_CHECKSUMS")?.equals("true", ignoreCase = true) == true`.
func TestRepairChecksumsRequested(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"false", false},
		{"", false}, // an unset variable: os.Getenv gives "", Kotlin gives null
		{"1", false},
		{"yes", false},
		{" true", false}, // Kotlin's equals does not trim either
	}
	for _, tc := range cases {
		t.Setenv(repairChecksumsEnv, tc.value)
		if got := repairChecksumsRequested(); got != tc.want {
			t.Errorf("%s=%q: repairChecksumsRequested() = %v, want %v", repairChecksumsEnv, tc.value, got, tc.want)
		}
	}
}

func i32(v int32) *int32 { return &v }

// Flyway's validateOnMigrate: an already-applied migration whose file has changed refuses the boot.
// docs/migrations.md "Rules" — never edit an applied migration, "this covers even a comment fix on a
// shipped V*.sql". .github/workflows/ci.yml exists to protect exactly this.
func TestValidateChecksumsRefusesAChangedMigration(t *testing.T) {
	byVersion := map[string]migration{
		"1": {version: "1", script: "V1__identity.sql", checksum: 111},
		"2": {version: "2", script: "V2__catalog.sql", checksum: 222},
	}

	clean := []appliedMigration{
		{installedRank: 1, version: "1", checksum: i32(111), success: true},
		{installedRank: 2, version: "2", checksum: i32(222), success: true},
	}
	if err := validateChecksums(clean, byVersion); err != nil {
		t.Fatalf("a matching history must validate: %v", err)
	}

	edited := []appliedMigration{
		{installedRank: 1, version: "1", checksum: i32(111), success: true},
		{installedRank: 2, version: "2", checksum: i32(999), success: true},
	}
	err := validateChecksums(edited, byVersion)
	if err == nil {
		t.Fatal("an edited applied migration must refuse the boot")
	}
	var mismatch *ChecksumMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want a *ChecksumMismatchError", err)
	}
	if mismatch.Script != "V2__catalog.sql" || mismatch.Stored != 999 || mismatch.Computed != 222 {
		t.Errorf("mismatch = %+v, want V2__catalog.sql stored 999 computed 222", mismatch)
	}
	// The message has to name the escape hatch, because the operator hitting it has a control plane
	// that will not boot and no other signal.
	if !strings.Contains(mismatch.Error(), repairChecksumsEnv) {
		t.Errorf("the refusal must name %s: %s", repairChecksumsEnv, mismatch.Error())
	}
}

func TestValidateChecksumsSkipsWhatItCannotCompare(t *testing.T) {
	byVersion := map[string]migration{
		"1": {version: "1", script: "V1__identity.sql", checksum: 111},
	}
	history := []appliedMigration{
		// A failed row is not part of the applied set (99-library-decisions.md §5 rule 1).
		{installedRank: 1, version: "1", checksum: i32(999), success: false},
		// A NULL checksum is Flyway's "nothing recorded to compare", not a mismatch.
		{installedRank: 2, version: "1", checksum: nil, success: true},
		// A version this binary does not ship cannot be recomputed. Flyway's full validate reports it
		// as "applied migration not resolved locally"; this runner deliberately does not — see
		// runMigrations' doc for why the description/type/missing rules are left out.
		{installedRank: 3, version: "42", checksum: i32(1), success: true},
	}
	if err := validateChecksums(history, byVersion); err != nil {
		t.Errorf("nothing here is comparable, so nothing may fail: %v", err)
	}
}

func TestHighestAppliedVersion(t *testing.T) {
	all, err := loadMigrations(migrations.FS, migrationDir)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	byVersion := make(map[string]migration, len(all))
	for _, m := range all {
		byVersion[m.version] = m
	}

	if got := highestAppliedVersion(nil, byVersion); got != nil {
		t.Errorf("an empty history has no highest version, got %v", got)
	}

	// Numeric, not lexicographic, and not "the last row": installed_rank order and version order are
	// independent columns.
	history := []appliedMigration{
		{installedRank: 1, version: "1", success: true},
		{installedRank: 2, version: "10", success: true},
		{installedRank: 3, version: "9", success: true},
	}
	ten, _ := parseVersionOrder("10")
	if got := highestAppliedVersion(history, byVersion); compareVersions(got, ten) != 0 {
		t.Errorf("highest = %v, want version 10", got)
	}

	// A failed row does not count as applied.
	failed := []appliedMigration{
		{installedRank: 1, version: "1", success: true},
		{installedRank: 2, version: "10", success: false},
	}
	one, _ := parseVersionOrder("1")
	if got := highestAppliedVersion(failed, byVersion); compareVersions(got, one) != 0 {
		t.Errorf("highest = %v, want version 1 (the failed V10 row is not applied)", got)
	}
}

// The whole runner over the shipped set, at the two ends: a clean database applies all ten in
// numeric order, and an up-to-date one applies nothing.
func TestPendingOverTheShippedSet(t *testing.T) {
	all, err := loadMigrations(migrations.FS, migrationDir)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	byVersion := make(map[string]migration, len(all))
	for _, m := range all {
		byVersion[m.version] = m
	}

	clean := pendingAfter(all, highestAppliedVersion(nil, byVersion))
	if len(clean) != 12 {
		t.Fatalf("clean database: %d pending, want 12", len(clean))
	}
	if clean[0].script != "V1__identity.sql" || clean[11].script != "V12__format_policy_source.sql" {
		t.Errorf("clean database order = %v, want V1 first and V12 last", versionsOf(clean))
	}

	var history []appliedMigration
	for i, m := range all {
		history = append(history, appliedMigration{
			installedRank: int32(i + 1), version: m.version, checksum: i32(m.checksum), success: true,
		})
	}
	if err := validateChecksums(history, byVersion); err != nil {
		t.Fatalf("a history written from these same files must validate: %v", err)
	}
	if got := pendingAfter(all, highestAppliedVersion(history, byVersion)); len(got) != 0 {
		t.Errorf("up-to-date database: pending = %v, want none", versionsOf(got))
	}
}

// The runner adopts Flyway's table rather than creating its own — that property is the entire reason
// D4 rejected golang-migrate, goose and Atlas, and it is what makes a rollback to the Kotlin binary a
// deploy instead of a restore. Asserting the table name and the inserted column list keeps a future
// edit from quietly renaming either.
func TestHistoryTableIsFlywaysOwn(t *testing.T) {
	if historyTable != "flyway_schema_history" {
		t.Errorf("historyTable = %q, want flyway_schema_history", historyTable)
	}
	for _, col := range []string{
		"installed_rank", "version", "description", "type", "script", "checksum",
		"installed_by", "execution_time", "success",
	} {
		if !strings.Contains(insertHistorySQL, col) {
			t.Errorf("the history insert omits %s", col)
		}
		if !strings.Contains(createHistoryTableSQL, col) {
			t.Errorf("the history DDL omits %s", col)
		}
	}
	// installed_on is written by the column default, exactly as Flyway leaves it.
	if strings.Contains(insertHistorySQL, "installed_on") {
		t.Error("installed_on must come from the column's DEFAULT now(), not from the insert")
	}
	if !strings.Contains(createHistoryTableSQL, "installed_on TIMESTAMP NOT NULL DEFAULT now()") {
		t.Error("the history DDL must default installed_on")
	}
	if !strings.Contains(insertHistorySQL, "current_user") {
		t.Error("installed_by must be Postgres' current_user, which is what Flyway records")
	}
	if migrationType != "SQL" {
		t.Errorf("migrationType = %q, want SQL", migrationType)
	}
}
