package store

import (
	"testing"
	"testing/fstest"

	"github.com/ridi-oss/proxy-monster/gocp/internal/migrations"
)

func TestParseMigrationName(t *testing.T) {
	cases := []struct {
		base, version, description string
	}{
		{"V1__identity.sql", "1", "identity"},
		{"V10__debug_requester_ip.sql", "10", "debug requester ip"},
		{"V9__datasource_cert_chain.sql", "9", "datasource cert chain"},
		{"V2.1__patch.sql", "2.1", "patch"},
		{"V3____leading.sql", "3", "  leading"}, // "__" splits once; the rest is description
	}
	for _, tc := range cases {
		version, description, err := parseMigrationName(tc.base)
		if err != nil {
			t.Errorf("parseMigrationName(%q): %v", tc.base, err)
			continue
		}
		if version != tc.version {
			t.Errorf("parseMigrationName(%q) version = %q, want %q", tc.base, version, tc.version)
		}
		if description != tc.description {
			t.Errorf("parseMigrationName(%q) description = %q, want %q", tc.base, description, tc.description)
		}
	}

	for _, bad := range []string{"identity.sql", "V1_identity.sql", "V1__identity.txt", "V__identity.sql", "V1__identity"} {
		if _, _, err := parseMigrationName(bad); err == nil {
			t.Errorf("parseMigrationName(%q) succeeded, want an error", bad)
		}
	}
}

// The naming note in internal/migrations/migrations.go: the version sorts NUMERICALLY, so V10 sorts
// after V9. A lexicographic sort of these filenames applies V10 second and V2..V9 after it, which on
// a clean database fails on the first foreign key.
func TestVersionOrderIsNumericNotLexicographic(t *testing.T) {
	ten, err := parseVersionOrder("10")
	if err != nil {
		t.Fatalf("parseVersionOrder(10): %v", err)
	}
	nine, err := parseVersionOrder("9")
	if err != nil {
		t.Fatalf("parseVersionOrder(9): %v", err)
	}
	if compareVersions(nine, ten) >= 0 {
		t.Error("version 9 must sort before version 10")
	}
	if "10" >= "9" {
		t.Error("precondition: lexicographic order disagrees, which is the whole point of this test")
	}

	one, _ := parseVersionOrder("1")
	oneDotZero, _ := parseVersionOrder("1.0")
	if compareVersions(one, oneDotZero) != 0 {
		t.Error("1 and 1.0 must compare equal")
	}
	oneDotOne, _ := parseVersionOrder("1.1")
	if compareVersions(one, oneDotOne) >= 0 {
		t.Error("1 must sort before 1.1")
	}

	for _, bad := range []string{"", "x", "1.x", "-1", "1..2"} {
		if _, err := parseVersionOrder(bad); err == nil {
			t.Errorf("parseVersionOrder(%q) succeeded, want an error", bad)
		}
	}
}

// 99-library-decisions.md §5 rule 3: honour `-- flyway:executeInTransaction=false`. No shipped
// migration uses it, but the guard is part of the contract.
func TestExecutesInTransaction(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"no directive", "CREATE TABLE t (id INT);\n", true},
		{"directive first line", "-- flyway:executeInTransaction=false\nCREATE INDEX CONCURRENTLY i ON t (id);\n", false},
		{"after a comment block", "-- why\n--\n-- flyway:executeInTransaction=false\nVACUUM;\n", false},
		{"after a blank line", "\n-- flyway:executeInTransaction=false\nVACUUM;\n", false},
		{"explicitly true", "-- flyway:executeInTransaction=true\nCREATE TABLE t (id INT);\n", true},
		{"case-insensitive", "-- FLYWAY:EXECUTEINTRANSACTION=FALSE\nVACUUM;\n", false},
		// Only the LEADING comment block is scanned. A directive that appears after SQL has begun is
		// ordinary text — otherwise a seeded string literal could silently change how a migration runs.
		{"below the first statement", "CREATE TABLE t (id INT);\n-- flyway:executeInTransaction=false\n", true},
		{"inside a value", "INSERT INTO t VALUES ('-- flyway:executeInTransaction=false');\n", true},
		{"empty file", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := executesInTransaction([]byte(tc.body)); got != tc.want {
				t.Errorf("executesInTransaction = %v, want %v", got, tc.want)
			}
		})
	}
}

// The real shipped set, loaded through the same path the runner uses.
func TestLoadEmbeddedMigrations(t *testing.T) {
	all, err := loadMigrations(migrations.FS, migrationDir)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	wantVersions := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	if len(all) != len(wantVersions) {
		t.Fatalf("loaded %d migrations, want %d", len(all), len(wantVersions))
	}
	for i, want := range wantVersions {
		if all[i].version != want {
			t.Errorf("migration %d has version %q, want %q (numeric order, V10 last)", i, all[i].version, want)
		}
		if len(all[i].body) == 0 {
			t.Errorf("migration %s has an empty body", all[i].script)
		}
		// grep over internal/migrations/sql found no `flyway:` directive, so every shipped file is
		// ordinary transactional DDL (docs/migrations.md "Every migration here is ordinary
		// transactional DDL").
		if !all[i].inTransaction {
			t.Errorf("migration %s is marked non-transactional; no shipped migration should be", all[i].script)
		}
		if all[i].checksum == 0 {
			t.Errorf("migration %s checksummed to 0, which means it read as empty", all[i].script)
		}
	}
	if all[0].script != "V1__identity.sql" || all[0].description != "identity" {
		t.Errorf("first migration = %q/%q, want V1__identity.sql/identity", all[0].script, all[0].description)
	}
	if last := all[len(all)-1]; last.script != "V10__debug_requester_ip.sql" || last.description != "debug requester ip" {
		t.Errorf("last migration = %q/%q, want V10__debug_requester_ip.sql/debug requester ip", last.script, last.description)
	}
}

func TestLoadMigrationsRejectsDuplicateVersions(t *testing.T) {
	fsys := fstest.MapFS{
		"sql/V1__a.sql":   {Data: []byte("SELECT 1;")},
		"sql/V1.0__b.sql": {Data: []byte("SELECT 2;")},
	}
	if _, err := loadMigrations(fsys, "sql"); err == nil {
		t.Error("loadMigrations accepted two files at the same version, want an error")
	}
}

// 99-library-decisions.md §5 rule 2 — apply only files above the recorded version.
func TestPendingAfter(t *testing.T) {
	all, err := loadMigrations(migrations.FS, migrationDir)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}

	if got := pendingAfter(all, nil); len(got) != len(all) {
		t.Errorf("clean database: %d pending, want all %d", len(got), len(all))
	}

	at9, _ := parseVersionOrder("9")
	pending := pendingAfter(all, at9)
	if len(pending) != 1 || pending[0].version != "10" {
		t.Errorf("after version 9: pending = %v, want just V10", versionsOf(pending))
	}

	at10, _ := parseVersionOrder("10")
	if got := pendingAfter(all, at10); len(got) != 0 {
		t.Errorf("after version 10: pending = %v, want none", versionsOf(got))
	}

	// REPRODUCE: a file at or below the recorded version is skipped, not applied out of order. That
	// is Flyway's behaviour with outOfOrder disabled, which is the default.
	at5, _ := parseVersionOrder("5")
	pending = pendingAfter(all, at5)
	if len(pending) != 5 {
		t.Errorf("after version 5: %d pending, want 5 (V6..V10)", len(pending))
	}
	for _, m := range pending {
		if compareVersions(m.order, at5) <= 0 {
			t.Errorf("pending set contains %s, which is not above the recorded version", m.script)
		}
	}
}

func versionsOf(ms []migration) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.version)
	}
	return out
}
