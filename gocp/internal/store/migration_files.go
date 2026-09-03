package store

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Flyway's naming contract for a versioned SQL migration: V<version>__<description>.sql
// (docs/migrations.md "Runtime migrations are plain SQL under resources/db/migration/, named
// V{n}__desc and numbered sequentially from V1__identity.sql").
const (
	versionedPrefix = "V"
	versionSep      = "__"
	sqlSuffix       = ".sql"

	// migrationType is the value Flyway records in flyway_schema_history.type for a versioned SQL
	// migration.
	migrationType = "SQL"
)

// executeInTransactionDirective is the script-configuration comment docs/migrations.md:74-77
// documents for a migration that cannot run inside a transaction (CREATE INDEX CONCURRENTLY,
// ALTER TYPE … ADD VALUE, VACUUM, …). No shipped migration uses it — V1..V10, grepped — but the
// guard is part of the contract (99-library-decisions.md §5 rule 3).
const executeInTransactionDirective = "flyway:executeintransaction="

// migration is one shipped V*.sql file, resolved.
type migration struct {
	// version is the raw version token, as it is written into flyway_schema_history.version. For the
	// shipped set that is "1".."10".
	version string
	// order is version parsed into its dotted numeric parts, for sorting. Lexicographic order on the
	// raw token is WRONG here: "V10" sorts before "V9" as text and after it numerically.
	order []int64
	// description is the token after "__" with underscores turned into spaces, which is what Flyway
	// stores in flyway_schema_history.description.
	description string
	// script is the file's base name, stored in flyway_schema_history.script.
	script string
	// body is the file's raw bytes, executed verbatim.
	body []byte
	// checksum is FlywayChecksum(body).
	checksum int32
	// inTransaction is false only when the file carries `-- flyway:executeInTransaction=false`.
	inTransaction bool
}

// loadMigrations reads every V*.sql under dir and returns them in ascending version order.
//
// It is deliberately a pure function over an fs.FS so the shipped set can be validated without a
// database: the embedded set is internal/migrations.FS with dir "sql".
func loadMigrations(fsys fs.FS, dir string) ([]migration, error) {
	names, err := fs.Glob(fsys, path.Join(dir, versionedPrefix+"*"+sqlSuffix))
	if err != nil {
		return nil, err
	}
	out := make([]migration, 0, len(names))
	for _, name := range names {
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		base := path.Base(name)
		version, description, err := parseMigrationName(base)
		if err != nil {
			return nil, err
		}
		order, err := parseVersionOrder(version)
		if err != nil {
			return nil, fmt.Errorf("migration %s: %w", base, err)
		}
		out = append(out, migration{
			version:       version,
			order:         order,
			description:   description,
			script:        base,
			body:          body,
			checksum:      FlywayChecksum(body),
			inTransaction: executesInTransaction(body),
		})
	}
	sort.Slice(out, func(i, j int) bool { return compareVersions(out[i].order, out[j].order) < 0 })

	for i := 1; i < len(out); i++ {
		if compareVersions(out[i-1].order, out[i].order) == 0 {
			return nil, fmt.Errorf("duplicate migration version %s: %s and %s",
				out[i].version, out[i-1].script, out[i].script)
		}
	}
	return out, nil
}

// parseMigrationName splits V<version>__<description>.sql.
//
// Flyway turns each underscore in the description into a space (V9__datasource_cert_chain.sql ⇒
// "datasource cert chain"), which is what the history row records. ⚠️ Unverified — no Flyway jar on
// this machine — and it is why the runner does NOT validate stored descriptions: a wrong derivation
// here would refuse to boot a healthy deployment, the "too strict" half of D4's fail-closed risk.
func parseMigrationName(base string) (version, description string, err error) {
	name, ok := strings.CutSuffix(base, sqlSuffix)
	if !ok {
		return "", "", fmt.Errorf("migration %s: not a %s file", base, sqlSuffix)
	}
	rest, ok := strings.CutPrefix(name, versionedPrefix)
	if !ok {
		return "", "", fmt.Errorf("migration %s: missing %q version prefix", base, versionedPrefix)
	}
	version, description, ok = strings.Cut(rest, versionSep)
	if !ok {
		return "", "", fmt.Errorf("migration %s: missing %q separator", base, versionSep)
	}
	if version == "" {
		return "", "", fmt.Errorf("migration %s: empty version", base)
	}
	return version, strings.ReplaceAll(description, "_", " "), nil
}

// parseVersionOrder splits a Flyway version into numeric parts. Flyway accepts "_" as an alternative
// to "." inside a version (V1_1 == V1.1); the shipped set uses neither, so this is carried for
// completeness and marked ⚠️ Unverified.
func parseVersionOrder(version string) ([]int64, error) {
	parts := strings.Split(strings.ReplaceAll(version, "_", "."), ".")
	order := make([]int64, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("version %q is not dotted-numeric", version)
		}
		order = append(order, n)
	}
	return order, nil
}

// compareVersions orders two parsed versions, treating a missing trailing part as 0 so 1 == 1.0.
func compareVersions(a, b []int64) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int64
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// executesInTransaction reports whether the migration runs inside a transaction — true unless the
// file carries `-- flyway:executeInTransaction=false`.
//
// Only the leading comment/blank block is scanned, stopping at the first line of SQL, because
// docs/migrations.md:74-77 places the directive "at the top" of the file. Scanning the whole body
// would let the string appear inside a seeded VALUES literal and silently change how the migration
// is applied.
func executesInTransaction(body []byte) bool {
	for _, raw := range flywayLines(body) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		comment, ok := strings.CutPrefix(line, "--")
		if !ok {
			return true // first SQL line: the leading block is over
		}
		directive := strings.TrimSpace(comment)
		value, ok := cutPrefixFold(directive, executeInTransactionDirective)
		if !ok {
			continue
		}
		return !strings.EqualFold(strings.TrimSpace(value), "false")
	}
	return true
}

// cutPrefixFold is strings.CutPrefix with an ASCII case-insensitive comparison, so
// `flyway:executeInTransaction=` matches however the file spells it.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

// pendingAfter returns the migrations that must still be applied: those strictly newer than the
// highest already-applied version.
//
// 99-library-decisions.md §5 rule 2 — "apply only those above the recorded version". A shipped file
// whose version is at or below `current` but has no history row is therefore SKIPPED, which is what
// Flyway does with outOfOrder disabled. See the runner's doc for what is deliberately not validated.
func pendingAfter(all []migration, current []int64) []migration {
	var out []migration
	for _, m := range all {
		if current == nil || compareVersions(m.order, current) > 0 {
			out = append(out, m)
		}
	}
	return out
}
