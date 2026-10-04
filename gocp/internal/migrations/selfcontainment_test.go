package migrations_test

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/migrations"
)

// ---------------------------------------------------------------------------------------------
// Port of MigrationSelfContainmentTest.kt (115 LOC, 2 cases, no DB).
//
// An applied migration is IMMUTABLE, and Flyway enforces that by checksumming the whole file —
// comments included. So a comment that names something outside the file is a tripwire: renaming that
// thing is a routine edit everywhere else in the tree, but here it changes the checksum of an
// already-applied migration, `validateOnMigrate` refuses, and control-plane startup aborts before it
// opens a port. Every existing install stops booting until an operator repairs
// `flyway_schema_history` by hand.
//
// That is not hypothetical. The Kotlin's own doc records it: a tree-wide doc-path rewrite once edited
// the comment headers of seven shipped migrations, and every control plane already carrying them
// refused to boot on its next start — over nine lines that no code reads and that Flyway only sees as
// bytes.
//
// 🔴 THE GO PORT INHERITS THE HAZARD UNCHANGED, and inherits it TWICE OVER. internal/migrations' own
// doc comment states these ten files "are copied byte-for-byte from
// control-plane/src/main/resources/db/migration/ and MUST NOT be edited", because the Go runner
// recomputes the same checksums that the KOTLIN deployment wrote. So a doc-path rewrite that touched
// a comment here would brick startup on installs that never ran a line of Go.
//
// TWO DIVERGENCES FROM THE KOTLIN, both deliberate:
//
//  1. The files are read from the EMBEDDED FS, not from a relative filesystem path. The Kotlin
//     resolves `src/main/resources/db/migration` against Gradle's working directory; `go test` runs in
//     the package directory, and an embed read cannot be defeated by a cwd change or by a file that
//     exists on disk but was never embedded. The Kotlin's "did the glob actually match anything"
//     guard is kept anyway, for the same reason it exists there.
//  2. `(?<![A-Za-z])(?:tasks|docs)/` uses a negative lookbehind, which Go's RE2 does not support. The
//     equivalent `(^|[^A-Za-z])(tasks|docs)/` is used instead. It classifies every line identically —
//     it only widens the reported match by the one preceding character — and
//     TestTheGuardRejectsTheReferenceFormsThatBreakADatabase is what proves the substitution did not
//     quietly change the verdict on any of the Kotlin's ten sample lines.
// ---------------------------------------------------------------------------------------------

// forbidden is a path, doc, or URL in a migration. Deliberately broad — every form is equally a
// checksum liability, and a narrow pattern would just move the tripwire rather than remove it.
var forbidden = []struct {
	pattern *regexp.Regexp
	what    string
}{
	{regexp.MustCompile(`\.md\b`), "a doc filename"},
	{regexp.MustCompile(`https?://`), "a URL"},
	{regexp.MustCompile(`(^|[^A-Za-z])(tasks|docs)/`), "a repository path"},
	{regexp.MustCompile(`\.(kts?|go|tsx?)\b`), "a source filename"},
}

func migrationFiles(t *testing.T) []string {
	t.Helper()
	names, err := fs.Glob(migrations.FS, "sql/V*.sql")
	if err != nil {
		t.Fatalf("glob the embedded migrations: %v", err)
	}
	return names
}

// KT: MigrationSelfContainmentTest.kt#every migration is self-contained
func TestEveryMigrationIsSelfContained(t *testing.T) {
	files := migrationFiles(t)
	// A directory that resolved to the wrong place, or a glob that matched nothing, would make an
	// empty result read exactly like a clean tree. Assert we actually looked at the migrations.
	if len(files) < 8 {
		t.Fatalf("expected the shipped migrations under the embedded sql/ tree, found %d", len(files))
	}

	var violations []string
	for _, name := range files {
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			for _, f := range forbidden {
				if m := f.pattern.FindString(line); m != "" {
					violations = append(violations, fmt.Sprintf("%s:%d contains %s (%q): %s",
						name, i+1, f.what, m, strings.TrimSpace(line)))
				}
			}
		}
	}

	if len(violations) > 0 {
		var b strings.Builder
		b.WriteString("A migration must not reference anything outside itself, because Flyway ")
		b.WriteString("checksums the whole file and a later rename of the referenced path then stops ")
		b.WriteString("every existing database from booting.\n\n")
		for _, v := range violations {
			b.WriteString("  " + v + "\n")
		}
		b.WriteString("\nWrite the comment so it stands alone: say what the schema is, not where to ")
		b.WriteString("read about it.")
		t.Error(b.String())
	}
}

// 🔒 Without this, the test above passes whether or not its patterns work — a clean tree and a broken
// matcher are indistinguishable. These include the form that has broken a control plane, plus the
// other forms someone would reach for next.
//
// It is also what makes the RE2 substitution for the Kotlin's lookbehind auditable: the same ten
// sample lines, the same verdicts.
// KT: MigrationSelfContainmentTest.kt#the guard rejects the reference forms that break a database
func TestTheGuardRejectsTheReferenceFormsThatBreakADatabase(t *testing.T) {
	fires := func(line string) bool {
		for _, f := range forbidden {
			if f.pattern.MatchString(line) {
				return true
			}
		}
		return false
	}

	for _, line := range []string{
		"-- The Cedar policy store (docs/policy-store.md, docs/authz-model.md).",
		"-- The audit trail (docs/audit-trail-hardening.md).",
		"-- See migrations.md for the rule.",
		"-- https://docs.cedarpolicy.com",
		"-- Mirrors Db.kt behaviour.",
	} {
		if !fires(line) {
			t.Errorf("the guard would have allowed a known-bad comment: %s", line)
		}
	}

	// And it must not fire on ordinary prose, or it would be switched off rather than obeyed.
	for _, line := range []string{
		"-- The Cedar policy store.",
		"-- One row per audited event, keyed by decision_id.",
		"-- Deny-by-default: a clean install has no usable admin until seeded.",
		"-- 3. the derived context.tags the request earned.",
	} {
		if fires(line) {
			t.Errorf("the guard fires on an ordinary comment: %s", line)
		}
	}
}
