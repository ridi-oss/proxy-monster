package conformance

import (
	"os"
	"path/filepath"
	"testing"
)

// goldenFixtureCandidates are the repo-relative homes of the audit canonical golden fixture, in
// preference order.
//
// ⚠️ F9. The FIRST entry is the language-neutral home doc.go proposes; it does not exist yet. The
// SECOND is where the fixture lives today, inside the Kotlin module's test resources — the directory
// cutover deletes. Trying the proposed home first means the day the move happens this suite keeps
// passing with no edit, which is the whole point of writing the candidate list rather than a path.
//
// Both are looked up by walking UP from the working directory (findUpwards), not by a counted `../`
// hop, so the suite also survives being moved within the module. auditmon/canon/canonical_test.go:90
// still uses a fixed two-level hop and still needs the F9 one-liner.
var goldenFixtureCandidates = []string{
	"testdata/audit-canonical/canonical-golden.json",
	"control-plane/src/test/resources/atrail/canonical-golden.json",
}

// goldenFixturePath returns the first candidate that exists, failing the test if none do.
//
// A MISSING fixture is a hard failure, never a skip. A skipped cross-language assertion is
// indistinguishable from a passing one in CI output, and this is the one suite where "we did not
// check" must never read as "we agree".
func goldenFixturePath(t *testing.T) string {
	t.Helper()
	for _, rel := range goldenFixtureCandidates {
		if p, ok := findUpwards(rel); ok {
			return p
		}
	}
	t.Fatalf("audit canonical golden fixture not found; tried %v walking up from the working directory",
		goldenFixtureCandidates)
	return ""
}

// findUpwards walks from the working directory to the filesystem root looking for rel. Same shape as
// internal/audit's and internal/dbtest's, and for the same F9 reason: a counted `../` hop bakes in a
// directory depth that a file move silently invalidates.
func findUpwards(rel string) (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		candidate := filepath.Join(dir, filepath.FromSlash(rel))
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}
