package dbtest

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
)

// Port of DbSupportMatrixTest.kt (143 LOC, 6 cases).
//
// The Kotlin header states what the suite is for: "`db-support.json` declares which database versions
// proxy-monster supports. Three things have to agree with it or the support claim is fiction: the
// engine's bundled classification manifests …, the CI matrix …, and the test infrastructure's defaults.
// This test is what makes disagreement a build failure rather than something discovered when a customer
// points a proxy at an untested server."
//
// dbsupport_test.go's TestDefaultImagesTrackDbSupportJson is a NEIGHBOUR of case 5, not a port of it: it
// asserts the two DEFAULT CONSTANTS equal the NEWEST declared series, which is a different and stronger
// claim about a narrower thing. It says nothing about the env-resolved image a matrix leg actually runs
// (case 5), about the other declared entries' images (case 2), about the storage engine list (case 3),
// about the manifests (case 1), or about CI (case 4). Those five are here.
//
// None of cases 1-5 needs Docker — they read files. Case 6 does, and fails rather than skips.

// declaredEntries is the Kotlin's `read(role)`.
func declaredEntries(t *testing.T, role string) []DbSupportEntry {
	t.Helper()
	support, path, err := LoadDbSupport()
	if err != nil {
		t.Fatalf("locating db-support.json: %v", err)
	}
	switch role {
	case "target":
		if len(support.Target) == 0 {
			t.Fatalf("%s declares no target engines", path)
		}
		return support.Target
	case "storage":
		if len(support.Storage) == 0 {
			t.Fatalf("%s declares no storage engines", path)
		}
		return support.Storage
	default:
		t.Fatalf("unknown role %q", role)
		return nil
	}
}

// Case 1. Both directions: a declared-but-unbundled series claims support the classifier cannot back;
// a bundled-but-undeclared series is curated code that no CI leg exercises.
//
// The Kotlin's own note on why the engine list is hardcoded rather than derived from `declared`:
// "deriving them from `declared` would make deleting an engine's last target entry hide its manifests
// from the comparison instead of failing it." Reproduced verbatim — engineNames below is a constant.
// KT: DbSupportMatrixTest.kt#every supported target series has a bundled classification manifest and vice versa
func TestEverySupportedTargetSeriesHasABundledClassificationManifestAndViceVersa(t *testing.T) {
	declared := map[string]bool{}
	for _, e := range declaredEntries(t, "target") {
		declared[e.Engine+"/"+e.Series] = true
	}

	store, err := engine.LoadSystemClassificationStore()
	if err != nil {
		t.Fatalf("the bundled classification manifests must load: %v", err)
	}
	bundled := map[string]bool{}
	for _, engineName := range []string{EngineMySQL, EnginePostgres} {
		for _, classifier := range store.ClassifiersForEngine(engineName) {
			bundled[engineName+"/"+classifier.Manifest().Series] = true
		}
	}

	declaredNotBundled := setDifference(declared, bundled)
	bundledNotDeclared := setDifference(bundled, declared)
	if len(declaredNotBundled) > 0 || len(bundledNotDeclared) > 0 {
		t.Errorf("db-support.json target versions and the bundled system-classification manifests "+
			"disagree — declared-not-bundled=%v, bundled-not-declared=%v",
			declaredNotBundled, bundledNotDeclared)
	}
}

func setDifference(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Case 2. The live-server check compares against the IMAGE's series, so an entry whose image disagrees
// with its own `series` field would pass every gate while running — and claiming a pass for — a
// different version than it declares. An image with no version in its tag ("latest") is refused for the
// same reason: nothing could be verified (imageSeries returns "" and verifySeries then checks nothing).
// KT: DbSupportMatrixTest.kt#every declared version pins an image of that same series
func TestEveryDeclaredVersionPinsAnImageOfThatSameSeries(t *testing.T) {
	for _, role := range []string{"target", "storage"} {
		for _, entry := range declaredEntries(t, role) {
			fromImage := imageSeries(entry.Image)
			if fromImage == entry.Series {
				continue
			}
			named := fromImage
			if named == "" {
				named = "no series at all"
			}
			t.Errorf("%s %s declares series %s but its image %s names %s",
				role, entry.Engine, entry.Series, entry.Image, named)
		}
	}
}

// Case 3. The control-plane store SQL is Postgres-specific (RETURNING, ON CONFLICT, jsonb, :: casts),
// so a non-Postgres storage entry would be a support claim no store query can honor.
// KT: DbSupportMatrixTest.kt#storage engines are postgres only
func TestStorageEnginesArePostgresOnly(t *testing.T) {
	var engines []string
	seen := map[string]bool{}
	for _, e := range declaredEntries(t, "storage") {
		if !seen[e.Engine] {
			seen[e.Engine] = true
			engines = append(engines, e.Engine) // `distinct()` keeps first-seen order
		}
	}
	if len(engines) != 1 || engines[0] != EnginePostgres {
		t.Errorf("storage engines = %v, want exactly [%s] — the control-plane store is Postgres-only",
			engines, EnginePostgres)
	}
}

// Case 4. The matrix is GENERATED from db-support.json at CI time, so no workflow spells the versions
// out. What this checks is the plumbing that carries a version into a leg: the per-leg environment
// variables the test infrastructure reads, and the file the matrix is built from. Without them a leg
// would run whatever the defaults are, for every version, and report a pass for each.
// KT: DbSupportMatrixTest.kt#the CI matrix runs exactly the declared versions
func TestTheCIMatrixRunsExactlyTheDeclaredVersions(t *testing.T) {
	dir, err := findUpwards(filepath.Join(".github", "workflows"))
	if err != nil {
		t.Fatalf("locating .github/workflows: %v", err)
	}
	items, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var workflows []string
	for _, it := range items {
		if it.IsDir() {
			continue
		}
		if ext := filepath.Ext(it.Name()); ext != ".yml" && ext != ".yaml" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, it.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", it.Name(), err)
		}
		workflows = append(workflows, string(raw))
	}
	// A missing directory yields an empty list and every check below would then be vacuously false —
	// so assert presence explicitly, the way the Kotlin does, and the failure names the real cause.
	if len(workflows) == 0 {
		t.Fatalf("expected at least one workflow under %s", dir)
	}

	anyContains := func(needle string) bool {
		for _, w := range workflows {
			if strings.Contains(w, needle) {
				return true
			}
		}
		return false
	}
	if !anyContains(dbSupportFile) {
		t.Errorf("no workflow reads %s — the CI matrix would not follow the declared version set", dbSupportFile)
	}
	for _, envVar := range []string{"PM_TEST_POSTGRES_IMAGE", "PM_TEST_MYSQL_IMAGE"} {
		if !anyContains(envVar) {
			t.Errorf("no workflow sets %s — its legs would all run the default version", envVar)
		}
	}
	// The Kotlin's reason: "Docker-less Testcontainers tests skip, and a skipped suite reports success.
	// CI has to opt into the hard failure or a leg can pass having run nothing."
	//
	// ⚠️ The Go harness does NOT skip — backend.go's mustBackend t.Fatal's on an unavailable container
	// ("Docker is REQUIRED for DB-backed tests and they FAIL rather than skip"), so PM_REQUIRE_DB_TESTS
	// is not what buys the hard failure here. The assertion is kept anyway, because it is what the
	// Kotlin case asserts and because the flag still governs the JVM legs the same matrix runs.
	if !anyContains("PM_REQUIRE_DB_TESTS") {
		t.Errorf("no workflow sets PM_REQUIRE_DB_TESTS — a Docker-less leg would pass by skipping")
	}
}

// Case 5. The Kotlin reads SharedPostgres.IMAGE / SharedMySql.IMAGE, which resolve PM_TEST_*_IMAGE, so
// "under a matrix leg this asserts the leg pinned a declared version, and on a plain local run it
// asserts the default is one". The Go equivalent of those two properties is image(envVar, default) —
// the same resolution the containers themselves use — so this reads it rather than the raw constants.
// KT: DbSupportMatrixTest.kt#the shared test containers default to a declared version
func TestTheSharedTestContainersDefaultToADeclaredVersion(t *testing.T) {
	declared := map[string]bool{}
	for _, e := range append(declaredEntries(t, "target"), declaredEntries(t, "storage")...) {
		declared[e.Image] = true
	}
	for _, tc := range []struct{ what, img string }{
		{"postgres", image("PM_TEST_POSTGRES_IMAGE", defaultPostgresImage)},
		{"mysql", image("PM_TEST_MYSQL_IMAGE", defaultMySQLImage)},
	} {
		if !declared[tc.img] {
			t.Errorf("the %s test container image %q is not a declared supported version", tc.what, tc.img)
		}
	}
}

// Case 6 — needs Docker, and FAILS rather than skips when it is absent.
//
// The Kotlin's reason: "The check above proves the CONFIGURED version is supported; this one proves the
// server the tests actually talked to is that version. A container reused from a different image, or a
// tag that resolved elsewhere, would otherwise let a leg report a pass for a version it never ran."
//
// verifySeries already enforces this at every backend startup, which is strictly stronger than one
// test — but "enforced by the harness" is not the same as "asserted by a named test that fails when the
// enforcement is removed", and the Kotlin case is the latter. This is that test.
// KT: DbSupportMatrixTest.kt#the running servers are the versions the images asked for
func TestTheRunningServersAreTheVersionsTheImagesAskedFor(t *testing.T) {
	for _, tc := range []struct {
		what    string
		backend Backend
	}{
		{"postgres", Postgres(t)},
		{"mysql", MySQL(t)},
	} {
		want := imageSeries(tc.backend.Image)
		if want == "" {
			t.Errorf("%s image %q pins no version, so nothing about the live server can be verified — "+
				"db-support.json must not declare a version with such an image", tc.what, tc.backend.Image)
			continue
		}
		if got := tc.backend.Series(t); got != want {
			t.Errorf("image %s should serve a %s server but it reported %s — this leg is not testing "+
				"the version it claims", tc.backend.Image, want, got)
		}
	}
}
