package dbtest

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// recordingTB is a testing.TB that records the terminal calls instead of performing them.
//
// It embeds *testing.T because testing.TB has an unexported method and cannot be implemented from
// outside the testing package; the embedded value supplies it while the overrides below shadow the
// four methods under test. Fatalf here RETURNS (the real one calls runtime.Goexit), which is exactly
// why requireBackend has an explicit `return Backend{}` after its Fatalf — without it, a fake TB would
// fall through to returning a backend the caller would then try to dial.
type recordingTB struct {
	*testing.T
	fatals  []string
	skipped bool
}

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}
func (r *recordingTB) Fatal(args ...any) { r.fatals = append(r.fatals, fmt.Sprint(args...)) }
func (r *recordingTB) Skip(...any)       { r.skipped = true }
func (r *recordingTB) Skipf(string, ...any) {
	r.skipped = true
}
func (r *recordingTB) SkipNow() { r.skipped = true }

// TestUnavailableBackendFailsAndNeverSkips is the executable form of doc.go rule 2 — the property the
// whole harness is built around, and the one that is invisible when it breaks.
//
// The failure it guards against is not a crash: it is a suite that goes green on a machine with no
// Docker, having run none of its enforcement or security regressions. That is how a port ships broken,
// and it is exactly what the Kotlin's default `requireDockerOrSkip()` does when PM_REQUIRE_DB_TESTS is
// unset — which `mise run verify` does not set (mise.toml:191-199, :252).
//
// It needs no Docker: it drives the reporting path directly with an error.
func TestUnavailableBackendFailsAndNeverSkips(t *testing.T) {
	rec := &recordingTB{T: t}
	got := requireBackend(rec, "Postgres", Backend{Host: "should-not-be-returned"},
		errors.New("no Docker environment found"))

	if rec.skipped {
		t.Fatal("an unavailable backend SKIPPED the test — the suite would report a pass it never ran")
	}
	if len(rec.fatals) != 1 {
		t.Fatalf("an unavailable backend produced %d fatal reports, want exactly 1: %v", len(rec.fatals), rec.fatals)
	}
	msg := rec.fatals[0]
	// The message has to say what to do about it: "unavailable" alone sends the reader to the wrong
	// place (their code) instead of the right one (their Docker daemon).
	for _, want := range []string{"Postgres", "no Docker environment found", "Docker is REQUIRED"} {
		if !strings.Contains(msg, want) {
			t.Errorf("failure message does not mention %q:\n%s", want, msg)
		}
	}
	if got != (Backend{}) {
		t.Errorf("requireBackend returned %+v after reporting a fatal error; a caller that survives "+
			"Fatalf must not receive a usable-looking backend", got)
	}
}

// TestAvailableBackendPassesThrough is the other half: the reporting path must not touch a healthy
// backend.
func TestAvailableBackendPassesThrough(t *testing.T) {
	rec := &recordingTB{T: t}
	want := Backend{Host: "localhost", Port: 5432, User: "postgres", DB: "app", Image: "postgres:17"}
	if got := requireBackend(rec, "Postgres", want, nil); got != want {
		t.Errorf("requireBackend(healthy) = %+v, want %+v", got, want)
	}
	if len(rec.fatals) != 0 || rec.skipped {
		t.Errorf("a healthy backend reported fatals=%v skipped=%v", rec.fatals, rec.skipped)
	}
}

// TestContainerNamePartitionsByImage pins the reuse key. Two matrix legs on different images must not
// share a container: reusing one started from another image would run the tests against the wrong
// version while reporting the version that was asked for — a pass for coverage that never happened.
func TestContainerNamePartitionsByImage(t *testing.T) {
	a := containerName("pm-cp-it-pg", "postgres:16")
	b := containerName("pm-cp-it-pg", "postgres:17")
	if a == b {
		t.Fatalf("postgres:16 and postgres:17 share the container name %q", a)
	}
	for _, name := range []string{a, b} {
		if strings.ContainsAny(name, ":/.") {
			t.Errorf("container name %q contains a character Docker rejects in a name", name)
		}
	}

	// PM_TEST_CONTAINER_SUFFIX partitions further, for legs that run concurrently on the SAME image.
	t.Setenv("PM_TEST_CONTAINER_SUFFIX", "leg.2")
	if suffixed := containerName("pm-cp-it-pg", "postgres:17"); suffixed == b {
		t.Errorf("PM_TEST_CONTAINER_SUFFIX did not partition the name: still %q", suffixed)
	}
}

// TestImageOverride pins that a blank override falls back rather than producing an image named "" —
// TestDatabases.kt:43-44's `takeIf { it.isNotBlank() }`.
func TestImageOverride(t *testing.T) {
	const env = "PM_TEST_POSTGRES_IMAGE"
	t.Setenv(env, "")
	if got := image(env, defaultPostgresImage); got != defaultPostgresImage {
		t.Errorf("blank override gave %q, want the default %q", got, defaultPostgresImage)
	}
	t.Setenv(env, "   ")
	if got := image(env, defaultPostgresImage); got != defaultPostgresImage {
		t.Errorf("whitespace override gave %q, want the default %q", got, defaultPostgresImage)
	}
	t.Setenv(env, "postgres:16")
	if got := image(env, defaultPostgresImage); got != "postgres:16" {
		t.Errorf("override gave %q, want %q", got, "postgres:16")
	}
}
