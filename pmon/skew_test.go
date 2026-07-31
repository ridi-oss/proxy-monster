package main

import (
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// TestFullVersion covers the ldflag fallback, which is what a go.work build resolves to.
func TestFullVersion(t *testing.T) {
	orig := Commit
	t.Cleanup(func() { Commit = orig })

	for _, test := range []struct {
		name   string
		commit string
		want   string
	}{
		{"no stamp", "", Version},
		{"whitespace only", "  ", Version},
		{"stamped", "abc123def456", Version + "+abc123def456"},
		{"stamped dirty", "abc123def456.dirty", Version + "+abc123def456.dirty"},
	} {
		t.Run(test.name, func(t *testing.T) {
			Commit = test.commit
			if got := FullVersion(); got != test.want {
				t.Errorf("Commit=%q: FullVersion() = %q, want %q", test.commit, got, test.want)
			}
		})
	}
}

// TestWarnVersionSkew covers each state a daemon can be in relative to this CLI.
func TestWarnVersionSkew(t *testing.T) {
	orig := Commit
	t.Cleanup(func() { Commit = orig })
	Commit = "aaaaaaaaaaaa"

	for _, test := range []struct {
		name      string
		status    *control.Status
		wantWarn  bool
		wantMatch string
	}{
		{"same build", &control.Status{Version: FullVersion()}, false, ""},
		{"older build", &control.Status{Version: "0.1.0+bbbbbbbbbbbb"}, true, "0.1.0+bbbbbbbbbbbb"},
		{"no version field", &control.Status{}, true, "predates this CLI"},
		{"nil status", nil, false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := captureStderr(t, func() { warnVersionSkew(test.status) })
			if test.wantWarn && got == "" {
				t.Fatal("expected a warning, got none")
			}
			if !test.wantWarn && got != "" {
				t.Fatalf("expected no warning, got %q", got)
			}
			if test.wantMatch != "" && !strings.Contains(got, test.wantMatch) {
				t.Fatalf("warning %q does not mention %q", got, test.wantMatch)
			}
			// Without the hint the warning is not actionable.
			if test.wantWarn && !strings.Contains(got, "pmon restart") {
				t.Fatalf("warning %q does not tell the user what to do", got)
			}
		})
	}
}

// captureStderr swaps os.Stderr for a pipe and returns what fn wrote, so the assertion covers the
// real stream rather than an injected writer.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

// TestDaemonPidsExcludesSelf: a daemon matches its own pgrep pattern, so without the exclusion every
// daemon would warn about itself.
func TestDaemonPidsExcludesSelf(t *testing.T) {
	self := strconv.Itoa(os.Getpid())
	for _, p := range daemonPids() {
		if p == self {
			t.Fatalf("daemonPids() includes this process (%s)", self)
		}
	}
}

// TestBuildRevisionPrefersBuildInfo pins the precedence: Go's vcs.revision wins over Commit, since a
// passed flag can disagree with the tree.
func TestBuildRevisionPrefersBuildInfo(t *testing.T) {
	orig := Commit
	t.Cleanup(func() { Commit = orig })

	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info")
	}
	var rev string
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			rev = s.Value
		}
	}

	Commit = "ffffffffffff"
	got := buildRevision()
	if rev == "" {
		// A go.work build: Go recorded nothing, so the ldflag is the answer.
		if got != "ffffffffffff" {
			t.Fatalf("buildRevision() = %q with no vcs.revision, want the Commit stamp", got)
		}
		return
	}
	// Built outside a workspace: build info wins over the stamp.
	if got == "ffffffffffff" {
		t.Fatalf("buildRevision() returned the ldflag %q although vcs.revision is %q", got, rev)
	}
	if !strings.HasPrefix(rev, strings.TrimSuffix(got, ".dirty")) {
		t.Fatalf("buildRevision() = %q, want a prefix of vcs.revision %q", got, rev)
	}
}
