package cli

import (
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// TestWarnVersionSkew covers each state a daemon can be in relative to this CLI.
func TestWarnVersionSkew(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })
	version = "0.1.7+aaaaaaaaaaaa"

	for _, test := range []struct {
		name      string
		status    *control.Status
		wantWarn  bool
		wantMatch string
	}{
		{"same build", &control.Status{Version: version}, false, ""},
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
