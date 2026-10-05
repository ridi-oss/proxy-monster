package main

import (
	"runtime/debug"
	"strings"
	"testing"
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
