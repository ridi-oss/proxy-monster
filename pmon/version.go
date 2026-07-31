package main

import (
	"runtime/debug"
	"strings"
)

// Version is rewritten by release-please on each pmon release, which matches this line's exact shape —
// keep `const Version = "x.y.z"` on one line, quoted.
const Version = "0.1.1"

// Commit is the fallback stamp, set by `mise run build-pmon` as `-X main.Commit=<rev>`, for builds
// under this repo's go.work where Go records no revision of its own.
var Commit = ""

// FullVersion is what `pmon --version` prints and what the daemon reports over the control socket.
// The revision is what distinguishes unreleased builds of one Version.
func FullVersion() string {
	rev := buildRevision()
	if rev == "" {
		return Version
	}
	return Version + "+" + rev
}

// buildRevision returns the commit this binary was built from, suffixed .dirty when the tree had
// uncommitted changes — such a binary corresponds to no commit, so it should not name one.
//
// Go records vcs.revision itself for any repository build, but skips it while a go.work is active;
// Commit covers those.
func buildRevision() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		var rev, modified string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				modified = s.Value
			}
		}
		if rev != "" {
			if len(rev) > 12 {
				rev = rev[:12]
			}
			if modified == "true" {
				rev += ".dirty"
			}
			return rev
		}
	}
	return strings.TrimSpace(Commit)
}
