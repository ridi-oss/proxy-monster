package main

import (
	"fmt"
	"os"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// warnVersionSkew warns when the daemon answering this command is a different build than the CLI.
//
// The daemon keeps serving when the binary on disk is replaced. A warning, not a restart: it holds a
// live session. Written to stderr, so it stays out of piped output.
func warnVersionSkew(s *control.Status) {
	if s == nil {
		return
	}
	if s.Version == "" {
		fmt.Fprintf(os.Stderr,
			"warning: the running daemon reports no version, so it predates this CLI (%s).\n"+
				"         run `pmon restart` to pick up the current build.\n",
			FullVersion())
		return
	}
	// Two unstamped builds report the same bare version. Warning on that would fire on every command
	// of a normal dev loop, which costs more than the rebuild reminder is worth.
	if s.Version == FullVersion() {
		return
	}
	fmt.Fprintf(os.Stderr,
		"warning: the running daemon is %s but this CLI is %s.\n"+
			"         run `pmon restart` to pick up the current build.\n",
		s.Version, FullVersion())
}
