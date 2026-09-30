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

// requireCurrentDaemon refuses to act on a daemon too old to report its servers, which would otherwise read as
// "no servers" and prompt a needless fresh login.
func requireCurrentDaemon(s *control.Status) error {
	if s.Outdated() {
		return fmt.Errorf("the running daemon predates this CLI (%s) and cannot report its servers — run `pmon restart`", FullVersion())
	}
	return nil
}
