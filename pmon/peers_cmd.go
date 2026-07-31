package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// warnOtherDaemons warns when a second pmon daemon is running.
//
// The pid lock is per config dir, so a second daemon takes a different lock and different ports —
// nothing collides, and a printed connection string may reach neither.
func warnOtherDaemons() {
	// Setting PMON_CONFIG_DIR asks for a separate daemon; running beside another is the point.
	if os.Getenv("PMON_CONFIG_DIR") != "" {
		return
	}
	pids := daemonPids()
	if len(pids) < 2 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"warning: another pmon daemon appears to be running (pids %s).\n"+
			"         each serves its own config dir and ports, so a connection string from one\n"+
			"         may not reach the daemon this command talked to.\n",
		strings.Join(pids, ", "))
}

// daemonPids returns the pids of running pmon daemons other than this process.
//
// pgrep, not the pid files: a pid file names only the daemon of its own config dir. The pattern is
// anchored because -f matches whole command lines, so a bare "pmon daemon" also matches any process
// merely mentioning it. Best effort — no pgrep means no warning, not an error.
func daemonPids() []string {
	out, err := exec.Command("pgrep", "-f", `(^|/)pmon daemon`).Output()
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var pids []string
	for _, line := range strings.Fields(string(out)) {
		n, err := strconv.Atoi(line)
		if err != nil || n == self {
			continue
		}
		pids = append(pids, line)
	}
	return pids
}
