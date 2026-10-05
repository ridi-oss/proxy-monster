package state

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// pidLock is the open, flocked pid file the daemon holds while it runs; [ReleasePidLock] closes it.
var pidLock *os.File

// AcquirePidLock takes the exclusive pid lock that makes the daemon single-instance. It returns held=false
// (no error) when another live daemon already holds it, so two peers racing to start one can't produce two.
// A crashed daemon's lock is auto-released by the OS, which is why this is an flock rather than a
// kill(pid,0) check — the latter is defeated by PID reuse and by the TOCTOU between check and start.
func AcquirePidLock() (held bool, err error) {
	if _, err := EnsureDir(); err != nil {
		return false, err
	}
	p, err := PidPath()
	if err != nil {
		return false, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return false, nil // already held by a live daemon
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt(fmt.Appendf(nil, "%d", os.Getpid()), 0)
	pidLock = f // keep the fd (and its lock) for the process lifetime
	return true, nil
}

// ReleasePidLock drops the lock, leaving the pid file in place.
//
// The file is deliberately NOT removed. Unlocking and then unlinking opens a window in which a second daemon
// opens and locks that same inode, the first daemon unlinks it, and a third creates and locks a FRESH inode —
// leaving two daemons each believing it is the singleton, and each entitled to unlink the other's control
// socket. Keeping one stable inode makes the flock the single arbiter; stale file CONTENTS are harmless,
// because liveness is decided by whether the lock can be taken, never by the pid written inside.
func ReleasePidLock() {
	if pidLock == nil {
		return
	}
	syscall.Flock(int(pidLock.Fd()), syscall.LOCK_UN)
	pidLock.Close()
	pidLock = nil
}

// DaemonRunning reports whether a daemon is alive, by probing the pid lock: if the flock can't be taken, a
// daemon holds it. Robust against PID reuse, and it needs no cooperation from the daemon — so it is also how
// a peer distinguishes "socket file is stale" from "a daemon is listening".
func DaemonRunning() bool {
	p, err := PidPath()
	if err != nil {
		return false
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0o600)
	if err != nil {
		return false // no pid file -> not running
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true // lock held elsewhere -> a daemon is alive
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

// DaemonPid reads the pid the running daemon recorded, for a signal-based stop when the control socket is
// unreachable. Returns 0 when the file is absent or unparseable.
func DaemonPid() int {
	p, err := PidPath()
	if err != nil {
		return 0
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}
