//go:build !windows

package control

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// trustedPathComponent requires that path be owned by this user (or root) and not group/world-writable. `what`
// names it in the error, so a refusal says whether the binary or its directory was the problem.
func trustedPathComponent(path, what string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify %s ownership", what)
	}
	if uid := os.Getuid(); int(st.Uid) != uid && st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not %d or root", what, st.Uid, uid)
	}
	// A sticky directory (/tmp, mode 1777) still bars unlinking someone else's file, but nothing here needs to
	// live in one, so the simpler predicate is kept rather than carving out an exception that widens the surface.
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is group/world-writable (%o)", what, perm)
	}
	return nil
}

const exeSuffix = ""

func runnable(_ string, info os.FileInfo) bool { return info.Mode()&0o111 != 0 }

// startDetached starts the daemon in a new session: it must not die with the peer's process group, nor take its
// controlling terminal's signals (a Ctrl-C in the shell that ran `pmon login` must not kill the daemon).
func startDetached(cmd *exec.Cmd) (*exec.Cmd, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd, cmd.Start()
}

func terminate(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
