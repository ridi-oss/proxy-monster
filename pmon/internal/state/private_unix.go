//go:build !windows

package state

import (
	"fmt"
	"os"
	"syscall"
)

func socketRoot() string { return "/tmp" }

func socketDirName() string { return fmt.Sprintf("pmon-%d", os.Getuid()) }

func ownedBy(path string, info os.FileInfo, uid int) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify its ownership")
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("owned by uid %d, not %d", st.Uid, uid)
	}
	return nil
}

// makePrivate sets a directory to 0700: always when exact, otherwise only when group or others have access.
func makePrivate(path string, info os.FileInfo, exact bool) error {
	perm := info.Mode().Perm()
	if (exact && perm == 0o700) || (!exact && perm&0o077 == 0) {
		return nil
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("could not set %s to 0700 (it is %o): %w", path, perm, err)
	}
	return nil
}
