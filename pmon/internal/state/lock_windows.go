package state

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// lockOffsetHigh places the lock at 4 GiB: Windows locks are mandatory, so locking the pid file's first bytes would
// stop anyone reading the pid. Locking past the end of a file is allowed.
const lockOffsetHigh = 1

// lockFile takes an exclusive lock on f; with wait false it returns errLocked at once when another process
// holds it. Windows releases it when the holder exits, as flock does.
func lockFile(f *os.File, wait bool) error {
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if !wait {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &windows.Overlapped{OffsetHigh: lockOffsetHigh})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errLocked
	}
	return err
}

func unlockFile(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{OffsetHigh: lockOffsetHigh})
}
