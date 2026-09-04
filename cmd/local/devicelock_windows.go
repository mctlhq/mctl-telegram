//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFileExclusive is the Windows half of the advisory lock. syscall.Flock
// does not exist here, and windows/amd64 is one of the targets this CLI is
// cross-compiled for, so the two halves are build-tagged rather than sharing
// one implementation. LockFileEx has the property that matters: the handle's
// lock is released when the process holding it exits, cleanly or not.
func lockFileExclusive(f *os.File) (bool, error) {
	var ol windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &ol,
	)
	if err == nil {
		return true, nil
	}
	if err == windows.ERROR_LOCK_VIOLATION || err == windows.ERROR_IO_PENDING {
		return false, nil
	}
	return false, err
}

func unlockFile(f *os.File) {
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
}
