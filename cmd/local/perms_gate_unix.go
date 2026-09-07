//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// repairAllowed reports whether the startup repair pass may rewrite the
// permissions under dir, and names the owner when it may not. See the Windows
// half for why the gate exists; on unix the same question is whether this
// process owns the directory, since chmod is the owner's to make (or root's).
func repairAllowed(dir string) (bool, string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return false, "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// A filesystem that carries no uid. Nothing to gate on, and chmod
		// either works or reports why.
		return true, "", nil
	}
	uid := os.Geteuid()
	return int(st.Uid) == uid || uid == 0, fmt.Sprintf("uid %d", st.Uid), nil
}
