//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// mayRestrict reports whether this process may rewrite the permissions of path,
// and names the owner when it may not. See the Windows half for why the gate
// exists; on unix the same question is whether this process owns the path,
// since chmod is the owner's to make (or root's).
func mayRestrict(path string) (bool, string, error) {
	info, err := os.Stat(path)
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
