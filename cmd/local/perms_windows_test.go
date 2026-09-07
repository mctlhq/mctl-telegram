//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRestrictDBPermsCannotEnforceOwnerOnlyOnWindows pins the platform gap that
// TestRestrictDBPerms (unix-only) would otherwise leave invisible here.
//
// restrictDBPerms chmods the session database and its sidecars to 0600. On
// Windows that call succeeds and achieves nothing: NTFS ignores POSIX modes and
// Go's os.Chmod only toggles the read-only attribute, so os.Stat reports 0666
// for a file every account on the machine can still read. The sealed session,
// the bridge token and the device key are protected by whatever ACL the user
// profile happens to grant — which is the same gap restrictUmask records in
// umask_windows.go and internal/bridge/DESIGN.md lists as gap 3.
//
// This asserts the gap rather than skipping the unix test and moving on. A
// skipped assertion is indistinguishable from a passing one, and this file
// exists so that closing the gap — an explicit ACL through
// golang.org/x/sys/windows — FAILS this test and forces the claim in the docs
// to be corrected at the same time.
func TestRestrictDBPermsCannotEnforceOwnerOnlyOnWindows(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := restrictDBPerms(dbPath); err != nil {
		t.Fatalf("restrictDBPerms: %v", err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got == 0o600 {
		t.Fatalf("mode is 0600 on Windows — the ACL gap may have been closed; "+
			"if so, update umask_windows.go, internal/bridge/DESIGN.md gap 3 and delete this test (got %04o)", got)
	}
}
