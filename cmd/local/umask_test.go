//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestRestrictUmask asserts that a file created after the call is owner-only
// without any explicit chmod — which is the whole point, since the SQLite
// driver creates the session database and its sidecars for us and we do not
// control the mode it passes.
func TestRestrictUmask(t *testing.T) {
	// Umask is process-wide, so restore whatever the test binary started with.
	restrictUmask()
	t.Cleanup(func() { syscall.Umask(0o022) })

	path := filepath.Join(t.TempDir(), "created-by-a-library")
	// 0666 is what a library that does not think about permissions passes.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = f.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file created with mode %04o, want 0600 — the umask did not take effect", got)
	}
}
