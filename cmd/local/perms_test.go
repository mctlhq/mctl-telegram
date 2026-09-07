//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRestrictDBPerms covers the sidecar files as well as the database
// itself. SQLite creates state.db, state.db-wal and state.db-shm under the
// process umask — 0644 on a default account — and recreates the -wal/-shm
// pair on every open, so narrowing them once at creation would not hold.
func TestRestrictDBPerms(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	// Deliberately group- and world-readable: what the driver produces under
	// a default umask.
	for _, p := range []string{dbPath, dbPath + "-wal"} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	// state.db-shm is deliberately absent — an absent sidecar is normal and
	// must not be reported as an error.

	if err := restrictDBPerms(dbPath); err != nil {
		t.Fatalf("restrictDBPerms: %v", err)
	}

	for _, p := range []string{dbPath, dbPath + "-wal"} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s has mode %04o, want 0600 — the sealed session would be readable by every local account", p, got)
		}
	}
}
