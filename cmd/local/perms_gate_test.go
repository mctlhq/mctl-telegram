package main

import (
	"path/filepath"
	"testing"
)

// TestRepairAllowed pins the gate the startup repair runs behind, on both
// platforms. The case it exists for — a config directory owned by an account
// this process is not — cannot be built in CI: it needs a second account, or
// SeRestorePrivilege to set an arbitrary owner. What is cheap, and what would
// otherwise be assumed, is the pair below.
func TestRepairAllowed(t *testing.T) {
	t.Run("a directory this process created is repairable", func(t *testing.T) {
		dir := t.TempDir()
		allowed, owner, err := repairAllowed(dir)
		if err != nil {
			t.Fatalf("repairAllowed: %v", err)
		}
		if !allowed {
			t.Errorf("own temp directory reported as owned by another account (owner %q); the repair would never run", owner)
		}
	})

	t.Run("a path that does not exist is an error, not a permission", func(t *testing.T) {
		allowed, _, err := repairAllowed(filepath.Join(t.TempDir(), "absent"))
		if err == nil {
			t.Error("want an error for a missing directory")
		}
		if allowed {
			t.Error("a missing directory must not report as repairable")
		}
	})
}
