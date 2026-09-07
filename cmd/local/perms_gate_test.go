package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMayRestrict pins the gate the permission writes run behind, on both
// platforms. The case it exists for — a config directory owned by an account
// this process is not — cannot be built in CI: it needs a second account, or
// SeRestorePrivilege to set an arbitrary owner. What is cheap, and what would
// otherwise be assumed, is the pair below.
func TestMayRestrict(t *testing.T) {
	t.Run("a directory this process created is repairable", func(t *testing.T) {
		dir := t.TempDir()
		allowed, owner, err := mayRestrict(dir)
		if err != nil {
			t.Fatalf("mayRestrict: %v", err)
		}
		if !allowed {
			t.Errorf("own temp directory reported as owned by another account (owner %q); the repair would never run", owner)
		}
	})

	t.Run("a path that does not exist is an error, not a permission", func(t *testing.T) {
		allowed, _, err := mayRestrict(filepath.Join(t.TempDir(), "absent"))
		if err == nil {
			t.Error("want an error for a missing directory")
		}
		if allowed {
			t.Error("a missing directory must not report as repairable")
		}
	})
}

// TestInstallNotOursIsLeftAlone drives the branch the gate exists for. The real
// scenario — a daemon under LocalSystem pointed at another account's config
// directory — needs a second account or SeRestorePrivilege and cannot be built
// in CI, so the decision is faked at the seam and what is asserted is the thing
// that would go wrong: nothing this process does not own gets its permissions
// rewritten.
//
// Both callers are covered, because they failed differently: hardenExistingSecrets
// asks once, and restrictDBPerms used to ask per file — which passed for -wal
// and -shm, created by this process moments earlier, in exactly the case the
// gate was added for.
func TestInstallNotOursIsLeftAlone(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	dir := filepath.Join(home, ".config", "mctl-telegram-local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed config dir: %v", err)
	}
	seeded := []string{configFileName, bridgeTokenName, "state.db", "state.db-wal"}
	for _, name := range seeded {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatalf("seed mode %s: %v", name, err)
		}
	}

	restore := installRestrictable
	installRestrictable = func() (bool, string, error) { return false, "another-account", nil }
	t.Cleanup(func() { installRestrictable = restore })

	hardenExistingSecrets()
	if err := restrictDBPerms(filepath.Join(dir, "state.db")); err != nil {
		t.Fatalf("restrictDBPerms: %v", err)
	}

	for _, name := range seeded {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Errorf("%s has mode %04o; permissions on an install owned by another account must be left alone", name, got)
		}
	}
}
