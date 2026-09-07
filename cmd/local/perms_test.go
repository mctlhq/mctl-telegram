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

// TestHardenExistingSecretsTightensAnUpgradedInstall covers the case every
// other call site misses: an install that already exists and is only read.
// loadConfig, loadBridgeToken and db.Open all run before anything writes, so
// without this the files would keep the permissions an older version left them
// with — on Windows, the DACL inherited from the profile.
//
// The mode assertions are unix-only; the Windows half of the same property is
// TestHardenExistingSecretsOnWindows, which asserts the same seeded install
// comes out with a protected single-ACE DACL on each secret.
func TestHardenExistingSecretsTightensAnUpgradedInstall(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	dir := filepath.Join(home, ".config", "mctl-telegram-local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed config dir: %v", err)
	}
	// What an older version left behind: world-readable secrets in a
	// world-traversable directory.
	secrets := []string{configFileName, bridgeTokenName, deviceKeyName, "state.db", "state.db-wal"}
	for _, name := range secrets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	hardenExistingSecrets()

	if info, err := os.Stat(dir); err != nil {
		t.Fatalf("stat dir: %v", err)
	} else if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("config dir has mode %04o, want 0700", got)
	}
	for _, name := range secrets {
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s has mode %04o after the upgrade pass, want 0600", name, got)
		}
	}
}

// TestHardenExistingSecretsDoesNotCreateTheConfigDir pins the other half: on a
// machine with no install it must not leave a directory behind. shouldHarden
// keeps `version` and `help` away from it entirely, so the case that actually
// reaches here is a first `init` — which creates the directory when it saves,
// not before.
func TestHardenExistingSecretsDoesNotCreateTheConfigDir(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	hardenExistingSecrets()

	if _, err := os.Stat(filepath.Join(home, ".config", "mctl-telegram-local")); !os.IsNotExist(err) {
		t.Errorf("config dir exists after hardening a machine with no install (err=%v)", err)
	}
}

// TestHardenForCommandWiring pins decision and action together: the rule and
// the repair are each covered on their own, and this is what connects them.
// main() is one line — hardenForCommand(os.Args[1:]) — and no unit test can
// reach it without executing the binary; everything below that line is here.
func TestHardenForCommandWiring(t *testing.T) {
	seed := func(t *testing.T) string {
		t.Helper()
		home := t.TempDir()
		setHome(t, home)
		dir := filepath.Join(home, ".config", "mctl-telegram-local")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("seed config dir: %v", err)
		}
		p := filepath.Join(dir, configFileName)
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatalf("seed config: %v", err)
		}
		// Chmod, not the WriteFile mode: that one is masked, so under
		// `umask 077` the seed would already be 0600 and both halves of this
		// test would stop meaning anything — the "untouched" case failing on a
		// run where nothing is wrong, the other passing without the repair
		// having done a thing.
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatalf("seed mode: %v", err)
		}
		return dir
	}

	t.Run("a command that reads state repairs first", func(t *testing.T) {
		dir := seed(t)
		hardenForCommand([]string{"connect", "--token", "x"})
		info, err := os.Stat(filepath.Join(dir, configFileName))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("config.json has mode %04o after `connect`, want 0600", got)
		}
	})

	t.Run("version leaves an existing install untouched", func(t *testing.T) {
		dir := seed(t)
		hardenForCommand([]string{"version"})
		info, err := os.Stat(filepath.Join(dir, configFileName))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Errorf("config.json has mode %04o after `version`, want it untouched at 0644", got)
		}
	})
}
