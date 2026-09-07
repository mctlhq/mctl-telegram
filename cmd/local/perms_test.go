//go:build !windows

package main

import (
	"errors"
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
	// MkdirAll's mode is masked like WriteFile's: without this the directory
	// is 0700 under `umask 077` and the assertion below restates the seed.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("seed config dir mode: %v", err)
	}
	// What an older version left behind: world-readable secrets in a
	// world-traversable directory. The mode is set with chmod because
	// WriteFile's is masked — under `umask 077` the seed would already be
	// 0600 and every assertion below would restate its own setup, passing
	// with the repair removed.
	secrets := []string{configFileName, bridgeTokenName, deviceKeyName, "state.db", "state.db-wal"}
	for _, name := range secrets {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatalf("seed mode %s: %v", name, err)
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

	restore, restoreDB := installRestrictable, dbRestrictable
	installRestrictable = func() (bool, string, error) { return false, "another-account", nil }
	dbRestrictable = func(string) (bool, string, error) { return false, "another-account", nil }
	t.Cleanup(func() { installRestrictable, dbRestrictable = restore, restoreDB })

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

// TestGateReadFailureLeavesPermissionsAlone pins the branch the other tests do
// not reach: not "this install is someone else's" but "the question could not
// be answered", which is what a volume carrying no security information in the
// form the platform expects produces. It must not stop the daemon, and it must
// not narrow anything on a guess.
func TestGateReadFailureLeavesPermissionsAlone(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	dir := filepath.Join(home, ".config", "mctl-telegram-local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed config dir: %v", err)
	}
	dbPath := filepath.Join(dir, "state.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed db: %v", err)
	}
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatalf("seed mode: %v", err)
	}

	restore, restoreDB := installRestrictable, dbRestrictable
	installRestrictable = func() (bool, string, error) {
		return false, "", errors.New("incorrect function")
	}
	dbRestrictable = func(string) (bool, string, error) {
		return false, "", errors.New("incorrect function")
	}
	t.Cleanup(func() { installRestrictable, dbRestrictable = restore, restoreDB })

	// Not an error: openLocalStore die()s on one, and a daemon holding a
	// working session must not be stopped by an unanswerable question about
	// who owns its files.
	if err := restrictDBPerms(dbPath); err != nil {
		t.Fatalf("restrictDBPerms returned %v; a gate read failure must not stop startup", err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("state.db has mode %04o; nothing may be narrowed on an unanswered ownership question", got)
	}
}

// TestMayRestrictOwnDirectory is the unix half of the gate's positive answer:
// a directory this process created is owned by it, so its permissions are ours
// to set.
func TestMayRestrictOwnDirectory(t *testing.T) {
	dir := t.TempDir()
	allowed, owner, err := mayRestrict(dir)
	if err != nil {
		t.Fatalf("mayRestrict: %v", err)
	}
	if !allowed {
		t.Errorf("own temp directory reported as owned by another account (owner %q); the repair would never run", owner)
	}
}

// TestDatabaseWeOwnIsProtectedOnAGroupOwnedInstall is the database half of the
// rule that the durable object answers for its own set. The config directory
// can be group-owned — the shape the strict gate produces — while the database
// is plainly ours, and then the sidecars db.Open recreates on every run must be
// narrowed like the database they carry the pages of.
func TestDatabaseWeOwnIsProtectedOnAGroupOwnedInstall(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	for _, p := range []string{dbPath, dbPath + "-wal"} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatalf("seed mode %s: %v", p, err)
		}
	}

	// The install is refused; the database is not. Only the second decides.
	restore := installRestrictable
	installRestrictable = func() (bool, string, error) { return false, "another-account", nil }
	t.Cleanup(func() { installRestrictable = restore })

	if err := restrictDBPerms(dbPath); err != nil {
		t.Fatalf("restrictDBPerms: %v", err)
	}
	for _, p := range []string{dbPath, dbPath + "-wal"} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s has mode %04o, want 0600 — the sidecar carries the same pages as the database", p, got)
		}
	}
}

// TestDeclinedGatePreservesTargetPermissions pins what declining means: the
// replacement keeps the permissions the target had. os.Rename carries the temp
// file's mode onto the target, so without copying them forward a refresh would
// hand back a file that is no longer as restricted as the one it replaced.
//
// It also pins the one-way rule: a target more permissive than the temp file is
// left behind rather than copied, because declining to restrict must not turn
// into a licence to loosen.
func TestDeclinedGatePreservesTargetPermissions(t *testing.T) {
	restore := installRestrictable
	installRestrictable = func() (bool, string, error) { return false, "another-account", nil }
	t.Cleanup(func() { installRestrictable = restore })

	for _, tc := range []struct {
		name           string
		seed, expected os.FileMode
	}{
		{"a stricter target is preserved", 0o400, 0o400},
		{"a wider target is not copied back", 0o644, 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// writeFileAtomic asks installRestrictable, which resolves the
			// config directory from home; without this the gate would be
			// answered about the developer's real install.
			setHome(t, t.TempDir())
			path := filepath.Join(dir, "secret.json")
			if err := os.WriteFile(path, []byte("old"), tc.seed); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if err := os.Chmod(path, tc.seed); err != nil {
				t.Fatalf("seed mode: %v", err)
			}

			if err := writeFileAtomic(path, []byte("new"), 0o600); err != nil {
				t.Fatalf("writeFileAtomic: %v", err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if got := info.Mode().Perm(); got != tc.expected {
				t.Errorf("mode %04o after a declined write, want %04o", got, tc.expected)
			}
		})
	}
}
