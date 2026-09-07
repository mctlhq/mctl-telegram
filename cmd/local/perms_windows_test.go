//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file replaces the assertion it used to make. Until #563 it pinned the
// GAP: restrictDBPerms achieved nothing on Windows, because NTFS ignores POSIX
// modes and os.Chmod only toggles the read-only attribute, so the test failed
// the day the mode became 0600 and forced umask_windows.go and DESIGN.md gap 3
// to be corrected at the same time. The gap is now closed by an explicit DACL
// rather than by a mode, so the mode is still 0666 and asserting on it would
// say nothing. What these tests assert instead is the property the ACL is
// supposed to deliver: exactly one account is granted access, it is this one,
// and no inherited ACE from the profile can widen that.

// dacl reads back the discretionary ACL actually stored on path, together with
// whether it is protected from inheritance.
func dacl(t *testing.T, path string) (*windows.ACL, bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("control(%s): %v", path, err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL(%s): %v", path, err)
	}
	if acl == nil {
		t.Fatalf("%s has a NULL DACL — every account has full access", path)
	}
	return acl, control&windows.SE_DACL_PROTECTED != 0
}

// aceAt returns the type, flags and trustee SID of one ACE. The SID is nil for
// anything that is not an access-allowed ACE: SidStart is only at that offset
// in that layout, so reading it out of, say, an object ACE would report a
// plausible-looking SID that is not the trustee — and the failure message would
// then be a lie about who was granted access.
func aceAt(t *testing.T, acl *windows.ACL, i uint32) (uint8, uint8, *windows.SID) {
	t.Helper()
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, i, &ace); err != nil {
		t.Fatalf("GetAce(%d): %v", i, err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return ace.Header.AceType, ace.Header.AceFlags, nil
	}
	return ace.Header.AceType, ace.Header.AceFlags, (*windows.SID)(unsafe.Pointer(&ace.SidStart))
}

// ownPath makes the current account the owner of path.
//
// The tests that exercise the repair need it because the gate asks whether this
// account owns the install, and a GitHub runner's account is an elevated
// administrator: files it creates are owned by BUILTIN\Administrators, a group,
// which the gate deliberately refuses. Setting the owner to oneself needs no
// privilege; setting it to somebody else would, which is why the divergent case
// still cannot be built here.
func ownPath(t *testing.T, path string) {
	t.Helper()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, testUserSID(t), nil, nil, nil); err != nil {
		t.Fatalf("take ownership of %s: %v", path, err)
	}
}

func testUserSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("currentUserSID: %v", err)
	}
	return sid
}

// TestSecureFileGrantsOnlyTheCurrentUser is the assertion that matters: after
// secureFile, the file's DACL names this account and nobody else. A second ACE
// — Administrators, SYSTEM, an inherited profile-wide grant — would fail here,
// which is deliberate. secureFile's contract is exclusivity, not merely that
// the owner has access.
func TestSecureFileGrantsOnlyTheCurrentUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge_token.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := secureFile(path); err != nil {
		t.Fatalf("secureFile: %v", err)
	}

	acl, protected := dacl(t, path)
	if !protected {
		t.Error("DACL is not protected — an inheritable ACE on the profile directory would widen it again")
	}
	if acl.AceCount != 1 {
		t.Fatalf("DACL has %d ACEs, want exactly 1 — something other than this account is granted access to the bridge token", acl.AceCount)
	}
	assertGrantsOnlyCurrentUser(t, path, acl)
	_, flags, _ := aceAt(t, acl, 0)
	if flags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0 {
		t.Errorf("file ACE carries inheritance flags %#x; a file inherits to nothing", flags)
	}
}

// TestSecureDirIsInheritable pins the half that protects files this code never
// touches itself: the SQLite driver's -wal and -shm sidecars and the media
// subdirectory are created inside the config directory by callers that do not
// call secureFile, so the directory's ACE has to be inheritable or those files
// are born with the profile's ACL.
//
// A directory legitimately carries MORE than one ACE here, which is why this
// asserts exclusivity per ACE rather than a count the way the file test does.
// GENERIC_ALL maps to different specific rights for a container than for an
// object, so when SetEntriesInAcl writes an inheritable generic ACE onto a
// directory Windows splits it: one effective ACE with the rights mapped for the
// directory itself, and one INHERIT_ONLY ACE that keeps the generic bits for
// children to map when they inherit it. Both name the same account, which is
// the property that matters; the first version of this test asserted
// AceCount == 1 and failed on CI for exactly this reason.
func TestSecureDirIsInheritable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mctl-telegram-local")
	if err := mkdirSecure(dir); err != nil {
		t.Fatalf("mkdirSecure: %v", err)
	}

	acl, protected := dacl(t, dir)
	if !protected {
		t.Error("directory DACL is not protected")
	}
	if acl.AceCount == 0 {
		t.Fatal("directory DACL is empty")
	}
	assertGrantsOnlyCurrentUser(t, dir, acl)

	const inherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	var inheritable bool
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		if _, flags, _ := aceAt(t, acl, i); flags&inherit == inherit {
			inheritable = true
		}
	}
	if !inheritable {
		t.Error("no directory ACE carries both inheritance bits; files created inside would keep the profile ACL")
	}

	// The property the flags exist for, asserted end to end rather than only
	// as bits: a file created afterwards by code that knows nothing about
	// ACLs carries the same grant and no other.
	child := filepath.Join(dir, "state.db-wal")
	if err := os.WriteFile(child, []byte("x"), 0o644); err != nil {
		t.Fatalf("write child: %v", err)
	}
	childACL, _ := dacl(t, child)
	if childACL.AceCount == 0 {
		t.Fatalf("inherited DACL on %s is empty", child)
	}
	assertGrantsOnlyCurrentUser(t, child, childACL)
}

// assertGrantsOnlyCurrentUser is the exclusivity check: every ACE in acl is an
// allow ACE naming this account. An inherited profile-wide grant, Administrators
// or SYSTEM all fail it, which is the whole point of the change.
func assertGrantsOnlyCurrentUser(t *testing.T, path string, acl *windows.ACL) {
	t.Helper()
	want := testUserSID(t)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		typ, flags, sid := aceAt(t, acl, i)
		if typ != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Errorf("%s: ACE %d has type %d, want ACCESS_ALLOWED_ACE_TYPE", path, i, typ)
			continue
		}
		if !sid.Equals(want) {
			t.Errorf("%s: ACE %d (flags %#x) grants %s, want only the current user %s", path, i, flags, sid, want)
		}
	}
}

// TestRestrictDBPermsOnWindows is the Windows counterpart of TestRestrictDBPerms
// in perms_test.go, which cannot run here because it asserts a mode. An absent
// sidecar must still not be an error: SetNamedSecurityInfo reports a missing
// path as a wrapped syscall.Errno, which os.IsNotExist does not unwrap, so this
// would fail if restrictDBPerms went back to the legacy helper.
func TestRestrictDBPermsOnWindows(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	for _, p := range []string{dbPath, dbPath + "-wal"} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	// The gate asks about state.db itself. Windows takes a new object's owner
	// from the creating token rather than from the parent directory, so on a
	// runner whose account is an elevated administrator the seeded database is
	// owned by BUILTIN\Administrators and the gate would refuse it.
	ownPath(t, dbPath)
	// state.db-shm is deliberately absent.

	if err := restrictDBPerms(dbPath); err != nil {
		t.Fatalf("restrictDBPerms: %v", err)
	}
	for _, p := range []string{dbPath, dbPath + "-wal"} {
		acl, protected := dacl(t, p)
		if !protected {
			t.Errorf("%s: DACL is not protected", p)
		}
		if acl.AceCount != 1 {
			t.Errorf("%s: DACL has %d ACEs, want exactly 1 — the sealed session would be readable by another local account", p, acl.AceCount)
		}
		assertGrantsOnlyCurrentUser(t, p, acl)
	}
}

// TestHardenExistingSecretsOnWindows is the counterpart of
// TestHardenExistingSecretsTightensAnUpgradedInstall in perms_test.go, which
// asserts modes and therefore cannot run here — on the one platform the repair
// exists for.
//
// It seeds a config directory the way an upgrade from a pre-#563 release leaves
// it: created and written by code that knows nothing about ACLs, so every file
// carries the temp directory's inherited, unprotected DACL. What it pins is the
// part inheritance alone does not give you — the explicit pass over the three
// known secrets. Dropping that loop and relying on propagation from secureDir
// fails this test for any child whose DACL is already protected.
func TestHardenExistingSecretsOnWindows(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	dir := filepath.Join(home, ".config", "mctl-telegram-local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed config dir: %v", err)
	}
	// An install this account owns; see ownPath for why the runner does not
	// produce one by itself. Each file as well as the directory: there is no
	// owner inheritance on NTFS, and since the database answers for its own
	// sidecars, a group-owned state.db would be refused even inside a directory
	// this account owns.
	ownPath(t, dir)
	secrets := []string{configFileName, bridgeTokenName, deviceKeyName, "state.db", "state.db-wal"}
	for _, name := range secrets {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		ownPath(t, p)
	}
	// The premise of the test: before hardening, these carry the profile's
	// inherited ACL, which grants more than this account.
	if acl, protected := dacl(t, filepath.Join(dir, configFileName)); protected && acl.AceCount == 1 {
		t.Skip("seeded files are already owner-only; the runner's profile ACL cannot exercise the repair")
	}

	hardenExistingSecrets()

	acl, protected := dacl(t, dir)
	if !protected {
		t.Error("config directory DACL is not protected after the repair pass")
	}
	assertGrantsOnlyCurrentUser(t, dir, acl)
	for _, name := range secrets {
		p := filepath.Join(dir, name)
		fileACL, fileProtected := dacl(t, p)
		if !fileProtected {
			t.Errorf("%s: DACL is not protected after the repair pass", name)
		}
		assertGrantsOnlyCurrentUser(t, p, fileACL)
	}
}

// TestInstallNotOursIsLeftAloneOnWindows is the Windows half of
// TestInstallNotOursIsLeftAlone, which asserts modes and so cannot run here.
// What it asserts instead is that the seeded files keep the inherited,
// unprotected DACL they were created with: on this platform "left alone" is a
// property of the ACL, and the mode never moves either way.
func TestInstallNotOursIsLeftAloneOnWindows(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	dir := filepath.Join(home, ".config", "mctl-telegram-local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed config dir: %v", err)
	}
	seeded := []string{configFileName, bridgeTokenName, "state.db", "state.db-wal"}
	for _, name := range seeded {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if _, protected := dacl(t, filepath.Join(dir, configFileName)); protected {
		t.Skip("seeded files are already protected; the runner's profile ACL cannot exercise this")
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
		p := filepath.Join(dir, name)
		if _, protected := dacl(t, p); protected {
			t.Errorf("%s carries a protected DACL; permissions on an install owned by another account must be left alone", name)
		}
	}

	// The third permission write, and the one that runs most often: a bridge
	// token refresh replaces the file through writeFileAtomic, and os.Rename
	// carries the temp file's security descriptor onto the final path. Without
	// the gate there, a refresh would hand the user's token to whoever is
	// running the daemon while the other two writes correctly declined.
	if err := saveBridgeToken(&bridgeTokenFile{BridgeToken: "x"}); err != nil {
		t.Fatalf("saveBridgeToken: %v", err)
	}
	if _, protected := dacl(t, filepath.Join(dir, bridgeTokenName)); protected {
		t.Error("a refreshed bridge token carries a protected DACL; the refresh path is not behind the ownership gate")
	}
}

// TestGateReadFailureLeavesReplacedSecretsAloneOnWindows is the sibling of the
// unix TestGateReadFailureLeavesPermissionsAlone, on the path where it is
// observable: a bridge token refresh replacing a secret that already exists.
// Deleting the error branch of the gate in writeFileAtomic makes the error fall
// through to the write, and this fires.
func TestGateReadFailureLeavesReplacedSecretsAloneOnWindows(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	dir := filepath.Join(home, ".config", "mctl-telegram-local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed config dir: %v", err)
	}
	tokenPath := filepath.Join(dir, bridgeTokenName)
	if err := os.WriteFile(tokenPath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if _, protected := dacl(t, tokenPath); protected {
		t.Skip("seeded file is already protected; the runner's profile ACL cannot exercise this")
	}

	restore := installRestrictable
	installRestrictable = func() (bool, string, error) {
		return false, "", errors.New("incorrect function")
	}
	t.Cleanup(func() { installRestrictable = restore })

	if err := saveBridgeToken(&bridgeTokenFile{BridgeToken: "x"}); err != nil {
		t.Fatalf("saveBridgeToken: %v", err)
	}
	if _, protected := dacl(t, tokenPath); protected {
		t.Error("a replaced secret carries a protected DACL after an unanswerable ownership question")
	}
}

// TestMayRestrictOwnership is the Windows half of the gate's answer, and the
// negative case is the one the runner can produce by itself: its account is an
// elevated administrator, so a directory it creates is owned by
// BUILTIN\Administrators. A group is not an account, and letting it through is
// how a LocalSystem service — a member of that same group — used to pass the
// gate and rewrite an install to SYSTEM-only.
func TestMayRestrictOwnership(t *testing.T) {
	t.Run("a group-owned directory is refused", func(t *testing.T) {
		dir := t.TempDir()
		allowed, owner, err := mayRestrict(dir)
		if err != nil {
			t.Fatalf("mayRestrict: %v", err)
		}
		if owner == testUserSID(t).String() {
			t.Skip("this runner's files are owned by the user, not a group; nothing to exercise")
		}
		if allowed {
			t.Errorf("directory owned by %s reported as ours; a group is not an account", owner)
		}
	})

	t.Run("a directory this account owns is repairable", func(t *testing.T) {
		dir := t.TempDir()
		ownPath(t, dir)
		allowed, owner, err := mayRestrict(dir)
		if err != nil {
			t.Fatalf("mayRestrict: %v", err)
		}
		if !allowed {
			t.Errorf("directory owned by this account reported as %q; the repair would never run", owner)
		}
	})
}

// TestNewSecretIsProtectedDespiteDeclinedGate pins the escape the gate makes
// for creation. It is the half of the rule that protects the install shape the
// strict gate creates: a config directory owned by a group gets no repair pass
// from any session, so if a declined gate also skipped new files, a freshly
// written bridge_token.json would carry only the inherited profile ACL — #563
// open on the new secret, with a warning as its only trace.
//
// The difference from TestInstallNotOursIsLeftAloneOnWindows is one line: the
// token file is absent, so there is nothing at the target path to take, and the
// assertion is inverted. With the existence check removed it fails.
func TestNewSecretIsProtectedDespiteDeclinedGate(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	dir := filepath.Join(home, ".config", "mctl-telegram-local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed config dir: %v", err)
	}

	restore := installRestrictable
	installRestrictable = func() (bool, string, error) { return false, "another-account", nil }
	t.Cleanup(func() { installRestrictable = restore })

	if err := saveBridgeToken(&bridgeTokenFile{BridgeToken: "x"}); err != nil {
		t.Fatalf("saveBridgeToken: %v", err)
	}
	acl, protected := dacl(t, filepath.Join(dir, bridgeTokenName))
	if !protected {
		t.Fatal("a newly created secret is unprotected; a declined gate must not leave a new file under the inherited ACL")
	}
	assertGrantsOnlyCurrentUser(t, filepath.Join(dir, bridgeTokenName), acl)
}

// TestDeclinedGateKeepsAProtectedTargetProtected is the Windows half of
// TestDeclinedGatePreservesTargetPermissions, and the case codex raised: the
// first write of a secret protects it (nothing was there to take), and the next
// refresh reaches the declining branch. os.Rename carries the temp file's
// security descriptor onto the target, so without copying the target's forward
// a routine refresh would replace a protected token with one carrying the
// directory's broad inherited ACL — re-exposing the secret it just rewrote.
func TestDeclinedGateKeepsAProtectedTargetProtected(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	dir := filepath.Join(home, ".config", "mctl-telegram-local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed config dir: %v", err)
	}
	tokenPath := filepath.Join(dir, bridgeTokenName)
	if err := os.WriteFile(tokenPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	// The state the first write leaves behind.
	if err := secureFile(tokenPath); err != nil {
		t.Fatalf("secureFile: %v", err)
	}

	restore := installRestrictable
	installRestrictable = func() (bool, string, error) { return false, "another-account", nil }
	t.Cleanup(func() { installRestrictable = restore })

	if err := saveBridgeToken(&bridgeTokenFile{BridgeToken: "refreshed"}); err != nil {
		t.Fatalf("saveBridgeToken: %v", err)
	}
	acl, protected := dacl(t, tokenPath)
	if !protected {
		t.Fatal("a refresh under a declined gate replaced a protected token with an inherited DACL")
	}
	assertGrantsOnlyCurrentUser(t, tokenPath, acl)
}
