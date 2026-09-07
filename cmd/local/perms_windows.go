//go:build windows

package main

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// secureFile and secureDir stand in for the POSIX mode on Windows, where the
// mode achieves nothing: NTFS ignores it, os.Chmod only toggles the read-only
// attribute, and a file created 0600 is reported 0666 while remaining readable
// by every account the profile directory happens to grant. The daemon keeps
// three secrets on disk — the sealed session database and its sidecars, the
// bridge token, and the device key — so "whatever the profile grants" is not a
// good enough answer on a shared or domain-joined machine.
//
// Both set an explicit DACL naming the current user and nobody else, and mark
// it PROTECTED so that an inheritable ACE further up the profile cannot widen
// it again. This is gap 3 in internal/bridge/DESIGN.md, and it is the change
// chosen over an OS keychain on #138: the daemon is meant to run under a
// service manager, where the macOS login keychain is locked and headless Linux
// has no Secret Service, so the credential stays a file and the file is what
// gets protected.
//
// What this deliberately does NOT grant is worth stating, because it is a real
// trade rather than an oversight: SYSTEM and Administrators get no ACE. A
// daemon started as a Windows service under LocalSystem therefore cannot read a
// token written by the interactive user, which is the intended consequence of
// the secrets belonging to one human account.
//
// What it protects against is the ordinary access check, and no more. An
// elevated administrator can still read these files without touching the DACL
// at all — SeBackupPrivilege opens them with backup semantics, and taking
// ownership is available as well; nothing here installs a SACL, so neither is
// audited unless the machine's audit policy says so independently. The
// threat model is another unprivileged account on the same machine, not the
// machine's administrator.
func secureFile(path string) error { return ownerOnlyACL(path, windows.NO_INHERITANCE) }

// secureDir makes the ACE inheritable, which is what keeps files created inside
// the directory protected without every creation site having to know about it —
// the SQLite driver's -wal and -shm sidecars and the media subdirectory among
// them.
//
// A directory ends up carrying two ACEs rather than one, both naming the same
// account: GENERIC_ALL maps to different specific rights for a container than
// for an object, so Windows splits an inheritable generic ACE into an effective
// ACE for the directory itself and an INHERIT_ONLY ACE that keeps the generic
// bits for children to map. That is normal, and perms_windows_test.go asserts
// exclusivity per ACE for directories rather than a count for that reason.
func secureDir(path string) error {
	return ownerOnlyACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

func ownerOnlyACL(path string, inheritance uint32) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	// TrusteeValueFromSID stores the SID as a bare uintptr, which the garbage
	// collector cannot see: x/sys requires the caller to pin it for the
	// lifetime of the trustee. Without this a moving GC during ACLFromEntries
	// could leave the trustee pointing at something that is no longer the SID,
	// and the ACL would be built from whatever is there — the failure mode is
	// a wrong grant, not a crash, which is the worst kind here.
	var pinner runtime.Pinner
	pinner.Pin(sid)
	defer pinner.Unpin()

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("build owner-only ACL for %s: %w", path, err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		return fmt.Errorf("restrict permissions on %s: %w", path, err)
	}
	return nil
}

// mayRestrict reports whether this process may rewrite the permissions of path,
// and names the owner when it may not.
//
// The gate exists because this runs over an install this process did not
// necessarily create. Granting the caller unconditionally would let a daemon
// installed as a Windows service under LocalSystem, pointed at the interactive
// user's config directory, rewrite that user's secrets to SYSTEM alone —
// handing the service the credentials and locking out the human they belong to.
//
// Ownership is a gate and never a grantee. Reading a SID off disk and writing
// it into a protected DACL is the other way to get this wrong: an owner
// inherited from another machine, a backup restored with /COPYALL, or a group
// that is not a login at all would then become the only account named on a
// secret this process can still read but nobody can subsequently fix. CI proved
// that danger rather than hypothesising it — on a GitHub Windows runner the
// account is an elevated administrator, so files it creates are owned by
// BUILTIN\Administrators (S-1-5-32-544), and an owner-as-grantee rule handed
// every secret to a group instead of to the user.
//
// Membership, not equality, for the same reason: the owner of a file an
// elevated user creates is often the Administrators group rather than that
// user, and the process token carries it.
func mayRestrict(path string) (bool, string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, "", fmt.Errorf("read owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, "", fmt.Errorf("read owner of %s: %w", path, err)
	}
	if owner == nil {
		// Distinct from a failure, and it has to say so: this decision leaves
		// the secrets under the old DACL, and "%!w(<nil>)" in the warning would
		// explain nothing about why.
		return false, "", fmt.Errorf("read owner of %s: the object carries no owner", path)
	}
	// Token(0), not OpenCurrentProcessToken: CheckTokenMembership requires an
	// impersonation token and fails with ERROR_NO_IMPERSONATION_TOKEN on a
	// primary one. The NULL handle makes Windows impersonate the calling
	// thread's own token for the check, which is the documented way to ask this
	// question from a process that is not impersonating anybody. Getting this
	// wrong made the gate error every time and killed the whole Windows repair
	// pass — CI caught it.
	member, err := windows.Token(0).IsMember(owner)
	if err != nil {
		return false, "", fmt.Errorf("check membership of %s: %w", owner, err)
	}
	return member, owner.String(), nil
}

// currentUserSID reads the SID of the account this process runs as. The token
// is opened rather than taken from windows.GetCurrentProcessToken() so that the
// handle is closed explicitly; the daemon calls this on every write of the
// bridge token, which happens roughly every five minutes for the lifetime of
// the process.
func currentUserSID() (*windows.SID, error) {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, fmt.Errorf("open process token: %w", err)
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("look up current user: %w", err)
	}
	return u.User.Sid, nil
}
