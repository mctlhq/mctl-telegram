//go:build !windows

package main

import "os"

// secureFile and secureDir narrow one path to its owner.
//
// On unix that is the POSIX mode, which is what every caller here already asks
// for when it creates the file. They exist as a pair of functions rather than
// as a literal 0600 at each call site so that the Windows build can substitute
// an explicit ACL — see perms_windows.go — for a mode NTFS ignores.
//
// Applying the mode to a path that already exists is deliberate: it repairs an
// installation created by an earlier version, or by a driver that made the file
// under a wider umask, which is the same reason restrictDBPerms runs on every
// open rather than once at creation.
func secureFile(path string) error { return os.Chmod(path, 0o600) }

func secureDir(path string) error { return os.Chmod(path, 0o700) }

// copyPermissions gives dst the permissions src already has, unless that would
// widen dst.
//
// It is what "leave this file's permissions alone" means on a path that is
// replaced through a temp file and a rename: the mode that survives is the temp
// file's, so preserving the target's means copying it forward.
//
// The one-way rule matters. Declining to restrict must not become a licence to
// loosen: a target left at 0644 by an older version would otherwise pull the
// replacement back to 0644, when the temp file is already 0600 and nobody is
// harmed by keeping it. The Windows half draws the same line by copying only a
// protected DACL and leaving an inherited one to inheritance.
func copyPermissions(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	dstInfo, err := os.Stat(dst)
	if err != nil {
		return err
	}
	srcPerm, dstPerm := srcInfo.Mode().Perm(), dstInfo.Mode().Perm()
	if srcPerm&^dstPerm != 0 {
		return nil
	}
	return os.Chmod(dst, srcPerm)
}
