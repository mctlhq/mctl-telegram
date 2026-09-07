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
