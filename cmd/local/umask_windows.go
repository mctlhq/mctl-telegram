//go:build windows

package main

// restrictUmask is a no-op on Windows, which has no umask: NTFS ignores POSIX
// modes entirely and inherits an ACL from the parent directory instead.
//
// That is not equivalent protection, and pretending otherwise here would hide
// the gap: on Windows the config, the bridge token and the session database
// carry whatever ACL the user profile grants. Closing it means setting an
// explicit ACL through golang.org/x/sys/windows. Tracked as gap 2a in
// internal/bridge/DESIGN.md.
func restrictUmask() {}
