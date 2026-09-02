//go:build windows

package main

// restrictUmask is a no-op on Windows, which has no umask: NTFS ignores POSIX
// modes entirely and inherits an ACL from the parent directory instead.
//
// That is not equivalent protection, and pretending otherwise here would hide
// the gap. Windows file protection for the config directory is tracked
// separately; see internal/bridge/DESIGN.md.
func restrictUmask() {}
