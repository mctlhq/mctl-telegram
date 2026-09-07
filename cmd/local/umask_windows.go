//go:build windows

package main

// restrictUmask is a no-op on Windows, which has no umask: NTFS ignores POSIX
// modes entirely and inherits an ACL from the parent directory instead.
//
// Unlike before #563 this is no longer an unclosed gap. The protection the
// umask provides on unix — a file is never created readable in the first place
// — is provided here by the inheritable owner-only DACL on the config
// directory, which mkdirSecure sets when it creates it and hardenExistingSecrets
// repairs at startup on an install that predates #563. Either way a file the
// SQLite driver creates inside is born with that grant and nothing wider.
// secureFile then applies an explicit, protected DACL to each secret in its own
// right. See perms_windows.go and gap 3 in internal/bridge/DESIGN.md.
func restrictUmask() {}
