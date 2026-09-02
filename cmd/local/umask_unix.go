//go:build !windows

package main

import "syscall"

// restrictUmask makes every file this process creates owner-only.
//
// restrictDBPerms narrows the database and its sidecars after the fact, which
// repairs installations that predate it but leaves a window: the SQLite driver
// creates the files under the inherited umask — 0644 on a default account — and
// they are readable for as long as it takes the chmod to land. Setting the
// umask first means they are never created readable at all.
//
// Both are kept. The umask covers files created from now on; the chmod covers
// files that already exist on disk from an earlier version, which no umask can
// reach.
func restrictUmask() { syscall.Umask(0o077) }
