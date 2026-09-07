package main

import (
	"path/filepath"
	"testing"
)

// TestMayRestrict pins the half of the gate that is the same everywhere: a path
// that does not exist is an error, not a permission. The positive answer is
// platform-specific — "owned by this account" is a uid on unix and a SID on
// Windows, where the runner's own files are owned by a group — so it lives in
// perms_test.go and perms_windows_test.go, next to the tools each needs.
func TestMayRestrict(t *testing.T) {
	allowed, _, err := mayRestrict(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Error("want an error for a missing directory")
	}
	if allowed {
		t.Error("a missing directory must not report as repairable")
	}
}
