//go:build !linux && !darwin

package telegram

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAllowlistedFile_FailClosedWithoutSecureFDPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.bin")
	if err := os.WriteFile(path, []byte("inside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadAllowlistedFile(path, dir, 1024)
	if err == nil {
		t.Fatalf("missing secure fd-to-path must fail closed, got %q", got)
	}
	if string(got) == "inside" {
		t.Fatal("must not return file bytes when fd-to-path is unavailable")
	}
	if !strings.Contains(err.Error(), "cannot resolve opened file path") {
		t.Fatalf("got %v, want a resolve error", err)
	}
}
