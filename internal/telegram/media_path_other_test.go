//go:build !linux && !darwin

package telegram

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAllowlistedFile_UnsupportedPlatform(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.bin")
	if err := os.WriteFile(path, []byte("inside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadAllowlistedFile(path, dir, 1024)
	if err == nil {
		t.Fatalf("file_path must be refused on this platform, got %q", got)
	}
	if string(got) == "inside" {
		t.Fatal("must not return file bytes when file_path is unsupported")
	}
	if !strings.Contains(err.Error(), "file_path is only supported on Linux and macOS") {
		t.Fatalf("got %v, want the documented platform error", err)
	}
	if strings.Contains(err.Error(), "secure fd-to-path") {
		t.Fatalf("got internal error %v, want the user-facing platform error", err)
	}

	// Refuse before I/O: a missing path must still get the platform error,
	// not a not-found from open.
	_, err = ReadAllowlistedFile(filepath.Join(dir, "missing.bin"), dir, 1024)
	if err == nil || !strings.Contains(err.Error(), "file_path is only supported on Linux and macOS") {
		t.Fatalf("missing path must still be the platform error, got %v", err)
	}
}
