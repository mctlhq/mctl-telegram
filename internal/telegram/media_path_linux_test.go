//go:build linux

package telegram

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAllowlistedFile_FailClosedWithoutProcFD(t *testing.T) {
	orig := procSelfFDDir
	t.Cleanup(func() { procSelfFDDir = orig })
	procSelfFDDir = filepath.Join(t.TempDir(), "missing-proc-self-fd")

	dir := t.TempDir()
	path := filepath.Join(dir, "note.bin")
	if err := os.WriteFile(path, []byte("inside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadAllowlistedFile(path, dir, 1024)
	if err == nil {
		t.Fatalf("missing /proc/self/fd must fail closed, got %q", got)
	}
	if string(got) == "inside" {
		t.Fatal("must not return file bytes when fd-to-path is unavailable")
	}
	if !strings.Contains(err.Error(), "cannot resolve opened file path") {
		t.Fatalf("got %v, want a resolve error", err)
	}
}
