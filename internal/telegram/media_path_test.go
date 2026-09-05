package telegram

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAllowlistedFile_ReadsInsideDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.ogg")
	if err := os.WriteFile(path, []byte("hello-media"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadAllowlistedFile(path, dir, 1024)
	if err != nil {
		t.Fatalf("ReadAllowlistedFile: %v", err)
	}
	if string(got) != "hello-media" {
		t.Fatalf("got %q", got)
	}
	got, err = ReadAllowlistedFile("note.ogg", dir, 1024)
	if err != nil {
		t.Fatalf("relative path: %v", err)
	}
	if string(got) != "hello-media" {
		t.Fatalf("relative got %q", got)
	}
}

func TestReadAllowlistedFile_RejectsEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "..", "escape.txt")
	if _, err := ReadAllowlistedFile(outside, dir, 1024); err == nil {
		t.Fatal("path escape must be refused")
	}
	if _, err := ReadAllowlistedFile("/etc/passwd", dir, 1024); err == nil {
		t.Fatal("absolute path outside allowlist must be refused")
	}
}

func TestReadAllowlistedFile_RejectsOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ReadAllowlistedFile(path, dir, 3); err == nil {
		t.Fatal("oversize file must be refused")
	}
}

func TestReadAllowlistedFile_RejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := ReadAllowlistedFile(link, dir, 1024); err == nil {
		t.Fatal("symlink pointing outside the allowlist must be refused")
	}
}

func TestReadAllowlistedFile_EmptyAllowDir(t *testing.T) {
	if _, err := ReadAllowlistedFile("x", "", 10); err == nil {
		t.Fatal("empty allowlist must be refused")
	}
}
