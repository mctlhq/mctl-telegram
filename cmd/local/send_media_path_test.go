//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSendMediaFilePath_ReadsAllowlistedAndNames(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MCTL_MEDIA_DIR", dir)
	path := filepath.Join(dir, "clip.ogg")
	if err := os.WriteFile(path, []byte("hello-media"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, name, mime, err := loadSendMediaFilePath(path, "")
	if err != nil {
		t.Fatalf("loadSendMediaFilePath: %v", err)
	}
	if string(data) != "hello-media" {
		t.Fatalf("got %q", data)
	}
	if name != "clip.ogg" {
		t.Fatalf("file name = %q, want clip.ogg from the path base", name)
	}
	if mime == "" {
		t.Fatal("mime type must be set")
	}

	_, name, _, err = loadSendMediaFilePath(path, "custom.ogg")
	if err != nil {
		t.Fatalf("named load: %v", err)
	}
	if name != "custom.ogg" {
		t.Fatalf("explicit file name = %q, want custom.ogg", name)
	}
}

func TestLoadSendMediaFilePath_RejectsEscape(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MCTL_MEDIA_DIR", dir)
	if _, _, _, err := loadSendMediaFilePath("/etc/passwd", ""); err == nil {
		t.Fatal("path outside the allowlist must be refused")
	}
}
