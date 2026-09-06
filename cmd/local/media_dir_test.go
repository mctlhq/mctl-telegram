package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMediaAllowDir_Override(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MCTL_MEDIA_DIR", dir)

	got := mediaAllowDir()
	if got != dir {
		t.Fatalf("got %q, want override %q", got, dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("override dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("override path is not a directory")
	}
}

func TestMediaAllowDir_TrimsEnv(t *testing.T) {
	dir := t.TempDir()
	raw := dir + " "
	t.Setenv("MCTL_MEDIA_DIR", "  "+dir+"  ")

	got := mediaAllowDir()
	if got != dir {
		t.Fatalf("got %q, want trimmed %q", got, dir)
	}
	if _, err := os.Stat(raw); err == nil {
		t.Fatalf("must not mkdir the untrimmed path %q", raw)
	}
}

func TestMediaAllowDir_WhitespaceOnlyFallsBack(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("MCTL_MEDIA_DIR", "   ")

	got := mediaAllowDir()
	want := filepath.Join(home, configDir, "media")
	if got != want {
		t.Fatalf("got %q, want fallback %q", got, want)
	}
}

func TestMediaAllowDir_Fallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("MCTL_MEDIA_DIR", "")

	got := mediaAllowDir()
	want, err := configDirPath()
	if err != nil {
		t.Fatalf("configDirPath: %v", err)
	}
	want = filepath.Join(want, "media")
	if got != want {
		t.Fatalf("got %q, want fallback %q", got, want)
	}
	info, err := os.Stat(want)
	if err != nil {
		t.Fatalf("fallback dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("fallback path is not a directory")
	}
}
