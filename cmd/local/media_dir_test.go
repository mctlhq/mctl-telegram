package main

import (
	"os"
	"path/filepath"
	"runtime"
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
	// The assertion above — that mediaAllowDir returns the trimmed path — holds
	// on every platform and is the behaviour under test. This second one, that
	// no stray directory was created for the untrimmed string, can only be
	// checked on unix: Win32 strips trailing spaces from a path before it ever
	// reaches the filesystem, so os.Stat(dir+" ") resolves to dir and succeeds
	// no matter what the code did. On Windows the two paths are not distinct
	// filesystem names, so there is nothing here to observe.
	if runtime.GOOS != "windows" {
		if _, err := os.Stat(raw); err == nil {
			t.Fatalf("must not mkdir the untrimmed path %q", raw)
		}
	}
}

func TestMediaAllowDir_WhitespaceOnlyFallsBack(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("MCTL_MEDIA_DIR", "   ")

	got := mediaAllowDir()
	want := filepath.Join(home, configDir, "media")
	if got != want {
		t.Fatalf("got %q, want fallback %q", got, want)
	}
}

func TestMediaAllowDir_Fallback(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
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
