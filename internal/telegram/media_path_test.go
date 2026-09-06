package telegram

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type modeOverride struct {
	os.FileInfo
	mode os.FileMode
}

func (m modeOverride) Mode() os.FileMode { return m.mode }

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

func TestReadAllowlistedFile_ExactCapIsAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.bin")
	payload := []byte("12345")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadAllowlistedFile(path, dir, int64(len(payload)))
	if err != nil {
		t.Fatalf("exact-cap file must be accepted: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q, want full payload", got)
	}
}

func TestReadAllowlistedFile_UncappedReadsAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.bin")
	if err := os.WriteFile(path, []byte("hello-media"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadAllowlistedFile(path, dir, 0)
	if err != nil {
		t.Fatalf("uncapped read: %v", err)
	}
	if string(got) != "hello-media" {
		t.Fatalf("got %q", got)
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

func TestReadAllowlistedFile_FollowsInternalSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.bin")
	if err := os.WriteFile(target, []byte("inside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	got, err := ReadAllowlistedFile(link, dir, 1024)
	if err != nil {
		t.Fatalf("internal symlink must resolve and read: %v", err)
	}
	if string(got) != "inside" {
		t.Fatalf("got %q", got)
	}
}

func TestReadAllowlistedFile_RejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadAllowlistedFile(dir, dir, 1024); err == nil {
		t.Fatal("directory must be refused")
	}
}

func TestReadAllowlistedFile_RejectsLstatSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.bin")
	if err := os.WriteFile(path, []byte("inside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	orig := lstatAllowlisted
	t.Cleanup(func() { lstatAllowlisted = orig })
	lstatAllowlisted = func(p string) (os.FileInfo, error) {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		return modeOverride{FileInfo: info, mode: os.ModeSymlink | 0o777}, nil
	}
	if _, err := ReadAllowlistedFile(path, dir, 1024); err == nil {
		t.Fatal("Lstat reporting a symlink must be refused")
	}
}

func TestReadAllowlistedFile_RejectsOpenedInodeMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.bin")
	if err := os.WriteFile(path, []byte("inside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	other := filepath.Join(dir, "other.bin")
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatalf("write other: %v", err)
	}
	orig := openAllowlisted
	t.Cleanup(func() { openAllowlisted = orig })
	openAllowlisted = func(string) (*os.File, error) {
		return os.Open(other)
	}
	if _, err := ReadAllowlistedFile(path, dir, 1024); err == nil {
		t.Fatal("SameFile mismatch must be refused")
	}
}

func TestReadAllowlistedFile_RejectsSwapToSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.bin")
	if err := os.WriteFile(path, []byte("inside"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	orig := lstatAllowlisted
	t.Cleanup(func() { lstatAllowlisted = orig })
	lstatAllowlisted = func(p string) (os.FileInfo, error) {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if err := os.Remove(p); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if err := os.Symlink(outside, p); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		return info, nil
	}
	got, err := ReadAllowlistedFile(path, dir, 1024)
	if err == nil {
		t.Fatalf("symlink swap must be refused, got %q", got)
	}
	if string(got) == "secret" {
		t.Fatal("must not return the swapped target")
	}
}

func TestReadAllowlistedFile_UncappedGrowingFileReadsAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grow.bin")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	grown := []byte("1234567890-grown")
	orig := lstatAllowlisted
	t.Cleanup(func() { lstatAllowlisted = orig })
	lstatAllowlisted = func(p string) (os.FileInfo, error) {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, grown, 0o600); err != nil {
			t.Fatalf("grow: %v", err)
		}
		return info, nil
	}
	got, err := ReadAllowlistedFile(path, dir, 0)
	if err != nil {
		t.Fatalf("uncapped growing file: %v", err)
	}
	if string(got) != string(grown) {
		t.Fatalf("got %q, want full grown payload (not stat-size truncated)", got)
	}
}

func TestReadAllowlistedFile_CappedGrowingFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grow.bin")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	orig := lstatAllowlisted
	t.Cleanup(func() { lstatAllowlisted = orig })
	lstatAllowlisted = func(p string) (os.FileInfo, error) {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, []byte("1234567890"), 0o600); err != nil {
			t.Fatalf("grow: %v", err)
		}
		return info, nil
	}
	if _, err := ReadAllowlistedFile(path, dir, 7); err == nil {
		t.Fatal("growing past the cap must be refused")
	} else if !strings.Contains(err.Error(), "exceeding") {
		t.Fatalf("got %v, want an oversize error", err)
	}
}
