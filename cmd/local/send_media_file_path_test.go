package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/bridge"
	tg "github.com/mctlhq/mctl-telegram/internal/telegram"
)

// dispatchSendMedia builds a minimal send_media TypeCall envelope and runs it
// through dispatchCall. The oversize and missing-path failures return before
// dispatchCall ever reaches pool.Borrow, so a zero-value pool is never
// touched on those paths. On paths that do fall through to pool.Borrow (e.g.
// draft mode), the zero-value pool fails fast with a
// "telegram api credentials not configured" error instead of attempting a
// real MTProto connection — good enough to prove the file_path was never
// opened, since that error text never mentions file_path.
func dispatchSendMedia(t *testing.T, args map[string]any) bridge.Envelope {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	env := bridge.Envelope{Type: bridge.TypeCall, ID: "test-id", Tool: "send_media", Args: raw}
	pool := &tg.ClientPool{}
	return dispatchCall(context.Background(), nil, pool, 0, env)
}

// TestDispatchSendMedia_FilePathOversizeRejected mirrors the existing
// file_base64 oversize behavior: a file_path larger than
// tg.DefaultMediaUploadMaxBytes must be rejected with the same error shape,
// without a partial send attempt.
func TestDispatchSendMedia_FilePathOversizeRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	oversized := make([]byte, tg.DefaultMediaUploadMaxBytes+1)
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatalf("write oversized file: %v", err)
	}

	resp := dispatchSendMedia(t, map[string]any{
		"peer":       "@x",
		"media_type": "document",
		"file_path":  path,
		"mode":       "send",
	})
	if resp.Type != bridge.TypeError {
		t.Fatalf("expected TypeError, got %v (result=%s)", resp.Type, resp.Result)
	}
	if !containsAll(resp.Error, "file_path", "exceeding", "upload cap") {
		t.Errorf("error = %q, want it to describe the upload cap being exceeded", resp.Error)
	}
}

// TestDispatchSendMedia_FilePathMissingReturnsClearError asserts a
// nonexistent file_path returns a "send_media: file_path: ..." error,
// distinguishable from the oversize error, without ever reaching the
// Telegram client pool.
func TestDispatchSendMedia_FilePathMissingReturnsClearError(t *testing.T) {
	resp := dispatchSendMedia(t, map[string]any{
		"peer":       "@x",
		"media_type": "document",
		"file_path":  filepath.Join(t.TempDir(), "does-not-exist.bin"),
		"mode":       "send",
	})
	if resp.Type != bridge.TypeError {
		t.Fatalf("expected TypeError, got %v (result=%s)", resp.Type, resp.Result)
	}
	if !containsAll(resp.Error, "send_media", "file_path") {
		t.Errorf("error = %q, want it to identify file_path as the failure source", resp.Error)
	}
	if containsAll(resp.Error, "exceeding", "upload cap") {
		t.Errorf("error = %q, missing-file error must not look like the oversize error", resp.Error)
	}
}

// TestDispatchSendMedia_DraftModeNeverReadsFilePath is the daemon-side
// regression guard: with mode != "send" (draft), a file_path pointing at a
// nonexistent file must not surface a filesystem error — realSend gating
// means the path is never opened. The call still reaches pool.Borrow (which
// fails fast here with a missing-credentials error, not a filesystem one) —
// what matters is that the failure is never file_path-shaped.
func TestDispatchSendMedia_DraftModeNeverReadsFilePath(t *testing.T) {
	resp := dispatchSendMedia(t, map[string]any{
		"peer":       "@x",
		"media_type": "document",
		"file_path":  filepath.Join(t.TempDir(), "does-not-exist.bin"),
	})
	if containsAll(resp.Error, "file_path") {
		t.Fatalf("draft-mode send_media must not attempt to read file_path, got error: %s", resp.Error)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// TestDispatchSendMedia_FilePathSensitiveRejected asserts file_path refuses
// credential material: a real send must not turn send_media into an
// exfiltration primitive for the caller's own secrets.
func TestDispatchSendMedia_FilePathSensitiveRejected(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	path := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(path, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	resp := dispatchSendMedia(t, map[string]any{
		"peer":       "@x",
		"media_type": "document",
		"file_path":  path,
		"mode":       "send",
	})
	if resp.Type != bridge.TypeError {
		t.Fatalf("expected TypeError, got %v (result=%s)", resp.Type, resp.Result)
	}
	if !containsAll(resp.Error, "file_path", "refusing to read") {
		t.Errorf("error = %q, want it to refuse the credential directory", resp.Error)
	}
}

// TestRejectSensitiveFilePath_FollowsSymlinks guards the resolution step: a
// benign-looking symlink must not smuggle a credential file past the check.
func TestRejectSensitiveFilePath_FollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	awsDir := filepath.Join(dir, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir .aws: %v", err)
	}
	target := filepath.Join(awsDir, "credentials")
	if err := os.WriteFile(target, []byte("[default]"), 0o600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	link := filepath.Join(dir, "holiday.jpg")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := rejectSensitiveFilePath(link); err == nil {
		t.Error("rejectSensitiveFilePath(symlink into .aws) = nil, want refusal")
	}
	ok := filepath.Join(dir, "photo.jpg")
	if err := os.WriteFile(ok, []byte("jpeg"), 0o600); err != nil {
		t.Fatalf("write photo: %v", err)
	}
	if err := rejectSensitiveFilePath(ok); err != nil {
		t.Errorf("rejectSensitiveFilePath(ordinary file) = %v, want nil", err)
	}
}

// TestReadBoundedFile_RejectsNonRegular is the memory/hang guard: a special
// file such as /dev/zero must be refused before any read, since os.ReadFile
// would grow without bound on it (and block forever on a FIFO). The timeout
// is what catches a regression that reorders the check after the open.
func TestReadBoundedFile_RejectsNonRegular(t *testing.T) {
	if info, err := os.Stat("/dev/zero"); err != nil || info.Mode().IsRegular() {
		t.Skip("no /dev/zero on this platform")
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := readBoundedFile("/dev/zero", tg.DefaultMediaUploadMaxBytes)
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Error("readBoundedFile(/dev/zero) = nil error, want refusal")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("readBoundedFile did not refuse a non-regular file promptly")
	}
}

// TestReadBoundedFile_RejectsDirectory covers the other non-regular case a
// caller can reach without a device node.
func TestReadBoundedFile_RejectsDirectory(t *testing.T) {
	if _, err := readBoundedFile(t.TempDir(), tg.DefaultMediaUploadMaxBytes); err == nil {
		t.Error("readBoundedFile(directory) = nil error, want refusal")
	}
}

// TestReadBoundedFile_OversizeNotBuffered asserts an oversized file is
// reported from its size, never loaded whole.
func TestReadBoundedFile_OversizeNotBuffered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	data, err := readBoundedFile(path, 1024)
	if err == nil {
		t.Fatalf("readBoundedFile(4096 bytes, cap 1024) = %d bytes, want error", len(data))
	}
	if !containsAll(err.Error(), "exceeding", "upload cap") {
		t.Errorf("err = %v, want it to name the upload cap", err)
	}
}
