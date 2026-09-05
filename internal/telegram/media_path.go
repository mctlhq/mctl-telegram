package telegram

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ReadAllowlistedFile reads path if and only if it resolves inside allowDir
// after cleaning and symlink evaluation. This is the send_media file_path
// boundary: the hosted server never calls it; only the Local Bridge daemon
// does, and only for files the operator placed under the media directory.
//
// Relative paths are resolved against allowDir, not the process working
// directory. A path that escapes via ".." or a symlink is refused. The
// file must be a regular file and, when maxBytes > 0, no larger than that
// cap. The function never follows a path outside allowDir, including when
// the file is missing (the parent prefix is still checked).
func ReadAllowlistedFile(path, allowDir string, maxBytes int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("file_path is required")
	}
	if strings.TrimSpace(allowDir) == "" {
		return nil, fmt.Errorf("media allowlist directory is not configured")
	}
	allowAbs, err := filepath.Abs(allowDir)
	if err != nil {
		return nil, fmt.Errorf("media allowlist: %w", err)
	}
	allowReal, err := filepath.EvalSymlinks(allowAbs)
	if err != nil {
		return nil, fmt.Errorf("media allowlist: %w", err)
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(allowReal, candidate)
	}
	candidate = filepath.Clean(candidate)
	if !isUnderDir(allowReal, candidate) {
		return nil, fmt.Errorf("file_path is outside the media allowlist directory")
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, fmt.Errorf("file_path: %w", err)
	}
	if !isUnderDir(allowReal, resolved) {
		return nil, fmt.Errorf("file_path is outside the media allowlist directory")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("file_path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file_path must be a regular file")
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("file_path is %d bytes, exceeding the %d-byte upload cap", info.Size(), maxBytes)
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("file_path: %w", err)
	}
	defer func() { _ = f.Close() }()
	limit := info.Size()
	if maxBytes > 0 && limit > maxBytes {
		limit = maxBytes
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("file_path: %w", err)
	}
	if maxBytes > 0 && int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file_path is %d bytes, exceeding the %d-byte upload cap", len(data), maxBytes)
	}
	return data, nil
}

func isUnderDir(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return true
}
