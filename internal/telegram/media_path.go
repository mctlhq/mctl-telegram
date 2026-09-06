package telegram

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Hooks are package-level so tests can inject a post-Lstat swap or an
// inode-mismatch open. Production keeps the OS implementations.
var (
	lstatAllowlisted = os.Lstat
	openAllowlisted  = openNoFollow
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
//
// After the allowlist resolve, the file is Lstat'd (must be a regular file,
// not a symlink), opened without following a final-component symlink
// (O_NOFOLLOW on Unix), and the opened fd is required to be the same inode
// (os.SameFile). The opened fd's kernel path is checked again so a parent
// directory swapped to a symlink between resolve and open cannot leak an
// outside regular file. If that fd-to-path lookup is unavailable, the
// read fails closed instead of re-evaluating the string path.
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

	lst, err := lstatAllowlisted(resolved)
	if err != nil {
		return nil, fmt.Errorf("file_path: %w", err)
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("file_path must not be a symlink")
	}
	if !lst.Mode().IsRegular() {
		return nil, fmt.Errorf("file_path must be a regular file")
	}
	if maxBytes > 0 && lst.Size() > maxBytes {
		return nil, fmt.Errorf("file_path is %d bytes, exceeding the %d-byte upload cap", lst.Size(), maxBytes)
	}

	f, err := openAllowlisted(resolved)
	if err != nil {
		return nil, fmt.Errorf("file_path: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("file_path: %w", err)
	}
	if !os.SameFile(lst, info) {
		return nil, fmt.Errorf("file_path changed during open")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file_path must be a regular file")
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("file_path is %d bytes, exceeding the %d-byte upload cap", info.Size(), maxBytes)
	}

	openedReal, err := realOpenedPath(f)
	if err != nil {
		return nil, fmt.Errorf("file_path: %w", err)
	}
	if !isUnderDir(allowReal, openedReal) {
		return nil, fmt.Errorf("file_path is outside the media allowlist directory")
	}

	// When uncapped, read the fd to EOF. Bounding by the stat-time size
	// would silently truncate a file that grows after Lstat (a voice note
	// still being written). Only apply LimitReader when a cap is set;
	// then a growing file that crosses the cap errors instead of uploading
	// a truncated body.
	if maxBytes <= 0 {
		data, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("file_path: %w", err)
		}
		return data, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("file_path: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file_path is %d bytes, exceeding the %d-byte upload cap", len(data), maxBytes)
	}
	return data, nil
}

// realOpenedPath returns the filesystem path of the already-opened fd
// via a kernel fd-to-path mechanism (/proc/self/fd on Linux, F_GETPATH
// on macOS). A missing or failed lookup is an error: re-evaluating the
// original string path is TOCTOU-racy (a parent directory can be swapped
// to a symlink for Lstat/Open and restored before a string EvalSymlinks).
func realOpenedPath(f *os.File) (string, error) {
	p, err := resolveOpenedFDPath(f)
	if err != nil {
		return "", fmt.Errorf("cannot resolve opened file path: %w", err)
	}
	if p == "" {
		return "", fmt.Errorf("cannot resolve opened file path")
	}
	return p, nil
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
