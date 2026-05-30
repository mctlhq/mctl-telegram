package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrDenied is returned when a path falls outside every allowed root.
var ErrDenied = errors.New("path denied: outside allowed roots")

// Allowed checks whether path falls within at least one of the given roots.
// An empty roots slice is treated as deny-all (returns ErrDenied).
// Returns the cleaned, symlink-resolved absolute path on success.
//
// Security properties enforced before any filesystem access:
//   - null bytes are rejected
//   - glob characters (*, ?, [) are rejected
//   - ".." as a path component is rejected
//
// Symlinks that resolve outside every allowed root are also denied.
func Allowed(roots []string, path string) (string, error) {
	if len(roots) == 0 || path == "" {
		return "", ErrDenied
	}

	if err := rejectUnsafePatterns(path); err != nil {
		return "", err
	}

	real, err := realPath(path)
	if err != nil {
		return "", fmt.Errorf("path resolution: %w", err)
	}

	for _, root := range roots {
		if root == "" {
			// An empty root expands to the process CWD via filepath.Abs,
			// silently widening the sandbox. Treat it as invalid and skip.
			continue
		}
		realRoot, err := realPath(root)
		if err != nil {
			continue
		}
		if isUnder(real, realRoot) {
			return real, nil
		}
	}
	return "", ErrDenied
}

// rejectUnsafePatterns returns an error if path contains characters or
// components that signal traversal or injection attempts.
func rejectUnsafePatterns(path string) error {
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("path denied: null byte in path")
	}
	for _, ch := range []string{"*", "?", "["} {
		if strings.Contains(path, ch) {
			return fmt.Errorf("path denied: unsafe pattern %q in path", ch)
		}
	}
	// Reject ".." as any path component (after separating on both / and \).
	clean := filepath.ToSlash(filepath.Clean(path))
	for _, part := range strings.Split(clean, "/") {
		if part == ".." {
			return fmt.Errorf("path denied: traversal component \"..\" in path")
		}
	}
	return nil
}

// realPath returns the canonical absolute path with symlinks resolved.
// When the path does not exist yet (e.g. a file about to be created), we
// resolve as many leading components as exist so that directory-level
// symlinks (e.g. /var → /private/var on macOS) are still followed.
//
// Broken symlinks (lstat succeeds but EvalSymlinks fails with ENOENT) are
// denied — their canonical target is unknown so the sandbox cannot be
// enforced.
func realPath(p string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return real, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	// EvalSymlinks returned ENOENT. Use lstat to distinguish:
	//   lstat OK  → path exists as a broken symlink → cannot determine target → deny
	//   lstat ENOENT → path truly does not exist → use parent-walking fallback
	if _, lstatErr := os.Lstat(abs); lstatErr == nil {
		return "", fmt.Errorf("path denied: broken symlink %q", abs)
	}
	// File does not exist — resolve the nearest existing ancestor and re-append
	// the trailing components so symlinks in the parent dirs are followed.
	dir := abs
	var tail []string
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		tail = append([]string{filepath.Base(dir)}, tail...)
		dir = parent
		resolvedDir, rerr := filepath.EvalSymlinks(dir)
		if rerr == nil {
			return filepath.Join(append([]string{resolvedDir}, tail...)...), nil
		}
		if !os.IsNotExist(rerr) {
			return "", rerr
		}
	}
	return abs, nil
}

// isUnder reports whether child is equal to root or is a direct descendant of root.
func isUnder(child, root string) bool {
	if child == root {
		return true
	}
	return strings.HasPrefix(child, root+string(os.PathSeparator))
}
