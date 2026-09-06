//go:build !unix

package telegram

import "os"

// openNoFollow falls back to a following open. Callers still Lstat,
// require a regular file, and check os.SameFile against the opened fd.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
