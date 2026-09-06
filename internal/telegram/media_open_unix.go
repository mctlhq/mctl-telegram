//go:build unix

package telegram

import (
	"os"

	"golang.org/x/sys/unix"
)

// openNoFollow opens path without following a symlink at the last
// component. Intermediate directory components are still followed by
// the kernel; ReadAllowlistedFile re-checks the opened fd's real path.
func openNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
