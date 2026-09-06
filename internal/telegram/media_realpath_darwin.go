//go:build darwin

package telegram

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const filePathSupported = true

func resolveOpenedFDPath(f *os.File) (string, error) {
	var buf [unix.PathMax]byte
	if _, err := fcntlGetPath(f.Fd(), uintptr(unsafe.Pointer(&buf[0]))); err != nil {
		return "", fmt.Errorf("F_GETPATH: %w", err)
	}
	p := unix.ByteSliceToString(buf[:])
	if p == "" {
		return "", fmt.Errorf("F_GETPATH returned an empty path")
	}
	return p, nil
}

// fcntlGetPath asks the kernel for the path of fd. The //go:uintptrescapes
// pragma keeps buf pinned for the duration of the call; converting the
// pointer to uintptr in this argument list (not earlier) is the only
// valid unsafe.Pointer pattern for FcntlInt, which has no such pragma.
//
//go:uintptrescapes
func fcntlGetPath(fd uintptr, buf uintptr) (int, error) {
	return unix.FcntlInt(fd, unix.F_GETPATH, int(buf))
}
