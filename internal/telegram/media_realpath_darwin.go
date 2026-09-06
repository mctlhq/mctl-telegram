//go:build darwin

package telegram

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func resolveOpenedFDPath(f *os.File) (string, error) {
	var buf [unix.PathMax]byte
	if _, err := fcntlGetPath(f.Fd(), &buf); err != nil {
		return "", fmt.Errorf("F_GETPATH: %w", err)
	}
	p := unix.ByteSliceToString(buf[:])
	if p == "" {
		return "", fmt.Errorf("F_GETPATH returned an empty path")
	}
	return p, nil
}

// fcntlGetPath asks the kernel for the path of fd. buf is passed as a
// pointer so the array stays alive across the FcntlInt call; the address
// is an int because that is what unix.FcntlInt accepts, and on darwin
// amd64/arm64 int is pointer-width.
func fcntlGetPath(fd uintptr, buf *[unix.PathMax]byte) (int, error) {
	return unix.FcntlInt(fd, unix.F_GETPATH, int(uintptr(unsafe.Pointer(&buf[0]))))
}
