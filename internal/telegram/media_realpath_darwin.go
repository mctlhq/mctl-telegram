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
	// The Pointer->uintptr conversion must appear in unix.Syscall itself
	// so the compiler keeps buf live across the call.
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, f.Fd(), unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return "", fmt.Errorf("F_GETPATH: %w", errno)
	}
	p := unix.ByteSliceToString(buf[:])
	if p == "" {
		return "", fmt.Errorf("F_GETPATH returned an empty path")
	}
	return p, nil
}
