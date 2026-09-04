//go:build !windows

package main

import (
	"os"
	"syscall"
)

// lockFileExclusive takes an exclusive, non-blocking advisory lock on f.
// Returns false when another process holds it.
//
// flock, not an O_EXCL sentinel file: the kernel drops this lock when the
// holding process dies, however it dies. A sentinel file survives SIGKILL, an
// OOM kill and a power cut, and every later activate and daemon refresh then
// fails until a human finds and deletes it — turning the guard against a
// bricked config directory into a way of bricking one.
func lockFileExclusive(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
		return false, nil
	}
	return false, err
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
