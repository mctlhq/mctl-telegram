//go:build linux

package telegram

import (
	"os"
	"path/filepath"
	"strconv"
)

// procSelfFDDir names the kernel fd-to-path directory. Tests replace it
// to exercise fail-closed behavior when /proc/self/fd is unavailable.
var procSelfFDDir = "/proc/self/fd"

func resolveOpenedFDPath(f *os.File) (string, error) {
	proc := filepath.Join(procSelfFDDir, strconv.FormatInt(int64(f.Fd()), 10))
	return filepath.EvalSymlinks(proc)
}
