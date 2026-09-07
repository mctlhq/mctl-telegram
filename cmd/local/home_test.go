package main

import "testing"

// setHome points os.UserHomeDir at dir for the duration of the test.
//
// It exists because `t.Setenv("HOME", dir)` is a no-op on Windows:
// os.UserHomeDir reads HOME on unix and USERPROFILE on Windows, so a test that
// sets only HOME keeps resolving the real profile. Every config path in this
// package is derived from os.UserHomeDir, so on Windows those tests did not
// merely fail — they read and wrote the developer's actual
// ~/.config/mctl-telegram-local, which holds their device key, their bridge
// token and their encrypted session. Running the suite could destroy a working
// installation.
//
// Nothing caught it because the suite only ever ran on Linux (see the
// test-cross-platform job in .github/workflows/build.yml, and #138).
//
// Both variables are set on every platform rather than switching on GOOS: the
// unused one is harmless, and a conditional here would be one more thing that
// is only exercised on one platform.
func setHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}
