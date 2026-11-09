// Package fakeonly is the runtime half of the fake-provider-only gate. The
// build-time half is gate_fake.go / gate_real.go.
package fakeonly

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// EnvFakeOnly must be exactly "true" for the worker to start.
const EnvFakeOnly = "FAKE_ONLY"

// ErrNotFakeOnly is returned when FAKE_ONLY is missing or not "true".
var ErrNotFakeOnly = errors.New("fakeonly: FAKE_ONLY=true is required")

// ErrCredentialEnv is returned when a Glovo credential or session variable is set.
var ErrCredentialEnv = errors.New("fakeonly: glovo credential or session environment variable is set")

// denyPatterns are matched case-insensitively against variable names only.
var denyPatterns = []string{
	"GLOVO_*TOKEN*",
	"GLOVO_*SESSION*",
	"GLOVO_*COOKIE*",
	"GLOVO_*PASSWORD*",
	"GLOVO_API_*",
	"GLOVO_BASE_URL",
}

// Check validates an environment in KEY=VALUE form. Error messages carry
// variable names only, never values.
func Check(env []string) error {
	var fakeOnly string
	var denied []string
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		if name == EnvFakeOnly {
			fakeOnly = value
		}
		upper := strings.ToUpper(name)
		for _, p := range denyPatterns {
			if ok, _ := path.Match(p, upper); ok {
				denied = append(denied, name)
				break
			}
		}
	}
	if len(denied) > 0 {
		sort.Strings(denied)
		return fmt.Errorf("%w: %s", ErrCredentialEnv, strings.Join(denied, ","))
	}
	if RealAdapterCompiled || fakeOnly != "true" {
		return ErrNotFakeOnly
	}
	return nil
}
