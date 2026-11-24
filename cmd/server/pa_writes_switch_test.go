package main

import (
	"errors"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
)

// TestPAWritesSwitch: the switch the linking service and the conversation
// layer read is on only when PA_WRITES_ENABLED read on. Flags that could
// not be read, and a writes value that could not be parsed, are errors,
// which every caller treats as off (#1320 P2-S14c).
func TestPAWritesSwitch(t *testing.T) {
	boom := errors.New("injected")
	for _, tc := range []struct {
		name   string
		flags  connector.Flags
		err    error
		on     bool
		failed bool
	}{
		{"on", connector.Flags{Writes: true}, nil, true, false},
		{"off", connector.Flags{}, nil, false, false},
		{"flags unreadable", connector.Flags{Writes: true}, boom, false, true},
		{"writes unreadable", connector.Flags{Writes: true, WritesErr: boom}, nil, false, true},
	} {
		on, err := paWritesSwitch(func() (connector.Flags, error) { return tc.flags, tc.err })()
		if (err != nil) != tc.failed || (err == nil && on != tc.on) {
			t.Fatalf("%s: %v, %v", tc.name, on, err)
		}
		if tc.failed && on {
			t.Fatalf("%s: reads on although the switch could not be read", tc.name)
		}
	}
	// The real reader: an unparseable value is not "on".
	for value, want := range map[string]bool{"true": true, "false": false, "": false} {
		on, err := paWritesSwitch(connector.EnvFlags(func(k string) string {
			if k == "PA_WRITES_ENABLED" {
				return value
			}
			return ""
		}))()
		if err != nil || on != want {
			t.Fatalf("PA_WRITES_ENABLED=%q: %v, %v", value, on, err)
		}
	}
	if on, err := paWritesSwitch(connector.EnvFlags(func(k string) string {
		if k == "PA_WRITES_ENABLED" {
			return "yes please"
		}
		return ""
	}))(); err == nil {
		t.Fatalf("an unparseable PA_WRITES_ENABLED read %v without an error", on)
	}
	// The scope tables this build starts with are valid.
	if err := connection.CheckScopeConfig(); err != nil {
		t.Fatal(err)
	}
}
