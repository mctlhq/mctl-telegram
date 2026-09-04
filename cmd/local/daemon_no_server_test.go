package main

import (
	"context"
	"errors"
	"testing"
)

// A config.json with no server must stop the daemon by name, before any
// credential work. Until #501, activate --server was not persisted, so this
// was the state every user reached after the documented first-time sequence;
// the failure they saw was "device credential refresh failed" against an
// empty URL, which names neither the cause nor the fix.
func TestServeDaemon_NoServerConfiguredIsNamed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := saveConfig(&localConfig{APIID: 1, APIHash: "h"}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	err := serveDaemon(context.Background())
	if !errors.Is(err, errNoServerConfigured) {
		t.Fatalf("serveDaemon with empty server: got %v, want errNoServerConfigured", err)
	}
}
