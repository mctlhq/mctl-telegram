package config

import (
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

// TestLoadClientProfiles pins MCP_CLIENT_PROFILES: unset restricts nobody,
// a valid table is loaded, and a table the server cannot honour stops
// startup instead of leaving a client on the full surface.
func TestLoadClientProfiles(t *testing.T) {
	t.Run("unset restricts nobody", func(t *testing.T) {
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if !cfg.ClientProfiles.Empty() {
			t.Fatalf("ClientProfiles = %v, want empty", cfg.ClientProfiles)
		}
	})
	t.Run("valid table", func(t *testing.T) {
		t.Setenv("MCP_CLIENT_PROFILES", `[{"client_id":"https://platform.example.test/oauth/client.json","profile":"core-readonly"}]`)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if got := cfg.ClientProfiles.ByClientID["https://platform.example.test/oauth/client.json"]; got != toolprofile.CoreReadonly {
			t.Fatalf("ClientProfiles = %v", cfg.ClientProfiles)
		}
	})
	t.Run("redirect_uri record", func(t *testing.T) {
		t.Setenv("MCP_CLIENT_PROFILES", `[{"redirect_uri":"https://platform.example.test/cb","profile":"core-reply"}]`)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if got := cfg.ClientProfiles.ByRedirectURI["https://platform.example.test/cb"]; got != toolprofile.CoreReply {
			t.Fatalf("ClientProfiles = %+v", cfg.ClientProfiles)
		}
	})
	t.Run("malformed table fails fast", func(t *testing.T) {
		t.Setenv("MCP_CLIENT_PROFILES", `[{"client_id":"x","redirect_uri":"https://platform.example.test/cb","profile":"core-readonly"}]`)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "MCP_CLIENT_PROFILES") || !strings.Contains(err.Error(), "names both client_id and redirect_uri") {
			t.Fatalf("Load() = %v, want the table refusal", err)
		}
	})
}
