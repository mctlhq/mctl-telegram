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
	t.Run("scope ceiling record", func(t *testing.T) {
		t.Setenv("MCP_CLIENT_PROFILES", `[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read","telegram:messages:read"]}]`)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if c, ok := cfg.ClientProfiles.ScopeCeiling("pa.example"); !ok || strings.Join(c, " ") != "telegram:dialogs:read telegram:messages:read" {
			t.Fatalf("ScopeCeiling = %v, %v", c, ok)
		}
	})
	t.Run("malformed scope ceiling fails fast", func(t *testing.T) {
		for _, raw := range []string{
			`[{"client_id":"pa.example","scope_ceiling":[]}]`,
			`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read telegram:messages:read"]}]`,
			`[{"redirect_uri":"https://pa.example.test/cb","scope_ceiling":null}]`,
			`[{"client_id":"pa.example","profile":"core-readonly","scope_ceiling":null}]`,
			`[{"client_id":"pa.example","profile":"core-readonly","scope_ceiling":["telegram:dialogs:read"],"scope_ceiling":null}]`,
			`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read"],"client_id":"other.example"}]`,
			`[{"client_id":"pa.example","profile":"core-readonly","scope_ceiling":["telegram:dialogs:read"],"SCOPE_CEILING":null}]`,
		} {
			t.Setenv("MCP_CLIENT_PROFILES", raw)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_CLIENT_PROFILES") {
				t.Fatalf("Load() with %s = %v, want the table refusal", raw, err)
			}
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

// TestLoadClientIDPrefixCeiling: a client_id_prefix ceiling bounds CIMD
// clients only, so with CIMD on a prefix the allowlist admits nothing below
// stops startup, and with CIMD off the table loads untouched.
func TestLoadClientIDPrefixCeiling(t *testing.T) {
	const table = `[{"client_id_prefix":"https://chatgpt.com/oauth/","scope_ceiling":["telegram:dialogs:read"]}]`
	t.Run("admitted prefix loads", func(t *testing.T) {
		t.Setenv("OAUTH_CIMD_ACCEPT", "true")
		t.Setenv("OAUTH_CIMD_ALLOWED_HOSTS", "chatgpt.com,claude.ai")
		t.Setenv("MCP_CLIENT_PROFILES", table)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if c, ok := cfg.ClientProfiles.ScopeCeilingFor("https://chatgpt.com/oauth/pXY-1/client.json", ""); !ok || strings.Join(c, " ") != "telegram:dialogs:read" {
			t.Fatalf("ScopeCeilingFor = %v, %v", c, ok)
		}
	})
	t.Run("prefix nothing admits fails fast", func(t *testing.T) {
		t.Setenv("OAUTH_CIMD_ACCEPT", "true")
		t.Setenv("OAUTH_CIMD_ALLOWED_HOSTS", "chatgtp.com,claude.ai")
		t.Setenv("MCP_CLIENT_PROFILES", table)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "can never match") {
			t.Fatalf("Load() = %v, want a client_id_prefix that can never match refused", err)
		}
	})
	t.Run("CIMD off leaves the table alone", func(t *testing.T) {
		t.Setenv("MCP_CLIENT_PROFILES", table)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() with OAUTH_CIMD_ACCEPT unset: %v", err)
		}
		if len(cfg.ClientProfiles.ScopeCeilingByClientIDPrefix) != 1 {
			t.Fatalf("ClientProfiles = %+v", cfg.ClientProfiles)
		}
	})
	t.Run("malformed prefix fails fast", func(t *testing.T) {
		t.Setenv("MCP_CLIENT_PROFILES", `[{"client_id_prefix":"https://chatgpt.com/oauth","scope_ceiling":["telegram:dialogs:read"]}]`)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_CLIENT_PROFILES") {
			t.Fatalf("Load() = %v, want an MCP_CLIENT_PROFILES refusal", err)
		}
	})
}
