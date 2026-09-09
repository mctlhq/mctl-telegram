package config

import (
	"strings"
	"testing"
)

func TestLoadOAuthPreregisteredClients_UnsetIsNoChange(t *testing.T) {
	t.Setenv("OAUTH_PREREGISTERED_CLIENTS", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.OAUTHPreregisteredClients != nil {
		t.Fatalf("OAUTHPreregisteredClients = %#v, want nil when unset", cfg.OAUTHPreregisteredClients)
	}
}

func TestLoadOAuthPreregisteredClients_Valid(t *testing.T) {
	t.Setenv("OAUTH_PREREGISTERED_CLIENTS", `[
		{"client_id": "portal-client-id", "redirect_uris": ["https://portal.example.test/servers-callback"]}
	]`)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.OAUTHPreregisteredClients) != 1 {
		t.Fatalf("OAUTHPreregisteredClients = %#v, want 1 entry", cfg.OAUTHPreregisteredClients)
	}
	got := cfg.OAUTHPreregisteredClients[0]
	if got.ClientID != "portal-client-id" {
		t.Errorf("ClientID = %q, want portal-client-id", got.ClientID)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://portal.example.test/servers-callback" {
		t.Errorf("RedirectURIs = %v, want [https://portal.example.test/servers-callback]", got.RedirectURIs)
	}
}

func TestLoadOAuthPreregisteredClients_Rejections(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		wantError string
	}{
		{
			name:      "invalid JSON",
			env:       `not json`,
			wantError: "invalid JSON",
		},
		{
			name:      "missing client_id",
			env:       `[{"redirect_uris": ["https://portal.example.test/cb"]}]`,
			wantError: "client_id is required",
		},
		{
			name:      "reserved client_id",
			env:       `[{"client_id": "mctl_self_connect", "redirect_uris": ["https://portal.example.test/cb"]}]`,
			wantError: "reserved",
		},
		{
			name: "duplicate client_id",
			env: `[
				{"client_id": "dup", "redirect_uris": ["https://portal.example.test/a"]},
				{"client_id": "dup", "redirect_uris": ["https://portal.example.test/b"]}
			]`,
			wantError: "duplicate client_id",
		},
		{
			name:      "empty redirect_uris",
			env:       `[{"client_id": "portal-client-id", "redirect_uris": []}]`,
			wantError: "redirect_uris must not be empty",
		},
		{
			name:      "relative redirect_uri",
			env:       `[{"client_id": "portal-client-id", "redirect_uris": ["/servers-callback"]}]`,
			wantError: "not an absolute URL",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OAUTH_PREREGISTERED_CLIENTS", tc.env)
			_, err := Load()
			if err == nil {
				t.Fatal("Load() succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantError)
			}
		})
	}
}
