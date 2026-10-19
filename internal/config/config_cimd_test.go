package config

import (
	"slices"
	"strings"
	"testing"
)

// TestLoadOAuthCIMD pins the CIMD switch: off by default, and an accepting
// configuration without a usable host allowlist refuses to start.
func TestLoadOAuthCIMD(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		t.Setenv("OAUTH_CIMD_ALLOWED_HOSTS", "platform.example.test")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if cfg.OAUTHCIMDAccept || cfg.OAUTHCIMDAllowedHosts != nil {
			t.Fatalf("CIMD on without OAUTH_CIMD_ACCEPT: accept=%v hosts=%v", cfg.OAUTHCIMDAccept, cfg.OAUTHCIMDAllowedHosts)
		}
	})
	t.Run("accept with hosts", func(t *testing.T) {
		t.Setenv("OAUTH_CIMD_ACCEPT", "true")
		t.Setenv("OAUTH_CIMD_ALLOWED_HOSTS", " Platform.Example.Test , .agents.example.test")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		want := []string{"platform.example.test", ".agents.example.test"}
		if !cfg.OAUTHCIMDAccept || !slices.Equal(cfg.OAUTHCIMDAllowedHosts, want) {
			t.Fatalf("accept=%v hosts=%v, want true %v", cfg.OAUTHCIMDAccept, cfg.OAUTHCIMDAllowedHosts, want)
		}
	})
	t.Run("advertise requires accept", func(t *testing.T) {
		t.Setenv("OAUTH_CIMD_ADVERTISE", "true")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "OAUTH_CIMD_ADVERTISE=true requires OAUTH_CIMD_ACCEPT=true") {
			t.Fatalf("Load() = %v, want the advertise-without-accept refusal", err)
		}
	})
	t.Run("advertise with accept", func(t *testing.T) {
		t.Setenv("OAUTH_CIMD_ACCEPT", "true")
		t.Setenv("OAUTH_CIMD_ADVERTISE", "true")
		t.Setenv("OAUTH_CIMD_ALLOWED_HOSTS", "platform.example.test")
		cfg, err := Load()
		if err != nil || !cfg.OAUTHCIMDAdvertise {
			t.Fatalf("Load() = advertise %v, err %v; want true, nil", cfg != nil && cfg.OAUTHCIMDAdvertise, err)
		}
	})
	for name, hosts := range map[string]string{
		"accept without hosts": "",
		"empty entry":          "platform.example.test,,other.example.test",
		"IP literal":           "203.0.113.7",
		"URL instead of host":  "https://platform.example.test",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OAUTH_CIMD_ACCEPT", "true")
			t.Setenv("OAUTH_CIMD_ALLOWED_HOSTS", hosts)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "OAUTH_CIMD_ALLOWED_HOSTS") {
				t.Fatalf("Load() = %v, want an OAUTH_CIMD_ALLOWED_HOSTS refusal", err)
			}
		})
	}
}
