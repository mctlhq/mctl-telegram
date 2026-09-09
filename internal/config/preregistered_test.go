package config

import (
	"strings"
	"testing"
)

// TestLoadOAuthPreregisteredClients pins the parsing contract of
// OAUTH_PREREGISTERED_CLIENTS. The variable is fail-closed on purpose: an
// operator who sets it is relying on the client existing, so a malformed
// value must stop the process rather than boot a server that silently
// refuses the very client the deployment was changed for.
func TestLoadOAuthPreregisteredClients(t *testing.T) {
	const portalCallback = "https://portal.example.test/servers-callback"

	t.Run("unset seeds nothing", func(t *testing.T) {
		t.Setenv("OAUTH_PREREGISTERED_CLIENTS", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if len(cfg.OAUTHPreregisteredClients) != 0 {
			t.Fatalf("OAUTHPreregisteredClients = %#v, want empty", cfg.OAUTHPreregisteredClients)
		}
	})

	t.Run("valid record is parsed", func(t *testing.T) {
		t.Setenv("OAUTH_PREREGISTERED_CLIENTS",
			`[{"client_id":"portal-client","client_name":"Portal","redirect_uris":["`+portalCallback+`"]}]`)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		got := cfg.OAUTHPreregisteredClients
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if got[0].ClientID != "portal-client" {
			t.Errorf("ClientID = %q", got[0].ClientID)
		}
		if got[0].ClientName != "Portal" {
			t.Errorf("ClientName = %q", got[0].ClientName)
		}
		if len(got[0].RedirectURIs) != 1 || got[0].RedirectURIs[0] != portalCallback {
			t.Errorf("RedirectURIs = %#v", got[0].RedirectURIs)
		}
	})

	t.Run("whitespace around values is trimmed", func(t *testing.T) {
		t.Setenv("OAUTH_PREREGISTERED_CLIENTS",
			"  [{\"client_id\":\" portal-client \",\"redirect_uris\":[\" "+portalCallback+" \"]}]  ")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		got := cfg.OAUTHPreregisteredClients
		if len(got) != 1 || got[0].ClientID != "portal-client" || got[0].RedirectURIs[0] != portalCallback {
			t.Fatalf("trimming failed: %#v", got)
		}
	})

	rejects := []struct {
		name string
		env  string
		want string
	}{
		{"malformed JSON", `[{"client_id":`, "decode"},
		{"not an array", `{"client_id":"x","redirect_uris":["` + portalCallback + `"]}`, "decode"},
		{"trailing data", `[] []`, "trailing data"},
		{"unknown field", `[{"client_id":"x","secret_field":"s","redirect_uris":["` + portalCallback + `"]}]`, "decode"},
		{"empty client_id", `[{"client_id":"","redirect_uris":["` + portalCallback + `"]}]`, "client_id is required"},
		{"no redirect_uris", `[{"client_id":"x"}]`, "at least one"},
		{"empty redirect_uri", `[{"client_id":"x","redirect_uris":["  "]}]`, "is empty"},
		{"duplicate client_id", `[{"client_id":"x","redirect_uris":["` + portalCallback + `"]},` +
			`{"client_id":"x","redirect_uris":["` + portalCallback + `"]}]`, "duplicate client_id"},
	}
	for _, tc := range rejects {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			t.Setenv("OAUTH_PREREGISTERED_CLIENTS", tc.env)
			_, err := Load()
			if err == nil {
				t.Fatalf("Load() accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), "OAUTH_PREREGISTERED_CLIENTS") {
				t.Errorf("error does not name the variable: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
