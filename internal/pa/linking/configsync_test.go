package linking

import (
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

// config cannot import this package, so it restates the app path, the
// callback prefix, the server list and the flag names: keep them equal.
func TestConfigPAToolsMatchesLinking(t *testing.T) {
	if config.PAAppPath != AppPath {
		t.Errorf("config.PAAppPath = %q, linking.AppPath = %q", config.PAAppPath, AppPath)
	}
	if want := strings.TrimSuffix(CallbackPath, "{server}"); config.PAOAuthCallbackPrefix != want {
		t.Errorf("config.PAOAuthCallbackPrefix = %q, want %q", config.PAOAuthCallbackPrefix, want)
	}
	c := &config.Config{PAEnabled: true, PublicBaseURL: "https://pa.example"}
	got, err := config.LoadPATools(c, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Servers) != len(FlagServers()) {
		t.Errorf("config reads %d servers, linking flags %d", len(got.Servers), len(FlagServers()))
	}
	for _, s := range FlagServers() {
		if _, ok := got.Servers[s]; !ok {
			t.Errorf("config does not read server %s", s)
		}
		if config.PAServerEnv(s, "ENABLED") != FlagEnv(s) {
			t.Errorf("%s: config flag %q, linking flag %q", s, config.PAServerEnv(s, "ENABLED"), FlagEnv(s))
		}
	}
}
