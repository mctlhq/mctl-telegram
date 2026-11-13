package config

import (
	"strings"
	"testing"
)

// MCP_K8S_SA_*: off when unset, fully specified when on, and the Telegram id
// can only be a canary-guarded account.
func TestLoadK8sSA(t *testing.T) {
	const sub = "system:serviceaccount:labs:labs-mctl-telegram-canary"
	set := func(t *testing.T, subject, aud, issuer, id, canary string) {
		t.Helper()
		t.Setenv("MCP_K8S_SA_SUBJECT", subject)
		t.Setenv("MCP_K8S_SA_AUDIENCE", aud)
		t.Setenv("MCP_K8S_SA_ISSUER", issuer)
		t.Setenv("MCP_K8S_SA_TELEGRAM_ID", id)
		t.Setenv("CANARY_TELEGRAM_IDS", canary)
	}
	t.Run("off", func(t *testing.T) {
		set(t, "", "", "", "", "")
		cfg, err := Load()
		if err != nil || cfg.K8sSASubject != "" {
			t.Fatalf("want disabled, got %q err=%v", cfg.K8sSASubject, err)
		}
	})
	t.Run("on", func(t *testing.T) {
		set(t, sub, "tg.example.test/canary", "", "7001", "7001")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if cfg.K8sSATelegramID != 7001 || cfg.K8sSAIssuer != defaultK8sSAIssuer || cfg.K8sSAAudience != "tg.example.test/canary" {
			t.Fatalf("unexpected config %+v", cfg)
		}
	})
	for name, tc := range map[string][5]string{
		"partial without subject": {"", "tg.example.test/canary", "", "7001", "7001"},
		"no audience":             {sub, "", "", "7001", "7001"},
		"api server audience":     {sub, "https://kubernetes.default.svc.cluster.local", "", "7001", "7001"},
		"bad id":                  {sub, "tg.example.test/canary", "", "abc", "7001"},
		"id not a guarded canary": {sub, "tg.example.test/canary", "", "7002", "7001"},
		"no canary list at all":   {sub, "tg.example.test/canary", "", "7001", ""},
	} {
		t.Run(name, func(t *testing.T) {
			set(t, tc[0], tc[1], tc[2], tc[3], tc[4])
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_K8S_SA") {
				t.Fatalf("want an MCP_K8S_SA error, got %v", err)
			}
		})
	}
}
