package config

import (
	"strings"
	"testing"
)

const (
	managedTestSigningKey = "managed-runtime-dedicated-key-not-real-0123456789"
	managedTestSharedKey  = "api-mctl-ai-shared-secret-not-real-0123456789"
)

// TestLoadManagedRuntime_DedicatedKey: MANAGED_RUNTIME_ENABLED=true is
// refused unless AUTH_MODE=local-jwt with a dedicated OAUTH_JWT_SIGNING_KEY
// (#1351). The managed runtime's agent-pool and agent-job tokens are signed
// with the resolved key, so a key api.mctl.ai also holds would let it mint
// a pool token and claim managed jobs. With the runtime off every one of
// these configurations still loads, as before.
// Mutation: drop the validateManagedRuntimeKey call from Load — the three
// refusal cases load; make it check OAUTHJWTSecret only — the legacy-only
// and shared-hmac cases load.
func TestLoadManagedRuntime_DedicatedKey(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		wantRefuse bool
	}{
		{"shared-hmac with both keys", map[string]string{
			"AUTH_MODE": "shared-hmac", "OAUTH_JWT_SECRET": managedTestSharedKey, "OAUTH_JWT_SIGNING_KEY": managedTestSigningKey,
		}, true},
		{"local-jwt with only the legacy OAUTH_JWT_SECRET", map[string]string{
			"AUTH_MODE": "local-jwt", "OAUTH_JWT_SECRET": managedTestSharedKey,
		}, true},
		{"local-dev without any key", map[string]string{"AUTH_MODE": "local-dev"}, true},
		{"local-jwt with the dedicated key", map[string]string{
			"AUTH_MODE": "local-jwt", "OAUTH_JWT_SIGNING_KEY": managedTestSigningKey,
		}, false},
		{"local-jwt with the dedicated key and the legacy secret", map[string]string{
			"AUTH_MODE": "local-jwt", "OAUTH_JWT_SIGNING_KEY": managedTestSigningKey, "OAUTH_JWT_SECRET": managedTestSharedKey,
		}, false},
	}
	for _, tc := range cases {
		for _, enabled := range []string{"true", "false"} {
			t.Run(tc.name+"/managed="+enabled, func(t *testing.T) {
				t.Setenv("OAUTH_JWT_SECRET", "")
				t.Setenv("OAUTH_JWT_SIGNING_KEY", "")
				for k, v := range tc.env {
					t.Setenv(k, v)
				}
				t.Setenv("MANAGED_RUNTIME_ENABLED", enabled)
				cfg, err := Load()
				if enabled == "false" || !tc.wantRefuse {
					if err != nil {
						t.Fatalf("Load() = %v, want success", err)
					}
					if enabled == "true" && (cfg.OAUTHJWTSecret != managedTestSigningKey || !cfg.OAUTHJWTSecretDedicated) {
						t.Fatalf("managed runtime on: signing key is not the dedicated one (dedicated=%v)", cfg.OAUTHJWTSecretDedicated)
					}
					return
				}
				if err == nil {
					t.Fatal("Load() accepted MANAGED_RUNTIME_ENABLED=true without a dedicated signing key")
				}
				msg := err.Error()
				if !strings.Contains(msg, "MANAGED_RUNTIME_ENABLED") || !strings.Contains(msg, "OAUTH_JWT_SIGNING_KEY") {
					t.Fatalf("error does not name the variables: %v", err)
				}
				if strings.Contains(msg, managedTestSharedKey) || strings.Contains(msg, managedTestSigningKey) {
					t.Fatal("error leaks a key value")
				}
			})
		}
	}
}
