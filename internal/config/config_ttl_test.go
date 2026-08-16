package config

import (
	"strings"
	"testing"
	"time"
)

// TestLoadOAuthAccessTokenTTLCeiling covers the gap that let tg-preview mint
// admin-scoped access tokens valid for a year. The variable had no ceiling,
// so the value looked fine in review and in the rendered manifest, and the
// only visible symptom was a leaked token that stayed useful until 2027.
func TestLoadOAuthAccessTokenTTLCeiling(t *testing.T) {
	tests := []struct {
		name    string
		ttl     string
		wantErr bool
	}{
		{name: "unset uses the 1h default", ttl: "", wantErr: false},
		{name: "an hour is fine", ttl: "1h", wantErr: false},
		{name: "at the ceiling is fine", ttl: "24h", wantErr: false},
		{name: "just over the ceiling is rejected", ttl: "25h", wantErr: true},
		{name: "the 1-year value that shipped is rejected", ttl: "8760h", wantErr: true},
		{name: "zero is rejected", ttl: "0s", wantErr: true},
		{name: "negative is rejected", ttl: "-1h", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.ttl != "" {
				t.Setenv("OAUTH_ACCESS_TOKEN_TTL", tc.ttl)
			}
			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load() accepted OAUTH_ACCESS_TOKEN_TTL=%q, want an error", tc.ttl)
				}
				// The message has to name the variable: a startup failure that
				// does not is indistinguishable from any other config problem.
				if !strings.Contains(err.Error(), "OAUTH_ACCESS_TOKEN_TTL") {
					t.Errorf("error = %q, want it to name OAUTH_ACCESS_TOKEN_TTL", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.OAUTHAccessTokenTTL > maxOAUTHAccessTokenTTL || cfg.OAUTHAccessTokenTTL <= 0 {
				t.Errorf("OAUTHAccessTokenTTL = %v, want within (0, %v]", cfg.OAUTHAccessTokenTTL, maxOAUTHAccessTokenTTL)
			}
		})
	}
}

// The refresh token is the long-lived half of the pair and must stay
// unbounded by this ceiling, or capping the access token would quietly break
// the 30-day renewal window that makes short access tokens usable at all.
func TestLoadRefreshTokenTTLNotCappedByAccessCeiling(t *testing.T) {
	t.Setenv("OAUTH_REFRESH_TOKEN_TTL", "720h")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.OAUTHRefreshTokenTTL != 720*time.Hour {
		t.Errorf("OAUTHRefreshTokenTTL = %v, want 720h", cfg.OAUTHRefreshTokenTTL)
	}
}
