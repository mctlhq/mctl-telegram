package config

import (
	"testing"
)

func TestLoadDBPoolEnvVars(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		wantMaxOpen int
		wantMaxIdle int
	}{
		{
			name:        "DB_MAX_OPEN_CONNS set to 25",
			env:         map[string]string{"DB_MAX_OPEN_CONNS": "25"},
			wantMaxOpen: 25,
			wantMaxIdle: 0,
		},
		{
			name:        "DB_MAX_IDLE_CONNS set to 5",
			env:         map[string]string{"DB_MAX_IDLE_CONNS": "5"},
			wantMaxOpen: 0,
			wantMaxIdle: 5,
		},
		{
			name:        "both unset returns zero sentinel",
			env:         map[string]string{},
			wantMaxOpen: 0,
			wantMaxIdle: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.DBMaxOpenConns != tc.wantMaxOpen {
				t.Errorf("DBMaxOpenConns = %d, want %d", cfg.DBMaxOpenConns, tc.wantMaxOpen)
			}
			if cfg.DBMaxIdleConns != tc.wantMaxIdle {
				t.Errorf("DBMaxIdleConns = %d, want %d", cfg.DBMaxIdleConns, tc.wantMaxIdle)
			}
		})
	}
}

func TestLoadAPIRateLimitEnvVars(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		wantRate  float64
		wantBurst int
	}{
		{
			name:      "both unset disables the limiter",
			env:       map[string]string{},
			wantRate:  0,
			wantBurst: 0,
		},
		{
			name:      "rate and burst set",
			env:       map[string]string{"TG_API_RATE_PER_SEC": "25", "TG_API_RATE_BURST": "50"},
			wantRate:  25,
			wantBurst: 50,
		},
		{
			name:      "fractional rate parses",
			env:       map[string]string{"TG_API_RATE_PER_SEC": "0.5"},
			wantRate:  0.5,
			wantBurst: 0,
		},
		{
			name:      "garbage rate falls back to disabled",
			env:       map[string]string{"TG_API_RATE_PER_SEC": "notanumber"},
			wantRate:  0,
			wantBurst: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.TGAPIRatePerSec != tc.wantRate {
				t.Errorf("TGAPIRatePerSec = %v, want %v", cfg.TGAPIRatePerSec, tc.wantRate)
			}
			if cfg.TGAPIRateBurst != tc.wantBurst {
				t.Errorf("TGAPIRateBurst = %d, want %d", cfg.TGAPIRateBurst, tc.wantBurst)
			}
		})
	}
}
