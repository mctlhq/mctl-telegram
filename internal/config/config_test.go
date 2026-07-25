package config

import (
	"strings"
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

// TestLoadMediaUploadMaxBytes mirrors the download cap's coverage: default
// value and an env override, plus independence from MEDIA_DOWNLOAD_MAX_BYTES
// (the two caps must not accidentally share one knob).
func TestLoadMediaUploadMaxBytes(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want int64
	}{
		{
			name: "default is 20 MiB",
			env:  map[string]string{},
			want: 20971520,
		},
		{
			name: "env override",
			env:  map[string]string{"MEDIA_UPLOAD_MAX_BYTES": "1048576"},
			want: 1048576,
		},
		{
			name: "garbage value falls back to default",
			env:  map[string]string{"MEDIA_UPLOAD_MAX_BYTES": "notanumber"},
			want: 20971520,
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
			if cfg.MediaUploadMaxBytes != tc.want {
				t.Errorf("MediaUploadMaxBytes = %d, want %d", cfg.MediaUploadMaxBytes, tc.want)
			}
		})
	}
}

// TestLoadMediaUploadMaxBytes_IndependentFromDownloadCap guards against the
// two caps being accidentally collapsed into one env var — see design.md's
// "Alternatives" section for why they are deliberately independent.
func TestLoadMediaUploadMaxBytes_IndependentFromDownloadCap(t *testing.T) {
	t.Setenv("MEDIA_DOWNLOAD_MAX_BYTES", "5000000")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.MediaDownloadMaxBytes != 5000000 {
		t.Errorf("MediaDownloadMaxBytes = %d, want 5000000", cfg.MediaDownloadMaxBytes)
	}
	if cfg.MediaUploadMaxBytes != 20971520 {
		t.Errorf("MediaUploadMaxBytes = %d, want unaffected default 20971520, got %d", cfg.MediaUploadMaxBytes, cfg.MediaUploadMaxBytes)
	}
}

func TestLoadToolFilter(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    string
		wantErr bool
	}{
		{
			name: "default is all",
			env:  map[string]string{},
			want: "all",
		},
		{
			name: "read-only accepted",
			env:  map[string]string{"MCP_TOOL_FILTER": "read-only"},
			want: "read-only",
		},
		{
			name: "all explicit",
			env:  map[string]string{"MCP_TOOL_FILTER": "all"},
			want: "all",
		},
		{
			name:    "invalid value rejected",
			env:     map[string]string{"MCP_TOOL_FILTER": "write-only"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "MCP_TOOL_FILTER") {
					t.Errorf("error should mention MCP_TOOL_FILTER, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.ToolFilter != tc.want {
				t.Errorf("ToolFilter = %q, want %q", cfg.ToolFilter, tc.want)
			}
		})
	}
}

// TestLoadAgentProfileOwnerRequired covers a Codex finding on #307:
// AGENT_PROFILE_OWNER_TG_ID is documented as required whenever
// AGENT_PROFILE_PATH is set, but a missing or malformed value silently
// defaulted to 0 with no validation, so the profile loaded successfully
// while GET /recruiters/{peer} returned 403 for every account (owner id
// zero is explicitly forbidden there) — a seemingly enabled endpoint left
// permanently unusable with no loud failure anywhere.
func TestLoadAgentProfileOwnerRequired(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{
			name:    "profile path set without owner id fails",
			env:     map[string]string{"AGENT_PROFILE_PATH": "/tmp/profile.yaml"},
			wantErr: true,
		},
		{
			name:    "profile path set with zero owner id fails",
			env:     map[string]string{"AGENT_PROFILE_PATH": "/tmp/profile.yaml", "AGENT_PROFILE_OWNER_TG_ID": "0"},
			wantErr: true,
		},
		{
			name:    "profile path set with negative owner id fails",
			env:     map[string]string{"AGENT_PROFILE_PATH": "/tmp/profile.yaml", "AGENT_PROFILE_OWNER_TG_ID": "-5"},
			wantErr: true,
		},
		{
			name:    "profile path set with positive owner id succeeds",
			env:     map[string]string{"AGENT_PROFILE_PATH": "/tmp/profile.yaml", "AGENT_PROFILE_OWNER_TG_ID": "12345"},
			wantErr: false,
		},
		{
			name:    "owner id set without profile path is ignored",
			env:     map[string]string{"AGENT_PROFILE_OWNER_TG_ID": "12345"},
			wantErr: false,
		},
		{
			name:    "neither set succeeds",
			env:     map[string]string{},
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "AGENT_PROFILE_OWNER_TG_ID") {
					t.Errorf("error should mention AGENT_PROFILE_OWNER_TG_ID, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
		})
	}
}
