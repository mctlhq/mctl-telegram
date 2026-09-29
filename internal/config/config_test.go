package config

import (
	"reflect"
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

func TestLoadOAuthAllowImplicitClientDefaultsOff(t *testing.T) {
	t.Setenv("OAUTH_ALLOW_IMPLICIT_CLIENT", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.OAUTHAllowImplicitClient {
		t.Fatal("OAUTH_ALLOW_IMPLICIT_CLIENT must default to false")
	}
	if cfg.AllowSharedHMACLegacy {
		t.Fatal("AUTH_ALLOW_SHARED_HMAC_LEGACY must default to false")
	}
	if cfg.OAUTHRegisterRatePerMin != 10 {
		t.Fatalf("OAUTH_REGISTER_RATE_PER_MIN default = %d, want 10", cfg.OAUTHRegisterRatePerMin)
	}

	t.Setenv("OAUTH_ALLOW_IMPLICIT_CLIENT", "true")
	t.Setenv("AUTH_ALLOW_SHARED_HMAC_LEGACY", "true")
	t.Setenv("OAUTH_REGISTER_RATE_PER_MIN", "3")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.OAUTHAllowImplicitClient {
		t.Fatal("OAUTH_ALLOW_IMPLICIT_CLIENT=true was ignored")
	}
	if !cfg.AllowSharedHMACLegacy {
		t.Fatal("AUTH_ALLOW_SHARED_HMAC_LEGACY=true was ignored")
	}
	if cfg.OAUTHRegisterRatePerMin != 3 {
		t.Fatalf("OAUTH_REGISTER_RATE_PER_MIN = %d, want 3", cfg.OAUTHRegisterRatePerMin)
	}
}

func TestLoadOAuthAllowedImplicitHosts(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want []string
	}{
		{
			name: "unset leaves the list empty so internal/oauth applies its default",
			env:  "",
			want: nil,
		},
		{
			name: "comma-separated hosts are split",
			env:  "claude.ai,chatgpt.com,antigravity.google",
			want: []string{"claude.ai", "chatgpt.com", "antigravity.google"},
		},
		{
			name: "surrounding whitespace is trimmed",
			env:  " claude.ai , antigravity.google ",
			want: []string{"claude.ai", "antigravity.google"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OAUTH_ALLOWED_IMPLICIT_HOSTS", tc.env)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if len(cfg.OAUTHAllowedImplicitHosts) != len(tc.want) {
				t.Fatalf("OAUTHAllowedImplicitHosts = %#v, want %#v", cfg.OAUTHAllowedImplicitHosts, tc.want)
			}
			for i, want := range tc.want {
				if cfg.OAUTHAllowedImplicitHosts[i] != want {
					t.Errorf("host[%d] = %q, want %q", i, cfg.OAUTHAllowedImplicitHosts[i], want)
				}
			}
		})
	}
}

func TestLoadOAuthDCRRedirectURIs(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want []string
	}{
		{name: "unset leaves DCR registration unchanged", env: "", want: nil},
		{
			name: "comma-separated URIs are split and trimmed, never otherwise altered",
			env:  " https://portal.example.test/servers-callback , https://dash.example.test/a/oauth-callback/tg ",
			want: []string{"https://portal.example.test/servers-callback", "https://dash.example.test/a/oauth-callback/tg"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OAUTH_DCR_REDIRECT_URIS", tc.env)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if !reflect.DeepEqual(cfg.OAUTHDCRRedirectURIs, tc.want) {
				t.Fatalf("OAUTHDCRRedirectURIs = %#v, want %#v", cfg.OAUTHDCRRedirectURIs, tc.want)
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

// TestLoadBulkMediaByteCap (issue #705, T9) covers BULK_MEDIA_BYTE_CAP's
// default and an env override, mirroring TestLoadMediaUploadMaxBytes.
func TestLoadBulkMediaByteCap(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want int64
	}{
		{name: "default is 8 MiB", env: map[string]string{}, want: 8388608},
		{name: "env override", env: map[string]string{"BULK_MEDIA_BYTE_CAP": "1048576"}, want: 1048576},
		{name: "garbage value falls back to default", env: map[string]string{"BULK_MEDIA_BYTE_CAP": "notanumber"}, want: 8388608},
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
			if cfg.BulkMediaByteCap != tc.want {
				t.Errorf("BulkMediaByteCap = %d, want %d", cfg.BulkMediaByteCap, tc.want)
			}
		})
	}
}

// TestLoadMediaTextInlineCapBytes (issue #705, T9) covers
// MEDIA_TEXT_INLINE_CAP_BYTES's default and env override, including the 0
// ("always inline") special case.
func TestLoadMediaTextInlineCapBytes(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want int64
	}{
		{name: "default is 1 MiB", env: map[string]string{}, want: 1048576},
		{name: "env override", env: map[string]string{"MEDIA_TEXT_INLINE_CAP_BYTES": "2097152"}, want: 2097152},
		{name: "zero means always inline", env: map[string]string{"MEDIA_TEXT_INLINE_CAP_BYTES": "0"}, want: 0},
		{name: "negative is treated as zero", env: map[string]string{"MEDIA_TEXT_INLINE_CAP_BYTES": "-1"}, want: 0},
		{name: "garbage value falls back to default", env: map[string]string{"MEDIA_TEXT_INLINE_CAP_BYTES": "notanumber"}, want: 1048576},
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
			if cfg.MediaTextInlineCapBytes != tc.want {
				t.Errorf("MediaTextInlineCapBytes = %d, want %d", cfg.MediaTextInlineCapBytes, tc.want)
			}
		})
	}
}

// TestLoadMediaMaxConcurrent (issue #705, T9) covers MEDIA_MAX_CONCURRENT's
// default and env override, including the 0 ("unlimited") special case.
func TestLoadMediaMaxConcurrent(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want int
	}{
		{name: "default is 2", env: map[string]string{}, want: 2},
		{name: "env override", env: map[string]string{"MEDIA_MAX_CONCURRENT": "5"}, want: 5},
		{name: "zero means unlimited", env: map[string]string{"MEDIA_MAX_CONCURRENT": "0"}, want: 0},
		{name: "garbage value falls back to default", env: map[string]string{"MEDIA_MAX_CONCURRENT": "notanumber"}, want: 2},
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
			if cfg.MediaMaxConcurrent != tc.want {
				t.Errorf("MediaMaxConcurrent = %d, want %d", cfg.MediaMaxConcurrent, tc.want)
			}
		})
	}
}

// TestLoadMediaGateConfig_IndependentFromDownloadCap guards against issue
// #705's three new knobs being accidentally collapsed with
// MEDIA_DOWNLOAD_MAX_BYTES, mirroring
// TestLoadMediaUploadMaxBytes_IndependentFromDownloadCap.
func TestLoadMediaGateConfig_IndependentFromDownloadCap(t *testing.T) {
	t.Setenv("MEDIA_DOWNLOAD_MAX_BYTES", "5000000")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.BulkMediaByteCap != 8388608 {
		t.Errorf("BulkMediaByteCap = %d, want unaffected default 8388608", cfg.BulkMediaByteCap)
	}
	if cfg.MediaTextInlineCapBytes != 1048576 {
		t.Errorf("MediaTextInlineCapBytes = %d, want unaffected default 1048576", cfg.MediaTextInlineCapBytes)
	}
	if cfg.MediaMaxConcurrent != 2 {
		t.Errorf("MediaMaxConcurrent = %d, want unaffected default 2", cfg.MediaMaxConcurrent)
	}
}

// TestLoadAppsEnabled is T13: MCP_APPS_ENABLED defaults to false and parses
// "true", mirroring AGENT_ENABLED's envBool wiring.
func TestLoadAppsEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{name: "default is false", env: map[string]string{}, want: false},
		{name: "true enables it", env: map[string]string{"MCP_APPS_ENABLED": "true"}, want: true},
		{name: "false stays off", env: map[string]string{"MCP_APPS_ENABLED": "false"}, want: false},
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
			if cfg.AppsEnabled != tc.want {
				t.Errorf("AppsEnabled = %v, want %v", cfg.AppsEnabled, tc.want)
			}
		})
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

// TestLoadNonPositiveBulkMediaByteCapFallsBack pins that a non-positive
// BULK_MEDIA_BYTE_CAP (which would make fetch_media=true silently skip every
// item, since it has no "0 = unlimited" meaning) falls back to the 8 MiB
// default rather than being used as-is.
func TestLoadNonPositiveBulkMediaByteCapFallsBack(t *testing.T) {
	for _, val := range []string{"0", "-1"} {
		t.Run(val, func(t *testing.T) {
			t.Setenv("BULK_MEDIA_BYTE_CAP", val)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.BulkMediaByteCap != 8388608 {
				t.Errorf("BulkMediaByteCap = %d, want the 8388608 default for %q", cfg.BulkMediaByteCap, val)
			}
		})
	}
}
