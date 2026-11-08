package config

import (
	"strings"
	"testing"
)

// DIGEST_FORMAT: unset defaults to html, case and whitespace are normalized,
// and an unknown value stops startup rather than silently picking a format.
func TestLoadDigestFormat(t *testing.T) {
	for _, tc := range []struct{ name, env, want string }{
		{"unset", "", "html"},
		{"html", "html", "html"},
		{"plain", "plain", "plain"},
		{"upper case", "PLAIN", "plain"},
		{"padded", "  Html ", "html"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DIGEST_FORMAT", tc.env)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.DigestFormat != tc.want {
				t.Fatalf("DigestFormat = %q, want %q", cfg.DigestFormat, tc.want)
			}
		})
	}
	t.Run("invalid", func(t *testing.T) {
		t.Setenv("DIGEST_FORMAT", "markdown")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DIGEST_FORMAT") {
			t.Fatalf("Load() error = %v, want a DIGEST_FORMAT error", err)
		}
	})
}
