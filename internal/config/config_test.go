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
