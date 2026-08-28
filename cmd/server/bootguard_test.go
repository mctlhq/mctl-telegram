package main

import (
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

func TestCheckBootGuardLoopbackLocalDevOK(t *testing.T) {
	cfg := &config.Config{
		Addr:         "127.0.0.1:8080",
		AuthMode:     "local-dev",
		AuthRequired: false,
	}
	if err := checkBootGuard(cfg); err != nil {
		t.Fatalf("loopback local-dev should be allowed, got err: %v", err)
	}
}

func TestCheckBootGuardPublicBindLocalDevFatal(t *testing.T) {
	cfg := &config.Config{
		Addr:         "0.0.0.0:8080",
		AuthMode:     "local-dev",
		AuthRequired: false,
	}
	err := checkBootGuard(cfg)
	if err == nil {
		t.Fatal("public bind with local-dev auth should be fatal")
	}
	if !strings.Contains(err.Error(), "AUTH_MODE") {
		t.Errorf("error message should mention AUTH_MODE, got: %s", err.Error())
	}
}

func TestCheckBootGuardEmptyHostTreatedAsPublicFatal(t *testing.T) {
	cfg := &config.Config{
		Addr:         ":8080",
		AuthMode:     "local-dev",
		AuthRequired: false,
	}
	if err := checkBootGuard(cfg); err == nil {
		t.Fatal("empty-host ADDR (bind-all) with local-dev auth should be fatal")
	}
}

func TestCheckBootGuardProductionNoKeyFatal(t *testing.T) {
	cfg := &config.Config{
		Environment:  "production",
		Addr:         "127.0.0.1:8080",
		AuthMode:     "local-jwt",
		AuthRequired: true,
	}
	err := checkBootGuard(cfg)
	if err == nil {
		t.Fatal("production without ENCRYPTION_KEY should be fatal regardless of ADDR")
	}
	if !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Errorf("error message should mention ENCRYPTION_KEY, got: %s", err.Error())
	}
}

func TestCheckBootGuardProductionCaseInsensitive(t *testing.T) {
	for _, env := range []string{"production", "Production", "PRODUCTION"} {
		cfg := &config.Config{
			Environment:  env,
			Addr:         "127.0.0.1:8080",
			AuthMode:     "local-jwt",
			AuthRequired: true,
		}
		if err := checkBootGuard(cfg); err == nil {
			t.Errorf("ENV=%q without ENCRYPTION_KEY should be fatal", env)
		}
	}
}

func TestCheckBootGuardBothProblemsReportedTogether(t *testing.T) {
	cfg := &config.Config{
		Addr:         "0.0.0.0:8080",
		AuthMode:     "local-dev",
		AuthRequired: false,
	}
	err := checkBootGuard(cfg)
	if err == nil {
		t.Fatal("expected a fatal error")
	}
	if !strings.Contains(err.Error(), "AUTH_MODE") || !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Errorf("error message should report both problems together, got: %s", err.Error())
	}
}

func TestCheckBootGuardCorrectlyConfiguredPublicBindOK(t *testing.T) {
	cfg := &config.Config{
		Addr:          "0.0.0.0:8080",
		AuthMode:      "local-jwt",
		AuthRequired:  true,
		EncryptionKey: make([]byte, 32),
	}
	if err := checkBootGuard(cfg); err != nil {
		t.Fatalf("correctly configured deployment on a public bind must not be blocked, got err: %v", err)
	}
}

func TestCheckBootGuardIPv6AndHostnameLoopback(t *testing.T) {
	cases := []struct {
		addr     string
		loopback bool
	}{
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"internal.example:8080", false},
	}
	for _, tc := range cases {
		got := isLoopbackAddr(tc.addr)
		if got != tc.loopback {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", tc.addr, got, tc.loopback)
		}
	}
}
