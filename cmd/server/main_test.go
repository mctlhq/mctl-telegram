package main

import (
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

func TestSelectProviderUnknownModeIsError(t *testing.T) {
	for _, mode := range []string{"bogus", "BOGUS", "prod", "", "  "} {
		cfg := &config.Config{AuthMode: mode}
		p, err := selectProvider(cfg, nil)
		if err == nil {
			t.Errorf("AUTH_MODE=%q: expected error, got provider %T", mode, p)
		}
		if p != nil {
			t.Errorf("AUTH_MODE=%q: expected nil provider on error, got %T", mode, p)
		}
	}
}

func TestSelectProviderUnknownModeErrorMessage(t *testing.T) {
	cfg := &config.Config{AuthMode: "BOGUS"}
	_, err := selectProvider(cfg, nil)
	if err == nil {
		t.Fatal("expected error for unknown AUTH_MODE")
	}
	if !strings.Contains(err.Error(), "unknown AUTH_MODE") {
		t.Errorf("error message should mention unknown AUTH_MODE, got: %s", err.Error())
	}
	for _, want := range []string{"local-jwt", "shared-hmac", "local-dev"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message should list valid modes including %q, got: %s", want, err.Error())
		}
	}
}

func TestSelectProviderLocalDevSucceeds(t *testing.T) {
	cfg := &config.Config{AuthMode: "local-dev", OperatorLogin: "testoperator"}
	p, err := selectProvider(cfg, nil)
	if err != nil {
		t.Fatalf("local-dev should succeed, got err: %v", err)
	}
	if p == nil {
		t.Fatal("local-dev should return non-nil provider")
	}
}

func TestSelectProviderLocalJWTRequiresSecret(t *testing.T) {
	cfg := &config.Config{
		AuthMode:     "local-jwt",
		OAUTHJWTSecret: "",
		PublicBaseURL: "https://example.com",
	}
	_, err := selectProvider(cfg, nil)
	if err == nil {
		t.Fatal("local-jwt with empty secret should return error")
	}
}

func TestSelectProviderCaseInsensitive(t *testing.T) {
	for _, mode := range []string{"LOCAL-DEV", "Local-Dev", "local-dev"} {
		cfg := &config.Config{AuthMode: mode, OperatorLogin: "op"}
		p, err := selectProvider(cfg, nil)
		if err != nil {
			t.Errorf("AUTH_MODE=%q should succeed, got: %v", mode, err)
		}
		if p == nil {
			t.Errorf("AUTH_MODE=%q should return non-nil provider", mode)
		}
	}
}
