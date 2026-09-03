package main

import (
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

func TestSelectProviderUnknownModeIsError(t *testing.T) {
	for _, mode := range []string{"bogus", "BOGUS", "prod", "", "  "} {
		cfg := &config.Config{AuthMode: mode}
		p, err := selectProvider(cfg, nil, nil)
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
	_, err := selectProvider(cfg, nil, nil)
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
	p, err := selectProvider(cfg, nil, nil)
	if err != nil {
		t.Fatalf("local-dev should succeed, got err: %v", err)
	}
	if p == nil {
		t.Fatal("local-dev should return non-nil provider")
	}
}

func TestSelectProviderLocalJWTRequiresSecret(t *testing.T) {
	cfg := &config.Config{
		AuthMode:       "local-jwt",
		OAUTHJWTSecret: "",
		PublicBaseURL:  "https://example.com",
	}
	_, err := selectProvider(cfg, nil, nil)
	if err == nil {
		t.Fatal("local-jwt with empty secret should return error")
	}
}

func TestSelectProviderCaseInsensitive(t *testing.T) {
	for _, mode := range []string{"LOCAL-DEV", "Local-Dev", "local-dev"} {
		cfg := &config.Config{AuthMode: mode, OperatorLogin: "op"}
		p, err := selectProvider(cfg, nil, nil)
		if err != nil {
			t.Errorf("AUTH_MODE=%q should succeed, got: %v", mode, err)
		}
		if p == nil {
			t.Errorf("AUTH_MODE=%q should return non-nil provider", mode)
		}
	}
}

// Worker tokens may only be minted where the verifying provider consults the
// revocation denylist — i.e. under local-jwt. Under shared-hmac the minted
// token verifies against sharedhmac.Provider, which has no revocation
// concept, so minting there would hand out a credential revoke_worker_token
// cannot actually take back (issue #472).
func TestWorkerTokenMintableOnlyUnderLocalJWT(t *testing.T) {
	mintable := []string{"local-jwt", "LOCAL-JWT", "Local-JWT"}
	for _, mode := range mintable {
		if !workerTokenMintable(&config.Config{AuthMode: mode}) {
			t.Errorf("AUTH_MODE=%q should allow worker-token minting", mode)
		}
	}
	notMintable := []string{"shared-hmac", "shared-hmac-legacy", "SHARED-HMAC", "local-dev", ""}
	for _, mode := range notMintable {
		if workerTokenMintable(&config.Config{AuthMode: mode}) {
			t.Errorf("AUTH_MODE=%q must not allow worker-token minting: revocation is unenforceable there", mode)
		}
	}
}
