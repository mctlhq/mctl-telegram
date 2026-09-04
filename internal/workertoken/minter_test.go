package workertoken

import (
	"math"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

// A ttl_hours large enough to overflow int64 nanoseconds must still land on the
// ceiling. The interesting case is not "the number is silly" but that the
// overflowed product is *negative*, so a naive "> maxWorkerTokenTTL" comparison
// accepts it and mints a credential that expired before it was handed over.
func TestClampTTL(t *testing.T) {
	maxHours := int(maxWorkerTokenTTL / time.Hour)
	cases := []struct {
		name  string
		hours int
		want  time.Duration
	}{
		{"zero means default", 0, defaultWorkerTokenTTL},
		{"negative means default", -5, defaultWorkerTokenTTL},
		{"below the ceiling is honoured", 48, 48 * time.Hour},
		{"exactly the ceiling", maxHours, maxWorkerTokenTTL},
		{"above the ceiling is clamped", maxHours + 1, maxWorkerTokenTTL},
		{"overflowing the duration is clamped", math.MaxInt32, maxWorkerTokenTTL},
		{"maximum int is clamped", math.MaxInt, maxWorkerTokenTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampTTL(tc.hours); got != tc.want {
				t.Fatalf("clampTTL(%d) = %v, want %v", tc.hours, got, tc.want)
			}
		})
	}
}

// The clamp has to hold through the real minting path, not just in isolation:
// a token whose expiry is in the past would authenticate nowhere.
func TestMint_OverflowingTTLStillExpiresInTheFuture(t *testing.T) {
	m, err := NewMinter([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	mt, err := m.Mint(MintRequest{TelegramID: 42, TTLHours: math.MaxInt32})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !mt.ExpiresAt.After(time.Now()) {
		t.Fatalf("expires_at %v is not in the future", mt.ExpiresAt)
	}
	if mt.TTL != maxWorkerTokenTTL {
		t.Fatalf("TTL = %v, want ceiling %v", mt.TTL, maxWorkerTokenTTL)
	}
}

// TestClampDeviceTTL mirrors TestClampTTL against the device-credential
// ceiling, which task 6's DoD requires to differ from Mint's.
func TestClampDeviceTTL(t *testing.T) {
	if defaultDeviceCredentialTTL == defaultWorkerTokenTTL || maxDeviceCredentialTTL == maxWorkerTokenTTL {
		t.Fatal("device credential TTL constants must differ from the worker-token ones")
	}
	maxHours := int(maxDeviceCredentialTTL / time.Hour)
	cases := []struct {
		name  string
		hours int
		want  time.Duration
	}{
		{"zero means default", 0, defaultDeviceCredentialTTL},
		{"negative means default", -1, defaultDeviceCredentialTTL},
		{"below the ceiling is honoured", 2, 2 * time.Hour},
		{"exactly the ceiling", maxHours, maxDeviceCredentialTTL},
		{"above the ceiling is clamped", maxHours + 1, maxDeviceCredentialTTL},
		{"overflowing is clamped", math.MaxInt32, maxDeviceCredentialTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampDeviceTTL(tc.hours); got != tc.want {
				t.Fatalf("clampDeviceTTL(%d) = %v, want %v", tc.hours, got, tc.want)
			}
		})
	}
}

// TestMintForDevice_SetsDeviceIDAndDistinctAudience covers task 6's DoD: the
// TTL ceiling differs from Mint's, DeviceID is set on the resulting claims,
// and the audience marker is workerDeviceAudience (task 9b), distinct from
// both workerAudience and workerBridgeAudience, while still carrying the
// configured mcpAudience alongside it.
func TestMintForDevice_SetsDeviceIDAndDistinctAudience(t *testing.T) {
	m, err := NewMinter([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "https://tg.test/mcp")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	issuedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	mt, err := m.MintForDevice(DeviceMintRequest{
		TelegramID:       42,
		DeviceID:         "dev_abc123",
		Scopes:           allowedReadOnlyScopes,
		Jti:              "jti-fixed",
		OriginalIssuedAt: issuedAt,
	})
	if err != nil {
		t.Fatalf("MintForDevice: %v", err)
	}
	if mt.TTL != defaultDeviceCredentialTTL {
		t.Errorf("TTL = %v, want %v (device default, not the worker-token default)", mt.TTL, defaultDeviceCredentialTTL)
	}
	claims, err := localjwt.Verify(mt.Token, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.DeviceID != "dev_abc123" {
		t.Errorf("DeviceID = %q, want %q", claims.DeviceID, "dev_abc123")
	}
	if !hasAudience(claims.Audience, workerDeviceAudience) {
		t.Errorf("audience %v missing workerDeviceAudience %q", claims.Audience, workerDeviceAudience)
	}
	if hasAudience(claims.Audience, workerAudience) || hasAudience(claims.Audience, workerBridgeAudience) {
		t.Errorf("device credential must not carry workerAudience/workerBridgeAudience: %v", claims.Audience)
	}
	if !hasAudience(claims.Audience, "https://tg.test/mcp") {
		t.Errorf("audience %v missing configured mcpAudience", claims.Audience)
	}
}

// A scope outside allowedLocalBridgeScopes is rejected exactly like Mint's
// existing check.
func TestMintForDevice_RejectsScopeOutsideAllowlist(t *testing.T) {
	m, err := NewMinter([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	_, err = m.MintForDevice(DeviceMintRequest{
		TelegramID:       42,
		DeviceID:         "dev_abc123",
		Scopes:           []string{"admin:users"},
		Jti:              "jti-1",
		OriginalIssuedAt: time.Now(),
	})
	if err == nil {
		t.Fatal("expected rejection for a scope outside allowedLocalBridgeScopes")
	}
}

// T5a: a device credential never carries account:manage, regardless of what
// scopes are requested -- account:manage is not in allowedLocalBridgeScopes
// at all, so any attempt to include it is rejected outright by the same
// allowlist check as any other disallowed scope.
func TestMintForDevice_RejectsAccountManageScope(t *testing.T) {
	m, err := NewMinter([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	_, err = m.MintForDevice(DeviceMintRequest{
		TelegramID:       42,
		DeviceID:         "dev_abc123",
		Scopes:           []string{"telegram:messages:read", "account:manage"},
		Jti:              "jti-1",
		OriginalIssuedAt: time.Now(),
	})
	if err == nil {
		t.Fatal("expected rejection: account:manage must never be mintable into a device credential")
	}
}

// Two calls given the same Jti/OriginalIssuedAt produce credentials carrying
// them unchanged -- the property refresh depends on (jti carried forward,
// never regenerated).
func TestMintForDevice_SameJtiAndOriginalIssuedAtCarriedForward(t *testing.T) {
	m, err := NewMinter([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	issuedAt := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	req := DeviceMintRequest{
		TelegramID:       7,
		DeviceID:         "dev_xyz",
		Scopes:           allowedReadOnlyScopes,
		Jti:              "jti-stable",
		OriginalIssuedAt: issuedAt,
	}
	first, err := m.MintForDevice(req)
	if err != nil {
		t.Fatalf("first MintForDevice: %v", err)
	}
	second, err := m.MintForDevice(req)
	if err != nil {
		t.Fatalf("second MintForDevice: %v", err)
	}
	for name, mt := range map[string]*Minted{"first": first, "second": second} {
		claims, err := localjwt.Verify(mt.Token, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
		if err != nil {
			t.Fatalf("verify %s: %v", name, err)
		}
		if claims.Jti != "jti-stable" {
			t.Errorf("%s Jti = %q, want %q", name, claims.Jti, "jti-stable")
		}
		if claims.OriginalIssuedAt != issuedAt.Unix() {
			t.Errorf("%s OriginalIssuedAt = %d, want %d", name, claims.OriginalIssuedAt, issuedAt.Unix())
		}
	}
}

// T5b: a device credential presented to the renew handler is refused, not
// renewed with whatever scopes it happened to carry -- proven end to end
// through NewRenewHandler, not merely by inspecting the audience marker in
// isolation, since renewhandler_test.go covers this from that entry point.
// This test asserts the minter-side half: the marker MintForDevice stamps is
// exactly workerDeviceAudience, which is what makes that refusal possible.
func TestMintForDevice_AudienceMarkerMatchesRenewHandlerRejection(t *testing.T) {
	m, err := NewMinter([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	mt, err := m.MintForDevice(DeviceMintRequest{
		TelegramID:       42,
		DeviceID:         "dev_abc123",
		Scopes:           []string{"telegram:messages:send", "telegram:messages:pin"},
		Jti:              "jti-1",
		OriginalIssuedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("MintForDevice: %v", err)
	}
	claims, err := localjwt.Verify(mt.Token, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// hasAudience(..., workerAudience) and hasAudience(..., workerBridgeAudience)
	// are exactly the two cases NewRenewHandler's switch matches; neither
	// matches here, so the handler's default case ("token is not a worker
	// token") is what a device credential reaches.
	if hasAudience(claims.Audience, workerAudience) || hasAudience(claims.Audience, workerBridgeAudience) {
		t.Fatal("device credential must not satisfy either renewable audience marker")
	}
}
