package workertoken

import (
	"math"
	"testing"
	"time"
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
