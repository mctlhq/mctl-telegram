package db

import (
	"context"
	"database/sql"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

// TestSaveSession_SendEnabledDefaultFalse verifies that SaveSession always
// inserts send_enabled=false, regardless of the user's prior state.
func TestSaveSession_SendEnabledDefaultFalse(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Wire a plaintext crypto so SaveSession can encrypt the blob.
	crypt, err := crypto.New(nil)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	s.Crypt = crypt

	uid, err := s.EnsureUser(ctx, "test-user", "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}

	if err := s.SaveSession(ctx, uid, []byte("session-bytes"), 12345, "Test User", "testuser"); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	enabled, err := s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("IsSendEnabled: %v", err)
	}
	if enabled {
		t.Error("SaveSession must insert send_enabled=false; got true")
	}
}

// TestSaveSession_StampsOnboardingCompletedOnce pins that SaveSession stamps
// onboarding_completed_at, and that stamping is idempotent (COALESCE
// stamp-once) across repeat calls for the same user, mirroring the
// ProvisionLocalAccount guarantee in TestProvisionLocalAccount_StampsOnboardingCompleted.
func TestSaveSession_StampsOnboardingCompletedOnce(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	crypt, err := crypto.New(nil)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	s.Crypt = crypt

	uid, err := s.EnsureUser(ctx, "onboarding-stamp-user", "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}

	if err := s.SaveSession(ctx, uid, []byte("session-bytes"), 12346, "Test User", "testuser"); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	var firstStamp sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT onboarding_completed_at FROM users WHERE id = $1`, uid,
	).Scan(&firstStamp); err != nil {
		t.Fatalf("read onboarding_completed_at: %v", err)
	}
	if !firstStamp.Valid {
		t.Fatal("onboarding_completed_at not stamped by SaveSession")
	}

	if err := s.SaveSession(ctx, uid, []byte("session-bytes-2"), 12346, "Test User", "testuser"); err != nil {
		t.Fatalf("SaveSession (second call): %v", err)
	}

	var secondStamp sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT onboarding_completed_at FROM users WHERE id = $1`, uid,
	).Scan(&secondStamp); err != nil {
		t.Fatalf("read onboarding_completed_at: %v", err)
	}
	if secondStamp.Time != firstStamp.Time {
		t.Errorf("onboarding_completed_at changed on repeat SaveSession: first=%v second=%v, want unchanged", firstStamp.Time, secondStamp.Time)
	}
}
