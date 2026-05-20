package db

import (
	"context"
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
