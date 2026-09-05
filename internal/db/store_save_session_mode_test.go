package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

// newSaveSessionTestStore wires a plaintext crypto instance into a fresh
// test store so SaveSession can seal the session blob.
func newSaveSessionTestStore(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	crypt, err := crypto.New(nil)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	s.Crypt = crypt
	return s
}

// TestSaveSession_RefusesActiveLocalAccount is the core regression test for
// issue-492: a hosted login must not silently revoke and replace an active
// mode='local' account. SaveSession must refuse with ErrAccountModeConflict
// and leave the local row's session_encrypted/revoked_at untouched.
func TestSaveSession_RefusesActiveLocalAccount(t *testing.T) {
	ctx := context.Background()
	s := newSaveSessionTestStore(t)

	uid, err := s.EnsureUser(ctx, "local-active", "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if err := s.ProvisionLocalAccount(ctx, uid, 700000301, "Local User", "localuser"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	err = s.SaveSession(ctx, uid, []byte("session-bytes"), 700000301, "Hosted Name", "hosteduser")
	if !errors.Is(err, ErrAccountModeConflict) {
		t.Fatalf("SaveSession error = %v, want ErrAccountModeConflict", err)
	}

	var sessionEncrypted []byte
	var revokedAt sql.NullTime
	if scanErr := s.DB.QueryRowContext(ctx,
		`SELECT session_encrypted, revoked_at FROM telegram_accounts WHERE user_id = $1`,
		uid,
	).Scan(&sessionEncrypted, &revokedAt); scanErr != nil {
		t.Fatalf("read local row: %v", scanErr)
	}
	if sessionEncrypted != nil {
		t.Errorf("session_encrypted = %v, want NULL after a refused SaveSession", sessionEncrypted)
	}
	if revokedAt.Valid {
		t.Errorf("revoked_at = %v, want NULL after a refused SaveSession", revokedAt.Time)
	}
}

// TestSaveSession_AllowsHostedAndNoActiveRow is the regression guard proving
// the new guard is scoped to mode='local' only: an active hosted row, and no
// active row at all, must both continue to let SaveSession succeed exactly
// as before.
func TestSaveSession_AllowsHostedAndNoActiveRow(t *testing.T) {
	ctx := context.Background()

	t.Run("active hosted row", func(t *testing.T) {
		s := newSaveSessionTestStore(t)
		uid := seedModedAccount(t, s, "hosted-active", 700000302, ModeHosted, false, false)
		if err := s.SaveSession(ctx, uid, []byte("session-bytes"), 700000302, "Hosted Name", "hosteduser"); err != nil {
			t.Fatalf("SaveSession: %v", err)
		}
		mode, err := s.GetAccountMode(ctx, uid)
		if err != nil {
			t.Fatalf("GetAccountMode: %v", err)
		}
		if mode != ModeHosted {
			t.Errorf("mode after SaveSession = %q, want %q", mode, ModeHosted)
		}
	})

	t.Run("no active row", func(t *testing.T) {
		s := newSaveSessionTestStore(t)
		uid, err := s.EnsureUser(ctx, "no-active-row", "", "test")
		if err != nil {
			t.Fatalf("EnsureUser: %v", err)
		}
		if err := s.SaveSession(ctx, uid, []byte("session-bytes"), 700000303, "Hosted Name", "hosteduser"); err != nil {
			t.Fatalf("SaveSession: %v", err)
		}
	})
}

// TestSaveSession_RevokedLocalRowDoesNotBlock guards the race the issue calls
// out: a mode='local' row that is already revoked must not wedge the user
// out of hosted login. Only an ACTIVE local row blocks SaveSession.
func TestSaveSession_RevokedLocalRowDoesNotBlock(t *testing.T) {
	ctx := context.Background()
	s := newSaveSessionTestStore(t)
	uid := seedModedAccount(t, s, "revoked-local-no-active", 700000304, ModeLocal, true, false)

	if err := s.SaveSession(ctx, uid, []byte("session-bytes"), 700000304, "Hosted Name", "hosteduser"); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	mode, err := s.GetAccountMode(ctx, uid)
	if err != nil {
		t.Fatalf("GetAccountMode: %v", err)
	}
	if mode != ModeHosted {
		t.Errorf("mode after SaveSession over a revoked local row = %q, want %q (fresh hosted row)", mode, ModeHosted)
	}
}
