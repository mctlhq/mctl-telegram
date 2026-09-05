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

// TestSaveSession_RefusesLocalRowBehindNewerHostedRow pins the guard's
// predicate to the same rows the revoke below it touches. Nothing stops a user
// from having several active rows, and the revoke is
// `WHERE user_id = $1 AND revoked_at IS NULL` -- every active row. A guard that
// inspected only the newest row (ORDER BY connected_at DESC LIMIT 1) would see
// the hosted row here, wave the login through, and then revoke the older local
// row anyway: the exact silent destruction issue-492 is about.
func TestSaveSession_RefusesLocalRowBehindNewerHostedRow(t *testing.T) {
	ctx := context.Background()
	s := newSaveSessionTestStore(t)
	uid := seedModedAccount(t, s, "local-behind-hosted", 700000305, ModeLocal, false, false)

	// A newer active hosted row for the same user, so the local row is no
	// longer the one a LIMIT 1 mode probe would find.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, mode, send_enabled)
		 VALUES($1,$2,$3,$4,$5)`,
		uid, 700000305, []byte("hosted-blob"), ModeHosted, false,
	); err != nil {
		t.Fatalf("seed newer hosted row: %v", err)
	}

	if err := s.SaveSession(ctx, uid, []byte("session-bytes"), 700000305, "Hosted Name", "hosteduser"); !errors.Is(err, ErrAccountModeConflict) {
		t.Fatalf("SaveSession error = %v, want ErrAccountModeConflict", err)
	}

	var revokedAt sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM telegram_accounts WHERE user_id = $1 AND mode = $2`,
		uid, ModeLocal,
	).Scan(&revokedAt); err != nil {
		t.Fatalf("read local row: %v", err)
	}
	if revokedAt.Valid {
		t.Errorf("local row revoked_at = %v, want NULL (the refused SaveSession must not revoke it)", revokedAt.Time)
	}
}

// TestClearActiveSessionBlobs_ClearsHostedRowToo is the regression test for
// the finding that the backstop cleanup was scoped to mode='local' while the
// write it repairs was not.
//
// When the gotd SessionStore has no loaded row id — the case for a provisioned
// local account, whose session_encrypted is NULL — StoreSession falls through
// to UpdateSessionBlob, which writes `WHERE user_id = $1 AND revoked_at IS
// NULL`: every active row. A user holding both a local and a hosted active row
// therefore ended a REFUSED connect with the hosted row carrying the freshly
// negotiated session. The first half of this test pins that write behaviour,
// so the cleanup's scope cannot drift back out of step with it.
func TestClearActiveSessionBlobs_ClearsHostedRowToo(t *testing.T) {
	ctx := context.Background()
	s := newSaveSessionTestStore(t)
	uid := seedModedAccount(t, s, "clear-all-rows", 700000606, ModeLocal, false, false)
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, mode, send_enabled)
		 VALUES($1,$2,$3,$4,$5)`,
		uid, 700000606, nil, ModeHosted, false,
	); err != nil {
		t.Fatalf("seed hosted row: %v", err)
	}

	// What telegram.Login does through the SessionStore on this path.
	if err := s.UpdateSessionBlob(ctx, uid, []byte("freshly-negotiated-session")); err != nil {
		t.Fatalf("UpdateSessionBlob: %v", err)
	}
	blobbed := func() map[string]bool {
		t.Helper()
		rows, err := s.DB.QueryContext(ctx,
			`SELECT mode, session_encrypted IS NOT NULL FROM telegram_accounts
			 WHERE user_id = $1 AND revoked_at IS NULL`, uid)
		if err != nil {
			t.Fatalf("query rows: %v", err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var mode string
			var has bool
			if err := rows.Scan(&mode, &has); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out[mode] = has
		}
		return out
	}
	// Control: the write really did reach both rows. Without this the
	// assertion below would pass even if UpdateSessionBlob had stopped
	// touching the hosted row, proving nothing about the cleanup.
	if got := blobbed(); !got[ModeLocal] || !got[ModeHosted] {
		t.Fatalf("after login write, blobs = %v, want both rows carrying bytes", got)
	}

	if err := s.ClearActiveSessionBlobs(ctx, uid); err != nil {
		t.Fatalf("ClearActiveSessionBlobs: %v", err)
	}
	got := blobbed()
	if got[ModeLocal] {
		t.Errorf("local row still carries session bytes after the backstop clear")
	}
	if got[ModeHosted] {
		t.Errorf("hosted row still carries the session bytes from a REFUSED connect; the cleanup must match UpdateSessionBlob's blast radius")
	}
	// Neither row may be revoked: destroying the local account is the very
	// thing issue-492's guard exists to prevent.
	var active int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1 AND revoked_at IS NULL`, uid,
	).Scan(&active); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if active != 2 {
		t.Errorf("active rows after cleanup = %d, want 2 (cleanup must not revoke)", active)
	}
}

// TestSaveSession_RefusalLeavesNoRowRevoked pins the property that makes the
// mode check safe to fold into the revoke: when SaveSession refuses, the
// deferred Rollback must undo the revoke the RETURNING statement performed, so
// the local row it was protecting survives with revoked_at still NULL.
//
// The earlier shape ran `SELECT EXISTS` and then the revoke as two statements.
// That left a window: under READ COMMITTED a ProvisionLocalAccount committing
// between them is a phantom the SELECT never sees, while the UPDATE takes a
// fresh snapshot at statement start, sees the new row and revokes it —
// issue-492 verbatim, and invisible to the enable_access backstop because
// SaveSession returns nil on that path.
//
// The hosted row is here as the control: it proves the statement really did
// revoke rows before the refusal (so the rollback is doing work), rather than
// the guard short-circuiting before any write.
func TestSaveSession_RefusalLeavesNoRowRevoked(t *testing.T) {
	ctx := context.Background()
	s := newSaveSessionTestStore(t)
	uid := seedModedAccount(t, s, "refusal-rolls-back", 700000707, ModeLocal, false, false)
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, mode, send_enabled)
		 VALUES($1,$2,$3,$4,$5)`,
		uid, 700000707, []byte("hosted-blob"), ModeHosted, false,
	); err != nil {
		t.Fatalf("seed hosted row: %v", err)
	}

	if err := s.SaveSession(ctx, uid, []byte("session-bytes"), 700000707, "Hosted", "hosted"); !errors.Is(err, ErrAccountModeConflict) {
		t.Fatalf("SaveSession error = %v, want ErrAccountModeConflict", err)
	}

	var revoked, total int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FILTER (WHERE revoked_at IS NOT NULL), COUNT(*)
		   FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&revoked, &total); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if total != 2 {
		t.Fatalf("row count = %d, want 2 (the refusal must not insert a hosted row either)", total)
	}
	if revoked != 0 {
		t.Errorf("%d row(s) left revoked after a refused SaveSession; the rollback must undo the revoke the mode check performed", revoked)
	}
}
