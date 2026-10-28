package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// revokedReasonOf reads telegram_accounts.revoked_reason for one Telegram id.
func revokedReasonOf(t *testing.T, s *Store, tgID int64) (sql.NullTime, sql.NullString) {
	t.Helper()
	var at sql.NullTime
	var reason sql.NullString
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT revoked_at, revoked_reason FROM telegram_accounts WHERE telegram_user_id = $1`, tgID,
	).Scan(&at, &reason); err != nil {
		t.Fatalf("read revoked columns: %v", err)
	}
	return at, reason
}

// TestSweepIdleSessionsStampsReason pins the #674 review finding: the idle
// sweep is the path that actually revokes an idle session (no request ever
// arrives to trigger the lazy CheckSessionValid revoke), so it must write
// revoked_reason itself or the digest's "session revoked (...)" clause can
// never say idle_expiry.
func TestSweepIdleSessionsStampsReason(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "sweep-idle-reason", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	stale := time.Now().UTC().Add(-40 * 24 * time.Hour) // past the 30d idle TTL
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,NULL)`,
		uid, 500100105, []byte("blob"), stale,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rows, err := s.SweepIdleSessions(ctx)
	if err != nil {
		t.Fatalf("sweep idle: %v", err)
	}
	if rows != 1 {
		t.Fatalf("idle sweep revoked %d rows, want 1", rows)
	}
	at, reason := revokedReasonOf(t, s, 500100105)
	if !at.Valid {
		t.Fatal("revoked_at not set by the idle sweep")
	}
	if reason.String != "idle_expiry" {
		t.Errorf("revoked_reason = %q, want idle_expiry", reason.String)
	}
}

// TestSweepAbsoluteSessionsStampsReason is the sibling for the absolute TTL
// sweep. Without the stamp the reason a digest showed for an expired session
// depended on whether a request happened to arrive before the sweeper.
func TestSweepAbsoluteSessionsStampsReason(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "sweep-absolute-reason", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	expired := time.Now().UTC().Add(-time.Hour)
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,$5)`,
		uid, 500100106, []byte("blob"), time.Now().UTC(), expired,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rows, err := s.SweepAbsoluteSessions(ctx)
	if err != nil {
		t.Fatalf("sweep absolute: %v", err)
	}
	if rows != 1 {
		t.Fatalf("absolute sweep revoked %d rows, want 1", rows)
	}
	at, reason := revokedReasonOf(t, s, 500100106)
	if !at.Valid {
		t.Fatal("revoked_at not set by the absolute sweep")
	}
	if reason.String != "absolute_expiry" {
		t.Errorf("revoked_reason = %q, want absolute_expiry", reason.String)
	}
}

// A row a login never finished (telegram_user_id NULL) is revoked as
// login_incomplete, not unauthorized: Telegram rejected nothing, and mixing
// the two hid the few real server-side kills among abandoned logins.
func TestCheckSessionValidIncompleteLoginStampsReason(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "incomplete-login-reason", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1,$2)`, uid, []byte("blob"),
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.CheckSessionValid(ctx, uid); !errors.Is(err, ErrSessionUnauthorized) {
		t.Fatalf("CheckSessionValid = %v, want ErrSessionUnauthorized", err)
	}
	var reason, detail sql.NullString
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_reason, revoked_detail FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&reason, &detail); err != nil {
		t.Fatalf("read: %v", err)
	}
	if reason.String != "login_incomplete" {
		t.Errorf("revoked_reason = %q, want login_incomplete", reason.String)
	}
	if detail.Valid {
		t.Errorf("revoked_detail = %q, want NULL", detail.String)
	}
}

// The Telegram error type behind an 'unauthorized' revoke is kept on the row;
// before revoked_detail it survived only in logs.
func TestRevokeSessionByIDStoresDetail(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "revoke-detail", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	var rowID int64
	if err := s.DB.QueryRowContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted) VALUES($1,$2,$3) RETURNING id`,
		uid, 500100107, []byte("blob"),
	).Scan(&rowID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if ok, err := s.RevokeSessionByID(ctx, uid, rowID, "unauthorized", "AUTH_KEY_UNREGISTERED"); err != nil || !ok {
		t.Fatalf("RevokeSessionByID = %v, %v", ok, err)
	}
	var detail sql.NullString
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_detail FROM telegram_accounts WHERE id = $1`, rowID,
	).Scan(&detail); err != nil {
		t.Fatalf("read: %v", err)
	}
	if detail.String != "AUTH_KEY_UNREGISTERED" {
		t.Errorf("revoked_detail = %q, want AUTH_KEY_UNREGISTERED", detail.String)
	}
}
