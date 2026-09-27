package db

import (
	"context"
	"database/sql"
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
