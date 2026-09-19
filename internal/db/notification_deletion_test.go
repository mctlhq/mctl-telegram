package db

import (
	"context"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// countNotificationRows returns the number of rows for uid across both
// issue-438 tables, so tests can assert "zero rows" in one call.
func countNotificationRows(t *testing.T, s *Store, uid int64) (prefs, reachability int) {
	t.Helper()
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM client_notification_prefs WHERE user_id = $1`, uid,
	).Scan(&prefs); err != nil {
		t.Fatalf("count notification prefs: %v", err)
	}
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM client_bot_reachability WHERE user_id = $1`, uid,
	).Scan(&reachability); err != nil {
		t.Fatalf("count reachability: %v", err)
	}
	return prefs, reachability
}

// TestHardDeleteAccount_PurgesNotificationState is T13: seed preferences and
// a reachability row, call HardDeleteAccount, assert zero rows in both new
// tables and that the users row itself survives (existing contract).
func TestHardDeleteAccount_PurgesNotificationState(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.SetNotificationPrefs(ctx, uid, map[string]string{
		string(CategoryProductUpdates): PrefSubscribed,
		string(CategoryMaintenance):    PrefUnsubscribed,
	}, "account_api"); err != nil {
		t.Fatalf("seed prefs: %v", err)
	}
	outcome := notify.ClassifyDelivery(200, "")
	if err := s.RecordBotReachability(ctx, uid, outcome, "digest_delivery"); err != nil {
		t.Fatalf("seed reachability: %v", err)
	}

	prefsBefore, reachBefore := countNotificationRows(t, s, uid)
	if prefsBefore == 0 || reachBefore == 0 {
		t.Fatalf("test setup: want non-zero rows before deletion, got prefs=%d reachability=%d", prefsBefore, reachBefore)
	}

	if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
		t.Fatalf("HardDeleteAccount: %v", err)
	}

	prefsAfter, reachAfter := countNotificationRows(t, s, uid)
	if prefsAfter != 0 {
		t.Errorf("client_notification_prefs has %d rows after deletion, want 0", prefsAfter)
	}
	if reachAfter != 0 {
		t.Errorf("client_bot_reachability has %d rows after deletion, want 0", reachAfter)
	}

	var stillExists bool
	if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, uid).Scan(&stillExists); err != nil {
		t.Fatalf("check users row: %v", err)
	}
	if !stillExists {
		t.Error("the users identity row was deleted; it must survive account deletion")
	}
}

// TestRevokeActiveSession_LeavesNotificationStateIntact is T14: a disconnect
// is not a deletion.
func TestRevokeActiveSession_LeavesNotificationStateIntact(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted) VALUES($1,$2,$3)`,
		uid, 111, []byte("blob"),
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := s.SetNotificationPrefs(ctx, uid, map[string]string{
		string(CategoryProductUpdates): PrefSubscribed,
	}, "account_api"); err != nil {
		t.Fatalf("seed prefs: %v", err)
	}
	outcome := notify.ClassifyDelivery(200, "")
	if err := s.RecordBotReachability(ctx, uid, outcome, "digest_delivery"); err != nil {
		t.Fatalf("seed reachability: %v", err)
	}

	if _, err := s.RevokeActiveSession(ctx, uid, "disconnect"); err != nil {
		t.Fatalf("RevokeActiveSession: %v", err)
	}

	prefs, reachability := countNotificationRows(t, s, uid)
	if prefs == 0 {
		t.Error("notification preferences were removed by a disconnect; they must survive")
	}
	if reachability == 0 {
		t.Error("bot reachability was removed by a disconnect; it must survive")
	}
}
