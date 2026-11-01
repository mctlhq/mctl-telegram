package db

import (
	"context"
	"testing"
	"time"
)

// seedAuditRow writes one audit_logs row directly, bypassing the hash chain:
// PublicStatsQuery reads tool_name/status/created_at/user_id only.
func seedAuditRow(t *testing.T, s *Store, userID int64, tool, status string, at time.Time) {
	t.Helper()
	if _, err := s.DB.ExecContext(context.Background(),
		`INSERT INTO audit_logs(user_id, tool_name, status, created_at) VALUES($1,$2,$3,$4)`,
		userID, tool, status, at,
	); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}
}

func TestPublicStatsQuery_CountsAndExclusions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()

	// Three Telegram users: Alice (active, two days of use), Bob (one old
	// call, outside the 30-day window) and Carol (connected, never called).
	// Dana is the canary: she calls every minute and must not count.
	// A fifth user is a legacy github_login row with no Telegram id.
	alice, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.EnsureUserByTelegramID(ctx, 222, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	carol, err := s.EnsureUserByTelegramID(ctx, 333, "carol", "Carol")
	if err != nil {
		t.Fatal(err)
	}
	dana, err := s.EnsureUserByTelegramID(ctx, 444, "dana", "Dana")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureUser(ctx, "legacy-gh", "", "test"); err != nil {
		t.Fatal(err)
	}

	// Counted: 3 ok tool calls by Alice, 1 old ok call by Bob.
	seedAuditRow(t, s, alice, "get_messages", "ok", now.Add(-time.Hour))
	seedAuditRow(t, s, alice, "list_dialogs", "ok", now.Add(-26*time.Hour))
	seedAuditRow(t, s, alice, "send_message:sent", "ok", now.Add(-2*time.Hour))
	seedAuditRow(t, s, bob, "get_messages", "ok", now.Add(-40*24*time.Hour))
	// Not counted: errors, connect steps, bridge keepalive, web posts, canary.
	seedAuditRow(t, s, alice, "get_messages", "error", now.Add(-time.Hour))
	seedAuditRow(t, s, alice, "connect:success", "ok", now.Add(-3*time.Hour))
	seedAuditRow(t, s, alice, "local_bridge_device_refresh", "ok", now.Add(-time.Minute))
	seedAuditRow(t, s, alice, "POST /telegram/connect/manage/notifications", "ok", now.Add(-time.Minute))
	for i := 0; i < 50; i++ {
		seedAuditRow(t, s, dana, "get_messages", "ok", now.Add(-time.Duration(i)*time.Minute))
	}

	// Sessions: Alice live, Bob revoked, Carol live but idle for two hours,
	// Dana (canary) live and used a minute ago.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at) VALUES($1,$2,$3)`,
		alice, []byte("a"), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, revoked_at) VALUES($1,$2,$3)`,
		bob, []byte("b"), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at) VALUES($1,$2,$3)`,
		carol, []byte("c"), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at) VALUES($1,$2,$3)`,
		dana, []byte("d"), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	got, err := s.PublicStatsQuery(ctx, []int64{444})
	if err != nil {
		t.Fatalf("PublicStatsQuery: %v", err)
	}
	if got.AccountsTotal != 3 {
		t.Errorf("AccountsTotal = %d, want 3 (alice, bob, carol; dana is canary, legacy row has no telegram id)", got.AccountsTotal)
	}
	if got.ToolCallsTotal != 4 {
		t.Errorf("ToolCallsTotal = %d, want 4 (3 alice + 1 bob; error, connect, bridge, POST and canary excluded)", got.ToolCallsTotal)
	}
	if got.ActiveUsers30d != 1 {
		t.Errorf("ActiveUsers30d = %d, want 1 (alice; bob is 40 days old, dana is canary)", got.ActiveUsers30d)
	}
	if got.SessionsActive != 1 {
		t.Errorf("SessionsActive = %d, want 1 (alice; bob revoked, carol idle 2h, dana canary)", got.SessionsActive)
	}

	// Without a canary list the canary counts like anyone else in every
	// field: proves the exclusion above is the clause doing the work, not a
	// coincidence.
	all, err := s.PublicStatsQuery(ctx, nil)
	if err != nil {
		t.Fatalf("PublicStatsQuery(nil): %v", err)
	}
	if all.AccountsTotal != 4 || all.ToolCallsTotal != 54 || all.ActiveUsers30d != 2 || all.SessionsActive != 2 {
		t.Errorf("without canary list: Accounts=%d ToolCalls=%d Active30d=%d Sessions=%d, want 4/54/2/2",
			all.AccountsTotal, all.ToolCallsTotal, all.ActiveUsers30d, all.SessionsActive)
	}
}

func TestPublicStatsQuery_DeletedAccountNotCounted(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET account_deleted_at = $1 WHERE id = $2`, time.Now().UTC(), uid); err != nil {
		t.Fatal(err)
	}
	got, err := s.PublicStatsQuery(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountsTotal != 0 {
		t.Errorf("AccountsTotal = %d, want 0 after deletion", got.AccountsTotal)
	}
}
