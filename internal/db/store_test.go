package db

import (
	"context"
	"testing"

	_ "modernc.org/sqlite"
)

// TestListIdentities checks the roster: fresh widget-authenticated users appear
// with a populated CreatedAt and an empty (unset) raw access_tier.
func TestListIdentities(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.EnsureUserByTelegramID(ctx, 111, "alice", "Alice"); err != nil {
		t.Fatalf("ensure 111: %v", err)
	}
	if _, err := st.EnsureUserByTelegramID(ctx, 222, "bob", "Bob"); err != nil {
		t.Fatalf("ensure 222: %v", err)
	}
	rows, err := st.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ListIdentities len = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r.CreatedAt.IsZero() {
			t.Errorf("identity %d has zero CreatedAt", r.TelegramID)
		}
		if r.AccessTier != "" {
			t.Errorf("fresh identity %d should have empty access_tier, got %q", r.TelegramID, r.AccessTier)
		}
	}
}

// newTestStore opens an in-memory SQLite DB, applies the migration, and
// returns a Store wired with a nil crypto (Seal/Open passthrough). Session
// blobs in these tests are arbitrary bytes — we never decrypt them.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	conn, err := Open(ctx, "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Store{DB: conn, Crypt: nil}
}

func TestRevokeActiveSession_FlipsOnceAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "alice", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1, $2)`,
		uid, []byte("blob"),
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	had, err := s.RevokeActiveSession(ctx, uid)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !had {
		t.Fatal("first revoke should report had=true")
	}

	had2, err := s.RevokeActiveSession(ctx, uid)
	if err != nil {
		t.Fatalf("revoke 2: %v", err)
	}
	if had2 {
		t.Fatal("second revoke should report had=false (idempotent)")
	}
}

func TestRevokeActiveSession_NoSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "bob", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	had, err := s.RevokeActiveSession(ctx, uid)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if had {
		t.Fatal("revoke with no session should report had=false, no error")
	}
}

func TestHardDeleteAccount_RemovesAllRows(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "carol", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	// Two rows: one active, one revoked. HardDelete should kill both.
	for _, revoked := range []bool{false, false} {
		_, err := s.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1, $2)`,
			uid, []byte("blob"),
		)
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		_ = revoked
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET revoked_at = CURRENT_TIMESTAMP WHERE id = (SELECT MIN(id) FROM telegram_accounts WHERE user_id = $1)`,
		uid,
	); err != nil {
		t.Fatalf("revoke seed: %v", err)
	}

	rows, err := s.HardDeleteAccount(ctx, uid)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if rows != 2 {
		t.Fatalf("expected 2 rows removed, got %d", rows)
	}

	var count int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 remaining rows, got %d", count)
	}
}

func TestGetActiveAccount_NoSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "dave", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	info, err := s.GetActiveAccount(ctx, uid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil AccountInfo")
	}
	if info.Connected {
		t.Fatal("expected Connected=false when no session")
	}
}

func TestGetActiveAccount_ReturnsFields(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "eve", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, display_name, username, session_encrypted, send_enabled) VALUES($1,$2,$3,$4,$5)`,
		uid, "Eve E.", "eve_e", []byte("blob"), true,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	info, err := s.GetActiveAccount(ctx, uid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !info.Connected || info.DisplayName != "Eve E." || info.Username != "eve_e" || !info.SendEnabled {
		t.Fatalf("unexpected: %+v", info)
	}
	if info.ConnectedAt.IsZero() {
		t.Fatal("expected ConnectedAt populated")
	}
}

func TestIsSendEnabled_DefaultFalseAndRespectsFlag(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "frank", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	// No account at all → false, no error.
	enabled, err := s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("no session: %v", err)
	}
	if enabled {
		t.Fatal("expected false when no session")
	}

	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled) VALUES($1, $2, $3)`,
		uid, []byte("blob"), false,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	enabled, err = s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if enabled {
		t.Fatal("expected false from seeded send_enabled=false")
	}

	if _, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET send_enabled = $1 WHERE user_id = $2`,
		true, uid,
	); err != nil {
		t.Fatalf("flip: %v", err)
	}
	enabled, err = s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if !enabled {
		t.Fatal("expected true after flip")
	}
}
