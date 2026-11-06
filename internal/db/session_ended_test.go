package db

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

type endedSession struct {
	uid  int64
	data string
}

func recordEndedSessions(s *Store) *[]endedSession {
	var got []endedSession
	s.WithSessionEnded(func(uid int64, data []byte) {
		got = append(got, endedSession{uid, string(data)})
	})
	return &got
}

func TestRevokeActiveSession_ErasesAndHandsOffSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	got := recordEndedSessions(s)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.SaveSession(ctx, uid, []byte("mtproto-session"), 111, "Alice", "alice"); err != nil {
		t.Fatalf("save session: %v", err)
	}

	had, err := s.RevokeActiveSession(ctx, uid, "disconnect")
	if err != nil || !had {
		t.Fatalf("revoke: had=%v err=%v", had, err)
	}

	var blob []byte
	var revokedAt sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT session_encrypted, revoked_at FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&blob, &revokedAt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if len(blob) != 0 {
		t.Errorf("sealed session survived the disconnect: %d bytes", len(blob))
	}
	if !revokedAt.Valid {
		t.Error("row is not marked revoked")
	}
	if len(*got) != 1 || (*got)[0] != (endedSession{uid, "mtproto-session"}) {
		t.Errorf("hook got %+v, want the decrypted session once", *got)
	}

	// A second disconnect finds nothing to end.
	had, err = s.RevokeActiveSession(ctx, uid, "disconnect")
	if err != nil || had {
		t.Fatalf("second revoke: had=%v err=%v", had, err)
	}
	if len(*got) != 1 {
		t.Errorf("hook ran again: %+v", *got)
	}
}

func TestRevokeActiveSession_LocalRowHasNothingToEnd(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	got := recordEndedSessions(s)
	uid, err := s.EnsureUserByTelegramID(ctx, 222, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, mode) VALUES($1,$2,$3)`,
		uid, 222, ModeLocal,
	); err != nil {
		t.Fatalf("seed local row: %v", err)
	}
	// An absent session must not read as a corrupt one in the logs.
	var logs bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prevLogger) })

	had, err := s.RevokeActiveSession(ctx, uid, "disconnect")
	if err != nil || !had {
		t.Fatalf("revoke: had=%v err=%v", had, err)
	}
	if len(*got) != 0 {
		t.Errorf("hook ran for a row with no session: %+v", *got)
	}
	if bytes.Contains(logs.Bytes(), []byte("did not decrypt")) {
		t.Errorf("a row with no session was reported as undecryptable: %s", logs.String())
	}
}

func TestHardDeleteAccount_HandsOffOnlyTheActiveSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	got := recordEndedSessions(s)
	uid, err := s.EnsureUserByTelegramID(ctx, 333, "carol", "Carol")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	// The second save supersedes the first row, whose key was already logged
	// out by the sign-in flow, so only the second must reach the hook.
	if err := s.SaveSession(ctx, uid, []byte("old-session"), 333, "Carol", "carol"); err != nil {
		t.Fatalf("save old session: %v", err)
	}
	if err := s.SaveSession(ctx, uid, []byte("new-session"), 333, "Carol", "carol"); err != nil {
		t.Fatalf("save new session: %v", err)
	}

	if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if len(*got) != 1 || (*got)[0] != (endedSession{uid, "new-session"}) {
		t.Errorf("hook got %+v, want only the active session", *got)
	}
}

// Production runs on Postgres, whose path takes the users-row lock and whose
// column nullability comes from a separate migration step.
func TestRevokeActiveSession_ErasesSession_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s := newPostgresTestStore(t, dsn)
	c, err := crypto.New(makeKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	s.Crypt = c
	got := recordEndedSessions(s)
	tgID := time.Now().UnixNano()
	uid, err := s.EnsureUserByTelegramID(ctx, tgID, "pg_disconnect", "PG")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM telegram_accounts WHERE user_id = $1`, uid)
		_, _ = s.DB.Exec(`DELETE FROM users WHERE id = $1`, uid)
	})
	if err := s.SaveSession(ctx, uid, []byte("mtproto-session"), tgID, "PG", "pg_disconnect"); err != nil {
		t.Fatalf("save session: %v", err)
	}

	had, err := s.RevokeActiveSession(ctx, uid, "disconnect")
	if err != nil || !had {
		t.Fatalf("revoke: had=%v err=%v", had, err)
	}

	var blob []byte
	var revokedAt sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT session_encrypted, revoked_at FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&blob, &revokedAt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if len(blob) != 0 || !revokedAt.Valid {
		t.Errorf("row after disconnect: %d session bytes, revoked=%v", len(blob), revokedAt.Valid)
	}
	if len(*got) != 1 || (*got)[0].uid != uid || (*got)[0].data != "mtproto-session" {
		t.Errorf("handed-off sessions = %+v", *got)
	}
}
