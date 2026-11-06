package db

import (
	"context"
	"testing"
	"time"
)

func blobPresent(t *testing.T, s *Store, id int64) bool {
	t.Helper()
	var b []byte
	if err := s.DB.QueryRow(`SELECT session_encrypted FROM telegram_accounts WHERE id=$1`, id).Scan(&b); err != nil {
		t.Fatal(err)
	}
	return b != nil
}

// TestEveryRevocationPathErasesTheSession pins that no revoked row keeps a
// sealed session, whichever path revoked it.
func TestEveryRevocationPathErasesTheSession(t *testing.T) {
	old := time.Now().UTC().Add(-365 * 24 * time.Hour)
	seed := func(t *testing.T, s *Store, tg int64) (uid, id int64) {
		t.Helper()
		ctx := context.Background()
		uid, err := s.EnsureUserByTelegramID(ctx, tg, "", "")
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := s.Crypt.SealForUser([]byte("session"), uid)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow(
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
			 VALUES($1,$2,$3,$4,$5) RETURNING id`, uid, tg, sealed, old, old).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return uid, id
	}
	cases := []struct {
		name   string
		revoke func(ctx context.Context, s *Store, uid, id int64) error
	}{
		{"by id", func(ctx context.Context, s *Store, uid, id int64) error {
			_, err := s.RevokeSessionByID(ctx, uid, id, "unauthorized", "")
			return err
		}},
		{"user decision", func(ctx context.Context, s *Store, uid, _ int64) error {
			_, err := s.RevokeActiveSession(ctx, uid, "disconnect")
			return err
		}},
		{"idle sweep", func(ctx context.Context, s *Store, _, _ int64) error {
			_, err := s.SweepIdleSessions(ctx)
			return err
		}},
		{"absolute sweep", func(ctx context.Context, s *Store, _, _ int64) error {
			_, err := s.SweepAbsoluteSessions(ctx)
			return err
		}},
		{"expired sweep", func(ctx context.Context, s *Store, _, _ int64) error {
			_, err := s.SweepExpiredSessions(ctx)
			return err
		}},
		{"superseded", func(ctx context.Context, s *Store, uid, _ int64) error {
			return s.SaveSession(ctx, uid, []byte("new"), 88001, "", "")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newTestStoreCrypted(t)
			uid, id := seed(t, s, 88001)
			if err := c.revoke(context.Background(), s, uid, id); err != nil {
				t.Fatal(err)
			}
			var revoked bool
			if err := s.DB.QueryRow(`SELECT revoked_at IS NOT NULL FROM telegram_accounts WHERE id=$1`, id).Scan(&revoked); err != nil {
				t.Fatal(err)
			}
			if !revoked {
				t.Fatal("row was not revoked")
			}
			if blobPresent(t, s, id) {
				t.Fatal("revoked row kept its sealed session")
			}
		})
	}
}

func TestSaveSessionForSignInSuperseding_StillReturnsTheOldSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 88002, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSession(ctx, uid, []byte("first"), 88002, "", ""); err != nil {
		t.Fatal(err)
	}
	old, err := s.SaveSessionForSignInSuperseding(ctx, uid, []byte("second"), 88002, "", "", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 1 || string(old[0]) != "first" {
		t.Fatalf("superseded = %q: erasing must not lose the bytes the logout needs", old)
	}
}
