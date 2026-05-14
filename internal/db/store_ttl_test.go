package db

import (
	"context"
	"errors"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestCheckSessionValid_NoSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "alice", "", "test")

	_, err := s.CheckSessionValid(ctx, uid)
	if !errors.Is(err, ErrNoActiveSession) {
		t.Fatalf("expected ErrNoActiveSession, got %v", err)
	}
}

func TestCheckSessionValid_FreshSessionPasses(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "alice", "", "test")
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4)`,
		uid, []byte("blob"), now, now.Add(90*24*time.Hour),
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.CheckSessionValid(ctx, uid); err != nil {
		t.Fatalf("expected fresh session to pass, got %v", err)
	}
}

func TestCheckSessionValid_IdleExpiryRevokes(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "bob", "", "test")
	now := time.Now().UTC()
	stale := now.Add(-31 * 24 * time.Hour) // older than 30-day idle TTL
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4)`,
		uid, []byte("blob"), stale, now.Add(60*24*time.Hour),
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	reason, err := s.CheckSessionValid(ctx, uid)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
	if reason != ReasonIdle {
		t.Fatalf("expected ReasonIdle, got %q", reason)
	}
	// And the row should now be revoked.
	var revoked bool
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at IS NOT NULL FROM telegram_accounts WHERE user_id=$1`, uid,
	).Scan(&revoked); err != nil {
		t.Fatalf("check revoked: %v", err)
	}
	if !revoked {
		t.Fatal("idle expiry should mark row revoked in-place")
	}
}

func TestCheckSessionValid_AbsoluteExpiryRevokes(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "carol", "", "test")
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4)`,
		uid, []byte("blob"), now, now.Add(-time.Hour), // expired an hour ago
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	reason, err := s.CheckSessionValid(ctx, uid)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
	if reason != ReasonAbsolute {
		t.Fatalf("expected ReasonAbsolute, got %q", reason)
	}
}

func TestMarkLastUsed_UpdatesActiveRow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "dave", "", "test")
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at) VALUES($1, $2, $3)`,
		uid, []byte("blob"), old,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s.MarkLastUsed(ctx, uid)

	var got time.Time
	if err := s.DB.QueryRowContext(ctx,
		`SELECT last_used_at FROM telegram_accounts WHERE user_id=$1`, uid,
	).Scan(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if time.Since(got) > time.Minute {
		t.Fatalf("MarkLastUsed should bump to ~now, got %v (delta %v)", got, time.Since(got))
	}
}

func TestSweepExpiredSessions_RevokesIdleAndAbsolute(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	alice, _ := s.EnsureUser(ctx, "alice", "", "test")
	bob, _ := s.EnsureUser(ctx, "bob", "", "test")
	carol, _ := s.EnsureUser(ctx, "carol", "", "test")
	now := time.Now().UTC()

	// alice — fresh session, must NOT be revoked
	_, _ = s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at) VALUES($1,$2,$3,$4)`,
		alice, []byte("blob"), now, now.Add(90*24*time.Hour),
	)
	// bob — idle-expired
	_, _ = s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at) VALUES($1,$2,$3,$4)`,
		bob, []byte("blob"), now.Add(-31*24*time.Hour), now.Add(60*24*time.Hour),
	)
	// carol — absolute-expired
	_, _ = s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at) VALUES($1,$2,$3,$4)`,
		carol, []byte("blob"), now, now.Add(-time.Hour),
	)

	rows, err := s.SweepExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rows != 2 {
		t.Fatalf("expected 2 rows revoked, got %d", rows)
	}

	// alice still active, bob+carol revoked.
	check := func(uid int64, wantRevoked bool, label string) {
		var revoked bool
		if err := s.DB.QueryRowContext(ctx,
			`SELECT revoked_at IS NOT NULL FROM telegram_accounts WHERE user_id=$1`, uid,
		).Scan(&revoked); err != nil {
			t.Fatalf("scan %s: %v", label, err)
		}
		if revoked != wantRevoked {
			t.Fatalf("%s: revoked=%v want=%v", label, revoked, wantRevoked)
		}
	}
	check(alice, false, "alice (fresh)")
	check(bob, true, "bob (idle)")
	check(carol, true, "carol (absolute)")
}

func TestSaveSession_StampsLastUsedAndExpires(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid, _ := s.EnsureUser(ctx, "ed", "", "test")
	if err := s.SaveSession(ctx, uid, []byte("pt"), 0, "", ""); err != nil {
		t.Fatalf("save: %v", err)
	}
	var lastUsed, expires time.Time
	if err := s.DB.QueryRowContext(ctx,
		`SELECT last_used_at, expires_at FROM telegram_accounts WHERE user_id=$1`, uid,
	).Scan(&lastUsed, &expires); err != nil {
		t.Fatalf("read: %v", err)
	}
	if lastUsed.IsZero() {
		t.Fatal("last_used_at should be stamped on insert")
	}
	if expires.IsZero() {
		t.Fatal("expires_at should be stamped on insert")
	}
	if expires.Sub(lastUsed) < 89*24*time.Hour {
		t.Fatalf("expires - last_used should be ~90 days, got %v", expires.Sub(lastUsed))
	}
}
