package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestHardDeleteAccount_RevokesRefreshTokens(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	alice, err := s.EnsureUserByTelegramID(ctx, 4242, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure alice: %v", err)
	}
	bob, err := s.EnsureUserByTelegramID(ctx, 4343, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure bob: %v", err)
	}
	seedAccount(t, s, alice, nil, nil, nil)

	mk := func(fam string, uid int64) RefreshToken {
		return RefreshToken{FamilyID: fam, UserID: uid, ClientID: "claude.ai",
			TelegramID: 1, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
	}
	for _, c := range []struct {
		pt  string
		fam string
		uid int64
	}{{"a-1", "fa", alice}, {"a-2", "fb", alice}, {"b-1", "fc", bob}} {
		if err := s.SaveRefreshToken(ctx, c.pt, mk(c.fam, c.uid)); err != nil {
			t.Fatalf("save %s: %v", c.pt, err)
		}
	}
	// a-old was rotated earlier and must keep its original reason.
	if err := s.SaveRefreshToken(ctx, "a-old", mk("fa", alice)); err != nil {
		t.Fatalf("save a-old: %v", err)
	}
	if err := s.RotateRefreshToken(ctx, "a-old", "a-new", mk("fa", alice)); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if _, err := s.HardDeleteAccount(ctx, alice); err != nil {
		t.Fatalf("delete: %v", err)
	}

	reason := func(pt string) (string, bool) {
		rt, err := s.LookupRefreshToken(ctx, pt)
		if err != nil {
			t.Fatalf("lookup %s: %v", pt, err)
		}
		return rt.RevokedReason, rt.Revoked()
	}
	for _, pt := range []string{"a-1", "a-2", "a-new"} {
		if r, rev := reason(pt); !rev || r != "account_deleted" {
			t.Errorf("%s: revoked=%v reason=%q, want account_deleted", pt, rev, r)
		}
	}
	if r, rev := reason("a-old"); !rev || r != "rotated" {
		t.Errorf("a-old: revoked=%v reason=%q, want rotated", rev, r)
	}
	if _, rev := reason("b-1"); rev {
		t.Error("other user's token must not be revoked")
	}
	if err := s.RotateRefreshToken(ctx, "a-1", "a-x", mk("fa", alice)); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("rotate after delete: err = %v, want ErrRefreshTokenNotFound", err)
	}
}

// TestHardDeleteAccount_RevokesRefreshTokens_PostgresConcurrent exercises the
// users-row lock (FOR UPDATE in HardDeleteAccount, FOR SHARE in
// RotateRefreshToken), which is compiled out on SQLite. Whichever ordering
// wins, no refresh token for the deleted user may remain live.
func TestHardDeleteAccount_RevokesRefreshTokens_PostgresConcurrent(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()

	run := time.Now().UnixNano()
	for round := 0; round < 10; round++ {
		tgID := int64(850000000 + round)
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
		if err != nil {
			t.Fatalf("round %d ensure: %v", round, err)
		}
		mk := func(fam string) RefreshToken {
			return RefreshToken{FamilyID: fam, UserID: uid, ClientID: "claude.ai",
				TelegramID: tgID, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
		}
		// Postgres keeps state between runs and token_hash is unique: clear
		// prior rows and use per-run plaintexts so the test is re-runnable.
		clear := func() {
			if _, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_refresh_tokens WHERE user_id = $1`, uid); err != nil {
				t.Errorf("round %d clear rows: %v", round, err)
			}
		}
		clear()
		t.Cleanup(clear)
		fam := fmt.Sprintf("race-fam-%d-%d", run, round)
		old := fmt.Sprintf("race-old-%d-%d", run, round)
		newPT := fmt.Sprintf("race-new-%d-%d", run, round)
		if err := s.SaveRefreshToken(ctx, old, mk(fam)); err != nil {
			t.Fatalf("round %d save: %v", round, err)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		var rotErr, delErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			rotErr = s.RotateRefreshToken(ctx, old, newPT, mk(fam))
		}()
		go func() {
			defer wg.Done()
			<-start
			_, delErr = s.HardDeleteAccount(ctx, uid)
		}()
		close(start)
		wg.Wait()

		if delErr != nil {
			t.Fatalf("round %d delete: %v", round, delErr)
		}
		if rotErr != nil && !errors.Is(rotErr, ErrRefreshTokenNotFound) {
			t.Fatalf("round %d rotate: %v", round, rotErr)
		}
		var live int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, uid).Scan(&live); err != nil {
			t.Fatalf("round %d count: %v", round, err)
		}
		if live != 0 {
			t.Fatalf("round %d: %d live refresh tokens left for a deleted account (rotErr=%v)", round, live, rotErr)
		}
	}
}

// A delete whose refresh-token revocation fails must roll back as a whole:
// the account row stays and the token stays live, so the caller never sees an
// account reported deleted while its clients keep rotating.
func TestHardDeleteAccount_RevocationFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	alice, err := s.EnsureUserByTelegramID(ctx, 4444, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure alice: %v", err)
	}
	seedAccount(t, s, alice, nil, nil, nil)
	if err := s.SaveRefreshToken(ctx, "rb-1", RefreshToken{FamilyID: "frb", UserID: alice,
		ClientID: "claude.ai", TelegramID: 1, Scope: "telegram:dialogs:read",
		ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Make the revocation UPDATE fail inside the delete transaction.
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_refresh_revoke
		BEFORE UPDATE ON oauth_refresh_tokens BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	t.Cleanup(func() { _, _ = s.DB.ExecContext(ctx, `DROP TRIGGER IF EXISTS fail_refresh_revoke`) })

	if _, err := s.HardDeleteAccount(ctx, alice); err == nil {
		t.Fatal("delete succeeded although revocation failed")
	}

	var accounts int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, alice).Scan(&accounts); err != nil {
		t.Fatalf("count accounts: %v", err)
	}
	if accounts != 1 {
		t.Errorf("telegram_accounts rows = %d after failed delete, want 1 (rolled back)", accounts)
	}
	rt, err := s.LookupRefreshToken(ctx, "rb-1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rt.Revoked() {
		t.Errorf("token revoked (reason %q) by a delete that failed", rt.RevokedReason)
	}
}
