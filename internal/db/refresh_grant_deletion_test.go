package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func liveRefreshTokens(t *testing.T, s *Store, uid int64) int {
	t.Helper()
	var live int
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, uid).Scan(&live); err != nil {
		t.Fatalf("count live refresh tokens: %v", err)
	}
	return live
}

// A code issued before the account was deleted must not mint a refresh
// family after it (#796); one issued after the delete, by a user who signed
// in again, still may.
func TestSaveRefreshTokenForGrant_RefusesGrantIssuedBeforeDelete(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		tgID := base + 1
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		mk := func() RefreshToken {
			return RefreshToken{FamilyID: fmt.Sprintf("grant-fam-%d-%d", tgID, time.Now().UnixNano()), UserID: uid,
				ClientID: "claude.ai", TelegramID: tgID, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
		}
		plain := func(tag string) string { return fmt.Sprintf("grant-%s-%d-%d", tag, tgID, time.Now().UnixNano()) }

		// Control: an account that was never deleted accepts the grant.
		if err := s.SaveRefreshTokenForGrant(ctx, plain("never-deleted"), mk(), time.Now().Add(-time.Minute)); err != nil {
			t.Fatalf("save for a never-deleted account: %v", err)
		}

		codeIssued := time.Now().UTC().Add(-time.Second)
		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		err = s.SaveRefreshTokenForGrant(ctx, plain("before"), mk(), codeIssued)
		if !errors.Is(err, ErrAccountDeletedSinceGrant) {
			t.Fatalf("save for a code issued before the delete: err = %v, want ErrAccountDeletedSinceGrant", err)
		}
		if n := liveRefreshTokens(t, s, uid); n != 0 {
			t.Fatalf("live refresh tokens after a refused grant = %d, want 0", n)
		}

		if err := s.SaveRefreshTokenForGrant(ctx, plain("after"), mk(), time.Now().UTC().Add(time.Second)); err != nil {
			t.Fatalf("save for a code issued after the delete: %v", err)
		}
		if n := liveRefreshTokens(t, s, uid); n != 1 {
			t.Fatalf("live refresh tokens after a post-delete grant = %d, want 1", n)
		}
	})
}

// An inconclusive dialect probe must fail the call rather than read as "not
// Postgres", which would drop the users-row lock on a live Postgres.
func TestCredentialWrites_FailOnInconclusiveDialectProbe(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 4646, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	mk := func(fam string) RefreshToken {
		return RefreshToken{FamilyID: fam, UserID: uid, ClientID: "claude.ai", TelegramID: 4646,
			Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
	}
	if err := s.SaveRefreshToken(ctx, "probe-old", mk("probe-fam")); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	s.pgMu.Lock()
	s.pgResolved = false
	s.probeFail = func() error { return errors.New("driver: bad connection") }
	s.pgMu.Unlock()

	if err := s.SaveRefreshTokenForGrant(ctx, "probe-grant", mk("probe-grant-fam"), time.Now()); err == nil {
		t.Error("SaveRefreshTokenForGrant succeeded on an inconclusive dialect probe")
	}
	if err := s.RotateRefreshToken(ctx, "probe-old", "probe-new", mk("probe-fam")); err == nil {
		t.Error("RotateRefreshToken succeeded on an inconclusive dialect probe")
	}
	if _, err := s.HardDeleteAccount(ctx, uid); err == nil {
		t.Error("HardDeleteAccount succeeded on an inconclusive dialect probe")
	}

	var total, live int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*), SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) FROM oauth_refresh_tokens WHERE user_id = $1`,
		uid).Scan(&total, &live); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	if total != 1 || live != 1 {
		t.Errorf("refresh tokens total=%d live=%d after refused writes, want only the seeded live one", total, live)
	}
	var deleted int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE id = $1 AND account_deleted_at IS NOT NULL`, uid).Scan(&deleted); err != nil {
		t.Fatalf("read deletion marker: %v", err)
	}
	if deleted != 0 {
		t.Error("a refused delete set account_deleted_at")
	}

	// Once the probe resolves again the same calls go through.
	s.pgMu.Lock()
	s.probeFail = nil
	s.pgMu.Unlock()
	if err := s.SaveRefreshTokenForGrant(ctx, "probe-grant", mk("probe-grant-fam"), time.Now()); err != nil {
		t.Errorf("save after the probe recovered: %v", err)
	}
}

// NewStore resolves the dialect from the driver, so the credential writes
// never depend on the probe for a store opened by Open.
func TestNewStore_ResolvesDialectFromDriver(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, _ int64) {
		fresh := NewStore(s.DB, nil)
		fresh.probeFail = func() error { return errors.New("driver: bad connection") }
		pg, err := fresh.postgresDialect(context.Background())
		if err != nil {
			t.Fatalf("dialect of a store opened by Open: %v", err)
		}
		// The subtest, not the driver, says which database this is: deriving
		// it from the driver type would repeat NewStore's own assertion.
		wantPg := strings.HasSuffix(t.Name(), "/postgres")
		if pg != wantPg {
			t.Fatalf("postgresDialect = %v, want %v", pg, wantPg)
		}
	})
}

// The code exchange and the delete race on Postgres: whichever commits first,
// no refresh token issued for a pre-delete code may be left live.
func TestSaveRefreshTokenForGrant_PostgresConcurrentDelete(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()

	run := time.Now().UnixNano()
	for round := 0; round < 10; round++ {
		tgID := int64(860000000 + round)
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
		if err != nil {
			t.Fatalf("round %d ensure: %v", round, err)
		}
		// The users row is reused across runs: clear an earlier run's marker
		// and tokens so the code below counts as issued before this delete.
		if _, err := s.DB.ExecContext(ctx, `UPDATE users SET account_deleted_at = NULL WHERE id = $1`, uid); err != nil {
			t.Fatalf("round %d reset marker: %v", round, err)
		}
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_refresh_tokens WHERE user_id = $1`, uid); err != nil {
			t.Fatalf("round %d clear rows: %v", round, err)
		}
		codeIssued := time.Now().UTC().Add(-time.Second)
		rt := RefreshToken{FamilyID: fmt.Sprintf("grant-race-fam-%d-%d", run, round), UserID: uid, ClientID: "claude.ai",
			TelegramID: tgID, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}

		var wg sync.WaitGroup
		start := make(chan struct{})
		var saveErr, delErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			saveErr = s.SaveRefreshTokenForGrant(ctx, fmt.Sprintf("grant-race-%d-%d", run, round), rt, codeIssued)
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
		if saveErr != nil && !errors.Is(saveErr, ErrAccountDeletedSinceGrant) {
			t.Fatalf("round %d save: %v", round, saveErr)
		}
		if n := liveRefreshTokens(t, s, uid); n != 0 {
			t.Fatalf("round %d: %d live refresh tokens after the delete (save err = %v)", round, n, saveErr)
		}
	}
}

// A delete that starts after the exchange read the deletion marker, but
// before it inserted the token, must wait for the insert and then revoke the
// new family. Without the share lock the delete finishes in between and the
// token it never saw stays live.
func TestSaveRefreshTokenForGrant_PostgresDeleteBetweenCheckAndInsert(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	tgID := int64(870000000)
	uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET account_deleted_at = NULL WHERE id = $1`, uid); err != nil {
		t.Fatalf("reset marker: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_refresh_tokens WHERE user_id = $1`, uid); err != nil {
		t.Fatalf("clear rows: %v", err)
	}

	delDone := make(chan error, 1)
	s.grantSaveHook = func() {
		go func() { _, err := s.HardDeleteAccount(ctx, uid); delDone <- err }()
		// Give the delete time to finish if nothing holds it back.
		select {
		case err := <-delDone:
			delDone <- err
		case <-time.After(500 * time.Millisecond):
		}
	}
	defer func() { s.grantSaveHook = nil }()

	run := time.Now().UnixNano()
	rt := RefreshToken{FamilyID: fmt.Sprintf("grant-gap-fam-%d", run), UserID: uid, ClientID: "claude.ai",
		TelegramID: tgID, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.SaveRefreshTokenForGrant(ctx, fmt.Sprintf("grant-gap-%d", run), rt, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := <-delDone; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n := liveRefreshTokens(t, s, uid); n != 0 {
		t.Fatalf("%d live refresh tokens after a delete that ran between the check and the insert", n)
	}
}
