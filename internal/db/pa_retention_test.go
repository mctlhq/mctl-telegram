package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// Retention and account deletion of the Personal Assistant linking state
// (#1338). They run on SQLite always and on Postgres when TEST_DATABASE_URL
// is set.

// TestPALinkSecretRetention_Bounds pins the retention window. Longer keeps a
// spent secret's principal, server and masked account past any reader's
// need; shorter than an hour could delete an expired, unconsumed row before
// the linking sweep has had a pass to fail its connection.
func TestPALinkSecretRetention_Bounds(t *testing.T) {
	if PALinkSecretRetention > 24*time.Hour {
		t.Errorf("PALinkSecretRetention = %s, want at most 24h", PALinkSecretRetention)
	}
	if PALinkSecretRetention < time.Hour {
		t.Errorf("PALinkSecretRetention = %s, want at least 1h", PALinkSecretRetention)
	}
}

// seedPALinkSecret creates a secret of principal expiring at expires and, if
// consumed, consumes it a minute before that.
func seedPALinkSecret(t *testing.T, s *Store, principal int64, expires time.Time, consumed bool) string {
	t.Helper()
	ctx := context.Background()
	h := paHash(fmt.Sprintf("ret-%d-%s", principal, randomSuffix(t)))
	created := expires.Add(-10 * time.Minute)
	if err := s.CreatePALinkSecret(ctx, PALinkSecret{Hash: h, Kind: PALinkConfirm, Principal: principal, Server: "tg",
		ConnectionID: "pac_ret", Revision: 4, AccountHint: "A***123", ExpiresAt: expires}, created); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if consumed {
		if _, err := s.ConsumePALinkSecret(ctx, PALinkConfirm, h, expires.Add(-time.Minute), nil); err != nil {
			t.Fatalf("consume secret: %v", err)
		}
	}
	return h
}

func paLinkSecretExists(t *testing.T, s *Store, hash string) bool {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM pa_link_secrets WHERE hash = $1`, hash).Scan(&n); err != nil {
		t.Fatalf("count secret: %v", err)
	}
	return n == 1
}

func TestSweepPAState_DeletesLinkSecretsPastRetention(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		now := time.Now()
		past := now.Add(-PALinkSecretRetention - time.Minute)
		within := now.Add(-PALinkSecretRetention + time.Minute)
		cases := []struct {
			name     string
			expires  time.Time
			consumed bool
			keep     bool
		}{
			{"expired unused past retention", past, false, false},
			{"consumed, expired past retention", past, true, false},
			{"expired unused within retention", within, false, true},
			{"consumed, expired within retention", within, true, true},
			{"consumed, not yet expired", now.Add(5 * time.Minute), true, true},
			{"live", now.Add(5 * time.Minute), false, true},
		}
		hashes := make([]string, len(cases))
		for i, c := range cases {
			hashes[i] = seedPALinkSecret(t, s, p, c.expires, c.consumed)
		}
		if _, err := s.SweepPAState(ctx, now, now.Add(-48*time.Hour)); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		for i, c := range cases {
			if got := paLinkSecretExists(t, s, hashes[i]); got != c.keep {
				t.Errorf("%s: row kept = %v, want %v", c.name, got, c.keep)
			}
		}
	})
}

// seedPAConnection creates a pending connection of principal.
func seedPAConnection(t *testing.T, s *Store, principal int64) string {
	t.Helper()
	id := fmt.Sprintf("pac_del_%d_%s", principal, randomSuffix(t))
	if err := s.CreatePAConnection(context.Background(), connection.Connection{
		ID: id, Principal: principal, Server: connection.ServerTG, State: connection.StatePendingLink, AuthorityRevision: 1,
	}, connection.Sealed{KEKID: "test", WrappedDEK: []byte("wrapped")}); err != nil {
		t.Fatalf("create connection: %v", err)
	}
	t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE id = $1`, id) })
	return id
}

// paRowCounts returns the pa_connections and pa_link_secrets rows of
// principal.
func paRowCounts(t *testing.T, s *Store, principal int64) (conns, secrets int) {
	t.Helper()
	ctx := context.Background()
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM pa_connections WHERE principal = $1`, principal).Scan(&conns); err != nil {
		t.Fatalf("count connections: %v", err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM pa_link_secrets WHERE principal = $1`, principal).Scan(&secrets); err != nil {
		t.Fatalf("count secrets: %v", err)
	}
	return conns, secrets
}

func TestHardDeleteAccount_PurgesPALinkingState(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		aliceLogin, aliceSession, bobID := base+21, base+22, base+23
		for _, p := range []int64{aliceLogin, aliceSession, bobID} {
			p := p
			t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_link_secrets WHERE principal = $1`, p) })
		}
		alice, err := s.EnsureUserByTelegramID(ctx, aliceLogin, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure alice: %v", err)
		}
		bob, err := s.EnsureUserByTelegramID(ctx, bobID, "bob", "Bob")
		if err != nil {
			t.Fatalf("ensure bob: %v", err)
		}
		// The session's Telegram id differs from the login id on purpose:
		// the PA rows of both go.
		seedAccountForTelegramID(t, s, alice, aliceSession, nil)
		seedAccountForTelegramID(t, s, bob, bobID, nil)
		now := time.Now()
		for _, p := range []int64{aliceLogin, aliceSession, bobID} {
			seedPAConnection(t, s, p)
			seedPAConnection(t, s, p)
			seedPALinkSecret(t, s, p, now.Add(5*time.Minute), false)
			seedPALinkSecret(t, s, p, now.Add(5*time.Minute), true)
		}

		if _, err := s.HardDeleteAccount(ctx, alice); err != nil {
			t.Fatalf("delete alice: %v", err)
		}
		for _, p := range []int64{aliceLogin, aliceSession} {
			if c, l := paRowCounts(t, s, p); c != 0 || l != 0 {
				t.Errorf("principal %d after delete: %d connections, %d secrets, want 0 and 0", p, c, l)
			}
		}
		if c, l := paRowCounts(t, s, bobID); c != 2 || l != 2 {
			t.Errorf("bob after alice's delete: %d connections, %d secrets, want 2 and 2", c, l)
		}
	})
}

// An account without PA rows deletes as it did before: its account rows go
// and the count is unchanged.
func TestHardDeleteAccount_WithoutPALinkingState(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		tgID := base + 24
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "carol", "Carol")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		seedAccountForTelegramID(t, s, uid, tgID, nil)
		rows, err := s.HardDeleteAccount(ctx, uid)
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		if rows != 1 {
			t.Errorf("rows removed = %d, want 1", rows)
		}
		var accounts int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&accounts); err != nil {
			t.Fatalf("count accounts: %v", err)
		}
		if accounts != 0 {
			t.Errorf("telegram_accounts rows = %d after the delete, want 0", accounts)
		}
	})
}

// isolatedDialects runs body on a SQLite database and a Postgres schema of
// its own, so a test may break a table without touching any other test.
func isolatedDialects(t *testing.T, body func(t *testing.T, s *Store)) {
	t.Run("sqlite", func(t *testing.T) {
		ctx := context.Background()
		conn, err := Open(ctx, "file:pa_iso_"+randomSuffix(t)+"?mode=memory&cache=shared", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := MigrateCached(ctx, conn); err != nil {
			t.Fatal(err)
		}
		body(t, &Store{DB: conn})
	})
	t.Run("postgres", func(t *testing.T) { body(t, newFreshSchemaPostgresStore(t)) })
}

// A failed PA delete fails the account deletion, and the deletion rolls back
// as a whole: the account and every PA row are still there.
func TestHardDeleteAccount_PALinkingPurgeFailureRollsBack(t *testing.T) {
	for _, table := range []string{"pa_link_secrets", "pa_connections"} {
		t.Run(table, func(t *testing.T) {
			isolatedDialects(t, func(t *testing.T, s *Store) {
				ctx := context.Background()
				const tgID = int64(4646)
				uid, err := s.EnsureUserByTelegramID(ctx, tgID, "dana", "Dana")
				if err != nil {
					t.Fatalf("ensure: %v", err)
				}
				seedAccountForTelegramID(t, s, uid, tgID, nil)
				seedPAConnection(t, s, tgID)
				seedPALinkSecret(t, s, tgID, time.Now().Add(5*time.Minute), false)
				// The other table stays readable, so the rollback is visible
				// in it.
				if _, err := s.DB.ExecContext(ctx, `ALTER TABLE `+table+` RENAME TO `+table+`_broken`); err != nil {
					t.Fatalf("break %s: %v", table, err)
				}

				if _, err := s.HardDeleteAccount(ctx, uid); err == nil {
					t.Fatalf("delete succeeded although deleting from %s failed", table)
				}
				if _, err := s.DB.ExecContext(ctx, `ALTER TABLE `+table+`_broken RENAME TO `+table); err != nil {
					t.Fatalf("restore %s: %v", table, err)
				}
				var accounts int
				if err := s.DB.QueryRowContext(ctx,
					`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&accounts); err != nil {
					t.Fatalf("count accounts: %v", err)
				}
				if accounts != 1 {
					t.Errorf("telegram_accounts rows = %d after a failed delete, want 1", accounts)
				}
				if c, l := paRowCounts(t, s, tgID); c != 1 || l != 1 {
					t.Errorf("PA rows after a failed delete: %d connections, %d secrets, want 1 and 1", c, l)
				}
			})
		})
	}
}
