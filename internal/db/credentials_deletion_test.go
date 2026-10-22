package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"
)

// deletionDialects runs body on SQLite and, when TEST_DATABASE_URL is set, on
// Postgres. base offsets the Telegram ids per dialect and per run, because the
// Postgres database is reused across runs.
func deletionDialects(t *testing.T, body func(t *testing.T, s *Store, base int64)) {
	t.Run("sqlite", func(t *testing.T) { body(t, newTestStore(t), 9100000) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		body(t, newPostgresTestStore(t, dsn), 9200000000+(time.Now().UnixNano()/1000)%100000000)
	})
}

// workerTokenLive reports whether a worker token for tgID issued at
// issuedAt would still authenticate.
func workerTokenLive(t *testing.T, s *Store, tgID int64, issuedAt time.Time) bool {
	t.Helper()
	revoked, err := s.IsWorkerTokenRevoked(context.Background(), fmt.Sprintf("jti-%d", tgID), tgID, issuedAt)
	if err != nil {
		t.Fatalf("revocation check for %d: %v", tgID, err)
	}
	return !revoked
}

func TestHardDeleteAccount_RevokesWorkerTokensAndDevices(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		aliceLogin, aliceSession, bobID := base+1, base+2, base+3
		alice, err := s.EnsureUserByTelegramID(ctx, aliceLogin, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure alice: %v", err)
		}
		bob, err := s.EnsureUserByTelegramID(ctx, bobID, "bob", "Bob")
		if err != nil {
			t.Fatalf("ensure bob: %v", err)
		}
		// The session's Telegram id differs from the login id on purpose:
		// both must be revoked.
		seedAccountForTelegramID(t, s, alice, aliceSession, nil)
		seedAccountForTelegramID(t, s, bob, bobID, nil)

		aliceDevice, err := s.RegisterDevice(ctx, alice, "laptop", "", nil)
		if err != nil {
			t.Fatalf("register alice device: %v", err)
		}
		bobDevice, err := s.RegisterDevice(ctx, bob, "laptop", "", nil)
		if err != nil {
			t.Fatalf("register bob device: %v", err)
		}
		// A device revoked before the delete keeps no label either.
		aliceOldDevice, err := s.RegisterDevice(ctx, alice, "old-laptop", "", nil)
		if err != nil {
			t.Fatalf("register alice old device: %v", err)
		}
		if err := s.RevokeDevice(ctx, aliceOldDevice, "user_revoked"); err != nil {
			t.Fatalf("revoke alice old device: %v", err)
		}

		issued := time.Now().UTC().Add(-time.Hour)
		for _, id := range []int64{aliceLogin, aliceSession, bobID} {
			if !workerTokenLive(t, s, id, issued) {
				t.Fatalf("token for %d revoked before the delete", id)
			}
		}

		if _, err := s.HardDeleteAccount(ctx, alice); err != nil {
			t.Fatalf("delete: %v", err)
		}

		for _, id := range []int64{aliceLogin, aliceSession} {
			if workerTokenLive(t, s, id, issued) {
				t.Errorf("worker token for %d still live after the delete", id)
			}
		}
		if !workerTokenLive(t, s, bobID, issued) {
			t.Error("another user's worker token was revoked")
		}
		var aliceName, bobName sql.NullString
		if err := s.DB.QueryRowContext(ctx, `SELECT telegram_username FROM users WHERE id = $1`, alice).Scan(&aliceName); err != nil {
			t.Fatalf("read alice username: %v", err)
		}
		if err := s.DB.QueryRowContext(ctx, `SELECT telegram_username FROM users WHERE id = $1`, bob).Scan(&bobName); err != nil {
			t.Fatalf("read bob username: %v", err)
		}
		if aliceName.Valid && aliceName.String != "" {
			t.Errorf("alice telegram_username = %q after the delete, want it cleared", aliceName.String)
		}
		if bobName.String != "bob" {
			t.Errorf("another user's telegram_username = %q, want it kept", bobName.String)
		}
		// One delete, one timestamp: the marker the code exchange checks and
		// the worker-token revocation carry the same moment.
		var sameMoment int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users u JOIN worker_token_revocations w
			   ON w.telegram_id = $2 AND w.jti IS NULL AND w.revoked_at = u.account_deleted_at
			 WHERE u.id = $1`, alice, aliceLogin).Scan(&sameMoment); err != nil {
			t.Fatalf("compare delete timestamps: %v", err)
		}
		if sameMoment != 1 {
			t.Error("account_deleted_at and the worker-token revocation carry different times")
		}
		// A credential minted after the delete (a reconnect) still works.
		for _, id := range []int64{aliceLogin, aliceSession} {
			if !workerTokenLive(t, s, id, time.Now().UTC().Add(time.Minute)) {
				t.Errorf("worker token for %d minted after the delete is revoked", id)
			}
		}

		d, err := s.GetDevice(ctx, aliceDevice)
		if err != nil {
			t.Fatalf("get alice device: %v", err)
		}
		if d.RevokedAt == nil || d.RevokedReason != ReasonAccountDeleted {
			t.Errorf("alice device revoked_at=%v reason=%q, want revoked with %q", d.RevokedAt, d.RevokedReason, ReasonAccountDeleted)
		}
		if d.DeviceLabel != "" {
			t.Errorf("alice device label = %q after the delete, want it cleared", d.DeviceLabel)
		}
		d, err = s.GetDevice(ctx, aliceOldDevice)
		if err != nil {
			t.Fatalf("get alice old device: %v", err)
		}
		if d.DeviceLabel != "" {
			t.Errorf("alice earlier-revoked device label = %q after the delete, want it cleared", d.DeviceLabel)
		}
		if d.RevokedReason != "user_revoked" {
			t.Errorf("alice earlier-revoked device reason = %q, want it left as %q", d.RevokedReason, "user_revoked")
		}
		if claimed, err := s.ClaimDeviceCredentialLineage(ctx, aliceDevice, "after-delete", time.Now()); err != nil || claimed {
			t.Errorf("revoked device claimed a credential lineage: claimed=%v err=%v", claimed, err)
		}
		d, err = s.GetDevice(ctx, bobDevice)
		if err != nil {
			t.Fatalf("get bob device: %v", err)
		}
		if d.RevokedAt != nil {
			t.Error("another user's device was revoked")
		}
		if d.DeviceLabel != "laptop" {
			t.Errorf("another user's device label = %q, want it kept", d.DeviceLabel)
		}
	})
}

// A user created before telegram_login_id existed carries only the synthetic
// "tg:<id>" login, which authentication still maps a token to.
func TestHardDeleteAccount_RevokesWorkerTokensForLegacyLogin(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		tgID := base + 4
		uid, err := s.EnsureUser(ctx, fmt.Sprintf("tg:%d", tgID), "", "tg-mcp")
		if err != nil {
			t.Fatalf("ensure legacy user: %v", err)
		}
		seedAccount(t, s, uid, nil, nil, nil)
		issued := time.Now().UTC().Add(-time.Hour)

		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if workerTokenLive(t, s, tgID, issued) {
			t.Error("worker token for a legacy tg: login still live after the delete")
		}
	})
}

// A delete whose credential revocation fails must roll back as a whole, as
// the refresh-token revocation does.
func TestHardDeleteAccount_WorkerTokenRevocationFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 4545, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	seedAccount(t, s, uid, nil, nil, nil)
	device, err := s.RegisterDevice(ctx, uid, "laptop", "", nil)
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_worker_revoke
		BEFORE INSERT ON worker_token_revocations BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	t.Cleanup(func() { _, _ = s.DB.ExecContext(ctx, `DROP TRIGGER IF EXISTS fail_worker_revoke`) })

	if _, err := s.HardDeleteAccount(ctx, uid); err == nil {
		t.Fatal("delete succeeded although the worker-token revocation failed")
	}
	var accounts int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&accounts); err != nil {
		t.Fatalf("count accounts: %v", err)
	}
	if accounts != 1 {
		t.Errorf("telegram_accounts rows = %d after a failed delete, want 1", accounts)
	}
	d, err := s.GetDevice(ctx, device)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if d.RevokedAt != nil {
		t.Error("device revoked by a delete that rolled back")
	}
}

// A user whose login is not the synthetic "tg:<id>" (an account first created
// through another provider) reaches worker tokens only through
// telegram_login_id.
func TestHardDeleteAccount_RevokesWorkerTokensForBoundLoginID(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		tgID := base + 5
		uid, err := s.EnsureUser(ctx, fmt.Sprintf("someone-%d", tgID), "", "mctl-api")
		if err != nil {
			t.Fatalf("ensure user: %v", err)
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE users SET telegram_login_id = $1 WHERE id = $2`, tgID, uid); err != nil {
			t.Fatalf("bind telegram login id: %v", err)
		}
		seedAccount(t, s, uid, nil, nil, nil)
		issued := time.Now().UTC().Add(-time.Hour)

		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if workerTokenLive(t, s, tgID, issued) {
			t.Error("worker token for a bound telegram_login_id still live after the delete")
		}
	})
}

// Deleting is callable with nothing left to delete. A repeat must move the
// revocation forward, not add rows to a table the revocation cache reads
// whole.
func TestHardDeleteAccount_RepeatDeleteKeepsOneRevocationPerTelegramID(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		tgID := base + 6
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		seedAccountForTelegramID(t, s, uid, tgID, nil)
		// An operator's blanket revocation for the same id is not ours to move.
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO worker_token_revocations (jti, telegram_id, revoked_at, reason, revoked_by)
			 VALUES (NULL, $1, $2, 'operator', NULL)`, tgID, time.Now().UTC().Add(-time.Hour)); err != nil {
			t.Fatalf("seed operator revocation: %v", err)
		}
		for i := 0; i < 3; i++ {
			if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
				t.Fatalf("delete %d: %v", i, err)
			}
		}
		var ours, operator int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM worker_token_revocations WHERE jti IS NULL AND telegram_id = $1 AND reason = $2`,
			tgID, ReasonAccountDeleted).Scan(&ours); err != nil {
			t.Fatalf("count delete revocations: %v", err)
		}
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM worker_token_revocations WHERE jti IS NULL AND telegram_id = $1 AND reason = 'operator'`,
			tgID).Scan(&operator); err != nil {
			t.Fatalf("count operator revocations: %v", err)
		}
		if ours != 1 || operator != 1 {
			t.Fatalf("revocation rows after three deletes: ours=%d operator=%d, want 1 and 1", ours, operator)
		}
		if workerTokenLive(t, s, tgID, time.Now().UTC().Add(-time.Second)) {
			t.Error("a repeat delete stopped revoking tokens issued before it")
		}
	})
}

// github_login is nullable on Postgres; a user without one must still be
// deletable.
func TestHardDeleteAccount_NullGithubLogin(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	tgID := 9500000000 + (time.Now().UnixNano()/1000)%100000000
	uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET github_login = NULL WHERE id = $1`, uid); err != nil {
		t.Fatalf("clear github_login: %v", err)
	}
	seedAccountForTelegramID(t, s, uid, tgID, nil)
	if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
		t.Fatalf("delete a user with a NULL github_login: %v", err)
	}
	if workerTokenLive(t, s, tgID, time.Now().UTC().Add(-time.Hour)) {
		t.Error("worker token still live after the delete")
	}
}

// A device that already holds a credential lineage loses it with the account.
func TestHardDeleteAccount_RevokesIssuedDeviceCredential(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		tgID := base + 7
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		seedAccountForTelegramID(t, s, uid, tgID, nil)
		device, err := s.RegisterDevice(ctx, uid, "laptop", "", nil)
		if err != nil {
			t.Fatalf("register device: %v", err)
		}
		issued := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
		jti := fmt.Sprintf("lineage-%d", tgID)
		if claimed, err := s.ClaimDeviceCredentialLineage(ctx, device, jti, issued); err != nil || !claimed {
			t.Fatalf("claim lineage: claimed=%v err=%v", claimed, err)
		}
		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		d, err := s.GetDevice(ctx, device)
		if err != nil {
			t.Fatalf("get device: %v", err)
		}
		if d.CurrentJti != jti || d.CredentialIssuedAt == nil {
			t.Fatalf("device lineage = (%q, %v), want (%q, set)", d.CurrentJti, d.CredentialIssuedAt, jti)
		}
		revoked, err := s.IsWorkerTokenRevoked(ctx, d.CurrentJti, tgID, *d.CredentialIssuedAt)
		if err != nil {
			t.Fatalf("revocation check: %v", err)
		}
		if !revoked {
			t.Error("the device's issued credential still authenticates after the delete")
		}
	})
}
