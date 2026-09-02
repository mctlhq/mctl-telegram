package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// TestProvisionLocalAccount_CreatesSessionlessRow covers acceptance criterion
// 1: provisioning a brand-new Telegram id (no prior hosted login, no prior
// users row) inserts a telegram_accounts row with mode='local' and
// session_encrypted IS NULL, without requiring any prior session.
func TestProvisionLocalAccount_CreatesSessionlessRow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 700000001, "newlocal", "New Local")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.ProvisionLocalAccount(ctx, uid, 700000001, "New Local", "newlocal"); err != nil {
		t.Fatalf("provision local account: %v", err)
	}
	var (
		mode    string
		session sql.NullString
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT mode, session_encrypted FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&mode, &session); err != nil {
		t.Fatalf("query row: %v", err)
	}
	if mode != ModeLocal {
		t.Errorf("mode = %q, want %q", mode, ModeLocal)
	}
	if session.Valid {
		t.Errorf("session_encrypted = %q, want NULL", session.String)
	}
}

// TestProvisionLocalAccount_RefusesExistingActiveAccount covers acceptance
// criterion 9: an id with an already-active row (hosted or local) is
// refused, and no second row is inserted.
func TestProvisionLocalAccount_RefusesExistingActiveAccount(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "existing", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted) VALUES($1,$2,$3)`,
		uid, 700000002, []byte("blob"),
	); err != nil {
		t.Fatalf("seed active hosted account: %v", err)
	}

	err = s.ProvisionLocalAccount(ctx, uid, 700000002, "", "")
	if !errors.Is(err, ErrAccountAlreadyActive) {
		t.Fatalf("expected ErrAccountAlreadyActive, got %v", err)
	}

	var count int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Errorf("row count = %d, want 1 (no second row inserted)", count)
	}
}

// TestGetAccountMode_HostedBehaviorUnchanged pins that narrowing
// GetAccountMode's query (dropping the revoked_at IS NULL predicate) does
// not change any existing hosted-path result.
func TestGetAccountMode_HostedBehaviorUnchanged(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	t.Run("no rows at all", func(t *testing.T) {
		uid, err := s.EnsureUser(ctx, "hosted-none", "", "test")
		if err != nil {
			t.Fatalf("ensure user: %v", err)
		}
		mode, err := s.GetAccountMode(ctx, uid)
		if err != nil {
			t.Fatalf("get account mode: %v", err)
		}
		if mode != ModeHosted {
			t.Errorf("mode = %q, want %q", mode, ModeHosted)
		}
	})

	t.Run("only a revoked hosted row", func(t *testing.T) {
		uid, err := s.EnsureUser(ctx, "hosted-revoked", "", "test")
		if err != nil {
			t.Fatalf("ensure user: %v", err)
		}
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, revoked_at)
			 VALUES($1,$2,$3,CURRENT_TIMESTAMP)`,
			uid, 700000003, []byte("blob"),
		); err != nil {
			t.Fatalf("seed revoked hosted row: %v", err)
		}
		mode, err := s.GetAccountMode(ctx, uid)
		if err != nil {
			t.Fatalf("get account mode: %v", err)
		}
		if mode != ModeHosted {
			t.Errorf("mode = %q, want %q", mode, ModeHosted)
		}
	})

	t.Run("revoked hosted row then a fresh hosted reconnect", func(t *testing.T) {
		uid, err := s.EnsureUser(ctx, "hosted-reconnect", "", "test")
		if err != nil {
			t.Fatalf("ensure user: %v", err)
		}
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, revoked_at, connected_at)
			 VALUES($1,$2,$3,CURRENT_TIMESTAMP,$4)`,
			uid, 700000004, []byte("blob"), time.Now().UTC().Add(-time.Hour),
		); err != nil {
			t.Fatalf("seed old revoked row: %v", err)
		}
		// A fresh hosted login always inserts a new row with the latest
		// connected_at and the default mode='hosted'.
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted)
			 VALUES($1,$2,$3)`,
			uid, 700000004, []byte("blob2"),
		); err != nil {
			t.Fatalf("seed fresh row: %v", err)
		}
		mode, err := s.GetAccountMode(ctx, uid)
		if err != nil {
			t.Fatalf("get account mode: %v", err)
		}
		if mode != ModeHosted {
			t.Errorf("mode = %q, want %q (the new row must win)", mode, ModeHosted)
		}
	})
}

// TestGetAccountMode_SurvivesRevocationWhenLocal is the direct test of
// acceptance criterion 4: revoking the hosted session of a migrated local
// account (or sweeping it) must not make GetAccountMode -- and therefore
// /bridge -- start treating the account as hosted again.
func TestGetAccountMode_SurvivesRevocationWhenLocal(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "local-survives-revoke", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, mode)
		 VALUES($1,$2,$3,$4)`,
		uid, 700000005, []byte("blob"), ModeLocal,
	); err != nil {
		t.Fatalf("seed local row: %v", err)
	}

	mode, err := s.GetAccountMode(ctx, uid)
	if err != nil {
		t.Fatalf("get account mode before revoke: %v", err)
	}
	if mode != ModeLocal {
		t.Fatalf("mode before revoke = %q, want %q", mode, ModeLocal)
	}

	// Simulate a disconnect or a TTL sweep setting revoked_at directly.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1`, uid,
	); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	mode, err = s.GetAccountMode(ctx, uid)
	if err != nil {
		t.Fatalf("get account mode after revoke: %v", err)
	}
	if mode != ModeLocal {
		t.Errorf("mode after revoke = %q, want %q -- revocation must not flip mode", mode, ModeLocal)
	}
}

// TestSweepIdleSessionsSkipsLocalMode is the direct acceptance-criteria test:
// a mode='local' row, stale past the idle TTL, with no TTL exemption
// configured at all, must survive SweepIdleSessions. The exemption list is
// no longer load-bearing for local accounts.
func TestSweepIdleSessionsSkipsLocalMode(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t) // no WithAbsoluteTTLExempt call: ttlExempt is empty
	uid, err := s.EnsureUser(ctx, "sweep-idle-local", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	stale := time.Now().UTC().Add(-40 * 24 * time.Hour) // past the 30d idle TTL
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, mode)
		 VALUES($1,$2,$3,$4,$5)`,
		uid, 700000006, []byte("blob"), stale, ModeLocal,
	); err != nil {
		t.Fatalf("seed stale local row: %v", err)
	}

	rows, err := s.SweepIdleSessions(ctx)
	if err != nil {
		t.Fatalf("sweep idle: %v", err)
	}
	if rows != 0 {
		t.Errorf("idle sweep revoked %d rows, want 0 -- local-mode rows must survive unconditionally", rows)
	}
	var revoked sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&revoked); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	if revoked.Valid {
		t.Error("local-mode row must survive the idle sweep")
	}
}

// TestSweepIdleSessionsTwoSided_HostedVsLocal is the mutation guard: one
// mode='local' row and one mode='hosted' row, both equally stale, neither
// TTL-exempt. Exactly the hosted row must be revoked. This is written so
// that flipping or deleting the sweeper's `mode <> 'local'` predicate
// changes WHICH row survives, unlike a test that only asserts "hosted gets
// swept" (which passes on both the fixed and the broken predicate).
func TestSweepIdleSessionsTwoSided_HostedVsLocal(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "sweep-idle-two-sided", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	stale := time.Now().UTC().Add(-40 * 24 * time.Hour)
	const localTgID, hostedTgID = 700000007, 700000008
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, mode)
		 VALUES($1,$2,$3,$4,$5)`,
		uid, localTgID, []byte("blob"), stale, ModeLocal,
	); err != nil {
		t.Fatalf("seed local row: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, mode)
		 VALUES($1,$2,$3,$4,$5)`,
		uid, hostedTgID, []byte("blob"), stale, ModeHosted,
	); err != nil {
		t.Fatalf("seed hosted row: %v", err)
	}

	rows, err := s.SweepIdleSessions(ctx)
	if err != nil {
		t.Fatalf("sweep idle: %v", err)
	}
	if rows != 1 {
		t.Fatalf("idle sweep revoked %d rows, want exactly 1", rows)
	}

	var localRevoked, hostedRevoked sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM telegram_accounts WHERE telegram_user_id = $1`, localTgID,
	).Scan(&localRevoked); err != nil {
		t.Fatalf("read local revoked_at: %v", err)
	}
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM telegram_accounts WHERE telegram_user_id = $1`, hostedTgID,
	).Scan(&hostedRevoked); err != nil {
		t.Fatalf("read hosted revoked_at: %v", err)
	}
	if localRevoked.Valid {
		t.Error("the local-mode row must not be revoked")
	}
	if !hostedRevoked.Valid {
		t.Error("the hosted-mode row must be revoked")
	}
}

// TestSweepAbsoluteSessionsSkipsLocalMode covers a migrated local account
// whose original expires_at (stamped by its hosted SaveSession call) has
// already elapsed -- the absolute sweep must not touch it either.
func TestSweepAbsoluteSessionsSkipsLocalMode(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "sweep-absolute-local", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	past := time.Now().UTC().Add(-24 * time.Hour)
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, expires_at, mode)
		 VALUES($1,$2,$3,$4,$5)`,
		uid, 700000009, []byte("blob"), past, ModeLocal,
	); err != nil {
		t.Fatalf("seed expired local row: %v", err)
	}

	rows, err := s.SweepAbsoluteSessions(ctx)
	if err != nil {
		t.Fatalf("sweep absolute: %v", err)
	}
	if rows != 0 {
		t.Errorf("absolute sweep revoked %d rows, want 0 -- local-mode rows must survive unconditionally", rows)
	}
	var revoked sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&revoked); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	if revoked.Valid {
		t.Error("local-mode row must survive the absolute sweep")
	}
}
