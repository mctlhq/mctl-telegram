package db

import (
	"context"
	"database/sql"
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
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4, $5)`,
		uid, 555, []byte("blob"), now, now.Add(90*24*time.Hour),
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.CheckSessionValid(ctx, uid); err != nil {
		t.Fatalf("expected fresh session to pass, got %v", err)
	}
}

// TestCheckSessionValid_UnauthorizedSession covers a row the gotd
// SessionStore inserted mid-login (telegram_user_id NULL) that enable_access
// never finalised. CheckSessionValid must reject it with ErrSessionUnauthorized
// and revoke the row so a reconnect re-runs enable_access.
func TestCheckSessionValid_UnauthorizedSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "mallory", "", "test")
	now := time.Now().UTC()
	// No telegram_user_id — mirrors UpdateSessionBlob's mid-login insert.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4)`,
		uid, []byte("blob"), now, now.Add(90*24*time.Hour),
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.CheckSessionValid(ctx, uid); !errors.Is(err, ErrSessionUnauthorized) {
		t.Fatalf("expected ErrSessionUnauthorized, got %v", err)
	}
	var revoked bool
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at IS NOT NULL FROM telegram_accounts WHERE user_id=$1`, uid,
	).Scan(&revoked); err != nil {
		t.Fatalf("check revoked: %v", err)
	}
	if !revoked {
		t.Fatal("unauthorized session should be revoked in-place")
	}
}

func TestCheckSessionValid_IdleExpiryRevokes(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "bob", "", "test")
	now := time.Now().UTC()
	stale := now.Add(-31 * 24 * time.Hour) // older than 30-day idle TTL
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4, $5)`,
		uid, 555, []byte("blob"), stale, now.Add(60*24*time.Hour),
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
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4, $5)`,
		uid, 555, []byte("blob"), now, now.Add(-time.Hour), // expired an hour ago
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

// seedAccountForTelegramID inserts a finalised session row for a specific
// Telegram id, so the exemption (which is keyed on telegram_user_id) applies.
func seedAccountForTelegramID(t *testing.T, s *Store, userID, tgID int64, expiresAt *time.Time) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(context.Background(),
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,$5)`,
		userID, tgID, []byte("blob"), now, expiresAt,
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}
}

func expiresAtFor(t *testing.T, s *Store, tgID int64) sql.NullTime {
	t.Helper()
	var got sql.NullTime
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT expires_at FROM telegram_accounts WHERE telegram_user_id = $1`, tgID,
	).Scan(&got); err != nil {
		t.Fatalf("read expires_at for %d: %v", tgID, err)
	}
	return got
}

// TestReconcileTTLExemptions covers both directions: an exempt identity has its
// absolute deadline cleared, a non-exempt one keeps it.
func TestReconcileTTLExemptions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "ttl-user", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deadline := time.Now().UTC().Add(30 * 24 * time.Hour)
	seedAccountForTelegramID(t, s, uid, 210408407, &deadline)
	seedAccountForTelegramID(t, s, uid, 999000111, &deadline)

	s = s.WithAbsoluteTTLExempt([]int64{210408407})
	cleared, err := s.ReconcileTTLExemptions(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if cleared != 1 {
		t.Errorf("cleared = %d, want 1", cleared)
	}
	if got := expiresAtFor(t, s, 210408407); got.Valid {
		t.Errorf("exempt identity must have NULL expires_at, got %v", got.Time)
	}
	if got := expiresAtFor(t, s, 999000111); !got.Valid {
		t.Error("non-exempt identity must keep its absolute deadline")
	}

	// Idempotent: a second pass has nothing left to clear.
	if again, err := s.ReconcileTTLExemptions(ctx); err != nil || again != 0 {
		t.Errorf("second pass cleared = %d err = %v, want 0/nil", again, err)
	}
}

// TestReconcileTTLExemptionsIsReversible pins the escape hatch: dropping an id
// from the list must let the Migrate backfill re-arm its TTL, otherwise an
// exemption granted once could never be taken back.
func TestReconcileTTLExemptionsIsReversible(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "ttl-reversible", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deadline := time.Now().UTC().Add(30 * 24 * time.Hour)
	seedAccountForTelegramID(t, s, uid, 210408407, &deadline)

	if _, err := s.WithAbsoluteTTLExempt([]int64{210408407}).ReconcileTTLExemptions(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := expiresAtFor(t, s, 210408407); got.Valid {
		t.Fatal("precondition: expires_at should be NULL")
	}

	// Identity removed from the list, then the boot sequence runs again.
	s = s.WithAbsoluteTTLExempt(nil)
	if err := Migrate(ctx, s.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := s.ReconcileTTLExemptions(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := expiresAtFor(t, s, 210408407); !got.Valid {
		t.Error("dropping an identity from the list must re-arm its absolute TTL")
	}
}

// TestSweepAbsoluteSessionsSkipsExempt is the payoff: the sweeper that revoked
// the operator's session on 2026-08-23 must walk past an exempt identity even
// when its original deadline is long past.
func TestSweepAbsoluteSessionsSkipsExempt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "ttl-sweep", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	past := time.Now().UTC().Add(-24 * time.Hour)
	seedAccountForTelegramID(t, s, uid, 210408407, &past)
	seedAccountForTelegramID(t, s, uid, 999000111, &past)

	s = s.WithAbsoluteTTLExempt([]int64{210408407})
	if _, err := s.ReconcileTTLExemptions(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	rows, err := s.SweepAbsoluteSessions(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rows != 1 {
		t.Errorf("sweep revoked %d rows, want 1 (only the non-exempt one)", rows)
	}

	var revoked sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM telegram_accounts WHERE telegram_user_id = 210408407`,
	).Scan(&revoked); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	if revoked.Valid {
		t.Error("exempt session must survive the absolute sweep")
	}
}

// TestSaveSessionExemptIdentityHasNoDeadline covers a fresh connect: the
// exemption must apply at insert time, not only after the next restart.
func TestSaveSessionExemptIdentityHasNoDeadline(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t).WithAbsoluteTTLExempt([]int64{210408407})
	uid, err := s.EnsureUser(ctx, "ttl-save", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.SaveSession(ctx, uid, []byte("blob"), 210408407, "Op", "op"); err != nil {
		t.Fatalf("save exempt session: %v", err)
	}
	if got := expiresAtFor(t, s, 210408407); got.Valid {
		t.Errorf("exempt identity must be inserted with NULL expires_at, got %v", got.Time)
	}

	uid2, err := s.EnsureUser(ctx, "ttl-save-other", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.SaveSession(ctx, uid2, []byte("blob"), 999000111, "Other", "other"); err != nil {
		t.Fatalf("save normal session: %v", err)
	}
	if got := expiresAtFor(t, s, 999000111); !got.Valid {
		t.Error("a normal identity must still get an absolute deadline")
	}
}

// TestCheckSessionValidAcceptsExempt proves the read path agrees with the
// sweeper: no absolute-expiry rejection for an exempt identity.
func TestCheckSessionValidAcceptsExempt(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t).WithAbsoluteTTLExempt([]int64{210408407})
	uid, err := s.EnsureUser(ctx, "ttl-check", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.SaveSession(ctx, uid, []byte("blob"), 210408407, "Op", "op"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := s.CheckSessionValid(ctx, uid); err != nil {
		t.Errorf("exempt session must validate, got %v", err)
	}
}

// TestMigrateLeavesExemptRowsNull is the multi-replica race guard. Migrate runs
// on every boot; if its backfill re-armed an exempt row, the deadline it writes
// for an identity already past the 90-day mark is in the past immediately, and
// another replica's sweeper tick or an inline CheckSessionValid could revoke
// the row before this replica reaches ReconcileTTLExemptions — which only
// clears expires_at and never touches revoked_at. That would reproduce #409 on
// a routine rolling restart, so the intermediate state must never exist.
func TestMigrateLeavesExemptRowsNull(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "ttl-race", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	seedAccountForTelegramID(t, s, uid, 210408407, nil)
	seedAccountForTelegramID(t, s, uid, 999000111, nil)

	if err := Migrate(ctx, s.DB, 210408407); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := expiresAtFor(t, s, 210408407); got.Valid {
		t.Errorf("exempt row must stay NULL through Migrate, got %v", got.Time)
	}
	if got := expiresAtFor(t, s, 999000111); !got.Valid {
		t.Error("a non-exempt NULL row must still be backfilled")
	}
}

// TestSweepIdleSessionsSkipsExempt pins the fix for #413: the exemption now
// lifts both the absolute ceiling and the idle TTL. An exempt identity
// nobody has used for longer than the idle TTL must survive the idle sweep.
func TestSweepIdleSessionsSkipsExempt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t).WithAbsoluteTTLExempt([]int64{210408407})
	uid, err := s.EnsureUser(ctx, "ttl-idle-exempt", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	stale := time.Now().UTC().Add(-40 * 24 * time.Hour) // past the 30d idle TTL
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,NULL)`,
		uid, 210408407, []byte("blob"), stale,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.ReconcileTTLExemptions(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	rows, err := s.SweepIdleSessions(ctx)
	if err != nil {
		t.Fatalf("sweep idle: %v", err)
	}
	if rows != 0 {
		t.Errorf("idle sweep revoked %d rows, want 0 — exempt identities must survive the idle sweep", rows)
	}
	var revoked sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM telegram_accounts WHERE telegram_user_id = 210408407`,
	).Scan(&revoked); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	if revoked.Valid {
		t.Error("exempt session must survive the idle sweep")
	}
}

// TestSweepIdleSessionsTwoSided proves SweepIdleSessions and the exempt list
// agree on exactly the rows they should: an exempt identity and a
// non-exempt identity both stale past the idle TTL, only the non-exempt one
// gets revoked.
func TestSweepIdleSessionsTwoSided(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t).WithAbsoluteTTLExempt([]int64{210408407})
	uid, err := s.EnsureUser(ctx, "ttl-idle-two-sided", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	stale := time.Now().UTC().Add(-40 * 24 * time.Hour) // past the 30d idle TTL
	seedAccountForTelegramID(t, s, uid, 210408407, nil)
	seedAccountForTelegramID(t, s, uid, 999000111, nil)
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET last_used_at = $1`, stale,
	); err != nil {
		t.Fatalf("stale last_used_at: %v", err)
	}
	if _, err := s.ReconcileTTLExemptions(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	rows, err := s.SweepIdleSessions(ctx)
	if err != nil {
		t.Fatalf("sweep idle: %v", err)
	}
	if rows != 1 {
		t.Errorf("idle sweep revoked %d rows, want 1 (only the non-exempt one)", rows)
	}

	var exemptRevoked, otherRevoked sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM telegram_accounts WHERE telegram_user_id = 210408407`,
	).Scan(&exemptRevoked); err != nil {
		t.Fatalf("read exempt revoked_at: %v", err)
	}
	if exemptRevoked.Valid {
		t.Error("exempt identity must survive the idle sweep")
	}
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM telegram_accounts WHERE telegram_user_id = 999000111`,
	).Scan(&otherRevoked); err != nil {
		t.Fatalf("read non-exempt revoked_at: %v", err)
	}
	if !otherRevoked.Valid {
		t.Error("non-exempt identity with the same staleness must be revoked")
	}
}

// TestCheckSessionValidAcceptsExemptIdle mirrors
// TestCheckSessionValidAcceptsExempt for the idle side: an exempt identity
// with a stale last_used_at must still validate, while a non-exempt
// identity with the same staleness is rejected with ReasonIdle.
func TestCheckSessionValidAcceptsExemptIdle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t).WithAbsoluteTTLExempt([]int64{210408407})
	stale := time.Now().UTC().Add(-40 * 24 * time.Hour) // past the 30d idle TTL

	exemptUID, err := s.EnsureUser(ctx, "ttl-check-idle-exempt", "", "test")
	if err != nil {
		t.Fatalf("ensure exempt user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,NULL)`,
		exemptUID, 210408407, []byte("blob"), stale,
	); err != nil {
		t.Fatalf("seed exempt: %v", err)
	}
	if _, err := s.CheckSessionValid(ctx, exemptUID); err != nil {
		t.Errorf("exempt session with stale last_used_at must validate, got %v", err)
	}

	otherUID, err := s.EnsureUser(ctx, "ttl-check-idle-other", "", "test")
	if err != nil {
		t.Fatalf("ensure non-exempt user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,NULL)`,
		otherUID, 999000111, []byte("blob"), stale,
	); err != nil {
		t.Fatalf("seed non-exempt: %v", err)
	}
	reason, err := s.CheckSessionValid(ctx, otherUID)
	if !errors.Is(err, ErrSessionExpired) || reason != ReasonIdle {
		t.Errorf("non-exempt stale session should reject with ReasonIdle, got reason=%q err=%v", reason, err)
	}
}
