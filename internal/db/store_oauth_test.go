package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestErrOAuthExpired_WrapsErrOAuthNotFound is the compatibility contract for
// the four existing ConsumeOAuthPending callers (internal/oauth/demo_login.go,
// internal/oauth/server.go): a caller checking only errors.Is(err,
// ErrOAuthNotFound) must keep working unmodified once ErrOAuthExpired starts
// being returned for the TTL case. No database needed, so this runs in every
// CI environment regardless of TEST_DATABASE_URL.
func TestErrOAuthExpired_WrapsErrOAuthNotFound(t *testing.T) {
	if !errors.Is(ErrOAuthExpired, ErrOAuthNotFound) {
		t.Fatal("ErrOAuthExpired does not wrap ErrOAuthNotFound")
	}
}

// TestConsumeOAuthPending_PostgresExpiredIsDistinguishable exercises the Postgres
// branch of ConsumeOAuthPending: a row whose created_at is older than ttl
// must return ErrOAuthExpired (which also satisfies errors.Is(err,
// ErrOAuthNotFound)), must still be deleted on the attempt, and a state that
// was never issued must give ErrOAuthNotFound without satisfying
// errors.Is(err, ErrOAuthExpired). Skipped unless TEST_DATABASE_URL points at
// a Postgres instance, same as TestRegisterDevice_PostgresUpsert.
func TestConsumeOAuthPending_PostgresExpiredIsDistinguishable(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	// Close in t.Cleanup, registered first so it runs last: a defer would run
	// before the row cleanup below and leave that DELETE on a closed pool.
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &Store{DB: conn}

	const state = "pgtest-expired-pending-state"
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, `DELETE FROM oauth_pending_auth WHERE state = $1`, state)
	})

	if err := s.InsertOAuthPending(ctx, OAuthPendingAuth{
		State:           state,
		ClientID:        "pgtest-client",
		RedirectURI:     "https://example.test/callback",
		CodeChallenge:   "pgtest-challenge",
		ChallengeMethod: "S256",
		CreatedAt:       time.Now(),
	}); err != nil {
		t.Fatalf("InsertOAuthPending: %v", err)
	}

	// Backdate created_at directly, well past any ttl the consume call below
	// will use.
	backdated := time.Now().UTC().Add(-time.Hour)
	if _, err := conn.ExecContext(ctx,
		`UPDATE oauth_pending_auth SET created_at = $1 WHERE state = $2`,
		backdated, state,
	); err != nil {
		t.Fatalf("backdate created_at: %v", err)
	}

	_, err = s.ConsumeOAuthPending(ctx, state, time.Minute)
	if !errors.Is(err, ErrOAuthExpired) {
		t.Errorf("ConsumeOAuthPending on an expired row: err = %v, want errors.Is(err, ErrOAuthExpired)", err)
	}
	if !errors.Is(err, ErrOAuthNotFound) {
		t.Errorf("ConsumeOAuthPending on an expired row: err = %v, want errors.Is(err, ErrOAuthNotFound) too", err)
	}

	// The row must be gone: a second consume of the same state reports plain
	// ErrOAuthNotFound (the row was deleted on the first attempt, not left
	// for the sweeper), and must NOT satisfy errors.Is(err, ErrOAuthExpired).
	_, err = s.ConsumeOAuthPending(ctx, state, time.Minute)
	if !errors.Is(err, ErrOAuthNotFound) {
		t.Errorf("second ConsumeOAuthPending: err = %v, want errors.Is(err, ErrOAuthNotFound)", err)
	}
	if errors.Is(err, ErrOAuthExpired) {
		t.Errorf("second ConsumeOAuthPending: err = %v, should not satisfy errors.Is(err, ErrOAuthExpired) — the row is gone, not expired", err)
	}

	// A state that was never issued must give ErrOAuthNotFound and must NOT
	// satisfy errors.Is(err, ErrOAuthExpired).
	_, err = s.ConsumeOAuthPending(ctx, "pgtest-never-issued-state", time.Minute)
	if !errors.Is(err, ErrOAuthNotFound) {
		t.Errorf("never-issued state: err = %v, want errors.Is(err, ErrOAuthNotFound)", err)
	}
	if errors.Is(err, ErrOAuthExpired) {
		t.Errorf("never-issued state: err = %v, should not satisfy errors.Is(err, ErrOAuthExpired)", err)
	}
}
