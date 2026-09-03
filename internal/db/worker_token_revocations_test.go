package db

import (
	"context"
	"os"
	"testing"
	"time"
)

func newWorkerTokenRevocationTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	conn, err := Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Store{DB: conn}
}

// Revoking a jti makes IsWorkerTokenRevoked true for that jti and false for
// an unrelated one.
func TestRevokeWorkerToken_JtiScoped(t *testing.T) {
	ctx := context.Background()
	s := newWorkerTokenRevocationTestStore(t)
	if err := s.RevokeWorkerToken(ctx, "jti-1", 42, "leak", 7); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revoked, err := s.IsWorkerTokenRevoked(ctx, "jti-1", 42, time.Now())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !revoked {
		t.Error("jti-1 should be revoked")
	}
	revoked, err = s.IsWorkerTokenRevoked(ctx, "jti-2", 42, time.Now())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if revoked {
		t.Error("jti-2 was never revoked and must not be reported revoked")
	}
}

// Double-revoking the same jti is a no-op, not an error.
func TestRevokeWorkerToken_DoubleRevokeIsNoop(t *testing.T) {
	ctx := context.Background()
	s := newWorkerTokenRevocationTestStore(t)
	if err := s.RevokeWorkerToken(ctx, "jti-dup", 1, "first", 1); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := s.RevokeWorkerToken(ctx, "jti-dup", 1, "second", 2); err != nil {
		t.Fatalf("second revoke should be a no-op, not an error: %v", err)
	}
	revoked, err := s.IsWorkerTokenRevoked(ctx, "jti-dup", 1, time.Now())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !revoked {
		t.Error("jti-dup should still be revoked")
	}
}

// T5: RevokeWorkerTokensForTelegramID then IsWorkerTokenRevoked for a token
// issuedAt before/at/after the revocation timestamp returns true/true/false.
func TestRevokeWorkerTokensForTelegramID_HonorsIssuedAt(t *testing.T) {
	ctx := context.Background()
	s := newWorkerTokenRevocationTestStore(t)
	if err := s.RevokeWorkerTokensForTelegramID(ctx, 99, "compromised account", 1); err != nil {
		t.Fatalf("blanket revoke: %v", err)
	}

	var revokedAt time.Time
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM worker_token_revocations WHERE telegram_id = $1 AND jti IS NULL`, 99,
	).Scan(&revokedAt); err != nil {
		t.Fatalf("read back revoked_at: %v", err)
	}

	cases := []struct {
		name     string
		issuedAt time.Time
		want     bool
	}{
		{"before", revokedAt.Add(-time.Hour), true},
		{"at", revokedAt, true},
		{"after", revokedAt.Add(time.Hour), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := s.IsWorkerTokenRevoked(ctx, "irrelevant-jti", 99, c.issuedAt)
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if got != c.want {
				t.Errorf("issuedAt=%s: got %v, want %v", c.name, got, c.want)
			}
		})
	}

	// An unrelated telegram id is unaffected by the blanket revocation.
	revoked, err := s.IsWorkerTokenRevoked(ctx, "irrelevant-jti", 100, revokedAt.Add(-time.Hour))
	if err != nil {
		t.Fatalf("check unrelated id: %v", err)
	}
	if revoked {
		t.Error("blanket revocation for telegram_id 99 must not affect telegram_id 100")
	}
}

func TestListWorkerTokenRevocations_ReturnsBothShapes(t *testing.T) {
	ctx := context.Background()
	s := newWorkerTokenRevocationTestStore(t)
	if err := s.RevokeWorkerToken(ctx, "jti-list", 1, "", 0); err != nil {
		t.Fatalf("revoke jti: %v", err)
	}
	if err := s.RevokeWorkerTokensForTelegramID(ctx, 2, "", 0); err != nil {
		t.Fatalf("revoke blanket: %v", err)
	}
	rows, err := s.ListWorkerTokenRevocations(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(rows), rows)
	}
	var sawJti, sawBlanket bool
	for _, r := range rows {
		switch {
		case r.Jti == "jti-list" && r.TelegramID == 1:
			sawJti = true
		case r.Jti == "" && r.TelegramID == 2:
			sawBlanket = true
		}
	}
	if !sawJti {
		t.Errorf("missing jti-scoped row in %+v", rows)
	}
	if !sawBlanket {
		t.Errorf("missing blanket row in %+v", rows)
	}
}

func TestRevokeWorkerToken_RequiresJti(t *testing.T) {
	ctx := context.Background()
	s := newWorkerTokenRevocationTestStore(t)
	if err := s.RevokeWorkerToken(ctx, "", 1, "", 0); err == nil {
		t.Error("expected an error when jti is empty")
	}
}

func TestRevokeWorkerTokensForTelegramID_RequiresTelegramID(t *testing.T) {
	ctx := context.Background()
	s := newWorkerTokenRevocationTestStore(t)
	if err := s.RevokeWorkerTokensForTelegramID(ctx, 0, "", 0); err == nil {
		t.Error("expected an error when telegram_id is <= 0")
	}
}

// TestIsWorkerTokenRevoked_NonUTCIssuedAt pins the normalisation. SQLite
// compares DATETIME values as text and revoked_at is stored in UTC, so a
// caller passing the same instant in another zone would have its offset read
// as part of the clock value — a genuine revocation then answers false, which
// is the wrong direction to fail in.
//
// The location is fixed here rather than taken from the environment on
// purpose: this bug is invisible when TZ=UTC, which is what CI runs, so a test
// that used time.Now() in the ambient zone would pass on the broken code
// everywhere it mattered.
func TestIsWorkerTokenRevoked_NonUTCIssuedAt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const tgID = 700000301

	if err := s.RevokeWorkerTokensForTelegramID(ctx, tgID, "test", 0); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// One instant, three spellings. All must give the same answer.
	base := time.Now().UTC().Add(-time.Hour)
	for _, loc := range []*time.Location{
		time.UTC,
		time.FixedZone("plus2", 2*60*60),
		time.FixedZone("minus5", -5*60*60),
	} {
		issued := base.In(loc)
		revoked, err := s.IsWorkerTokenRevoked(ctx, "no-such-jti", tgID, issued)
		if err != nil {
			t.Fatalf("IsWorkerTokenRevoked(%s): %v", loc, err)
		}
		if !revoked {
			t.Errorf("issuedAt in %s: revoked=false, want true — the revocation postdates the token regardless of how the instant is spelled", loc)
		}
	}
}

// TestRevokeWorkerToken_PostgresUpsert exercises the Postgres branch of
// RevokeWorkerToken against a real server. The two dialects take different
// statements — Postgres uses ON CONFLICT, SQLite INSERT OR IGNORE — so the
// SQLite tests above cannot see a defect in the Postgres one, and this
// statement's arbiter index is partial, which Postgres will not infer from a
// bare ON CONFLICT (jti). Without the index predicate repeated in the
// conflict target, production fails on the first revoke-by-jti with
// "there is no unique or exclusion constraint matching the ON CONFLICT
// specification" while every SQLite test stays green.
//
// Skipped unless TEST_DATABASE_URL points at a Postgres instance.
func TestRevokeWorkerToken_PostgresUpsert(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	defer conn.Close()
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &Store{DB: conn}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, `DELETE FROM worker_token_revocations WHERE jti LIKE 'pgtest-%'`)
	})

	const jti = "pgtest-jti-1"
	if err := s.RevokeWorkerToken(ctx, jti, 0, "first", 0); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	// Idempotent: revoking the same jti again must not error.
	if err := s.RevokeWorkerToken(ctx, jti, 0, "second", 0); err != nil {
		t.Fatalf("second revoke of the same jti: %v", err)
	}
	revoked, err := s.IsWorkerTokenRevoked(ctx, jti, 0, time.Now())
	if err != nil {
		t.Fatalf("IsWorkerTokenRevoked: %v", err)
	}
	if !revoked {
		t.Error("jti not reported as revoked on Postgres")
	}
}
