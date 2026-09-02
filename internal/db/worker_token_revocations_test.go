package db

import (
	"context"
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
