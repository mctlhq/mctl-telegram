package db

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"
)

// TestRecordClientAssertionJTI_Postgres pins the replay contract for
// private_key_jwt client assertions: a jti is accepted once while live,
// refused while its record is live, accepted again once the record has
// expired, and swept afterwards.
func TestRecordClientAssertionJTI_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &Store{DB: conn}

	// The jti carries a NUL on purpose: it is client-chosen, and the row key
	// must hold any bytes.
	const clientID, jti = "https://platform.example.test/client", "pgtest-jti\x00tail"
	sum := sha256.Sum256([]byte(clientID + "\x00" + jti))
	key := sum[:]
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, `DELETE FROM oauth_client_assertion_jtis WHERE jti_hash = $1`, key)
	})

	live := 5 * time.Minute
	if fresh, err := s.RecordClientAssertionJTI(ctx, clientID, jti, live); err != nil || !fresh {
		t.Fatalf("first use: fresh=%v err=%v, want true nil", fresh, err)
	}
	if fresh, err := s.RecordClientAssertionJTI(ctx, clientID, jti, live); err != nil || fresh {
		t.Fatalf("replay while live: fresh=%v err=%v, want false nil", fresh, err)
	}
	// The same jti from another client is another record.
	other := "https://other.example.test/client"
	otherSum := sha256.Sum256([]byte(other + "\x00" + jti))
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, `DELETE FROM oauth_client_assertion_jtis WHERE jti_hash = $1`, otherSum[:])
	})
	if fresh, err := s.RecordClientAssertionJTI(ctx, other, jti, live); err != nil || !fresh {
		t.Fatalf("same jti, other client: fresh=%v err=%v, want true nil", fresh, err)
	}

	if _, err := conn.ExecContext(ctx,
		`UPDATE oauth_client_assertion_jtis SET expires_at = NOW() - INTERVAL '1 second' WHERE jti_hash = $1`, key); err != nil {
		t.Fatalf("expire row: %v", err)
	}
	if fresh, err := s.RecordClientAssertionJTI(ctx, clientID, jti, live); err != nil || !fresh {
		t.Fatalf("reuse after expiry: fresh=%v err=%v, want true nil", fresh, err)
	}

	if _, err := conn.ExecContext(ctx,
		`UPDATE oauth_client_assertion_jtis SET expires_at = NOW() - INTERVAL '1 second' WHERE jti_hash = $1`, key); err != nil {
		t.Fatalf("expire row: %v", err)
	}
	if n, err := s.DeleteExpiredClientAssertionJTIs(ctx); err != nil || n < 1 {
		t.Fatalf("sweep: n=%d err=%v, want at least 1 nil", n, err)
	}
	var left int
	_ = conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_client_assertion_jtis WHERE jti_hash = $1`, key).Scan(&left)
	if left != 0 {
		t.Fatalf("expired row survived the sweep")
	}
}
