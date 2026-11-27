package db

import (
	"context"
	"os"
	"testing"
	"time"
)

// An audit row written with a clock finer than a microsecond, as on Linux,
// still verifies after it is read back from either store.
func TestAuditChainVerifiesAfterASubMicrosecondClock(t *testing.T) {
	real := auditNow
	t.Cleanup(func() { auditNow = real })
	auditNow = func() time.Time { return real().Truncate(time.Microsecond).Add(123 * time.Nanosecond) }

	check := func(t *testing.T, s *Store) {
		ctx := context.Background()
		// Postgres is reused between runs: a user of its own, so that the
		// chain verified here holds only the rows written here.
		tgID := real().UnixNano()
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice_tg", "Alice")
		if err != nil {
			t.Fatalf("user: %v", err)
		}
		for range 2 {
			if err := s.LogToolCallChecked(ctx, ToolCall{UserID: uid, Tool: "list_dialogs", Status: "ok"}); err != nil {
				t.Fatalf("log: %v", err)
			}
		}
		v, err := s.VerifyAuditChain(ctx, uid)
		if err != nil || !v.OK || v.Verified != 2 {
			t.Fatalf("audit chain does not verify: %+v %v", v, err)
		}
	}
	t.Run("sqlite", func(t *testing.T) { check(t, newTestStoreCrypted(t)) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		check(t, newPostgresTestStore(t, dsn))
	})
}
