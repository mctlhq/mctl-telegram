package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestClientRegPinned_PostgresExemptFromSweepAndEviction pins the storage half
// of the DCR allowlist (OAUTH_DCR_REDIRECT_URIS): a registration whose
// client_id carries PinnedClientIDPrefix survives both the ClientRegistrationTTL
// sweep and the MaxRegisteredClients eviction, and does not count toward the
// cap, while random registrations keep both bounds. oauth_client_registrations
// exists only in the Postgres schema, so this test has no SQLite twin.
func TestClientRegPinned_PostgresExemptFromSweepAndEviction(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	// The table is transient OAuth state and nothing else in this package
	// writes it; start from empty so the eviction arithmetic is exact.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_client_registrations`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM oauth_client_registrations`) })

	old := time.Now().UTC().Add(-48 * time.Hour)
	insert := func(id string, at time.Time) {
		t.Helper()
		if err := s.InsertClientReg(ctx, OAuthClientReg{
			ClientID: id, ClientName: "n", RedirectURIs: []string{"https://portal.example.test/cb"}, CreatedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(id string) bool {
		t.Helper()
		_, err := s.GetClientReg(ctx, id)
		if errors.Is(err, ErrOAuthNotFound) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		return true
	}

	pinned := PinnedClientIDPrefix + "pinnedrow"
	insert(pinned, old.Add(-time.Hour)) // the oldest row of all
	insert("tgmcp_random_a", old)
	insert("tgmcp_random_b", old.Add(time.Minute))

	// Cap of 2 non-pinned rows: at the cap, so one eviction removes the
	// oldest RANDOM row, never the (older) pinned one.
	if err := s.EvictOldestClientRegIfOver(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if !exists(pinned) {
		t.Fatal("eviction removed the pinned registration")
	}
	if exists("tgmcp_random_a") {
		t.Fatal("eviction did not remove the oldest random registration")
	}
	// One random row left, under a cap of 2 once the pinned row is not
	// counted: nothing further is evicted.
	if err := s.EvictOldestClientRegIfOver(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if !exists("tgmcp_random_b") {
		t.Fatal("the pinned row was counted toward the cap")
	}

	n, err := s.DeleteExpiredClientRegs(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || exists("tgmcp_random_b") {
		t.Fatalf("sweep deleted %d rows, want exactly the expired random one", n)
	}
	if !exists(pinned) {
		t.Fatal("the TTL sweep removed the pinned registration")
	}
}
