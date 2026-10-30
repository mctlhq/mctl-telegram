package db

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"
)

// TestConnectFirstCall_SQLite and TestConnectFirstCall_Postgres run the same
// checks on both dialects: the funnel's correctness rests on hand-written
// UPDATE ... RETURNING and timestamp range comparisons, which is exactly
// where SQLite and Postgres part ways.
func TestConnectFirstCall_SQLite(t *testing.T) {
	assertConnectFirstCallStore(t, newTestStore(t))
}

func TestConnectFirstCall_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	assertConnectFirstCallStore(t, newPostgresTestStore(t, dsn))
}

func assertConnectFirstCallStore(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	uid, err := s.EnsureUser(ctx, fmt.Sprintf("cfc_alice_%d", time.Now().UnixNano()), "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM connect_first_call WHERE user_id = $1`, uid)
		_, _ = s.DB.Exec(`DELETE FROM users WHERE id = $1`, uid)
	})
	// Classification and the sweep are table-wide, and Postgres keeps state
	// between runs: an instant of its own, far from any real grant, keeps
	// this run's ranges to this run's rows.
	base := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(time.Now().UnixNano()%1e6) * time.Minute)
	at := func(d time.Duration) time.Time { return base.Add(d) }
	const window = 5 * time.Minute

	insert := func(clientID, client string, d time.Duration) {
		t.Helper()
		if err := s.InsertConnectGrant(ctx, uid, clientID, client, at(d)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	expect := func(what string, got []string, err error, want ...string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		sort.Strings(got)
		sort.Strings(want)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
	}

	insert("c-claude", "claude", 0)
	insert("c-claude", "claude", time.Minute)
	insert("c-chatgpt", "chatgpt", 0)

	got, err := s.CloseConnectGrants(ctx, uid, "c-claude", at(2*time.Minute), window, at(2*time.Minute))
	expect("close in window", got, err, "claude", "claude")
	got, err = s.CloseConnectGrants(ctx, uid, "c-claude", at(2*time.Minute), window, at(2*time.Minute))
	expect("second close", got, err)
	got, err = s.CloseConnectGrants(ctx, uid, "c-chatgpt", at(window+time.Second), window, at(window+time.Second))
	expect("close after window", got, err)
	got, err = s.CloseConnectGrants(ctx, uid+1, "c-chatgpt", at(time.Minute), window, at(time.Minute))
	expect("close by another user", got, err)

	got, err = s.ClassifyOpenConnectGrants(ctx, at(-time.Second), at(time.Second), ConnectOutcomeNone, "", at(7*time.Minute))
	expect("classify open", got, err, "chatgpt")
	got, err = s.ClassifyOpenConnectGrants(ctx, at(-time.Second), at(time.Second), ConnectOutcomeNone, "", at(7*time.Minute))
	expect("classify again", got, err)

	// The upper bound is exclusive, at Postgres' microsecond precision.
	insert("c-claude", "claude", 20*time.Minute)
	got, err = s.ClassifyOpenConnectGrants(ctx, at(19*time.Minute), at(20*time.Minute), ConnectOutcomeUnknown, "restart", at(30*time.Minute))
	expect("classify up to the grant, exclusive", got, err)
	got, err = s.ClassifyOpenConnectGrants(ctx, at(19*time.Minute), at(20*time.Minute).Add(time.Microsecond), ConnectOutcomeUnknown, "restart", at(30*time.Minute))
	expect("classify one microsecond past the grant", got, err, "claude")

	var outcome, reason string
	if err := s.DB.QueryRow(`SELECT outcome, reason FROM connect_first_call WHERE user_id = $1 AND granted_at = $2`, uid, at(20*time.Minute)).Scan(&outcome, &reason); err != nil {
		t.Fatalf("read classified row: %v", err)
	}
	if outcome != ConnectOutcomeUnknown || reason != "restart" {
		t.Fatalf("row = (%q, %q), want (unknown, restart)", outcome, reason)
	}

	// Retention: the two ok rows were classified at +2m, the none row at
	// +7m, the unknown one at +30m. An open row is never swept.
	insert("c-chatgpt", "chatgpt", 40*time.Minute)
	// The sweep is table-wide, so count this run's rows rather than trust
	// the deleted-row total, which a leftover from an aborted run would skew.
	rowsLeft := func() int {
		t.Helper()
		var n int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM connect_first_call WHERE user_id = $1`, uid).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if _, err := s.SweepConnectGrants(ctx, at(2*time.Minute+time.Second)); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n := rowsLeft(); n != 3 {
		t.Fatalf("rows after sweeping the ok rows = %d, want 3", n)
	}
	if _, err := s.SweepConnectGrants(ctx, at(time.Hour)); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n := rowsLeft(); n != 1 {
		t.Fatalf("rows left = %d, want the one open row", n)
	}
}
