package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// TestManagedQuota_PostgresConcurrent is T7 on the real dialect. SQLite
// serializes writers, so the SQLite race test survives removing the advisory
// lock; only Postgres READ COMMITTED lets two own -> managed writes both see
// "no managed account yet". With MaxAccounts = 1 exactly one of two
// concurrent writes may succeed, the other must be ErrManagedQuota.
func TestManagedQuota_PostgresConcurrent(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	var uids [2]int64
	for i := range uids {
		uids[i] = seedAgentUser(t, s, fmt.Sprintf("managed-pg-%d-%d", stamp, i))
		if err := s.UpsertAgentProfile(ctx, AgentProfile{UserID: uids[i], Mode: AgentModeObserve}); err != nil {
			t.Fatalf("upsert profile: %v", err)
		}
	}
	reset := func() {
		// The Postgres database is shared between tests and runs.
		if _, err := s.DB.ExecContext(ctx, `UPDATE agent_profiles SET runtime = 'own' WHERE runtime <> 'own'`); err != nil {
			t.Fatalf("reset runtime: %v", err)
		}
	}
	t.Cleanup(reset)

	const rounds = 40
	managed, one := RuntimeManaged, 1
	for round := 0; round < rounds; round++ {
		reset()
		var ready, done sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, len(uids))
		ready.Add(len(uids))
		done.Add(len(uids))
		for i, uid := range uids {
			go func() {
				defer done.Done()
				ready.Done()
				<-start
				errs[i] = s.UpdateAgentProfileFields(ctx, uid, AgentProfileUpdate{Runtime: &managed, ManagedQuota: &one})
			}()
		}
		ready.Wait()
		close(start)
		done.Wait()

		ok, quota := 0, 0
		for _, e := range errs {
			switch {
			case e == nil:
				ok++
			case errors.Is(e, ErrManagedQuota):
				quota++
			default:
				t.Fatalf("round %d: unexpected error %v", round, e)
			}
		}
		n, err := s.CountManagedAccounts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ok != 1 || quota != 1 || n != 1 {
			t.Fatalf("round %d: successes=%d quota refusals=%d managed accounts=%d, want 1/1/1", round, ok, quota, n)
		}
	}
}
