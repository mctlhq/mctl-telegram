package sweeper

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestForkEvalSweepOnce_ExpiresOldOpenRuns(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:sweeper_fork_eval?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := &db.Store{DB: conn}
	uid, err := store.EnsureUser(ctx, "owner", "", "test")
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	insert := func(age time.Duration) int64 {
		t.Helper()
		var id int64
		if err := conn.QueryRow(
			`INSERT INTO assistant_fork_eval_runs(user_id, fork_digest, base_digest, suite_digest, harness_version, state, created_at)
			 VALUES($1,'f','b','s','h','queued',$2) RETURNING id`, uid, time.Now().UTC().Add(-age)).Scan(&id); err != nil {
			t.Fatalf("insert: %v", err)
		}
		return id
	}
	old, young := insert(25*time.Hour), insert(time.Hour)
	forkEvalSweepOnce(ctx, store)
	state := func(id int64) string {
		var s string
		if err := conn.QueryRow(`SELECT state FROM assistant_fork_eval_runs WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if state(old) != db.ForkEvalExpired || state(young) != db.ForkEvalQueued {
		t.Fatalf("states = %s, %s", state(old), state(young))
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	ForkEvals(cctx, store) // runs once at boot, then returns on the cancelled context
}
