package queue

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

func newTestQueue(t *testing.T) (*Queue, *metrics.Registry, int64) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := db.NewStore(conn, nil)
	uid, err := store.EnsureUser(ctx, "owner", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	m := metrics.New()
	return New(store, "test-replica", m), m, uid
}

func TestQueue_TransitionsCountMetrics(t *testing.T) {
	ctx := context.Background()
	q, m, uid := newTestQueue(t)

	if _, _, err := q.Store.InsertIncomingEvent(ctx, db.IncomingEvent{
		EventID: "evt:t:1", UserID: uid, Kind: db.EventKindPrivateMessage,
		ChatTGID: 1, SenderTGID: 1, MessageID: 1,
	}); err != nil {
		t.Fatalf("event: %v", err)
	}

	if _, enq, err := q.Enqueue(ctx, "evt:t:1", uid, 0); err != nil || !enq {
		t.Fatalf("enqueue: %v", err)
	}
	// Duplicate enqueue must not double-count.
	if _, enq, err := q.Enqueue(ctx, "evt:t:1", uid, 0); err != nil || enq {
		t.Fatalf("dup enqueue: enq=%v err=%v", enq, err)
	}
	if got := testutil.ToFloat64(m.AgentJobsTotal.WithLabelValues(db.JobPending)); got != 1 {
		t.Fatalf("pending count = %v, want 1", got)
	}

	jobs, err := q.Claim(ctx, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: jobs=%v err=%v", jobs, err)
	}
	if got := testutil.ToFloat64(m.AgentJobsTotal.WithLabelValues(db.JobProcessing)); got != 1 {
		t.Fatalf("processing count = %v, want 1", got)
	}

	if err := q.Complete(ctx, jobs[0].ID, db.JobCompleted, ""); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got := testutil.ToFloat64(m.AgentJobsTotal.WithLabelValues(db.JobCompleted)); got != 1 {
		t.Fatalf("completed count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.AgentDeadLetterTotal); got != 0 {
		t.Fatalf("dead letter count = %v, want 0", got)
	}
}
