// Package queue wraps the agent-job store methods with metrics so every
// producer (listener) and consumer (agent API) counts state transitions the
// same way. The store remains the source of truth for queue semantics —
// idempotent enqueue, SKIP LOCKED claims, exponential retry, dead-letter;
// this package only adds observability and a single place to hang future
// concerns (e.g. per-user quotas).
package queue

import (
	"context"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// Queue is the metrics-aware facade over the agent_jobs table.
type Queue struct {
	Store     *db.Store
	ReplicaID string
	m         *metrics.Registry
}

// New constructs a Queue. metrics may be nil (tests).
func New(store *db.Store, replicaID string, m *metrics.Registry) *Queue {
	return &Queue{Store: store, ReplicaID: replicaID, m: m}
}

func (q *Queue) count(status string, n int) {
	if q.m == nil || n <= 0 {
		return
	}
	q.m.AgentJobsTotal.WithLabelValues(status).Add(float64(n))
	if status == db.JobDeadLetter {
		q.m.AgentDeadLetterTotal.Add(float64(n))
	}
}

// Enqueue inserts a pending job for an event; idempotent on event id.
func (q *Queue) Enqueue(ctx context.Context, eventID string, userID, conversationID int64) (int64, bool, error) {
	id, enqueued, err := q.Store.EnqueueAgentJob(ctx, eventID, userID, conversationID)
	if err == nil && enqueued {
		q.count(db.JobPending, 1)
	}
	return id, enqueued, err
}

// Ingest persists an actionable incoming event, enqueues its job, and updates
// the conversation's last-incoming timestamp in one transaction. It counts both
// the received event and pending job only after commit. Duplicate deliveries are
// a complete no-op and count nothing.
func (q *Queue) Ingest(ctx context.Context, ev db.IncomingEvent, conversationID int64) (int64, bool, error) {
	id, enqueued, err := q.Store.InsertEventEnqueueJobAndTouch(ctx, ev, conversationID)
	if err == nil && enqueued {
		if q.m != nil {
			q.m.AgentEventsReceivedTotal.WithLabelValues(ev.Kind).Inc()
		}
		q.count(db.JobPending, 1)
	}
	return id, enqueued, err
}

// Claim atomically claims up to limit due jobs for this replica, scoped to
// userID — see Store.ClaimAgentJobs for why the scoping is load-bearing.
func (q *Queue) Claim(ctx context.Context, userID int64, limit int) ([]db.AgentJob, error) {
	jobs, err := q.Store.ClaimAgentJobs(ctx, q.ReplicaID, userID, limit)
	if err == nil {
		q.count(db.JobProcessing, len(jobs))
	}
	return jobs, err
}

// Complete closes a processing job with a terminal status. attempt is the
// claim identity from Claim, so a worker whose claim was requeued cannot
// overwrite the newer claim's outcome.
func (q *Queue) Complete(ctx context.Context, jobID int64, attempt int, status, note string) error {
	err := q.Store.CompleteAgentJob(ctx, jobID, attempt, status, note)
	if err == nil {
		q.count(status, 1)
	}
	return err
}

// Retry returns a processing job to the queue with backoff, or dead-letters
// it when attempts are exhausted. attempt is the claim identity from Claim.
func (q *Queue) Retry(ctx context.Context, jobID int64, attempt int, errMsg string) (string, error) {
	status, err := q.Store.RetryAgentJob(ctx, jobID, attempt, errMsg)
	if err == nil {
		q.count(status, 1)
	}
	return status, err
}

// RequeueStale is crash recovery for jobs whose claim outlived the
// visibility timeout: they return to pending (or dead_letter when attempts
// are exhausted). Called by the sweeper.
func (q *Queue) RequeueStale(ctx context.Context, visibility time.Duration) (requeued, dead int64, err error) {
	requeued, dead, err = q.Store.RequeueStaleAgentJobs(ctx, visibility)
	if err == nil {
		q.count(db.JobPending, int(requeued))
		q.count(db.JobDeadLetter, int(dead))
	}
	return requeued, dead, err
}
