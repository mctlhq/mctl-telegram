package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// OutboxRow is one reference-only event envelope awaiting publication.
type OutboxRow struct {
	ID        int64
	EventID   string
	UserID    int64
	Stream    string
	Envelope  string
	Attempts  int
	CreatedAt time.Time
}

// OutboxBuilder derives the outbox row for an incoming event, or ok=false when
// the event kind is not published. It is injected (internal/events) rather than
// imported so this package keeps no dependency on the transport, and it must
// read identifiers only: the envelope is stored in plaintext.
//
// routingReason is empty for an ingest-time envelope and one of the Route*
// constants for a routed one.
type OutboxBuilder func(ev IncomingEvent, occurredAt time.Time, routingReason string) (row OutboxRow, ok bool, err error)

// Closed set of reasons an event is forwarded to the operator stream when
// operator routing is on.
const (
	RoutePolicyDeny            = "policy_deny"
	RoutePolicyRequireApproval = "policy_require_approval"
	RouteWorkerFailure         = "worker_failure"
	RouteWorkerUnclaimed       = "worker_unclaimed"
)

// WithOperatorRouting turns operator routing on or off. When on, ingest does
// not write an outbox row for an event that was enqueued as an agent job; the
// row is written later, in the transaction that decides the job's fate, and
// only for a deny, require_approval or worker failure. Off (the default)
// publishes at ingest exactly as before.
func (s *Store) WithOperatorRouting(on bool) *Store {
	s.operatorRouting = on
	return s
}

// WithEventOutbox enables the event outbox: every published incoming event gets
// an event_outbox row in the same transaction that records it. Without it no
// rows are written, so a deployment that does not publish events accumulates
// nothing.
func (s *Store) WithEventOutbox(b OutboxBuilder) *Store {
	s.outbox = b
	return s
}

// WithEventOutboxNotify registers a callback run after an ingest that wrote an
// outbox row has committed, so the relay publishes immediately instead of on its
// safety timer. It must not block.
func (s *Store) WithEventOutboxNotify(fn func()) *Store {
	s.outboxNotify = fn
	return s
}

// insertOutboxTx writes the outbox row inside the ingest transaction. Commit
// makes the event and its publication intent durable together: a crash before
// XADD leaves the row unpublished and the relay publishes it on the next pass,
// and a rolled-back ingest leaves nothing to publish.
// It reports whether a row was written, so callers wake the relay only then.
func (s *Store) insertOutboxTx(ctx context.Context, tx *sql.Tx, ev IncomingEvent, at time.Time) (bool, error) {
	return s.insertOutboxReasonTx(ctx, tx, ev, at, "")
}

func (s *Store) insertOutboxReasonTx(ctx context.Context, tx *sql.Tx, ev IncomingEvent, at time.Time, reason string) (bool, error) {
	if s.outbox == nil {
		return false, nil
	}
	row, ok, err := s.outbox(ev, at, reason)
	if err != nil {
		return false, fmt.Errorf("build event envelope: %w", err)
	}
	if !ok {
		return false, nil
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO event_outbox(event_id, user_id, stream, envelope, created_at)
		 VALUES($1,$2,$3,$4,$5)
		 ON CONFLICT (event_id) DO NOTHING`,
		row.EventID, ev.UserID, row.Stream, row.Envelope, at,
	)
	if err != nil {
		return false, fmt.Errorf("insert event outbox: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("insert event outbox rows: %w", err)
	}
	return n == 1, nil
}

// insertRoutedOutboxTx forwards an event to the operator stream with a routing
// reason, inside the caller's transaction. It reads identifiers only from the
// incoming_events row (never the body) and is a no-op unless operator routing
// is on. The unique event_id makes the first reason win. It reports whether a
// row was written, so callers wake the relay after commit.
func (s *Store) insertRoutedOutboxTx(ctx context.Context, tx *sql.Tx, userID int64, eventID, reason string) (bool, error) {
	if !s.operatorRouting || s.outbox == nil {
		return false, nil
	}
	ev := IncomingEvent{EventID: eventID, UserID: userID}
	err := tx.QueryRowContext(ctx,
		`SELECT kind, chat_tg_id, sender_tg_id, message_id
		   FROM incoming_events WHERE event_id = $1 AND user_id = $2`,
		eventID, userID,
	).Scan(&ev.Kind, &ev.ChatTGID, &ev.SenderTGID, &ev.MessageID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load event for routing: %w", err)
	}
	return s.insertOutboxReasonTx(ctx, tx, ev, time.Now().UTC(), reason)
}

// routeJobEventTx forwards the source event of a job to the operator stream.
// For a coalesced head it forwards every event of the turn: the head's own and
// those of the members coalesced into it. First reason wins per event_id.
func (s *Store) routeJobEventTx(ctx context.Context, tx *sql.Tx, jobID int64, reason string) (bool, error) {
	if !s.operatorRouting || s.outbox == nil {
		return false, nil
	}
	type src struct {
		userID  int64
		eventID string
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT user_id, event_id FROM agent_jobs WHERE id = $1 OR coalesced_into = $1 ORDER BY id`, jobID)
	if err != nil {
		return false, fmt.Errorf("load job for routing: %w", err)
	}
	var srcs []src
	for rows.Next() {
		var x src
		if err := rows.Scan(&x.userID, &x.eventID); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("load job for routing: %w", err)
		}
		srcs = append(srcs, x)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, fmt.Errorf("load job for routing: %w", err)
	}
	_ = rows.Close()
	var wroteAny bool
	for _, x := range srcs {
		wrote, err := s.insertRoutedOutboxTx(ctx, tx, x.userID, x.eventID, reason)
		if err != nil {
			return false, err
		}
		wroteAny = wroteAny || wrote
	}
	return wroteAny, nil
}

// RouteUnclaimedAgentJobs moves every pending job that was never claimed
// (attempts = 0) and is older than after to terminal routed, and forwards its
// source event to the operator stream with RouteWorkerUnclaimed. It does
// nothing unless operator routing is on and after > 0. The status
// compare-and-set serializes with ClaimAgentJobs on the row lock, so a job is
// never both routed and claimed. An event already routed for another reason
// keeps its first outbox row; its job still leaves pending. Returns the number
// of jobs moved.
func (s *Store) RouteUnclaimedAgentJobs(ctx context.Context, after time.Duration) (int64, error) {
	if !s.operatorRouting || s.outbox == nil || after <= 0 {
		return 0, nil
	}
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin route unclaimed tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ids, err := requeueTransition(ctx, tx,
		`UPDATE agent_jobs SET status = $1, last_error = $2, updated_at = $3
		  WHERE status = $4 AND attempts = 0 AND created_at < $5
			    AND NOT EXISTS (
			        SELECT 1 FROM agent_jobs p
			         WHERE p.conversation_id = agent_jobs.conversation_id
			           AND (p.status = $6 OR (p.status = $4 AND p.id < agent_jobs.id))
			    )
		 RETURNING id`,
		JobRouted, "unclaimed past threshold, routed to operator", now, JobPending, now.Add(-after), JobProcessing)
	if err != nil {
		return 0, fmt.Errorf("route unclaimed agent jobs: %w", err)
	}
	var routed bool
	for _, id := range ids {
		wrote, err := s.routeJobEventTx(ctx, tx, id, RouteWorkerUnclaimed)
		if err != nil {
			return 0, err
		}
		routed = routed || wrote
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit route unclaimed tx: %w", err)
	}
	s.notifyOutbox(routed)
	return int64(len(ids)), nil
}

// notifyOutbox wakes the relay after a commit that wrote a routed row.
func (s *Store) notifyOutbox(wrote bool) {
	if wrote && s.outboxNotify != nil {
		s.outboxNotify()
	}
}

const outboxLeaseName = "relay"

// AcquireOutboxLease takes or renews the relay lease for holder. It succeeds
// when the lease is free, expired or already held by holder, and reports false
// while another replica holds it.
func (s *Store) AcquireOutboxLease(ctx context.Context, holder string, now time.Time, ttl time.Duration) (bool, error) {
	if holder == "" || ttl <= 0 {
		return false, errors.New("lease needs a holder and a positive ttl")
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO event_outbox_lease(name, holder, expires_at) VALUES($1,$2,$3)
		 ON CONFLICT (name) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
		 WHERE event_outbox_lease.holder = excluded.holder OR event_outbox_lease.expires_at < $4`,
		outboxLeaseName, holder, now.UTC().Add(ttl), now.UTC())
	if err != nil {
		return false, fmt.Errorf("acquire event outbox lease: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("acquire event outbox lease: %w", err)
	}
	return n == 1, nil
}

// ReleaseOutboxLease gives the lease up if holder still owns it.
func (s *Store) ReleaseOutboxLease(ctx context.Context, holder string) error {
	if _, err := s.DB.ExecContext(ctx,
		`DELETE FROM event_outbox_lease WHERE name = $1 AND holder = $2`, outboxLeaseName, holder); err != nil {
		return fmt.Errorf("release event outbox lease: %w", err)
	}
	return nil
}

// PendingOutbox returns unpublished rows, oldest first.
func (s *Store) PendingOutbox(ctx context.Context, limit int) ([]OutboxRow, error) {
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, event_id, user_id, stream, envelope, attempts, created_at
		   FROM event_outbox
		  WHERE published_at IS NULL
		  ORDER BY id
		  LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("query event outbox: %w", err)
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var r OutboxRow
		if err := rows.Scan(&r.ID, &r.EventID, &r.UserID, &r.Stream, &r.Envelope, &r.Attempts, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan event outbox: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkOutboxPublished records a successful XADD.
func (s *Store) MarkOutboxPublished(ctx context.Context, id int64, at time.Time) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE event_outbox SET published_at = $1, attempts = attempts + 1, last_error = '' WHERE id = $2`,
		at, id)
	if err != nil {
		return fmt.Errorf("mark event published: %w", err)
	}
	return nil
}

// MarkOutboxFailed records a failed publish attempt; the row stays pending.
func (s *Store) MarkOutboxFailed(ctx context.Context, id int64, reason string) error {
	if len(reason) > 500 {
		// Cut on a rune boundary: Postgres TEXT rejects invalid UTF-8, and the
		// failure would then not be recorded at all.
		reason = strings.ToValidUTF8(reason[:500], "")
	}
	_, err := s.DB.ExecContext(ctx,
		`UPDATE event_outbox SET attempts = attempts + 1, last_error = $1
		  WHERE id = $2 AND published_at IS NULL`,
		reason, id)
	if err != nil {
		return fmt.Errorf("mark event publish failed: %w", err)
	}
	return nil
}

// PurgePublishedOutbox deletes rows published before the cutoff.
func (s *Store) PurgePublishedOutbox(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM event_outbox WHERE published_at IS NOT NULL AND published_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("purge event outbox: %w", err)
	}
	return res.RowsAffected()
}

// OutboxBacklog counts unpublished rows.
func (s *Store) OutboxBacklog(ctx context.Context) (int64, error) {
	var n int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM event_outbox WHERE published_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count event outbox: %w", err)
	}
	return n, nil
}
