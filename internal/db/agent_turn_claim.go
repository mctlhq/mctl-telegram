package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/turn"
)

// claimCandidateScan caps how many candidate heads one coalescing claim looks
// at, so a head that is still collecting cannot take a slot from another
// conversation's ready head.
const claimCandidateScan = 100

const agentJobCols = `id, event_id, user_id, conversation_id, status, attempts,
           max_attempts, next_run_at, claimed_by, claimed_at, last_error,
           result_action_id, result_lead_id, cost_usd, created_at, updated_at,
           turn_id, coalesced_into`

// WithTurnCoalescing turns on claim-time turn coalescing with cfg. A nil cfg or
// one with QuietMS <= 0 leaves it off (one job per event, today's claim).
func (s *Store) WithTurnCoalescing(cfg *turn.Config) *Store {
	if cfg == nil || cfg.QuietMS <= 0 {
		s.turnCfg = nil
		return s
	}
	c := *cfg
	s.turnCfg = &c
	return s
}

func (s *Store) now() time.Time {
	if s.timeNow != nil {
		return s.timeNow().UTC()
	}
	return time.Now().UTC()
}

type claimCandidate struct {
	id             int64
	eventID        string
	conversationID sql.NullInt64
	createdAt      time.Time
	bytes          int
	chatTGID       int64
	turnID         sql.NullString
}

// claimCoalesced is ClaimAgentJobs with turn coalescing on. It runs in one
// transaction: for each candidate head (oldest pending job of a conversation)
// it runs the slice-1 coalescer over the head and the conversation's
// never-claimed pending jobs, and claims the head only when its turn is READY.
// The other members of the turn move to coalesced in the same transaction.
// Jobs that waited behind an earlier turn coalesce regardless of their
// arrival gaps (see readyTurn).
func (s *Store) claimCoalesced(ctx context.Context, replicaID string, userID int64, limit int) ([]AgentJob, error) {
	now := s.now()
	lock := ""
	if s.isPostgres(ctx) {
		lock = " FOR UPDATE OF j SKIP LOCKED"
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cands, err := loadClaimCandidates(ctx, tx,
		`SELECT j.id, j.event_id, j.conversation_id, j.created_at, COALESCE(j.body_bytes, 0),
		        e.chat_tg_id, j.turn_id
		   FROM agent_jobs j
		   JOIN incoming_events e ON e.event_id = j.event_id AND e.user_id = j.user_id
		  WHERE j.status = $1 AND j.next_run_at <= $2 AND j.user_id = $3
		    AND NOT EXISTS (
		        SELECT 1 FROM agent_jobs p
		         WHERE p.conversation_id = j.conversation_id
		           AND (p.status = $4 OR (p.status = $1 AND p.id < j.id))
		    )
		  ORDER BY j.next_run_at, j.id
		  LIMIT $5`+lock,
		JobPending, now, userID, JobProcessing, claimCandidateScan)
	if err != nil {
		return nil, fmt.Errorf("claim agent jobs: %w", err)
	}

	var jobs []AgentJob
	for _, c := range cands {
		if len(jobs) >= limit {
			break
		}
		var members []claimCandidate
		var tid string
		if c.turnID.Valid && c.turnID.String != "" {
			// Retry or stale requeue of a head claimed before: membership is
			// frozen, the members are already coalesced.
			tid = c.turnID.String
		} else {
			var ready bool
			tid, members, ready, err = s.readyTurn(ctx, tx, userID, c, now, lock)
			if err != nil {
				return nil, err
			}
			if !ready {
				continue
			}
		}
		rows, err := tx.QueryContext(ctx,
			`UPDATE agent_jobs
			    SET status = $1, attempts = attempts + 1,
			        claimed_by = $2, claimed_at = $3, updated_at = $3, turn_id = $4
			  WHERE id = $5 AND status = $6
			 RETURNING `+agentJobCols,
			JobProcessing, replicaID, now, tid, c.id, JobPending)
		if err != nil {
			return nil, fmt.Errorf("claim agent job: %w", err)
		}
		claimed, err := scanAgentJobs(rows)
		if err != nil {
			return nil, err
		}
		if len(claimed) != 1 {
			continue
		}
		for _, m := range members {
			res, err := tx.ExecContext(ctx,
				`UPDATE agent_jobs
				    SET status = $1, coalesced_into = $2, turn_id = $3, updated_at = $4
				  WHERE id = $5 AND status = $6`,
				JobCoalesced, c.id, tid, now, m.id, JobPending)
			if err != nil {
				return nil, fmt.Errorf("coalesce agent job: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return nil, errors.New("coalesce agent job: member moved concurrently")
			}
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO agent_job_attempts(job_id, attempt, started_at) VALUES($1,$2,$3)`,
			claimed[0].ID, claimed[0].Attempts, now,
		); err != nil {
			return nil, fmt.Errorf("insert job attempt: %w", err)
		}
		if err := s.fillSourceEvents(ctx, tx, claimed); err != nil {
			return nil, err
		}
		jobs = append(jobs, claimed[0])
	}
	sort.SliceStable(jobs, func(i, k int) bool {
		if !jobs[i].NextRunAt.Equal(jobs[k].NextRunAt) {
			return jobs[i].NextRunAt.Before(jobs[k].NextRunAt)
		}
		return jobs[i].ID < jobs[k].ID
	})
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit claim tx: %w", err)
	}
	return jobs, nil
}

// readyTurn builds the turn for head c from the head and the conversation's
// never-claimed pending followers. It reports the turn id, the follower jobs
// that belong to the head's turn, and whether that turn is READY.
func (s *Store) readyTurn(ctx context.Context, tx *sql.Tx, userID int64, c claimCandidate, now time.Time, lock string) (string, []claimCandidate, bool, error) {
	followers := []claimCandidate{}
	if c.conversationID.Valid {
		var err error
		followers, err = loadClaimCandidates(ctx, tx,
			`SELECT j.id, j.event_id, j.conversation_id, j.created_at, COALESCE(j.body_bytes, 0),
			        e.chat_tg_id, j.turn_id
			   FROM agent_jobs j
			   JOIN incoming_events e ON e.event_id = j.event_id AND e.user_id = j.user_id
			  WHERE j.conversation_id = $1 AND j.user_id = $2 AND j.status = $3
			    AND j.attempts = 0 AND j.id > $4
			  ORDER BY j.id`+blockingLock(lock),
			c.conversationID.Int64, userID, JobPending, c.id)
		if err != nil {
			return "", nil, false, fmt.Errorf("load turn followers: %w", err)
		}
	}
	cfg := *s.turnCfg
	co, err := turn.New(cfg)
	if err != nil {
		return "", nil, false, err
	}
	events := append([]claimCandidate{c}, followers...)
	// Backlog: jobs that waited behind an earlier turn of this conversation
	// could not be claimed however far apart they arrived, so
	// their gaps say nothing about the sender's burst. They are offered at the
	// arrival time of the last of them, which merges them into one turn (still
	// within MaxMsgs/MaxBytes) and starts the quiet window from that last
	// arrival rather than from the end of the earlier turn.
	until, blocked, err := backlogUntil(ctx, tx, c)
	if err != nil {
		return "", nil, false, err
	}
	var backlogAt time.Time
	if blocked {
		for _, e := range events {
			if e.createdAt.Before(until) && e.createdAt.After(backlogAt) {
				backlogAt = e.createdAt
			}
		}
	}
	byEvent := map[string]claimCandidate{}
	var closed []turn.Turn
	for _, e := range events {
		byEvent[e.eventID] = e
		at := e.createdAt
		if blocked && at.Before(until) {
			at = backlogAt
		}
		closed = append(closed, co.Offer(turn.Event{
			ID:         e.eventID,
			SessionKey: turn.SessionKey(userID, e.chatTGID),
			At:         at,
			Bytes:      e.bytes,
		})...)
	}
	closed = append(closed, co.Tick(now)...)
	for _, t := range closed {
		if len(t.SourceEventIDs) == 0 || t.SourceEventIDs[0] != c.eventID {
			continue
		}
		var members []claimCandidate
		for _, id := range t.SourceEventIDs[1:] {
			members = append(members, byEvent[id])
		}
		return t.TurnID, members, true, nil
	}
	return "", nil, false, nil
}

// backlogUntil reports whether head c waited behind an earlier attempt of its
// conversation, and if so when the latest such attempt finished. Jobs created before that moment are the conversation's backlog.
func backlogUntil(ctx context.Context, tx *sql.Tx, c claimCandidate) (time.Time, bool, error) {
	if !c.conversationID.Valid {
		return time.Time{}, false, nil
	}
	// Any attempt of an earlier job that finished after c arrived held c back,
	// whether it started before c arrived or after (c left over by a capped
	// turn, or queued behind a head still collecting). created_at is stamped
	// by the database and finished_at by the app, so skew between the two
	// clocks (or SQLite's whole-second CURRENT_TIMESTAMP) can only miss a job
	// at the boundary, which falls back to arrival-gap coalescing.
	var until sql.NullTime
	err := tx.QueryRowContext(ctx,
		`SELECT a.finished_at
		   FROM agent_job_attempts a
		   JOIN agent_jobs p ON p.id = a.job_id
		  WHERE p.conversation_id = $1 AND p.id < $2
		    AND a.finished_at > $3
		  ORDER BY a.finished_at DESC
		  LIMIT 1`,
		c.conversationID.Int64, c.id, c.createdAt).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("load turn backlog: %w", err)
	}
	return until.Time, until.Valid, nil
}

// blockingLock turns a SKIP LOCKED suffix into a plain row lock: followers
// must not silently drop out of a turn because another transaction holds them.
func blockingLock(lock string) string {
	if lock == "" {
		return ""
	}
	return " FOR UPDATE OF j"
}

func loadClaimCandidates(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]claimCandidate, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []claimCandidate
	for rows.Next() {
		var c claimCandidate
		if err := rows.Scan(&c.id, &c.eventID, &c.conversationID, &c.createdAt, &c.bytes, &c.chatTGID, &c.turnID); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
