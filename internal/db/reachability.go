package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// BotReachability is the admin-facing projection of a client_bot_reachability
// row: whether the login bot may currently initiate a chat with this client,
// and how that was learned. Omitted entirely from IdentityRow when the user
// has no row (i.e. reachability has never been recorded), which reads as
// "unknown" without a synthetic row ever being written for them.
type BotReachability struct {
	State      string     `json:"state"`
	ReasonCode string     `json:"reason_code,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Source     string     `json:"source,omitempty"`
}

// RecordBotReachability upserts client_bot_reachability for userID from a
// classified delivery outcome. Writes only when outcome.Conclusive is true --
// a non-conclusive outcome (429, 5xx, transport error) must leave the
// existing state and observed_at untouched, per the requirement that a
// transient failure never downgrades a previously-recorded reachable row.
func (s *Store) RecordBotReachability(ctx context.Context, userID int64, outcome notify.DeliveryOutcome, source string) error {
	if !outcome.Conclusive {
		return nil
	}
	if userID <= 0 {
		return errors.New("user id must be positive")
	}
	if err := upsertBotReachability(ctx, s.DB, userID, outcome, source); err != nil {
		return fmt.Errorf("record bot reachability: %w", err)
	}
	return nil
}

// RecordInboundBotReachabilityTx records reachability learned from an inbound
// update, inside the caller's transaction so the write commits or rolls back
// with the receiver's done mark. Same conclusive-only rule.
//
// observedAt is when the evidence was observed -- for the login bot, the
// update's received_at, persisted at accept time. Unlike an outbound delivery,
// which is classified the moment it happens, an inbound update can be
// dispatched late when the pending sweep retries it. So the write applies only when observedAt is strictly newer than the
// stored observed_at; a stale /start never overwrites a newer conclusive
// observation such as a later `blocked`. applied reports whether the row was
// written; false with a nil error means the stored observation is newer.
func (s *Store) RecordInboundBotReachabilityTx(ctx context.Context, tx *sql.Tx, userID int64, outcome notify.DeliveryOutcome, source string, observedAt time.Time) (applied bool, err error) {
	if !outcome.Conclusive {
		return false, nil
	}
	if userID <= 0 {
		return false, errors.New("user id must be positive")
	}
	if observedAt.IsZero() {
		return false, errors.New("observed time must be set")
	}
	observedAt = observedAt.UTC()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO client_bot_reachability(user_id, state, reason_code, observed_at, source, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (user_id) DO UPDATE SET
		     state = EXCLUDED.state,
		     reason_code = EXCLUDED.reason_code,
		     observed_at = EXCLUDED.observed_at,
		     source = EXCLUDED.source,
		     updated_at = EXCLUDED.updated_at
		 WHERE client_bot_reachability.observed_at IS NULL
		    OR client_bot_reachability.observed_at < EXCLUDED.observed_at`,
		userID, outcome.State, outcome.ReasonCode, observedAt, source, time.Now().UTC(),
	)
	if err != nil {
		return false, fmt.Errorf("record inbound bot reachability: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("record inbound bot reachability: rows affected: %w", err)
	}
	return n > 0, nil
}

func upsertBotReachability(ctx context.Context, ex execer, userID int64, outcome notify.DeliveryOutcome, source string) error {
	now := time.Now().UTC()
	_, err := ex.ExecContext(ctx,
		`INSERT INTO client_bot_reachability(user_id, state, reason_code, observed_at, source, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (user_id) DO UPDATE SET
		     state = EXCLUDED.state,
		     reason_code = EXCLUDED.reason_code,
		     observed_at = EXCLUDED.observed_at,
		     source = EXCLUDED.source,
		     updated_at = EXCLUDED.updated_at`,
		userID, outcome.State, outcome.ReasonCode, now, source, now,
	)
	return err
}

// GetBotReachability reads one user's reachability row, or nil when none has
// ever been recorded (reads as "unknown" with no observation metadata).
func (s *Store) GetBotReachability(ctx context.Context, userID int64) (*BotReachability, error) {
	var (
		state      string
		reasonCode string
		observedAt sql.NullTime
		source     string
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT state, reason_code, observed_at, source FROM client_bot_reachability WHERE user_id = $1`,
		userID,
	).Scan(&state, &reasonCode, &observedAt, &source)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get bot reachability: %w", err)
	}
	r := &BotReachability{State: state, ReasonCode: reasonCode, Source: source}
	if observedAt.Valid {
		t := observedAt.Time
		r.ObservedAt = &t
	}
	return r, nil
}
