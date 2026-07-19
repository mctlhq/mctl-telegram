package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// TGUpdateState is the gotd updates.Manager watermark for one account:
// the general pts/qts/date/seq quadruple. Per-channel pts and access hashes
// live in tg_channel_state. Keyed by the internal users.id (FK, cascades on
// user deletion) — the adapter in internal/telegram maps gotd's telegram-side
// user id onto the internal id.
type TGUpdateState struct {
	Pts, Qts, Date, Seq int
}

// ErrTGUpdateStateNotFound is returned by the partial setters (SetTGPts &co)
// when no state row exists yet — gotd requires this to be an error so it can
// fall back to SetState.
var ErrTGUpdateStateNotFound = errors.New("tg update state not found")

// GetTGUpdateState returns the account's stored update watermark.
// found=false (no error) when the account has no state yet.
func (s *Store) GetTGUpdateState(ctx context.Context, userID int64) (state TGUpdateState, found bool, err error) {
	err = s.DB.QueryRowContext(ctx,
		`SELECT pts, qts, date, seq FROM tg_update_state WHERE user_id = $1`,
		userID,
	).Scan(&state.Pts, &state.Qts, &state.Date, &state.Seq)
	if errors.Is(err, sql.ErrNoRows) {
		return state, false, nil
	}
	if err != nil {
		return state, false, fmt.Errorf("get tg update state: %w", err)
	}
	return state, true, nil
}

// SetTGUpdateState upserts the full watermark and drops the account's stored
// channel state.
//
// gotd calls SetState only when it (re)initializes the whole update state —
// e.g. Manager.Run with AuthOptions.Forget, or after the main state row is
// recreated — and its reference storage resets the user's channel map on that
// path, immediately reloading channels via ForEachChannels. Leaving the old
// tg_channel_state rows behind would seed recovery from stale pts / access
// hashes instead of the freshly fetched remote state, so the reset is done
// atomically with the watermark write.
func (s *Store) SetTGUpdateState(ctx context.Context, userID int64, st TGUpdateState) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin set tg update state: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO tg_update_state(user_id, pts, qts, date, seq)
		 VALUES($1,$2,$3,$4,$5)
		 ON CONFLICT (user_id) DO UPDATE SET
		   pts = EXCLUDED.pts, qts = EXCLUDED.qts,
		   date = EXCLUDED.date, seq = EXCLUDED.seq`,
		userID, st.Pts, st.Qts, st.Date, st.Seq,
	); err != nil {
		return fmt.Errorf("set tg update state: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM tg_channel_state WHERE user_id = $1`, userID,
	); err != nil {
		return fmt.Errorf("reset tg channel state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit set tg update state: %w", err)
	}
	return nil
}

// setTGUpdateField updates a single watermark column; ErrTGUpdateStateNotFound
// when no row exists (gotd contract for the partial setters).
func (s *Store) setTGUpdateField(ctx context.Context, query string, args ...any) error {
	res, err := s.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("set tg update field: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTGUpdateStateNotFound
	}
	return nil
}

// SetTGPts updates the general pts.
func (s *Store) SetTGPts(ctx context.Context, userID int64, pts int) error {
	return s.setTGUpdateField(ctx,
		`UPDATE tg_update_state SET pts = $1 WHERE user_id = $2`, pts, userID)
}

// SetTGQts updates the qts.
func (s *Store) SetTGQts(ctx context.Context, userID int64, qts int) error {
	return s.setTGUpdateField(ctx,
		`UPDATE tg_update_state SET qts = $1 WHERE user_id = $2`, qts, userID)
}

// SetTGDate updates the date.
func (s *Store) SetTGDate(ctx context.Context, userID int64, date int) error {
	return s.setTGUpdateField(ctx,
		`UPDATE tg_update_state SET date = $1 WHERE user_id = $2`, date, userID)
}

// SetTGSeq updates the seq.
func (s *Store) SetTGSeq(ctx context.Context, userID int64, seq int) error {
	return s.setTGUpdateField(ctx,
		`UPDATE tg_update_state SET seq = $1 WHERE user_id = $2`, seq, userID)
}

// SetTGDateSeq updates date and seq together.
func (s *Store) SetTGDateSeq(ctx context.Context, userID int64, date, seq int) error {
	return s.setTGUpdateField(ctx,
		`UPDATE tg_update_state SET date = $1, seq = $2 WHERE user_id = $3`, date, seq, userID)
}

// GetTGChannelPts returns the stored pts for one channel.
//
// A tg_channel_state row can be created by SetTGChannelAccessHash with pts
// left at its default 0 (the two setters share the row). Since a channel's pts
// is a positive sequence counter that is never legitimately 0, a stored 0
// means "pts was never set" — report found=false so gotd fetches the current
// state instead of resuming from a bogus 0.
func (s *Store) GetTGChannelPts(ctx context.Context, userID, channelID int64) (pts int, found bool, err error) {
	err = s.DB.QueryRowContext(ctx,
		`SELECT pts FROM tg_channel_state WHERE user_id = $1 AND channel_id = $2`,
		userID, channelID,
	).Scan(&pts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("get tg channel pts: %w", err)
	}
	if pts == 0 {
		return 0, false, nil
	}
	return pts, true, nil
}

// SetTGChannelPts upserts the pts for one channel.
func (s *Store) SetTGChannelPts(ctx context.Context, userID, channelID int64, pts int) error {
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO tg_channel_state(user_id, channel_id, pts)
		 VALUES($1,$2,$3)
		 ON CONFLICT (user_id, channel_id) DO UPDATE SET pts = EXCLUDED.pts`,
		userID, channelID, pts,
	); err != nil {
		return fmt.Errorf("set tg channel pts: %w", err)
	}
	return nil
}

// ForEachTGChannel iterates the account's initialized channels.
//
// The rows are fully materialized and the cursor closed BEFORE any callback
// runs. gotd's Manager.Run calls GetChannelAccessHash from inside this
// callback, and on SQLite db.Open pins the pool to a single connection
// (MaxOpenConns(1)) — invoking the callback while the cursor still held that
// connection would deadlock the nested query until the context was cancelled,
// hanging listener startup for any account with a stored channel row.
//
// Rows with pts = 0 are skipped: they were created by SetTGChannelAccessHash
// (which leaves pts at its default) and represent a channel whose pts was
// never initialized. Reporting them would make gotd start channel-difference
// recovery from zero. See GetTGChannelPts for the same sentinel rule.
func (s *Store) ForEachTGChannel(ctx context.Context, userID int64, f func(ctx context.Context, channelID int64, pts int) error) error {
	type channelState struct {
		id  int64
		pts int
	}
	var states []channelState
	if err := func() error {
		rows, err := s.DB.QueryContext(ctx,
			`SELECT channel_id, pts FROM tg_channel_state WHERE user_id = $1 AND pts <> 0`,
			userID,
		)
		if err != nil {
			return fmt.Errorf("list tg channels: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var cs channelState
			if err := rows.Scan(&cs.id, &cs.pts); err != nil {
				return fmt.Errorf("scan tg channel: %w", err)
			}
			states = append(states, cs)
		}
		return rows.Err()
	}(); err != nil {
		return err
	}
	for _, cs := range states {
		if err := f(ctx, cs.id, cs.pts); err != nil {
			return err
		}
	}
	return nil
}

// SetTGChannelAccessHash upserts a channel access hash (keeps pts when the
// row already exists).
func (s *Store) SetTGChannelAccessHash(ctx context.Context, userID, channelID, accessHash int64) error {
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO tg_channel_state(user_id, channel_id, access_hash)
		 VALUES($1,$2,$3)
		 ON CONFLICT (user_id, channel_id) DO UPDATE SET access_hash = EXCLUDED.access_hash`,
		userID, channelID, accessHash,
	); err != nil {
		return fmt.Errorf("set tg channel access hash: %w", err)
	}
	return nil
}

// GetTGChannelAccessHash returns a stored channel access hash.
//
// The row may have been created by SetTGChannelPts with access_hash left at
// its default 0. A Telegram access hash is never legitimately 0, so a stored 0
// means "access hash was never set" — report found=false so gotd re-resolves
// the channel rather than using a bogus 0 hash (which would fail every call).
func (s *Store) GetTGChannelAccessHash(ctx context.Context, userID, channelID int64) (accessHash int64, found bool, err error) {
	err = s.DB.QueryRowContext(ctx,
		`SELECT access_hash FROM tg_channel_state WHERE user_id = $1 AND channel_id = $2`,
		userID, channelID,
	).Scan(&accessHash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("get tg channel access hash: %w", err)
	}
	if accessHash == 0 {
		return 0, false, nil
	}
	return accessHash, true, nil
}
