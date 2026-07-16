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

// SetTGUpdateState upserts the full watermark.
func (s *Store) SetTGUpdateState(ctx context.Context, userID int64, st TGUpdateState) error {
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO tg_update_state(user_id, pts, qts, date, seq)
		 VALUES($1,$2,$3,$4,$5)
		 ON CONFLICT (user_id) DO UPDATE SET
		   pts = EXCLUDED.pts, qts = EXCLUDED.qts,
		   date = EXCLUDED.date, seq = EXCLUDED.seq`,
		userID, st.Pts, st.Qts, st.Date, st.Seq,
	); err != nil {
		return fmt.Errorf("set tg update state: %w", err)
	}
	return nil
}

// setTGUpdateField updates a single watermark column; ErrTGUpdateStateNotFound
// when no row exists (gotd contract for the partial setters).
func (s *Store) setTGUpdateField(ctx context.Context, userID int64, query string, args ...any) error {
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
		userID, `UPDATE tg_update_state SET pts = $1 WHERE user_id = $2`, pts, userID)
}

// SetTGQts updates the qts.
func (s *Store) SetTGQts(ctx context.Context, userID int64, qts int) error {
	return s.setTGUpdateField(ctx,
		userID, `UPDATE tg_update_state SET qts = $1 WHERE user_id = $2`, qts, userID)
}

// SetTGDate updates the date.
func (s *Store) SetTGDate(ctx context.Context, userID int64, date int) error {
	return s.setTGUpdateField(ctx,
		userID, `UPDATE tg_update_state SET date = $1 WHERE user_id = $2`, date, userID)
}

// SetTGSeq updates the seq.
func (s *Store) SetTGSeq(ctx context.Context, userID int64, seq int) error {
	return s.setTGUpdateField(ctx,
		userID, `UPDATE tg_update_state SET seq = $1 WHERE user_id = $2`, seq, userID)
}

// SetTGDateSeq updates date and seq together.
func (s *Store) SetTGDateSeq(ctx context.Context, userID int64, date, seq int) error {
	return s.setTGUpdateField(ctx,
		userID, `UPDATE tg_update_state SET date = $1, seq = $2 WHERE user_id = $3`, date, seq, userID)
}

// GetTGChannelPts returns the stored pts for one channel.
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

// ForEachTGChannel iterates the account's stored channels.
func (s *Store) ForEachTGChannel(ctx context.Context, userID int64, f func(ctx context.Context, channelID int64, pts int) error) error {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT channel_id, pts FROM tg_channel_state WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("list tg channels: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var channelID int64
		var pts int
		if err := rows.Scan(&channelID, &pts); err != nil {
			return fmt.Errorf("scan tg channel: %w", err)
		}
		if err := f(ctx, channelID, pts); err != nil {
			return err
		}
	}
	return rows.Err()
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
	return accessHash, true, nil
}
