package telegram

import (
	"context"

	"github.com/gotd/td/telegram/updates"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// UpdateStateStore adapts the DB-backed tg_update_state / tg_channel_state
// tables to gotd's updates.StateStorage and updates.ChannelAccessHasher, the
// same way SessionStore adapts telegram_accounts.session_encrypted.
//
// Key mapping: gotd keys every call by the TELEGRAM user id it was given in
// Manager.Run, but the tables are keyed by the internal users.id (FK with
// cascade). One UpdateStateStore is constructed per agent-enabled account
// with the internal id pinned; gotd's id argument is ignored for keying.
// Safe because a Manager instance only ever serves the single user it runs
// for.
type UpdateStateStore struct {
	UserID int64 // internal users.id
	Store  *db.Store
}

var (
	_ updates.StateStorage        = (*UpdateStateStore)(nil)
	_ updates.ChannelAccessHasher = (*UpdateStateStore)(nil)
)

// GetState implements updates.StateStorage.
func (u *UpdateStateStore) GetState(ctx context.Context, _ int64) (updates.State, bool, error) {
	st, found, err := u.Store.GetTGUpdateState(ctx, u.UserID)
	return updates.State{Pts: st.Pts, Qts: st.Qts, Date: st.Date, Seq: st.Seq}, found, err
}

// SetState implements updates.StateStorage.
func (u *UpdateStateStore) SetState(ctx context.Context, _ int64, state updates.State) error {
	return u.Store.SetTGUpdateState(ctx, u.UserID, db.TGUpdateState{
		Pts: state.Pts, Qts: state.Qts, Date: state.Date, Seq: state.Seq,
	})
}

// SetPts implements updates.StateStorage.
func (u *UpdateStateStore) SetPts(ctx context.Context, _ int64, pts int) error {
	return u.Store.SetTGPts(ctx, u.UserID, pts)
}

// SetQts implements updates.StateStorage.
func (u *UpdateStateStore) SetQts(ctx context.Context, _ int64, qts int) error {
	return u.Store.SetTGQts(ctx, u.UserID, qts)
}

// SetDate implements updates.StateStorage.
func (u *UpdateStateStore) SetDate(ctx context.Context, _ int64, date int) error {
	return u.Store.SetTGDate(ctx, u.UserID, date)
}

// SetSeq implements updates.StateStorage.
func (u *UpdateStateStore) SetSeq(ctx context.Context, _ int64, seq int) error {
	return u.Store.SetTGSeq(ctx, u.UserID, seq)
}

// SetDateSeq implements updates.StateStorage.
func (u *UpdateStateStore) SetDateSeq(ctx context.Context, _ int64, date, seq int) error {
	return u.Store.SetTGDateSeq(ctx, u.UserID, date, seq)
}

// GetChannelPts implements updates.StateStorage.
func (u *UpdateStateStore) GetChannelPts(ctx context.Context, _ int64, channelID int64) (int, bool, error) {
	return u.Store.GetTGChannelPts(ctx, u.UserID, channelID)
}

// SetChannelPts implements updates.StateStorage.
func (u *UpdateStateStore) SetChannelPts(ctx context.Context, _ int64, channelID int64, pts int) error {
	return u.Store.SetTGChannelPts(ctx, u.UserID, channelID, pts)
}

// ForEachChannels implements updates.StateStorage.
func (u *UpdateStateStore) ForEachChannels(ctx context.Context, _ int64, f func(ctx context.Context, channelID int64, pts int) error) error {
	return u.Store.ForEachTGChannel(ctx, u.UserID, f)
}

// SetChannelAccessHash implements updates.ChannelAccessHasher.
func (u *UpdateStateStore) SetChannelAccessHash(ctx context.Context, _ int64, channelID, accessHash int64) error {
	return u.Store.SetTGChannelAccessHash(ctx, u.UserID, channelID, accessHash)
}

// GetChannelAccessHash implements updates.ChannelAccessHasher.
func (u *UpdateStateStore) GetChannelAccessHash(ctx context.Context, _ int64, channelID int64) (int64, bool, error) {
	return u.Store.GetTGChannelAccessHash(ctx, u.UserID, channelID)
}
