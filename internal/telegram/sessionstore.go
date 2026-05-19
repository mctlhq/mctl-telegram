package telegram

import (
	"context"

	"github.com/gotd/td/session"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// SessionStore implements gotd's session.Storage interface (LoadSession,
// StoreSession). It is bound to a single user_id so each gotd client serves
// exactly one operator account.
type SessionStore struct {
	UserID int64
	Store  *db.Store
}

func (s *SessionStore) LoadSession(ctx context.Context) ([]byte, error) {
	if s.Store == nil {
		return nil, session.ErrNotFound
	}
	pt, err := s.Store.LoadSession(ctx, s.UserID)
	if err != nil {
		return nil, err
	}
	if pt == nil {
		return nil, session.ErrNotFound
	}
	return pt, nil
}

func (s *SessionStore) StoreSession(ctx context.Context, data []byte) error {
	if s.Store == nil {
		return nil
	}
	return s.Store.UpdateSessionBlob(ctx, s.UserID, data)
}
