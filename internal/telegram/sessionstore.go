package telegram

import (
	"context"
	"sync/atomic"

	"github.com/gotd/td/session"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// SessionStore implements gotd's session.Storage interface (LoadSession,
// StoreSession). It is bound to a single user_id so each gotd client serves
// exactly one operator account.
type SessionStore struct {
	UserID int64
	Store  *db.Store
	rowID  atomic.Int64
}

func (s *SessionStore) LoadSession(ctx context.Context) ([]byte, error) {
	if s.Store == nil {
		return nil, session.ErrNotFound
	}
	pt, rowID, err := s.Store.LoadSessionWithID(ctx, s.UserID)
	if err != nil {
		return nil, err
	}
	if pt == nil {
		return nil, session.ErrNotFound
	}
	s.rowID.Store(rowID)
	return pt, nil
}

func (s *SessionStore) StoreSession(ctx context.Context, data []byte) error {
	if s.Store == nil {
		return nil
	}
	return s.Store.UpdateSessionBlob(ctx, s.UserID, data)
}

// LoadedRowID identifies the immutable telegram_accounts row whose auth key
// this gotd client loaded. It remains stable when gotd rotates session bytes.
func (s *SessionStore) LoadedRowID() int64 {
	return s.rowID.Load()
}
