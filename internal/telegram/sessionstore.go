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
	// gotd can load storage more than once during one client's lifetime.
	// Keep the first row immutable so an old client can never switch its
	// identity to a replacement session created by a concurrent OAuth flow.
	s.rowID.CompareAndSwap(0, rowID)
	return pt, nil
}

func (s *SessionStore) StoreSession(ctx context.Context, data []byte) error {
	if s.Store == nil {
		return nil
	}
	if rowID := s.rowID.Load(); rowID > 0 {
		return s.Store.UpdateSessionBlobByID(ctx, s.UserID, rowID, data)
	}
	return s.Store.UpdateSessionBlob(ctx, s.UserID, data)
}

// LoadedRowID identifies the immutable telegram_accounts row whose auth key
// this gotd client loaded. It remains stable when gotd rotates session bytes.
func (s *SessionStore) LoadedRowID() int64 {
	return s.rowID.Load()
}
