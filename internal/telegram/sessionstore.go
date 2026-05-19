package telegram

import (
	"context"
	"errors"

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

// errNilStore is returned by StoreSession when the wrapped *db.Store is nil
// — defensive guard so a misconfigured pool surfaces a clean error instead
// of a SIGSEGV from inside gotd's MTProto goroutine.
var errNilStore = errors.New("sessionstore: nil *db.Store (pool constructed without a session store)")

func (s *SessionStore) LoadSession(ctx context.Context) ([]byte, error) {
	// gotd treats a nil store as "no persisted session" via ErrNotFound and
	// drives the caller toward the auth flow. Returning a hard error would
	// crash any test that exercises clientpool.acquire without a real DB.
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
		return errNilStore
	}
	return s.Store.UpdateSessionBlob(ctx, s.UserID, data)
}
