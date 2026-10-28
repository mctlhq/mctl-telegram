package telegram

import (
	"context"
	"errors"
	"sync"

	"github.com/gotd/td/session"
)

// deferredSession is the gotd session.Storage of a login whose account is not
// yet known to be the right one (#901). gotd writes the session as soon as it
// has an auth key, long before sign-in finishes, so a login on the database
// store has already overwritten the user's row by the time it can tell whose
// account it signed in to. This store keeps every write in memory instead and
// hands the latest bytes to target only on commit, which the login calls once
// the account check has passed. On a mismatch nothing reaches target at all.
//
// LoadSession serves only what this store buffered itself, never target's
// row: the login always starts from a fresh auth key, so the logOut of a
// mismatched account ends that key and not the user's existing session.
type deferredSession struct {
	target session.Storage

	mu   sync.Mutex
	data []byte
}

func (d *deferredSession) LoadSession(context.Context) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.data == nil {
		return nil, session.ErrNotFound
	}
	return append([]byte(nil), d.data...), nil
}

func (d *deferredSession) StoreSession(_ context.Context, data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data = append([]byte(nil), data...)
	return nil
}

// take empties the buffer and returns what it held.
func (d *deferredSession) take() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	data := d.data
	d.data = nil
	return data
}

// settle ends the deferral: on a mismatch the buffered bytes are dropped
// without a single write to target, otherwise the latest ones are written
// through once. A failed write puts them back, so the caller can still log
// out the authorization they carry instead of leaving it orphaned.
func (d *deferredSession) settle(ctx context.Context, mismatch bool) error {
	data := d.take()
	if mismatch {
		return nil
	}
	if data == nil {
		return errors.New("login completed but no session bytes were persisted")
	}
	if err := d.target.StoreSession(ctx, data); err != nil {
		d.mu.Lock()
		if d.data == nil {
			d.data = data
		}
		d.mu.Unlock()
		return err
	}
	return nil
}
