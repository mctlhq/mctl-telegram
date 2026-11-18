package connection_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// TestConnection_S1C4_RefreshCallEndsBeforeLease pins the other half of
// S1-C4: the outbound refresh call must end before the store lease does, or
// another replica could take the lease and present the same refresh token
// while this one is still on the wire.
func TestConnection_S1C4_RefreshCallEndsBeforeLease(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		const lease = 400 * time.Millisecond
		e.withLease(t, lease)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)

		start := time.Now()
		var deadline time.Time
		var bounded bool
		_, err := e.m.Refresh(ctx, alice, c.ID, func(fctx context.Context, _ connection.Server, _ connection.Secret) ([]byte, error) {
			deadline, bounded = fctx.Deadline()
			select {
			case <-fctx.Done():
				return nil, fctx.Err()
			case <-time.After(10 * time.Second):
				return nil, errors.New("refresh call outlived its lease")
			}
		})
		if !bounded || !deadline.Before(start.Add(lease)) {
			t.Fatalf("refresh call deadline %v (set %v), want before the lease ends at %v", deadline, bounded, start.Add(lease))
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err %v, want the call's deadline", err)
		}
		got, err := e.m.Get(ctx, alice, c.ID)
		if err != nil || got.State != connection.StateActive || got.TokenGeneration != c.TokenGeneration {
			t.Fatalf("after a timed-out refresh: %+v (%v), want active and unrotated", got, err)
		}
	})
}

// TestConnection_S1C4_CancelledCallerStillStores: once the server has
// rotated the tokens, a caller that stops waiting must not stop the
// rotation from being stored. Otherwise the row keeps a refresh token the
// server has already consumed, and the connection later expires.
func TestConnection_S1C4_CancelledCallerStillStores(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)

		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		_, err := e.m.Refresh(cctx, alice, c.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			cancel() // the caller goes away after the server rotated
			return tokenResponse("fake-at-cx-"+c.ID, "fake-rt-cx-"+c.ID, tgScope), nil
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("err %v, want nil or the caller's cancellation", err)
		}
		stop := time.Now().Add(5 * time.Second)
		for {
			got, err := e.m.Get(ctx, alice, c.ID)
			if err == nil && got.TokenGeneration == c.TokenGeneration+1 {
				break
			}
			if time.Now().After(stop) {
				t.Fatalf("rotation was not stored after the caller left: %+v (%v)", got, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil || tok.Reveal() != "fake-at-cx-"+c.ID {
			t.Fatalf("access token after rotation: err %v", err)
		}
		if r := e.revoker.revoked(); slices.Contains(r, "fake-at-cx-"+c.ID) {
			t.Fatal("the stored tokens were revoked")
		}
	})
}

// TestConnection_S1C4_FencedRotationRevokesIssued: a disconnect that lands
// while the refresh is on the wire makes the rotation CAS miss. That is
// ErrFenced, and what the server issued is revoked, never stored.
func TestConnection_S1C4_FencedRotationRevokesIssued(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		_, err := e.m.Refresh(ctx, alice, c.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			if _, err := e.m.Disconnect(ctx, alice, c.ID); err != nil {
				t.Errorf("disconnect: %v", err)
			}
			return tokenResponse("fake-at-fx-"+c.ID, "fake-rt-fx-"+c.ID, tgScope), nil
		})
		if !errors.Is(err, connection.ErrFenced) {
			t.Fatalf("err %v, want ErrFenced", err)
		}
		if r := e.revoker.revoked(); !slices.Contains(r, "fake-at-fx-"+c.ID) || !slices.Contains(r, "fake-rt-fx-"+c.ID) {
			t.Fatal("tokens issued after the disconnect were not revoked")
		}
	})
}

// rotateFailingStore fails every rotation write with a non-CAS error.
type rotateFailingStore struct{ connection.Store }

func (rotateFailingStore) RotatePAConnectionTokens(context.Context, int64, string, connection.Rotation) (connection.Connection, error) {
	return connection.Connection{}, errInjected
}

// TestConnection_S1C4_RotationStoreErrorIsNotAFence: a rotation write that
// fails for a reason other than a CAS miss is reported as that error, not
// as ErrFenced. The issued tokens are still revoked.
func TestConnection_S1C4_RotationStoreErrorIsNotAFence(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnvWithStore(t, s, rotateFailingStore{s})
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		_, err := e.m.Refresh(ctx, alice, c.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			return tokenResponse("fake-at-sx-"+c.ID, "fake-rt-sx-"+c.ID, tgScope), nil
		})
		if errors.Is(err, connection.ErrFenced) || !errors.Is(err, errInjected) {
			t.Fatalf("err %v, want the store error and not ErrFenced", err)
		}
		if r := e.revoker.revoked(); !slices.Contains(r, "fake-at-sx-"+c.ID) {
			t.Fatal("unstored tokens were not revoked")
		}
	})
}

// TestConnection_S1C7_RevisionMoveFencesActiveRow pins the revision branch
// of Call.Finish: a row that is still active but at a different authority
// revision than the call was bound to is fenced.
func TestConnection_S1C7_RevisionMoveFencesActiveRow(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		call, err := e.m.BeginCall(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_connections SET authority_revision = authority_revision + 1
			WHERE principal = $1 AND id = $2`, alice, c.ID); err != nil {
			t.Fatal(err)
		}
		if got, err := e.m.Get(ctx, alice, c.ID); err != nil || got.State != connection.StateActive {
			t.Fatalf("row %+v (%v), want still active", got, err)
		}
		if err := call.Finish(ctx); !errors.Is(err, connection.ErrFenced) {
			t.Fatalf("err %v, want ErrFenced", err)
		}
		if evs := e.auditor.all(); len(evs) != 1 || evs[0].Reason != "revision_changed" {
			t.Fatalf("fenced audit = %+v, want revision_changed", evs)
		}
	})
}

// disconnectAfterReadStore runs a disconnect right after the first
// connection read returns, i.e. after Authorize saw the row active.
type disconnectAfterReadStore struct {
	connection.Store
	once sync.Once
	hook func()
}

func (d *disconnectAfterReadStore) GetPAConnection(ctx context.Context, p int64, id string) (connection.Connection, error) {
	c, err := d.Store.GetPAConnection(ctx, p, id)
	if d.hook != nil {
		d.once.Do(d.hook)
	}
	return c, err
}

// TestConnection_S1C6_DisconnectDuringBeginCallCancels: a disconnect that
// commits after BeginCall's gate read must still cancel that call.
func TestConnection_S1C6_DisconnectDuringBeginCallCancels(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		ds := &disconnectAfterReadStore{Store: s}
		e := newEnvWithStore(t, s, ds)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		ds.hook = func() {
			if _, err := e.m.Disconnect(ctx, alice, c.ID); err != nil {
				t.Errorf("disconnect: %v", err)
			}
		}
		call, err := e.m.BeginCall(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil {
			t.Fatalf("begin call: %v (the gate read happened before the disconnect)", err)
		}
		select {
		case <-call.Ctx.Done():
		default:
			t.Fatal("a call authorized just before a disconnect was not cancelled by it")
		}
		if err := call.Finish(ctx); !errors.Is(err, connection.ErrFenced) {
			t.Fatalf("finish err %v, want ErrFenced", err)
		}
	})
}
