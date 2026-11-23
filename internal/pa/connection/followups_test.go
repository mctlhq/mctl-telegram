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

// Follow-ups of #1332 (refresh timing, the final exchange write, and the
// CompleteExchange caller contract), landed with the linking slice of #1314.

// fakeClock is a settable clock for the manager.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// countingKEK counts Unwrap calls.
type countingKEK struct {
	connection.KEK
	mu      sync.Mutex
	unwraps int
}

func (k *countingKEK) Unwrap(ctx context.Context, w []byte) ([]byte, error) {
	k.mu.Lock()
	k.unwraps++
	k.mu.Unlock()
	return k.KEK.Unwrap(ctx, w)
}

func (k *countingKEK) count() int { k.mu.Lock(); defer k.mu.Unlock(); return k.unwraps }

func (e *env) withClockAndKEK(t *testing.T, clock *fakeClock, lease time.Duration) *countingKEK {
	t.Helper()
	base, err := connection.NewLocalKEK(testKEKKey, "test")
	if err != nil {
		t.Fatal(err)
	}
	kek := &countingKEK{KEK: base}
	e.m, err = connection.NewManager(connection.Config{
		Store: e.store, KEK: kek, Revoker: e.revoker, Auditor: e.auditor, Now: clock.Now, RefreshLease: lease,
	})
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// TestConnection_S1C4_RotationAfterLeaseIsFenced: the steps after the
// refresh call are bounded by the lease end on the manager's own clock. A
// call that returns when, by that clock, the lease has already run out must
// not store its rotation (another replica may hold the lease by then); the
// tokens it got are revoked and the result is ErrFenced.
func TestConnection_S1C4_RotationAfterLeaseIsFenced(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		clock := &fakeClock{t: time.Now()}
		const lease = time.Minute
		e.withClockAndKEK(t, clock, lease)

		_, err := e.m.Refresh(ctx, alice, c.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			clock.Add(lease + time.Second) // the call returns after the lease, by the manager's clock
			return tokenResponse("fake-at-late-"+c.ID, "fake-rt-late-"+c.ID, tgScope), nil
		})
		if !errors.Is(err, connection.ErrFenced) {
			t.Fatalf("err %v, want ErrFenced", err)
		}
		got, gerr := e.m.Get(ctx, alice, c.ID)
		if gerr != nil || got.TokenGeneration != c.TokenGeneration {
			t.Fatalf("rotation stored past the lease: %+v (%v)", got, gerr)
		}
		revoked := e.revoker.revoked()
		if !slices.Contains(revoked, "fake-at-late-"+c.ID) || !slices.Contains(revoked, "fake-rt-late-"+c.ID) {
			t.Fatalf("issued tokens not revoked: %v", revoked)
		}
	})
}

// TestConnection_S1C4_StoreRechecksLeaseEnd: the rotation CAS itself refuses
// a lease that has ended at the rotation's clock, so a check in the manager
// that raced the clock is not the only guard.
func TestConnection_S1C4_StoreRechecksLeaseEnd(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		now := time.Now()
		ok, err := s.ClaimPAConnectionRefresh(ctx, alice, c.ID, c.TokenGeneration, "owner-a", now, now.Add(time.Minute))
		if err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		_, err = s.RotatePAConnectionTokens(ctx, alice, c.ID, connection.Rotation{
			ExpectRevision: c.AuthorityRevision, ExpectGeneration: c.TokenGeneration, GrantedScope: c.GrantedScope,
			LeaseOwner: "owner-a", SealedTokens: []byte("x"), Now: now.Add(time.Minute + time.Millisecond),
		})
		if !errors.Is(err, connection.ErrConflict) {
			t.Fatalf("rotation after the lease end: err %v, want ErrConflict", err)
		}
	})
}

// TestConnection_S1C4_RefreshUnwrapsOnce: the DEK opened before the call
// seals the rotation, so no KEK round trip runs after the call.
func TestConnection_S1C4_RefreshUnwrapsOnce(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		clock := &fakeClock{t: time.Now()}
		kek := e.withClockAndKEK(t, clock, time.Minute)

		var during int
		got, err := e.m.Refresh(ctx, alice, c.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			during = kek.count()
			return tokenResponse("fake-at-2-"+c.ID, "fake-rt-2-"+c.ID, tgScope), nil
		})
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if got.TokenGeneration != c.TokenGeneration+1 {
			t.Fatalf("generation %d, want %d", got.TokenGeneration, c.TokenGeneration+1)
		}
		if during != 1 || kek.count() != 1 {
			t.Fatalf("unwraps: %d before the call returned, %d total; want 1 and 1", during, kek.count())
		}
	})
}

// confirmFailStore fails the pending_return -> pending_confirm write.
type confirmFailStore struct{ connection.Store }

func (f confirmFailStore) TransitionPAConnection(ctx context.Context, p int64, id string, t connection.Transition) (connection.Connection, error) {
	if t.To == connection.StatePendingConfirm {
		return connection.Connection{}, errInjected
	}
	return f.Store.TransitionPAConnection(ctx, p, id, t)
}

// TestConnection_S1T9_FinalExchangeWriteFailureRevokes covers the last
// branch of CompleteExchange: the scope check passed, but the write into
// pending_confirm failed. The tokens were never stored, so they must not
// stay live at the server.
func TestConnection_S1T9_FinalExchangeWriteFailureRevokes(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnvWithStore(t, s, confirmFailStore{s})
		alice, _ := principals(t, s)
		c := e.toPendingReturn(t, alice, connection.ServerTG)
		_, err := e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice",
			tokenResponse("fake-at-w-"+c.ID, "fake-rt-w-"+c.ID, tgScope))
		if !errors.Is(err, errInjected) {
			t.Fatalf("err %v, want the injected store error", err)
		}
		revoked := e.revoker.revoked()
		if !slices.Contains(revoked, "fake-at-w-"+c.ID) || !slices.Contains(revoked, "fake-rt-w-"+c.ID) {
			t.Fatalf("unstored tokens not revoked: %v", revoked)
		}
		got, gerr := e.m.Get(ctx, alice, c.ID)
		if gerr != nil || got.State != connection.StatePendingReturn {
			t.Fatalf("state %+v (%v), want still pending_return", got, gerr)
		}
	})
}

// TestConnection_RevokeTokenResponse is the caller's half of the
// CompleteExchange contract: it revokes both tokens of a raw response, even
// one whose scope check would fail.
func TestConnection_RevokeTokenResponse(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newEnv(t, s)
		raw := tokenResponse("fake-at-r", "fake-rt-r", tgScope+" admin:users")
		if err := e.m.RevokeTokenResponse(context.Background(), connection.ServerTG, raw); err != nil {
			t.Fatal(err)
		}
		got := e.revoker.revoked()
		slices.Sort(got)
		if !slices.Equal(got, []string{"fake-at-r", "fake-rt-r"}) {
			t.Fatalf("revoked %v", got)
		}
		if err := e.m.RevokeTokenResponse(context.Background(), connection.Server("nope"), raw); err == nil {
			t.Fatal("unknown server accepted")
		}
	})
}
