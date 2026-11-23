package connection_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// Manager-level guards of the linking wiring (#1338): the T10 pending cap
// before the KEK wrap, and account deletion's provider-first revocation.

// wrapCountingKEK counts Wrap calls of the KEK it wraps.
type wrapCountingKEK struct {
	connection.KEK
	mu    sync.Mutex
	wraps int
}

func (k *wrapCountingKEK) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	k.mu.Lock()
	k.wraps++
	k.mu.Unlock()
	return k.KEK.Wrap(ctx, dek)
}

func (k *wrapCountingKEK) count() int { k.mu.Lock(); defer k.mu.Unlock(); return k.wraps }

// T10: a principal at MaxPendingConnections is refused before the KEK wrap,
// another principal is not affected, and a finished attempt frees a slot.
func TestConnection_T10_PendingCapBeforeKEKWrap(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		local, err := connection.NewLocalKEK(testKEKKey, "test")
		if err != nil {
			t.Fatal(err)
		}
		kek := &wrapCountingKEK{KEK: local}
		m, err := connection.NewManager(connection.Config{Store: s, KEK: kek, Revoker: &fakeRevoker{}, Auditor: &fakeAuditor{}})
		if err != nil {
			t.Fatal(err)
		}
		alice, bob := principals(t, s)
		var first connection.Connection
		for i := range connection.MaxPendingConnections {
			c, err := m.Begin(ctx, alice, connection.ServerTG)
			if err != nil {
				t.Fatalf("begin %d: %v", i, err)
			}
			if i == 0 {
				first = c
			}
		}
		if _, err := m.Begin(ctx, alice, connection.ServerTG); !errors.Is(err, connection.ErrTooManyPending) {
			t.Fatalf("begin past the cap: %v, want ErrTooManyPending", err)
		}
		if got := kek.count(); got != connection.MaxPendingConnections {
			t.Fatalf("KEK wraps = %d, want %d: the refused Begin must not wrap", got, connection.MaxPendingConnections)
		}
		if _, err := m.Begin(ctx, bob, connection.ServerTG); err != nil {
			t.Fatalf("bob's begin while alice is at the cap: %v", err)
		}
		if _, err := m.Abandon(ctx, alice, first.ID, first.AuthorityRevision, "test"); err != nil {
			t.Fatalf("abandon: %v", err)
		}
		if _, err := m.Begin(ctx, alice, connection.ServerTG); err != nil {
			t.Fatalf("begin after an attempt failed: %v", err)
		}
	})
}

// gatedRevoker fails while err is set and records, for every call, whether
// the row still held its tokens at that moment.
type gatedRevoker struct {
	fakeRevoker
	s          *db.Store
	principal  int64
	id         string
	heldAtCall []bool
}

func (g *gatedRevoker) Revoke(ctx context.Context, server connection.Server, token connection.Secret, hint connection.TokenHint) error {
	_, sealed, err := g.s.GetPAConnectionSealed(ctx, g.principal, g.id)
	g.mu.Lock()
	g.heldAtCall = append(g.heldAtCall, err == nil && len(sealed.SealedTokens) > 0)
	g.mu.Unlock()
	return g.fakeRevoker.Revoke(ctx, server, token, hint)
}

// Account deletion revokes at the provider first. A failed remote
// revocation keeps the row active with its sealed tokens, so a retry can
// still revoke them; a successful one revokes the row locally. A connection
// without tokens is left for the purge.
func TestConnection_RevokeHeldTokens_ProviderFirst(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		pending, err := e.m.Begin(ctx, alice, connection.ServerTG)
		if err != nil {
			t.Fatal(err)
		}
		rev := &gatedRevoker{s: s, principal: alice, id: c.ID}
		kek, err := connection.NewLocalKEK(testKEKKey, "test")
		if err != nil {
			t.Fatal(err)
		}
		m, err := connection.NewManager(connection.Config{Store: s, KEK: kek, Revoker: rev, Auditor: e.auditor})
		if err != nil {
			t.Fatal(err)
		}

		cause := errors.New("provider unreachable")
		rev.err = cause
		if err := m.RevokeHeldTokens(ctx, alice); !errors.Is(err, cause) {
			t.Fatalf("revoke with the provider down: %v, want the cause", err)
		}
		got, sealed, err := s.GetPAConnectionSealed(ctx, alice, c.ID)
		if err != nil || got.State != connection.StateActive || len(sealed.SealedTokens) == 0 {
			t.Fatalf("after a failed remote revocation: state %s, %d token bytes, err %v; want active with tokens",
				got.State, len(sealed.SealedTokens), err)
		}

		rev.err = nil
		if err := m.RevokeHeldTokens(ctx, alice); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		got, sealed, err = s.GetPAConnectionSealed(ctx, alice, c.ID)
		if err != nil || got.State != connection.StateRevoked || len(sealed.SealedTokens) != 0 {
			t.Fatalf("after the revocation: state %s, %d token bytes, err %v; want revoked without tokens",
				got.State, len(sealed.SealedTokens), err)
		}
		for i, held := range rev.heldAtCall {
			if !held {
				t.Fatalf("remote call %d ran after the local wipe: the provider must be called first", i)
			}
		}
		if r := rev.revoked(); !slices.Contains(r, "fake-at-1-"+c.ID) || !slices.Contains(r, "fake-rt-1-"+c.ID) {
			t.Fatalf("revoked %v, want both tokens of %s", r, c.ID)
		}
		if p, err := s.GetPAConnection(ctx, alice, pending.ID); err != nil || p.State != connection.StatePendingLink {
			t.Fatalf("token-free connection: state %s, err %v; want it left pending_link", p.State, err)
		}
	})
}

// rotatingStore rotates the connection's tokens just before the first local
// revocation, as a refresh on another replica would.
type rotatingStore struct {
	connection.Store
	once   sync.Once
	rotate func()
}

func (r *rotatingStore) RevokePAConnectionAt(ctx context.Context, principal int64, id string, revision, generation int64, reason string) (connection.Connection, error) {
	r.once.Do(r.rotate)
	return r.Store.RevokePAConnectionAt(ctx, principal, id, revision, generation, reason)
}

// Tokens that rotate while the connection is being revoked are revoked at
// the provider too, before the row is wiped: the local revocation is pinned
// to the token generation the remote one used.
func TestConnection_RevokeHeldTokens_RotationDuringRevoke(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		rs := &rotatingStore{Store: s}
		e := newEnvWithStore(t, s, rs)
		bob, _ := principals(t, s)
		c := e.toActive(t, bob)
		rs.rotate = func() {
			if _, err := e.m.Refresh(ctx, bob, c.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
				return tokenResponse("fake-at-2-"+c.ID, "fake-rt-2-"+c.ID, tgScope), nil
			}); err != nil {
				t.Errorf("rotate: %v", err)
			}
		}
		if err := e.m.RevokeHeldTokens(ctx, bob); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		r := e.revoker.revoked()
		for _, tok := range []string{"fake-rt-1-" + c.ID, "fake-rt-2-" + c.ID, "fake-at-2-" + c.ID} {
			if !slices.Contains(r, tok) {
				t.Fatalf("revoked %v, missing %s", r, tok)
			}
		}
		if got, sealed, err := s.GetPAConnectionSealed(ctx, bob, c.ID); err != nil || got.State != connection.StateRevoked || len(sealed.SealedTokens) != 0 {
			t.Fatalf("after the revocation: state %s, %d token bytes, err %v; want revoked", got.State, len(sealed.SealedTokens), err)
		}
	})
}

// A listing that cannot be read is an error, never "nothing to revoke".
func TestConnection_RevokeHeldTokens_UnreadableListing(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		fs := &failingStore{Store: s}
		e := newEnvWithStore(t, s, fs)
		carol, _ := principals(t, s)
		e.toActive(t, carol)
		fs.setFail(true)
		if err := e.m.RevokeHeldTokens(context.Background(), carol); !errors.Is(err, connection.ErrUnreadable) {
			t.Fatalf("revoke with an unreadable listing: %v, want ErrUnreadable", err)
		}
	})
}
