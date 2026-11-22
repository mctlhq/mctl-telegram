package connection_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// Token expiry and refresh (#1318 slice C2b): the sealed set keeps an
// absolute expiry stamped at receipt, AccessToken refreshes ahead of it,
// RefreshAccess is the 401 path, and an activation supersedes the
// principal's other connections on the same server.

// clock is a settable time source for the manager.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *clock) set(t time.Time)     { c.mu.Lock(); c.at = t; c.mu.Unlock() }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.at = c.at.Add(d); c.mu.Unlock() }

// refresher is a fake refresh-token grant that counts its calls.
type refresher struct {
	calls atomic.Int32
	// answer, when set, replaces the default fresh response.
	answer func(n int32) ([]byte, error)
	gate   chan struct{}
}

func (r *refresher) fn(_ context.Context, _ connection.Server, _ connection.Secret) ([]byte, error) {
	n := r.calls.Add(1)
	if r.gate != nil {
		<-r.gate
	}
	if r.answer != nil {
		return r.answer(n)
	}
	return tokenResponse("fake-at-fresh", "fake-rt-fresh", tgScope), nil
}

// withRefresh rebuilds e's manager with clock c and refresh grant r.
func (e *env) withRefresh(t *testing.T, c *clock, r *refresher) {
	t.Helper()
	kek, err := connection.NewLocalKEK(testKEKKey, "test")
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	cfg := connection.Config{Store: e.store, KEK: kek, Revoker: e.revoker, Auditor: e.auditor, Now: c.now}
	if r != nil {
		cfg.Refresh = r.fn
	}
	if e.m, err = connection.NewManager(cfg); err != nil {
		t.Fatalf("manager: %v", err)
	}
}

// activeWith drives a tg connection to active with the given exchange
// response, received at the clock's current time.
func (e *env) activeWith(t *testing.T, principal int64, resp []byte) connection.Connection {
	t.Helper()
	ctx := context.Background()
	c := e.toPendingReturn(t, principal, connection.ServerTG)
	c, err := e.m.CompleteExchange(ctx, principal, c.ID, c.AuthorityRevision, "acct-alice", resp)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if c, err = e.m.Confirm(ctx, principal, c.ID, c.AuthorityRevision); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	return c
}

var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// expiry -> refresh -> success: the token is used until RefreshAhead
// before its expiry, then refreshed once and the new token handed out.
func TestConnection_C2b_RefreshAheadOfExpiry(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		c0 := &clock{at: t0}
		r := &refresher{}
		e.withRefresh(t, c0, r)
		alice, _ := principals(t, s)
		c := e.activeWith(t, alice, tokenResponse("fake-at-old", "fake-rt-old", tgScope)) // expires_in 3600

		c0.set(t0.Add(time.Hour - connection.RefreshAhead - time.Second))
		tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil || tok.Reveal() != "fake-at-old" || r.calls.Load() != 0 {
			t.Fatalf("before the window: %q %v, refreshes %d; want the stored token, no refresh", tok.Reveal(), err, r.calls.Load())
		}
		c0.set(t0.Add(time.Hour - connection.RefreshAhead + time.Second))
		tok, got, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil || tok.Reveal() != "fake-at-fresh" || r.calls.Load() != 1 {
			t.Fatalf("inside the window: %q %v, refreshes %d; want the fresh token after one refresh", tok.Reveal(), err, r.calls.Load())
		}
		if got.TokenGeneration != c.TokenGeneration+1 || got.AuthorityRevision != c.AuthorityRevision {
			t.Fatalf("after refresh: generation %d revision %d, want %d and unchanged %d",
				got.TokenGeneration, got.AuthorityRevision, c.TokenGeneration+1, c.AuthorityRevision)
		}
		// The fresh set's expiry counts from its own receipt.
		tok, _, err = e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil || tok.Reveal() != "fake-at-fresh" || r.calls.Load() != 1 {
			t.Fatalf("right after: %q %v, refreshes %d; want no second refresh", tok.Reveal(), err, r.calls.Load())
		}
		// The refreshed set carries its own known expiry (stamped at the
		// refresh's receipt): it too is refreshed ahead, an hour later.
		refreshedAt := t0.Add(time.Hour - connection.RefreshAhead + time.Second)
		c0.set(refreshedAt.Add(time.Hour - connection.RefreshAhead + time.Second))
		if _, _, err = e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision); err != nil || r.calls.Load() != 2 {
			t.Fatalf("an hour after the refresh: %v, refreshes %d; want a second refresh ahead", err, r.calls.Load())
		}
	})
}

// An unknown expiry (no expires_in, or 0) is never "does not expire" and
// never refreshed ahead: the token is used until the server rejects it.
func TestConnection_C2b_UnknownExpiryNotRefreshedAhead(t *testing.T) {
	for name, resp := range map[string]string{
		"absent": `{"access_token":"fake-at-u","token_type":"Bearer","refresh_token":"fake-rt-u","scope":"` + tgScope + `"}`,
		"zero":   `{"access_token":"fake-at-u","token_type":"Bearer","expires_in":0,"refresh_token":"fake-rt-u","scope":"` + tgScope + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				ctx := context.Background()
				e := newEnv(t, s)
				c0 := &clock{at: t0}
				r := &refresher{}
				e.withRefresh(t, c0, r)
				alice, _ := principals(t, s)
				c := e.activeWith(t, alice, []byte(resp))
				c0.add(365 * 24 * time.Hour)
				tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
				if err != nil || tok.Reveal() != "fake-at-u" || r.calls.Load() != 0 {
					t.Fatalf("%q %v, refreshes %d; want the stored token and no refresh", tok.Reveal(), err, r.calls.Load())
				}
				// The 401 path still recovers it.
				tok, _, err = e.m.RefreshAccess(ctx, alice, c.ID, c.AuthorityRevision, c.TokenGeneration)
				if err != nil || tok.Reveal() != "fake-at-fresh" || r.calls.Load() != 1 {
					t.Fatalf("after a 401: %q %v, refreshes %d", tok.Reveal(), err, r.calls.Load())
				}
			})
		})
	}
}

// Concurrent calls in the refresh window share one refresh.
func TestConnection_C2b_ConcurrentCallsOneRefresh(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		c0 := &clock{at: t0}
		r := &refresher{gate: make(chan struct{})}
		e.withRefresh(t, c0, r)
		alice, _ := principals(t, s)
		c := e.activeWith(t, alice, tokenResponse("fake-at-old", "fake-rt-old", tgScope))
		c0.set(t0.Add(time.Hour))

		const n = 12
		var wg sync.WaitGroup
		toks := make([]string, n)
		errs := make([]error, n)
		for i := range n {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
				toks[i], errs[i] = tok.Reveal(), err
			}(i)
		}
		// Every wait is bounded, so a regression fails here by name
		// instead of hanging until the go test timeout.
		var open sync.Once
		release := func() { open.Do(func() { close(r.gate) }) }
		t.Cleanup(release)
		for deadline := time.Now().Add(10 * time.Second); r.calls.Load() == 0; {
			if time.Now().After(deadline) {
				release()
				t.Fatal("no refresh started within 10s")
			}
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(150 * time.Millisecond) // let every caller join the flight
		release()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("callers still waiting 10s after the refresh was released (refreshes %d)", r.calls.Load())
		}
		if got := r.calls.Load(); got != 1 {
			t.Fatalf("refreshes %d, want 1", got)
		}
		for i := range n {
			if errs[i] != nil || toks[i] != "fake-at-fresh" {
				t.Errorf("caller %d: %q %v, want the fresh token", i, toks[i], errs[i])
			}
		}
	})
}

// RefreshAccess refreshes only the rejected generation: a caller whose
// token was already replaced gets the current one, without a refresh.
func TestConnection_C2b_RefreshAccessDedupesByGeneration(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		r := &refresher{}
		e.withRefresh(t, &clock{at: t0}, r)
		alice, _ := principals(t, s)
		c := e.activeWith(t, alice, tokenResponse("fake-at-old", "fake-rt-old", tgScope))
		tok, after, err := e.m.RefreshAccess(ctx, alice, c.ID, c.AuthorityRevision, c.TokenGeneration)
		if err != nil || tok.Reveal() != "fake-at-fresh" || r.calls.Load() != 1 {
			t.Fatalf("first 401: %q %v, refreshes %d", tok.Reveal(), err, r.calls.Load())
		}
		tok, _, err = e.m.RefreshAccess(ctx, alice, c.ID, c.AuthorityRevision, c.TokenGeneration)
		if err != nil || tok.Reveal() != "fake-at-fresh" || r.calls.Load() != 1 {
			t.Fatalf("a late 401 for the old generation: %q %v, refreshes %d; want the current token, no refresh",
				tok.Reveal(), err, r.calls.Load())
		}
		if after.TokenGeneration != c.TokenGeneration+1 {
			t.Fatalf("generation %d, want %d", after.TokenGeneration, c.TokenGeneration+1)
		}
	})
}

// invalid_grant expires the connection: reported as expired, one notice
// queued, and no further refresh is attempted.
func TestConnection_C2b_InvalidGrantExpires(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		r := &refresher{answer: func(int32) ([]byte, error) { return nil, connection.ErrInvalidGrant }}
		e.withRefresh(t, &clock{at: t0}, r)
		alice, _ := principals(t, s)
		c := e.activeWith(t, alice, tokenResponse("fake-at-old", "fake-rt-old", tgScope))
		_, _, err := e.m.RefreshAccess(ctx, alice, c.ID, c.AuthorityRevision, c.TokenGeneration)
		if !errors.Is(err, connection.ErrInvalidGrant) {
			t.Fatalf("err %v, want ErrInvalidGrant", err)
		}
		got, err := e.m.Get(ctx, alice, c.ID)
		if err != nil || got.State != connection.StateExpired {
			t.Fatalf("state %s (%v), want expired", got.State, err)
		}
		for range 3 {
			if _, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrExpired) {
				t.Fatalf("AccessToken after expiry: %v, want ErrExpired", err)
			}
			if _, _, err := e.m.RefreshAccess(ctx, alice, c.ID, c.AuthorityRevision, c.TokenGeneration); !errors.Is(err, connection.ErrExpired) {
				t.Fatalf("RefreshAccess after expiry: %v, want ErrExpired", err)
			}
		}
		if n := r.calls.Load(); n != 1 {
			t.Fatalf("refreshes %d, want 1: no retry storm", n)
		}
		if n := expiryNotices(t, s, alice, c.ID); n != 1 {
			t.Fatalf("expiry notices %d, want 1", n)
		}
	})
}

// A connection without a refresh token cannot recover from a 401: it
// expires, with its notice, and the grant is never called.
func TestConnection_C2b_NoRefreshTokenExpires(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		c0 := &clock{at: t0}
		r := &refresher{}
		e.withRefresh(t, c0, r)
		alice, _ := principals(t, s)
		c := e.activeWith(t, alice, tokenResponse("fake-at-old", "", tgScope))
		// Inside the window, without a refresh token: used as it is.
		c0.set(t0.Add(time.Hour))
		if tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision); err != nil || tok.Reveal() != "fake-at-old" {
			t.Fatalf("AccessToken: %q %v", tok.Reveal(), err)
		}
		_, _, err := e.m.RefreshAccess(ctx, alice, c.ID, c.AuthorityRevision, c.TokenGeneration)
		if !errors.Is(err, connection.ErrNoRefreshToken) {
			t.Fatalf("err %v, want ErrNoRefreshToken", err)
		}
		got, err := e.m.Get(ctx, alice, c.ID)
		if err != nil || got.State != connection.StateExpired || r.calls.Load() != 0 {
			t.Fatalf("state %s (%v), refreshes %d; want expired and no grant", got.State, err, r.calls.Load())
		}
		if n := expiryNotices(t, s, alice, c.ID); n != 1 {
			t.Fatalf("expiry notices %d, want 1", n)
		}
	})
}

// A refresh ahead that fails transiently is not retried, and does not
// fail the call while the current token has not expired: that token is
// handed out (P3 of the #1397 review). Past its expiry the call fails. A
// lease held by another replica is the same. invalid_grant always fails
// the call and expires the connection.
func TestConnection_C2b_RefreshAheadFailure(t *testing.T) {
	down := func(int32) ([]byte, error) { return nil, errors.New("fake: down") }
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		c0 := &clock{at: t0}
		r := &refresher{answer: down}
		e.withRefresh(t, c0, r)
		alice, bob := principals(t, s)
		c := e.activeWith(t, alice, tokenResponse("fake-at-old", "fake-rt-old", tgScope)) // expires t0+1h

		// Inside the window, not yet expired: the current token.
		c0.set(t0.Add(time.Hour - time.Second))
		tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil || tok.Reveal() != "fake-at-old" || r.calls.Load() != 1 {
			t.Fatalf("unexpired, refresh down: %q %v, refreshes %d; want the current token after one attempt", tok.Reveal(), err, r.calls.Load())
		}
		// At its expiry: the call fails, no token.
		c0.set(t0.Add(time.Hour))
		tok, _, err = e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
		if !errors.Is(err, connection.ErrRefreshFailed) || !tok.Empty() {
			t.Fatalf("expired, refresh down: %q %v, want no token and ErrRefreshFailed", tok.Reveal(), err)
		}
		if got, err := e.m.Get(ctx, alice, c.ID); err != nil || got.State != connection.StateActive {
			t.Fatalf("state %s (%v), want active", got.State, err)
		}

		// Another replica holds the lease: the same, without a call.
		c0.set(t0.Add(time.Hour - time.Second))
		cur, err := e.m.Get(ctx, alice, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := s.ClaimPAConnectionRefresh(ctx, alice, c.ID, cur.TokenGeneration, "replica-b", t0, t0.Add(2*time.Hour)); err != nil || !ok {
			t.Fatalf("lease: %v %v", ok, err)
		}
		before := r.calls.Load()
		tok, _, err = e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil || tok.Reveal() != "fake-at-old" || r.calls.Load() != before {
			t.Fatalf("lease held elsewhere, unexpired: %q %v; want the current token, no call", tok.Reveal(), err)
		}
		c0.set(t0.Add(time.Hour))
		if _, _, err = e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrRefreshInProgress) {
			t.Fatalf("lease held elsewhere, expired: %v, want ErrRefreshInProgress", err)
		}

		// invalid_grant inside the window: refused and expired.
		r2 := &refresher{answer: func(int32) ([]byte, error) { return nil, connection.ErrInvalidGrant }}
		c1 := &clock{at: t0}
		e.withRefresh(t, c1, r2)
		b := e.activeWith(t, bob, tokenResponse("fake-at-bob", "fake-rt-bob", tgScope))
		c1.set(t0.Add(time.Hour - time.Second))
		tok, _, err = e.m.AccessToken(ctx, bob, b.ID, b.AuthorityRevision)
		if !errors.Is(err, connection.ErrInvalidGrant) || !tok.Empty() {
			t.Fatalf("invalid_grant, unexpired: %q %v, want no token and ErrInvalidGrant", tok.Reveal(), err)
		}
		if got, err := e.m.Get(ctx, bob, b.ID); err != nil || got.State != connection.StateExpired {
			t.Fatalf("state %s (%v), want expired", got.State, err)
		}
	})
}

// A flight asked for a generation that is already gone does not rotate
// again (P3 of the #1397 review): the caller that read it before another
// flight finished gets the current row, and the grant is not called.
func TestConnection_C2b_RefreshFromStaleGenerationIsNoop(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		r := &refresher{}
		e.withRefresh(t, &clock{at: t0}, r)
		alice, _ := principals(t, s)
		c := e.activeWith(t, alice, tokenResponse("fake-at-old", "fake-rt-old", tgScope))
		if _, err := e.m.RefreshFrom(ctx, alice, c.ID, r.fn, c.TokenGeneration); err != nil || r.calls.Load() != 1 {
			t.Fatalf("first flight: %v, refreshes %d", err, r.calls.Load())
		}
		got, err := e.m.RefreshFrom(ctx, alice, c.ID, r.fn, c.TokenGeneration)
		if err != nil || r.calls.Load() != 1 || got.TokenGeneration != c.TokenGeneration+1 {
			t.Fatalf("late flight for the old generation: gen %d %v, refreshes %d; want the current row and no second rotation",
				got.TokenGeneration, err, r.calls.Load())
		}
	})
}

// Without a configured grant nothing is refreshed: the stored token is
// used, and the 401 path reports that it cannot refresh.
func TestConnection_C2b_NoGrantConfigured(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		c0 := &clock{at: t0}
		e.withRefresh(t, c0, nil)
		alice, _ := principals(t, s)
		c := e.activeWith(t, alice, tokenResponse("fake-at-old", "fake-rt-old", tgScope))
		c0.set(t0.Add(time.Hour))
		if tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision); err != nil || tok.Reveal() != "fake-at-old" {
			t.Fatalf("AccessToken: %q %v", tok.Reveal(), err)
		}
		if _, _, err := e.m.RefreshAccess(ctx, alice, c.ID, c.AuthorityRevision, c.TokenGeneration); !errors.Is(err, connection.ErrRefreshUnavailable) {
			t.Fatalf("RefreshAccess: %v, want ErrRefreshUnavailable", err)
		}
	})
}

// A fresh /connect next to a dead (expired) or live connection on the same
// server leaves exactly one bound connection: the activation revokes the
// others in its transaction and their tokens at the server.
func TestConnection_C2b_ActivationSupersedes(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		r := &refresher{answer: func(int32) ([]byte, error) { return nil, connection.ErrInvalidGrant }}
		e.withRefresh(t, &clock{at: t0}, r)
		alice, bob := principals(t, s)
		dead := e.activeWith(t, alice, tokenResponse("fake-at-dead", "fake-rt-dead", tgScope))
		if _, _, err := e.m.RefreshAccess(ctx, alice, dead.ID, dead.AuthorityRevision, dead.TokenGeneration); !errors.Is(err, connection.ErrInvalidGrant) {
			t.Fatalf("expire: %v", err)
		}
		live := e.activeWith(t, alice, tokenResponse("fake-at-live", "fake-rt-live", tgScope))
		bobs := e.activeWith(t, bob, tokenResponse("fake-at-bob", "fake-rt-bob", tgScope))
		// Alice's connection to another server is not superseded by a tg
		// activation.
		home := e.toPendingReturn(t, alice, connection.ServerAlice)
		home, err := e.m.CompleteExchange(ctx, alice, home.ID, home.AuthorityRevision, "acct-alice",
			tokenResponse("fake-at-home", "fake-rt-home", "iot:view"))
		if err != nil {
			t.Fatal(err)
		}
		if home, err = e.m.Confirm(ctx, alice, home.ID, home.AuthorityRevision); err != nil {
			t.Fatal(err)
		}
		if got, err := e.m.Get(ctx, alice, dead.ID); err != nil || got.State != connection.StateRevoked {
			t.Fatalf("expired connection after a reconnect: %s (%v), want revoked", got.State, err)
		}
		// A call in flight on the connection being superseded is cancelled.
		call, err := e.m.BeginCall(ctx, alice, live.ID, live.AuthorityRevision)
		if err != nil {
			t.Fatal(err)
		}
		newest := e.activeWith(t, alice, tokenResponse("fake-at-new", "fake-rt-new", tgScope))
		select {
		case <-call.Ctx.Done():
		default:
			t.Fatal("supersede did not cancel the in-flight call")
		}
		if err := call.Finish(ctx); !errors.Is(err, connection.ErrFenced) {
			t.Fatalf("late result on a superseded connection: %v, want ErrFenced", err)
		}
		if got, err := e.m.Get(ctx, alice, home.ID); err != nil || got.State != connection.StateActive {
			t.Fatalf("connection to another server: %s (%v), want active", got.State, err)
		}
		conns, err := e.m.List(ctx, alice)
		if err != nil {
			t.Fatal(err)
		}
		bound := 0
		for _, c := range conns {
			switch c.State {
			case connection.StateActive, connection.StateExpired:
				if c.Server != connection.ServerTG {
					continue
				}
				bound++
				if c.ID != newest.ID {
					t.Fatalf("connection %s still %s next to the new one", c.ID, c.State)
				}
			}
		}
		if bound != 1 {
			t.Fatalf("%d bound connections, want exactly 1", bound)
		}
		if _, _, err := e.m.AccessToken(ctx, alice, live.ID, live.AuthorityRevision); !errors.Is(err, connection.ErrNotActive) {
			t.Fatalf("superseded connection still hands out a token: %v", err)
		}
		revoked := e.revoker.revoked()
		for _, want := range []string{"fake-rt-live", "fake-at-live"} {
			found := false
			for _, got := range revoked {
				found = found || got == want
			}
			if !found {
				t.Fatalf("superseded token %s not revoked at the server: %v", want, revoked)
			}
		}
		// Another principal's connection is never touched.
		if got, err := e.m.Get(ctx, bob, bobs.ID); err != nil || got.State != connection.StateActive {
			t.Fatalf("bob's connection: %s (%v), want active", got.State, err)
		}
	})
}

// The activation re-reads the admin disable under the principal lock
// (review P3 of #1390): a disable after /connect refuses it, fail-closed.
func TestConnection_C2b_DisabledAtActivationRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toPendingReturn(t, alice, connection.ServerTG)
		c, err := e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice",
			tokenResponse("fake-at-d", "fake-rt-d", tgScope))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetPAPrincipalDisabled(ctx, alice, 4242001, "test", time.Now()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.ClearPAPrincipalDisabled(context.Background(), alice) })
		if _, err := e.m.Confirm(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrPrincipalDisabled) {
			t.Fatalf("confirm of a disabled principal: %v, want ErrPrincipalDisabled", err)
		}
		if got, err := e.m.Get(ctx, alice, c.ID); err != nil || got.State != connection.StatePendingConfirm {
			t.Fatalf("state %s (%v), want left pending_confirm", got.State, err)
		}
	})
}

// A disable that cannot be read refuses the activation too.
func TestConnection_C2b_UnreadableDisableRefusesActivation(t *testing.T) {
	s := newSQLiteStore(t) // drops a table: never on the shared Postgres
	ctx := context.Background()
	e := newEnv(t, s)
	alice, _ := principals(t, s)
	c := e.toPendingReturn(t, alice, connection.ServerTG)
	c, err := e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice",
		tokenResponse("fake-at-d", "fake-rt-d", tgScope))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DROP TABLE pa_principal_disables`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Confirm(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrPrincipalDisabled) {
		t.Fatalf("confirm with an unreadable disable: %v, want ErrPrincipalDisabled", err)
	}
	if got, err := e.m.Get(ctx, alice, c.ID); err != nil || got.State != connection.StatePendingConfirm {
		t.Fatalf("state %s (%v), want left pending_confirm", got.State, err)
	}
}

func expiryNotices(t *testing.T, s *db.Store, principal int64, id string) int {
	t.Helper()
	rows, err := s.PAOutboxRows(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		if r.Kind == jobs.OutboxConnectionExpired && r.ConnectionID == id {
			n++
		}
	}
	return n
}

// expiryFailStore fails the active -> expired transition.
type expiryFailStore struct {
	connection.Store
}

func (f expiryFailStore) TransitionPAConnection(ctx context.Context, principal int64, id string, t connection.Transition) (connection.Connection, error) {
	if t.To == connection.StateExpired {
		return connection.Connection{}, errors.New("fake: disk full")
	}
	return f.Store.TransitionPAConnection(ctx, principal, id, t)
}

// An expiry that could not be recorded is not reported as one: the call
// fails as a failed refresh, the connection stays active with no notice,
// and the next call meets the same answer and records it then.
func TestConnection_C2b_UnrecordedExpiryIsAFailedRefresh(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		r := &refresher{answer: func(int32) ([]byte, error) { return nil, connection.ErrInvalidGrant }}
		e.withRefresh(t, &clock{at: t0}, r)
		alice, bob := principals(t, s)
		c := e.activeWith(t, alice, tokenResponse("fake-at-old", "fake-rt-old", tgScope))
		noRT := e.activeWith(t, bob, tokenResponse("fake-at-nort", "", tgScope))
		healthy := e.store
		e.store = expiryFailStore{Store: healthy}
		e.withRefresh(t, &clock{at: t0}, r)
		// invalid_grant on the refresh, and a 401 with no refresh token.
		for _, cc := range []connection.Connection{c, noRT} {
			_, _, err := e.m.RefreshAccess(ctx, cc.Principal, cc.ID, cc.AuthorityRevision, cc.TokenGeneration)
			if !errors.Is(err, connection.ErrRefreshFailed) {
				t.Fatalf("%s, expiry unrecorded: %v, want ErrRefreshFailed", cc.ID, err)
			}
			if cc.ID == noRT.ID && errors.Is(err, connection.ErrNoRefreshToken) {
				t.Fatalf("unrecorded expiry reported as ErrNoRefreshToken: %v", err)
			}
		}
		// A refresh ahead that hits invalid_grant and cannot record the
		// expiry does not fall back to the unexpired token: the grant is
		// dead even though the row still reads active.
		ahead := &clock{at: t0}
		e.withRefresh(t, ahead, r)
		ahead.set(t0.Add(time.Hour - time.Second))
		if tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrInvalidGrant) || !tok.Empty() {
			t.Fatalf("refresh ahead, invalid_grant, expiry unrecorded: %q %v; want no token", tok.Reveal(), err)
		}
		e.store = healthy
		e.withRefresh(t, &clock{at: t0}, r)
		for _, cc := range []connection.Connection{c, noRT} {
			if got, err := e.m.Get(ctx, cc.Principal, cc.ID); err != nil || got.State != connection.StateActive {
				t.Fatalf("state %s (%v), want still active", got.State, err)
			}
			if n := expiryNotices(t, s, cc.Principal, cc.ID); n != 0 {
				t.Fatalf("notices %d for an unrecorded expiry", n)
			}
		}
	})
}
