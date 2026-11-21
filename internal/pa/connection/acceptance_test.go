package connection_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// TestConnection_S1C1_NonActiveStatesRefuse is S1-C1: revoked, expired,
// failed and every pending_* state refuse a read, at the connection's own
// current revision (so only the state can be the reason).
func TestConnection_S1C1_NonActiveStatesRefuse(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)

		reached := map[connection.State]connection.Connection{}
		c, err := e.m.Begin(ctx, alice, connection.ServerTG)
		if err != nil {
			t.Fatal(err)
		}
		reached[c.State] = c
		c, _ = e.m.StartOAuth(ctx, alice, c.ID, c.AuthorityRevision)
		reached[c.State] = c
		c, _ = e.m.StoreAuthorizationCode(ctx, alice, c.ID, c.AuthorityRevision, connection.NewSecret("fake-code"))
		reached[c.State] = c
		c, err = e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice", tokenResponse("fake-at-c1", "fake-rt-c1", tgScope))
		if err != nil {
			t.Fatal(err)
		}
		reached[c.State] = c

		active := e.toActive(t, alice)
		// Positive control: the gate passes an active row at its revision.
		if _, err := e.m.Authorize(ctx, alice, active.ID, active.AuthorityRevision); err != nil {
			t.Fatalf("active connection refused: %v", err)
		}

		failed, err := e.m.Fail(ctx, alice, e.toActive(t, alice).ID, active.AuthorityRevision, "test")
		if err != nil {
			t.Fatal(err)
		}
		reached[failed.State] = failed

		exp := e.toActive(t, alice)
		_, err = e.m.Refresh(ctx, alice, exp.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			return nil, fmt.Errorf("server said: %w", connection.ErrInvalidGrant)
		})
		if !errors.Is(err, connection.ErrInvalidGrant) {
			t.Fatalf("refresh invalid_grant: %v", err)
		}
		if exp, err = e.m.Get(ctx, alice, exp.ID); err != nil {
			t.Fatal(err)
		}
		reached[exp.State] = exp

		rev := e.toActive(t, alice)
		if _, err := e.m.Disconnect(ctx, alice, rev.ID); err != nil {
			t.Fatal(err)
		}
		if rev, err = e.m.Get(ctx, alice, rev.ID); err != nil {
			t.Fatal(err)
		}
		reached[rev.State] = rev

		for _, st := range connection.AllStates {
			if st == connection.StateActive {
				continue
			}
			c, ok := reached[st]
			if !ok || c.State != st {
				t.Fatalf("state %s was not reached (got %+v)", st, c)
			}
			if got, err := e.m.Authorize(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrNotActive) || got.ID != "" {
				t.Errorf("%s: Authorize = (%q, %v), want ErrNotActive and no connection", st, got.ID, err)
			}
			if tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrNotActive) || !tok.Empty() {
				t.Errorf("%s: AccessToken err = %v, want ErrNotActive and no token", st, err)
			}
			if call, err := e.m.BeginCall(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrNotActive) || call != nil {
				t.Errorf("%s: BeginCall err = %v, want ErrNotActive", st, err)
			}
		}
	})
}

// TestConnection_S1C2_RevisionMismatchRefuses is S1-C2.
func TestConnection_S1C2_RevisionMismatchRefuses(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		for _, bound := range []int64{c.AuthorityRevision - 1, c.AuthorityRevision + 1, 0} {
			if _, err := e.m.Authorize(ctx, alice, c.ID, bound); !errors.Is(err, connection.ErrRevisionMismatch) {
				t.Errorf("bound %d: Authorize err = %v, want ErrRevisionMismatch", bound, err)
			}
			if _, _, err := e.m.AccessToken(ctx, alice, c.ID, bound); !errors.Is(err, connection.ErrRevisionMismatch) {
				t.Errorf("bound %d: AccessToken err = %v, want ErrRevisionMismatch", bound, err)
			}
		}
		tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil || tok.Reveal() != "fake-at-1-"+c.ID {
			t.Fatalf("bound revision refused: %v", err)
		}
	})
}

// TestConnection_S1C3_RotationKeepsRun is S1-C3: a token rotation moves
// token_generation only, so a run bound to the revision before the refresh
// keeps working and gets the new token.
func TestConnection_S1C3_RotationKeepsRun(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		bound := c.AuthorityRevision

		var presented string
		after, err := e.m.Refresh(ctx, alice, c.ID, func(_ context.Context, _ connection.Server, rt connection.Secret) ([]byte, error) {
			presented = rt.Reveal()
			return tokenResponse("fake-at-2-"+c.ID, "", tgScope), nil
		})
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if presented != "fake-rt-1-"+c.ID {
			t.Fatalf("refresh presented the wrong refresh token")
		}
		if after.AuthorityRevision != bound || after.TokenGeneration != c.TokenGeneration+1 {
			t.Fatalf("after refresh: revision %d generation %d, want %d and %d",
				after.AuthorityRevision, after.TokenGeneration, bound, c.TokenGeneration+1)
		}
		tok, _, err := e.m.AccessToken(ctx, alice, c.ID, bound)
		if err != nil {
			t.Fatalf("the run's next call was refused after a rotation: %v", err)
		}
		if tok.Reveal() != "fake-at-2-"+c.ID {
			t.Fatal("the next call did not get the rotated token")
		}
		// A response without a refresh_token keeps the old one.
		_, err = e.m.Refresh(ctx, alice, c.ID, func(_ context.Context, _ connection.Server, rt connection.Secret) ([]byte, error) {
			presented = rt.Reveal()
			return tokenResponse("fake-at-3-"+c.ID, "fake-rt-3-"+c.ID, tgScope), nil
		})
		if err != nil || presented != "fake-rt-1-"+c.ID {
			t.Fatalf("second refresh: err %v", err)
		}
	})
}

// TestConnection_S1C4_SingleFlightRefresh is S1-C4: concurrent refreshes
// produce one refresh request, both within one process (single-flight, every
// caller gets the shared result) and across replicas (the store lease: a
// second replica is refused and never presents the refresh token).
func TestConnection_S1C4_SingleFlightRefresh(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)

		var calls atomic.Int32
		release := make(chan struct{})
		var releaseOnce sync.Once
		releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
		// A failing assertion below must not leave the refresh goroutines
		// blocked forever.
		defer releaseAll()
		entered := make(chan struct{}, 1)
		fn := func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			calls.Add(1)
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
			return tokenResponse("fake-at-c4-"+c.ID, "fake-rt-c4-"+c.ID, tgScope), nil
		}

		const n = 16
		var wg sync.WaitGroup
		errs := make([]error, n)
		gens := make([]int64, n)
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := e.m.Refresh(ctx, alice, c.ID, fn)
			errs[0], gens[0] = err, got.TokenGeneration
		}()
		<-entered
		for i := 1; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				got, err := e.m.Refresh(ctx, alice, c.ID, fn)
				errs[i], gens[i] = err, got.TokenGeneration
			}(i)
		}

		// A second replica (its own Manager, same store) while the lease is
		// held: refused, and its refresh function never runs.
		replica := newEnv(t, s)
		var replicaCalls atomic.Int32
		_, rerr := replica.m.Refresh(ctx, alice, c.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			replicaCalls.Add(1)
			return tokenResponse("fake-at-replica", "fake-rt-replica", tgScope), nil
		})
		if !errors.Is(rerr, connection.ErrRefreshInProgress) || replicaCalls.Load() != 0 {
			t.Fatalf("second replica: err %v, calls %d; want ErrRefreshInProgress and 0", rerr, replicaCalls.Load())
		}

		time.Sleep(200 * time.Millisecond) // let every goroutine join the flight
		releaseAll()
		wg.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("refresh requests = %d, want 1", got)
		}
		for i, err := range errs {
			if err != nil || gens[i] != c.TokenGeneration+1 {
				t.Errorf("caller %d: err %v generation %d, want the shared result", i, err, gens[i])
			}
		}
	})
}

// TestConnection_S1C5_UnreadableRefuses is S1-C5: an unreadable connection
// row (injected store error, a state value this build does not know, or
// sealed material that does not open) refuses and is never treated as
// active.
func TestConnection_S1C5_UnreadableRefuses(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		alice, _ := principals(t, s)
		fs := &failingStore{Store: s}
		e := newEnvWithStore(t, s, fs)
		c := e.toActive(t, alice)

		fs.setFail(true)
		if got, err := e.m.Authorize(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrUnreadable) || got.ID != "" {
			t.Errorf("Authorize on a store error = (%q, %v), want ErrUnreadable", got.ID, err)
		}
		if tok, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrUnreadable) || !tok.Empty() {
			t.Errorf("AccessToken on a store error = %v, want ErrUnreadable", err)
		}
		if call, err := e.m.BeginCall(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrUnreadable) || call != nil {
			t.Errorf("BeginCall on a store error = %v, want ErrUnreadable", err)
		}
		if l, err := e.m.List(ctx, alice); !errors.Is(err, connection.ErrUnreadable) || l != nil {
			t.Errorf("List on a store error = (%v, %v), want ErrUnreadable and no list", l, err)
		}
		fs.setFail(false)

		// An unknown state value in the row is unreadable, not "not active".
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_connections SET state = 'activ' WHERE id = $1`, c.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := e.m.Authorize(ctx, alice, c.ID, c.AuthorityRevision); !errors.Is(err, connection.ErrUnreadable) {
			t.Errorf("unknown state: err %v, want ErrUnreadable", err)
		}
		if _, err := e.m.List(ctx, alice); !errors.Is(err, connection.ErrUnreadable) {
			t.Errorf("unknown state in list: err %v, want ErrUnreadable", err)
		}

		// Sealed tokens that do not open refuse the call.
		c2 := e.toActive(t, alice)
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_connections SET sealed_tokens = $1 WHERE id = $2`, []byte("garbage-garbage-garbage-garbage-"), c2.ID); err != nil {
			t.Fatal(err)
		}
		if tok, _, err := e.m.AccessToken(ctx, alice, c2.ID, c2.AuthorityRevision); !errors.Is(err, connection.ErrUnreadable) || !tok.Empty() {
			t.Errorf("corrupt sealed tokens: err %v, want ErrUnreadable", err)
		}

		// Sealed tokens copied from another row do not open there: the seal
		// is bound to (principal, id).
		c3, c4 := e.toActive(t, alice), e.toActive(t, alice)
		if _, err := s.DB.ExecContext(ctx,
			`UPDATE pa_connections SET sealed_tokens = (SELECT sealed_tokens FROM pa_connections WHERE id = $1), wrapped_dek = (SELECT wrapped_dek FROM pa_connections WHERE id = $1) WHERE id = $2`,
			c3.ID, c4.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.m.AccessToken(ctx, alice, c4.ID, c4.AuthorityRevision); !errors.Is(err, connection.ErrUnreadable) {
			t.Errorf("transplanted sealed tokens: err %v, want ErrUnreadable", err)
		}
	})
}

// TestConnection_S1C6_DisconnectRevokesLocallyFirst is S1-C6: /disconnect
// with remote revocation failing still leaves the token unusable by MCTL --
// the gate refuses, and the DEK wrapper and sealed tokens are gone from the
// row, so not even a gate bypass could open them.
func TestConnection_S1C6_DisconnectRevokesLocallyFirst(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)
		e.revoker.err = errors.New("revocation endpoint down")

		res, err := e.m.Disconnect(ctx, alice, c.ID)
		if err != nil {
			t.Fatalf("disconnect: %v", err)
		}
		if res.RemoteErr == nil {
			t.Fatal("remote revocation failure was not reported")
		}
		if res.Connection.State != connection.StateRevoked || res.Connection.AuthorityRevision <= c.AuthorityRevision {
			t.Fatalf("after disconnect: %s at %d", res.Connection.State, res.Connection.AuthorityRevision)
		}
		if got := e.revoker.revoked(); !slices.Contains(got, "fake-at-1-"+c.ID) || !slices.Contains(got, "fake-rt-1-"+c.ID) {
			t.Fatalf("remote revocation was not attempted for both tokens")
		}
		for _, bound := range []int64{c.AuthorityRevision, res.Connection.AuthorityRevision} {
			if tok, _, err := e.m.AccessToken(ctx, alice, c.ID, bound); err == nil || !tok.Empty() {
				t.Fatalf("token still usable after disconnect (bound %d)", bound)
			}
		}
		_, sealed, err := s.GetPAConnectionSealed(ctx, alice, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed.WrappedDEK) != 0 || len(sealed.SealedTokens) != 0 || len(sealed.SealedCode) != 0 {
			t.Fatal("secret material survived disconnect")
		}
		// A second disconnect is a no-op, not an error.
		again, err := e.m.Disconnect(ctx, alice, c.ID)
		if err != nil || !again.AlreadyRevoked {
			t.Fatalf("second disconnect: %+v %v", again, err)
		}
	})
}

// TestConnection_S1C7_LateResultFenced is S1-C7: a result arriving after
// revoke is discarded and audited fenced. The call's context is cancelled
// by the disconnect, which does not wait for it.
func TestConnection_S1C7_LateResultFenced(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)

		// Control: an undisturbed call is not fenced.
		ok, err := e.m.BeginCall(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil {
			t.Fatal(err)
		}
		if err := ok.Finish(ctx); err != nil {
			t.Fatalf("undisturbed call fenced: %v", err)
		}
		if len(e.auditor.all()) != 0 {
			t.Fatal("undisturbed call was audited fenced")
		}

		call, err := e.m.BeginCall(ctx, alice, c.ID, c.AuthorityRevision)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.m.Disconnect(ctx, alice, c.ID); err != nil {
			t.Fatal(err)
		}
		select {
		case <-call.Ctx.Done():
		default:
			t.Fatal("disconnect did not cancel the in-flight call")
		}
		err = call.Finish(ctx)
		if !errors.Is(err, connection.ErrFenced) {
			t.Fatalf("late result: err %v, want ErrFenced", err)
		}
		evs := e.auditor.all()
		if len(evs) != 1 || evs[0].ConnectionID != c.ID || evs[0].Principal != alice || evs[0].Reason != "not_active" || evs[0].BoundRevision != c.AuthorityRevision {
			t.Fatalf("fenced audit = %+v", evs)
		}

		// A late code-exchange result after /disconnect is discarded: never
		// stored, and what the server issued is revoked.
		pend := e.toPendingReturn(t, alice, connection.ServerTG)
		if _, err := e.m.Disconnect(ctx, alice, pend.ID); err != nil {
			t.Fatal(err)
		}
		_, err = e.m.CompleteExchange(ctx, alice, pend.ID, pend.AuthorityRevision, "acct-alice",
			tokenResponse("fake-at-late", "fake-rt-late", tgScope))
		if !errors.Is(err, connection.ErrConflict) {
			t.Fatalf("late exchange: err %v, want ErrConflict", err)
		}
		if r := e.revoker.revoked(); !slices.Contains(r, "fake-at-late") || !slices.Contains(r, "fake-rt-late") {
			t.Fatal("late exchange tokens were not revoked")
		}
		if got, _ := e.m.Get(ctx, alice, pend.ID); got.State != connection.StateRevoked {
			t.Fatalf("late exchange changed the revoked row: %s", got.State)
		}

		// A post-call re-read that fails is fenced too, never "fine".
		fs := &failingStore{Store: s}
		e2 := newEnvWithStore(t, s, fs)
		c2 := e2.toActive(t, alice)
		call2, err := e2.m.BeginCall(ctx, alice, c2.ID, c2.AuthorityRevision)
		if err != nil {
			t.Fatal(err)
		}
		fs.setFail(true)
		if err := call2.Finish(ctx); !errors.Is(err, connection.ErrFenced) {
			t.Fatalf("unreadable post-call check: err %v, want ErrFenced", err)
		}
		if evs := e2.auditor.all(); len(evs) != 1 || evs[0].Reason != "unreadable" {
			t.Fatalf("fenced audit on unreadable = %+v", evs)
		}
	})
}

// TestConnection_S1C8_ScopeEscalationNeedsNewConnection is S1-C8: an
// existing connection never gains scope or account, and is never
// re-activated; the only way to a different grant is Begin, which is a new
// connection id at pending_link.
func TestConnection_S1C8_ScopeEscalationNeedsNewConnection(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, _ := principals(t, s)
		c := e.toActive(t, alice)

		// No edge sets account or scope except into pending_confirm.
		_, err := s.TransitionPAConnection(ctx, alice, c.ID, connection.Transition{
			From: connection.StateActive, To: connection.StateExpired, ExpectRevision: c.AuthorityRevision,
			AccountID: "acct-other", GrantedScope: tgScope + " admin:users", SealedTokens: []byte("x"),
		})
		if !errors.Is(err, connection.ErrInvalidTransition) {
			t.Fatalf("scope change on an existing connection: err %v, want ErrInvalidTransition", err)
		}
		// A rotation cannot change the granted scope either. The lease is
		// really held, so the only thing the wider rotation differs in is
		// the scope; the same rotation with the granted scope then applies.
		now := time.Now()
		if ok, err := s.ClaimPAConnectionRefresh(ctx, alice, c.ID, c.TokenGeneration, "x", now, now.Add(time.Minute)); err != nil || !ok {
			t.Fatalf("claim refresh lease: ok=%v err=%v", ok, err)
		}
		rot := connection.Rotation{
			ExpectRevision: c.AuthorityRevision, ExpectGeneration: c.TokenGeneration,
			GrantedScope: tgScope + " admin:users", LeaseOwner: "x", SealedTokens: []byte("x"), Now: now,
		}
		if _, err = s.RotatePAConnectionTokens(ctx, alice, c.ID, rot); !errors.Is(err, connection.ErrConflict) {
			t.Fatalf("rotation with a different scope: err %v, want ErrConflict", err)
		}
		rot.GrantedScope = c.GrantedScope
		if _, err = s.RotatePAConnectionTokens(ctx, alice, c.ID, rot); err != nil {
			t.Fatalf("rotation with the granted scope under the same lease: %v", err)
		}
		if c, err = e.m.Get(ctx, alice, c.ID); err != nil {
			t.Fatal(err)
		}

		// Terminal rows never go back to any pending state or to active.
		failed, err := e.m.Fail(ctx, alice, c.ID, c.AuthorityRevision, "test")
		if err != nil {
			t.Fatal(err)
		}
		for _, to := range []connection.State{connection.StatePendingLink, connection.StatePendingOAuth, connection.StatePendingReturn, connection.StatePendingConfirm, connection.StateActive} {
			_, err := s.TransitionPAConnection(ctx, alice, c.ID, connection.Transition{From: failed.State, To: to, ExpectRevision: failed.AuthorityRevision})
			if !errors.Is(err, connection.ErrIllegalTransition) {
				t.Errorf("failed -> %s: err %v, want ErrIllegalTransition", to, err)
			}
		}
		// The whole edge table: exactly the threat model's edges.
		legal := map[[2]connection.State]bool{
			{connection.StatePendingLink, connection.StatePendingOAuth}:     true,
			{connection.StatePendingOAuth, connection.StatePendingReturn}:   true,
			{connection.StatePendingReturn, connection.StatePendingConfirm}: true,
			{connection.StatePendingConfirm, connection.StateActive}:        true,
			{connection.StateActive, connection.StateExpired}:               true,
		}
		for _, from := range connection.AllStates {
			if from.NonTerminal() {
				legal[[2]connection.State{from, connection.StateFailed}] = true
			}
			if from != connection.StateRevoked {
				legal[[2]connection.State{from, connection.StateRevoked}] = true
			}
		}
		for _, from := range connection.AllStates {
			for _, to := range connection.AllStates {
				if got := connection.CanTransition(from, to); got != legal[[2]connection.State{from, to}] {
					t.Errorf("CanTransition(%s, %s) = %v", from, to, got)
				}
			}
		}

		// Reconnect = a new id; the old row is untouched.
		n1, err := e.m.Begin(ctx, alice, connection.ServerTG)
		if err != nil {
			t.Fatal(err)
		}
		if n1.ID == c.ID || n1.State != connection.StatePendingLink || n1.AuthorityRevision != 1 {
			t.Fatalf("reconnect did not create a fresh connection: %+v", n1)
		}
		if old, _ := e.m.Get(ctx, alice, c.ID); old.State != connection.StateFailed {
			t.Fatalf("old connection changed by reconnect: %s", old.State)
		}
	})
}

// TestConnection_S1T9_ExchangeScopeCheck is S1-T9: a token response with an
// extra scope, no scope field, or an unparseable scope fails the connection
// and revokes the token. A missing scope (a subset) fails the same way.
func TestConnection_S1T9_ExchangeScopeCheck(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		cases := []struct {
			name string
			resp string
		}{
			{"extra scope", `{"access_token":"fake-at-t9","refresh_token":"fake-rt-t9","token_type":"Bearer","scope":"telegram:dialogs:read telegram:messages:read admin:users"}`},
			{"no scope field", `{"access_token":"fake-at-t9","refresh_token":"fake-rt-t9","token_type":"Bearer"}`},
			{"null scope", `{"access_token":"fake-at-t9","refresh_token":"fake-rt-t9","token_type":"Bearer","scope":null}`},
			{"scope not a string", `{"access_token":"fake-at-t9","refresh_token":"fake-rt-t9","token_type":"Bearer","scope":["telegram:dialogs:read","telegram:messages:read"]}`},
			{"double space", `{"access_token":"fake-at-t9","refresh_token":"fake-rt-t9","token_type":"Bearer","scope":"telegram:dialogs:read  telegram:messages:read"}`},
			{"comma separated", `{"access_token":"fake-at-t9","refresh_token":"fake-rt-t9","token_type":"Bearer","scope":"telegram:dialogs:read,telegram:messages:read"}`},
			{"duplicated", `{"access_token":"fake-at-t9","refresh_token":"fake-rt-t9","token_type":"Bearer","scope":"telegram:dialogs:read telegram:messages:read telegram:messages:read"}`},
			{"missing scope", `{"access_token":"fake-at-t9","refresh_token":"fake-rt-t9","token_type":"Bearer","scope":"telegram:dialogs:read"}`},
			{"empty scope", `{"access_token":"fake-at-t9","refresh_token":"fake-rt-t9","token_type":"Bearer","scope":""}`},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				e := newEnv(t, s)
				alice, _ := principals(t, s)
				c := e.toPendingReturn(t, alice, connection.ServerTG)
				got, err := e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice", []byte(tc.resp))
				if !errors.Is(err, connection.ErrScopeMismatch) {
					t.Fatalf("err %v, want ErrScopeMismatch", err)
				}
				if got.State != connection.StateFailed {
					t.Fatalf("state %s, want failed", got.State)
				}
				if r := e.revoker.revoked(); !slices.Contains(r, "fake-at-t9") || !slices.Contains(r, "fake-rt-t9") {
					t.Fatalf("issued tokens were not revoked: %d calls", len(r))
				}
				_, sealed, err := s.GetPAConnectionSealed(ctx, alice, c.ID)
				if err != nil {
					t.Fatal(err)
				}
				if len(sealed.SealedTokens) != 0 || len(sealed.WrappedDEK) != 0 {
					t.Fatal("tokens were stored for a failed exchange")
				}
			})
		}
		t.Run("exact scope in any order succeeds", func(t *testing.T) {
			e := newEnv(t, s)
			alice, _ := principals(t, s)
			c := e.toPendingReturn(t, alice, connection.ServerTG)
			got, err := e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice",
				tokenResponse("fake-at-ok", "fake-rt-ok", "telegram:messages:read telegram:dialogs:read"))
			if err != nil || got.State != connection.StatePendingConfirm || got.GrantedScope != tgScope {
				t.Fatalf("exact scope: %+v %v", got, err)
			}
			if len(e.revoker.revoked()) != 0 {
				t.Fatal("a valid exchange revoked tokens")
			}
		})
		t.Run("alice allows iot:view only", func(t *testing.T) {
			e := newEnv(t, s)
			alice, _ := principals(t, s)
			c := e.toPendingReturn(t, alice, connection.ServerAlice)
			if _, err := e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice",
				tokenResponse("fake-at-al", "fake-rt-al", "iot:view iot:control")); !errors.Is(err, connection.ErrScopeMismatch) {
				t.Fatalf("alice with iot:control: err %v", err)
			}
			c2 := e.toPendingReturn(t, alice, connection.ServerAlice)
			if _, err := e.m.CompleteExchange(ctx, alice, c2.ID, c2.AuthorityRevision, "acct-alice",
				tokenResponse("fake-at-al2", "fake-rt-al2", "iot:view")); err != nil {
				t.Fatalf("alice with iot:view: %v", err)
			}
		})
	})
}

// TestConnection_S1T10_RefreshWiderScopeFails is S1-T10: a refresh that
// returns a wider scope fails the connection and revokes both what it issued
// and the original tokens.
func TestConnection_S1T10_RefreshWiderScopeFails(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		for _, scope := range []string{tgScope + " admin:broadcast", tgScope + " telegram:messages:write", ""} {
			t.Run(fmt.Sprintf("scope=%q", scope), func(t *testing.T) {
				e := newEnv(t, s)
				alice, _ := principals(t, s)
				c := e.toActive(t, alice)
				_, err := e.m.Refresh(ctx, alice, c.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
					return tokenResponse("fake-at-wide", "fake-rt-wide", scope), nil
				})
				if !errors.Is(err, connection.ErrScopeMismatch) {
					t.Fatalf("err %v, want ErrScopeMismatch", err)
				}
				got, err := e.m.Get(ctx, alice, c.ID)
				if err != nil || got.State != connection.StateFailed {
					t.Fatalf("state %s (%v), want failed", got.State, err)
				}
				if r := e.revoker.revoked(); !slices.Contains(r, "fake-at-wide") || !slices.Contains(r, "fake-rt-wide") {
					t.Fatal("the widened tokens were not revoked")
				}
				// The original tokens are wiped locally by the move to failed;
				// they must be revoked at the server too, not orphaned.
				if r := e.revoker.revoked(); !slices.Contains(r, "fake-rt-1-"+c.ID) || !slices.Contains(r, "fake-at-1-"+c.ID) {
					t.Fatal("the original tokens were not revoked")
				}
				if _, _, err := e.m.AccessToken(ctx, alice, c.ID, c.AuthorityRevision); err == nil {
					t.Fatal("connection still usable after a widened refresh")
				}
			})
		}
	})
}

// TestConnection_S1X1_CrossPrincipalIsolation is S1-X1 at the store level:
// with two principals A (Alice) and B (Bob), B cannot list, read, confirm or
// disconnect A's connection, and every refusal looks like "not found".
func TestConnection_S1X1_CrossPrincipalIsolation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		e := newEnv(t, s)
		alice, bob := principals(t, s)
		active := e.toActive(t, alice)
		pending := e.toPendingReturn(t, alice, connection.ServerTG)
		pending, err := e.m.CompleteExchange(ctx, alice, pending.ID, pending.AuthorityRevision, "acct-alice",
			tokenResponse("fake-at-x1", "fake-rt-x1", tgScope))
		if err != nil {
			t.Fatal(err)
		}
		bobsOwn := e.toActive(t, bob)

		list, err := e.m.List(ctx, bob)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 1 || list[0].ID != bobsOwn.ID {
			t.Fatalf("Bob's list = %+v, want only his own connection", list)
		}
		if _, err := e.m.Get(ctx, bob, active.ID); !errors.Is(err, connection.ErrNotFound) {
			t.Errorf("Bob Get(Alice's) err %v, want ErrNotFound", err)
		}
		if _, err := e.m.Authorize(ctx, bob, active.ID, active.AuthorityRevision); !errors.Is(err, connection.ErrNotFound) {
			t.Errorf("Bob Authorize(Alice's) err %v, want ErrNotFound", err)
		}
		if tok, _, err := e.m.AccessToken(ctx, bob, active.ID, active.AuthorityRevision); !errors.Is(err, connection.ErrNotFound) || !tok.Empty() {
			t.Errorf("Bob AccessToken(Alice's) err %v, want ErrNotFound", err)
		}
		if _, err := e.m.Confirm(ctx, bob, pending.ID, pending.AuthorityRevision); !errors.Is(err, connection.ErrNotFound) {
			t.Errorf("Bob Confirm(Alice's) err %v, want ErrNotFound", err)
		}
		if _, err := e.m.Disconnect(ctx, bob, active.ID); !errors.Is(err, connection.ErrNotFound) {
			t.Errorf("Bob Disconnect(Alice's) err %v, want ErrNotFound", err)
		}
		if _, err := e.m.Refresh(ctx, bob, active.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			t.Error("Bob's refresh ran against Alice's connection")
			return nil, errors.New("unreachable")
		}); !errors.Is(err, connection.ErrNotFound) {
			t.Errorf("Bob Refresh(Alice's) err %v, want ErrNotFound", err)
		}

		// Alice's rows are untouched.
		if c, err := e.m.Get(ctx, alice, active.ID); err != nil || c.State != connection.StateActive || c.AuthorityRevision != active.AuthorityRevision {
			t.Errorf("Alice's active connection changed: %+v %v", c, err)
		}
		if c, err := e.m.Get(ctx, alice, pending.ID); err != nil || c.State != connection.StatePendingConfirm {
			t.Errorf("Alice's pending connection changed: %+v %v", c, err)
		}
		if len(e.revoker.revoked()) != 0 {
			t.Error("Bob's disconnect revoked a token")
		}
	})
}

// TestConnection_S1K1_RedactionDropsTokens is S1-K1: the redaction handler
// drops token and client-secret fields, and a connection.Secret renders as
// "[redacted]" however it is logged or printed.
func TestConnection_S1K1_RedactionDropsTokens(t *testing.T) {
	const pattern = "fake-tok-k1"
	var buf bytes.Buffer
	log := slog.New(audit.NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))

	ts := connection.VerifyTokenResponse(connection.ServerTG,
		tokenResponse(pattern+"-access", pattern+"-refresh", tgScope)).Tokens
	sec := connection.NewSecret(pattern + "-secret")

	log.Info("token fields",
		"access_token", pattern+"-a",
		"refresh_token", pattern+"-r",
		"id_token", pattern+"-i",
		"client_secret", pattern+"-cs",
		"registration_access_token", pattern+"-rat",
		"code", pattern+"-code",
		"authorization_code", pattern+"-ac",
		"code_verifier", pattern+"-cv",
		"completion_code", pattern+"-cc",
		"link_token", pattern+"-lt",
		"dek", pattern+"-dek",
		"wrapped_dek", pattern+"-wdek",
		"X-Vault-Token", pattern+"-vault",
		slog.Group("oauth", slog.String("Access_Token", pattern+"-nested")),
	)
	log.With("refresh_token", pattern+"-with").Info("with attrs")
	log.Info("secret values under innocent keys", "tokens", ts, "s", sec, "ptr", &ts)

	formatted := fmt.Sprintf("%v %+v %#v %s %q", ts, ts, ts, sec, sec)
	js, err := json.Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"slog": buf.String(), "fmt": formatted, "json": string(js)} {
		if strings.Contains(out, pattern) {
			t.Errorf("%s output carries token material: %s", name, out)
		}
	}
	if !strings.Contains(buf.String(), "[redacted") {
		t.Fatal("redaction marker missing; the test is not looking at the log")
	}
}
