package pa_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// Token refresh at dispatch (#1318 slice C2b). A 401 from the server gets
// exactly one refresh and one retry per tool request; a 403 is a refusal
// with neither; a refresh the server answers invalid_grant expires the
// connection, queues one notice, and every later call is refused without
// asking the server again.

const (
	oldTG   = "fake-at-acct-alice"
	freshTG = "fake-at-acct-alice-r"
)

func (e *dispatchEnv) rejectList(tokens map[string]error) {
	e.tg.mu.Lock()
	e.tg.listReject = tokens
	e.tg.mu.Unlock()
}

func (e *dispatchEnv) rejectCall(tokens map[string]error) {
	e.tg.mu.Lock()
	e.tg.callReject = tokens
	e.tg.mu.Unlock()
}

func (e *dispatchEnv) setRefresh(fn connection.RefreshFunc) { e.refreshFn.Store(&fn) }

func (e *dispatchEnv) connState(t *testing.T, id string) connection.State {
	t.Helper()
	c, err := e.mgr.Get(context.Background(), alice, id)
	if err != nil {
		t.Fatal(err)
	}
	return c.State
}

// expiryNotices counts alice's connection_expired outbox rows for id.
func (e *dispatchEnv) expiryNotices(t *testing.T, id string) int {
	t.Helper()
	rows, err := e.store.PAOutboxRows(context.Background(), alice)
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

func TestDispatch_C2b_ListRejectedRefreshesOnceAndRetries(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		e.rejectList(map[string]error{oldTG: connector.ErrMCPTokenRejected})
		token, _ := e.run(alice)
		if a := e.call(token, req("tg", "list_dialogs", "")); a.code != http.StatusOK {
			t.Fatalf("call after a 401 on tools/list: %+v", a)
		}
		if n := e.refreshes.Load(); n != 1 {
			t.Fatalf("refreshes %d, want 1", n)
		}
		_, bearers, _ := e.tg.snapshot()
		if !slices.Equal(bearers, []string{oldTG, freshTG, freshTG}) {
			t.Fatalf("bearers %v, want the old token once, then the refreshed one", bearers)
		}
		// The refreshed token is stored: the next call needs no refresh.
		if a := e.call(token, req("tg", "get_messages", "")); a.code != http.StatusOK {
			t.Fatalf("second call: %+v", a)
		}
		if n := e.refreshes.Load(); n != 1 {
			t.Fatalf("refreshes %d after a second call, want 1", n)
		}
	})
}

func TestDispatch_C2b_CallRejectedRefreshesOnceAndRetries(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		e.rejectCall(map[string]error{oldTG: connector.ErrMCPTokenRejected})
		token, _ := e.run(alice)
		if a := e.call(token, req("tg", "list_dialogs", "")); a.code != http.StatusOK {
			t.Fatalf("call after a 401 on tools/call: %+v", a)
		}
		calls, bearers, _ := e.tg.snapshot()
		if n := e.refreshes.Load(); n != 1 || len(calls) != 2 || bearers[len(bearers)-1] != freshTG {
			t.Fatalf("refreshes %d, calls %v, bearers %v; want 1 refresh and one retry with the fresh token", n, calls, bearers)
		}
	})
}

// A 401 after the refresh is a refusal: one refresh per request, never a
// loop.
func TestDispatch_C2b_SecondRejectionRefused(t *testing.T) {
	for name, reject := range map[string]func(*dispatchEnv, map[string]error){
		"list": (*dispatchEnv).rejectList,
		"call": (*dispatchEnv).rejectCall,
	} {
		t.Run(name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newDispatchEnv(t, s)
				reject(e, map[string]error{oldTG: connector.ErrMCPTokenRejected, freshTG: connector.ErrMCPTokenRejected})
				token, _ := e.run(alice)
				a := e.call(token, req("tg", "list_dialogs", ""))
				if a.code != http.StatusBadGateway || a.Stop != connector.ReasonServerRefused {
					t.Fatalf("answer %+v, want 502 server_refused", a)
				}
				if n := e.refreshes.Load(); n != 1 {
					t.Fatalf("refreshes %d, want exactly 1", n)
				}
				if st := e.connState(t, e.connA.ID); st != connection.StateActive {
					t.Fatalf("state %s, want active: a rejected token is not an expired grant", st)
				}
			})
		})
	}
}

// A 403 means the server accepted the token and refused the request: no
// refresh, no retry.
func TestDispatch_C2b_ForbiddenNotRetried(t *testing.T) {
	for name, reject := range map[string]func(*dispatchEnv, map[string]error){
		"list": (*dispatchEnv).rejectList,
		"call": (*dispatchEnv).rejectCall,
	} {
		t.Run(name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newDispatchEnv(t, s)
				reject(e, map[string]error{oldTG: connector.ErrMCPForbidden})
				token, _ := e.run(alice)
				a := e.call(token, req("tg", "list_dialogs", ""))
				if a.code != http.StatusBadGateway || a.Stop != connector.ReasonServerRefused {
					t.Fatalf("answer %+v, want 502 server_refused", a)
				}
				calls, bearers, _ := e.tg.snapshot()
				if n := e.refreshes.Load(); n != 0 || slices.Contains(bearers, freshTG) {
					t.Fatalf("refreshes %d, bearers %v; a 403 must not refresh", n, bearers)
				}
				if name == "call" && len(calls) != 1 {
					t.Fatalf("calls %v, want one: a 403 is not retried", calls)
				}
			})
		})
	}
}

// invalid_grant on the refresh expires the connection, queues exactly one
// "link it again" notice, and refuses as connection_expired. Later calls
// are refused before the server is asked: no retry storm.
func TestDispatch_C2b_InvalidGrantExpiresOnce(t *testing.T) {
	for name, reject := range map[string]func(*dispatchEnv, map[string]error){
		"list": (*dispatchEnv).rejectList,
		"call": (*dispatchEnv).rejectCall,
	} {
		t.Run(name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newDispatchEnv(t, s)
				e.setRefresh(func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
					return nil, connection.ErrInvalidGrant
				})
				reject(e, map[string]error{oldTG: connector.ErrMCPTokenRejected})
				token, _ := e.run(alice)
				a := e.call(token, req("tg", "list_dialogs", ""))
				if a.code != http.StatusForbidden || a.Stop != connector.ReasonConnectionExpired {
					t.Fatalf("answer %+v, want 403 connection_expired", a)
				}
				if st := e.connState(t, e.connA.ID); st != connection.StateExpired {
					t.Fatalf("state %s, want expired", st)
				}
				calls, _, lists := e.tg.snapshot()
				for i := 0; i < 3; i++ {
					a = e.call(token, req("tg", "list_dialogs", ""))
					if a.code != http.StatusForbidden || a.Stop != connector.ReasonConnectionExpired {
						t.Fatalf("later call %d: %+v, want 403 connection_expired", i, a)
					}
				}
				calls2, _, lists2 := e.tg.snapshot()
				if n := e.refreshes.Load(); n != 1 || len(calls2) != len(calls) || lists2 != lists {
					t.Fatalf("refreshes %d, server reached %d->%d calls %d->%d lists; want 1 refresh and no more requests",
						n, len(calls), len(calls2), lists, lists2)
				}
				if n := e.expiryNotices(t, e.connA.ID); n != 1 {
					t.Fatalf("expiry notices %d, want exactly 1", n)
				}
			})
		})
	}
}

// A refresh that fails for any other reason fails this call only: the
// connection stays active and nothing retries.
func TestDispatch_C2b_TransientRefreshFailsCall(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		e.setRefresh(func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
			return nil, errors.New("fake: token endpoint down")
		})
		e.rejectList(map[string]error{oldTG: connector.ErrMCPTokenRejected})
		token, _ := e.run(alice)
		a := e.call(token, req("tg", "list_dialogs", ""))
		if a.code != http.StatusServiceUnavailable || a.Stop != connector.ReasonRefreshUnavailable {
			t.Fatalf("answer %+v, want 503 refresh_unavailable", a)
		}
		if n := e.refreshes.Load(); n != 1 {
			t.Fatalf("refreshes %d, want 1", n)
		}
		if st := e.connState(t, e.connA.ID); st != connection.StateActive {
			t.Fatalf("state %s, want active", st)
		}
		if n := e.expiryNotices(t, e.connA.ID); n != 0 {
			t.Fatalf("expiry notices %d for a transient failure, want 0", n)
		}
	})
}

// A request whose tools/list already used its one refresh does not get a
// second one when tools/call then rejects the refreshed token.
func TestDispatch_C2b_OneRefreshAcrossListAndCall(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		e.rejectList(map[string]error{oldTG: connector.ErrMCPTokenRejected})
		e.rejectCall(map[string]error{freshTG: connector.ErrMCPTokenRejected})
		token, _ := e.run(alice)
		a := e.call(token, req("tg", "list_dialogs", ""))
		if a.code != http.StatusBadGateway || a.Stop != connector.ReasonServerRefused {
			t.Fatalf("answer %+v, want 502 server_refused", a)
		}
		if n := e.refreshes.Load(); n != 1 {
			t.Fatalf("refreshes %d, want exactly 1 per request", n)
		}
	})
}
