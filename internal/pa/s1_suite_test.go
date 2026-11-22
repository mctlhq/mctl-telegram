package pa_test

// S1 tests added when the suite was assembled (#1317): the rows that had
// no test of their own. Each one is named in
// docs/agent-runtime/pa-s1-manifest.yaml. They reuse the dispatch
// acceptance environment: fake tg- and alice-shaped MCP servers, the real
// run loop, job ledger, connection manager and audit chain.

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
)

// tokenPatterns are the prefixes of every secret the fake authorization
// server issues in this environment (dispatchEnv.active): access token,
// refresh token and authorization code.
var tokenPatterns = []string{"fake-at-", "fake-rt-", "fake-code-"}

func carriesToken(s string) string {
	for _, p := range tokenPatterns {
		if strings.Contains(s, p) {
			return p
		}
	}
	return ""
}

// jwtPayload decodes the claims segment of a compact JWT, so a token
// smuggled into a claim is scanned too.
func jwtPayload(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("job token is not a compact JWT: %d parts", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("job token payload: %v", err)
	}
	return string(b)
}

// TestDispatch_S1K2_NoTokenMaterialToWorker: the job envelope (the claim
// response and the job token in it), the turn answer and every tool answer
// the worker gets back (a result, a tool error, a transport failure and a
// refusal) carry none of the fake server's token material, although the
// connection's access token was really used for the call.
func TestDispatch_S1K2_NoTokenMaterialToWorker(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		e.h.Consent(alice)
		e.h.Text(alice, "what is new?")
		claim, token, code := e.h.ClaimRaw()
		if code != http.StatusOK || token == "" {
			t.Fatalf("claim: %d %s", code, claim)
		}
		seen := map[string]string{
			"claim":     string(claim),
			"job token": jwtPayload(t, token),
		}
		turn, code := e.h.TurnRaw(token)
		if code != http.StatusOK {
			t.Fatalf("turn: %d %s", code, turn)
		}
		seen["turn"] = string(turn)

		ok := e.call(token, req("tg", "list_dialogs", ""))
		if ok.code != http.StatusOK || !strings.Contains(ok.Output, "result of list_dialogs") {
			t.Fatalf("result: %+v", ok)
		}
		seen["result"] = ok.raw

		e.tg.mu.Lock()
		e.tg.out = []byte(`{"isError":true,"content":[{"type":"text","text":"tool failed"}]}`)
		e.tg.mu.Unlock()
		seen["tool error"] = e.call(token, req("tg", "get_messages", "")).raw

		e.tg.mu.Lock()
		e.tg.out, e.tg.callErr = nil, errFakeTransport
		e.tg.mu.Unlock()
		seen["transport failure"] = e.call(token, req("tg", "list_dialogs", "")).raw

		refused := e.call(token, req("tg", "list_dialogs", e.connB.ID))
		if refused.Stop != connector.ReasonConnectionUnbound {
			t.Fatalf("refusal: %+v", refused)
		}
		seen["refusal"] = refused.raw

		// The token was opened and sent to the server: the scan is looking
		// at a run that really held token material.
		if _, bearers, _ := e.tg.snapshot(); len(bearers) == 0 || !strings.HasPrefix(bearers[0], "fake-at-") {
			t.Fatalf("bearers %v: the fake server never saw the token", bearers)
		}
		for name, body := range seen {
			if p := carriesToken(body); p != "" {
				t.Errorf("%s returned to the worker carries %q token material: %s", name, p, body)
			}
		}
	})
}

// TestDispatch_S1F4_ConsentWithdrawnRefusesNextDispatch: consent withdrawn
// between two calls of one run refuses the run's next dispatch, before the
// server is called. (The flag halves of S1-F4 are TestDispatch_S1F4; a
// result on the wire when consent goes is TestDispatch_JobStoppedFencesResult.)
func TestDispatch_S1F4_ConsentWithdrawnRefusesNextDispatch(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		token, _ := e.run(alice)
		if a := e.call(token, req("tg", "list_dialogs", "")); a.code != http.StatusOK {
			t.Fatalf("first call %+v", a)
		}
		e.h.Text(alice, "/consent withdraw")
		a := e.call(token, req("tg", "list_dialogs", ""))
		if a.code == http.StatusOK || a.Output != "" {
			t.Fatalf("dispatched after consent was withdrawn: %+v", a)
		}
		if a.Stop != connector.ReasonJobStale && a.Stop != connector.ReasonJobGone {
			t.Fatalf("refusal %q, want job_stale or job_gone", a.Stop)
		}
		if calls, _, _ := e.tg.snapshot(); len(calls) != 1 {
			t.Fatalf("calls after withdrawal: %v", calls)
		}
	})
}

// TestDispatch_S1F1_ExternalToolsFlagOnlyStopsTools: turning
// PA_EXTERNAL_TOOLS_ENABLED off disables MCP calls and nothing else: the
// same run still gets its model turn, and turning the flag back on lets
// the run dispatch again. The server flag stops only its own server. The
// parsing half of S1-F1 (each variable sets exactly its own switch) is
// connector.TestEnvFlags_S1F1_EachVariableItsOwnSwitch; PA_ENABLED is
// TestBuildPA_InertByDefault.
func TestDispatch_S1F1_ExternalToolsFlagOnlyStopsTools(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		token, _ := e.run(alice)

		e.flags.Store(&connector.Flags{ExternalTools: false, Servers: map[string]bool{"tg": true}})
		if a := e.call(token, req("tg", "list_dialogs", "")); a.Stop != connector.ReasonFlagOff {
			t.Fatalf("tools off: %+v", a)
		}
		if body, code := e.h.TurnRaw(token); code != http.StatusOK {
			t.Fatalf("tools off stopped the model turn: %d %s", code, body)
		}

		e.flags.Store(&connector.Flags{ExternalTools: true, Servers: map[string]bool{"tg": true}})
		if a := e.call(token, req("tg", "list_dialogs", "")); a.code != http.StatusOK {
			t.Fatalf("tools back on: %+v", a)
		}

		// A server flag for another server does not touch tg.
		e.flags.Store(&connector.Flags{ExternalTools: true, Servers: map[string]bool{"tg": true, "alice": false}})
		if a := e.call(token, req("tg", "get_messages", "")); a.code != http.StatusOK {
			t.Fatalf("alice off stopped tg: %+v", a)
		}
		if calls, _, _ := e.tg.snapshot(); len(calls) != 2 {
			t.Fatalf("calls %v, want the two with tools on", calls)
		}
	})
}

type fakeTransportError struct{}

func (fakeTransportError) Error() string { return "fake transport failure" }

var errFakeTransport error = fakeTransportError{}

// TestDispatch_S1X3_OwnUnboundConnectionRefused: the other half of S1-X3.
// A connection of the same principal, on the same server, that the run did
// not bind is refused as unbound before any token is opened, even though
// the principal filter of the listing keeps it.
func TestDispatch_S1X3_OwnUnboundConnectionRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		// Not active: a second active connection on tg would supersede
		// the bound one (#1318 C2b). Unbound is refused whatever its state.
		unbound := e.pendingConfirm(alice, "tg", "acct-alice-2", tgScope)
		token, _ := e.run(alice)
		e.wantRefusal(e.call(token, req("tg", "list_dialogs", unbound.ID)), http.StatusForbidden, connector.ReasonConnectionUnbound, alice, 0)
		e.noDispatch()
		if _, bearers, _ := e.tg.snapshot(); len(bearers) != 0 {
			t.Fatalf("a token was opened: %v", bearers)
		}
		// The bound connection still works on the same run.
		if a := e.call(token, req("tg", "list_dialogs", e.connA.ID)); a.code != http.StatusOK {
			t.Fatalf("bound call %+v", a)
		}
	})
}

// disablePrincipal records an admin disable of principal, as the MCP tool
// set_pa_principal_disabled does.
func disablePrincipal(t *testing.T, s *db.Store, principal int64) {
	t.Helper()
	if err := s.SetPAPrincipalDisabled(context.Background(), principal, 4242999, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
}

// TestDispatch_S1F4_PrincipalDisabledRefusesNextDispatch: an admin disable
// (T11, #1318) takes effect at the principal's next dispatch, with no
// restart: the call is refused and audited as principal_disabled, nothing
// reaches the server, the job is cancelled and the principal told once.
// Bob is not touched. Taking a principal off the preview allowlist does
// the same, as principal_not_allowed.
func TestDispatch_S1F4_PrincipalDisabledRefusesNextDispatch(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		refuse       func(e *dispatchEnv)
	}{
		{"disabled", connector.ReasonPrincipalDisabled, func(e *dispatchEnv) { disablePrincipal(e.t, e.store, alice) }},
		{"not allowed", connector.ReasonPrincipalNotAllowed, func(e *dispatchEnv) { e.h.Deny(alice) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newDispatchEnv(t, s)
				token, jobID := e.run(alice)
				if a := e.call(token, req("tg", "list_dialogs", "")); a.code != http.StatusOK {
					t.Fatalf("first call %+v", a)
				}
				tokenB, _ := e.run(bob)
				tc.refuse(e)
				before := len(e.audit(alice))
				e.wantRefusal(e.call(token, req("tg", "list_dialogs", "")), http.StatusForbidden, tc.reason, alice, before)
				if calls, _, _ := e.tg.snapshot(); len(calls) != 1 {
					t.Fatalf("calls after the refusal: %v", calls)
				}
				if st := e.h.Count(`SELECT count(*) FROM pa_jobs WHERE id = $1 AND status = 'cancelled'`, jobID); st != 1 {
					t.Fatal("the refused principal's job was not cancelled")
				}
				if n := e.h.Count(`SELECT count(*) FROM pa_outbox WHERE principal = $1 AND kind = 'principal_stopped'`, alice); n != 1 {
					t.Fatalf("%d unavailable notices, want 1", n)
				}
				if a := e.call(tokenB, req("tg", "list_dialogs", "")); a.code != http.StatusOK {
					t.Fatalf("bob refused: %+v", a)
				}
			})
		})
	}
}

// TestDispatch_S1F4_PrincipalDisabledFencesInFlight: a disable that lands
// while a call is in flight fences its result: the worker gets no output.
func TestDispatch_S1F4_PrincipalDisabledFencesInFlight(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		token, _ := e.run(alice)
		e.tg.onCall = func() { disablePrincipal(t, s, alice) }
		a := e.call(token, req("tg", "list_dialogs", ""))
		if a.code != http.StatusConflict || a.Stop != connector.ReasonFenced || a.Output != "" || strings.Contains(a.raw, "result of") {
			t.Fatalf("answer %+v", a)
		}
		rows := e.audit(alice)
		if last := rows[len(rows)-1]; last.status != "fenced" {
			t.Fatalf("last row %+v", last)
		}
	})
}

// TestDispatch_S1F4_PrincipalStatusUnreadableRefuses: a disable that
// cannot be read refuses the dispatch as unreadable. It is neither
// "enabled" (the call would run) nor "disabled" (the job would be
// cancelled for a fault): the job stays and the next readable step goes on.
func TestDispatch_S1F4_PrincipalStatusUnreadableRefuses(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		token, jobID := e.run(alice)
		e.h.FailDisableReads(true)
		before := len(e.audit(alice))
		e.wantRefusal(e.call(token, req("tg", "list_dialogs", "")), http.StatusServiceUnavailable, connector.ReasonJobUnreadable, alice, before)
		if calls, _, _ := e.tg.snapshot(); len(calls) != 0 {
			t.Fatalf("dispatched on an unreadable disable: %v", calls)
		}
		if n := e.h.Count(`SELECT count(*) FROM pa_jobs WHERE id = $1 AND status = 'cancelled'`, jobID); n != 0 {
			t.Fatal("an unreadable disable cancelled the job")
		}
		e.h.FailDisableReads(false)
		if a := e.call(token, req("tg", "list_dialogs", "")); a.code != http.StatusOK {
			t.Fatalf("after the store recovers: %+v", a)
		}
	})
}

// TestDispatch_S1F1_WritesFlagLeavesReadsAlone: PA_WRITES_ENABLED gates
// writes and disclosures only (T11; its "disables writes" half is S2-F3,
// owner decision 2026-11-21, #1318). With it unset, "true", "false" or
// malformed, a read dispatches identically: same status, same output, one
// call to the server.
func TestDispatch_S1F1_WritesFlagLeavesReadsAlone(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		token, _ := e.run(alice)
		var want *answer
		for i, v := range []string{"<unset>", "true", "false", "yes"} {
			env := map[string]string{connector.ExternalToolsFlagEnv: "true", "PA_SERVER_TG_ENABLED": "true"}
			if v != "<unset>" {
				env[connector.WritesFlagEnv] = v
			}
			e.reconfigure(func(c *connector.DispatcherConfig) {
				c.Flags = connector.EnvFlags(func(k string) string { return env[k] })
			})
			a := e.call(token, req("tg", "list_dialogs", ""))
			if calls, _, _ := e.tg.snapshot(); len(calls) != i+1 {
				t.Fatalf("%s=%s: %d calls in all, want %d", connector.WritesFlagEnv, v, len(calls), i+1)
			}
			if want == nil {
				if a.code != http.StatusOK || a.Output == "" {
					t.Fatalf("control (%s unset): %+v", connector.WritesFlagEnv, a)
				}
				want = &a
				continue
			}
			if a.code != want.code || a.Stop != want.Stop || a.Output != want.Output {
				t.Fatalf("%s=%s: %+v, want the same as unset %+v", connector.WritesFlagEnv, v, a, *want)
			}
		}
	})
}
