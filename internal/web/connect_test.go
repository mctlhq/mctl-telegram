package web

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

const testConnectIssuer = "https://tg.test"

// stubExchanger implements OAuthExchanger for tests.
type stubExchanger struct {
	err error
}

func (s *stubExchanger) ExchangeConnect(_ context.Context, _, _, _, _ string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "fake-access-token", nil
}

// stubIdentifier implements ConnectIdentifier for tests.
type stubIdentifier struct {
	id  *auth.Identity
	err error
}

func (s *stubIdentifier) Authenticate(_ *http.Request) (*auth.Identity, error) {
	return s.id, s.err
}

// captureConnectLog swaps slog's default handler for a text handler writing
// to buf, restoring the previous default on test cleanup. Matches the
// pattern in internal/oauth/enable_access_abandonment_test.go's
// captureEnableLog.
func captureConnectLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func newTestConnectServer(t *testing.T, opts ...func(*ConnectConfig)) *ConnectServer {
	t.Helper()
	cfg := ConnectConfig{
		Issuer:               testConnectIssuer,
		OAuthServer:          &stubExchanger{},
		CodeTTL:              10 * time.Minute,
		ClaudeAIConnectorURL: "https://claude.ai/settings/integrations",
		ClientID:             "test-connect-client",
		MCPPath:              "/mcp",
	}
	for _, o := range opts {
		o(&cfg)
	}
	return NewConnectServer(cfg)
}

// TestHandleConnect_MaxSessionsCap confirms that when MaxSessions is set,
// the oldest pending session is evicted when the cap is reached.
func TestHandleConnect_MaxSessionsCap(t *testing.T) {
	srv := newTestConnectServer(t, func(cfg *ConnectConfig) {
		cfg.MaxSessions = 2
	})

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/telegram/connect", nil)
		rec := httptest.NewRecorder()
		srv.HandleConnect(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("HandleConnect call %d status = %d", i+1, rec.Code)
		}
	}

	srv.mu.Lock()
	n := len(srv.sessions)
	srv.mu.Unlock()

	if n != 2 {
		t.Errorf("expected %d sessions after cap eviction, got %d", 2, n)
	}
}

// TestHandleConnect_GeneratesDistinctPKCEPairs confirms that successive calls
// to HandleConnect produce distinct state tokens and PKCE pairs.
func TestHandleConnect_GeneratesDistinctPKCEPairs(t *testing.T) {
	srv := newTestConnectServer(t)

	req1 := httptest.NewRequest("GET", "/telegram/connect", nil)
	rec1 := httptest.NewRecorder()
	srv.HandleConnect(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first HandleConnect status = %d", rec1.Code)
	}

	req2 := httptest.NewRequest("GET", "/telegram/connect", nil)
	rec2 := httptest.NewRecorder()
	srv.HandleConnect(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second HandleConnect status = %d", rec2.Code)
	}

	// Each call should have stored a distinct session.
	srv.mu.Lock()
	n := len(srv.sessions)
	verifiers := make(map[string]bool)
	for _, s := range srv.sessions {
		verifiers[s.verifier] = true
	}
	srv.mu.Unlock()

	if n != 2 {
		t.Errorf("expected 2 pending sessions after 2 calls, got %d", n)
	}
	if len(verifiers) != 2 {
		t.Error("successive HandleConnect calls generated duplicate PKCE verifiers")
	}
}

// TestHandleConnect_CSPPresent confirms that the CSP header is set on the
// landing page response and does not include script-src without a nonce
// (the landing page has no inline script).
func TestHandleConnect_CSPPresent(t *testing.T) {
	srv := newTestConnectServer(t)
	req := httptest.NewRequest("GET", "/telegram/connect", nil)
	rec := httptest.NewRecorder()
	srv.HandleConnect(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing from HandleConnect response")
	}
	if strings.Contains(csp, "script-src") {
		t.Errorf("landing page CSP should not include script-src (no inline script): %q", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("landing page CSP should start with default-src 'none': %q", csp)
	}
	if !strings.Contains(csp, "img-src https://ui.mctl.ai") {
		t.Errorf("landing page CSP must allow the CDN favicon: %q", csp)
	}
}

// TestHandleConnectDone_CSPPresent confirms that the success/error pages also
// carry the strict CSP header.
func TestHandleConnectDone_CSPPresent(t *testing.T) {
	srv := newTestConnectServer(t)

	// Trigger the error page (unknown state) to check CSP on a done response.
	req := httptest.NewRequest("GET", "/telegram/connect/done?code=x&state=unknown", nil)
	rec := httptest.NewRecorder()
	srv.HandleConnectDone(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing from HandleConnectDone response")
	}
	if strings.Contains(csp, "script-src") {
		t.Errorf("done page CSP should not include script-src (no inline script): %q", csp)
	}
	if !strings.Contains(csp, "img-src https://ui.mctl.ai") {
		t.Errorf("done page CSP must allow the CDN favicon: %q", csp)
	}
}

// TestHandleConnectDone_UnknownState confirms that /telegram/connect/done
// with an unknown state, and no already-connected credential, renders the
// "link already used" page at 200 rather than a bare 400 (issue-695: a
// reused/unknown state is a correct answer about link state, not a client
// error).
func TestHandleConnectDone_UnknownState(t *testing.T) {
	srv := newTestConnectServer(t)
	req := httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=bogus", nil)
	rec := httptest.NewRecorder()
	srv.HandleConnectDone(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("unknown state: status = %d, want 200 (reused-link page)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "already used") {
		t.Errorf("reused-link page body should mention the link was already used: %s", rec.Body.String())
	}
}

// TestHandleConnectDone_ExpiredSession confirms that a session past CodeTTL
// is swept on the next HandleConnect call and that HandleConnectDone then
// renders the "link already used" page at 200 (no already-connected
// credential is wired in this test, so no redirect to manage is possible).
func TestHandleConnectDone_ExpiredSession(t *testing.T) {
	now := time.Now()
	srv := newTestConnectServer(t, func(cfg *ConnectConfig) {
		cfg.CodeTTL = 1 * time.Second
		cfg.clock = func() time.Time { return now }
	})

	// Generate a session at 'now'.
	req := httptest.NewRequest("GET", "/telegram/connect", nil)
	rec := httptest.NewRecorder()
	srv.HandleConnect(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleConnect status = %d", rec.Code)
	}

	// Grab the state from the in-memory map (only one session exists).
	var state string
	srv.mu.Lock()
	for k := range srv.sessions {
		state = k
	}
	srv.mu.Unlock()
	if state == "" {
		t.Fatal("no session stored after HandleConnect")
	}

	// Advance clock past TTL and trigger a sweep via another HandleConnect.
	srv.clock = func() time.Time { return now.Add(10 * time.Second) }
	req2 := httptest.NewRequest("GET", "/telegram/connect", nil)
	rec2 := httptest.NewRecorder()
	srv.HandleConnect(rec2, req2)

	// The original session should have been swept.
	srv.mu.Lock()
	_, ok := srv.sessions[state]
	srv.mu.Unlock()
	if ok {
		t.Error("expired session was not swept by the second HandleConnect call")
	}

	// HandleConnectDone with the swept state should render the reused page
	// (should return 200, not 400): the session no longer exists in
	// s.sessions, so this is indistinguishable from an unknown state.
	req3 := httptest.NewRequest("GET", "/telegram/connect/done?code=x&state="+state, nil)
	rec3 := httptest.NewRecorder()
	srv.HandleConnectDone(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("expired session done: status = %d, want 200 (reused-link page)", rec3.Code)
	}
	if !strings.Contains(rec3.Body.String(), "already used") {
		t.Errorf("expired session done body should mention the link was already used: %s", rec3.Body.String())
	}
}

// TestHandleConnectDone_ReusedState_RedirectsToManage confirms that a replay
// of a consumed state redirects to /telegram/connect/manage (303) when the
// request carries a credential the configured Identifier accepts.
func TestHandleConnectDone_ReusedState_RedirectsToManage(t *testing.T) {
	ident := &stubIdentifier{id: &auth.Identity{UserID: 1, Subject: "tg:1"}}
	srv := newTestConnectServer(t, func(cfg *ConnectConfig) {
		cfg.Identifier = ident
	})

	state := "reused-state-with-identity"
	srv.mu.Lock()
	srv.sessions[state] = &connectSession{verifier: strings.Repeat("a", 43), createdAt: time.Now()}
	srv.mu.Unlock()
	url := "/telegram/connect/done?code=abc&state=" + state

	// First call consumes the state.
	firstRec := httptest.NewRecorder()
	srv.HandleConnectDone(firstRec, httptest.NewRequest("GET", url, nil))
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first call: status = %d, body=%s", firstRec.Code, firstRec.Body.String())
	}

	// Replay: state is now unknown. The stub Identifier reports the browser
	// as already connected, so this must redirect rather than show the
	// reused page.
	replayRec := httptest.NewRecorder()
	srv.HandleConnectDone(replayRec, httptest.NewRequest("GET", url, nil))
	if replayRec.Code != http.StatusSeeOther {
		t.Fatalf("replay with identity: status = %d, want 303, body=%s", replayRec.Code, replayRec.Body.String())
	}
	if loc := replayRec.Header().Get("Location"); loc != "/telegram/connect/manage" {
		t.Errorf("Location = %q, want /telegram/connect/manage", loc)
	}
}

// TestHandleConnectDone_RecoveredRedirect confirms that an unknown/expired
// state whose request carries a credential the configured Identifier accepts
// logs the recovery under its own reason (recovered_redirect) instead of the
// failure reasons (unknown_state/expired_state) — so a successful redirect to
// /manage does not inflate the failure count a real operator greps and
// alerts on.
func TestHandleConnectDone_RecoveredRedirect(t *testing.T) {
	t.Run("identifier accepts: logs recovered_redirect, not a failure reason", func(t *testing.T) {
		buf := captureConnectLog(t)
		ident := &stubIdentifier{id: &auth.Identity{UserID: 1, Subject: "tg:1"}}
		srv := newTestConnectServer(t, func(cfg *ConnectConfig) {
			cfg.Identifier = ident
		})

		rec := httptest.NewRecorder()
		srv.HandleConnectDone(rec, httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=never-issued", nil))

		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303, body=%s", rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "/telegram/connect/manage" {
			t.Errorf("Location = %q, want /telegram/connect/manage", loc)
		}
		out := buf.String()
		if !strings.Contains(out, "reason="+reasonRecoveredRedirect) {
			t.Errorf("expected a log line with reason=%s, got:\n%s", reasonRecoveredRedirect, out)
		}
		if strings.Contains(out, "reason="+reasonUnknownState) {
			t.Errorf("must not log reason=%s on a recovered redirect, got:\n%s", reasonUnknownState, out)
		}
		if strings.Contains(out, "reason="+reasonExpiredState) {
			t.Errorf("must not log reason=%s on a recovered redirect, got:\n%s", reasonExpiredState, out)
		}
	})

	t.Run("no identifier: unchanged unknown_state WARN and reused page", func(t *testing.T) {
		buf := captureConnectLog(t)
		srv := newTestConnectServer(t)

		rec := httptest.NewRecorder()
		srv.HandleConnectDone(rec, httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=never-issued", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (reused page)", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "already used") {
			t.Errorf("expected the reused-link page, got: %s", rec.Body.String())
		}
		out := buf.String()
		if !strings.Contains(out, "reason="+reasonUnknownState) {
			t.Errorf("expected a log line with reason=%s, got:\n%s", reasonUnknownState, out)
		}
		if strings.Contains(out, "reason="+reasonRecoveredRedirect) {
			t.Errorf("must not log reason=%s with no Identifier, got:\n%s", reasonRecoveredRedirect, out)
		}
	})
}

// TestHandleConnectDone_ReusedState_NoIdentity_ShowsReusedPage confirms that
// a replay of a consumed state with no Identifier (or one that reports no
// identity) shows the "link already used" page at 200, carrying the CSP
// header and a link back to /telegram/connect.
func TestHandleConnectDone_ReusedState_NoIdentity_ShowsReusedPage(t *testing.T) {
	srv := newTestConnectServer(t)

	state := "reused-state-no-identity"
	srv.mu.Lock()
	srv.sessions[state] = &connectSession{verifier: strings.Repeat("a", 43), createdAt: time.Now()}
	srv.mu.Unlock()
	url := "/telegram/connect/done?code=abc&state=" + state

	firstRec := httptest.NewRecorder()
	srv.HandleConnectDone(firstRec, httptest.NewRequest("GET", url, nil))
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first call: status = %d, body=%s", firstRec.Code, firstRec.Body.String())
	}

	replayRec := httptest.NewRecorder()
	srv.HandleConnectDone(replayRec, httptest.NewRequest("GET", url, nil))
	if replayRec.Code != http.StatusOK {
		t.Fatalf("replay status = %d, want 200", replayRec.Code)
	}
	body := replayRec.Body.String()
	if !strings.Contains(body, "already used") {
		t.Errorf("reused page missing 'already used' copy: %s", body)
	}
	if replayRec.Header().Get("Content-Security-Policy") == "" {
		t.Error("reused page missing Content-Security-Policy header")
	}
	if !strings.Contains(body, `href="`+testConnectIssuer+`/telegram/connect"`) {
		t.Errorf("reused page missing link back to /telegram/connect: %s", body)
	}
}

// TestHandleConnectDone_ReusedState_IdentifierError_FailsClosed pins the
// fail-closed contract of alreadyConnected: when the Identifier rejects the
// presented credential (expired or revoked token, DB or revocation-cache
// failure), a reused link shows the "already used" page rather than
// redirecting, and the rejection is logged so the missing redirect is
// attributable.
func TestHandleConnectDone_ReusedState_IdentifierError_FailsClosed(t *testing.T) {
	buf := captureConnectLog(t)
	srv := newTestConnectServer(t, func(cfg *ConnectConfig) {
		cfg.Identifier = &stubIdentifier{err: errors.New("revocation cache unavailable")}
	})

	rec := httptest.NewRecorder()
	srv.HandleConnectDone(rec, httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=never-issued", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (reused page, no redirect)", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("unexpected redirect to %q on an identifier error", loc)
	}
	if !strings.Contains(rec.Body.String(), "already used") {
		t.Errorf("expected the reused-link page, got: %s", rec.Body.String())
	}
	out := buf.String()
	if !strings.Contains(out, "session credential rejected") || !strings.Contains(out, "revocation cache unavailable") {
		t.Errorf("expected a WARN line naming the identifier error, got:\n%s", out)
	}
}

// TestHandleConnectDone_LogsOneWarnPerBranch confirms each 4xx-equivalent
// branch of HandleConnectDone emits exactly one log line carrying the
// expected reason, and that no line names the state or code value.
func TestHandleConnectDone_LogsOneWarnPerBranch(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(srv *ConnectServer) string // returns the request path+query
		reason string
	}{
		{
			name:   "missing_state",
			setup:  func(_ *ConnectServer) string { return "/telegram/connect/done?code=abc" },
			reason: reasonMissingState,
		},
		{
			// A state without a code must not be reported as a missing state.
			name:   "missing_code",
			setup:  func(_ *ConnectServer) string { return "/telegram/connect/done?state=some-state" },
			reason: reasonMissingCode,
		},
		{
			name:   "unknown_state",
			setup:  func(_ *ConnectServer) string { return "/telegram/connect/done?code=abc&state=never-issued" },
			reason: reasonUnknownState,
		},
		{
			name: "expired_state",
			setup: func(srv *ConnectServer) string {
				state := "log-branch-expired-state"
				srv.mu.Lock()
				srv.sessions[state] = &connectSession{verifier: strings.Repeat("a", 43), createdAt: time.Now().Add(-1 * time.Hour)}
				srv.mu.Unlock()
				return "/telegram/connect/done?code=abc&state=" + state
			},
			reason: reasonExpiredState,
		},
		{
			name: "exchange_failed",
			setup: func(srv *ConnectServer) string {
				state := "log-branch-exchange-failed-state"
				srv.mu.Lock()
				srv.sessions[state] = &connectSession{verifier: strings.Repeat("a", 43), createdAt: time.Now()}
				srv.mu.Unlock()
				return "/telegram/connect/done?code=abc&state=" + state
			},
			reason: reasonExchangeFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureConnectLog(t)
			srv := newTestConnectServer(t, func(cfg *ConnectConfig) {
				if tc.name == "exchange_failed" {
					cfg.OAuthServer = &stubExchanger{err: errors.New("invalid_grant")}
				}
			})
			path := tc.setup(srv)
			rec := httptest.NewRecorder()
			srv.HandleConnectDone(rec, httptest.NewRequest("GET", path, nil))

			out := strings.TrimRight(buf.String(), "\n")
			if out == "" {
				t.Fatalf("expected exactly one log line, got none")
			}
			lines := strings.Split(out, "\n")
			if len(lines) != 1 {
				t.Fatalf("expected exactly one log line, got %d:\n%s", len(lines), out)
			}
			if !strings.Contains(lines[0], "reason="+tc.reason) {
				t.Errorf("log line = %q, want reason=%s", lines[0], tc.reason)
			}
			if strings.Contains(lines[0], "state=") || strings.Contains(lines[0], "code=") || strings.Contains(lines[0], "cookie") {
				t.Errorf("log line leaked state/code/cookie: %s", lines[0])
			}
			// Schema-stability: the prefetch attribute is retained on every
			// reject line (always false here, since a real prefetch never
			// reaches this far), so one prefetch= query matches every line
			// this route emits.
			if !strings.Contains(lines[0], "prefetch=false") {
				t.Errorf("log line = %q, want prefetch=false", lines[0])
			}
		})
	}
}

// TestHandleConnectDone_PrefetchDoesNotConsumeState confirms that a
// Sec-Purpose: prefetch (and legacy Purpose: prefetch) request gets 204 and
// leaves the pending state usable by the subsequent real request.
func TestHandleConnectDone_PrefetchDoesNotConsumeState(t *testing.T) {
	srv := newTestConnectServer(t)
	state := "prefetch-state"
	srv.mu.Lock()
	srv.sessions[state] = &connectSession{verifier: strings.Repeat("a", 43), createdAt: time.Now()}
	srv.mu.Unlock()
	url := "/telegram/connect/done?code=abc&state=" + state

	req1 := httptest.NewRequest("GET", url, nil)
	req1.Header.Set("Sec-Purpose", "prefetch;prerender")
	rec1 := httptest.NewRecorder()
	srv.HandleConnectDone(rec1, req1)
	if rec1.Code != http.StatusNoContent {
		t.Fatalf("Sec-Purpose prefetch: status = %d, want 204", rec1.Code)
	}
	if got := rec1.Header().Values("Vary"); len(got) != 1 || got[0] != "Sec-Purpose, Purpose" {
		t.Errorf("Sec-Purpose prefetch: Vary = %v, want exactly one \"Sec-Purpose, Purpose\"", got)
	}

	req2 := httptest.NewRequest("GET", url, nil)
	req2.Header.Set("Purpose", "prefetch")
	rec2 := httptest.NewRecorder()
	srv.HandleConnectDone(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("Purpose prefetch: status = %d, want 204", rec2.Code)
	}
	if got := rec2.Header().Values("Vary"); len(got) != 1 || got[0] != "Sec-Purpose, Purpose" {
		t.Errorf("Purpose prefetch: Vary = %v, want exactly one \"Sec-Purpose, Purpose\"", got)
	}

	srv.mu.Lock()
	_, ok := srv.sessions[state]
	srv.mu.Unlock()
	if !ok {
		t.Fatal("prefetch requests consumed the pending state")
	}

	rec3 := httptest.NewRecorder()
	srv.HandleConnectDone(rec3, httptest.NewRequest("GET", url, nil))
	if rec3.Code != http.StatusOK {
		t.Fatalf("real request after prefetch: status = %d, body=%s", rec3.Code, rec3.Body.String())
	}
	if !strings.Contains(rec3.Body.String(), "connected") {
		t.Errorf("real request should render the success page: %s", rec3.Body.String())
	}
}

// TestHandleConnectDone_OIDCError confirms that /telegram/connect/done with
// an error query parameter renders the error page (not a 500).
func TestHandleConnectDone_OIDCError(t *testing.T) {
	srv := newTestConnectServer(t)
	req := httptest.NewRequest("GET", "/telegram/connect/done?error=access_denied", nil)
	rec := httptest.NewRecorder()
	srv.HandleConnectDone(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("OIDC error: status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "sign-in was not completed") &&
		!strings.Contains(rec.Body.String(), "failed") &&
		!strings.Contains(rec.Body.String(), "Connection failed") {
		t.Errorf("error page body missing expected message: %s", rec.Body.String())
	}
}

// TestHandleConnectDone_ExchangeError confirms that a failure from
// ExchangeConnect renders the error page (not a 500 or success page).
func TestHandleConnectDone_ExchangeError(t *testing.T) {
	srv := newTestConnectServer(t, func(cfg *ConnectConfig) {
		cfg.OAuthServer = &stubExchanger{err: errors.New("invalid_grant: code expired")}
	})

	// Set up a valid pending session manually.
	state := "test-state-value"
	srv.mu.Lock()
	srv.sessions[state] = &connectSession{
		verifier:  strings.Repeat("a", 43),
		createdAt: time.Now(),
	}
	srv.mu.Unlock()

	req := httptest.NewRequest("GET", "/telegram/connect/done?code=some-code&state="+state, nil)
	rec := httptest.NewRecorder()
	srv.HandleConnectDone(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("exchange error: status = %d, want 400", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "connected") {
		t.Error("exchange error should not render success page")
	}
}

// TestHandleConnectDone_Success confirms that a valid state + successful
// ExchangeConnect call renders the success page.
func TestHandleConnectDone_Success(t *testing.T) {
	srv := newTestConnectServer(t)

	state := "valid-state"
	srv.mu.Lock()
	srv.sessions[state] = &connectSession{
		verifier:  strings.Repeat("a", 43),
		createdAt: time.Now(),
	}
	srv.mu.Unlock()

	req := httptest.NewRequest("GET", "/telegram/connect/done?code=valid-code&state="+state, nil)
	rec := httptest.NewRecorder()
	srv.HandleConnectDone(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("success: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "connected") {
		t.Errorf("success page body missing 'connected': %s", rec.Body.String())
	}

	// The session must be consumed on success.
	srv.mu.Lock()
	_, ok := srv.sessions[state]
	srv.mu.Unlock()
	if ok {
		t.Error("session was not deleted after successful exchange")
	}
}

// TestHandleConnectDone_SessionConsumedOnError confirms that even when
// ExchangeConnect fails the session is deleted (no replay possible).
func TestHandleConnectDone_SessionConsumedOnError(t *testing.T) {
	srv := newTestConnectServer(t, func(cfg *ConnectConfig) {
		cfg.OAuthServer = &stubExchanger{err: errors.New("invalid_grant")}
	})

	state := "one-shot-state"
	srv.mu.Lock()
	srv.sessions[state] = &connectSession{
		verifier:  strings.Repeat("b", 43),
		createdAt: time.Now(),
	}
	srv.mu.Unlock()

	req := httptest.NewRequest("GET", "/telegram/connect/done?code=x&state="+state, nil)
	rec := httptest.NewRecorder()
	srv.HandleConnectDone(rec, req)

	srv.mu.Lock()
	_, ok := srv.sessions[state]
	srv.mu.Unlock()
	if ok {
		t.Error("session should be deleted even when ExchangeConnect fails")
	}
}
