package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func newTestConnectServer(t *testing.T, opts ...func(*ConnectConfig)) *ConnectServer {
	t.Helper()
	cfg := ConnectConfig{
		Issuer:               testConnectIssuer,
		OAuthServer:          &stubExchanger{},
		CodeTTL:              10 * time.Minute,
		ClaudeAIConnectorURL: "https://claude.ai/settings/integrations",
	}
	for _, o := range opts {
		o(&cfg)
	}
	return NewConnectServer(cfg)
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
}

// TestHandleConnectDone_UnknownState confirms that /telegram/connect/done
// with an unknown state renders the error page with HTTP 400.
func TestHandleConnectDone_UnknownState(t *testing.T) {
	srv := newTestConnectServer(t)
	req := httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=bogus", nil)
	rec := httptest.NewRecorder()
	srv.HandleConnectDone(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown state: status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "expired") && !strings.Contains(rec.Body.String(), "unknown") {
		t.Errorf("error page body should mention expiry/unknown: %s", rec.Body.String())
	}
}

// TestHandleConnectDone_ExpiredSession confirms that a session past CodeTTL
// is swept on the next HandleConnect call and that HandleConnectDone then
// renders the error page.
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

	// HandleConnectDone with the swept state should return 400.
	req3 := httptest.NewRequest("GET", "/telegram/connect/done?code=x&state="+state, nil)
	rec3 := httptest.NewRecorder()
	srv.HandleConnectDone(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Errorf("expired session done: status = %d, want 400", rec3.Code)
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
