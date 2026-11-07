package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestEnableAccess_NoScopesGetsNextStepPage pins #1127 at the callback: a
// sign-in that receives no telegram:* scope still gets its authorization
// code, but on a page that says Telegram is not connected and names the
// next step, instead of the "Telegram connected" interstitial that made the
// MCP client report success over a token every Telegram tool refuses.
func TestEnableAccess_NoScopesGetsNextStepPage(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	rec := telegramCallbackFor(t, srv, mux, 999000111) // in no allowlist
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 page; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"not connected yet",
		"set_telegram_access",
		"sign in again",
		"Reconnect",
		testIssuer + "/telegram/connect/manage",
		"Continue to",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("no-session page lacks %q", want)
		}
	}
	if strings.Contains(body, "Telegram connected") {
		t.Errorf("no-session page still claims the account is connected")
	}
	if strings.Contains(body, "<script") {
		t.Errorf("no-session page must not auto-redirect: the user has to read it")
	}
	// The code is still issued: the client flow completes on the
	// self-service tools, and get_my_send_status repeats the next step.
	if loc := authCodeRedirect(t, rec); loc.Query().Get("code") == "" {
		t.Fatalf("no-session page carries no authorization code: %s", loc)
	}
	srv.mu.Lock()
	numEnables := len(srv.enables)
	srv.mu.Unlock()
	if numEnables != 0 {
		t.Errorf("no-session callback created %d pending enableSession(s), want 0", numEnables)
	}
}

// A lookup-admin identity has a tier, just not one that reads Telegram, so
// its page must not send it to the operator for an access grant.
func TestEnableAccess_LookupAdminOnlyGetsLookupPage(t *testing.T) {
	lookupID := int64(888000333)
	srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
		c.LookupAdminTelegramIDs = map[int64]bool{lookupID: true}
	})
	rec := telegramCallbackFor(t, srv, mux, lookupID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 page; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "admin lookup access only") {
		t.Errorf("lookup-admin page does not explain the lookup tier")
	}
	if strings.Contains(body, "set_telegram_access") {
		t.Errorf("lookup-admin page sends a tiered identity to the operator for a grant")
	}
	if loc := authCodeRedirect(t, rec); loc.Query().Get("code") == "" {
		t.Fatalf("lookup-admin page carries no authorization code: %s", loc)
	}
}

// After the operator grants the client tier, the next sign-in from the
// client must land on the phone/QR step (the connect flow the page promised),
// not on the no-session page again. This is why the page can tell the user
// to sign in again instead of carrying a return token.
func TestEnableAccess_SignInAfterGrantReachesPhoneStep(t *testing.T) {
	tgID := int64(999000112)
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	first := telegramCallbackFor(t, srv, mux, tgID)
	if !strings.Contains(first.Body.String(), "not connected yet") {
		t.Fatalf("precondition: first sign-in did not get the no-session page: %s", first.Body.String())
	}
	if err := srv.store.SetAccessTier(context.Background(), tgID, db.TierClient); err != nil {
		t.Fatalf("set tier client: %v", err)
	}
	second := telegramCallbackFor(t, srv, mux, tgID)
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "/oauth/telegram/enable_access/start") {
		t.Fatalf("second sign-in after the grant did not reach the phone step: status %d body=%s", second.Code, second.Body.String())
	}
}

// The browser's own /telegram/connect flow (client ConnectClientID, same-host
// redirect) keeps its 302 to /telegram/connect/done on the no-scope path,
// as issueAuthCode does: the no-session page talks about a connector to
// remove and an app to return to, which that flow has neither of.
func TestEnableAccess_NoScopesSameHostKeeps302(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	authFake(srv).identity = &telegramoidc.Identity{TelegramID: 999000113, Username: "user", FirstName: "User"}
	_, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {ConnectClientID},
		"redirect_uri":          {testIssuer + "/telegram/connect/done"},
		"state":                 {"wizard-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d body=%s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize redirect parse: %v", err)
	}
	cb := callbackViaChi(t, mux, loc.Query().Get("state"))
	if cb.Code != http.StatusFound {
		t.Fatalf("same-host no-scope callback: status %d, want 302; body=%s", cb.Code, cb.Body.String())
	}
	done, err := url.Parse(cb.Header().Get("Location"))
	if err != nil {
		t.Fatalf("callback redirect parse: %v", err)
	}
	if done.Path != "/telegram/connect/done" || done.Query().Get("code") == "" || done.Query().Get("state") != "wizard-state" {
		t.Errorf("same-host no-scope callback redirected to %s, want /telegram/connect/done with code and state", done)
	}
}
