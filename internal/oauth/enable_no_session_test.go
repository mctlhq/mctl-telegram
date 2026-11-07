package oauth

import (
	"context"
	"net/http"
	"strings"
	"testing"

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
