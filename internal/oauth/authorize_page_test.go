package oauth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The consent screen offers an account-switch help block instead of an
// automated logout: the legacy Telegram Login Widget exposes no logout API,
// and oauth.telegram.org/auth/logOut does not clear the session. The block
// must be present, explain the manual steps, and never link the defunct
// logOut endpoint.
func TestRenderAuthorizeAccountSwitchHelp(t *testing.T) {
	rec := httptest.NewRecorder()
	renderAuthorizeHTML(rec, authorizePage{
		Issuer:       "https://tg.mctl.ai",
		BotUsername:  "MCTL_AI_bot",
		ServerState:  "st",
		RedirectHost: "claude.ai",
	})
	body := rec.Body.String()

	if !strings.Contains(body, "Want to use a different Telegram account?") {
		t.Fatalf("rendered page missing account-switch help block:\n%s", body)
	}
	// Lock down all three manual steps so a reworded option is caught.
	for _, step := range []string{"incognito", "oauth.telegram.org", "Logged in with Telegram"} {
		if !strings.Contains(body, step) {
			t.Fatalf("account-switch help missing manual step %q:\n%s", step, body)
		}
	}
	if strings.Contains(body, "auth/logOut") {
		t.Fatalf("page still renders the broken logOut link:\n%s", body)
	}
}

// The Login Widget must not request bot-DM write access: the grant makes
// Telegram open the shared @MCTL_AI_bot chat for the user, which triggers the
// OpenClaw admins-tenant pairing prompt. The widget only needs identity auth.
func TestRenderAuthorizeNoWriteAccess(t *testing.T) {
	rec := httptest.NewRecorder()
	renderAuthorizeHTML(rec, authorizePage{
		Issuer:      "https://tg.mctl.ai",
		BotUsername: "MCTL_AI_bot",
		ServerState: "st",
	})
	if strings.Contains(rec.Body.String(), "data-request-access") {
		t.Fatal("widget requests data-request-access; identity auth must not request write access")
	}
}
