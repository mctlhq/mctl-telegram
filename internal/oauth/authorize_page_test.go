package oauth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBotIDFromToken(t *testing.T) {
	cases := []struct {
		name, token, want string
	}{
		{"valid", "8568443430:AAHxyz-123_abc", "8568443430"},
		{"empty", "", ""},
		{"no colon", "8568443430", ""},
		{"empty id", ":AAHxyz", ""},
		{"non-numeric id", "bot123:AAHxyz", ""},
		{"id with letters", "12ab34:AAHxyz", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := botIDFromToken(c.token); got != c.want {
				t.Fatalf("botIDFromToken(%q) = %q, want %q", c.token, got, c.want)
			}
		})
	}
}

func TestRenderAuthorizeSwitchControl(t *testing.T) {
	const logoutPrefix = "https://oauth.telegram.org/auth/logOut?bot_id="

	t.Run("present when BotID set", func(t *testing.T) {
		rec := httptest.NewRecorder()
		renderAuthorizeHTML(rec, authorizePage{
			Issuer:       "https://tg.mctl.ai",
			BotUsername:  "MCTL_AI_bot",
			ServerState:  "st",
			RedirectHost: "claude.ai",
			BotID:        "8568443430",
		})
		if body := rec.Body.String(); !strings.Contains(body, logoutPrefix+"8568443430") {
			t.Fatalf("rendered page missing switch-account logout link:\n%s", body)
		}
	})

	t.Run("absent when BotID empty", func(t *testing.T) {
		rec := httptest.NewRecorder()
		renderAuthorizeHTML(rec, authorizePage{
			Issuer:      "https://tg.mctl.ai",
			BotUsername: "MCTL_AI_bot",
			ServerState: "st",
		})
		if strings.Contains(rec.Body.String(), logoutPrefix) {
			t.Fatal("switch-account link rendered despite empty BotID")
		}
	})
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
