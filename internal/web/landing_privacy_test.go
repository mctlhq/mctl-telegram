package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLandingPrivacyClaimsAlignWithAgentStorage(t *testing.T) {
	w := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).
		ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()

	for _, stale := range []string{
		"No message text, phone numbers, or 2FA passwords are ever logged or persisted",
		"Only an encrypted session blob per account. No message text is ever stored or logged.",
		"This server stores only an encrypted session blob and audit metadata",
		"<strong>Not stored:</strong> message bodies",
	} {
		if strings.Contains(body, stale) {
			t.Fatalf("landing contains stale storage claim %q", stale)
		}
	}

	for _, must := range []string{
		"When Communication Agent is enabled",
		"encrypted at rest",
		"Not stored in logs or audit history",
		"Listener-enabled Communication Agent accounts",
		"retention details",
		`href="/privacy"`,
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("landing missing agent storage disclosure %q", must)
		}
	}
}

func TestPrivacyNamesTheOperatorInContact(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()

	contact := strings.Index(body, "<h2>Contact</h2>")
	if contact < 0 {
		t.Fatal("privacy page has no Contact section")
	}
	section := body[contact:]
	for _, must := range []string{"operated by Dmitrii Mashkov", "mailto:privacy@mctl.ai"} {
		if !strings.Contains(section, must) {
			t.Fatalf("Contact section missing %q", must)
		}
	}
}
