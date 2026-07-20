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

func TestAlignLandingPrivacyClaimsDoesNotChangeUnrelatedCopy(t *testing.T) {
	const input = `<p>unrelated landing copy</p>`
	if got := alignLandingPrivacyClaims(input); got != input {
		t.Fatalf("unrelated copy changed: got %q", got)
	}
}
