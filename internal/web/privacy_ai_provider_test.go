package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivacyNamesTheAIProvider(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()
	if !strings.Contains(body, "<strong>Anthropic</strong> (AI model)") {
		t.Error("privacy page must name the AI model provider")
	}
	if strings.Contains(body, "The AI model provider behind Communication Agent") {
		t.Error("privacy page still leaves the provider unnamed")
	}
}

// TestPrivacyNamesThePARecipients: the personal assistant's consent text
// (pa-data-flow/v1) points at /privacy, so the page lists the same
// recipients it names: Nebius, reached through Cloudflare AI Gateway.
func TestPrivacyNamesThePARecipients(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()
	for _, must := range []string{"<strong>Nebius</strong>", "Cloudflare AI Gateway", "pa-data-flow/v1", "24 hours"} {
		if !strings.Contains(body, must) {
			t.Errorf("privacy page lacks %q in the personal assistant entry", must)
		}
	}
}
