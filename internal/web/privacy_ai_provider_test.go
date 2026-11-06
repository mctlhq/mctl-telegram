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
