package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIAppsChallenge_ServesTokenAsPlainText(t *testing.T) {
	w := httptest.NewRecorder()
	OpenAIAppsChallenge().ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/openai-apps-challenge", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("expected text/plain, got %q", ct)
	}
	if got := w.Body.String(); got != openAIAppsChallengeToken {
		t.Fatalf("body = %q, want exactly the token %q", got, openAIAppsChallengeToken)
	}
}
