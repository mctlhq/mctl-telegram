package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivacySignUpAttributionMatchesTheNoCookieFlow(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()
	for _, must := range []string{"How did you hear about us?", "sets no cookie for this", "is no longer set"} {
		if !strings.Contains(body, must) {
			t.Errorf("privacy page missing %q", must)
		}
	}
	if strings.Contains(body, "sets one first-party cookie") {
		t.Error("privacy page still says a cookie is set")
	}
}
