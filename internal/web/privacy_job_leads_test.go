package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivacyDescribesJobLeadProtection(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()
	for _, want := range []string{"90 days after the lead was last updated", "AGENT_LEAD_RETENTION_DAYS", "Encrypted with your per-user key, except the status"} {
		if !strings.Contains(body, want) {
			t.Errorf("privacy page is missing %q", want)
		}
	}
	if strings.Contains(body, "These fields are not encrypted") {
		t.Error("privacy page still says job leads are not encrypted")
	}
}
