package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getAssistantsPage(t *testing.T, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/assistants", nil))
	return rec
}

func TestAssistantsPage_EmbeddedCatalogWithoutInstructions(t *testing.T) {
	f := newManageAssistantFixture(t, nil)
	// An install with every marker stored must not reach the public page.
	f.installDirect()
	rec := getAssistantsPage(t, Assistants(f.svc, "https://tg.test", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"hr-recruiter@0.1.0", "Recruiter assistant", "recruiting",
		"Senior Go role at Acme", // an example
		"<code>salary_floor</code>", "<code>work_mode</code>", "remote, hybrid, office",
		"<code>discovery</code>", "<td>approve</td>",
		"<code>observe</code>", "6 autonomous turns, 2 messages a minute, 1200 characters a reply",
		"added unless you turn it off",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "Catalog unavailable") {
		t.Error("a readable catalog shows the unavailable state")
	}
	assertNoAssistantLeak(t, body)
}

func TestAssistantsPage_RegistryCatalogAndFailure(t *testing.T) {
	reg := newFakeWebRegistry(t)
	f := newManageAssistantFixture(t, reg.client())
	h := Assistants(f.svc, "https://tg.test", true)

	rec := getAssistantsPage(t, h)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "registry-only@2.0.0") ||
		!strings.Contains(body, "Hello from a recruiter") || !strings.Contains(body, "Default: Acme.") ||
		!strings.Contains(body, "always added") {
		t.Fatalf("status %d; registry entry not rendered: %s", rec.Code, body)
	}
	// The embedded catalog is not mixed in when the registry is the source.
	if strings.Contains(body, "hr-recruiter@0.1.0") {
		t.Error("registry page lists an embedded entry")
	}
	// The registry gives no default for the variable without one; the page
	// invents none.
	if strings.Count(body, "Default:") != 1 {
		t.Errorf("want exactly one default rendered, got %d", strings.Count(body, "Default:"))
	}

	// A registry that cannot be read is an explicit error state with an
	// error status, never an empty catalog.
	reg.setDown(true)
	rec = getAssistantsPage(t, h)
	body = rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	if !strings.Contains(body, `id="catalog-unavailable"`) || strings.Contains(body, `id="catalog-empty"`) ||
		strings.Contains(body, "registry-only") {
		t.Fatalf("unavailable catalog not stated explicitly: %s", body)
	}
}
