package web

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/ui"
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
		"<code>discovery</code>", `<span class="badge pill-write">approve</span>`,
		`<span class="badge pill-read">auto</span>`, `<span class="badge ok">published</span>`,
		`<ul class="chat-examples">`,
		"<code>observe</code>", "6 autonomous turns, 2 messages per minute, 1,200 characters per reply",
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

// The header and footer link to /assistants only where the server mounted
// it (AGENT_ENABLED): a link on a deployment without the page is a 404 in
// the main nav. With it mounted, the catalog page marks its own link active.
func TestAssistantsNavLinkFollowsMount(t *testing.T) {
	const active = `<a href="/assistants" class="active">Assistants</a>`
	const footer = `<a href="/assistants">Assistants</a>`
	f := newManageAssistantFixture(t, nil)
	render := func() string {
		return getAssistantsPage(t, Assistants(f.svc, "https://tg.test", true)).Body.String()
	}
	t.Cleanup(func() { ui.SetAssistantsMounted(false) })

	ui.SetAssistantsMounted(false)
	if body := render(); strings.Contains(body, `href="/assistants"`) {
		t.Fatal("nav links to /assistants although it is not mounted")
	}

	ui.SetAssistantsMounted(true)
	body := render()
	for _, want := range []string{active, footer} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	rec := httptest.NewRecorder()
	Platforms("https://tg.test", "/mcp", "https://tg.test", true, testPlatformFacts()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/platforms", nil))
	if b := rec.Body.String(); !strings.Contains(b, `<a href="/assistants">Assistants</a>`) || strings.Contains(b, active) {
		t.Error("/platforms must link to /assistants without marking it active")
	}
}

// The catalog holds more than one version of an assistant: the newest is
// the card, every older version stays on the page inside that card as its
// own collapsed block, newest first, and none hides another (#1022).
func TestAssistantsPage_ListsEveryVersion(t *testing.T) {
	f := newManageAssistantFixture(t, nil)
	body := getAssistantsPage(t, Assistants(f.svc, "https://tg.test", true)).Body.String()
	newer, older := strings.Index(body, "hr-recruiter@0.1.1"), strings.Index(body, "hr-recruiter@0.1.0")
	if newer < 0 || older < 0 || newer > older {
		t.Fatalf("versions on the page: 0.1.1 at %d, 0.1.0 at %d; want both, newest first", newer, older)
	}
	if !strings.Contains(body[newer:older], "<code>compensation</code>") || strings.Contains(body[older:], "<code>compensation</code>") {
		t.Fatal("the compensation intent is not shown under 0.1.1 alone")
	}
	// One card per name: the newest version is the card, the older one is a
	// collapsed block inside it, reachable by its own id.
	if n := strings.Count(body, `class="card assistant-card"`); n != 1 {
		t.Fatalf("want one card for hr-recruiter, got %d", n)
	}
	for _, want := range []string{
		`<article class="card assistant-card" id="hr-recruiter-0.1.1">`,
		`Other versions: <a href="#hr-recruiter-0.1.0">0.1.0</a>`,
		`<details class="assistant-details assistant-older" id="hr-recruiter-0.1.0">`,
		`<span class="tier-auto">auto</span>: discovery, schedule · <span class="tier-approve">approve</span>: decline, share_details, compensation`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Nothing is pre-expanded: the full tables and older versions open on a
	// click, without script.
	if strings.Contains(body, "<details open") {
		t.Error("a details block rendered open")
	}
	assertNoAssistantLeak(t, body)
}

func TestGroupAssistants(t *testing.T) {
	views := []assistantView{
		{Name: "bot-a", Version: "1.2.0"},
		{Name: "bot-a", Version: "1.1.0"},
		{Name: "bot-a", Version: "1.0.0"},
		{Name: "bot-b", Version: "0.1.0"},
	}
	groups := groupAssistants(views)
	if len(groups) != 2 {
		t.Fatalf("want 2 groups, got %d: %+v", len(groups), groups)
	}
	a, b := groups[0], groups[1]
	if a.Latest.Version != "1.2.0" || len(a.Older) != 2 || a.Older[0].Version != "1.1.0" || a.Older[1].Version != "1.0.0" {
		t.Errorf("bot-a grouped as %+v", a)
	}
	if b.Latest.Name != "bot-b" || b.Latest.Version != "0.1.0" || len(b.Older) != 0 {
		t.Errorf("bot-b grouped as %+v", b)
	}
	// Every input version is in exactly one group.
	total := 0
	for _, g := range groups {
		total += 1 + len(g.Older)
	}
	if total != len(views) {
		t.Errorf("%d views in, %d out", len(views), total)
	}
	if groupAssistants(nil) != nil {
		t.Error("no views must group to nil")
	}
}

func TestTierSummary(t *testing.T) {
	in := func(name, tier string) assistantinstall.CatalogIntent {
		return assistantinstall.CatalogIntent{Name: name, Tier: tier}
	}
	got := tierSummary([]assistantinstall.CatalogIntent{
		in("decline", "approve"), in("discovery", "auto"), in("pay", "never"),
		in("schedule", "auto"), in("odd", "custom"), in("share_details", "approve"),
	})
	want := []tierLine{
		{"auto", "discovery, schedule"}, {"approve", "decline, share_details"},
		{"never", "pay"}, {"custom", "odd"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tierSummary = %+v, want %+v", got, want)
	}
	// Empty tiers are left out; no intents is nil.
	if got := tierSummary([]assistantinstall.CatalogIntent{in("x", "never")}); !reflect.DeepEqual(got, []tierLine{{"never", "x"}}) {
		t.Errorf("single never tier = %+v", got)
	}
	if got := tierSummary(nil); got != nil {
		t.Errorf("no intents = %+v, want nil", got)
	}
}

func TestGroupThousands(t *testing.T) {
	for n, want := range map[int]string{0: "0", 2: "2", 999: "999", 1200: "1,200", 4096: "4,096", 1234567: "1,234,567", -1200: "-1,200"} {
		if got := groupThousands(n); got != want {
			t.Errorf("groupThousands(%d) = %q, want %q", n, got, want)
		}
	}
}
