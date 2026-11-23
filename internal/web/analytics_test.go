package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

// Every public content page carries the self-hosted Umami tracker exactly
// once. These pages send no Content-Security-Policy today; should one ever be
// added, it must allow stats.mctl.ai or the tracker silently stops counting.
func TestPublicPagesLoadUmami(t *testing.T) {
	const base = "https://tg.mctl.ai"
	pages := map[string]struct {
		h    http.HandlerFunc
		path string
	}{
		"landing":         {Landing(base, "/mcp", base, true), "/"},
		"docs":            {Docs(base, "/mcp", base, true, false), "/docs"},
		"demo":            {Demo(base, "", true), "/demo"},
		"security":        {Security(base, true), "/security"},
		"privacy":         {Privacy(base, true), "/privacy"},
		"terms":           {Terms(base, true), "/terms"},
		"platforms":       {Platforms(base, "/mcp", base, true, testPlatformFacts()), "/platforms"},
		"local-bridge":    {LocalBridge(base, true), "/docs/local-bridge"},
		"product-updates": {ProductUpdates(nil, nil, base, true), "/docs/product-updates"},
	}
	for name, p := range pages {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			p.h(rec, httptest.NewRequest(http.MethodGet, p.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			body := rec.Body.String()
			// The app name is MCTL (Telegram API ToS §2.3), in the title and
			// in the description that feeds the meta, og and twitter tags.
			if !strings.Contains(body, "<title>MCTL — ") {
				t.Errorf("title must start with \"MCTL — \"")
			}
			for _, bad := range []string{"mctl-telegram —", "MCTL Telegram", `content="mctl-telegram`, `for mctl-telegram`, `How mctl-telegram`, `What mctl-telegram`, `to mctl-telegram:`} {
				if strings.Contains(body, bad) {
					t.Errorf("page still carries the old app name %q", bad)
				}
			}
			if n := strings.Count(body, ui.AnalyticsScript); n != 1 {
				t.Fatalf("want the Umami tag exactly once, found %d", n)
			}
			if csp := rec.Header().Get("Content-Security-Policy"); csp != "" {
				for _, dir := range []string{"script-src", "connect-src"} {
					if !directiveAllows(csp, dir, "https://stats.mctl.ai") {
						t.Errorf("CSP %s does not allow https://stats.mctl.ai: %q", dir, csp)
					}
				}
			}
		})
	}
}

// Pages that show connect state, tokens or account data use the lite chrome
// under a strict CSP and must never load the tracker.
func TestStrictCSPPagesDoNotLoadUmami(t *testing.T) {
	cases := map[string]func(http.ResponseWriter){
		"connect-error": func(w http.ResponseWriter) {
			renderConnect(w, http.StatusBadRequest, connectErrorTemplate, connectErrorData{Message: "x"})
		},
		"manage-error": func(w http.ResponseWriter) { renderManageError(w, "x") },
	}
	for name, render := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			render(rec)
			if strings.Contains(rec.Body.String(), "stats.mctl.ai") {
				t.Fatal("strict-CSP page loads the analytics tracker")
			}
			if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "stats.mctl.ai") {
				t.Fatalf("strict CSP was widened for analytics: %q", csp)
			}
		})
	}
}

func directiveAllows(csp, directive, source string) bool {
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) > 0 && f[0] == directive {
			for _, s := range f[1:] {
				if s == source {
					return true
				}
			}
		}
	}
	return false
}

// TestLandingPartnerCard: the hosted-agent card appears only when a valid
// AgentsPodium partner link is configured, carries campaign tags, is marked
// sponsored, is counted by an Umami event, and discloses the partner link.
func TestLandingPartnerCard(t *testing.T) {
	const base = "https://tg.mctl.ai"
	render := func(opts ...LandingOption) string {
		rec := httptest.NewRecorder()
		Landing(base, "/mcp", base, true, opts...)(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		return rec.Body.String()
	}
	if body := render(); strings.Contains(body, "hosted-agent") || strings.Contains(body, "agentspodium.com/?") {
		t.Fatal("the card is rendered without a partner link configured")
	}
	for _, bad := range []string{"https://evil.example/?ref=x", "http://agentspodium.com/?ref=x", "https://agentspodium.com.evil.example/?ref=x", "not a url", ""} {
		if body := render(WithPartnerLink(bad)); strings.Contains(body, "hosted-agent") {
			t.Fatalf("the card is rendered for the invalid link %q", bad)
		}
	}
	body := render(WithPartnerLink("https://agentspodium.com/?ref=TESTREF"))
	for _, want := range []string{
		`id="hosted-agent"`, "ref=TESTREF", "utm_source=mctl", "utm_medium=referral", "utm_campaign=hermes-integration",
		`rel="sponsored noopener"`, `data-umami-event="agentspodium-partner-click"`, "Partner link:",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the partner card lacks %q", want)
		}
	}
	// A tag already set on the link wins over the default.
	if body := render(WithPartnerLink("https://agentspodium.com/?ref=TESTREF&utm_source=custom")); !strings.Contains(body, "utm_source=custom") || strings.Contains(body, "utm_source=mctl") {
		t.Error("an explicit utm_source was overwritten")
	}
}
