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
		"docs":            {Docs(base, "/mcp", base, true), "/docs"},
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
