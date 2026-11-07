package web

import (
	"encoding/json"
	"html"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExamples_ToolsExistAndSendFlagMatches keeps the curated list honest:
// every tool a prompt names must be a published tool, and a prompt is marked
// "needs sending on" exactly when one of its tools is not read-only. The
// list itself is written by hand (owner decision on #1156); only its claims
// about tools are checked against docs/tool-descriptors.json.
func TestExamples_ToolsExistAndSendFlagMatches(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "tool-descriptors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tools map[string]struct {
			Annotations struct {
				ReadOnlyHint *bool `json:"readOnlyHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Tools) == 0 {
		t.Fatal("tool-descriptors.json lists no tools; a failed read must not pass this check")
	}
	seen := map[string]bool{}
	for _, c := range exampleCategories {
		if c.ID == "" || c.Title == "" || len(c.Prompts) != 2 {
			t.Errorf("category %q: want an id, a title and exactly 2 prompts, got %d", c.ID, len(c.Prompts))
		}
		if seen[c.ID] {
			t.Errorf("category id %q repeats; the anchors would collide", c.ID)
		}
		seen[c.ID] = true
		for _, p := range c.Prompts {
			if strings.TrimSpace(p.Text) == "" || len(p.Tools) == 0 {
				t.Errorf("%s: a prompt needs text and at least one tool: %+v", c.ID, p)
			}
			writes := false
			for _, tool := range p.Tools {
				d, ok := doc.Tools[tool]
				if !ok {
					t.Errorf("%s: %q names tool %q, which is not published", c.ID, p.Text, tool)
					continue
				}
				if ro := d.Annotations.ReadOnlyHint; ro == nil || !*ro {
					writes = true
				}
			}
			if writes != p.Send {
				t.Errorf("%s: %q has Send=%v, but its tools make it %v", c.ID, p.Text, p.Send, writes)
			}
		}
	}
	if len(exampleCategories) != 6 {
		t.Errorf("categories = %d, want 6", len(exampleCategories))
	}
}

func TestExamples_PageRendersEveryPromptWithItsChip(t *testing.T) {
	rec := httptest.NewRecorder()
	Examples("https://tg.example.test/", false)(rec, httptest.NewRequest("GET", "/examples", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != chromeCSP {
		t.Errorf("CSP = %q, want the shared chrome policy", csp)
	}
	body := html.UnescapeString(rec.Body.String())
	sends := 0
	for _, c := range exampleCategories {
		if !strings.Contains(body, `id="`+c.ID+`"`) {
			t.Errorf("category %q has no anchor", c.ID)
		}
		for _, p := range c.Prompts {
			if !strings.Contains(body, `data-prompt="`+p.Text+`"`) {
				t.Errorf("prompt %q has no copy button carrying its text", p.Text)
			}
			if p.Send {
				sends++
			}
		}
	}
	// One chip per prompt plus the one in the explanation paragraph.
	if got := strings.Count(body, `class="chip chip--send"`); got != sends+1 {
		t.Errorf("send chips = %d, want %d", got, sends+1)
	}
	if !strings.Contains(body, `hidden>Copy</button>`) {
		t.Error("copy buttons must start hidden so the page works without JavaScript")
	}
	if !strings.Contains(body, `href="/examples" class="active"`) {
		t.Error("the Examples nav link is not marked active")
	}
}

func TestExamples_LinkedFromLandingSitemapAndConnectDone(t *testing.T) {
	if !strings.Contains(landingHTML, `href="/examples"`) {
		t.Error("landing does not link /examples")
	}
	rec := httptest.NewRecorder()
	Sitemap("https://tg.example.test")(rec, httptest.NewRequest("GET", "/sitemap.xml", nil))
	if !strings.Contains(rec.Body.String(), "<loc>https://tg.example.test/examples</loc>") {
		t.Error("sitemap does not list /examples")
	}
	var b strings.Builder
	if err := connectSuccessTemplate.Execute(&b, map[string]any{"MCPURL": "https://tg.example.test/mcp"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `href="/examples"`) {
		t.Error("the wizard's Done step does not link /examples")
	}
}
