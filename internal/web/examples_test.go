package web

import (
	"encoding/json"
	"errors"
	"fmt"
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
	tools, err := parseExampleDescriptors(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range validateExamples(exampleCategories, tools) {
		t.Error(p)
	}
	if len(exampleCategories) != 6 {
		t.Errorf("categories = %d, want 6", len(exampleCategories))
	}
}

// exampleToolInfo is what the validation needs of one published tool.
type exampleToolInfo struct {
	ReadOnlyHint *bool
}

// parseExampleDescriptors reads docs/tool-descriptors.json bytes. Missing,
// empty or malformed input is an error, never an empty-but-valid tool set.
func parseExampleDescriptors(raw []byte) (map[string]exampleToolInfo, error) {
	var doc struct {
		Tools map[string]struct {
			Annotations struct {
				ReadOnlyHint *bool `json:"readOnlyHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("tool descriptors: %w", err)
	}
	if len(doc.Tools) == 0 {
		return nil, errors.New("tool-descriptors.json lists no tools; a failed read must not pass this check")
	}
	out := make(map[string]exampleToolInfo, len(doc.Tools))
	for name, d := range doc.Tools {
		out[name] = exampleToolInfo{ReadOnlyHint: d.Annotations.ReadOnlyHint}
	}
	return out, nil
}

// validateExamples is the single validation path for the shipped list and for
// the negative fixtures: it returns one message per problem found.
func validateExamples(cats []exampleCategory, tools map[string]exampleToolInfo) []string {
	var problems []string
	seen := map[string]bool{}
	for _, c := range cats {
		if c.ID == "" || c.Title == "" || len(c.Prompts) != 2 {
			problems = append(problems, fmt.Sprintf("category %q: want an id, a title and exactly 2 prompts, got %d", c.ID, len(c.Prompts)))
		}
		if seen[c.ID] {
			problems = append(problems, fmt.Sprintf("category id %q repeats; the anchors would collide", c.ID))
		}
		seen[c.ID] = true
		for _, p := range c.Prompts {
			if strings.TrimSpace(p.Text) == "" || len(p.Tools) == 0 {
				problems = append(problems, fmt.Sprintf("%s: a prompt needs text and at least one tool: %+v", c.ID, p))
			}
			writes := false
			for _, tool := range p.Tools {
				d, ok := tools[tool]
				if !ok {
					problems = append(problems, fmt.Sprintf("%s: %q names tool %q, which is not published", c.ID, p.Text, tool))
					continue
				}
				if d.ReadOnlyHint == nil || !*d.ReadOnlyHint {
					writes = true
				}
			}
			if writes != p.Send {
				problems = append(problems, fmt.Sprintf("%s: %q has Send=%v, but its tools make it %v", c.ID, p.Text, p.Send, writes))
			}
		}
	}
	return problems
}

func TestExamples_ValidationRejectsInvalidFixtures(t *testing.T) {
	yes, no := true, false
	tools := map[string]exampleToolInfo{
		"read_tool":  {ReadOnlyHint: &yes},
		"send_tool":  {ReadOnlyHint: &no},
		"unset_tool": {},
	}
	cat := func(p examplePrompt) []exampleCategory {
		return []exampleCategory{{ID: "c", Title: "C", Prompts: []examplePrompt{p, {Text: "ok", Tools: []string{"read_tool"}}}}}
	}
	if got := validateExamples(cat(examplePrompt{Text: "fine", Tools: []string{"send_tool"}, Send: true}), tools); len(got) != 0 {
		t.Fatalf("valid fixture rejected: %v", got)
	}
	cases := []struct {
		name string
		p    examplePrompt
		want string
	}{
		{"unknown tool", examplePrompt{Text: "x", Tools: []string{"nope"}}, "not published"},
		{"sending tool marked read-only", examplePrompt{Text: "x", Tools: []string{"send_tool"}, Send: false}, "has Send=false"},
		{"read-only tool marked sending", examplePrompt{Text: "x", Tools: []string{"read_tool"}, Send: true}, "has Send=true"},
		{"tool without readOnlyHint counts as sending", examplePrompt{Text: "x", Tools: []string{"unset_tool"}, Send: false}, "has Send=false"},
		{"empty text", examplePrompt{Text: "  ", Tools: []string{"read_tool"}}, "needs text"},
		{"no tools", examplePrompt{Text: "x"}, "at least one tool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateExamples(cat(tc.p), tools)
			if len(got) == 0 {
				t.Fatal("invalid fixture passed validation")
			}
			if !strings.Contains(strings.Join(got, "\n"), tc.want) {
				t.Errorf("problems %v do not mention %q", got, tc.want)
			}
		})
	}
}

func TestExamples_DescriptorParsingRejectsBadInput(t *testing.T) {
	good := `{"tools":{"a":{"annotations":{"readOnlyHint":true}}}}`
	if tools, err := parseExampleDescriptors([]byte(good)); err != nil || len(tools) != 1 || tools["a"].ReadOnlyHint == nil || !*tools["a"].ReadOnlyHint {
		t.Fatalf("good descriptor: tools=%v err=%v", tools, err)
	}
	for name, raw := range map[string]string{
		"missing input":    "",
		"malformed json":   `{"tools":`,
		"not an object":    `[1,2]`,
		"no tools key":     `{}`,
		"empty tools":      `{"tools":{}}`,
		"null tools":       `{"tools":null}`,
		"wrong tools type": `{"tools":"a"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if tools, err := parseExampleDescriptors([]byte(raw)); err == nil {
				t.Errorf("accepted %q: %v", raw, tools)
			}
		})
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
