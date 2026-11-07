package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// shippedTools reads docs/tool-descriptors.json, the committed tool surface,
// and returns each tool's readOnlyHint. The tests only read it.
func shippedTools(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "tool-descriptors.json"))
	if err != nil {
		t.Fatalf("read tool descriptors: %v", err)
	}
	var doc struct {
		Tools map[string]struct {
			Annotations struct {
				ReadOnlyHint bool `json:"readOnlyHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse tool descriptors: %v", err)
	}
	if len(doc.Tools) == 0 {
		t.Fatal("tool descriptors list no tools")
	}
	out := make(map[string]bool, len(doc.Tools))
	for name, tool := range doc.Tools {
		out[name] = tool.Annotations.ReadOnlyHint
	}
	return out
}

func renderExamples(t *testing.T, cats []exampleCategory) (*httptest.ResponseRecorder, *html.Node) {
	t.Helper()
	rec := httptest.NewRecorder()
	examplesHandler("https://tg.example.test/", true, cats).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/examples", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	doc, err := html.Parse(strings.NewReader(rec.Body.String()))
	if err != nil {
		t.Fatalf("parse rendered page: %v", err)
	}
	return rec, doc
}

func walk(n *html.Node, visit func(*html.Node)) {
	visit(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, visit)
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func hasClass(n *html.Node, class string) bool {
	for _, c := range strings.Fields(attr(n, "class")) {
		if c == class {
			return true
		}
	}
	return false
}

func text(n *html.Node) string {
	var b strings.Builder
	walk(n, func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}
	})
	return b.String()
}

func find(root *html.Node, match func(*html.Node) bool) []*html.Node {
	var out []*html.Node
	walk(root, func(n *html.Node) {
		if n.Type == html.ElementNode && match(n) {
			out = append(out, n)
		}
	})
	return out
}

func articles(doc *html.Node) []*html.Node {
	return find(doc, func(n *html.Node) bool { return n.Data == "article" && hasClass(n, "example") })
}

// The page is exactly the intended 12 prompts: two in each of the six
// categories, in this order.
func TestCuratedExamples_AreExactlyTheIntendedSet(t *testing.T) {
	want := []struct {
		slug string
		ids  []string
	}{
		{"briefing", []string{"unread-digest", "busiest-chats"}},
		{"search", []string{"search-recent-keyword", "search-one-chat"}},
		{"extract", []string{"extract-dates", "extract-links"}},
		{"people", []string{"people-waiting", "people-draft-reply"}},
		{"analytics", []string{"analytics-busy-hours", "analytics-audit"}},
		{"media", []string{"media-inventory", "media-download"}},
	}
	if len(curatedExamples) != len(want) {
		t.Fatalf("%d categories, want %d", len(curatedExamples), len(want))
	}
	total := 0
	for i, w := range want {
		c := curatedExamples[i]
		if c.Slug != w.slug || len(c.Examples) != len(w.ids) {
			t.Fatalf("category %d = %q with %d examples, want %q with %d", i, c.Slug, len(c.Examples), w.slug, len(w.ids))
		}
		for j, id := range w.ids {
			if c.Examples[j].ID != id {
				t.Errorf("%s[%d] = %q, want %q", w.slug, j, c.Examples[j].ID, id)
			}
			total++
		}
	}
	if total != 12 {
		t.Fatalf("%d examples, want 12", total)
	}
}

// Every tool a curated example names is a tool the server ships, and every
// consent label follows from the tools used.
func TestCuratedExamples_ValidateAgainstShippedDescriptors(t *testing.T) {
	if err := validateExamples(curatedExamples, shippedTools(t)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateExamples_UnknownToolFails(t *testing.T) {
	tools := shippedTools(t)
	// Labelled Sends with a confirmation prompt, so the consent checks alone
	// would accept it: only the unknown-tool check can reject this example.
	cats := []exampleCategory{{Slug: "x", Name: "X", Examples: []example{
		{ID: "a", Title: "A", Prompt: "do it, not until I tell you to", Tools: []string{"read_minds"}, Sends: true},
	}}}
	err := validateExamples(cats, tools)
	if err == nil || !strings.Contains(err.Error(), "read_minds") || !strings.Contains(err.Error(), "not in the shipped tool descriptors") {
		t.Fatalf("an unknown tool must fail validation naming it, got %v", err)
	}
}

func TestValidateExamples_ConsentLabelMustMatchTools(t *testing.T) {
	tools := shippedTools(t)
	one := func(e example) error {
		e.ID, e.Title = "a", "A"
		return validateExamples([]exampleCategory{{Slug: "x", Name: "X", Examples: []example{e}}}, tools)
	}
	// A prompt that can send must be labelled as sending, and asks to wait.
	if err := one(example{Prompt: "reply, do not send until I tell you to", Tools: []string{"draft_reply", "send_reply"}}); err == nil {
		t.Error("send_reply without Sends=true must fail")
	}
	if err := one(example{Prompt: "reply, do not send until I tell you to", Tools: []string{"draft_reply", "send_reply"}, Sends: true}); err != nil {
		t.Errorf("a labelled sending example with a confirmation prompt must pass: %v", err)
	}
	// A read-only prompt must not claim to send.
	if err := one(example{Prompt: "p", Tools: []string{"get_messages"}, Sends: true}); err == nil {
		t.Error("read-only tools labelled Sends=true must fail")
	}
	// A sending prompt must ask for confirmation.
	if err := one(example{Prompt: "reply to Alice", Tools: []string{"send_reply"}, Sends: true}); err == nil {
		t.Error("a sending prompt that never asks to wait must fail")
	}
	// Duplicate ids would break the anchors and the copy status wiring.
	dup := []exampleCategory{{Slug: "x", Name: "X", Examples: []example{
		{ID: "a", Title: "A", Prompt: "p", Tools: []string{"get_messages"}},
		{ID: "a", Title: "B", Prompt: "q", Tools: []string{"get_messages"}},
	}}}
	if err := validateExamples(dup, tools); err == nil {
		t.Error("duplicate ids must fail")
	}
}

// Exactly one curated example can send, and it is the draft/confirm one; all
// others are read-only on the shipped descriptors.
func TestCuratedExamples_OnlyTheDraftReplyCanSend(t *testing.T) {
	tools := shippedTools(t)
	var sending []string
	for _, c := range curatedExamples {
		for _, e := range c.Examples {
			if e.Sends {
				sending = append(sending, e.ID)
			}
			for _, tool := range e.Tools {
				if !tools[tool] && !e.Sends {
					t.Errorf("%s uses non-read-only %s but is labelled read-only", e.ID, tool)
				}
			}
		}
	}
	if len(sending) != 1 || sending[0] != "people-draft-reply" {
		t.Fatalf("sending examples = %v, want only people-draft-reply", sending)
	}
}

func TestExamples_RendersEveryExampleWithToolsAndConsent(t *testing.T) {
	rec, doc := renderExamples(t, curatedExamples)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp != chromeCSP {
		t.Errorf("CSP = %q, want the shared chrome CSP", csp)
	}
	if strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP must not allow eval: %s", csp)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<link rel="canonical" href="https://tg.example.test/examples">`,
		`<a href="/platforms">Platforms</a>`, // shared chrome
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}

	arts := articles(doc)
	if len(arts) != 12 {
		t.Fatalf("%d example cards, want 12", len(arts))
	}
	i := 0
	for _, c := range curatedExamples {
		for _, e := range c.Examples {
			art := arts[i]
			i++
			if attr(art, "id") != e.ID {
				t.Errorf("card %d id = %q, want %q", i, attr(art, "id"), e.ID)
			}
			prompt := find(art, func(n *html.Node) bool { return n.Data == "p" && hasClass(n, "prompt") })
			if len(prompt) != 1 || text(prompt[0]) != e.Prompt {
				t.Errorf("%s: shown prompt does not match the curated one", e.ID)
			}
			var tools []string
			for _, code := range find(art, func(n *html.Node) bool { return n.Data == "code" }) {
				tools = append(tools, text(code))
			}
			if strings.Join(tools, ",") != strings.Join(e.Tools, ",") {
				t.Errorf("%s: shown tools %v, want %v", e.ID, tools, e.Tools)
			}
			read := find(art, func(n *html.Node) bool { return hasClass(n, "pill-read") })
			write := find(art, func(n *html.Node) bool { return hasClass(n, "pill-write") })
			switch {
			case e.Sends && (len(write) != 1 || len(read) != 0):
				t.Errorf("%s: a sending example must carry the send label only", e.ID)
			case e.Sends && !strings.Contains(text(write[0]), "explicit confirmation"):
				t.Errorf("%s: send label = %q, must say confirmation is required", e.ID, text(write[0]))
			case !e.Sends && (len(read) != 1 || len(write) != 0):
				t.Errorf("%s: a read-only example must carry the read-only label only", e.ID)
			case !e.Sends && !strings.Contains(text(read[0]), "no send consent needed"):
				t.Errorf("%s: read label = %q", e.ID, text(read[0]))
			}
		}
	}
	for _, c := range curatedExamples {
		if len(find(doc, func(n *html.Node) bool { return n.Data == "h2" && attr(n, "id") == c.Slug })) != 1 {
			t.Errorf("category heading %q missing", c.Slug)
		}
	}
}

// Curated data is escaped everywhere it is rendered: text, attributes and
// the copy payload, and none of it can open a tag or add an attribute.
func TestExamples_EscapesHostileData(t *testing.T) {
	evil := `</p><script>alert("x")</script><img src=x onerror=alert(1)>" onmouseover="alert(2)`
	cats := []exampleCategory{{
		Slug: "s" + evil, Name: "N" + evil, Intro: "I" + evil,
		Examples: []example{{
			ID: "id", Title: "T" + evil, Prompt: "P" + evil, Tools: []string{"get_messages" + evil}, Note: "O" + evil,
		}},
	}}
	rec, doc := renderExamples(t, cats)
	body := rec.Body.String()
	if strings.Contains(body, `<script>alert`) || strings.Contains(body, `<img src=x`) {
		t.Fatal("hostile markup reached the page unescaped")
	}
	if got := len(find(doc, func(n *html.Node) bool { return n.Data == "img" && attr(n, "src") == "x" })); got != 0 {
		t.Fatalf("injected <img> element present (%d)", got)
	}
	for _, s := range find(doc, func(n *html.Node) bool { return n.Data == "script" }) {
		if strings.Contains(text(s), "alert(") {
			t.Fatal("injected script element present")
		}
	}
	btns := find(doc, func(n *html.Node) bool { return n.Data == "button" && hasClass(n, "copy-prompt") })
	if len(btns) != 1 {
		t.Fatalf("%d copy buttons, want 1", len(btns))
	}
	if got := attr(btns[0], "data-prompt"); got != "P"+evil {
		t.Errorf("data-prompt = %q, want the hostile prompt carried as inert text", got)
	}
	for _, a := range btns[0].Attr {
		if a.Key == "onmouseover" {
			t.Error("attribute injection through data-prompt")
		}
	}
	prompt := find(doc, func(n *html.Node) bool { return n.Data == "p" && hasClass(n, "prompt") })
	if len(prompt) != 1 || text(prompt[0]) != "P"+evil {
		t.Error("prompt text must render as inert text")
	}
}

// Each copy button carries exactly its own prompt and has a live status
// region it points at, and the page script reports both outcomes.
func TestExamples_CopyButtonWiring(t *testing.T) {
	rec, doc := renderExamples(t, curatedExamples)
	btns := find(doc, func(n *html.Node) bool { return n.Data == "button" && hasClass(n, "copy-prompt") })
	if len(btns) != 12 {
		t.Fatalf("%d copy buttons, want 12", len(btns))
	}
	i := 0
	for _, c := range curatedExamples {
		for _, e := range c.Examples {
			b := btns[i]
			i++
			if attr(b, "type") != "button" {
				t.Errorf("%s: button type = %q, a copy button must not submit anything", e.ID, attr(b, "type"))
			}
			if got := attr(b, "data-prompt"); got != e.Prompt {
				t.Errorf("%s: copies %q, want its own prompt", e.ID, got)
			}
			status := find(doc, func(n *html.Node) bool { return attr(n, "id") == attr(b, "aria-describedby") })
			if len(status) != 1 || attr(status[0], "role") != "status" || attr(status[0], "aria-live") != "polite" || !hasClass(status[0], "copy-status") {
				t.Errorf("%s: button must point at one polite role=status region", e.ID)
			}
		}
	}

	var script string
	for _, s := range find(doc, func(n *html.Node) bool { return n.Data == "script" }) {
		if strings.Contains(text(s), "copy-prompt") {
			script += text(s)
		}
	}
	if script == "" {
		t.Fatal("no script wires the copy buttons")
	}
	for _, want := range []string{
		"navigator.clipboard.writeText(text).then(",      // async clipboard API
		"function () {\n          if (legacyCopy(text))", // rejection handler is the second then() argument
		"document.execCommand('copy')",                   // fallback when the API is absent or refused
		"'Copied to clipboard.'",                         // success state
		"'Copy failed.",                                  // failure state
		"range.selectNodeContents(el)",                   // failure leaves the prompt selected for a manual copy
	} {
		if !strings.Contains(script, want) {
			t.Errorf("copy script lacks %q", want)
		}
	}
	if strings.Contains(script, "http://") || strings.Contains(script, "fetch(") || strings.Contains(script, "XMLHttpRequest") {
		t.Error("the copy script must not make network requests")
	}
	if n := strings.Count(rec.Body.String(), "copy-prompt"); n < 12 {
		t.Errorf("copy-prompt appears %d times", n)
	}
}

// The landing page points at /examples.
func TestLanding_LinksToExamples(t *testing.T) {
	rec := httptest.NewRecorder()
	Landing("https://tg.example.test", "/mcp", "", true).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	doc, err := html.Parse(strings.NewReader(rec.Body.String()))
	if err != nil {
		t.Fatal(err)
	}
	links := find(doc, func(n *html.Node) bool { return n.Data == "a" && attr(n, "href") == "/examples" })
	if len(links) == 0 {
		t.Fatal("the landing page does not link to /examples")
	}
}
