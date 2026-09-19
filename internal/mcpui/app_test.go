package mcpui

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestTriageHTMLHasNoExternalDeps is T4: asset hygiene, mirroring
// internal/ui/chrome_test.go's TestLiteChromeHasNoExternalDeps. The embedded
// document must reference no external origin and use no markup-assignment or
// dynamic-code-evaluation API; a CI failure here is what backs the
// requirements' "insert it through a text node, never innerHTML" acceptance
// criterion.
func TestTriageHTMLHasNoExternalDeps(t *testing.T) {
	for _, bad := range []string{
		"innerHTML",
		"insertAdjacentHTML",
		"outerHTML",
		"document.write",
		"eval(",
		"new Function",
		"fetch(",
		"XMLHttpRequest",
		"import(",
		"http://",
		"https://",
		"fonts.googleapis.com",
	} {
		if strings.Contains(triageHTML, bad) {
			t.Errorf("triage.html must not contain %q", bad)
		}
	}
}

// TestTriageHTMLContentHash is T5: a golden hash on the embedded document, so
// an edit to triage.html is a deliberate, reviewable change to this constant
// rather than silent drift a client (or the report's content-hash claim)
// would not notice.
func TestTriageHTMLContentHash(t *testing.T) {
	const wantHash = "390a03383cafc2a0272f5fac87e462306a365a07953f267f0760b999c7a50e88"
	sum := sha256.Sum256([]byte(triageHTML))
	got := hex.EncodeToString(sum[:])
	if got != wantHash {
		t.Fatalf("triage.html sha256 = %s, want %s (recorded golden hash)\n"+
			"If this edit to triage.html was deliberate, update wantHash to the "+
			"new value printed above.", got, wantHash)
	}
}

// TestTriageHTMLRejectsForeignMessageSources pins the transport's sender
// check: the postMessage handler must drop any event whose source is not the
// parent window. A sandboxed iframe is reachable from sibling frames in the
// host page (via parent.frames), and the sequential "app-N" request ids are
// guessable, so without this guard a sibling could resolve an in-flight
// request or push a forged tool-result whose rendered card carries an
// attacker-chosen peer into the draft/send path.
func TestTriageHTMLRejectsForeignMessageSources(t *testing.T) {
	const guard = "if (event.source !== window.parent) return;"
	if !strings.Contains(triageHTML, guard) {
		t.Fatalf("triage.html must contain the host-sender guard %q", guard)
	}
	listener := strings.Index(triageHTML, `window.addEventListener("message"`)
	if listener < 0 {
		t.Fatal("triage.html has no message listener")
	}
	if got := strings.Index(triageHTML, guard); got < listener {
		t.Fatal("the sender guard must sit inside the message listener, not before it")
	}
	body := triageHTML[listener:]
	if strings.Index(body, guard) > strings.Index(body, "var data = event.data;") {
		t.Fatal("the sender guard must run before the handler inspects event.data")
	}
}

func TestResource(t *testing.T) {
	r := Resource()
	if r.URI != ResourceURI {
		t.Errorf("URI = %q, want %q", r.URI, ResourceURI)
	}
	if r.MIMEType != MIMEType {
		t.Errorf("MIMEType = %q, want %q", r.MIMEType, MIMEType)
	}
	if r.Meta == nil {
		t.Fatal("Meta is nil")
	}
	assertCSPEmpty(t, r.Meta.AdditionalFields)
}

func TestContents(t *testing.T) {
	contents := Contents(ResourceURI)
	if len(contents) != 1 {
		t.Fatalf("len(Contents) = %d, want 1", len(contents))
	}
	tc, ok := contents[0].(mcplib.TextResourceContents)
	if !ok {
		t.Fatalf("contents[0] is %T, want TextResourceContents", contents[0])
	}
	if tc.URI != ResourceURI {
		t.Errorf("URI = %q, want %q", tc.URI, ResourceURI)
	}
	if tc.MIMEType != MIMEType {
		t.Errorf("MIMEType = %q, want %q", tc.MIMEType, MIMEType)
	}
	if tc.Text == "" {
		t.Fatal("Text is empty")
	}
	if tc.Text != triageHTML {
		t.Error("Text does not match the embedded document")
	}
	assertCSPEmpty(t, tc.Meta)
}

func assertCSPEmpty(t *testing.T, meta map[string]any) {
	t.Helper()
	ui, ok := meta["ui"].(map[string]any)
	if !ok {
		t.Fatal("meta[\"ui\"] missing or wrong type")
	}
	csp, ok := ui["csp"].(map[string]any)
	if !ok {
		t.Fatal("meta[\"ui\"][\"csp\"] missing or wrong type")
	}
	for _, key := range []string{"connectDomains", "resourceDomains", "frameDomains", "baseUriDomains"} {
		v, ok := csp[key]
		if !ok {
			t.Errorf("csp[%q] missing", key)
			continue
		}
		list, ok := v.([]string)
		if !ok {
			t.Errorf("csp[%q] = %T, want []string", key, v)
			continue
		}
		if len(list) != 0 {
			t.Errorf("csp[%q] = %v, want empty", key, list)
		}
	}
}

func TestExtensionCapability(t *testing.T) {
	cap := ExtensionCapability()
	entry, ok := cap[ExtensionID].(map[string]any)
	if !ok {
		t.Fatalf("ExtensionCapability()[%q] missing or wrong type", ExtensionID)
	}
	mimeTypes, ok := entry["mimeTypes"].([]string)
	if !ok || len(mimeTypes) != 1 || mimeTypes[0] != MIMEType {
		t.Errorf("mimeTypes = %v, want [%q]", entry["mimeTypes"], MIMEType)
	}
}

func TestToolMeta(t *testing.T) {
	meta := ToolMeta()
	ui, ok := meta["ui"].(map[string]any)
	if !ok {
		t.Fatal("meta[\"ui\"] missing or wrong type")
	}
	if ui["resourceUri"] != ResourceURI {
		t.Errorf("resourceUri = %v, want %q", ui["resourceUri"], ResourceURI)
	}
	vis, ok := ui["visibility"].([]string)
	if !ok || len(vis) != 2 || vis[0] != "model" || vis[1] != "app" {
		t.Errorf("visibility = %v, want [model app]", ui["visibility"])
	}
	// The deprecated flat key must never appear anywhere in the map.
	if _, present := meta["ui/resourceUri"]; present {
		t.Error("ToolMeta emits the deprecated flat ui/resourceUri key")
	}
}
