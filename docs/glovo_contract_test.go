package docs

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type glovoContract struct {
	ID    string `json:"$id"`
	Tools []struct {
		Name          string         `json:"name"`
		Description   string         `json:"description"`
		RequiredScope string         `json:"required_scope"`
		InputSchema   map[string]any `json:"input_schema"`
		OutputSchema  map[string]any `json:"output_schema"`
	} `json:"tools"`
	ProtectedResource struct {
		Resource        string   `json:"resource"`
		ScopesSupported []string `json:"scopes_supported"`
	} `json:"protected_resource"`
}

var glovoToolAllowlist = []string{
	"glovo_auth_status", "glovo_connect_account", "glovo_get_basket",
	"glovo_get_order_history", "glovo_order_status", "glovo_prepare_order",
	"glovo_preview_reorder",
}

var glovoForbiddenProps = map[string]bool{
	"tenant": true, "tenant_id": true, "principal": true, "principal_id": true,
	"namespace": true, "task_queue": true, "workflow_id": true, "url": true,
	"endpoint": true, "cookie": true, "session": true, "password": true, "token": true,
}

var glovoForbiddenName = regexp.MustCompile(`place|pay|checkout|purchase|submit_order`)

// checkClosed walks a schema and verifies every object is closed and no
// forbidden input property is declared.
func checkClosed(t *testing.T, path string, v any, input bool) {
	t.Helper()
	switch n := v.(type) {
	case map[string]any:
		if n["type"] == "object" {
			if ap, ok := n["additionalProperties"].(bool); !ok || ap {
				t.Errorf("%s: object is not closed (additionalProperties must be false)", path)
			}
		}
		if props, ok := n["properties"].(map[string]any); ok {
			for name, sub := range props {
				if input && glovoForbiddenProps[name] {
					t.Errorf("%s: forbidden input property %q", path, name)
				}
				checkClosed(t, path+"."+name, sub, input)
			}
		}
		if items, ok := n["items"]; ok {
			checkClosed(t, path+"[]", items, input)
		}
	}
}

func TestGlovoContract(t *testing.T) {
	raw, err := os.ReadFile("contracts/glovo-mcp-tools.json")
	if err != nil {
		t.Fatal(err)
	}
	var c glovoContract
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.ID, "v1alpha1") {
		t.Errorf("$id %q must contain v1alpha1", c.ID)
	}
	if c.ProtectedResource.Resource == "" || len(c.ProtectedResource.ScopesSupported) == 0 {
		t.Error("protected resource metadata incomplete")
	}
	var names []string
	for _, tool := range c.Tools {
		names = append(names, tool.Name)
		if glovoForbiddenName.MatchString(tool.Name) {
			t.Errorf("forbidden tool name %q", tool.Name)
		}
		if tool.Name == "glovo_connect_account" && strings.Contains(strings.ToLower(tool.Description), "oauth") {
			t.Error("glovo_connect_account must be described as a delegated account connection, not OAuth")
		}
		if tool.RequiredScope == "" {
			t.Errorf("%s: missing required_scope", tool.Name)
		}
		checkClosed(t, tool.Name+".input", tool.InputSchema, true)
		checkClosed(t, tool.Name+".output", tool.OutputSchema, false)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != strings.Join(glovoToolAllowlist, ",") {
		t.Errorf("tool set %v does not equal allowlist %v", names, glovoToolAllowlist)
	}
}

func TestGlovoThreatModelCrossReferences(t *testing.T) {
	tm, err := os.ReadFile("agent-runtime/glovo-threat-model.md")
	if err != nil {
		t.Fatal(err)
	}
	adr, err := os.ReadFile("adr/0010-glovo-multitenant-connections.md")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`\bT\d+\b`)
	ids := re.FindAllString(string(tm), -1)
	if len(ids) == 0 {
		t.Fatal("threat model names no test IDs")
	}
	for _, id := range ids {
		if !regexp.MustCompile(`\b` + id + `\b`).Match(adr) {
			t.Errorf("test ID %s missing from ADR", id)
		}
	}
	for _, line := range strings.Split(string(tm), "\n") {
		if strings.HasPrefix(line, "| TM") && !re.MatchString(line) {
			t.Errorf("threat row without test ID: %s", line)
		}
	}
}

func TestGlovoDocsHaveNoCredentialShapes(t *testing.T) {
	files := []string{
		"reports/glovo-connector-feasibility.md",
		"adr/0010-glovo-multitenant-connections.md",
		"contracts/glovo-mcp-tools.json",
		"agent-runtime/glovo-threat-model.md",
		"contracts/glovo-facade-mctl-api.md",
		"glovo-mcp.md",
	}
	pats := []*regexp.Regexp{
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+`),
		regexp.MustCompile(`(?i)(set-)?cookie:\s*\S`),
		regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`),
		regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`),
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pats {
			if m := p.FindString(string(b)); m != "" {
				t.Errorf("%s: credential-shaped string matches %s", f, p)
			}
		}
	}
}
