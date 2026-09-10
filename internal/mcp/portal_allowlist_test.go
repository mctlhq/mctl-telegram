package mcp

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// portalAllowlist mirrors docs/portal-allowlist.json. The file is what the
// Cloudflare portal mapping for server `tg` is applied from; this test is
// what keeps the file honest.
type portalAllowlist struct {
	Portal          string `json:"portal"`
	Server          string `json:"server"`
	DefaultDisabled bool   `json:"default_disabled"`
	Tools           []struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	} `json:"tools"`
}

// TestPortalAllowlist_CoversEveryRegisteredTool is the drift guard for the
// portal's fail-closed exposure (mctlhq/.github#44, finding 6). The portal
// only hides a tool it has an explicit entry for, so a tool added to this
// server without a decision here would surface on the aggregate the moment
// the portal re-syncs. Failing the build is the decision being asked for.
//
// Two invariants:
//   - the set of names in the file equals the set of tools newMCPServer
//     registers — no missing tool, no stale entry;
//   - a tool may be enabled only if it declares readOnlyHint=true, which is
//     the whole content of "curated read-only surface".
func TestPortalAllowlist_CoversEveryRegisteredTool(t *testing.T) {
	raw, err := os.ReadFile("../../docs/portal-allowlist.json")
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	var list portalAllowlist
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	if list.Portal != "mcp" || list.Server != "tg" {
		t.Fatalf("allowlist targets portal=%q server=%q, want mcp/tg", list.Portal, list.Server)
	}
	if !list.DefaultDisabled {
		t.Fatal("default_disabled must be true: it is the half of the configuration that hides a tool the list does not know about")
	}

	registered := (&Server{}).newMCPServer().ListTools()
	if len(registered) == 0 {
		t.Fatal("no tools registered — the enumeration this test relies on is broken")
	}

	listed := make(map[string]bool, len(list.Tools))
	for _, tool := range list.Tools {
		if _, dup := listed[tool.Name]; dup {
			t.Errorf("%s: listed twice", tool.Name)
		}
		listed[tool.Name] = tool.Enabled
	}

	var missing, stale, unsafe []string
	for name, st := range registered {
		enabled, ok := listed[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		if enabled && (st.Tool.Annotations.ReadOnlyHint == nil || !*st.Tool.Annotations.ReadOnlyHint) {
			unsafe = append(unsafe, name)
		}
	}
	for name := range listed {
		if _, ok := registered[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	sort.Strings(unsafe)
	if len(missing) > 0 {
		t.Errorf("tools registered by the server but absent from docs/portal-allowlist.json (add each with an explicit enabled decision): %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("entries in docs/portal-allowlist.json for tools the server no longer registers: %v", stale)
	}
	if len(unsafe) > 0 {
		t.Errorf("enabled on the portal but not readOnlyHint=true: %v", unsafe)
	}
}
