package mcp

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
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
		Name string `json:"name"`
		// Enabled is a pointer so that a missing or misspelled key is a
		// test failure, not a silent false. "Explicit decision for every
		// tool" has to be enforced here or it is enforced nowhere.
		Enabled *bool `json:"enabled"`
		// Reason is required on an enabled tool: readOnlyHint says a tool
		// has no side effects, not that its output belongs on a shared
		// surface. get_messages is read-only and returns message bodies.
		Reason string `json:"reason,omitempty"`
		// UpstreamGate names the server-side check that decides, per
		// identity, what the call may do: a scope, the send gate, an admin
		// scope, or the authenticated identity for self-only reads. The
		// portal allowlist cannot see users; this field records where the
		// access control actually lives. Required on every enabled tool,
		// and it must name a check the server really performs (see
		// knownGates below), so a made-up gate is as much a failure as a
		// missing one.
		UpstreamGate string `json:"upstream_gate,omitempty"`
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
//   - a tool may be enabled only if the entry says why its output is
//     acceptable on a shared surface AND names the upstream gate that
//     decides per identity what the call may do. The portal switch is
//     per-server and user-blind; the gate is the access control, and the
//     entry is where that dependency is written down and reviewed
//     (decision 2026-09-12 on mctlhq/.github#35: every tool on, upstream
//     decides).
//
// minReasonLen is a floor on the privacy decision, not a quality bar: it
// rejects a placeholder, not a short sentence.
const minReasonLen = 40

// knownGates are the server-side checks a tool may cite. Each is a
// substring of a real gate: a scope string passed to requireScope /
// requireAnyScope / evaluateWriteGate, the ALLOW_SEND flag, or the
// authenticated identity itself for tools that only ever act on the
// caller. A gate the server does not have cannot be cited.
var knownGates = []string{
	"telegram:dialogs:read",
	"telegram:messages:read",
	"telegram:messages:send",
	"telegram:messages:pin",
	"account:manage",
	"admin:users",
	"ALLOW_SEND",
	"authenticated identity",
}

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

	// Enumerate through the unfiltered server. ToolFilter "" means "all"
	// today (toolPassesFilter); the comparison against the read-only-only
	// variant proves this is the full set rather than trusting the default.
	registered := (&Server{ToolFilter: ""}).newMCPServer().ListTools()
	readOnlyOnly := (&Server{ToolFilter: "read-only"}).newMCPServer().ListTools()
	if len(registered) == 0 || len(registered) <= len(readOnlyOnly) {
		t.Fatalf("enumeration is not the unfiltered tool set: all=%d read-only=%d", len(registered), len(readOnlyOnly))
	}

	listed := make(map[string]bool, len(list.Tools))
	for _, tool := range list.Tools {
		if _, dup := listed[tool.Name]; dup {
			t.Errorf("%s: listed twice", tool.Name)
		}
		if tool.Enabled == nil {
			t.Errorf("%s: no \"enabled\" key; every entry must carry an explicit decision", tool.Name)
			listed[tool.Name] = false
			continue
		}
		listed[tool.Name] = *tool.Enabled
		if *tool.Enabled && len(tool.Reason) < minReasonLen {
			t.Errorf("%s: enabled but reason is %d chars (minimum %d): say what the tool exposes and why that is acceptable on a shared surface", tool.Name, len(tool.Reason), minReasonLen)
		}
		if *tool.Enabled && !citesKnownGate(tool.UpstreamGate) {
			t.Errorf("%s: enabled but upstream_gate %q names no server-side check (want one of %v)", tool.Name, tool.UpstreamGate, knownGates)
		}
	}

	var missing, stale []string
	for name := range registered {
		if _, ok := listed[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range listed {
		if _, ok := registered[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("tools registered by the server but absent from docs/portal-allowlist.json (add each with an explicit enabled decision): %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("entries in docs/portal-allowlist.json for tools the server no longer registers: %v", stale)
	}
}

// citesKnownGate reports whether gate names at least one check the server
// performs. Substring match on purpose: a compound gate such as
// "ALLOW_SEND + telegram:messages:send + per-account send consent" cites
// several, and the send tools are gated on all of them.
func citesKnownGate(gate string) bool {
	for _, k := range knownGates {
		if strings.Contains(gate, k) {
			return true
		}
	}
	return false
}
