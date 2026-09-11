package mcp

import (
	"encoding/json"
	"os"
	"regexp"
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
		// UpstreamGates is the exact set of server-side checks the handler
		// performs: scope tokens passed to requireScope / requireAnyScope,
		// "send-gate" when the handler runs evaluateSendGate or
		// evaluateWriteGate, or "self-only" for a tool that acts on the
		// caller alone and which selfOnlyTools below vouches for. The portal
		// allowlist cannot see users; this field records where the access
		// control actually lives. It is not trusted: the test re-derives
		// the set from the Go source and fails on any difference, so a
		// claim the code does not back is a build failure, not a comment.
		UpstreamGates []string `json:"upstream_gates,omitempty"`
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
//     acceptable on a shared surface AND its upstream_gates equal, as a
//     set, the checks the handler performs in the Go source. The portal
//     switch is per-server and user-blind; the gate is the access control,
//     and the entry is where that dependency is written down and reviewed
//     (decision 2026-09-12 on mctlhq/.github#35: every tool on, upstream
//     decides). A tool whose handler performs no check at all may be
//     enabled only if selfOnlyTools names it, and that map lives here, in
//     reviewed Go, not in the JSON.
//
// minReasonLen is a floor on the privacy decision, not a quality bar: it
// rejects a placeholder, not a short sentence.
const minReasonLen = 40

// selfOnlyTools are the handlers that perform no scope or send-gate check
// because they cannot act on anyone but the authenticated caller: they take
// no telegram_id, no peer, and touch nothing outside the caller's own row or
// session. This is the one place a gate-less tool may be vouched for. A new
// tool whose handler checks nothing and is absent here fails the test
// whether or not the JSON enables it with "self-only": adding a name here is
// a reviewed Go change, and the reason the tool is safe belongs in the
// comment next to it.
var selfOnlyTools = map[string]string{
	"get_my_identity":             "returns the caller's own identity row",
	"get_my_send_status":          "reports the caller's own send gate without acting",
	"get_my_audit_log":            "reads the caller's own audit rows, peers redacted",
	"prepare_pin_message":         "mints a confirmation id for the caller's own later pin_message; no Telegram action",
	"disconnect_telegram_account": "revokes the caller's own session",
	"delete_telegram_account":     "deletes the caller's own account row",
}

// gateSelfOnly and gateSend are the two non-scope tokens upstream_gates may
// carry. Everything else must be a scope string that appears verbatim in a
// requireScope / requireAnyScope / evaluateWriteGate call of the handler.
const (
	gateSelfOnly = "self-only"
	gateSend     = "send-gate"
)

var (
	reNewTool   = regexp.MustCompile(`mcplib\.NewTool\(\s*"([^"]+)"`)
	reScopeCall = regexp.MustCompile(`require(?:Any)?Scope\(id,\s*((?:"[^"]+"\s*,?\s*)+)\)`)
	reScopeStr  = regexp.MustCompile(`"([^"]+)"`)
	reSendGate  = regexp.MustCompile(`evaluateSendGate\(`)
	reWriteGate = regexp.MustCompile(`evaluateWriteGate\([^)]*"([^"]+)"\)`)
)

// gatesFromSource derives, per registered tool, the set of checks its
// handler performs, by reading the registration functions in tools.go and
// media_tools.go. A registration is the text from its mcplib.NewTool("name"
// call to the next top-level func: every handler closure is registered
// inside that same function, and the shared gate helpers (evaluateSendGate
// and friends) are top-level funcs, so the boundary keeps a helper's body
// from being read as a caller's check. The scan is textual on purpose — the
// handlers are closures, not values the test could introspect — and the
// equality check on the registered tool set proves it did not miss one.
func gatesFromSource(t *testing.T, files ...string) map[string]map[string]bool {
	t.Helper()
	var src strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src.Write(b)
		src.WriteString("\n")
	}
	text := src.String()
	out := map[string]map[string]bool{}
	locs := reNewTool.FindAllStringSubmatchIndex(text, -1)
	for _, loc := range locs {
		name := text[loc[2]:loc[3]]
		seg := text[loc[1]:]
		if end := strings.Index(seg, "\nfunc "); end >= 0 {
			seg = seg[:end]
		}
		if _, dup := out[name]; dup {
			t.Fatalf("%s: registered twice in the scanned sources", name)
		}
		gates := map[string]bool{}
		for _, m := range reScopeCall.FindAllStringSubmatch(seg, -1) {
			for _, sm := range reScopeStr.FindAllStringSubmatch(m[1], -1) {
				gates[sm[1]] = true
			}
		}
		if reSendGate.MatchString(seg) {
			gates[gateSend] = true
			gates["telegram:messages:send"] = true
		}
		for _, m := range reWriteGate.FindAllStringSubmatch(seg, -1) {
			gates[gateSend] = true
			gates[m[1]] = true
		}
		out[name] = gates
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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

	// The source scan must see exactly the tools the server registers; a
	// registration the regex missed would otherwise read as "no gates" and
	// could only be enabled via selfOnlyTools, but the honest failure is here.
	fromSource := gatesFromSource(t, "tools.go", "media_tools.go")
	for name := range registered {
		if _, ok := fromSource[name]; !ok {
			t.Errorf("%s: registered by the server but not found by the source scan (tools.go, media_tools.go); extend gatesFromSource if registrations moved", name)
		}
	}
	for name := range fromSource {
		if _, ok := registered[name]; !ok {
			t.Errorf("%s: found by the source scan but not registered by the server", name)
		}
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
		if *tool.Enabled {
			claimed := map[string]bool{}
			for _, g := range tool.UpstreamGates {
				if claimed[g] {
					t.Errorf("%s: upstream_gates lists %q twice", tool.Name, g)
				}
				claimed[g] = true
			}
			checkGates(t, tool.Name, claimed, fromSource[tool.Name])
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

// checkGates compares what the JSON claims for an enabled tool with what the
// handler does. Exact set equality: a claimed gate the code does not perform
// is a false statement about access control, and a performed gate the JSON
// omits is a decision made without knowing what it rests on. "self-only" is
// accepted only when the handler performs nothing AND selfOnlyTools vouches
// for the tool; a gate-less handler nobody vouched for cannot be enabled.
func checkGates(t *testing.T, name string, claimed, actual map[string]bool) {
	t.Helper()
	if len(actual) == 0 {
		if _, vouched := selfOnlyTools[name]; !vouched {
			t.Errorf("%s: enabled, but its handler performs no scope or send-gate check and selfOnlyTools does not vouch for it; a tool with no upstream gate cannot go on the shared surface", name)
			return
		}
		if len(claimed) != 1 || !claimed[gateSelfOnly] {
			t.Errorf("%s: handler performs no check and is vouched self-only; upstream_gates must be exactly [%q], got %v", name, gateSelfOnly, sortedKeys(claimed))
		}
		return
	}
	if claimed[gateSelfOnly] {
		t.Errorf("%s: claims %q but its handler performs %v", name, gateSelfOnly, sortedKeys(actual))
	}
	for g := range claimed {
		if g != gateSelfOnly && !actual[g] {
			t.Errorf("%s: upstream_gates claims %q, which the handler does not perform (source: %v)", name, g, sortedKeys(actual))
		}
	}
	for g := range actual {
		if !claimed[g] {
			t.Errorf("%s: handler performs %q but upstream_gates omits it (claimed: %v)", name, g, sortedKeys(claimed))
		}
	}
}
