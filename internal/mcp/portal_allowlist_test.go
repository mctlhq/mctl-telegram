package mcp

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
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
// reportsGateTools are handlers that CALL a gate helper and do not act on the
// answer: they put the verdict in their own output. The AST scan cannot tell
// that apart from enforcement -- it sees a call -- so the distinction is made
// here, by a person, and the scan's derived gates are dropped for these tools.
//
// Without this, teaching the scan the decomposed BeforeAccount helpers made
// get_my_send_status derive ["send-gate", "telegram:messages:send"], and the
// allowlist entry had to claim a check that a client holding only the read
// scopes sails straight through: the tool reports can_send and returns either
// way, and its own description says operators cannot disable it. Worse than
// the wrong entry was the quiet change to the rule -- any handler that
// mentions a gate function and ignores it would have been enabled with no
// reviewed Go change at all, which is exactly what selfOnlyTools exists to
// prevent. A tool named here is treated as gate-less and therefore still needs
// its vouch below.
var reportsGateTools = map[string]string{
	"get_my_send_status": "runs evaluateSendGateBeforeAccount to compute can_send/reason for its own output; the verdict is returned, never enforced",
}

var selfOnlyTools = map[string]string{
	"get_my_identity":             "returns the caller's own identity row",
	"get_my_send_status":          "reports the caller's own send gate without acting on it (see reportsGateTools)",
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
	// sendScopeFromSource is the scope evaluateSendGate binds in tools.go.
	// TestSendScopeMatchesSource pins it against the source, so a rename
	// there fails here instead of silently deriving a gate set that names a
	// scope no handler requires any more.
	sendScopeFromSource = "telegram:messages:send"
)

// The scan records that a gate call is PRESENT in the handler, not that its
// result is enforced: `_ = requireScope(...)` and a check inside a branch both
// derive a full gate set. That is deliberate — deciding enforcement from the
// AST would mean re-implementing the type checker — and it is the reason the
// JSON entry is reviewed by a person rather than merely generated. Read a
// derived gate as "the handler asks this question", and read the handler when
// the answer matters.
//
// gatesFromSource derives, per registered tool, the set of checks its
// handler performs, from the Go AST of the given files. Each tool is
// registered by one top-level function that builds the mcplib.NewTool
// value and its handler closure (toolSendMessage, toolGetMedia, ...). The
// scan attributes to a tool every gate call made anywhere inside the
// function that contains its NewTool call: requireScope / requireAnyScope
// (string-literal scopes), evaluateSendGate, and evaluateWriteGate (its
// string-literal scope). It is the AST, so comments and strings cannot
// impersonate a call, and a function that registers two tools is refused
// outright rather than letting one tool's checks vouch for the other's.
// A handler defined outside its tool's function is read as gate-less,
// which fails closed: the tool can then be enabled only via selfOnlyTools.
func gatesFromSource(fset *token.FileSet, files ...*ast.File) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var names []string
			gates := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch calleeName(call.Fun) {
				case "NewTool":
					if lit := stringLit(call.Args, 0); lit != "" {
						names = append(names, lit)
					}
				case "requireScope", "requireAnyScope":
					for i := 1; i < len(call.Args); i++ {
						if lit := stringLit(call.Args, i); lit != "" {
							gates[lit] = true
						}
					}
				case "evaluateSendGate", "evaluateSendGateBeforeAccount":
					// evaluateSendGate is evaluateWriteGate with the send
					// scope bound (tools.go); the BeforeAccount variant is the
					// same decision taken before the account row is read, and
					// handlers do gate that way (tools.go:905). Missing it
					// would report a gated handler as "no checks at all" and
					// nudge whoever reads that toward a selfOnlyTools vouch
					// the code does not deserve.
					gates[gateSend] = true
					gates[sendScopeFromSource] = true
				case "evaluateWriteGate", "evaluateWriteGateBeforeAccount":
					gates[gateSend] = true
					if lit := stringLit(call.Args, len(call.Args)-1); lit != "" {
						gates[lit] = true
					}
				}
				return true
			})
			switch len(names) {
			case 0:
				continue
			case 1:
			default:
				return nil, fmt.Errorf("%s registers %d tools (%v) in one function; one function per tool, or the checks of one would vouch for the other", fset.Position(fn.Pos()), len(names), names)
			}
			if _, dup := out[names[0]]; dup {
				return nil, fmt.Errorf("%s: tool %q registered twice", fset.Position(fn.Pos()), names[0])
			}
			out[names[0]] = gates
		}
	}
	return out, nil
}

// calleeName returns the bare identifier a call targets: f, pkg.f or
// recv.f all yield "f". Package qualification is not checked because the
// gate helpers are unexported functions of this package and NewTool is
// only ever mcplib's; a same-named local would be a change to this package
// that the reviewer sees.
func calleeName(fun ast.Expr) string {
	switch e := fun.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// stringLit returns the unquoted value of args[i] when it is a string
// literal, else "". A scope passed through a variable is not a gate the
// scan can vouch for, and reads as absent — the failing direction.
func stringLit(args []ast.Expr, i int) string {
	if i < 0 || i >= len(args) {
		return ""
	}
	lit, ok := args[i].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return v
}

func parseSources(t *testing.T, paths ...string) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	for _, p := range paths {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		files = append(files, f)
	}
	return fset, files
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
	fset, parsed := parseSources(t, "tools.go", "media_tools.go")
	fromSource, err := gatesFromSource(fset, parsed...)
	if err != nil {
		t.Fatal(err)
	}
	// A reported gate is not a gate. Dropping the derived set here, before any
	// consumer reads it, is what keeps the vouch requirement honest for these
	// handlers rather than letting a mention of a gate helper stand in for one.
	for name := range reportsGateTools {
		gates, ok := fromSource[name]
		if !ok {
			t.Errorf("reportsGateTools names %q, which no tool registers any more; drop the entry", name)
			continue
		}
		if len(gates) == 0 {
			t.Errorf("reportsGateTools names %q, but the scan derives no gate for it; the entry explains a subtraction that no longer happens", name)
		}
		fromSource[name] = map[string]bool{}
	}
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

	// A vouch is a claim about a handler, so it must still describe one: a
	// name that no longer registers, or one the scan now shows is gated,
	// means the map outlived the code it was vouching for. Without this a
	// renamed tool keeps a live gate-less exemption under its old name.
	for name := range selfOnlyTools {
		gates, ok := fromSource[name]
		if !ok {
			t.Errorf("selfOnlyTools vouches for %q, which no tool registers any more; drop the entry", name)
			continue
		}
		if len(gates) > 0 {
			t.Errorf("selfOnlyTools vouches for %q as gate-less, but its handler performs %v; drop the vouch and list the gates instead", name, sortedKeys(gates))
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

// TestGatesFromSource pins the scan itself against the shapes agy named on
// #629: a gate that exists only in a comment or a string, two tools in one
// function, multi-line and variable arguments, and the two write-gate
// helpers. Each case is a source snippet, not a fixture file, so the case
// and its expectation are read together.
func TestGatesFromSource(t *testing.T) {
	parse := func(t *testing.T, src string) (*token.FileSet, *ast.File) {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "snippet.go", "package mcp\n"+src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse snippet: %v", err)
		}
		return fset, f
	}
	cases := []struct {
		name string
		src  string
		want map[string][]string
		err  string
	}{
		{
			name: "scope in a comment and a string is not a gate",
			src: `func (s *Server) toolA() {
	tool := mcplib.NewTool("a")
	// requireScope(id, "admin:users")
	_ = "requireScope(id, \"admin:users\")"
	_ = tool
}`,
			want: map[string][]string{"a": {}},
		},
		{
			name: "multi-line requireAnyScope and evaluateWriteGate",
			src: `func (s *Server) toolB() {
	tool := mcplib.NewTool(
		"b",
	)
	h := func() {
		if err := requireAnyScope(id,
			"admin:users",
			"admin:users:read"); err != nil {
			return
		}
		_, _ = evaluateWriteGate(ctx, s.Store, id, s.AllowSend, s.DemoReviewerTGID,
			"telegram:messages:pin")
	}
	_, _ = tool, h
}`,
			want: map[string][]string{"b": {"admin:users", "admin:users:read", "send-gate", "telegram:messages:pin"}},
		},
		{
			name: "evaluateSendGate implies the send scope",
			src: `func (s *Server) toolC() {
	tool := mcplib.NewTool("c")
	_, _ = evaluateSendGate(ctx, s.Store, id, s.AllowSend, s.DemoReviewerTGID)
	_ = tool
}`,
			want: map[string][]string{"c": {"send-gate", "telegram:messages:send"}},
		},
		{
			name: "scope through a variable is not vouched for",
			src: `func (s *Server) toolD() {
	tool := mcplib.NewTool("d")
	scope := "admin:users"
	_ = requireScope(id, scope)
	_ = tool
}`,
			want: map[string][]string{"d": {}},
		},
		{
			name: "two tools in one function are refused",
			src: `func (s *Server) toolE() {
	a := mcplib.NewTool("e1")
	b := mcplib.NewTool("e2")
	_ = requireScope(id, "admin:users")
	_, _ = a, b
}`,
			err: "registers 2 tools",
		},
		{
			name: "same tool registered twice is refused",
			src: `func (s *Server) toolF() { _ = mcplib.NewTool("f") }
func (s *Server) toolF2() { _ = mcplib.NewTool("f") }`,
			err: "registered twice",
		},
		{
			name: "functions without a registration are ignored",
			src: `func helper() { _ = requireScope(id, "admin:users") }
func (s *Server) toolG() { _ = mcplib.NewTool("g"); _ = requireScope(id, "account:manage") }`,
			want: map[string][]string{"g": {"account:manage"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset, f := parse(t, tc.src)
			got, err := gatesFromSource(fset, f)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("want error containing %q, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("tools: got %v, want %v", got, tc.want)
			}
			for name, want := range tc.want {
				g, ok := got[name]
				if !ok {
					t.Fatalf("tool %q not found in %v", name, got)
				}
				gotKeys := sortedKeys(g)
				sort.Strings(want)
				if fmt.Sprint(gotKeys) != fmt.Sprint(want) {
					t.Errorf("%s: gates got %v, want %v", name, gotKeys, want)
				}
			}
		})
	}
}

// sendScopeFromSource is retyped in this file, so it has to be checked against
// the scope evaluateSendGate actually binds. A rename in tools.go would
// otherwise leave the scan deriving a scope no handler requires, and every
// enabled entry would keep passing while naming the wrong thing.
func TestSendScopeMatchesSource(t *testing.T) {
	src, err := os.ReadFile("tools.go")
	if err != nil {
		t.Fatalf("read tools.go: %v", err)
	}
	want := `return evaluateWriteGate(ctx, store, id, allowSend, demoReviewerTGID, "` + sendScopeFromSource + `")`
	if !strings.Contains(string(src), want) {
		t.Errorf("evaluateSendGate no longer binds %q; update sendScopeFromSource to the scope it binds now", sendScopeFromSource)
	}
}
