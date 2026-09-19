package mcpprobe

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// TestModernRun_UsesDiscoverAndNeverInitializes is T1 and T2 together,
// because they are two halves of one claim: a modern run bootstraps with
// server/discover, and the only initialize it ever sends is the negative
// probe that expects a rejection.
func TestModernRun_UsesDiscoverAndNeverInitializes(t *testing.T) {
	fake, url := newFake(t, func(f *fakeServer) { f.modern = true })

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Summary != OutcomePass {
		t.Fatalf("summary = %s, want PASS (steps %v)", report.Summary, labelsOf(report.Steps))
	}

	methods := fake.dispatchedMethods()
	if got := countMethod(methods, string(mcp.MethodInitialize)); got != 0 {
		t.Errorf("initialize reached dispatch %d times in modern mode; want 0", got)
	}
	if methods[0] != string(mcp.MethodServerDiscover) {
		t.Errorf("first dispatched method = %q, want server/discover", methods[0])
	}
	if got := countMethod(methods, string(mcp.MethodToolsCall)); got != 1 {
		t.Errorf("tools/call dispatched %d times, want exactly 1", got)
	}

	if report.Server.Name != "fake-telegram" || report.Server.Version != "9.9.9" {
		t.Errorf("server identity = %+v", report.Server)
	}
	if len(report.Server.SupportedVersions) == 0 {
		t.Error("discover did not record supported versions")
	}
	if report.Session.HeaderPresent {
		t.Error("modern mode recorded a session id; the modern path must not mint one")
	}
	if report.ProtocolVersion != mcp.ProtocolVersion20260728 {
		t.Errorf("protocol version = %q", report.ProtocolVersion)
	}
	call := stepByLabel(t, report.Steps, "tools_call_readonly")
	if call.Outcome != OutcomePass || call.Tool != DefaultTool {
		t.Errorf("read-only call step = %+v", call)
	}
}

// TestModernRun_InitializeIsANegativeProbeOnly is the other half of T2: the
// removed-method rejection is recorded as a negative, never as the way the
// run got started.
func TestModernRun_InitializeIsANegativeProbeOnly(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) { f.modern = true })

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	neg := stepByLabel(t, report.Negatives, "modern_initialize_removed")
	if neg.Outcome != OutcomePass {
		t.Fatalf("initialize negative = %+v, want PASS", neg)
	}
	if neg.JSONRPCode == nil || *neg.JSONRPCode != -32601 {
		t.Errorf("initialize negative code = %v, want -32601", neg.JSONRPCode)
	}
	for _, s := range report.Steps {
		if s.Method == string(mcp.MethodInitialize) {
			t.Errorf("initialize appears as a positive step: %+v", s)
		}
	}
}

// TestModernRun_ObservesASessionMintedOnToolsList pins the widened
// observation from #605: the "modern path mints no session identifier" claim
// has to cover every response on the path, not just discover. Here the
// fixture only mints a session on tools/list, which the fixture in
// TestModernRun_UsesDiscoverAndNeverInitializes never does.
func TestModernRun_ObservesASessionMintedOnToolsList(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) {
		f.modern = true
		f.mintSessionOn = map[string]bool{string(mcp.MethodToolsList): true}
	})

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !report.Session.HeaderPresent {
		t.Error("tools/list minted a session id the report did not observe")
	}
	if report.Session.IDLength != len(fakeSessionID) {
		t.Errorf("id length = %d, want %d", report.Session.IDLength, len(fakeSessionID))
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(encoded), fakeSessionID) {
		t.Error("report serialized the session identifier itself")
	}
}

// TestModernRun_ObservesASessionMintedOnToolsCall is
// TestModernRun_ObservesASessionMintedOnToolsList's counterpart for the last
// step of the modern path: the read-only tools/call.
func TestModernRun_ObservesASessionMintedOnToolsCall(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) {
		f.modern = true
		f.mintSessionOn = map[string]bool{string(mcp.MethodToolsCall): true}
	})

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !report.Session.HeaderPresent {
		t.Error("tools/call minted a session id the report did not observe")
	}
	if report.Session.IDLength != len(fakeSessionID) {
		t.Errorf("id length = %d, want %d", report.Session.IDLength, len(fakeSessionID))
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(encoded), fakeSessionID) {
		t.Error("report serialized the session identifier itself")
	}
}

// TestModernRun_NoSilentFallbackToLegacy pins the rule that gives the whole
// report its meaning. A server that refuses server/discover must yield a
// failed modern row, not a legacy handshake wearing a modern label.
func TestModernRun_NoSilentFallbackToLegacy(t *testing.T) {
	// A pre-2026-07-28 server: server/discover is an unknown method to it.
	fake, url := newFake(t, func(f *fakeServer) { f.legacyOnly = true })

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Mode != ModeModern {
		t.Fatalf("mode = %s, want it to stay modern", report.Mode)
	}
	if report.Summary != OutcomeFail {
		t.Fatalf("summary = %s, want FAIL", report.Summary)
	}
	discover := stepByLabel(t, report.Steps, "discover")
	if discover.Outcome != OutcomeFail {
		t.Errorf("discover = %+v, want FAIL", discover)
	}
	// Downstream steps are recorded as skipped, not silently absent, so the
	// report says why they were not measured.
	for _, label := range []string{"tools_list", "tools_call_readonly"} {
		s := stepByLabel(t, report.Steps, label)
		if s.Outcome != OutcomeSkipped || s.Reason != ReasonPrerequisiteFailed {
			t.Errorf("%s = %+v, want SKIPPED/prerequisite-failed", label, s)
		}
	}
	// The run must not proceed to the capability calls on a failed
	// discovery, and must not reach for the legacy lifecycle to rescue them.
	for _, method := range []mcp.MCPMethod{mcp.MethodToolsList, mcp.MethodToolsCall} {
		if got := countMethod(fake.dispatchedMethods(), string(method)); got != 0 {
			t.Errorf("%s dispatched %d times after a failed discovery; want 0", method, got)
		}
	}
}
