package mcpprobe_test

import (
	"context"
	"net/http"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"
)

// T1: modern request fixture follows the pinned mcp-go v1.0.0 2026-07-28
// request shape and succeeds against a modern fake/server.
func TestProbeModern_DiscoverToolsListAndReadOnlyCall(t *testing.T) {
	srv := newFixtureServer(t)

	result, err := mcpprobe.ProbeModern(context.Background(), mcpprobe.ModernConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("ProbeModern: %v", err)
	}

	if result.ProtocolVersion != mcpprobe.DefaultModernProtocolVersion {
		t.Errorf("ProtocolVersion = %q, want %q", result.ProtocolVersion, mcpprobe.DefaultModernProtocolVersion)
	}

	if result.Discover == nil {
		t.Fatal("Discover observation missing")
	}
	if result.Discover.HTTPStatus != http.StatusOK {
		t.Fatalf("discover HTTP status = %d, want 200", result.Discover.HTTPStatus)
	}
	found := false
	for _, v := range result.Discover.SupportedVersions {
		if v == mcplib.ProtocolVersion20260728 {
			found = true
		}
	}
	if !found {
		t.Errorf("discover supportedVersions = %v, want it to contain %q", result.Discover.SupportedVersions, mcplib.ProtocolVersion20260728)
	}
	// The modern path must never mint/require Mcp-Session-Id (SEP-2567);
	// this is an observation, not a hard-coded assumption (requirements.md
	// acceptance criterion A).
	if result.Discover.SessionIDPresent {
		t.Error("modern server/discover response carried Mcp-Session-Id, want none")
	}

	if result.ToolsList == nil {
		t.Fatal("ToolsList observation missing")
	}
	if result.ToolsList.HTTPStatus != http.StatusOK {
		t.Fatalf("tools/list HTTP status = %d, want 200", result.ToolsList.HTTPStatus)
	}
	if result.ToolsList.ToolCount != 2 {
		t.Fatalf("tools/list tool count = %d, want 2", result.ToolsList.ToolCount)
	}

	if result.ToolCall == nil {
		t.Fatal("ToolCall observation missing")
	}
	if !result.ToolCall.Attempted {
		t.Fatalf("ToolCall not attempted: refusal=%q", result.ToolCall.RefusalReason)
	}
	if result.ToolCall.ToolName != mcpprobe.DefaultReadOnlyTool {
		t.Errorf("ToolCall.ToolName = %q, want %q", result.ToolCall.ToolName, mcpprobe.DefaultReadOnlyTool)
	}
	if result.ToolCall.IsError {
		t.Error("read-only tools/call reported isError=true, want a clean success")
	}
	if result.ToolCall.SessionIDPresent {
		t.Error("modern tools/call response carried Mcp-Session-Id, want none")
	}
}

// T2: modern `initialize` is exercised only as a negative removed-method
// test, never used to bootstrap modern requests (ProbeModern above never
// calls it for that purpose).
func TestProbeModern_InitializeIsRemovedMethodNegativeTest(t *testing.T) {
	srv := newFixtureServer(t)

	result, err := mcpprobe.ProbeModern(context.Background(), mcpprobe.ModernConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("ProbeModern: %v", err)
	}

	neg := result.InitializeRemovedMethod
	if neg == nil {
		t.Fatal("InitializeRemovedMethod negative case missing")
	}
	if !neg.Rejected {
		t.Errorf("initialize in modern mode was not rejected: status=%d code=%d", neg.HTTPStatus, neg.JSONRPCErrorCode)
	}
	if neg.HTTPStatus != http.StatusNotFound {
		t.Errorf("initialize removed-method HTTP status = %d, want 404", neg.HTTPStatus)
	}
	if neg.JSONRPCErrorCode != mcplib.METHOD_NOT_FOUND {
		t.Errorf("initialize removed-method JSON-RPC code = %d, want %d", neg.JSONRPCErrorCode, mcplib.METHOD_NOT_FOUND)
	}
}

// T3: missing/mismatched modern method/name headers are rejected and
// recorded correctly.
func TestProbeModern_HeaderNegativeCasesAreAllRejected(t *testing.T) {
	srv := newFixtureServer(t)

	result, err := mcpprobe.ProbeModern(context.Background(), mcpprobe.ModernConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("ProbeModern: %v", err)
	}

	if len(result.HeaderNegativeTests) == 0 {
		t.Fatal("no header negative cases recorded")
	}
	for _, c := range result.HeaderNegativeTests {
		if !c.Rejected {
			t.Errorf("case %q was not rejected: status=%d code=%d", c.Name, c.HTTPStatus, c.JSONRPCErrorCode)
		}
		if c.JSONRPCErrorCode != mcplib.HEADER_MISMATCH {
			t.Errorf("case %q code = %d, want HEADER_MISMATCH (%d)", c.Name, c.JSONRPCErrorCode, mcplib.HEADER_MISMATCH)
		}
	}
}

// T5: read-only guard refuses send_message (and any unverified tool) before
// issuing tools/call.
func TestProbeModern_ReadOnlyGuardRefusesNonReadOnlyTool(t *testing.T) {
	srv := newFixtureServer(t)

	result, err := mcpprobe.ProbeModern(context.Background(), mcpprobe.ModernConfig{
		BaseURL:      srv.URL,
		ReadOnlyTool: "send_message",
	})
	if err != nil {
		t.Fatalf("ProbeModern: %v", err)
	}

	if result.ToolCall.Attempted {
		t.Fatal("guard let a non-read-only tool through to tools/call")
	}
	if result.ToolCall.RefusalReason == "" {
		t.Error("refusal recorded with no reason")
	}
}

func TestProbeModern_ReadOnlyGuardRefusesUnknownTool(t *testing.T) {
	srv := newFixtureServer(t)

	result, err := mcpprobe.ProbeModern(context.Background(), mcpprobe.ModernConfig{
		BaseURL:      srv.URL,
		ReadOnlyTool: "does_not_exist",
	})
	if err != nil {
		t.Fatalf("ProbeModern: %v", err)
	}

	if result.ToolCall.Attempted {
		t.Fatal("guard let an unknown tool through to tools/call")
	}
}

// The header-negative battery sends real tools/call bodies. Against a server
// that does not enforce the SEP-2243 headers -- the class this probe surveys
// -- those bodies are dispatched, so the battery may never name a tool the
// read-only guard refused (requirements.md acceptance criterion C). This
// pins that substitution: it fails if the sentinel fallback in ProbeModern is
// removed, which the guard tests above cannot detect because their mcp-go
// fixture rejects the battery on headers before dispatch either way.
func TestProbeModern_HeaderNegativesNeverNameAGuardRefusedTool(t *testing.T) {
	srv, rec := newHeaderTolerantFixture(t)

	result, err := mcpprobe.ProbeModern(context.Background(), mcpprobe.ModernConfig{
		BaseURL:      srv.URL,
		ReadOnlyTool: "send_message",
	})
	if err != nil {
		t.Fatalf("ProbeModern: %v", err)
	}

	if result.ToolCall.Attempted {
		t.Fatal("guard let the non-read-only tool through to tools/call")
	}
	if len(result.HeaderNegativeTests) == 0 {
		t.Fatal("no header negative cases recorded")
	}

	names := rec.snapshot()
	if len(names) == 0 {
		t.Fatal("fixture saw no tools/call at all; the header-negative battery never ran")
	}
	for _, n := range names {
		if n == "send_message" {
			t.Fatalf("a tools/call named the guard-refused tool: recorded names = %v", names)
		}
	}
}
