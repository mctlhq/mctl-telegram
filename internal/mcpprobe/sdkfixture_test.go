package mcpprobe

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// newSDKServer builds a target out of the pinned SDK's own server rather than
// this package's hand-written fake.
//
// The two fixtures answer different questions and neither replaces the other.
// The fake is deliberately permissive: it is the only way to ask what the
// probe does when a server does NOT enforce the modern binding, which is the
// case the read-only guard exists for. This one is the opposite — it enforces
// exactly what a conforming deployment enforces, because the SDK is the same
// code a real server runs. A probe that agreed with a hand-rolled fake about
// the wire format but disagreed with the SDK would be measuring its author's
// beliefs, and this fixture is what rules that out.
func newSDKServer(t *testing.T, opts ...mcpserver.StreamableHTTPOption) string {
	t.Helper()

	core := mcpserver.NewMCPServer("sdk-fixture", "1.0.0", mcpserver.WithToolCapabilities(true))
	core.AddTool(
		mcp.NewTool(DefaultTool, mcp.WithDescription("read-only status"),
			mcp.WithToolAnnotation(mcp.ToolAnnotation{ReadOnlyHint: mcp.ToBoolPtr(true)})),
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText(`{"can_send":true}`), nil
		},
	)
	core.AddTool(
		mcp.NewTool("send_message", mcp.WithDescription("mutating"),
			mcp.WithToolAnnotation(mcp.ToolAnnotation{ReadOnlyHint: mcp.ToBoolPtr(false)})),
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("sent"), nil
		},
	)

	ts := httptest.NewServer(mcpserver.NewStreamableHTTPServer(core, opts...))
	t.Cleanup(ts.Close)
	return ts.URL + "/mcp"
}

// TestAgainstSDKServer_Modern is the fidelity check: every modern request this
// package builds is accepted by the SDK's own validator, and every negative it
// builds is refused by it. If the request shape drifts from the specification,
// this test fails where a test against our own fake would not.
func TestAgainstSDKServer_Modern(t *testing.T) {
	url := newSDKServer(t)

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Summary != OutcomePass {
		t.Fatalf("summary = %s\nsteps: %+v\nnegatives: %+v", report.Summary, report.Steps, report.Negatives)
	}
	if report.Server.Name != "sdk-fixture" {
		t.Errorf("server name = %q, want the SDK fixture's own identity", report.Server.Name)
	}
	if report.Session.HeaderPresent {
		t.Error("the SDK minted a session id on the modern path; it must not")
	}
	for _, s := range report.Negatives {
		if s.Outcome != OutcomePass {
			t.Errorf("the SDK accepted a request it should refuse: %+v", s)
		}
	}
}

// TestAgainstSDKServer_Legacy pins the legacy observations against the real
// SDK, including the two that decide whether anything in front of the server
// needs session affinity.
func TestAgainstSDKServer_Legacy(t *testing.T) {
	url := newSDKServer(t)

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618,
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Summary != OutcomePass {
		t.Fatalf("summary = %s\nsteps: %+v", report.Summary, report.Steps)
	}
	if !report.Session.HeaderPresent {
		t.Error("the SDK's default manager minted no session id at initialize")
	}
	if report.Session.Required == nil || report.Session.ForeignAccepted == nil {
		t.Fatalf("session observations incomplete: %+v", report.Session)
	}
	// The SDK's default manager validates the identifier's shape and not its
	// existence, so both halves hold: the header is needed, its issuer is not.
	if !*report.Session.Required {
		t.Error("the SDK served a request with no session header at all")
	}
	if !*report.Session.ForeignAccepted {
		t.Error("the SDK refused a well-formed identifier it never issued")
	}
}

// TestAgainstSDKServer_ReadOnlyGuardStillRefuses confirms the guard is the
// probe's own decision and not a consequence of the server's validation: the
// SDK would happily run send_message, and the probe still declines to ask.
func TestAgainstSDKServer_ReadOnlyGuardStillRefuses(t *testing.T) {
	url := newSDKServer(t)

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Tool: "send_message",
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	call := stepByLabel(t, report.Steps, "tools_call_readonly")
	if call.Outcome != OutcomeSkipped || call.Reason != ReasonToolNotReadOnly {
		t.Fatalf("call step = %+v, want SKIPPED/tool-not-read-only", call)
	}
	if report.Summary == OutcomePass {
		t.Error("summary = PASS although the mandatory read-only call never ran")
	}
}
