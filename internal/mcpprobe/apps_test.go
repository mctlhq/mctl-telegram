package mcpprobe_test

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"
)

// TestInProcess_AppsProbe_AdvertisedAgainstFlagOnEndpoint is T12: against a
// real, in-process MCP_APPS_ENABLED=true endpoint, the Apps probe reports
// the extension advertised, the triage resource listed and readable, and at
// least one tool carrying _meta.ui.resourceUri -- without the run erroring.
func TestInProcess_AppsProbe_AdvertisedAgainstFlagOnEndpoint(t *testing.T) {
	url, token := newInProcessAppsTarget(t, true)

	report, err := mcpprobe.Run(context.Background(), mcpprobe.Options{
		URL: url, Mode: mcpprobe.ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618, Token: token,
		Source: mcpprobe.SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Apps == nil {
		t.Fatal("report.Apps is nil")
	}
	if !report.Apps.ExtensionAdvertised {
		t.Error("ExtensionAdvertised = false, want true against a flag-on endpoint")
	}
	if !report.Apps.ResourceListed {
		t.Error("ResourceListed = false, want true")
	}
	if !report.Apps.ResourceReadable {
		t.Error("ResourceReadable = false, want true")
	}
	if len(report.Apps.UIToolNames) == 0 {
		t.Error("UIToolNames is empty, want at least one tool carrying _meta.ui.resourceUri")
	}
	if report.Apps.Outcome != mcpprobe.OutcomePass {
		t.Errorf("Apps.Outcome = %s, want PASS", report.Apps.Outcome)
	}
	// The Apps step must never turn a flag-on run's overall Summary into
	// anything it would not otherwise have been on its own -- this endpoint
	// is otherwise ordinary and healthy, so the run itself still passes.
	if report.Summary != mcpprobe.OutcomePass {
		t.Errorf("Summary = %s, want PASS (steps %+v)", report.Summary, report.Steps)
	}
}

// TestInProcess_AppsProbe_NotAdvertisedAgainstFlagOffEndpoint is T12's other
// half: against the default, flag-off endpoint, the probe reports "not
// advertised" -- never a failure -- and the overall run still passes.
func TestInProcess_AppsProbe_NotAdvertisedAgainstFlagOffEndpoint(t *testing.T) {
	url, token := newInProcessAppsTarget(t, false)

	report, err := mcpprobe.Run(context.Background(), mcpprobe.Options{
		URL: url, Mode: mcpprobe.ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618, Token: token,
		Source: mcpprobe.SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Apps == nil {
		t.Fatal("report.Apps is nil")
	}
	if report.Apps.ExtensionAdvertised {
		t.Error("ExtensionAdvertised = true, want false against the flag-off default")
	}
	if report.Apps.Outcome != mcpprobe.OutcomeSkipped {
		t.Errorf("Apps.Outcome = %s, want SKIPPED (not a failure) against a flag-off endpoint", report.Apps.Outcome)
	}
	if report.Apps.Reason != mcpprobe.ReasonNotApplicable {
		t.Errorf("Apps.Reason = %s, want %s", report.Apps.Reason, mcpprobe.ReasonNotApplicable)
	}
	if report.Summary != mcpprobe.OutcomePass {
		t.Errorf("Summary = %s, want PASS: the Apps probe must not fail a normal flag-off run", report.Summary)
	}
}
