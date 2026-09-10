package mcpprobe

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// TestReadOnlyGuard_RefusesMutatingTool is T5. The guard is what keeps a
// compatibility probe from being a way to send someone a message.
func TestReadOnlyGuard_RefusesMutatingTool(t *testing.T) {
	fake, url := newFake(t, func(f *fakeServer) { f.modern = true })

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
	if got := countMethod(fake.dispatchedMethods(), string(mcp.MethodToolsCall)); got != 0 {
		t.Fatalf("a mutating tool was invoked %d times; the guard must prevent every call", got)
	}
	// A refused call is not a passing run: the mandatory cell did not
	// execute, so the summary must not read PASS.
	if report.Summary == OutcomePass {
		t.Error("summary = PASS despite the read-only call never executing")
	}
}

// TestReadOnlyGuard_RefusesUnannotatedTool pins the conservative reading of a
// missing annotation. Silence is not a promise of safety.
func TestReadOnlyGuard_RefusesUnannotatedTool(t *testing.T) {
	fake, url := newFake(t, func(f *fakeServer) { f.modern = true })

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Tool: "unannotated_tool",
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	call := stepByLabel(t, report.Steps, "tools_call_readonly")
	if call.Outcome != OutcomeSkipped || call.Reason != ReasonToolNotReadOnly {
		t.Errorf("call step = %+v, want SKIPPED/tool-not-read-only", call)
	}
	if got := countMethod(fake.dispatchedMethods(), string(mcp.MethodToolsCall)); got != 0 {
		t.Errorf("an unannotated tool was invoked %d times", got)
	}
}

// TestReadOnlyGuard_RefusesAbsentTool distinguishes "not offered here" from
// "offered but mutating", because they lead an operator to different fixes.
func TestReadOnlyGuard_RefusesAbsentTool(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) { f.modern = true })

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Tool: "no_such_tool",
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	call := stepByLabel(t, report.Steps, "tools_call_readonly")
	if call.Reason != ReasonToolNotListed {
		t.Errorf("call step reason = %q, want tool-not-listed", call.Reason)
	}
}

// TestSelectReadOnlyTool covers the guard directly, including the annotation
// shapes the wire can produce.
func TestSelectReadOnlyTool(t *testing.T) {
	yes, no := true, false
	tools := []ToolInfo{
		{Name: "read", ReadOnly: &yes},
		{Name: "write", ReadOnly: &no},
		{Name: "silent"},
	}
	if _, err := selectReadOnlyTool(tools, "read"); err != nil {
		t.Errorf("read-only tool rejected: %v", err)
	}
	for _, name := range []string{"write", "silent"} {
		if _, err := selectReadOnlyTool(tools, name); err == nil {
			t.Errorf("selectReadOnlyTool accepted %q", name)
		}
	}
	if _, err := selectReadOnlyTool(tools, "absent"); err == nil {
		t.Error("selectReadOnlyTool accepted a tool that is not listed")
	}
}
