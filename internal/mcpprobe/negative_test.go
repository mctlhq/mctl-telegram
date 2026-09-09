package mcpprobe

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// TestModernNegatives_HeaderFaultsAreRejectedBeforeDispatch is T3.
//
// It asserts more than "the server said no": it asserts the request never
// reached dispatch. A server that validated the header after running the
// method would satisfy a status-code assertion while still having executed
// the call, which is precisely the failure mode a routing gateway must not
// inherit.
func TestModernNegatives_HeaderFaultsAreRejectedBeforeDispatch(t *testing.T) {
	fake, url := newFake(t, func(f *fakeServer) { f.modern = true })

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, label := range []string{
		"missing_method_header",
		"mismatched_method_header",
		"missing_name_header",
		"mismatched_name_header",
	} {
		s := stepByLabel(t, report.Negatives, label)
		if s.Outcome != OutcomePass {
			t.Errorf("%s = %+v, want PASS", label, s)
		}
		if s.Reason != ReasonHeaderMismatch {
			t.Errorf("%s reason = %q, want header-mismatch", label, s.Reason)
		}
	}

	// One legitimate tools/call from the positive path, and nothing from the
	// four header faults.
	if got := countMethod(fake.dispatchedMethods(), string(mcp.MethodToolsCall)); got != 1 {
		t.Errorf("tools/call reached dispatch %d times; want exactly the one legitimate call", got)
	}
	if got := countMethod(fake.dispatchedMethods(), string(mcp.MethodToolsList)); got != 1 {
		t.Errorf("tools/list reached dispatch %d times; want exactly the one legitimate list", got)
	}
}

// TestModernNegatives_ToleratedFaultFailsTheRun confirms the negatives are
// load-bearing: against a server that ignores the modern binding, the
// negative probes report FAIL rather than quietly passing.
func TestModernNegatives_ToleratedFaultFailsTheRun(t *testing.T) {
	// A fake that answers modern methods but performs no header validation.
	_, url := newFake(t, nil)

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	tolerated := stepByLabel(t, report.Negatives, "missing_method_header")
	if tolerated.Outcome != OutcomeFail || tolerated.Reason != ReasonUnexpectedSuccess {
		t.Errorf("missing_method_header = %+v, want FAIL/unexpected-success", tolerated)
	}
	if report.Summary != OutcomeFail {
		t.Errorf("summary = %s, want FAIL", report.Summary)
	}
}
