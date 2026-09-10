package mcpprobe

import (
	"context"
	"net/http"
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
		"missing_protocol_version_header",
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

// TestModernNegatives_AuthRefusalIsNotEnforcement is the regression for a
// false positive that survived the first review round.
//
// A negative probe proves something only when the same request succeeds
// unmutated. Against an endpoint that serves discovery anonymously but wants
// a bearer for the capability calls, the probe cannot tell a header refusal
// from an authentication one, because it never saw the unmutated request
// work. Reporting enforcement from that would be the exact failure this
// package exists to prevent: a cell that is green for a reason unrelated to
// the claim it makes.
func TestModernNegatives_AuthRefusalIsNotEnforcement(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) {
		f.modern = true
		f.unauthorizedMethods = map[string]bool{
			string(mcp.MethodToolsList):  true,
			string(mcp.MethodToolsCall):  true,
			string(mcp.MethodInitialize): true,
		}
	})

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, s := range report.Negatives {
		if s.Outcome == OutcomePass {
			t.Errorf("%s claimed enforcement (status %d) although the unmutated request "+
				"never succeeded; with no working baseline a refusal cannot be attributed "+
				"to the mutated header", s.Label, s.HTTPStatus)
		}
	}
	if report.Summary == OutcomePass {
		t.Error("summary = PASS although nothing was actually measured")
	}
}

// TestModernNegatives_AuthRefusalOnItsOwnRequestIsNotEnforcement covers the
// remaining shape: the baseline holds, so the probe knows the endpoint works,
// and yet this particular request is turned away by something that never
// looked at the protocol.
//
// The fixture models an edge that refuses what it cannot route: a request
// with no Mcp-Method header gets 403 before any protocol validation. The
// positive calls carry the header and succeed, so the baseline is genuinely
// established — and the probe must still decline to call that 403 evidence
// of the modern binding, because it is not.
func TestModernNegatives_AuthRefusalOnItsOwnRequestIsNotEnforcement(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) {
		f.modern = true
		f.unroutableIsForbidden = true
	})

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The baseline really did hold: the positive path completed.
	if got := stepByLabel(t, report.Steps, "tools_list").Outcome; got != OutcomePass {
		t.Fatalf("tools_list = %s; the fixture was meant to serve the unmutated calls", got)
	}

	missing := stepByLabel(t, report.Negatives, "missing_method_header")
	if missing.Outcome != OutcomeSkipped || missing.Reason != ReasonUnauthenticatedProbe {
		t.Errorf("missing_method_header = %+v, want SKIPPED/unauthenticated-probe: a 403 from an "+
			"edge that never parsed the request is not proof the server enforces the binding", missing)
	}
	if missing.HTTPStatus != http.StatusForbidden {
		t.Errorf("missing_method_header status = %d, want 403", missing.HTTPStatus)
	}
	// And a case whose header survives routing is still measured normally.
	mismatched := stepByLabel(t, report.Negatives, "mismatched_method_header")
	if mismatched.Outcome != OutcomePass {
		t.Errorf("mismatched_method_header = %+v, want PASS; it carries a header and is a real "+
			"protocol refusal", mismatched)
	}
	if report.Summary == OutcomePass {
		t.Error("summary = PASS although one mandatory negative was never measured")
	}
}

// TestModernNegatives_AllMeasuredAgainstAConformingServer is the control: with
// nothing interfering, every mandatory negative is genuinely exercised.
func TestModernNegatives_AllMeasuredAgainstAConformingServer(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) { f.modern = true })

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, label := range mandatoryNegatives(ModeModern) {
		s := stepByLabel(t, report.Negatives, label)
		if s.Outcome != OutcomePass {
			t.Errorf("%s = %+v, want PASS against a conforming server", label, s)
		}
	}
}
