package mcpprobe

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// TestLegacyRun_MintsAndRequiresSession is T4: against a server that both
// mints a session identifier and insists on it, the probe records presence
// and length, never the value, and reports the identifier as required.
func TestLegacyRun_MintsAndRequiresSession(t *testing.T) {
	fake, url := newFake(t, func(f *fakeServer) {
		f.mintSession = true
		f.requireSession = true
	})

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618,
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Summary != OutcomePass {
		t.Fatalf("summary = %s, want PASS (steps %v)", report.Summary, labelsOf(report.Steps))
	}
	if !report.Session.HeaderPresent {
		t.Fatal("session header was not recorded")
	}
	if report.Session.IDLength != len(fakeSessionID) {
		t.Errorf("session id length = %d, want %d", report.Session.IDLength, len(fakeSessionID))
	}
	if report.Session.Required == nil || !*report.Session.Required {
		t.Errorf("session required = %v, want true", report.Session.Required)
	}
	if report.Mode != ModeLegacy || report.ProtocolVersion != mcp.ProtocolVersion20250618 {
		t.Errorf("mode/version = %s/%s", report.Mode, report.ProtocolVersion)
	}
	// The legacy row carries no negatives: the modern binding it would be
	// testing does not exist at this protocol version.
	if len(report.Negatives) != 0 {
		t.Errorf("legacy run recorded %d negatives, want none", len(report.Negatives))
	}
	if fake.lastSessionID() != fakeSessionID {
		t.Errorf("probe did not send the minted session id on later calls")
	}
	// A server that tracks real sessions refuses one it never issued.
	if report.Session.ForeignAccepted == nil || *report.Session.ForeignAccepted {
		t.Errorf("foreign session accepted = %v, want false for a session-bound server",
			report.Session.ForeignAccepted)
	}
}

// TestLegacyRun_RequiresTheHeaderButNotTheIssuer covers the shape today's
// server actually has, and the reason the two measurements are separate: the
// header must be carried through, yet any well-formed value passes. A router
// in front of such a server needs to forward the identifier and does not
// need to pin the request to the process that issued it.
func TestLegacyRun_RequiresTheHeaderButNotTheIssuer(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) {
		f.mintSession = true
		f.requireSession = true
		f.acceptAnySession = true
	})

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618,
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Session.Required == nil || !*report.Session.Required {
		t.Errorf("session required = %v, want true", report.Session.Required)
	}
	if report.Session.ForeignAccepted == nil || !*report.Session.ForeignAccepted {
		t.Errorf("foreign accepted = %v, want true", report.Session.ForeignAccepted)
	}
	if report.Summary != OutcomePass {
		t.Errorf("summary = %s, want PASS", report.Summary)
	}
}

// TestLegacyRun_MintedButNotRequiredIsRecorded covers a server that hands an
// identifier out and never asks for it back.
func TestLegacyRun_MintedButNotRequiredIsRecorded(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) {
		f.mintSession = true
		f.requireSession = false
	})

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618,
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !report.Session.HeaderPresent {
		t.Fatal("session header was not recorded")
	}
	if report.Session.Required == nil || *report.Session.Required {
		t.Errorf("session required = %v, want false", report.Session.Required)
	}
	if report.Session.ForeignAccepted == nil || !*report.Session.ForeignAccepted {
		t.Errorf("foreign session accepted = %v, want true for a server that only mints",
			report.Session.ForeignAccepted)
	}
	if report.Summary != OutcomePass {
		t.Errorf("summary = %s, want PASS", report.Summary)
	}
}

// TestLegacyRun_NoSessionMintedLeavesRequiredUnset keeps the report honest
// about a measurement it could not take: with no identifier there is nothing
// to withhold, so "required" stays absent rather than defaulting to false.
func TestLegacyRun_NoSessionMintedLeavesRequiredUnset(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) { f.mintSession = false })

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618,
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Session.HeaderPresent || report.Session.IDLength != 0 {
		t.Errorf("session = %+v, want empty", report.Session)
	}
	if report.Session.Required != nil {
		t.Errorf("session required = %v, want unset", *report.Session.Required)
	}
	s := stepByLabel(t, report.Steps, "tools_list_without_session")
	if s.Outcome != OutcomeSkipped || s.Reason != ReasonNoSessionID {
		t.Errorf("bare list step = %+v, want SKIPPED/no-session-id", s)
	}
	if report.Session.ForeignAccepted != nil {
		t.Errorf("foreign-session measurement = %v, want unset when nothing was minted",
			*report.Session.ForeignAccepted)
	}
}

// TestRun_RejectsIncoherentModeOptions keeps the two modes from blurring at
// the API boundary.
func TestRun_RejectsIncoherentModeOptions(t *testing.T) {
	_, url := newFake(t, nil)
	cases := []struct {
		name string
		opts Options
	}{
		{"no mode", Options{URL: url}},
		{"legacy without version", Options{URL: url, Mode: ModeLegacy}},
		{"modern with a legacy version", Options{URL: url, Mode: ModeModern, LegacyVersion: mcp.ProtocolVersion20250618}},
		{"unknown legacy version", Options{URL: url, Mode: ModeLegacy, LegacyVersion: "1999-01-01"}},
		{"modern version passed as legacy", Options{URL: url, Mode: ModeLegacy, LegacyVersion: mcp.ProtocolVersion20260728}},
		{"unknown mode", Options{URL: url, Mode: Mode("stateless")}},
		{"unknown source", Options{URL: url, Mode: ModeModern, Source: Source("production")}},
		{"empty url", Options{Mode: ModeModern}},
		{"non-http scheme", Options{URL: "ftp://example.test/mcp", Mode: ModeModern}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Run(context.Background(), tc.opts); err == nil {
				t.Fatal("Run accepted incoherent options")
			}
		})
	}
}

// TestSyntheticSessionID keeps the foreign-identifier probe well-formed: it
// must look like the identifier the server issued, or a format check would
// reject it for the wrong reason and the measurement would say "session
// bound" about a server that merely disliked the shape.
func TestSyntheticSessionID(t *testing.T) {
	issued := fakeSessionID
	got := syntheticSessionID(issued)
	if got == issued {
		t.Fatal("synthetic identifier equals the issued one; it would measure nothing")
	}
	if len(got) != len(issued) {
		t.Errorf("length = %d, want %d so the shape is preserved", len(got), len(issued))
	}
	if prefix := issued[:len("mcp-session-")]; got[:len(prefix)] != prefix {
		t.Errorf("prefix = %q, want %q", got[:len(prefix)], prefix)
	}
	if short := syntheticSessionID("tiny"); len(short) == 0 {
		t.Error("an unfamiliar identifier shape produced an empty synthetic value")
	}
}
