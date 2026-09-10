package main

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"
)

// TestExitCodeForSummary pins the distinction finalize exists to make. The
// CLI is finalize's only consumer, so collapsing an unmeasured run into
// success here would hand that distinction straight back.
func TestExitCodeForSummary(t *testing.T) {
	// Driven from the constants, not from re-spelled literals: a table that
	// repeats the strings the switch matches cannot catch the two drifting
	// apart across the package boundary.
	cases := []struct {
		summary mcpprobe.Outcome
		want    int
	}{
		{mcpprobe.OutcomePass, exitOK},
		{mcpprobe.OutcomeFail, exitFinding},
		{mcpprobe.OutcomeBlocked, exitFinding},
		{mcpprobe.OutcomeSkipped, exitUnmeasured},
		{mcpprobe.OutcomePending, exitUnmeasured},
	}
	for _, tc := range cases {
		if got := exitCodeForSummary(tc.summary); got != tc.want {
			t.Errorf("summary %s -> exit %d, want %d", tc.summary, got, tc.want)
		}
	}
}
