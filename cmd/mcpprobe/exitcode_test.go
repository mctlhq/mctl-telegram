package main

import "testing"

// TestExitCodeForSummary pins the distinction finalize exists to make. The
// CLI is finalize's only consumer, so collapsing an unmeasured run into
// success here would hand that distinction straight back.
func TestExitCodeForSummary(t *testing.T) {
	cases := []struct {
		summary string
		want    int
	}{
		{"PASS", exitOK},
		{"FAIL", exitFinding},
		{"BLOCKED", exitFinding},
		{"SKIPPED", exitUnmeasured},
		{"PENDING-OPERATOR", exitUnmeasured},
	}
	for _, tc := range cases {
		if got := exitCodeForSummary(tc.summary); got != tc.want {
			t.Errorf("summary %s -> exit %d, want %d", tc.summary, got, tc.want)
		}
	}
}
