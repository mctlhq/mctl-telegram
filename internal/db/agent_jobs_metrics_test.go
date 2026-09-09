package db

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// TestJobStatusesMatchMetricsSlice pins metrics.JobStatuses to the job-status
// constants declared here. metrics.New() pre-creates one AgentJobsTotal child
// per entry so increase() has a zero baseline (issue #591), and internal/db
// imports internal/metrics — the reverse would be an import cycle — so the
// list has to be duplicated as literals over there. This test is what stops
// the two copies drifting: adding a status here without adding it to
// metrics.JobStatuses would silently leave that child lazy again.
func TestJobStatusesMatchMetricsSlice(t *testing.T) {
	want := []string{JobPending, JobProcessing, JobCompleted, JobFailed, JobDeadLetter, JobIgnored}
	if len(metrics.JobStatuses()) != len(want) {
		t.Fatalf("metrics.JobStatuses = %v, want the %d db.Job* constants %v", metrics.JobStatuses(), len(want), want)
	}
	have := map[string]bool{}
	for _, s := range metrics.JobStatuses() {
		have[s] = true
	}
	for _, s := range want {
		if !have[s] {
			t.Errorf("db status %q missing from metrics.JobStatuses %v", s, metrics.JobStatuses())
		}
	}
}
