package mcp

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// The error series of a healthy service must exist at 0 before the first
// error, so that error is an ordinary increment rather than a series that
// starts at 1 (docs/slo.md, "Minimum-volume guard").
func TestInitToolInvocationSeries(t *testing.T) {
	reg := metrics.New()
	s := &Server{Metrics: reg}
	srv := s.newMCPServer()
	tools := srv.ListTools()
	if len(tools) == 0 {
		t.Fatal("no tools registered")
	}

	if got := testutil.CollectAndCount(reg.ToolInvocationsTotal); got != 0 {
		t.Fatalf("series before init = %d, want 0 (a counter child exists only after first use)", got)
	}

	s.initToolInvocationSeries(srv)

	// Exactly tool x status for user traffic: no canary series, none for a
	// tool that is not registered.
	if got, want := testutil.CollectAndCount(reg.ToolInvocationsTotal), len(tools)*len(toolInvocationStatuses); got != want {
		t.Fatalf("series after init = %d, want %d (%d tools x %d statuses)", got, want, len(tools), len(toolInvocationStatuses))
	}
	for name := range tools {
		for _, status := range toolInvocationStatuses {
			if v := testutil.ToFloat64(reg.ToolInvocationsTotal.WithLabelValues(name, status, metrics.TrafficUser)); v != 0 {
				t.Fatalf("{%s,%s,user} = %v, want 0", name, status, v)
			}
		}
	}

	// The first error is an increment of an existing series, not a new one.
	tool := ""
	for name := range tools {
		tool = name
		break
	}
	reg.ToolInvocationsTotal.WithLabelValues(tool, "error", metrics.TrafficUser).Inc()
	if got, want := testutil.CollectAndCount(reg.ToolInvocationsTotal), len(tools)*len(toolInvocationStatuses); got != want {
		t.Fatalf("series after the first error = %d, want %d (no new series)", got, want)
	}
	if v := testutil.ToFloat64(reg.ToolInvocationsTotal.WithLabelValues(tool, "error", metrics.TrafficUser)); v != 1 {
		t.Fatalf("{%s,error,user} = %v, want 1", tool, v)
	}
}

// The initialised statuses are the four the code can write
// (callRecord.metricStatus). Pinned literally: a test that read
// toolInvocationStatuses would stay green if a status were dropped from it.
func TestToolInvocationStatusesAreTheFourTheCodeWrites(t *testing.T) {
	want := map[string]bool{"ok": true, "error": true, statusCallerError: true, statusNoSession: true}
	if len(toolInvocationStatuses) != len(want) {
		t.Fatalf("toolInvocationStatuses = %v, want exactly ok, error, caller_error, no_session", toolInvocationStatuses)
	}
	for _, st := range toolInvocationStatuses {
		if !want[st] {
			t.Fatalf("unexpected status %q in toolInvocationStatuses", st)
		}
	}
	if statusCallerError != "caller_error" || statusNoSession != "no_session" {
		t.Fatalf("status constants changed (%q, %q): the SLI selectors and the init list must change with them", statusCallerError, statusNoSession)
	}
}

func TestInitToolInvocationSeries_NoRegistry(t *testing.T) {
	s := &Server{}
	s.initToolInvocationSeries(s.newMCPServer()) // must not panic
}

// HTTPHandler is the one place that calls it at startup; a test on the method
// alone would stay green if the call were dropped.
func TestHTTPHandlerInitialisesToolInvocationSeries(t *testing.T) {
	reg := metrics.New()
	s := &Server{Metrics: reg}
	_ = s.HTTPHandler()
	if got := testutil.CollectAndCount(reg.ToolInvocationsTotal); got == 0 {
		t.Fatal("HTTPHandler left mctl_tool_invocations_total with no series")
	}
}
