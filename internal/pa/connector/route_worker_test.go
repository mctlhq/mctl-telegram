package connector

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
)

// TestPAToolRouteMatchesWorker: the worker's copy of the executor route is
// this package's (the worker does not import the server packages).
func TestPAToolRouteMatchesWorker(t *testing.T) {
	if agentworker.PARouteTool != RouteTool {
		t.Fatalf("agentworker.PARouteTool = %q, want %q", agentworker.PARouteTool, RouteTool)
	}
}
