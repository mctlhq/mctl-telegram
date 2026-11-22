package connector

import (
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
)

// TestPAToolRouteMatchesWorker: the worker's copy of the executor route is
// this package's (the worker does not import the server packages).
func TestPAToolRouteMatchesWorker(t *testing.T) {
	if agentworker.PARouteTool != RouteTool {
		t.Fatalf("agentworker.PARouteTool = %q, want %q", agentworker.PARouteTool, RouteTool)
	}
	if agentworker.PAMaxToolRequestBytes != maxToolRequestBytes {
		t.Fatalf("agentworker.PAMaxToolRequestBytes = %d, want %d", agentworker.PAMaxToolRequestBytes, maxToolRequestBytes)
	}
}

// toolCallMargin is the least the worker must wait past the dispatcher's
// own call bound, for the listing, audit and token refresh around it.
const toolCallMargin = 15 * time.Second

// TestPAToolTimeoutCoversDispatcher: the worker waits longer for a /tool
// answer than the dispatcher may take, so a slow call the server completes
// is not abandoned by the worker. Raising DefaultCallTimeout past the
// worker's timeout fails here.
func TestPAToolTimeoutCoversDispatcher(t *testing.T) {
	if agentworker.PAToolCallTimeout < DefaultCallTimeout+toolCallMargin {
		t.Fatalf("worker /tool timeout %v < dispatcher call timeout %v + %v", agentworker.PAToolCallTimeout, DefaultCallTimeout, toolCallMargin)
	}
}
