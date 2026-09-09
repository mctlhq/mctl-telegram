package agentapi

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// TestPolicySurfaceForOwnerTool pins the mapping handleOwnerFacing's two
// callers rely on, and that an unmapped name is reported as unknown rather
// than folded into one of the real surfaces — a silent fold would corrupt
// that surface's series instead of surfacing the gap.
func TestPolicySurfaceForOwnerTool(t *testing.T) {
	for _, tc := range []struct{ tool, want string }{
		{"send_owner_summary", metrics.PolicySurfaceOwnerSummary},
		{"request_owner_approval", metrics.PolicySurfaceOwnerApproval},
		{"", metrics.PolicySurfaceUnknown},
		{"send_owner_summary_v2", metrics.PolicySurfaceUnknown},
	} {
		if got := policySurfaceForOwnerTool(tc.tool); got != tc.want {
			t.Errorf("policySurfaceForOwnerTool(%q) = %q, want %q", tc.tool, got, tc.want)
		}
	}
}
