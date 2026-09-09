package policy

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// TestDenyCodesMatchMetricsList pins metrics' copy of the DenyCode set to the
// constants declared here. metrics.New() pre-creates one AgentPolicyDenialsTotal
// child per (reason, surface) pair so increase() has a zero baseline (issue
// #591), and the list is duplicated as literals over there to keep that package
// a leaf rather than have it depend on this one. This test is what stops the
// two copies drifting: adding a DenyCode here without adding it there would
// silently leave that reason's children lazy again.
func TestDenyCodesMatchMetricsList(t *testing.T) {
	want := []DenyCode{
		DenyGlobalKill, DenyUserMismatch, DenyModeOff, DenyModeUnrecognized,
		DenyAutopilotPaused, DenyConvTakenOver, DenyConvClosed, DenyConvPaused,
		DenyConvStateUnknown, DenySenderBlocked, DenyActionTypeUnknown,
		DenyPeerMismatch, DenyNoDisclosure, DenyEmptyReply, DenyReplyTooLong,
		DenyReplyURL, DenyReplyCredentials, DenyUnknown,
	}
	have := map[string]bool{}
	for _, r := range metrics.PolicyDenyReasons() {
		have[r] = true
	}
	if len(have) != len(want) {
		t.Fatalf("metrics.PolicyDenyReasons() has %d entries, want the %d DenyCode constants", len(have), len(want))
	}
	for _, c := range want {
		if !have[string(c)] {
			t.Errorf("DenyCode %q missing from metrics.PolicyDenyReasons()", c)
		}
	}
}
