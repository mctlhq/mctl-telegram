package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestOwnerHoldReasons_EveryHoldReasonIsRewritten drives Evaluate into each
// require-approval branch and checks the owner sees wording, not the stored
// audit string (#989).
func TestOwnerHoldReasons_EveryHoldReasonIsRewritten(t *testing.T) {
	cases := []struct {
		name string
		mut  func(in *Input)
		want string
	}{
		{"observe", func(in *Input) { in.Profile.Mode = db.AgentModeObserve }, "observe mode is on"},
		{"turn budget", func(in *Input) { in.Conversation.AutonomousTurns = 99 }, "used up its reply budget"},
		{"intent", func(in *Input) { in.Action.Intent = "negotiate" }, "not on your auto-send list"},
		{"rate", func(in *Input) {
			now := in.Now
			in.RecentAgentSends = []time.Time{now.Add(-10 * time.Second), now.Add(-20 * time.Second), now.Add(-30 * time.Second)}
		}, "most replies allowed per minute"},
		{"working hours", func(in *Input) {
			in.Profile.WorkingHours = "UTC;mon-sun 00:00-24:00"
		}, "within your working hours"},
		{"working hours unreadable", func(in *Input) {
			in.Profile.WorkingHours = "Mars/Olympus;mon 09:00-10:00"
		}, "could not be read"},
		{"protected field", func(in *Input) {
			in.ProtectedField = &ProtectedField{Key: "public_profile.open_to"}
		}, `it repeats your profile field "public_profile.open_to" to someone you have not been in touch with yet`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			tc.mut(&in)
			res := Evaluate(in)
			if res.Decision != RequireApproval {
				t.Fatalf("decision = %s %v, want require_approval", res.Decision, res.Reasons)
			}
			stored := strings.Join(res.Reasons, "; ")
			got := OwnerHoldReasons(stored)
			if len(got) != len(res.Reasons) {
				t.Fatalf("owner reasons = %q from %q", got, stored)
			}
			joined := strings.Join(got, "; ")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("owner reasons = %q, want %q", joined, tc.want)
			}
			for _, r := range res.Reasons {
				if strings.Contains(joined, r) {
					t.Fatalf("stored reason %q shown verbatim: %q", r, joined)
				}
			}
		})
	}
}

func TestOwnerHoldReasons_EmptyAndUnknown(t *testing.T) {
	if got := OwnerHoldReasons(""); len(got) != 0 {
		t.Fatalf("empty = %q", got)
	}
	got := OwnerHoldReasons("some future reason; " + ReasonRateLimit)
	if len(got) != 2 || got[0] != "some future reason" || strings.Contains(got[1], ReasonRateLimit) {
		t.Fatalf("unknown + rate = %q", got)
	}
}
