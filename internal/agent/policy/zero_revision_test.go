package policy

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// #1266: InstallRevision 0 is never a valid input. It is denied for every
// action type, whatever the profile holds, and is distinct from the nonzero
// stale-revision denial.
func TestEvaluate_ZeroInstallRevisionAlwaysDenied(t *testing.T) {
	for _, actionType := range []string{db.ActionTypeReply, db.ActionTypeOwnerSummary, db.ActionTypeOwnerApproval} {
		for _, profileRev := range []int64{0, 1, 5} {
			in := baseInput()
			in.Action.Type = actionType
			in.Profile.InstallRevision = profileRev
			in.InstallRevision = 0
			got := Evaluate(in)
			if got.Decision != Deny || got.DenyCode() != DenyInstallRevisionMissing {
				t.Fatalf("%s profile rev %d: decision=%s code=%s, want deny/%s", actionType, profileRev, got.Decision, got.DenyCode(), DenyInstallRevisionMissing)
			}
			if len(got.Reasons) != 1 || got.Reasons[0] != ReasonInstallRevisionMissing {
				t.Fatalf("%s profile rev %d: reasons = %v", actionType, profileRev, got.Reasons)
			}
		}
	}
}

func TestEvaluate_ExplicitCurrentRevisionStillWorksAndStaleStaysInstallChanged(t *testing.T) {
	in := baseInput()
	in.Profile.InstallRevision = 4
	in.InstallRevision = 4
	if got := Evaluate(in); got.Decision != Allow {
		t.Fatalf("current revision decision = %s (%v), want allow", got.Decision, got.Reasons)
	}
	in.InstallRevision = 3
	got := Evaluate(in)
	if got.Decision != Deny || got.DenyCode() != DenyInstallChanged {
		t.Fatalf("stale revision decision=%s code=%s, want deny/%s", got.Decision, got.DenyCode(), DenyInstallChanged)
	}
}
