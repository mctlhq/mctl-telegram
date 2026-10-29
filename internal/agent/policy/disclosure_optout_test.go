package policy

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// A blank disclosure is allowed only with the owner's explicit opt-out; on
// its own it stays a fail-closed misconfiguration.
func TestEvaluate_DisclosureOptOutAllowsBlankText(t *testing.T) {
	in := baseInput()
	in.Profile.DisclosureText = ""
	in.Profile.DisclosureDisabled = true
	if got := Evaluate(in); got.Decision != Allow {
		t.Fatalf("decision = %s (%v), want allow for an opted-out profile", got.Decision, got.Reasons)
	}
}

func TestEvaluate_BlankDisclosureWithoutOptOutStillDenies(t *testing.T) {
	in := baseInput()
	in.Profile.DisclosureText = " "
	in.Profile.DisclosureDisabled = false
	got := Evaluate(in)
	if got.Decision != Deny || got.Code != DenyNoDisclosure {
		t.Fatalf("got %s/%s (%v), want deny/%s", got.Decision, got.Code, got.Reasons, DenyNoDisclosure)
	}
}

// With the opt-out the disclosure is never appended, so it must not eat into
// the reply's length budget either; without it the budget is unchanged.
func TestEvaluate_DisclosureOptOutLengthBudget(t *testing.T) {
	in := baseInput()
	in.Profile.MaxReplyChars = 100
	in.Action.Text = repeatRune(100)

	in.Profile.DisclosureDisabled = true
	if got := Evaluate(in); got.Decision != Allow {
		t.Fatalf("opted out: decision = %s (%v), want allow at exactly the limit", got.Decision, got.Reasons)
	}
	in.Profile.DisclosureDisabled = false
	if got := Evaluate(in); got.Code != DenyReplyTooLong {
		t.Fatalf("not opted out: code = %s (%v), want %s", got.Code, got.Reasons, DenyReplyTooLong)
	}
}

func TestEffectiveDisclosure(t *testing.T) {
	p := db.AgentProfile{DisclosureText: "— AI"}
	if got := EffectiveDisclosure(p); got != "— AI" {
		t.Fatalf("EffectiveDisclosure = %q, want the configured text", got)
	}
	p.DisclosureDisabled = true
	if got := EffectiveDisclosure(p); got != "" {
		t.Fatalf("EffectiveDisclosure with opt-out = %q, want empty", got)
	}
}
