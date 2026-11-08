//go:build l2finance

package policy

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func l2OwnerSummaryInput() Input {
	in := baseInput()
	in.Profile.InstallRevision = 3
	in.InstallRevision = 3
	in.Action = Action{Type: db.ActionTypeOwnerSummary, Text: "L2SYNTH-TXN-7f3a total 12.34"}
	return in
}

func TestL2Finance_T7_1_StaleRevisionDenied(t *testing.T) {
	in := l2OwnerSummaryInput()
	in.InstallRevision = 2
	got := Evaluate(in)
	if got.Decision != Deny || got.DenyCode() != DenyInstallChanged {
		t.Fatalf("decision=%s code=%s, want deny/%s", got.Decision, got.DenyCode(), DenyInstallChanged)
	}
	l2Record(t, "T7.1", l2Pass, "stale revision -> DenyInstallChanged")
}

func TestL2Finance_T7_2_RevisionZeroSkipsFence(t *testing.T) {
	in := l2OwnerSummaryInput()
	in.InstallRevision = 0
	got := Evaluate(in)
	expectGap(t, "T7.2", got.Decision == Allow,
		"InstallRevision=0 owner summary evaluated "+string(got.Decision)+" (policy.go install fence skipped)")
}

func TestL2Finance_T8_KillAndModeOff(t *testing.T) {
	in := l2OwnerSummaryInput()
	in.GlobalKill = true
	if got := Evaluate(in); got.Decision != Deny || got.DenyCode() != DenyGlobalKill {
		t.Fatalf("kill: decision=%s code=%s", got.Decision, got.DenyCode())
	}
	l2Record(t, "T8.kill", l2Pass, "GlobalKill -> DenyGlobalKill")

	in = l2OwnerSummaryInput()
	in.Profile.Mode = db.AgentModeOff
	if got := Evaluate(in); got.Decision != Deny || got.DenyCode() != DenyModeOff {
		t.Fatalf("mode off: decision=%s code=%s", got.Decision, got.DenyCode())
	}
	l2Record(t, "T8.mode_off_before_queue", l2Pass, "mode off -> DenyModeOff")
}

func TestL2Finance_T9_ReplyWithFinanceTextIsContained(t *testing.T) {
	in := baseInput()
	in.Profile.Mode = db.AgentModeObserve
	in.Action.Text = "L2SYNTH-TXN-7f3a total 12.34"
	got := Evaluate(in)
	if got.Decision == Allow {
		t.Fatalf("observe-mode reply with finance text was allowed (%v)", got.Reasons)
	}
	l2Record(t, "T9.reply_observe", l2Pass, "decision="+string(got.Decision)+" code="+string(got.DenyCode()))
	l2Record(t, "T9.finance_tier", l2NotImplemented, "no finance ActionType or never tier in policy")
}

func TestL2Finance_T10_DenyCodes(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Input)
		want   DenyCode
	}{
		{"kill", func(in *Input) { in.GlobalKill = true }, DenyGlobalKill},
		{"stale", func(in *Input) { in.InstallRevision = 1 }, DenyInstallChanged},
		{"off", func(in *Input) { in.Profile.Mode = db.AgentModeOff }, DenyModeOff},
		{"unknown_mode", func(in *Input) { in.Profile.Mode = "x" }, DenyModeUnrecognized},
	}
	for _, c := range cases {
		in := l2OwnerSummaryInput()
		c.mutate(&in)
		got := Evaluate(in)
		if got.Decision != Deny || got.DenyCode() != c.want || len(got.Reasons) == 0 {
			t.Fatalf("%s: decision=%s code=%s reasons=%v, want deny/%s", c.name, got.Decision, got.DenyCode(), got.Reasons, c.want)
		}
	}
	l2Record(t, "T10.denycode", l2Pass, "every deny carries a DenyCode and reasons")
}
