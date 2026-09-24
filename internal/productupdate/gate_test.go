package productupdate

import (
	"strings"
	"testing"
)

const sendMessageV2 = `{"name":"send_message","description":"Send a message.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"silent":{"type":"boolean"}}},"annotations":{"readOnlyHint":false,"destructiveHint":false,"title":"Send"}}`

func runGate(t *testing.T, entries []Entry, previous, current Snapshot) GateReport {
	t.Helper()
	r, err := Gate(Feed{Entries: entries}, "0.69.0", previous, current)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func wantProblem(t *testing.T, r GateReport, fragment string) {
	t.Helper()
	for _, p := range r.Problems {
		if strings.Contains(p, fragment) {
			return
		}
	}
	t.Fatalf("no problem mentions %q; problems: %q", fragment, r.Problems)
}

func wantPass(t *testing.T, r GateReport) {
	t.Helper()
	if !r.Passed() {
		t.Fatalf("gate failed: %q", r.Problems)
	}
}

func TestANoOpReleaseRequiresNothing(t *testing.T) {
	s := snapshot(t, listDialogs, sendMessage)
	r := runGate(t, nil, s, s)
	wantPass(t, r)
	if len(r.Required) != 0 {
		t.Fatalf("required %+v", r.Required)
	}
}

func TestAnAddedToolNeedsAnApprovedEntry(t *testing.T) {
	before, after := snapshot(t, listDialogs), snapshot(t, listDialogs, sendMessage)
	wantProblem(t, runGate(t, nil, before, after), "send_message added since 0.69.0 has no product update")
	wantPass(t, runGate(t, []Entry{approved("send-message")}, before, after))

	draft := approved("send-message")
	draft.Status, draft.Provenance.ReviewedBy, draft.ReviewedAt = StatusDraft, "", ""
	wantProblem(t, runGate(t, []Entry{draft}, before, after), "claimed only by draft send-message")
}

func TestARemovedToolNeedsADeprecation(t *testing.T) {
	before, after := snapshot(t, listDialogs, deleteMessage), snapshot(t, listDialogs)
	wantProblem(t, runGate(t, nil, before, after), "delete_messages removed since 0.69.0")

	d := approved("drop-delete-messages")
	d.Kind, d.Tools = KindDeprecation, []string{"delete_messages"}
	d.Evidence.Changes = []Claim{{Tool: "delete_messages", Change: ClaimRemoved}}
	wantPass(t, runGate(t, []Entry{d}, before, after))
}

// A rename is a removal and an addition. Both need coverage; one entry may
// claim the pair.
func TestARenameNeedsBothHalvesCovered(t *testing.T) {
	renamed := strings.Replace(sendMessage, `"send_message"`, `"post_message"`, 1)
	before, after := snapshot(t, listDialogs, sendMessage), snapshot(t, listDialogs, renamed)

	onlyNew := approved("rename-send")
	onlyNew.Kind, onlyNew.Tools = KindNewTool, []string{"post_message"}
	onlyNew.Evidence.Changes = []Claim{{Tool: "post_message", Change: ClaimAdded}}
	wantProblem(t, runGate(t, []Entry{onlyNew}, before, after), "send_message removed since 0.69.0 has no product update")

	both := approved("rename-send")
	both.Kind, both.Tools = KindChangedBehavior, []string{"send_message", "post_message"}
	both.Evidence.Changes = []Claim{{Tool: "send_message", Change: ClaimRemoved}, {Tool: "post_message", Change: ClaimAdded}}
	wantPass(t, runGate(t, []Entry{both}, before, after))
}

func TestASchemaOnlyChangeNeedsCoverageAndTextDoesNot(t *testing.T) {
	before, after := snapshot(t, sendMessage), snapshot(t, sendMessageV2)
	wantProblem(t, runGate(t, nil, before, after), "send_message schema since 0.69.0 has no product update")

	e := approved("send-silent")
	e.Kind = KindChangedBehavior
	e.Evidence.Changes = []Claim{{Tool: "send_message", Change: ClaimSchema}}
	wantPass(t, runGate(t, []Entry{e}, before, after))

	textOnly := strings.Replace(sendMessage, "Send a message.", "Send a text message.", 1)
	wantPass(t, runGate(t, nil, snapshot(t, sendMessage), snapshot(t, textOnly)))
}

func TestAnAnnotationChangeNeedsCoverage(t *testing.T) {
	flipped := strings.Replace(sendMessage, `"destructiveHint":false`, `"destructiveHint":true`, 1)
	wantProblem(t, runGate(t, nil, snapshot(t, sendMessage), snapshot(t, flipped)), "send_message annotations since 0.69.0")
}

// An update may not state a change the tool surface does not show.
func TestAnInventedClaimFails(t *testing.T) {
	s := snapshot(t, listDialogs, sendMessage)
	wantProblem(t, runGate(t, []Entry{approved("send-message")}, s, s), "which the tool diff from 0.69.0 does not show")

	ghost := approved("ghost-tool")
	ghost.Tools = []string{"send_message", "teleport"}
	before, after := snapshot(t, listDialogs), snapshot(t, listDialogs, sendMessage)
	wantProblem(t, runGate(t, []Entry{ghost}, before, after), "names tool teleport")
}

// The same change in two entries is a duplicate -- one change, one update --
// whether the second is a draft or re-lists it for a repeated release.
func TestADuplicateClaimFails(t *testing.T) {
	before, after := snapshot(t, listDialogs), snapshot(t, listDialogs, sendMessage)
	r := runGate(t, []Entry{approved("send-message"), approved("send-message-again")}, before, after)
	wantProblem(t, r, "both claim send_message added")
}

func TestOlderEntriesAreHistoryAndNewerOnesAreRefused(t *testing.T) {
	s := snapshot(t, listDialogs, sendMessage)
	old := approved("send-message")
	old.Evidence.From = "0.68.0"
	wantPass(t, runGate(t, []Entry{old}, s, s))

	future := approved("send-message")
	future.Evidence.From = "0.70.0"
	wantProblem(t, runGate(t, []Entry{future}, s, s), "newer than the latest released snapshot")
}

func TestWithoutABaselineNothingIsRequiredButNothingCanCite(t *testing.T) {
	r, err := Gate(Feed{}, "", Snapshot{}, snapshot(t, listDialogs))
	if err != nil {
		t.Fatal(err)
	}
	wantPass(t, r)
	r, err = Gate(Feed{Entries: []Entry{approved("send-message")}}, "", Snapshot{}, snapshot(t, listDialogs))
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, r, "no release carries a tool snapshot yet")
}

func TestLatestReleaseSortsNumericallyAndSkipsTagsWithoutASnapshot(t *testing.T) {
	tags := []string{"0.9.0", "0.10.0", "0.69.0", "v1.0.0", "0.70.0-rc1", "notes"}
	has := map[string]bool{"0.9.0": true, "0.10.0": true, "0.69.0": false}
	if got := LatestRelease(tags, func(t string) bool { return has[t] }); got != "0.10.0" {
		t.Fatalf("latest %q, want 0.10.0", got)
	}
	if got := LatestRelease(tags, func(string) bool { return false }); got != "" {
		t.Fatalf("latest %q, want none", got)
	}
}
