package productupdate

import (
	"encoding/json"
	"strings"
	"testing"
)

const sendMessageV2 = `{"name":"send_message","description":"Send a message.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"silent":{"type":"boolean"}}},"annotations":{"readOnlyHint":false,"destructiveHint":false,"title":"Send"}}`

func runGate(t *testing.T, entries []Entry, previous, current Snapshot) GateReport {
	t.Helper()
	r, err := Gate(Feed{Entries: entries}, "0.69.0", "0.69.0", previous, current)
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

// Before the first release that carries a snapshot nothing can be required or
// verified. A product update written then still cites a release (Validate
// demands it), and passes as unverified rather than being unwritable.
func TestWithoutABaselineCitationsPassAsUnverified(t *testing.T) {
	r, err := Gate(Feed{}, "", "0.68.0", Snapshot{}, snapshot(t, listDialogs, sendMessage))
	if err != nil {
		t.Fatal(err)
	}
	wantPass(t, r)
	e := approved("send-message")
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.Evidence.From = "0.68.0"
	r, err = Gate(Feed{Entries: []Entry{e}}, "", "0.68.0", Snapshot{}, snapshot(t, listDialogs, sendMessage))
	if err != nil {
		t.Fatal(err)
	}
	wantPass(t, r)
	if len(r.Unverified) != 1 || !strings.Contains(r.Unverified[0], "send-message") {
		t.Fatalf("unverified %q", r.Unverified)
	}
}

// What can still be checked in the bootstrap window is: the cited release
// exists, and a named tool (other than a removal) exists at HEAD. Such an
// entry is never held to a diff later, so this is its only check.
func TestTheBootstrapWindowStillRefusesGhostsAndFutureReleases(t *testing.T) {
	head := snapshot(t, listDialogs)
	ghost := approved("send-message")
	ghost.Evidence.From = "0.68.0"
	r, err := Gate(Feed{Entries: []Entry{ghost}}, "", "0.68.0", Snapshot{}, head)
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, r, "names tool send_message, which does not exist at HEAD")

	gone := approved("drop-delete-messages")
	gone.Kind, gone.Tools = KindDeprecation, []string{"delete_messages"}
	gone.Evidence = Evidence{From: "0.68.0", Changes: []Claim{{Tool: "delete_messages", Change: ClaimRemoved}}}
	r, err = Gate(Feed{Entries: []Entry{gone}}, "", "0.68.0", Snapshot{}, head)
	if err != nil {
		t.Fatal(err)
	}
	wantPass(t, r)

	future := approved("list-dialogs")
	future.Tools = []string{"list_dialogs"}
	future.Evidence = Evidence{From: "0.69.0", Changes: []Claim{{Tool: "list_dialogs", Change: ClaimAdded}}}
	r, err = Gate(Feed{Entries: []Entry{future}}, "", "0.68.0", Snapshot{}, head)
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, r, "cites release 0.69.0, which is not a released version (latest: 0.68.0)")

	// A tool listed without a claim is checked too: it is what recipients read.
	listed := approved("list-dialogs")
	listed.Tools = []string{"list_dialogs", "teleport"}
	listed.Evidence = Evidence{From: "0.68.0", Changes: []Claim{{Tool: "list_dialogs", Change: ClaimSchema}}}
	listed.Kind = KindChangedBehavior
	r, err = Gate(Feed{Entries: []Entry{listed}}, "", "0.68.0", Snapshot{}, head)
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, r, "names tool teleport, which does not exist at HEAD")

	// One change, one update, before the first baseline as after it.
	a, b := listed, listed
	a.Tools, b.ID, b.Tools = []string{"list_dialogs"}, "list-dialogs-again", []string{"list_dialogs"}
	r, err = Gate(Feed{Entries: []Entry{a, b}}, "", "0.68.0", Snapshot{}, head)
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, r, "both claim list_dialogs schema")

	// A malformed citation is reported as malformed, not as a future release.
	bad := a
	bad.Evidence.From = "v0.68.0"
	r, err = Gate(Feed{Entries: []Entry{bad}}, "", "0.68.0", Snapshot{}, head)
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, r, "list-dialogs: evidence.from:")

	// With no release tag at all, a product update cannot be written yet.
	r, err = Gate(Feed{Entries: []Entry{a}}, "", "", Snapshot{}, head)
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, r, "cites release 0.68.0, but no release exists yet")
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

// The report and the digest hash serialise claims with stable lower-case keys.
func TestClaimsSerialiseWithStableKeys(t *testing.T) {
	raw, err := json.Marshal(Evidence{From: "0.69.0", Changes: []Claim{{Tool: "send_message", Change: ClaimAdded}}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"from":"0.69.0","changes":[{"tool":"send_message","change":"added"}],"links":null}`; string(raw) != want {
		t.Fatalf("got %s, want %s", raw, want)
	}
}

// A links-only notice claims no capability. A notice naming a tool that a
// deprecation removes in the same pull request, or one a later release
// removes, must not fail the gate: that failure could never be fixed.
func TestALinksOnlyNoticeIsNotHeldToHEAD(t *testing.T) {
	notice := approved("delete-advisory")
	notice.Kind, notice.Tools = KindSecurity, []string{"delete_messages"}
	notice.Evidence = Evidence{Links: []string{"https://github.com/mctlhq/mctl-telegram/security/advisories/1"}}
	d := approved("drop-delete-messages")
	d.Kind, d.Tools = KindDeprecation, []string{"delete_messages"}
	d.Evidence.Changes = []Claim{{Tool: "delete_messages", Change: ClaimRemoved}}
	wantPass(t, runGate(t, []Entry{notice, d}, snapshot(t, listDialogs, deleteMessage), snapshot(t, listDialogs)))
	s := snapshot(t, listDialogs)
	wantPass(t, runGate(t, []Entry{notice}, s, s))
}

// A release cut while a pull request is open leaves its entry citing the old
// baseline; the failure says to bump it rather than to add a new entry.
func TestAnEntryCitingAnOlderBaselineIsToldToBump(t *testing.T) {
	before, after := snapshot(t, listDialogs), snapshot(t, listDialogs, sendMessage)
	old := approved("send-message")
	old.Evidence.From = "0.68.0"
	wantProblem(t, runGate(t, []Entry{old}, before, after), "bump its evidence.from to 0.69.0, otherwise add a new entry")
}
