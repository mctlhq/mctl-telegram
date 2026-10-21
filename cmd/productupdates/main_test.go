package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

const (
	listDialogs = `{"name":"list_dialogs","description":"List dialogs.","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true,"title":"List dialogs"}}`
	sendMessage = `{"name":"send_message","description":"Send a message.","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":false,"title":"Send"}}`
)

const sendMessageEntry = `schema: mctl-telegram.product-update/v1
id: send-message
kind: new_tool
title: Send messages
summary: You can now send a message to a chat.
locale: en
delivery: next_digest
tools: [send_message]
evidence:
  from: 0.69.0
  changes:
    - {tool: send_message, change: added}
status: approved
provenance:
  author: alice
  reviewed_by: alice
created_at: "2026-09-24"
reviewed_at: "2026-09-24"
`

// repo is a throwaway git repository the gate reads tags and snapshots from.
type repo struct {
	t   *testing.T
	dir string
}

func newRepo(t *testing.T) repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	r := repo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.git("config", "user.email", "test@example.com")
	r.git("config", "user.name", "test")
	r.git("config", "commit.gpgsign", "false")
	r.git("config", "tag.gpgsign", "false")
	return r
}

func (r repo) git(args ...string) {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func (r repo) write(path, body string) {
	r.t.Helper()
	full := filepath.Join(r.dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// snapshot writes the full surface, and the same tools as every profile's
// surface, so a test that is not about profiles has nothing to say about them.
func (r repo) snapshot(descriptors ...string) {
	r.t.Helper()
	r.surface(snapshotPath, "", descriptors...)
	for _, name := range toolprofile.Names() {
		r.surface(profileSnapshotPath(name), name, descriptors...)
	}
}

// profile writes one profile's surface alone.
func (r repo) profile(name string, descriptors ...string) {
	r.t.Helper()
	r.surface(profileSnapshotPath(name), name, descriptors...)
}

func (r repo) surface(path, profile string, descriptors ...string) {
	r.t.Helper()
	raw := map[string][]byte{}
	for _, d := range descriptors {
		var head struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(d), &head); err != nil {
			r.t.Fatal(err)
		}
		raw[head.Name] = []byte(d)
	}
	s, err := productupdate.NewSnapshot(productupdate.Surface{AppsEnabled: true, ToolFilter: "all", Profile: profile}, raw)
	if err != nil {
		r.t.Fatal(err)
	}
	encoded, err := s.Marshal()
	if err != nil {
		r.t.Fatal(err)
	}
	r.write(path, string(encoded))
}

func (r repo) commit(message string) {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "--allow-empty", "-m", message)
}

func (r repo) gate() (int, string) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"gate", "-repo", r.dir}, &stdout, &stderr)
	return code, stdout.String() + stderr.String()
}

func TestTheGateHoldsATagToTheFeed(t *testing.T) {
	r := newRepo(t)
	r.write("README.md", "x\n")
	r.commit("before any snapshot")
	r.git("tag", "0.68.0")

	// No release carries a snapshot yet: nothing can be required, and an
	// entry citing the latest release is reported as unverified.
	r.snapshot(listDialogs)
	r.write(filepath.Join(productupdate.FeedDir, "list-dialogs.yaml"), strings.NewReplacer(
		"send-message", "list-dialogs", "send_message", "list_dialogs", "0.69.0", "0.68.0").Replace(sendMessageEntry))
	r.commit("snapshot")
	if code, out := r.gate(); code != exitOK || !strings.Contains(out, "no release carries") ||
		!strings.Contains(out, "unverified until a release carries a snapshot: list-dialogs (evidence.from 0.68.0)") {
		t.Fatalf("no baseline: exit %d\n%s", code, out)
	}

	// 0.69.0 carries the snapshot; a tool added after it needs an entry.
	r.git("tag", "0.69.0")
	r.snapshot(listDialogs, sendMessage)
	r.commit("add send_message")
	code, out := r.gate()
	if code != exitFailed || !strings.Contains(out, "send_message added since 0.69.0 has no product update") {
		t.Fatalf("uncovered addition: exit %d\n%s", code, out)
	}

	r.write(filepath.Join(productupdate.FeedDir, "send-message.yaml"), sendMessageEntry)
	r.commit("product update")
	if code, out := r.gate(); code != exitOK {
		t.Fatalf("covered addition: exit %d\n%s", code, out)
	}

	// Releasing it moves the baseline: the entry is history, and the next
	// no-op release requires nothing.
	r.git("tag", "0.70.0")
	if code, out := r.gate(); code != exitOK || !strings.Contains(out, `"baseline": "0.70.0"`) {
		t.Fatalf("after release: exit %d\n%s", code, out)
	}
}

const getMessages = `{"name":"get_messages","description":"Read messages.","inputSchema":{"type":"object","properties":{"peer":{"type":"string"}}},"annotations":{"readOnlyHint":true,"title":"Read"}}`

// The profile entry is the sendMessageEntry shape for get_messages joining
// core-readonly: a change only that profile's surface shows.
const profileEntry = `schema: mctl-telegram.product-update/v1
id: core-readonly-reads-messages
kind: changed_behavior
title: Read-only connections can read messages
summary: Connections with the core-readonly profile can now read a chat's messages.
locale: en
delivery: docs_only
tools: [get_messages]
evidence:
  from: 0.70.0
  changes:
    - {tool: get_messages, change: added, profile: core-readonly}
status: approved
provenance:
  author: alice
  reviewed_by: alice
created_at: "2026-09-24"
reviewed_at: "2026-09-24"
`

func TestTheGateHoldsEachProfileToTheFeed(t *testing.T) {
	r := newRepo(t)
	// 0.69.0 carries the full snapshot but no profile snapshot: every profile
	// is in its bootstrap window, so a profile differing from the full
	// surface requires nothing yet.
	r.surface(snapshotPath, "", listDialogs, getMessages)
	r.commit("full snapshot only")
	r.git("tag", "0.69.0")
	r.snapshot(listDialogs, getMessages)
	r.profile(toolprofile.CoreReadonly, listDialogs)
	r.commit("profile snapshots")
	if code, out := r.gate(); code != exitOK {
		t.Fatalf("profile bootstrap: exit %d\n%s", code, out)
	}
	// A claim on a profile in its bootstrap window passes unverified, and
	// says so in the log although the full surface has a baseline.
	early := filepath.Join(productupdate.FeedDir, "core-readonly-reads-messages.yaml")
	r.write(early, strings.ReplaceAll(profileEntry, "from: 0.70.0", "from: 0.69.0"))
	r.commit("early profile product update")
	if code, out := r.gate(); code != exitOK ||
		!strings.Contains(out, "productupdates: unverified until a release carries a snapshot: core-readonly-reads-messages claims get_messages added (profile core-readonly)") {
		t.Fatalf("bootstrap profile claim: exit %d\n%s", code, out)
	}
	r.git("rm", "-q", early)
	r.commit("drop early product update")

	// 0.70.0 carries profile snapshots. A tool added to one profile alone is
	// that profile's change and needs a profile-scoped entry.
	r.git("tag", "0.70.0")
	r.profile(toolprofile.CoreReadonly, listDialogs, getMessages)
	r.commit("get_messages joins core-readonly")
	code, out := r.gate()
	if code != exitFailed || !strings.Contains(out, "get_messages added (profile core-readonly) since 0.70.0 has no product update") {
		t.Fatalf("uncovered profile addition: exit %d\n%s", code, out)
	}
	r.write(filepath.Join(productupdate.FeedDir, "core-readonly-reads-messages.yaml"), profileEntry)
	r.commit("profile product update")
	if code, out := r.gate(); code != exitOK {
		t.Fatalf("covered profile addition: exit %d\n%s", code, out)
	}

	// A tool added to the full surface and to every profile at once needs
	// only the full-surface entry.
	r.git("tag", "0.71.0")
	r.snapshot(listDialogs, getMessages, sendMessage)
	r.write(filepath.Join(productupdate.FeedDir, "send-message.yaml"), strings.ReplaceAll(sendMessageEntry, "0.69.0", "0.71.0"))
	r.commit("send_message everywhere")
	if code, out := r.gate(); code != exitOK {
		t.Fatalf("addition shown on the full surface: exit %d\n%s", code, out)
	}
}

// Once a baseline carries profile snapshots, a profile missing from it is
// observed absent, not unknown: it is a new surface and each of its tools
// was added to it.
func TestANewProfileIsANewSurface(t *testing.T) {
	r := newRepo(t)
	names := toolprofile.Names()
	if len(names) < 2 {
		t.Skip("needs two profiles")
	}
	r.surface(snapshotPath, "", listDialogs)
	r.profile(names[0], listDialogs)
	r.commit("one profile released")
	r.git("tag", "0.70.0")
	r.snapshot(listDialogs)
	r.commit("second profile")
	code, out := r.gate()
	if code != exitFailed || !strings.Contains(out, "list_dialogs added (profile "+names[1]+") since 0.70.0 has no product update") {
		t.Fatalf("new profile: exit %d\n%s", code, out)
	}
}

func TestEveryProfileCommitsItsSnapshot(t *testing.T) {
	r := newRepo(t)
	r.snapshot(listDialogs)
	if err := os.Remove(filepath.Join(r.dir, profileSnapshotPath(toolprofile.CoreReply))); err != nil {
		t.Fatal(err)
	}
	r.commit("missing profile snapshot")
	r.git("tag", "0.69.0")
	if code, out := r.gate(); code != exitFailed || !strings.Contains(out, "every tool profile commits its snapshot") {
		t.Fatalf("missing profile snapshot: exit %d\n%s", code, out)
	}
}

func TestAnInvalidFeedFailsValidate(t *testing.T) {
	r := newRepo(t)
	r.write(filepath.Join(productupdate.FeedDir, "send-message.yaml"), strings.Replace(sendMessageEntry, "locale: en", "locale: ru", 1))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"validate", "-repo", r.dir}, &stdout, &stderr); code != exitFailed {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
	// Usage errors stay usage errors even where the feed is broken.
	for _, args := range [][]string{
		{"bogus", "-repo", r.dir},
		{"validate", "-repo", r.dir, "-baseline", "0.69.0"},
		{"gate", "-repo", r.dir, "-baseline", "--output=x"},
	} {
		if code := run(args, &stdout, &stderr); code != exitUsage {
			t.Fatalf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

// A shallow clone has no tags: no baseline there means "not fetched", and the
// gate refuses rather than judging the feed against nothing.
func TestTheGateRefusesAShallowClone(t *testing.T) {
	r := newRepo(t)
	r.snapshot(listDialogs)
	r.commit("one")
	r.git("tag", "0.69.0")
	r.commit("two")
	shallow := t.TempDir()
	if out, err := exec.Command("git", "clone", "-q", "--depth", "1", "--no-tags", "file://"+r.dir, shallow).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"gate", "-repo", shallow}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "needs the full history") {
		t.Fatalf("shallow clone: exit %d\n%s", code, stderr.String())
	}
}

// The repository's own feed and snapshot pass the gate against its own tags.
// CI runs the same command with full history.
func TestTheRepositoryPassesItsOwnGate(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skip("not a git checkout")
	}
	// The test and test-cross-platform jobs check out shallow, without tags;
	// only the product-updates job has the history this needs.
	if out, err := exec.Command("git", "-C", root, "rev-parse", "--is-shallow-repository").Output(); err != nil || strings.TrimSpace(string(out)) == "true" {
		t.Skip("shallow checkout: the product-updates CI job runs this gate with full history")
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"gate", "-repo", root}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
}
