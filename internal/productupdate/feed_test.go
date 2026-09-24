package productupdate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// approved is a valid approved new_tool entry claiming send_message added
// since 0.69.0; tests mutate copies of it.
func approved(id string) Entry {
	return Entry{
		Schema:   EntrySchema,
		ID:       id,
		Kind:     KindNewTool,
		Title:    "Send messages",
		Summary:  "You can now send a message to a chat.",
		Locale:   "en",
		Delivery: DeliveryNextDigest,
		Tools:    []string{"send_message"},
		Evidence: Evidence{From: "0.69.0", Changes: []Claim{{Tool: "send_message", Change: ClaimAdded}}},
		Status:   StatusApproved,
		Provenance: Provenance{
			Author:     "alice",
			ReviewedBy: "alice",
		},
		CreatedAt:  "2026-09-24",
		ReviewedAt: "2026-09-24",
	}
}

func wantInvalid(t *testing.T, e Entry, fragment string) {
	t.Helper()
	err := e.Validate()
	if err == nil {
		t.Fatalf("entry %+v validated; want an error containing %q", e, fragment)
	}
	if !strings.Contains(err.Error(), fragment) {
		t.Fatalf("error %q does not mention %q", err, fragment)
	}
}

func TestAValidEntryValidates(t *testing.T) {
	if err := approved("send-message").Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCategoryIsDerivedFromKindAndIsAlwaysOne(t *testing.T) {
	cases := map[Kind]db.NotificationCategory{
		KindNewTool:         db.CategoryProductUpdates,
		KindChangedBehavior: db.CategoryProductUpdates,
		KindDeprecation:     db.CategoryProductUpdates,
		KindMaintenance:     db.CategoryMaintenance,
		KindSecurity:        db.CategorySecurity,
	}
	for kind, want := range cases {
		if got := kind.Category(); got != want {
			t.Errorf("%s: category %s, want %s", kind, got, want)
		}
	}
}

func TestImmediateIsOnlyForSecurityMaintenanceOrHighValue(t *testing.T) {
	e := approved("send-message")
	e.Delivery = DeliveryImmediate
	wantInvalid(t, e, "delivery immediate")

	e.HighValue = true
	if err := e.Validate(); err != nil {
		t.Fatalf("high_value immediate: %v", err)
	}

	s := approved("token-rotation")
	s.Kind, s.Delivery = KindSecurity, DeliveryImmediate
	s.Evidence = Evidence{Links: []string{"https://github.com/mctlhq/mctl-telegram/security/advisories/1"}}
	s.Tools = nil
	if err := s.Validate(); err != nil {
		t.Fatalf("security immediate: %v", err)
	}
}

func TestEveryFactualUpdateCitesEvidence(t *testing.T) {
	e := approved("send-message")
	e.Kind = KindMaintenance
	e.Evidence = Evidence{}
	wantInvalid(t, e, "evidence needs changes")

	e = approved("send-message")
	e.Evidence.From = ""
	wantInvalid(t, e, "evidence.changes needs evidence.from")

	e = approved("send-message")
	e.Evidence.Changes = append(e.Evidence.Changes, Claim{Tool: "list_dialogs", Change: ClaimText})
	wantInvalid(t, e, "which tools does not list")

	e = approved("send-message")
	e.Evidence.Links = []string{"http://example.com"}
	wantInvalid(t, e, "not https")
}

func TestKindsNeedTheChangesThatShowThem(t *testing.T) {
	e := approved("send-message")
	e.Evidence.Changes = []Claim{{Tool: "send_message", Change: ClaimSchema}}
	wantInvalid(t, e, "new_tool update must claim at least one added")

	d := approved("drop-send")
	d.Kind = KindDeprecation
	d.Evidence = Evidence{Links: []string{"https://example.com/notice"}}
	wantInvalid(t, d, "deprecation must claim")
}

// Generated copy is rejected as approval: a model may help word an update,
// but the reviewer is a named human, never a bot and never that model.
func TestGeneratedCopyCannotApproveItself(t *testing.T) {
	e := approved("send-message")
	e.Provenance.AssistedBy = "claude-opus"
	e.Provenance.ReviewedBy = "claude-opus"
	wantInvalid(t, e, "model that assisted")

	e = approved("send-message")
	e.Provenance.ReviewedBy = "mctl-agents[bot]"
	wantInvalid(t, e, "is a bot")

	e = approved("send-message")
	e.Provenance.ReviewedBy = ""
	wantInvalid(t, e, "needs provenance.reviewed_by")

	e = approved("send-message")
	e.Provenance.Author = "app/mctl-agents"
	wantInvalid(t, e, "author \"app/mctl-agents\" is a bot")

	// A model-assisted update reviewed by a person is fine, and the reviewer
	// may be the author (owner decision on #440).
	e = approved("send-message")
	e.Provenance.AssistedBy = "claude-opus"
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestADraftHasNoReviewer(t *testing.T) {
	e := approved("send-message")
	e.Status = StatusDraft
	wantInvalid(t, e, "a draft has no reviewer")
	e.Provenance.ReviewedBy, e.ReviewedAt = "", ""
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyEnglishInV1(t *testing.T) {
	e := approved("send-message")
	e.Locale = "ru"
	wantInvalid(t, e, "locale \"ru\" is not supported")
}

func TestParseEntryIsStrict(t *testing.T) {
	if _, err := ParseEntry([]byte("schema: x\nid: a\nunknown_field: 1\n")); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if _, err := ParseEntry([]byte("schema: x\n---\nschema: y\n")); err == nil {
		t.Fatal("two YAML documents were accepted")
	}
}

func writeEntry(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const entryYAML = `schema: mctl-telegram.product-update/v1
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

func TestLoadFeedHoldsTheFileNameToTheID(t *testing.T) {
	dir := t.TempDir()
	writeEntry(t, dir, "send-message.yaml", entryYAML)
	writeEntry(t, dir, "README.md", "# feed\n")
	feed, err := LoadFeed(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(feed.Entries) != 1 || feed.Entries[0].ID != "send-message" {
		t.Fatalf("feed %+v", feed)
	}

	writeEntry(t, dir, "other-name.yaml", entryYAML)
	if _, err := LoadFeed(dir); err == nil || !strings.Contains(err.Error(), "must equal the file name") {
		t.Fatalf("a misnamed file was accepted: %v", err)
	}
}

func TestLoadFeedRefusesOtherExtensions(t *testing.T) {
	dir := t.TempDir()
	writeEntry(t, dir, "send-message.yml", entryYAML)
	if _, err := LoadFeed(dir); err == nil {
		t.Fatal("a .yml file was accepted")
	}
}

// The committed feed is valid: any entry merged into docs/product-updates is
// held to the schema by this test as well as by the CI gate.
func TestTheCommittedFeedIsValid(t *testing.T) {
	if _, err := LoadFeed(filepath.Join("..", "..", FeedDir)); err != nil {
		t.Fatal(err)
	}
}
