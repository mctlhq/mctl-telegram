package productupdate

import (
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestDigestCandidatesAreOneCategoryApprovedAndUnsent(t *testing.T) {
	product := approved("send-message")
	draft := approved("list-dialogs")
	draft.Status, draft.Provenance.ReviewedBy, draft.ReviewedAt = StatusDraft, "", ""
	docs := approved("docs-note")
	docs.Delivery = DeliveryDocsOnly
	maintenance := approved("maintenance-window")
	maintenance.Kind = KindMaintenance
	sent := approved("already-sent")

	feed := Feed{Entries: []Entry{product, draft, docs, maintenance, sent}}
	got := DigestCandidates(feed, db.CategoryProductUpdates, map[string]bool{"already-sent": true})
	if len(got) != 1 || got[0].ID != "send-message" {
		t.Fatalf("candidates %+v", got)
	}
	if got := DigestCandidates(feed, db.CategoryMaintenance, nil); len(got) != 1 || got[0].ID != "maintenance-window" {
		t.Fatalf("maintenance candidates %+v", got)
	}
}

func TestFreezeDigestNeverMixesCategories(t *testing.T) {
	maintenance := approved("maintenance-window")
	maintenance.Kind = KindMaintenance
	_, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, []Entry{approved("send-message"), maintenance})
	if err == nil || !strings.Contains(err.Error(), "one digest, one category") {
		t.Fatalf("a mixed digest was frozen: %v", err)
	}
}

func TestFreezeDigestRefusesUnreviewedDuplicateAndEmpty(t *testing.T) {
	draft := approved("send-message")
	draft.Status = StatusDraft
	if _, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, []Entry{draft}); err == nil {
		t.Fatal("a draft was frozen into a digest")
	}
	e := approved("send-message")
	if _, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, []Entry{e, e}); err == nil {
		t.Fatal("a duplicate entry was frozen")
	}
	if _, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, nil); err == nil {
		t.Fatal("an empty digest was frozen")
	}
}

func TestTheFrozenDigestIsContentAddressed(t *testing.T) {
	a, b := approved("send-message"), approved("list-dialogs")
	first, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, []Entry{a, b})
	if err != nil {
		t.Fatal(err)
	}
	again, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, []Entry{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentHash != again.ContentHash || strings.Join(first.SourceRefs, ",") != strings.Join(again.SourceRefs, ",") {
		t.Fatalf("order changed the digest: %+v vs %+v", first, again)
	}
	if !strings.HasPrefix(first.SourceRefs[0], FeedDir+"/list-dialogs.yaml@sha256:") {
		t.Fatalf("source ref %q", first.SourceRefs[0])
	}

	// Review metadata is not content; the text is.
	reviewed := a
	reviewed.ReviewedAt = "2026-09-25"
	same, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, []Entry{reviewed, b})
	if err != nil {
		t.Fatal(err)
	}
	if same.ContentHash != first.ContentHash {
		t.Fatal("review metadata changed the content hash")
	}
	edited := a
	edited.Summary = "You can now send a message."
	changed, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, []Entry{edited, b})
	if err != nil {
		t.Fatal(err)
	}
	if changed.ContentHash == first.ContentHash {
		t.Fatal("an edited summary kept the content hash")
	}
	bumped, err := FreezeDigest("weekly-2026-39", 2, db.CategoryProductUpdates, []Entry{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if bumped.ContentHash == first.ContentHash {
		t.Fatal("a new version kept the content hash")
	}
}
