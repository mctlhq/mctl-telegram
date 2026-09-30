package productupdate

import (
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// testTextLimit mirrors broadcast.MaxTextUnits without importing
// internal/broadcast, which render.go is documented not to depend on.
const testTextLimit = 4096

func mustDigest(t *testing.T, entries ...Entry) Digest {
	t.Helper()
	d, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, "0.70.0", entries)
	if err != nil {
		t.Fatalf("FreezeDigest: %v", err)
	}
	return d
}

func TestRenderBroadcastDeterministicAndOrdered(t *testing.T) {
	a, b := approved("send-message"), approved("list-dialogs")
	feed := Feed{Entries: []Entry{a, b}}
	d := mustDigest(t, a, b)

	first, err := RenderBroadcast(d, feed, "https://tg.mctl.ai/docs/product-updates", testTextLimit)
	if err != nil {
		t.Fatal(err)
	}
	again, err := RenderBroadcast(d, feed, "https://tg.mctl.ai/docs/product-updates", testTextLimit)
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("rendering the same digest twice differed:\n%s\n---\n%s", first, again)
	}
	// Entries are rendered in the digest's SourceRefs order (id order:
	// list-dialogs before send-message), not the order passed to FreezeDigest.
	ids, err := d.EntryIDs()
	if err != nil {
		t.Fatal(err)
	}
	if ids[0] != "list-dialogs" || ids[1] != "send-message" {
		t.Fatalf("unexpected source ref order: %v", ids)
	}
}

func TestRenderBroadcastRefusesEditedOrMissingEntry(t *testing.T) {
	a := approved("send-message")
	feed := Feed{Entries: []Entry{a}}
	d := mustDigest(t, a)

	// Entry text changed after freezing: the recomputed hash no longer
	// matches the digest's stored SourceRefs.
	edited := a
	edited.Summary = "A materially different summary."
	editedFeed := Feed{Entries: []Entry{edited}}
	if _, err := RenderBroadcast(d, editedFeed, "https://x/docs", testTextLimit); err == nil {
		t.Fatal("rendered a digest whose entry text changed since freezing")
	}

	// Entry removed from the feed entirely.
	emptyFeed := Feed{}
	if _, err := RenderBroadcast(d, emptyFeed, "https://x/docs", testTextLimit); err == nil {
		t.Fatal("rendered a digest whose entry is missing from the feed")
	}

	// Sanity: the unmodified feed still renders.
	if _, err := RenderBroadcast(d, feed, "https://x/docs", testTextLimit); err != nil {
		t.Fatalf("unmodified feed refused to render: %v", err)
	}
}

func TestRenderBroadcastFullCompactRefuse(t *testing.T) {
	a := approved("send-message")
	feed := Feed{Entries: []Entry{a}}
	d := mustDigest(t, a)

	// Under the limit: full form (title + summary).
	full, err := RenderBroadcast(d, feed, "https://x/docs", testTextLimit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full, a.Summary) {
		t.Fatalf("full form does not carry the summary: %q", full)
	}

	// A limit that fits the title but not the summary: compact form.
	compact, err := RenderBroadcast(d, feed, "https://x/docs", len(full)-10)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(compact, a.Summary) {
		t.Fatalf("compact form carries the summary: %q", compact)
	}
	if !strings.Contains(compact, a.Title) {
		t.Fatalf("compact form does not carry the title: %q", compact)
	}

	// A limit that not even the compact form fits: refusal naming the
	// entry count, no truncation.
	_, err = RenderBroadcast(d, feed, "https://x/docs", 5)
	if err == nil {
		t.Fatal("rendered text that cannot possibly fit the limit")
	}
	if !strings.Contains(err.Error(), "1 entries") {
		t.Fatalf("refusal does not name the entry count: %v", err)
	}
}

func TestRenderDocsGroupsByReleaseNewestFirstAndOmitsProvenance(t *testing.T) {
	older := approved("send-message") // evidence.from 0.69.0
	newer := approved("list-dialogs")
	newer.Evidence.From = "0.70.0"
	newer.Evidence.Changes = []Claim{{Tool: "list_dialogs", Change: ClaimAdded}}
	newer.Tools = []string{"list_dialogs"}
	linksOnly := approved("maintenance-window")
	linksOnly.Kind, linksOnly.Tools = KindMaintenance, nil
	linksOnly.Evidence = Evidence{Links: []string{"https://example.com/maintenance"}}
	docsOnly := approved("docs-note")
	docsOnly.Delivery = DeliveryDocsOnly
	draft := approved("unreviewed")
	draft.Status, draft.Provenance.ReviewedBy, draft.ReviewedAt = StatusDraft, "", ""

	feed := Feed{Entries: []Entry{older, newer, linksOnly, docsOnly, draft}}
	groups := RenderDocs(feed)

	if len(groups) != 3 {
		t.Fatalf("groups = %+v, want 3 (0.70.0, 0.69.0, no-release)", groups)
	}
	if groups[0].Release != "0.70.0" || groups[1].Release != "0.69.0" {
		t.Fatalf("release order = %q, %q; want newest first", groups[0].Release, groups[1].Release)
	}
	if groups[2].Release != "" {
		t.Fatalf("no-release group did not sort last: %+v", groups[2])
	}
	// docs_only entries are included.
	found := false
	for _, e := range groups[1].Entries {
		if e.ID == "docs-note" {
			found = true
		}
	}
	if !found {
		t.Fatal("docs_only entry was dropped from the docs rendering")
	}
	// Draft (unreviewed) entries are never rendered. RenderDocs returns the
	// full Entry (including Provenance) since it is the caller's/template's
	// job never to render that field -- asserted at the web layer
	// (productupdates_test.go).
	for _, g := range groups {
		for _, e := range g.Entries {
			if e.ID == "unreviewed" {
				t.Fatal("a draft entry leaked into the docs rendering")
			}
		}
	}
}
