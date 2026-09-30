package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
)

func puEntry(id, from string) productupdate.Entry {
	return productupdate.Entry{
		Schema: productupdate.EntrySchema, ID: id, Kind: productupdate.KindNewTool,
		Title: "Send messages " + id, Summary: "You can now send a message to a chat (" + id + ").",
		Locale: "en", Delivery: productupdate.DeliveryNextDigest,
		Tools:      []string{"send_message"},
		Evidence:   productupdate.Evidence{From: from, Changes: []productupdate.Claim{{Tool: "send_message", Change: productupdate.ClaimAdded}}},
		Status:     productupdate.StatusApproved,
		Provenance: productupdate.Provenance{Author: "alice", ReviewedBy: "alice", AssistedBy: "a-super-secret-model-codename"},
		CreatedAt:  "2026-09-24", ReviewedAt: "2026-09-24",
	}
}

// TestProductUpdatesPage_ListsGroupsAndOmitsProvenance is T11: the docs page
// lists approved en entries including docs_only, groups by release newest
// first, and never shows provenance fields.
func TestProductUpdatesPage_ListsGroupsAndOmitsProvenance(t *testing.T) {
	older := puEntry("send-message", "0.69.0")
	newer := puEntry("list-dialogs", "0.70.0")
	docsOnly := puEntry("docs-note", "0.69.0")
	docsOnly.Delivery = productupdate.DeliveryDocsOnly
	draft := puEntry("unreviewed", "0.69.0")
	draft.Status, draft.Provenance.ReviewedBy, draft.ReviewedAt = productupdate.StatusDraft, "", ""

	feed := productupdate.Feed{Entries: []productupdate.Entry{older, newer, docsOnly, draft}}
	groups := productupdate.RenderDocs(feed)

	h := ProductUpdates(groups, nil, "https://tg.mctl.ai", false)
	req := httptest.NewRequest(http.MethodGet, "/docs/product-updates", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"0.70.0", "0.69.0", "Send messages send-message", "Send messages list-dialogs", "Send messages docs-note", "(docs only)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "unreviewed") {
		t.Fatal("a draft (unreviewed) entry was rendered")
	}
	if strings.Contains(body, "a-super-secret-model-codename") || strings.Contains(body, "alice") {
		t.Fatal("provenance (author/reviewer/assisted_by) leaked onto the page")
	}
	// Newest release first: 0.70.0's heading appears before 0.69.0's.
	if i70, i69 := strings.Index(body, "0.70.0"), strings.Index(body, "0.69.0"); i70 < 0 || i69 < 0 || i70 > i69 {
		t.Fatalf("releases not newest-first: 0.70.0 at %d, 0.69.0 at %d", i70, i69)
	}
}

// TestProductUpdatesPage_LoadErrorRendersNoticeNot500 is the other half of
// T11: a feed that failed to load at startup serves a notice, not a 500 and
// not stale/partial entries.
func TestProductUpdatesPage_LoadErrorRendersNoticeNot500(t *testing.T) {
	// Groups would normally be non-empty; passing loadErr must still
	// suppress every entry, proving the page does not serve partial content.
	groups := productupdate.RenderDocs(productupdate.Feed{Entries: []productupdate.Entry{puEntry("send-message", "0.69.0")}})
	h := ProductUpdates(groups, errors.New("read feed: no such directory"), "https://tg.mctl.ai", false)
	req := httptest.NewRequest(http.MethodGet, "/docs/product-updates", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a notice, not a 500)", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "send-message") || strings.Contains(body, "Send messages") {
		t.Fatalf("stale/partial entries rendered despite a load error:\n%s", body)
	}
	if !strings.Contains(strings.ToLower(body), "could not be loaded") {
		t.Fatalf("no load-error notice rendered:\n%s", body)
	}
}
