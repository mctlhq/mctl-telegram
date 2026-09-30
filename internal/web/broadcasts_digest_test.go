package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/productupdate"
)

// The digest id the page suggests and the README documents must be one
// FreezeDigest accepts: the first suggestion, product_updates-2026-w39, was
// refused by the id pattern for its underscore (#715 review). This submits
// the page's own placeholder end to end, and checks the README convention
// for every category.
func TestBroadcastPage_DigestIDConventionFreezes(t *testing.T) {
	feed := productupdate.Feed{Entries: []productupdate.Entry{maintenanceDigestEntry("maint-note")}}
	e := newBroadcastEnv(t, func(d *DigestSource) { *d = DigestSource{Feed: feed, LatestRelease: "0.70.0"} })

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/broadcasts", nil)
	req = req.WithContext(auth.With(req.Context(), e.connectIdentity()))
	w := httptest.NewRecorder()
	e.srv.HandleList(w, req)
	m := regexp.MustCompile(`name="digest_id" placeholder="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no digest_id placeholder on the page:\n%s", w.Body.String())
	}
	placeholder := m[1]

	readme, err := os.ReadFile("../../docs/product-updates/README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "`"+placeholder+"`") {
		t.Fatalf("README does not document the page's placeholder %q", placeholder)
	}

	form := url.Values{"category": {"maintenance"}, "digest_id": {placeholder}, "version": {"1"}}
	if w := e.prepareDigest(e.connectIdentity(), bcIssuer, form); w.Code != http.StatusSeeOther {
		t.Fatalf("prepare-digest with the page's placeholder %q = %d %s", placeholder, w.Code, w.Body.String())
	}

	// The README convention: <category>-<YYYY>-w<WW>, underscores as hyphens.
	for _, c := range db.NotificationCategories() {
		id := strings.ReplaceAll(string(c), "_", "-") + "-2026-w39"
		entry := maintenanceDigestEntry("any-note")
		if _, err := productupdate.FreezeDigest(id, 1, entry.Category(), "0.70.0", []productupdate.Entry{entry}); err != nil {
			t.Errorf("README convention id %q is refused: %v", id, err)
		}
	}
}

// A render refusal happens before anything is stored, so the id, version
// and entries stay free (#715 review: persisting before render wedged them).
func TestBroadcastPage_PrepareFromDigest_RenderRefusalStoresNothing(t *testing.T) {
	var entries []productupdate.Entry
	for i := 0; i < 80; i++ {
		en := maintenanceDigestEntry(fmt.Sprintf("maint-note-%02d", i))
		en.Title = strings.Repeat("Long maintenance title ", 6)
		entries = append(entries, en)
	}
	feed := productupdate.Feed{Entries: entries}
	e := newBroadcastEnv(t, func(d *DigestSource) { *d = DigestSource{Feed: feed, LatestRelease: "0.70.0"} })

	form := url.Values{"category": {"maintenance"}, "digest_id": {"maint-2026-w39"}, "version": {"1"}}
	w := e.prepareDigest(e.connectIdentity(), bcIssuer, form)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "compact form") {
		t.Fatalf("prepare-digest = %d %s, want a 409 render refusal", w.Code, w.Body.String())
	}
	assertDigestNotStored(t, e, "maint-2026-w39", 1, entries[0].ID)
}

// A Prepare refusal after the digest was stored discards it again, so a
// retry -- with the same id and version or another -- is not wedged.
func TestBroadcastPage_PrepareFromDigest_PrepareRefusalDiscardsDigest(t *testing.T) {
	entry := maintenanceDigestEntry("maint-note")
	feed := productupdate.Feed{Entries: []productupdate.Entry{entry}}
	e := newBroadcastEnv(t, func(d *DigestSource) { *d = DigestSource{Feed: feed, LatestRelease: "0.70.0"} })

	form := url.Values{"category": {"maintenance"}, "digest_id": {"maint-2026-w39"}, "version": {"1"}, "connected_via": {"nobody-connects-this-way"}}
	w := e.prepareDigest(e.connectIdentity(), bcIssuer, form)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "no eligible recipients") {
		t.Fatalf("prepare-digest = %d %s, want a 409 no-eligible-recipients refusal", w.Code, w.Body.String())
	}
	assertDigestNotStored(t, e, "maint-2026-w39", 1, entry.ID)

	form.Del("connected_via")
	if w := e.prepareDigest(e.connectIdentity(), bcIssuer, form); w.Code != http.StatusSeeOther {
		t.Fatalf("retry after the refusal = %d %s", w.Code, w.Body.String())
	}
	if _, err := e.store.GetProductUpdateDigest(context.Background(), "maint-2026-w39", 1); err != nil {
		t.Fatalf("digest after a successful retry: %v", err)
	}
}

// A double submit of the same form prepares one campaign; the second is an
// operator refusal naming the busy category, not an internal failure.
func TestBroadcastPage_PrepareFromDigest_DoubleSubmit(t *testing.T) {
	feed := productupdate.Feed{Entries: []productupdate.Entry{maintenanceDigestEntry("maint-note")}}
	e := newBroadcastEnv(t, func(d *DigestSource) { *d = DigestSource{Feed: feed, LatestRelease: "0.70.0"} })
	form := url.Values{"category": {"maintenance"}, "digest_id": {"maint-2026-w39"}, "version": {"1"}}
	if w := e.prepareDigest(e.connectIdentity(), bcIssuer, form); w.Code != http.StatusSeeOther {
		t.Fatalf("first submit = %d %s", w.Code, w.Body.String())
	}
	w := e.prepareDigest(e.connectIdentity(), bcIssuer, form)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "already prepared") {
		t.Fatalf("second submit = %d %s, want a 409 busy-category refusal", w.Code, w.Body.String())
	}
	list, err := e.store.ListBroadcastCampaigns(context.Background(), 10, db.CampaignPrepared)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("prepared campaigns = %d, want 1", len(list))
	}
	// The digest the first submit stored belongs to its campaign: the
	// refused second submit must not have discarded it.
	if _, err := e.store.GetProductUpdateDigest(context.Background(), "maint-2026-w39", 1); err != nil {
		t.Fatalf("the first submit's digest after the refused second: %v", err)
	}
}

// A store failure is an internal error: the generic failure page and an
// Error log, never the raw error on a 409 refusal page (#715 review:
// everything used to be wrapped as a refusal).
func TestBroadcastPage_PrepareFromDigest_StoreFailureIsInternal(t *testing.T) {
	feed := productupdate.Feed{Entries: []productupdate.Entry{maintenanceDigestEntry("maint-note")}}
	e := newBroadcastEnv(t, func(d *DigestSource) { *d = DigestSource{Feed: feed, LatestRelease: "0.70.0"} })
	// Break the one table the busy-category guard reads; the audit log and
	// everything before the guard keep working.
	if _, err := e.store.DB.ExecContext(context.Background(), `ALTER TABLE broadcast_campaigns RENAME TO broadcast_campaigns_gone`); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	form := url.Values{"category": {"maintenance"}, "digest_id": {"maint-2026-w39"}, "version": {"1"}}
	w := e.prepareDigest(e.connectIdentity(), bcIssuer, form)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d %s, want 500", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "broadcast_campaigns") {
		t.Fatalf("the internal error reached the page: %s", w.Body.String())
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "action failed") {
		t.Fatalf("no Error log for the store failure:\n%s", logs.String())
	}
}

func assertDigestNotStored(t *testing.T, e *bcEnv, id string, version int, entryID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := e.store.GetProductUpdateDigest(ctx, id, version); !errors.Is(err, db.ErrDigestNotFound) {
		t.Fatalf("digest %s v%d after the refusal: %v, want ErrDigestNotFound", id, version, err)
	}
	published, err := e.store.PublishedProductUpdateEntries(ctx, "some-other-digest")
	if err != nil {
		t.Fatal(err)
	}
	if published[entryID] {
		t.Fatalf("%s is claimed by a digest that never became a campaign", entryID)
	}
}

// T8 at the page level: each refusal below is a 409 with its documented
// message, and writes no campaign and no digest.
func TestBroadcastPage_PrepareFromDigest_GuardRefusals(t *testing.T) {
	entry := maintenanceDigestEntry("maint-note")
	feed := productupdate.Feed{Entries: []productupdate.Entry{entry}}
	for _, tc := range []struct {
		name    string
		source  DigestSource
		version string
		want    string
	}{
		{"version 2 without version 1", DigestSource{Feed: feed, LatestRelease: "0.70.0"}, "2", "needs a stored version 1 first"},
		{"empty LatestRelease (a dev build)", DigestSource{Feed: feed, LatestRelease: ""}, "1", "is not a released tag"},
		{"feed not loaded", DigestSource{Feed: feed, LatestRelease: "0.70.0", LoadErr: errors.New("product update feed directory \"/srv/x\" does not exist")}, "1", "feed is not loaded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newBroadcastEnv(t, func(d *DigestSource) { *d = tc.source })
			form := url.Values{"category": {"maintenance"}, "digest_id": {"maint-2026-w39"}, "version": {tc.version}}
			w := e.prepareDigest(e.connectIdentity(), bcIssuer, form)
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("prepare-digest = %d %s, want 409 containing %q", w.Code, w.Body.String(), tc.want)
			}
			list, err := e.store.ListBroadcastCampaigns(context.Background(), 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != 0 {
				t.Fatalf("campaigns after the refusal = %d, want 0", len(list))
			}
			for _, v := range []int{1, 2} {
				if _, err := e.store.GetProductUpdateDigest(context.Background(), "maint-2026-w39", v); !errors.Is(err, db.ErrDigestNotFound) {
					t.Fatalf("digest v%d after the refusal: %v, want ErrDigestNotFound", v, err)
				}
			}
			assertDigestNotStored(t, e, "maint-2026-w39", 1, entry.ID)
		})
	}
}

// T9 consent safety: a product_updates digest is prepared with the
// product_updates selector category -- the opt-in category -- so it reaches
// only subscribers, never the opt-out maintenance audience.
func TestBroadcastPage_PrepareFromDigest_ProductUpdatesKeepsItsCategory(t *testing.T) {
	entry := productupdate.Entry{
		Schema: productupdate.EntrySchema, ID: "send-message", Kind: productupdate.KindNewTool,
		Title: "Send messages", Summary: "You can now send a message to a chat.",
		Locale: "en", Delivery: productupdate.DeliveryNextDigest,
		Tools:      []string{"send_message"},
		Evidence:   productupdate.Evidence{From: "0.69.0", Changes: []productupdate.Claim{{Tool: "send_message", Change: productupdate.ClaimAdded}}},
		Status:     productupdate.StatusApproved,
		Provenance: productupdate.Provenance{Author: "alice", ReviewedBy: "alice"},
		CreatedAt:  "2026-09-24", ReviewedAt: "2026-09-24",
	}
	if entry.Category() != db.CategoryProductUpdates {
		t.Fatalf("fixture category = %s, want product_updates", entry.Category())
	}
	feed := productupdate.Feed{Entries: []productupdate.Entry{entry}}
	e := newBroadcastEnv(t, func(d *DigestSource) { *d = DigestSource{Feed: feed, LatestRelease: "0.70.0"} })
	// product_updates is opt-in: without a subscriber there is no audience.
	ctx := context.Background()
	if err := e.store.SetNotificationPrefs(ctx, e.clients[0], map[string]string{
		string(db.CategoryProductUpdates): db.PrefSubscribed,
	}, "account_api"); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"category": {"product_updates"}, "digest_id": {"product-updates-2026-w39"}, "version": {"1"}}
	if w := e.prepareDigest(e.connectIdentity(), bcIssuer, form); w.Code != http.StatusSeeOther {
		t.Fatalf("prepare-digest = %d %s", w.Code, w.Body.String())
	}
	list, err := e.store.ListBroadcastCampaigns(ctx, 10, db.CampaignPrepared)
	if err != nil || len(list) != 1 {
		t.Fatalf("prepared campaigns = %d (%v), want 1", len(list), err)
	}
	c := list[0]
	if c.Category != string(db.CategoryProductUpdates) {
		t.Fatalf("campaign category = %s, want product_updates", c.Category)
	}
	if !strings.Contains(c.SelectorJSON, `"category":"product_updates"`) {
		t.Fatalf("selector %s does not carry the product_updates category", c.SelectorJSON)
	}
	d, err := e.store.GetProductUpdateDigest(ctx, "product-updates-2026-w39", 1)
	if err != nil || d.Category != string(db.CategoryProductUpdates) {
		t.Fatalf("stored digest = %+v, %v; want category product_updates", d, err)
	}
}
