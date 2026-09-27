package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

// TestProductUpdateDigestStore_SQLite and _Postgres run the same body on both
// dialects, as the broadcast campaign store tests do: the digest store is
// hand-written SQL in two schema lists.
func TestProductUpdateDigestStore_SQLite(t *testing.T) {
	assertProductUpdateDigestStore(t, newTestStore(t), 830000001)
}

func TestProductUpdateDigestStore_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	assertProductUpdateDigestStore(t, newPostgresTestStore(t, dsn), 840000001)
}

func assertProductUpdateDigestStore(t *testing.T, s *Store, tgID int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	// Postgres keeps state between runs, so every id carries this run's
	// prefix; SQLite is fresh each time.
	p := fmt.Sprintf("pu%d-", now.UnixNano())
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM broadcast_campaigns WHERE id LIKE $1`, p+"%")
		_, _ = s.DB.Exec(`DELETE FROM product_update_publications WHERE digest_id LIKE $1`, p+"%")
		_, _ = s.DB.Exec(`DELETE FROM product_update_entry_owners WHERE entry_id LIKE $1`, p+"%")
		_, _ = s.DB.Exec(`DELETE FROM product_update_digests WHERE id LIKE $1`, p+"%")
	})
	uid := productUpdateTestUser(t, s, tgID, now)

	weekly := ProductUpdateDigest{
		ID: p + "weekly", Version: 1, Category: string(CategoryProductUpdates), ContentHash: "sha256:one",
		SourceRefs: []string{"a@1", "b@1"}, EntryIDs: []string{p + "b", p + "a"}, CreatedBy: uid,
	}
	stored, err := s.SaveProductUpdateDigest(ctx, weekly, now)
	if err != nil || !stored {
		t.Fatalf("save: stored=%v err=%v", stored, err)
	}

	// Freeze immutability: the identical digest again is a harmless retry,
	// and the same (id, version) with other content is refused and leaves the
	// stored row as it was.
	if stored, err := s.SaveProductUpdateDigest(ctx, weekly, now.Add(time.Minute)); err != nil || stored {
		t.Fatalf("identical re-save: stored=%v err=%v; want a no-op", stored, err)
	}
	changed := weekly
	changed.ContentHash = "sha256:two"
	if _, err := s.SaveProductUpdateDigest(ctx, changed, now); !errors.Is(err, ErrDigestConflict) {
		t.Fatalf("overwrite with another content hash: %v; want ErrDigestConflict", err)
	}
	moreEntries := weekly
	moreEntries.EntryIDs = []string{p + "a", p + "b", p + "c"}
	moreEntries.SourceRefs = []string{"a@1", "b@1", "c@1"}
	if _, err := s.SaveProductUpdateDigest(ctx, moreEntries, now); !errors.Is(err, ErrDigestConflict) {
		t.Fatalf("overwrite with other entries: %v; want ErrDigestConflict", err)
	}
	otherEntries := weekly
	otherEntries.EntryIDs = []string{p + "a", p + "x"}
	if _, err := s.SaveProductUpdateDigest(ctx, otherEntries, now); !errors.Is(err, ErrDigestConflict) {
		t.Fatalf("overwrite with the same refs but other entry ids: %v; want ErrDigestConflict", err)
	}
	got, err := s.GetProductUpdateDigest(ctx, weekly.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentHash != "sha256:one" || !slices.Equal(got.EntryIDs, []string{p + "a", p + "b"}) ||
		!slices.Equal(got.SourceRefs, weekly.SourceRefs) || got.Category != weekly.Category || got.CreatedBy != uid ||
		!got.CreatedAt.Equal(now) {
		t.Fatalf("stored digest changed: %+v", got)
	}
	if _, err := s.GetProductUpdateDigest(ctx, weekly.ID, 9); !errors.Is(err, ErrDigestNotFound) {
		t.Fatalf("missing version: %v", err)
	}

	// Dedupe: the carried entries are the published set, except for the
	// digest's own id; another digest id cannot carry them again, a later
	// version of the same digest can.
	published, err := s.PublishedProductUpdateEntries(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if !published[p+"a"] || !published[p+"b"] {
		t.Fatalf("published set %v misses the carried entries", published)
	}
	own, err := s.PublishedProductUpdateEntries(ctx, weekly.ID)
	if err != nil {
		t.Fatal(err)
	}
	if own[p+"a"] || own[p+"b"] {
		t.Fatalf("published set except %s still holds its entries: %v", weekly.ID, own)
	}
	other := ProductUpdateDigest{
		ID: p + "other", Version: 1, Category: string(CategoryProductUpdates), ContentHash: "sha256:three",
		SourceRefs: []string{"b@1", "c@1"}, EntryIDs: []string{p + "b", p + "c"}, CreatedBy: uid,
	}
	if _, err := s.SaveProductUpdateDigest(ctx, other, now); !errors.Is(err, ErrDigestEntryPublished) {
		t.Fatalf("second digest carrying a published entry: %v; want ErrDigestEntryPublished", err)
	}
	if _, err := s.GetProductUpdateDigest(ctx, other.ID, 1); !errors.Is(err, ErrDigestNotFound) {
		t.Fatalf("a refused digest was written: %v", err)
	}
	if published, _ := s.PublishedProductUpdateEntries(ctx, ""); published[p+"c"] {
		t.Fatal("a refused digest's entries were published")
	}
	v2 := weekly
	v2.Version, v2.ContentHash = 2, "sha256:v2"
	if stored, err := s.SaveProductUpdateDigest(ctx, v2, now); err != nil || !stored {
		t.Fatalf("a later version of the same digest: stored=%v err=%v", stored, err)
	}

	// Entry ids whose byte order and a libc collation's order disagree: the
	// postgres image's default en_US.utf8 ignores the hyphen at the primary
	// level and sorts "exportable-feed" before "export-chat". An identical
	// re-save of such a digest must still be a no-op, and the stored digest
	// reads back in byte order whatever the server collation.
	hyphenated := ProductUpdateDigest{
		ID: p + "hyphenated", Version: 1, Category: string(CategoryProductUpdates), ContentHash: "sha256:hy",
		SourceRefs: []string{"x@1", "y@1"}, EntryIDs: []string{p + "exportable-feed", p + "export-chat"}, CreatedBy: uid,
	}
	if stored, err := s.SaveProductUpdateDigest(ctx, hyphenated, now); err != nil || !stored {
		t.Fatalf("save hyphenated: stored=%v err=%v", stored, err)
	}
	if stored, err := s.SaveProductUpdateDigest(ctx, hyphenated, now.Add(time.Minute)); err != nil || stored {
		t.Fatalf("identical re-save of hyphenated ids: stored=%v err=%v; want a no-op", stored, err)
	}
	got, err = s.GetProductUpdateDigest(ctx, hyphenated.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{p + "export-chat", p + "exportable-feed"}; !slices.Equal(got.EntryIDs, want) {
		t.Fatalf("hyphenated entry ids read back as %v; want byte order %v", got.EntryIDs, want)
	}

	// The owner table refuses on its own: an entry owned by another digest
	// id is refused even when no publication row names it, which is the
	// state a concurrent saver that skipped the table lock would find.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO product_update_entry_owners(entry_id, digest_id) VALUES($1,$2)`, p+"owned", p+"racer"); err != nil {
		t.Fatal(err)
	}
	owned := ProductUpdateDigest{
		ID: p + "late", Version: 1, Category: string(CategoryProductUpdates), ContentHash: "sha256:late",
		SourceRefs: []string{"o@1"}, EntryIDs: []string{p + "owned"}, CreatedBy: uid,
	}
	if _, err := s.SaveProductUpdateDigest(ctx, owned, now); !errors.Is(err, ErrDigestEntryPublished) {
		t.Fatalf("entry owned by another digest id: %v; want ErrDigestEntryPublished", err)
	}
	if _, err := s.GetProductUpdateDigest(ctx, owned.ID, 1); !errors.Is(err, ErrDigestNotFound) {
		t.Fatalf("a digest refused by the owner table was written: %v", err)
	}
	// ...and the published set agrees with it, so FreezeNextDigest never
	// offers an entry that saving would refuse.
	if published, err := s.PublishedProductUpdateEntries(ctx, owned.ID); err != nil || !published[p+"owned"] {
		t.Fatalf("an owned entry is missing from the published set: %v, %v", published, err)
	}

	bad := weekly
	bad.Category = "mixed"
	if _, err := s.SaveProductUpdateDigest(ctx, bad, now); !errors.Is(err, ErrUnknownNotificationCategory) {
		t.Fatalf("unknown category: %v", err)
	}

	// source_ref: nullable, set once, never changed.
	mk := func(suffix, category string, expires time.Time) string {
		id := p + suffix
		if err := s.CreateBroadcastCampaign(ctx, BroadcastCampaign{
			ID: id, Category: category, SelectorJSON: `{}`, SelectorHash: "sh", Content: "text",
			ContentHash: "ch", CreatedBy: uid, Surface: "test", RecipientLimit: 10, ExpiresAt: expires,
		}, now); err != nil {
			t.Fatalf("create %s: %v", suffix, err)
		}
		return id
	}
	ref := CampaignSourceRef{DigestID: weekly.ID, DigestVersion: 1, ContentHash: "sha256:one"}
	manual := mk("manual", string(CategoryProductUpdates), now.Add(time.Hour))
	if c, err := s.GetBroadcastCampaign(ctx, manual); err != nil || c.SourceRef != nil {
		t.Fatalf("a new campaign has a source_ref: %+v, %v", c, err)
	}
	if err := s.SetBroadcastCampaignSourceRef(ctx, manual, ref, now); err != nil {
		t.Fatalf("set source_ref: %v", err)
	}
	if err := s.SetBroadcastCampaignSourceRef(ctx, manual, ref, now); err != nil {
		t.Fatalf("set the same source_ref again: %v", err)
	}
	for name, change := range map[string]CampaignSourceRef{
		"version":      {DigestID: weekly.ID, DigestVersion: 2, ContentHash: "sha256:v2"},
		"content hash": {DigestID: weekly.ID, DigestVersion: 1, ContentHash: "sha256:two"},
	} {
		if err := s.SetBroadcastCampaignSourceRef(ctx, manual, change, now); !errors.Is(err, ErrCampaignSourceRefSet) {
			t.Fatalf("changing the source_ref %s: %v; want ErrCampaignSourceRefSet", name, err)
		}
	}
	if c, err := s.GetBroadcastCampaign(ctx, manual); err != nil || c.SourceRef == nil || *c.SourceRef != ref {
		t.Fatalf("source_ref after refused changes: %+v, %v; want %+v", c.SourceRef, err, ref)
	}

	fresh := mk("fresh", string(CategoryProductUpdates), now.Add(time.Hour))
	if err := s.SetBroadcastCampaignSourceRef(ctx, fresh, CampaignSourceRef{DigestID: p + "nope", DigestVersion: 1, ContentHash: "x"}, now); !errors.Is(err, ErrDigestNotFound) {
		t.Fatalf("unknown digest: %v", err)
	}
	if err := s.SetBroadcastCampaignSourceRef(ctx, fresh, CampaignSourceRef{DigestID: weekly.ID, DigestVersion: 1, ContentHash: "sha256:two"}, now); !errors.Is(err, ErrCampaignSourceMismatch) {
		t.Fatalf("content hash that is not the stored digest's: %v", err)
	}
	maint := mk("maint", string(CategoryMaintenance), now.Add(time.Hour))
	if err := s.SetBroadcastCampaignSourceRef(ctx, maint, ref, now); !errors.Is(err, ErrCampaignSourceMismatch) {
		t.Fatalf("digest of another category: %v", err)
	}
	if err := s.CancelBroadcastCampaign(ctx, fresh, uid, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetBroadcastCampaignSourceRef(ctx, fresh, ref, now); !errors.Is(err, ErrCampaignNotPrepared) {
		t.Fatalf("source_ref on a cancelled campaign: %v", err)
	}
	if err := s.SetBroadcastCampaignSourceRef(ctx, p+"missing", ref, now); !errors.Is(err, ErrCampaignNotFound) {
		t.Fatalf("missing campaign: %v", err)
	}
	for _, id := range []string{fresh, maint} {
		if c, err := s.GetBroadcastCampaign(ctx, id); err != nil || c.SourceRef != nil {
			t.Fatalf("a refused source_ref was written to %s: %+v, %v", id, c, err)
		}
	}
}

// productUpdateTestUser returns a fresh users row for tgID, clearing what an
// earlier Postgres run left behind first: campaigns and digests reference the
// user with no cascade.
func productUpdateTestUser(t *testing.T, s *Store, tgID int64, now time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`DELETE FROM broadcast_campaigns WHERE created_by IN (SELECT id FROM users WHERE telegram_login_id = $1)`,
		`DELETE FROM product_update_publications WHERE (digest_id, digest_version) IN
		   (SELECT id, version FROM product_update_digests WHERE created_by IN (SELECT id FROM users WHERE telegram_login_id = $1))`,
		`DELETE FROM product_update_entry_owners WHERE digest_id IN
		   (SELECT id FROM product_update_digests WHERE created_by IN (SELECT id FROM users WHERE telegram_login_id = $1))`,
		`DELETE FROM product_update_digests WHERE created_by IN (SELECT id FROM users WHERE telegram_login_id = $1)`,
		`DELETE FROM users WHERE telegram_login_id = $1`,
	} {
		if _, err := s.DB.ExecContext(ctx, q, tgID); err != nil {
			t.Fatalf("reset: %v", err)
		}
	}
	uid, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: tgID, Username: "pu", FirstName: "P", Source: "telegram_oidc", CapturedAt: now,
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	return uid
}

// Every guard in ProductUpdateDigest.validate refuses its shape before
// anything is written.
func TestSaveProductUpdateDigestRejectsInvalidShapes(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()
	uid := productUpdateTestUser(t, s, 830000002, now)
	valid := func() ProductUpdateDigest {
		return ProductUpdateDigest{
			ID: "weekly", Version: 1, Category: string(CategoryProductUpdates), ContentHash: "sha256:one",
			SourceRefs: []string{"a@1", "b@1"}, EntryIDs: []string{"a", "b"}, CreatedBy: uid,
		}
	}
	for name, mutate := range map[string]func(*ProductUpdateDigest){
		"empty id":           func(d *ProductUpdateDigest) { d.ID = "" },
		"version 0":          func(d *ProductUpdateDigest) { d.Version = 0 },
		"negative version":   func(d *ProductUpdateDigest) { d.Version = -1 },
		"unknown category":   func(d *ProductUpdateDigest) { d.Category = "mixed" },
		"empty content hash": func(d *ProductUpdateDigest) { d.ContentHash = "" },
		"no creator":         func(d *ProductUpdateDigest) { d.CreatedBy = 0 },
		"no entries":         func(d *ProductUpdateDigest) { d.EntryIDs, d.SourceRefs = nil, nil },
		"fewer refs":         func(d *ProductUpdateDigest) { d.SourceRefs = d.SourceRefs[:1] },
		"more refs":          func(d *ProductUpdateDigest) { d.SourceRefs = append(d.SourceRefs, "c@1") },
		"empty entry id":     func(d *ProductUpdateDigest) { d.EntryIDs = []string{"a", ""} },
		"repeated entry id":  func(d *ProductUpdateDigest) { d.EntryIDs = []string{"a", "a"} },
	} {
		t.Run(name, func(t *testing.T) {
			d := valid()
			mutate(&d)
			if stored, err := s.SaveProductUpdateDigest(ctx, d, now); err == nil || stored {
				t.Fatalf("stored=%v err=%v; want a refusal", stored, err)
			}
			if d.ID != "" {
				if _, err := s.GetProductUpdateDigest(ctx, d.ID, d.Version); !errors.Is(err, ErrDigestNotFound) {
					t.Fatalf("a refused digest was written: %v", err)
				}
			}
		})
	}
	if stored, err := s.SaveProductUpdateDigest(ctx, valid(), now); err != nil || !stored {
		t.Fatalf("the valid shape itself: stored=%v err=%v", stored, err)
	}
}
