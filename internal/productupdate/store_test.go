package productupdate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func newDigestStore(t *testing.T) (*db.Store, int64) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, fmt.Sprintf("file:pu-%d?mode=memory&cache=shared", time.Now().UnixNano()), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(conn, nil)
	uid, err := s.EnsureUser(ctx, "operator", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	return s, uid
}

// An entry a stored digest carried is never a candidate for another digest:
// the published set comes from the database, not from the caller.
func TestFreezeNextDigestNeverOffersAPublishedEntryAgain(t *testing.T) {
	ctx := context.Background()
	s, uid := newDigestStore(t)
	now := time.Now().UTC()
	a, b, c := approved("send-message"), approved("list-dialogs"), approved("pin-message")

	first, stored, err := FreezeNextDigest(ctx, s, Feed{Entries: []Entry{a, b}}, "weekly-2026-39", 1, db.CategoryProductUpdates, "0.70.0", uid, now)
	if err != nil || !stored {
		t.Fatalf("first digest: stored=%v err=%v", stored, err)
	}
	if ids, _ := first.EntryIDs(); !slices.Equal(ids, []string{"list-dialogs", "send-message"}) {
		t.Fatalf("first digest carries %v", ids)
	}

	// A week later c is approved too; only c is new.
	next, stored, err := FreezeNextDigest(ctx, s, Feed{Entries: []Entry{a, b, c}}, "weekly-2026-40", 1, db.CategoryProductUpdates, "0.71.0", uid, now)
	if err != nil || !stored {
		t.Fatalf("next digest: stored=%v err=%v", stored, err)
	}
	if ids, _ := next.EntryIDs(); !slices.Equal(ids, []string{"pin-message"}) {
		t.Fatalf("next digest carries %v; a published entry was offered again", ids)
	}

	// Nothing new: there is nothing to freeze.
	if _, _, err := FreezeNextDigest(ctx, s, Feed{Entries: []Entry{a, b, c}}, "weekly-2026-41", 1, db.CategoryProductUpdates, "0.71.0", uid, now); err == nil {
		t.Fatal("a digest of already published entries was frozen")
	}

	// Repeating the first call (a lost response) yields the same digest and
	// stores nothing.
	again, stored, err := FreezeNextDigest(ctx, s, Feed{Entries: []Entry{a, b}}, "weekly-2026-39", 1, db.CategoryProductUpdates, "0.70.0", uid, now)
	if err != nil || stored || again.ContentHash != first.ContentHash {
		t.Fatalf("retry: stored=%v err=%v hash=%s want %s", stored, err, again.ContentHash, first.ContentHash)
	}
}

// A stored digest is immutable: the same id and version frozen from edited
// content is refused, and the stored row keeps the original hash.
func TestPersistDigestNeverOverwritesAFrozenDigest(t *testing.T) {
	ctx := context.Background()
	s, uid := newDigestStore(t)
	now := time.Now().UTC()
	e := approved("send-message")
	d, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, "0.70.0", []Entry{e})
	if err != nil {
		t.Fatal(err)
	}
	if stored, err := PersistDigest(ctx, s, d, uid, now); err != nil || !stored {
		t.Fatalf("persist: stored=%v err=%v", stored, err)
	}
	if stored, err := PersistDigest(ctx, s, d, uid, now); err != nil || stored {
		t.Fatalf("identical re-persist: stored=%v err=%v; want a no-op", stored, err)
	}
	e.Summary = "Edited after the digest was frozen."
	edited, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, "0.70.0", []Entry{e})
	if err != nil {
		t.Fatal(err)
	}
	if edited.ContentHash == d.ContentHash {
		t.Fatal("editing the summary did not change the content hash")
	}
	if _, err := PersistDigest(ctx, s, edited, uid, now); !errors.Is(err, db.ErrDigestConflict) {
		t.Fatalf("overwrite: %v; want db.ErrDigestConflict", err)
	}
	got, err := s.GetProductUpdateDigest(ctx, "weekly-2026-39", 1)
	if err != nil || got.ContentHash != d.ContentHash || !slices.Equal(got.SourceRefs, d.SourceRefs) {
		t.Fatalf("stored digest after a refused overwrite: %+v, %v", got, err)
	}
}

func TestDigestEntryIDsRejectsAForeignRef(t *testing.T) {
	d := Digest{ID: "weekly-2026-39", SourceRefs: []string{"elsewhere/send-message.yaml@content-sha256:ab"}}
	if _, err := d.EntryIDs(); err == nil {
		t.Fatal("a ref outside the feed directory was accepted")
	}
	d.SourceRefs = []string{FeedDir + "/send-message.yaml@content-sha256:ab"}
	if ids, err := d.EntryIDs(); err != nil || !slices.Equal(ids, []string{"send-message"}) {
		t.Fatalf("ids %v, %v", ids, err)
	}
}

// PersistDigest refuses a digest of another schema, or one whose refs do not
// name feed entries, before anything reaches the store.
func TestPersistDigestRejectsForeignShapes(t *testing.T) {
	ctx := context.Background()
	s, uid := newDigestStore(t)
	d, err := FreezeDigest("weekly-2026-39", 1, db.CategoryProductUpdates, "0.70.0", []Entry{approved("send-message")})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Digest){
		"other schema": func(d *Digest) { d.Schema = "mctl-telegram.product-update-digest/v2" },
		"no schema":    func(d *Digest) { d.Schema = "" },
		"foreign ref":  func(d *Digest) { d.SourceRefs = []string{"elsewhere/send-message.yaml@content-sha256:ab"} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := d
			bad.SourceRefs = slices.Clone(d.SourceRefs)
			mutate(&bad)
			if stored, err := PersistDigest(ctx, s, bad, uid, time.Now().UTC()); err == nil || stored {
				t.Fatalf("stored=%v err=%v; want a refusal", stored, err)
			}
			if _, err := s.GetProductUpdateDigest(ctx, d.ID, d.Version); !errors.Is(err, db.ErrDigestNotFound) {
				t.Fatalf("a refused digest was written: %v", err)
			}
		})
	}
}

// A later version of the same digest id is frozen from the earlier entries
// plus whatever was approved since, not from the earlier set alone; the new
// entries are then published under this id. Pinned so the documented
// behaviour cannot drift into an implied "correction reproduces v1".
func TestFreezeNextDigestLaterVersionTakesNewEntriesToo(t *testing.T) {
	ctx := context.Background()
	s, uid := newDigestStore(t)
	now := time.Now().UTC()
	a, b := approved("send-message"), approved("list-dialogs")
	if _, _, err := FreezeNextDigest(ctx, s, Feed{Entries: []Entry{a}}, "weekly-2026-39", 1, db.CategoryProductUpdates, "0.70.0", uid, now); err != nil {
		t.Fatal(err)
	}
	v2, stored, err := FreezeNextDigest(ctx, s, Feed{Entries: []Entry{a, b}}, "weekly-2026-39", 2, db.CategoryProductUpdates, "0.71.0", uid, now)
	if err != nil || !stored {
		t.Fatalf("v2: stored=%v err=%v", stored, err)
	}
	if ids, _ := v2.EntryIDs(); !slices.Equal(ids, []string{"list-dialogs", "send-message"}) {
		t.Fatalf("v2 carries %v; want the v1 entry plus the newly approved one", ids)
	}
	if _, _, err := FreezeNextDigest(ctx, s, Feed{Entries: []Entry{a, b}}, "weekly-2026-40", 1, db.CategoryProductUpdates, "0.71.0", uid, now); err == nil {
		t.Fatal("the next digest id was offered an entry v2 of the previous one already carried")
	}
}
