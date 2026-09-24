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
