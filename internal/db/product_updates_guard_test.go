package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// One active digest campaign per category and the discard of an unused
// digest (#715 review), on both dialects.
func TestDigestCampaignCategoryGuard_SQLite(t *testing.T) {
	assertDigestCampaignCategoryGuard(t, newTestStore(t), 830000011)
}

func TestDigestCampaignCategoryGuard_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	assertDigestCampaignCategoryGuard(t, newPostgresTestStore(t, dsn), 840000011)
}

func TestDiscardUnusedProductUpdateDigest_SQLite(t *testing.T) {
	assertDiscardUnusedProductUpdateDigest(t, newTestStore(t), 830000012)
}

func TestDiscardUnusedProductUpdateDigest_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	assertDiscardUnusedProductUpdateDigest(t, newPostgresTestStore(t, dsn), 840000012)
}

// TestDigestCampaignCategoryGuard_PostgresConcurrent is the double-submit
// race the NOT EXISTS predicate alone cannot close under READ COMMITTED:
// several digest campaigns for one category inserted at once. Exactly one
// may win; every other must read as ErrCampaignCategoryBusy.
func TestDigestCampaignCategoryGuard_PostgresConcurrent(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	uid := productUpdateTestUser(t, s, 840000013, now)
	clearActiveCampaigns(t, s, CategoryProductUpdates)

	const racers = 8
	refs := make([]CampaignSourceRef, racers)
	for i := range refs {
		d := guardDigest(uid, fmt.Sprintf("race-%d", i), fmt.Sprintf("race-entry-%d", i))
		if _, err := s.SaveProductUpdateDigest(ctx, d, now); err != nil {
			t.Fatalf("save %s: %v", d.ID, err)
		}
		refs[i] = CampaignSourceRef{DigestID: d.ID, DigestVersion: 1, ContentHash: d.ContentHash}
	}
	for round := 0; round < 5; round++ {
		clearActiveCampaigns(t, s, CategoryProductUpdates)
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, racers)
		for i := range refs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = s.CreateBroadcastCampaign(ctx, guardCampaign(uid, fmt.Sprintf("bc_race_%d_%d", round, i), refs[i]), now)
			}(i)
		}
		close(start)
		wg.Wait()
		won := 0
		for i, err := range errs {
			switch {
			case err == nil:
				won++
			case errors.Is(err, ErrCampaignCategoryBusy):
			default:
				t.Fatalf("round %d racer %d: %v", round, i, err)
			}
		}
		if won != 1 {
			t.Fatalf("round %d: %d concurrent digest campaigns created for one category, want exactly 1", round, won)
		}
	}
}

func assertDigestCampaignCategoryGuard(t *testing.T, s *Store, tgID int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	uid := productUpdateTestUser(t, s, tgID, now)
	clearActiveCampaigns(t, s, CategoryProductUpdates)

	a := guardDigest(uid, fmt.Sprintf("guard-a-%d", tgID), fmt.Sprintf("guard-a-entry-%d", tgID))
	b := guardDigest(uid, fmt.Sprintf("guard-b-%d", tgID), fmt.Sprintf("guard-b-entry-%d", tgID))
	for _, d := range []ProductUpdateDigest{a, b} {
		if _, err := s.SaveProductUpdateDigest(ctx, d, now); err != nil {
			t.Fatalf("save %s: %v", d.ID, err)
		}
	}
	refA := CampaignSourceRef{DigestID: a.ID, DigestVersion: 1, ContentHash: a.ContentHash}
	refB := CampaignSourceRef{DigestID: b.ID, DigestVersion: 1, ContentHash: b.ContentHash}
	first := guardCampaign(uid, fmt.Sprintf("bc_guard_first_%d", tgID), refA)
	if err := s.CreateBroadcastCampaign(ctx, first, now); err != nil {
		t.Fatalf("first digest campaign: %v", err)
	}

	// A double submit through the store: refused, nothing written.
	second := guardCampaign(uid, fmt.Sprintf("bc_guard_second_%d", tgID), refB)
	if err := s.CreateBroadcastCampaign(ctx, second, now); !errors.Is(err, ErrCampaignCategoryBusy) {
		t.Fatalf("second digest campaign in the category: %v, want ErrCampaignCategoryBusy", err)
	}
	if _, err := s.GetBroadcastCampaign(ctx, second.ID); !errors.Is(err, ErrCampaignNotFound) {
		t.Fatalf("the refused campaign was written: %v", err)
	}
	active, err := s.ActiveBroadcastCampaign(ctx, string(CategoryProductUpdates))
	if err != nil || active.ID != first.ID {
		t.Fatalf("ActiveBroadcastCampaign = %+v, %v; want %s", active, err, first.ID)
	}

	// The database itself holds the rule, not only the NOT EXISTS read: an
	// INSERT that skips the predicate (what a concurrent racer's snapshot
	// amounts to) still fails on the partial unique index.
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO broadcast_campaigns(id, state, category, selector_json, selector_hash, content, content_hash,
		     created_by, surface, recipient_limit, preview_counts, expires_at, created_at, updated_at,
		     source_digest_id, source_digest_version, source_content_hash)
		 VALUES($1,'prepared',$2,'{}','sh','text','ch',$3,'web',10,'{}',$4,$5,$5,$6,1,$7)`,
		fmt.Sprintf("bc_guard_raw_%d", tgID), string(CategoryProductUpdates), uid, now.Add(time.Hour), now, b.ID, b.ContentHash)
	if err == nil {
		t.Fatal("a second active digest campaign for the category was inserted past the unique index")
	}

	// Once the first campaign is terminal the category is free again.
	if _, err := s.DB.ExecContext(ctx, `UPDATE broadcast_campaigns SET state = 'cancelled' WHERE id = $1`, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveBroadcastCampaign(ctx, string(CategoryProductUpdates)); !errors.Is(err, ErrCampaignNotFound) {
		t.Fatalf("ActiveBroadcastCampaign after cancel: %v, want ErrCampaignNotFound", err)
	}
	if err := s.CreateBroadcastCampaign(ctx, second, now); err != nil {
		t.Fatalf("digest campaign after the first ended: %v", err)
	}
}

func assertDiscardUnusedProductUpdateDigest(t *testing.T, s *Store, tgID int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	uid := productUpdateTestUser(t, s, tgID, now)
	clearActiveCampaigns(t, s, CategoryProductUpdates)
	entry := fmt.Sprintf("discard-entry-%d", tgID)
	otherID := fmt.Sprintf("discard-other-%d", tgID)

	d := guardDigest(uid, fmt.Sprintf("discard-%d", tgID), entry)
	if _, err := s.SaveProductUpdateDigest(ctx, d, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DiscardUnusedProductUpdateDigest(ctx, d.ID, 1, "sha256:someone-else"); !errors.Is(err, ErrDigestConflict) {
		t.Fatalf("discard with another content hash: %v, want ErrDigestConflict", err)
	}
	if err := s.DiscardUnusedProductUpdateDigest(ctx, d.ID, 1, d.ContentHash); err != nil {
		t.Fatalf("discard: %v", err)
	}
	if _, err := s.GetProductUpdateDigest(ctx, d.ID, 1); !errors.Is(err, ErrDigestNotFound) {
		t.Fatalf("digest after discard: %v, want ErrDigestNotFound", err)
	}
	published, err := s.PublishedProductUpdateEntries(ctx, otherID)
	if err != nil {
		t.Fatal(err)
	}
	if published[entry] {
		t.Fatalf("%s is still owned after its only digest was discarded", entry)
	}
	// The entry is free for another digest id, and the discarded (id,
	// version) can be frozen afresh with different content.
	other := guardDigest(uid, otherID, entry)
	if _, err := s.SaveProductUpdateDigest(ctx, other, now); err != nil {
		t.Fatalf("another digest carrying the freed entry: %v", err)
	}
	if err := s.DiscardUnusedProductUpdateDigest(ctx, d.ID, 1, d.ContentHash); !errors.Is(err, ErrDigestNotFound) {
		t.Fatalf("second discard: %v, want ErrDigestNotFound", err)
	}

	// A digest a campaign names is not the caller's to take back.
	ref := CampaignSourceRef{DigestID: other.ID, DigestVersion: 1, ContentHash: other.ContentHash}
	if err := s.CreateBroadcastCampaign(ctx, guardCampaign(uid, fmt.Sprintf("bc_discard_%d", tgID), ref), now); err != nil {
		t.Fatal(err)
	}
	if err := s.DiscardUnusedProductUpdateDigest(ctx, other.ID, 1, other.ContentHash); !errors.Is(err, ErrCampaignSourceRefSet) {
		t.Fatalf("discard of a campaign's source digest: %v, want ErrCampaignSourceRefSet", err)
	}
	if _, err := s.GetProductUpdateDigest(ctx, other.ID, 1); err != nil {
		t.Fatalf("a refused discard deleted the digest: %v", err)
	}

	// Discarding version 2 keeps what version 1 still backs.
	v1Entry, v2Entry := fmt.Sprintf("discard-v1-%d", tgID), fmt.Sprintf("discard-v2-%d", tgID)
	v1 := guardDigest(uid, fmt.Sprintf("discard-versions-%d", tgID), v1Entry)
	v2 := ProductUpdateDigest{
		ID: v1.ID, Version: 2, Category: v1.Category, ContentHash: "sha256:v2",
		SourceRefs: []string{v1Entry + "@1", v2Entry + "@1"}, EntryIDs: []string{v1Entry, v2Entry}, CreatedBy: uid,
	}
	for _, x := range []ProductUpdateDigest{v1, v2} {
		if _, err := s.SaveProductUpdateDigest(ctx, x, now); err != nil {
			t.Fatalf("save v%d: %v", x.Version, err)
		}
	}
	if err := s.DiscardUnusedProductUpdateDigest(ctx, v2.ID, 2, v2.ContentHash); err != nil {
		t.Fatalf("discard v2: %v", err)
	}
	published, err = s.PublishedProductUpdateEntries(ctx, otherID)
	if err != nil {
		t.Fatal(err)
	}
	if !published[v1Entry] || published[v2Entry] {
		t.Fatalf("after discarding v2: %s owned=%v (want true), %s owned=%v (want false)",
			v1Entry, published[v1Entry], v2Entry, published[v2Entry])
	}
}

func guardDigest(uid int64, id, entry string) ProductUpdateDigest {
	return ProductUpdateDigest{
		ID: id, Version: 1, Category: string(CategoryProductUpdates), ContentHash: "sha256:" + id,
		SourceRefs: []string{entry + "@1"}, EntryIDs: []string{entry}, CreatedBy: uid,
	}
}

func guardCampaign(uid int64, id string, ref CampaignSourceRef) BroadcastCampaign {
	now := time.Now().UTC()
	return BroadcastCampaign{
		ID: id, Category: string(CategoryProductUpdates), SelectorJSON: `{}`, SelectorHash: "sh",
		Content: "text", ContentHash: "ch", CreatedBy: uid, Surface: "web", RecipientLimit: 10,
		ExpiresAt: now.Add(time.Hour), SourceRef: &ref,
	}
}

// clearActiveCampaigns ends every active campaign in category, now and when
// the test finishes, so a test starts from a free category and leaves one
// behind. The Postgres test database is shared across runs and packages.
func clearActiveCampaigns(t *testing.T, s *Store, category NotificationCategory) {
	t.Helper()
	t.Cleanup(func() { endActiveCampaigns(t, s, category) })
	endActiveCampaigns(t, s, category)
}

func endActiveCampaigns(t *testing.T, s *Store, category NotificationCategory) {
	t.Helper()
	if _, err := s.DB.ExecContext(context.Background(),
		`UPDATE broadcast_campaigns SET state = 'cancelled'
		  WHERE category = $1 AND state IN ('prepared', 'approved', 'sending')`, string(category)); err != nil {
		t.Fatalf("clear active campaigns: %v", err)
	}
}

// The source digest reference is held by the database on both dialects: a
// campaign cannot name a digest that is not stored, a source_ref is all set
// or all NULL, and a digest a campaign names cannot be deleted.
func TestCampaignSourceDigestReference_SQLite(t *testing.T) {
	assertCampaignSourceDigestReference(t, newTestStore(t), 830000014)
}

func TestCampaignSourceDigestReference_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	assertCampaignSourceDigestReference(t, newPostgresTestStore(t, dsn), 840000014)
}

func assertCampaignSourceDigestReference(t *testing.T, s *Store, tgID int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	uid := productUpdateTestUser(t, s, tgID, now)
	clearActiveCampaigns(t, s, CategoryProductUpdates)
	d := guardDigest(uid, fmt.Sprintf("fk-%d", tgID), fmt.Sprintf("fk-entry-%d", tgID))
	if _, err := s.SaveProductUpdateDigest(ctx, d, now); err != nil {
		t.Fatal(err)
	}
	insert := func(id string, digestID any, version any, hash any) error {
		_, err := s.DB.ExecContext(ctx,
			`INSERT INTO broadcast_campaigns(id, state, category, selector_json, selector_hash, content, content_hash,
			     created_by, surface, recipient_limit, preview_counts, expires_at, created_at, updated_at,
			     source_digest_id, source_digest_version, source_content_hash)
			 VALUES($1,'cancelled',$2,'{}','sh','text','ch',$3,'web',10,'{}',$4,$5,$5,$6,$7,$8)`,
			id, string(CategoryProductUpdates), uid, now.Add(time.Hour), now, digestID, version, hash)
		return err
	}
	if err := insert(fmt.Sprintf("bc_fk_missing_%d", tgID), "no-such-digest", 1, "sha256:x"); !isForeignKeyViolation(err) {
		t.Fatalf("campaign naming a digest that is not stored: %v, want a foreign key violation", err)
	}
	if err := insert(fmt.Sprintf("bc_fk_half_%d", tgID), d.ID, nil, nil); err == nil {
		t.Fatal("a half-set source_ref was inserted")
	}
	if err := insert(fmt.Sprintf("bc_fk_manual_%d", tgID), nil, nil, nil); err != nil {
		t.Fatalf("a manual campaign (all source columns NULL): %v", err)
	}
	if err := insert(fmt.Sprintf("bc_fk_ok_%d", tgID), d.ID, 1, d.ContentHash); err != nil {
		t.Fatalf("campaign naming the stored digest: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM product_update_digests WHERE id = $1 AND version = 1`, d.ID); !isForeignKeyViolation(err) {
		t.Fatalf("deleting a digest a campaign names: %v, want a foreign key violation", err)
	}
}

// TestDiscardRacesCreate_Postgres is the #715 review race: submit R1 stored
// digest D and its Prepare refused, so it discards D, while submit R2 (same
// digest id+version, another selector) creates its campaign naming D. A
// third transaction holds a table lock that parks the discard at a chosen
// statement, so each interleaving is forced rather than hoped for:
//
//   - "create lands mid-discard": the discard has read "no campaign names
//     D" and is parked before its DELETEs; R2's campaign commits; the
//     discard resumes and must refuse, leaving D and its entries held.
//   - "discard deletes first": the discard has deleted D (uncommitted) and
//     is parked before its last statement; R2's INSERT still sees D in its
//     snapshot; the discard commits and R2 must refuse, writing nothing.
//
// In both, a stored campaign never names a missing digest, and D's entries
// are never eligible again while a campaign carries them.
func TestDiscardRacesCreate_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	uid := productUpdateTestUser(t, s, 840000015, now)

	type setup struct {
		d     ProductUpdateDigest
		ref   CampaignSourceRef
		entry string
		cid   string
	}
	prep := func(t *testing.T, name string) setup {
		clearActiveCampaigns(t, s, CategoryProductUpdates)
		entry := "race-entry-" + name
		d := guardDigest(uid, "race-"+name, entry)
		if _, err := s.SaveProductUpdateDigest(ctx, d, now); err != nil {
			t.Fatal(err)
		}
		return setup{d: d, ref: CampaignSourceRef{DigestID: d.ID, DigestVersion: 1, ContentHash: d.ContentHash}, entry: entry, cid: "bc_race_" + name}
	}
	// park holds lockSQL in its own transaction and returns its release.
	park := func(t *testing.T, lockSQL string) func() {
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, lockSQL); err != nil {
			t.Fatal(err)
		}
		released := false
		release := func() {
			if !released {
				released = true
				_ = tx.Commit()
			}
		}
		t.Cleanup(release)
		return release
	}
	check := func(t *testing.T, st setup) (campaignStored bool) {
		t.Helper()
		_, err := s.GetBroadcastCampaign(ctx, st.cid)
		campaignStored = err == nil
		if !campaignStored && !errors.Is(err, ErrCampaignNotFound) {
			t.Fatalf("read campaign: %v", err)
		}
		_, err = s.GetProductUpdateDigest(ctx, st.d.ID, 1)
		digestStored := err == nil
		if !digestStored && !errors.Is(err, ErrDigestNotFound) {
			t.Fatalf("read digest: %v", err)
		}
		published, err := s.PublishedProductUpdateEntries(ctx, "someone-else")
		if err != nil {
			t.Fatal(err)
		}
		if campaignStored && !digestStored {
			t.Fatalf("campaign %s names digest %s, which was discarded", st.cid, st.d.ID)
		}
		if campaignStored && !published[st.entry] {
			t.Fatalf("campaign %s carries %s, but the entry is eligible again", st.cid, st.entry)
		}
		return campaignStored
	}

	t.Run("create lands mid-discard", func(t *testing.T) {
		st := prep(t, "mid")
		// SHARE on publications blocks the discard's first DELETE, after its
		// campaign COUNT has already run.
		release := park(t, `LOCK TABLE product_update_publications IN SHARE MODE`)
		discardErr := make(chan error, 1)
		go func() { discardErr <- s.DiscardUnusedProductUpdateDigest(ctx, st.d.ID, 1, st.d.ContentHash) }()
		waitForLockWait(t, s, "DELETE FROM product_update_publications%")
		createErr := s.CreateBroadcastCampaign(ctx, guardCampaign(uid, st.cid, st.ref), now)
		release()
		derr := <-discardErr
		if createErr != nil {
			t.Fatalf("create: %v", createErr)
		}
		if !errors.Is(derr, ErrCampaignSourceRefSet) {
			t.Fatalf("discard after a campaign named the digest: %v, want ErrCampaignSourceRefSet", derr)
		}
		if !check(t, st) {
			t.Fatal("the created campaign is missing")
		}
	})

	t.Run("discard deletes first", func(t *testing.T) {
		st := prep(t, "first")
		// SHARE on entry owners blocks the discard's last DELETE, after it
		// has deleted the digest row (uncommitted).
		release := park(t, `LOCK TABLE product_update_entry_owners IN SHARE MODE`)
		discardErr := make(chan error, 1)
		go func() { discardErr <- s.DiscardUnusedProductUpdateDigest(ctx, st.d.ID, 1, st.d.ContentHash) }()
		waitForLockWait(t, s, "DELETE FROM product_update_entry_owners%")
		createErr := make(chan error, 1)
		go func() { createErr <- s.CreateBroadcastCampaign(ctx, guardCampaign(uid, st.cid, st.ref), now) }()
		// Give the INSERT time to take its snapshot (which still shows D)
		// and reach the digest row, then let the discard commit.
		waitForLockWaitOrTimeout(s, "INSERT INTO broadcast_campaigns%", 2*time.Second)
		release()
		if derr := <-discardErr; derr != nil {
			t.Fatalf("discard: %v", derr)
		}
		if cerr := <-createErr; !errors.Is(cerr, ErrCampaignSourceMismatch) {
			t.Fatalf("create naming a digest discarded under it: %v, want ErrCampaignSourceMismatch", cerr)
		}
		if check(t, st) {
			t.Fatal("a campaign was stored for a discarded digest")
		}
	})
}

// waitForLockWait blocks until a backend running a query matching like is
// waiting on a lock, failing the test after five seconds.
func waitForLockWait(t *testing.T, s *Store, like string) {
	t.Helper()
	if !waitForLockWaitOrTimeout(s, like, 5*time.Second) {
		t.Fatalf("no backend waiting on a lock for %q", like)
	}
}

func waitForLockWaitOrTimeout(s *Store, like string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var n int
		err := s.DB.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM pg_stat_activity
			  WHERE wait_event_type = 'Lock' AND ltrim(query) LIKE $1`, like).Scan(&n)
		if err == nil && n > 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
