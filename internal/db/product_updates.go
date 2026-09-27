package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Product-update digests (issue-683). The feed lives in the repository; what
// the database keeps is what was frozen from it and handed to a broadcast:
//
//	product_update_digests       one row per frozen (id, version), written once
//	product_update_publications  the entry ids each digest version carried
//	product_update_entry_owners  the one digest id allowed to carry each entry:
//	                             the published set, and the dedupe authority
//	broadcast_campaigns.source_* the digest a campaign was prepared from
//
// A digest row is never updated. Saving the same (id, version) again is a
// no-op when the content is identical and refused when it is not, so the text
// a campaign was prepared from cannot change underneath it. An entry is
// carried by at most one digest id (a later version of the same digest may
// carry it again), which is the dedupe across releases and channels.

// Errors returned by the product-update digest store.
var (
	ErrDigestNotFound       = errors.New("product update digest not found")
	ErrDigestConflict       = errors.New("product update digest is already stored with different content")
	ErrDigestEntryPublished = errors.New("product update entry was already carried by another digest")
	// ErrCampaignSourceRefSet refuses a second, different source_ref: once a
	// campaign names the digest it was prepared from, that never changes.
	ErrCampaignSourceRefSet = errors.New("broadcast campaign source_ref is already set to a different digest")
	// ErrCampaignSourceMismatch refuses a source_ref whose content hash or
	// category does not match the stored digest.
	ErrCampaignSourceMismatch = errors.New("broadcast campaign source_ref does not match the stored digest")
)

// ProductUpdateDigest is one frozen digest (productupdate.Digest) as stored.
// EntryIDs is the set of feed entries it carried, sorted in byte order
// (not the database collation's).
type ProductUpdateDigest struct {
	ID          string
	Version     int
	Category    string
	ContentHash string
	SourceRefs  []string
	EntryIDs    []string
	CreatedBy   int64
	CreatedAt   time.Time
}

// CampaignSourceRef names the frozen digest a broadcast campaign was prepared
// from.
type CampaignSourceRef struct {
	DigestID      string
	DigestVersion int
	ContentHash   string
}

func (d ProductUpdateDigest) validate() error {
	switch {
	case d.ID == "":
		return errors.New("digest id is required")
	case d.Version < 1:
		return errors.New("digest version must be at least 1")
	case !isKnownCategory(d.Category):
		return fmt.Errorf("%w: %s", ErrUnknownNotificationCategory, d.Category)
	case d.ContentHash == "":
		return errors.New("digest content hash is required")
	case d.CreatedBy <= 0:
		return errors.New("digest creator must be a known user")
	case len(d.EntryIDs) == 0:
		return errors.New("digest carries no entries")
	case len(d.SourceRefs) != len(d.EntryIDs):
		return fmt.Errorf("digest has %d source refs for %d entries", len(d.SourceRefs), len(d.EntryIDs))
	}
	seen := map[string]bool{}
	for _, id := range d.EntryIDs {
		if id == "" || seen[id] {
			return fmt.Errorf("digest entry id %q is empty or repeated", id)
		}
		seen[id] = true
	}
	return nil
}

// SaveProductUpdateDigest stores a frozen digest and the entries it carried,
// in one transaction. It returns true when it wrote the digest and false when
// the identical digest was already stored (a retry). It refuses, writing
// nothing, a digest whose (id, version) is stored with different content
// (ErrDigestConflict) and one carrying an entry another digest id already
// carried (ErrDigestEntryPublished).
func (s *Store) SaveProductUpdateDigest(ctx context.Context, d ProductUpdateDigest, now time.Time) (bool, error) {
	if err := d.validate(); err != nil {
		return false, fmt.Errorf("save product update digest: %w", err)
	}
	d.EntryIDs = slices.Sorted(slices.Values(d.EntryIDs))
	refs, err := json.Marshal(d.SourceRefs)
	if err != nil {
		return false, fmt.Errorf("save product update digest: %w", err)
	}
	pg := s.isPostgres(ctx)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("save product update digest: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if pg {
		// Serialise savers so the "already carried by another digest" check
		// below cannot race a concurrent save of the same entry. SQLite runs
		// on one connection, so its transactions are already serial. Saving
		// is a rare, operator-driven step; the lock is held for milliseconds.
		if _, err := tx.ExecContext(ctx, `LOCK TABLE product_update_digests IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return false, fmt.Errorf("save product update digest: lock: %w", err)
		}
	}

	existing, err := getProductUpdateDigest(ctx, tx, d.ID, d.Version)
	switch {
	case err == nil:
		return false, d.sameAs(existing)
	case !errors.Is(err, ErrDigestNotFound):
		return false, fmt.Errorf("save product update digest: %w", err)
	}

	args := []any{d.ID}
	ph := make([]string, len(d.EntryIDs))
	for i, id := range d.EntryIDs {
		args = append(args, id)
		ph[i] = fmt.Sprintf("$%d", i+2)
	}
	var otherDigest, entry string
	err = tx.QueryRowContext(ctx,
		`SELECT digest_id, entry_id FROM product_update_entry_owners
		  WHERE digest_id <> $1 AND entry_id IN (`+strings.Join(ph, ",")+`)
		  ORDER BY entry_id LIMIT 1`, args...).Scan(&otherDigest, &entry)
	switch {
	case err == nil:
		return false, fmt.Errorf("%w: %s is in %s", ErrDigestEntryPublished, entry, otherDigest)
	case !errors.Is(err, sql.ErrNoRows):
		return false, fmt.Errorf("save product update digest: published check: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO product_update_digests(id, version, category, content_hash, source_refs, created_by, created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id, version) DO NOTHING`,
		d.ID, d.Version, d.Category, d.ContentHash, string(refs), d.CreatedBy, now.UTC())
	if err != nil {
		return false, fmt.Errorf("save product update digest: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("save product update digest: rows affected: %w", err)
	}
	if n == 0 {
		// A concurrent saver of the same (id, version) committed after the
		// read above, which only the skipped table lock allows: this INSERT
		// waited for it and wrote nothing. Answer as the read would have,
		// a no-op for identical content and ErrDigestConflict otherwise,
		// rather than surface a unique violation.
		existing, err := getProductUpdateDigest(ctx, tx, d.ID, d.Version)
		if err != nil {
			return false, fmt.Errorf("save product update digest: %w", err)
		}
		return false, d.sameAs(existing)
	}
	for _, id := range d.EntryIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO product_update_publications(digest_id, digest_version, entry_id) VALUES($1,$2,$3)`,
			d.ID, d.Version, id); err != nil {
			return false, fmt.Errorf("save product update publication %s: %w", id, err)
		}
		// The database-held form of the published check above. A concurrent
		// saver of the same entry blocks on the primary key until this
		// transaction ends, then finds the committed owner and is refused;
		// that holds even when the table lock was skipped.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO product_update_entry_owners(entry_id, digest_id) VALUES($1,$2) ON CONFLICT (entry_id) DO NOTHING`,
			id, d.ID); err != nil {
			return false, fmt.Errorf("save product update entry owner %s: %w", id, err)
		}
		var owner string
		if err := tx.QueryRowContext(ctx,
			`SELECT digest_id FROM product_update_entry_owners WHERE entry_id = $1`, id).Scan(&owner); err != nil {
			return false, fmt.Errorf("save product update entry owner %s: %w", id, err)
		}
		if owner != d.ID {
			return false, fmt.Errorf("%w: %s is in %s", ErrDigestEntryPublished, id, owner)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("save product update digest: commit: %w", err)
	}
	return true, nil
}

// sameAs is nil when stored holds the same content as d (a retry) and
// ErrDigestConflict otherwise. d.EntryIDs must already be sorted; stored's
// are, by getProductUpdateDigest.
func (d ProductUpdateDigest) sameAs(stored *ProductUpdateDigest) error {
	if stored.Category != d.Category || stored.ContentHash != d.ContentHash ||
		!slices.Equal(stored.SourceRefs, d.SourceRefs) || !slices.Equal(stored.EntryIDs, d.EntryIDs) {
		return fmt.Errorf("%w: %s v%d", ErrDigestConflict, d.ID, d.Version)
	}
	return nil
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// GetProductUpdateDigest returns one stored digest or ErrDigestNotFound.
func (s *Store) GetProductUpdateDigest(ctx context.Context, id string, version int) (*ProductUpdateDigest, error) {
	return getProductUpdateDigest(ctx, s.DB, id, version)
}

func getProductUpdateDigest(ctx context.Context, q queryer, id string, version int) (*ProductUpdateDigest, error) {
	d := ProductUpdateDigest{ID: id, Version: version}
	var refs string
	err := q.QueryRowContext(ctx,
		`SELECT category, content_hash, source_refs, created_by, created_at
		   FROM product_update_digests WHERE id = $1 AND version = $2`, id, version).
		Scan(&d.Category, &d.ContentHash, &refs, &d.CreatedBy, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDigestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get product update digest: %w", err)
	}
	if err := json.Unmarshal([]byte(refs), &d.SourceRefs); err != nil {
		return nil, fmt.Errorf("get product update digest: source refs: %w", err)
	}
	rows, err := q.QueryContext(ctx,
		`SELECT entry_id FROM product_update_publications
		  WHERE digest_id = $1 AND digest_version = $2 ORDER BY entry_id`, id, version)
	if err != nil {
		return nil, fmt.Errorf("get product update digest: entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, fmt.Errorf("get product update digest: entries scan: %w", err)
		}
		d.EntryIDs = append(d.EntryIDs, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("get product update digest: entries: %w", err)
	}
	// Byte order, as SaveProductUpdateDigest sorts the ids it compares
	// against. ORDER BY above follows the server collation, and a libc one
	// such as en_US.utf8 (the postgres image default) ignores hyphens at the
	// primary level, so "exportable-feed" sorts before "export-chat" there
	// and an identical retry would otherwise read as ErrDigestConflict.
	slices.Sort(d.EntryIDs)
	return &d, nil
}

// PublishedProductUpdateEntries returns the ids of every feed entry a stored
// digest carried: the published set productupdate.DigestCandidates excludes.
// Entries carried only by exceptDigestID (any version) are left out, so
// re-freezing that same digest after a retry offers the same candidates
// again; pass "" for the whole set. The exclusion is by id, not version: for
// a later version of exceptDigestID it also lets through entries approved
// since (see productupdate.FreezeNextDigest).
func (s *Store) PublishedProductUpdateEntries(ctx context.Context, exceptDigestID string) (map[string]bool, error) {
	// Read from the owners, the same table SaveProductUpdateDigest refuses
	// on, so an entry is never offered as a candidate that saving would
	// then refuse.
	rows, err := s.DB.QueryContext(ctx,
		`SELECT entry_id FROM product_update_entry_owners WHERE digest_id <> $1`, exceptDigestID)
	if err != nil {
		return nil, fmt.Errorf("published product update entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("published product update entries: scan: %w", err)
		}
		out[id] = true
	}
	// Never a partial set with an error: a caller that dropped the error
	// would treat the missing entries as unpublished and send them again.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("published product update entries: %w", err)
	}
	return out, nil
}

// SetBroadcastCampaignSourceRef records the frozen digest a prepared campaign
// was prepared from. The single conditional UPDATE writes only when the
// campaign is still prepared, has no source_ref yet, and the digest exists
// with that content hash and the campaign's category. Setting the same ref
// again is a no-op; any other ref once one is set is ErrCampaignSourceRefSet,
// and nothing is written on any refusal.
func (s *Store) SetBroadcastCampaignSourceRef(ctx context.Context, campaignID string, ref CampaignSourceRef, now time.Time) error {
	if ref.DigestID == "" || ref.DigestVersion < 1 || ref.ContentHash == "" {
		return errors.New("set broadcast campaign source_ref: digest id, version and content hash are required")
	}
	now = now.UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_campaigns
		    SET source_digest_id = $2, source_digest_version = $3, source_content_hash = $4, updated_at = $5
		  WHERE id = $1 AND state = $6 AND source_digest_id IS NULL
		    AND EXISTS (SELECT 1 FROM product_update_digests d
		                 WHERE d.id = $2 AND d.version = $3 AND d.content_hash = $4
		                   AND d.category = broadcast_campaigns.category)`,
		campaignID, ref.DigestID, ref.DigestVersion, ref.ContentHash, now, CampaignPrepared)
	if err != nil {
		return fmt.Errorf("set broadcast campaign source_ref: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set broadcast campaign source_ref: rows affected: %w", err)
	}
	if n == 1 {
		return nil
	}
	c, err := s.GetBroadcastCampaign(ctx, campaignID)
	if err != nil {
		return fmt.Errorf("set broadcast campaign source_ref %s: %w", campaignID, err)
	}
	if c.SourceRef != nil {
		if *c.SourceRef == ref {
			return nil
		}
		return ErrCampaignSourceRefSet
	}
	if c.State != CampaignPrepared {
		return ErrCampaignNotPrepared
	}
	d, err := s.GetProductUpdateDigest(ctx, ref.DigestID, ref.DigestVersion)
	if err != nil {
		return fmt.Errorf("set broadcast campaign source_ref %s: %w", campaignID, err)
	}
	if d.ContentHash != ref.ContentHash || d.Category != c.Category {
		return ErrCampaignSourceMismatch
	}
	// Every condition held on re-read, so the row changed between the UPDATE
	// and the read. Report that rather than claim a write that did not happen.
	return errors.New("set broadcast campaign source_ref: campaign changed concurrently; retry")
}
