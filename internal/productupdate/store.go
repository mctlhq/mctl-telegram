package productupdate

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// DigestStore is where frozen digests are kept: *db.Store. The database holds
// only publication and digest state; the feed stays in the repository.
type DigestStore interface {
	PublishedProductUpdateEntries(ctx context.Context, exceptDigestID string) (map[string]bool, error)
	SaveProductUpdateDigest(ctx context.Context, d db.ProductUpdateDigest, now time.Time) (bool, error)
}

// contentHashPattern is the hex SHA-256 FreezeDigest writes after
// "@content-sha256:"; a ref without one names no content.
var contentHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// EntryIDs returns the ids of the entries the digest carries, in SourceRefs
// order, read back from the "<FeedDir>/<id>.yaml@content-sha256:<hex>" refs
// FreezeDigest wrote.
func (d Digest) EntryIDs() ([]string, error) {
	ids := make([]string, 0, len(d.SourceRefs))
	for _, ref := range d.SourceRefs {
		file, hash, ok := strings.Cut(ref, "@content-sha256:")
		id, found := strings.CutPrefix(file, FeedDir+"/")
		id, yaml := strings.CutSuffix(id, ".yaml")
		if !ok || !found || !yaml || !idPattern.MatchString(id) || !contentHashPattern.MatchString(hash) {
			return nil, fmt.Errorf("digest %s: source ref %q is not %s/<id>.yaml@content-sha256:<hex>", d.ID, ref, FeedDir)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// PersistDigest stores a frozen digest and the entries it carried. It returns
// true when it wrote the digest and false when the identical digest was
// already stored, so a retry is harmless; a stored digest is never
// overwritten (db.ErrDigestConflict).
func PersistDigest(ctx context.Context, st DigestStore, d Digest, createdBy int64, now time.Time) (bool, error) {
	if d.Schema != DigestSchema {
		return false, fmt.Errorf("digest %s: schema %q, want %s", d.ID, d.Schema, DigestSchema)
	}
	ids, err := d.EntryIDs()
	if err != nil {
		return false, err
	}
	return st.SaveProductUpdateDigest(ctx, db.ProductUpdateDigest{
		ID: d.ID, Version: d.Version, Category: string(d.Category), ContentHash: d.ContentHash,
		SourceRefs: d.SourceRefs, EntryIDs: ids, CreatedBy: createdBy,
	}, now)
}

// FreezeNextDigest freezes and stores the next digest for one category: the
// feed's candidates minus every entry another stored digest already carried,
// frozen with FreezeDigest and persisted. Entries this same digest id carried
// are not excluded, so repeating the call after a lost response yields the
// identical digest and stores nothing new. It runs only while an operator is
// present (it is the step before broadcast Prepare), never on a timer.
//
// A later version of the same id is NOT a reproduction of the earlier one.
// Because the exclusion is by digest id, version+1 is frozen from every
// entry the earlier versions carried plus every entry approved since that no
// other digest id carried, and those new entries are then published under
// this id (so the next digest id will not carry them). Nothing here checks
// that a correction keeps the earlier entry set, and reusing an id that was
// already sent reopens its entries as candidates. A caller that needs a
// correction limited to the earlier entries must enforce that itself.
func FreezeNextDigest(ctx context.Context, st DigestStore, feed Feed, id string, version int, category db.NotificationCategory, latestRelease string, createdBy int64, now time.Time) (Digest, bool, error) {
	published, err := st.PublishedProductUpdateEntries(ctx, id)
	if err != nil {
		return Digest{}, false, err
	}
	d, err := FreezeDigest(id, version, category, latestRelease, DigestCandidates(feed, category, latestRelease, published))
	if err != nil {
		return Digest{}, false, err
	}
	stored, err := PersistDigest(ctx, st, d, createdBy, now)
	if err != nil {
		return Digest{}, false, err
	}
	return d, stored, nil
}
