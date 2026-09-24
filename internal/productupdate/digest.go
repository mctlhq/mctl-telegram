package productupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// DigestSchema names the frozen digest format.
const DigestSchema = "mctl-telegram.product-update-digest/v1"

// DigestCandidates returns the entries a category's next weekly digest may
// contain: approved, delivered next_digest, of that category, already shipped
// in a release up to latestRelease (Entry.Shipped -- an update merged with its
// change is not announced before the release carrying it is cut), and not
// already sent (published holds the ids of entries a digest already carried).
// One category only: a digest never mixes consent domains.
func DigestCandidates(feed Feed, category db.NotificationCategory, latestRelease string, published map[string]bool) []Entry {
	var out []Entry
	for _, e := range feed.Entries {
		if e.Status != StatusApproved || e.Delivery != DeliveryNextDigest || e.Category() != category {
			continue
		}
		if !e.Shipped(latestRelease) {
			continue
		}
		if published[e.ID] {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Digest is a frozen, content-addressed digest: the immutable thing a
// broadcast is prepared from. Freezing happens while an operator is present,
// because broadcast Prepare opens a 30-minute approval window; nothing here
// runs on a timer.
type Digest struct {
	Schema   string                  `json:"schema"`
	ID       string                  `json:"id"`
	Version  int                     `json:"version"`
	Category db.NotificationCategory `json:"category"`
	// SourceRefs name each entry by its file and the hash of its CONTENT --
	// the JSON projection digestEntry, not the file bytes, so review metadata
	// can change without moving it: "<file>@content-sha256:<hex>". The
	// digest says exactly which reviewed text it was built from.
	SourceRefs []string `json:"sourceRefs"`
	// ContentHash covers the schema, id, version, category and every entry's
	// content: two digests with the same hash carry the same text.
	ContentHash string `json:"contentHash"`
}

// digestEntry is the content of an entry a digest carries: what a recipient
// reads and the evidence behind it. Review metadata is not content.
type digestEntry struct {
	ID       string   `json:"id"`
	Kind     Kind     `json:"kind"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Locale   string   `json:"locale"`
	Tools    []string `json:"tools"`
	Evidence Evidence `json:"evidence"`
}

// entryContent is the hashed projection of an entry. Absent and empty lists
// are the same content, so they are normalised before hashing.
func entryContent(e Entry) digestEntry {
	evidence := Evidence{From: e.Evidence.From, Changes: e.Evidence.Changes, Links: e.Evidence.Links}
	if evidence.Changes == nil {
		evidence.Changes = []Claim{}
	}
	if evidence.Links == nil {
		evidence.Links = []string{}
	}
	tools := e.Tools
	if tools == nil {
		tools = []string{}
	}
	return digestEntry{ID: e.ID, Kind: e.Kind, Title: e.Title, Summary: e.Summary, Locale: e.Locale, Tools: tools, Evidence: evidence}
}

func hashJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// FreezeDigest builds the frozen digest for one category from the given
// entries. It refuses a mixed category, an entry that is not an approved
// next_digest update, an entry whose change is not in a release up to
// latestRelease, a duplicate entry, and an empty digest.
func FreezeDigest(id string, version int, category db.NotificationCategory, latestRelease string, entries []Entry) (Digest, error) {
	if !idPattern.MatchString(id) {
		return Digest{}, fmt.Errorf("digest id %q must match %s", id, idPattern)
	}
	if version < 1 {
		return Digest{}, fmt.Errorf("digest version must be at least 1")
	}
	if len(entries) == 0 {
		return Digest{}, fmt.Errorf("digest %s has no entries", id)
	}
	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	contents := make([]digestEntry, 0, len(sorted))
	refs := make([]string, 0, len(sorted))
	for i, e := range sorted {
		switch {
		case e.Category() != category:
			return Digest{}, fmt.Errorf("digest %s is %s but %s is %s; one digest, one category", id, category, e.ID, e.Category())
		case e.Status != StatusApproved:
			return Digest{}, fmt.Errorf("digest %s: %s is not approved", id, e.ID)
		case e.Delivery != DeliveryNextDigest:
			return Digest{}, fmt.Errorf("digest %s: %s is delivered %s, not next_digest", id, e.ID, e.Delivery)
		case !e.Shipped(latestRelease):
			return Digest{}, fmt.Errorf("digest %s: %s describes a change after %s, not released yet", id, e.ID, e.Evidence.From)
		case i > 0 && sorted[i-1].ID == e.ID:
			return Digest{}, fmt.Errorf("digest %s carries %s twice", id, e.ID)
		}
		content := entryContent(e)
		h, err := hashJSON(content)
		if err != nil {
			return Digest{}, fmt.Errorf("hash %s: %w", e.ID, err)
		}
		contents = append(contents, content)
		refs = append(refs, fmt.Sprintf("%s/%s.yaml@content-sha256:%s", FeedDir, e.ID, h))
	}
	d := Digest{Schema: DigestSchema, ID: id, Version: version, Category: category, SourceRefs: refs}
	h, err := hashJSON(struct {
		Schema   string                  `json:"schema"`
		ID       string                  `json:"id"`
		Version  int                     `json:"version"`
		Category db.NotificationCategory `json:"category"`
		Entries  []digestEntry           `json:"entries"`
	}{d.Schema, d.ID, d.Version, d.Category, contents})
	if err != nil {
		return Digest{}, fmt.Errorf("hash digest %s: %w", id, err)
	}
	d.ContentHash = "sha256:" + h
	return d, nil
}
