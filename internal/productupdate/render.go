package productupdate

// render.go turns a frozen Digest into the exact text a broadcast delivers
// (RenderBroadcast) and turns the whole feed into the grouped view the docs
// and web page render (RenderDocs). Neither function imports
// internal/broadcast: the caller passes in the text limit and the docs URL
// so this package stays the single place that knows how to read the feed.

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// ReleaseGroup is every entry citing the same release, for the docs/web page.
// Release is Entry.Evidence.From; the empty group (entries with no cited
// release -- a maintenance or security notice backed by links alone) sorts
// last.
type ReleaseGroup struct {
	Release string
	Entries []Entry
}

// RenderBroadcast returns the Telegram body for a frozen digest d, built
// from the entries it names in feed. It resolves each of d's SourceRefs
// back to a feed entry, recomputes the entry's content hash with the same
// projection FreezeDigest hashes, and refuses unless the rebuilt refs equal
// d.SourceRefs byte for byte -- an entry edited or removed from the feed
// since freezing is refused rather than silently rendered as it now reads.
//
// Two deterministic forms: full (title plus summary per entry) when its
// UTF-16 length is within limit, else compact (titles only). If even compact
// overflows, RenderBroadcast refuses and names the entry count; it never
// truncates or rewords reviewed text. Text is English only and copies each
// entry's Title and Summary verbatim.
func RenderBroadcast(d Digest, feed Feed, docsURL string, limit int) (string, error) {
	ids, err := d.EntryIDs()
	if err != nil {
		return "", err
	}
	byID := make(map[string]Entry, len(feed.Entries))
	for _, e := range feed.Entries {
		byID[e.ID] = e
	}
	entries := make([]Entry, 0, len(ids))
	refs := make([]string, 0, len(ids))
	for _, id := range ids {
		e, ok := byID[id]
		if !ok {
			return "", fmt.Errorf("render digest %s: entry %s is missing from the feed", d.ID, id)
		}
		h, err := hashJSON(entryContent(e))
		if err != nil {
			return "", fmt.Errorf("render digest %s: hash %s: %w", d.ID, id, err)
		}
		entries = append(entries, e)
		refs = append(refs, fmt.Sprintf("%s/%s.yaml@content-sha256:%s", FeedDir, id, h))
	}
	if !slices.Equal(refs, d.SourceRefs) {
		return "", fmt.Errorf("render digest %s: the feed no longer matches the frozen source refs; an entry changed since freezing", d.ID)
	}

	heading := renderHeading(d)
	if full := renderForm(heading, entries, docsURL, true); withinLimit(full, limit) {
		return full, nil
	}
	if compact := renderForm(heading, entries, docsURL, false); withinLimit(compact, limit) {
		return compact, nil
	}
	return "", fmt.Errorf("render digest %s: %d entries exceed the broadcast text limit even in compact form; mark surplus entries docs_only", d.ID, len(entries))
}

// renderHeading names the category and the digest this text was prepared
// from, so an approver reading only the rendered text (not the source_ref
// alongside it) can still tell which frozen digest produced it.
func renderHeading(d Digest) string {
	return fmt.Sprintf("%s — %s v%d", categoryLabel(d.Category), d.ID, d.Version)
}

func categoryLabel(c db.NotificationCategory) string {
	switch c {
	case db.CategoryProductUpdates:
		return "Product updates"
	case db.CategoryMaintenance:
		return "Maintenance notice"
	case db.CategorySecurity:
		return "Security notice"
	default:
		return string(c)
	}
}

func renderForm(heading string, entries []Entry, docsURL string, full bool) string {
	var b strings.Builder
	b.WriteString(heading)
	b.WriteString("\n\n")
	for _, e := range entries {
		b.WriteString(e.Title)
		b.WriteString("\n")
		if full {
			b.WriteString(e.Summary)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("Full details: ")
	b.WriteString(docsURL)
	return strings.TrimRight(b.String(), "\n")
}

func withinLimit(s string, limit int) bool {
	return len(utf16.Encode([]rune(s))) <= limit
}

// RenderDocs returns the approved, English feed as an ordered view for the
// docs and web page: grouped by the release each entry cites
// (Evidence.From), newest release first, entries within a group in id
// order. docs_only entries are included -- they exist precisely to be
// rendered here and never sent. Provenance (author, reviewer, assisting
// model) is never part of the returned Entry the caller should show; the
// page template is responsible for not rendering it, same as this function
// is responsible for not filtering entries docs is not a consent domain.
func RenderDocs(feed Feed) []ReleaseGroup {
	groups := map[string][]Entry{}
	for _, e := range feed.Entries {
		if e.Status != StatusApproved || e.Locale != "en" {
			continue
		}
		groups[e.Evidence.From] = append(groups[e.Evidence.From], e)
	}
	releases := make([]string, 0, len(groups))
	for r := range groups {
		releases = append(releases, r)
	}
	sort.Slice(releases, func(i, j int) bool {
		a, b := releases[i], releases[j]
		switch {
		case a == "" && b == "":
			return false
		case a == "":
			return false // no cited release sorts last
		case b == "":
			return true
		default:
			// Both keys come from entries LoadFeed validated, whose
			// evidence.from must be a MAJOR.MINOR.PATCH release, so the
			// error cannot occur; a malformed key sorts as "not after".
			after, err := releaseAfter(a, b)
			return err == nil && after
		}
	})
	out := make([]ReleaseGroup, 0, len(releases))
	for _, r := range releases {
		entries := groups[r]
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
		out = append(out, ReleaseGroup{Release: r, Entries: entries})
	}
	return out
}
