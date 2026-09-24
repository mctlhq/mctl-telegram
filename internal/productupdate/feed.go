package productupdate

// This file is the second half of the product-update evidence (issue-440):
// the curated feed. An entry is a reviewed YAML file under
// docs/product-updates/, merged through a pull request -- that review is the
// first of the two human approvals the owner chose (the broadcast page's
// approval is the second). The database holds only publication and digest
// state; what an update says lives here, next to the tool snapshot it cites.
//
// An entry may state only what the tool surface shows. Every change it claims
// is a (tool, change) pair that the diff against the previous release must
// contain (gate.go), so wording can be rewritten -- by a person or with a
// model's help -- but a capability cannot be invented.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// EntrySchema names the entry format. A file of any other schema is refused
// rather than read as if it were this one.
const EntrySchema = "mctl-telegram.product-update/v1"

// Kind is what an update is about.
type Kind string

const (
	KindNewTool         Kind = "new_tool"
	KindChangedBehavior Kind = "changed_behavior"
	KindDeprecation     Kind = "deprecation"
	KindMaintenance     Kind = "maintenance"
	KindSecurity        Kind = "security"
)

// Category is the notification category -- the consent domain -- an entry is
// delivered under. It is derived from Kind, never written by hand, so an
// entry always has exactly one, and a digest is always built for one
// category: product_updates is opt-in while maintenance and security are not,
// and mixing them would send opt-in content to people who never opted in.
func (k Kind) Category() db.NotificationCategory {
	switch k {
	case KindSecurity:
		return db.CategorySecurity
	case KindMaintenance:
		return db.CategoryMaintenance
	default:
		return db.CategoryProductUpdates
	}
}

// Delivery is how an entry reaches people.
type Delivery string

const (
	// DeliveryNextDigest: grouped into the category's next weekly digest. The
	// default for routine updates.
	DeliveryNextDigest Delivery = "next_digest"
	// DeliveryImmediate: its own campaign. Only for security and maintenance,
	// or an update explicitly marked high_value.
	DeliveryImmediate Delivery = "immediate"
	// DeliveryDocsOnly: rendered in docs, never sent.
	DeliveryDocsOnly Delivery = "docs_only"
)

// Status is the review state of an entry's content.
type Status string

const (
	StatusDraft Status = "draft"
	// StatusApproved: a named human reviewed the content. Only approved
	// entries cover a change in the release gate or become campaign-eligible.
	StatusApproved Status = "approved"
)

// ClaimChange is one kind of diff item an entry can claim.
type ClaimChange string

const (
	ClaimAdded       ClaimChange = "added"
	ClaimRemoved     ClaimChange = "removed"
	ClaimSchema      ClaimChange = ChangeSchema
	ClaimAnnotations ClaimChange = ChangeAnnotations
	ClaimText        ClaimChange = ChangeText
)

// SupportedLocales is every locale v1 accepts. Localisation is a later,
// separate issue.
var SupportedLocales = []string{"en"}

// Claim is one (tool, change) pair an entry says the tool surface shows.
type Claim struct {
	Tool   string      `yaml:"tool"`
	Change ClaimChange `yaml:"change"`
}

// Evidence ties an entry to the deterministic source it may cite.
type Evidence struct {
	// From is the release tag the tool diff is taken against: the previous
	// release when the entry was written. The release gate holds every claim
	// of an entry whose From is the current baseline to that diff.
	From string `yaml:"from"`
	// Changes are the diff items this entry covers.
	Changes []Claim `yaml:"changes"`
	// Links are further sources (a release, an advisory, a pull request).
	Links []string `yaml:"links"`
}

// Provenance records who wrote and who reviewed the content.
type Provenance struct {
	Author string `yaml:"author"`
	// AssistedBy names a model that helped with the wording, if any. It may
	// never be the reviewer: a model can rewrite, not approve.
	AssistedBy string `yaml:"assisted_by"`
	ReviewedBy string `yaml:"reviewed_by"`
}

// Entry is one product update, as committed in docs/product-updates/<id>.yaml.
type Entry struct {
	Schema    string   `yaml:"schema"`
	ID        string   `yaml:"id"`
	Kind      Kind     `yaml:"kind"`
	Title     string   `yaml:"title"`
	Summary   string   `yaml:"summary"`
	Locale    string   `yaml:"locale"`
	Delivery  Delivery `yaml:"delivery"`
	HighValue bool     `yaml:"high_value"`
	Tools     []string `yaml:"tools"`
	Surfaces  []string `yaml:"surfaces"`
	Evidence  Evidence `yaml:"evidence"`
	// Release is the version the change shipped in, once known. Optional:
	// release-please picks the version only when the release is cut.
	Release    string     `yaml:"release"`
	Status     Status     `yaml:"status"`
	Provenance Provenance `yaml:"provenance"`
	CreatedAt  string     `yaml:"created_at"`
	ReviewedAt string     `yaml:"reviewed_at"`
}

// Category is the entry's notification category (Kind.Category).
func (e Entry) Category() db.NotificationCategory { return e.Kind.Category() }

const (
	maxTitle   = 120
	maxSummary = 1000
)

var (
	idPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,79}$`)
	toolPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	releasePattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

// ParseEntry decodes one entry strictly: an unknown field is an error, so a
// typo cannot silently drop a field.
func ParseEntry(raw []byte) (Entry, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var e Entry
	if err := decoder.Decode(&e); err != nil {
		return Entry{}, fmt.Errorf("decode entry: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Entry{}, fmt.Errorf("decode entry: more than one YAML document")
	}
	return e, nil
}

// Validate checks everything that can be checked from the entry alone. The
// release gate (gate.go) adds what needs the tool surface.
func (e Entry) Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if e.Schema != EntrySchema {
		add("schema %q is not %q", e.Schema, EntrySchema)
	}
	if !idPattern.MatchString(e.ID) {
		add("id %q must match %s", e.ID, idPattern)
	}
	switch e.Kind {
	case KindNewTool, KindChangedBehavior, KindDeprecation, KindMaintenance, KindSecurity:
	default:
		add("kind %q is not one of new_tool, changed_behavior, deprecation, maintenance, security", e.Kind)
	}
	if strings.TrimSpace(e.Title) == "" || len(e.Title) > maxTitle {
		add("title must be 1-%d characters", maxTitle)
	}
	if strings.TrimSpace(e.Summary) == "" || len(e.Summary) > maxSummary {
		add("summary must be 1-%d characters", maxSummary)
	}
	if !contains(SupportedLocales, e.Locale) {
		add("locale %q is not supported (v1: %s)", e.Locale, strings.Join(SupportedLocales, ", "))
	}
	switch e.Delivery {
	case DeliveryNextDigest, DeliveryDocsOnly:
	case DeliveryImmediate:
		if e.Category() == db.CategoryProductUpdates && !e.HighValue {
			add("delivery immediate is only for security, maintenance or a high_value update")
		}
	default:
		add("delivery %q is not one of next_digest, immediate, docs_only", e.Delivery)
	}
	for _, tool := range e.Tools {
		if !toolPattern.MatchString(tool) {
			add("tool %q is not a tool name", tool)
		}
	}
	if dup := duplicate(e.Tools); dup != "" {
		add("tool %q is listed twice", dup)
	}
	if e.Release != "" && !releasePattern.MatchString(e.Release) {
		add("release %q is not MAJOR.MINOR.PATCH", e.Release)
	}
	problems = append(problems, e.validateEvidence()...)
	problems = append(problems, e.validateReview()...)
	if len(problems) > 0 {
		return fmt.Errorf("%s: %s", e.label(), strings.Join(problems, "; "))
	}
	return nil
}

func (e Entry) validateEvidence() []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	ev := e.Evidence
	if ev.From != "" && !releasePattern.MatchString(ev.From) {
		add("evidence.from %q is not a release tag", ev.From)
	}
	if len(ev.Changes) > 0 && ev.From == "" {
		add("evidence.changes needs evidence.from, the release the diff is taken against")
	}
	// Every factual update links back to deterministic source evidence: a
	// tool change to the diff, anything else to at least one link.
	if len(ev.Changes) == 0 && len(ev.Links) == 0 {
		add("evidence needs changes from the tool diff or at least one link")
	}
	for _, link := range ev.Links {
		if !strings.HasPrefix(link, "https://") {
			add("evidence link %q is not https", link)
		}
	}
	seen := map[Claim]bool{}
	var added, removed int
	for _, c := range ev.Changes {
		switch c.Change {
		case ClaimAdded:
			added++
		case ClaimRemoved:
			removed++
		case ClaimSchema, ClaimAnnotations, ClaimText:
		default:
			add("evidence change %q is not one of added, removed, schema, annotations, text", c.Change)
		}
		if !contains(e.Tools, c.Tool) {
			add("evidence names %s, which tools does not list", c.Tool)
		}
		if seen[c] {
			add("evidence claims %s %s twice", c.Tool, c.Change)
		}
		seen[c] = true
	}
	if e.Kind == KindNewTool && added == 0 {
		add("a new_tool update must claim at least one added tool")
	}
	if e.Kind == KindDeprecation && len(ev.Changes) == 0 {
		add("a deprecation must claim the change that shows it")
	}
	return problems
}

func (e Entry) validateReview() []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	p := e.Provenance
	if strings.TrimSpace(p.Author) == "" {
		add("provenance.author is required")
	}
	if _, err := time.Parse(time.DateOnly, e.CreatedAt); err != nil {
		add("created_at %q is not YYYY-MM-DD", e.CreatedAt)
	}
	switch e.Status {
	case StatusDraft:
		if p.ReviewedBy != "" || e.ReviewedAt != "" {
			add("a draft has no reviewer yet")
		}
	case StatusApproved:
		// Generated copy is never self-approving: the reviewer is a named
		// human, never a bot account and never the model that helped write it.
		// Reviewer and author may be the same person (owner decision on #440:
		// one operator today).
		switch {
		case strings.TrimSpace(p.ReviewedBy) == "":
			add("an approved update needs provenance.reviewed_by")
		case isBot(p.ReviewedBy):
			add("reviewer %q is a bot; approval needs a human", p.ReviewedBy)
		case p.AssistedBy != "" && strings.EqualFold(p.ReviewedBy, p.AssistedBy):
			add("reviewer %q is the model that assisted; a model cannot approve", p.ReviewedBy)
		}
		reviewed, err := time.Parse(time.DateOnly, e.ReviewedAt)
		if err != nil {
			add("reviewed_at %q is not YYYY-MM-DD", e.ReviewedAt)
		} else if created, cerr := time.Parse(time.DateOnly, e.CreatedAt); cerr == nil && reviewed.Before(created) {
			add("reviewed_at is before created_at")
		}
	default:
		add("status %q is not draft or approved", e.Status)
	}
	if isBot(p.Author) && p.AssistedBy == "" {
		add("author %q is a bot; name the model in provenance.assisted_by and a human author", p.Author)
	}
	return problems
}

func (e Entry) label() string {
	if e.ID != "" {
		return "product update " + e.ID
	}
	return "product update"
}

// isBot reports a GitHub bot or app login.
func isBot(login string) bool {
	l := strings.ToLower(strings.TrimSpace(login))
	return strings.HasSuffix(l, "[bot]") || strings.HasPrefix(l, "app/")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func duplicate(list []string) string {
	seen := map[string]bool{}
	for _, v := range list {
		if seen[v] {
			return v
		}
		seen[v] = true
	}
	return ""
}

// Feed is every entry in the feed directory, in id order.
type Feed struct {
	Entries []Entry
}

// FeedDir is where the canonical feed lives, relative to the repository root.
const FeedDir = "docs/product-updates"

// LoadFeed reads and validates every *.yaml file in dir. The file name must be
// the entry id, and ids are unique by construction of the file system -- but
// two files differing only in extension (.yml) are refused, so an id cannot
// appear twice. A missing directory is an empty feed.
func LoadFeed(dir string) (Feed, error) {
	files, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return Feed{}, nil
	}
	if err != nil {
		return Feed{}, fmt.Errorf("read feed: %w", err)
	}
	var feed Feed
	var problems []string
	for _, f := range files {
		name := f.Name()
		if f.IsDir() || name == "README.md" {
			continue
		}
		if filepath.Ext(name) != ".yaml" {
			problems = append(problems, fmt.Sprintf("%s: feed files are <id>.yaml", name))
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return Feed{}, fmt.Errorf("read %s: %w", name, err)
		}
		e, err := ParseEntry(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if want := strings.TrimSuffix(name, ".yaml"); e.ID != want {
			problems = append(problems, fmt.Sprintf("%s: id %q must equal the file name %q", name, e.ID, want))
		}
		if err := e.Validate(); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
		}
		feed.Entries = append(feed.Entries, e)
	}
	sort.Slice(feed.Entries, func(i, j int) bool { return feed.Entries[i].ID < feed.Entries[j].ID })
	if len(problems) > 0 {
		return feed, fmt.Errorf("invalid product-update feed:\n  %s", strings.Join(problems, "\n  "))
	}
	return feed, nil
}
