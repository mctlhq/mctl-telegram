// Package acquisition holds the sign-up source record of one account: the
// bounded MCP client label, taken from the OAuth redirect URI, and the
// optional answer to "How did you hear about us?" on the connect screen.
//
// The service sets no cookie for this and holds no IP address, user agent or
// referrer. A person who skips the question stays unknown; skipping is never
// read as "direct".
package acquisition

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxSnapshotBytes = 2048
	maxClientRunes   = 40
)

// Snapshot is what an authorize request knows about a possible sign-up.
type Snapshot struct {
	MCPClient  string    `json:"mc,omitempty"`
	CapturedAt time.Time `json:"t"`
}

// HeardFromOption is one fixed answer to the connect screen question.
type HeardFromOption struct {
	Value string
	Label string
}

// HeardFromOptions are the only answers stored. There is deliberately no free
// text field: a typed answer could hold a name or a message.
var HeardFromOptions = []HeardFromOption{
	{"search", "Search engine"},
	{"ai_assistant", "An AI assistant or its connector directory"},
	{"telegram", "Telegram"},
	{"social_media", "Social media"},
	{"article", "Article or blog"},
	{"friend_or_colleague", "Friend or colleague"},
	{"other", "Other"},
}

// ValidHeardFrom reports whether v is one of HeardFromOptions.
func ValidHeardFrom(v string) bool {
	for _, o := range HeardFromOptions {
		if o.Value == v {
			return true
		}
	}
	return false
}

func isBidi(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F, r == 0x061C:
		return true
	}
	return false
}

// Clean strips control characters, line separators and bidi overrides, trims
// space and truncates to max runes.
func Clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || isBidi(r) || r == 0x2028 || r == 0x2029 || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// New returns the snapshot of an authorize request.
func New(mcpClient string, now time.Time) Snapshot {
	return Snapshot{MCPClient: Clean(mcpClient, maxClientRunes), CapturedAt: now.UTC()}
}

// Marshal serialises a snapshot for the pending-auth entry.
func Marshal(s Snapshot) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Unmarshal parses a stored snapshot. An empty or malformed value yields an
// empty client label. Fields written by an older image, including the campaign
// values of the removed cookie, are ignored.
func Unmarshal(raw string, now time.Time) Snapshot {
	if raw == "" || len(raw) > maxSnapshotBytes {
		return New("", now)
	}
	var s Snapshot
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return New("", now)
	}
	s.MCPClient = Clean(s.MCPClient, maxClientRunes)
	if s.CapturedAt.IsZero() {
		s.CapturedAt = now.UTC()
	}
	return s
}
