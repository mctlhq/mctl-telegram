// Package broadcast implements the safe client broadcast workflow (issue-439):
// an operator-facing campaign that is prepared (previewed) by one call and
// released for delivery only by a separate human approval bound to the exact
// content and audience selector that were previewed.
//
// This file is the pure policy half: the audience selector, its canonical
// form and hash, content normalization and hash, and the per-recipient
// eligibility decision. Nothing here touches the database or the network, so
// the same Evaluate call decides eligibility at prepare time (the preview)
// and again immediately before each send (the delivery worker) -- one
// decision function, not two that can drift apart.
package broadcast

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// MaxTextRunes is Telegram's sendMessage text limit (4096 UTF-8 characters
// after entity parsing; no parse mode is used, so the raw text is what
// counts). A longer text would fail at delivery time for every recipient, so
// it is refused at prepare time instead.
const MaxTextRunes = 4096

// Tier values a selector may target. The tier is the recipient's EFFECTIVE
// tier as the OAuth server would resolve it (see TierOf), never the raw
// users.access_tier column.
const (
	TierClient = "client"
	TierAdmin  = "admin"
)

// SkipReason is why a recipient inside the selector's audience is not
// eligible. The set is closed and deterministic: the same facts and policy
// always produce the same reason, checked in the order Evaluate lists them.
type SkipReason string

const (
	// SkipNoAccount: the users row carries no live client identity -- never
	// captured since issue-438, or cleared by account deletion. The users
	// row survives deletion and preference rows are purged with it, so
	// without this rule a deleted account would fall back to the
	// subscribed-by-default operational categories and keep receiving
	// maintenance/security broadcasts.
	SkipNoAccount SkipReason = "no_account"
	// SkipPolicy: the recipient's effective tier is outside the selector
	// (including banned users and lookup-only operator identities).
	SkipPolicy SkipReason = "policy"
	// SkipUnsubscribed: the resolved preference for the campaign category
	// is unsubscribed (explicitly, or by default for product_updates).
	SkipUnsubscribed SkipReason = "unsubscribed"
	// SkipUnreachable: a real delivery has conclusively shown the bot
	// cannot reach this client (blocked / cannot_initiate).
	SkipUnreachable SkipReason = "unreachable"
	// SkipOutOfAudience: the selector's targeting filters (connected_via,
	// active window) exclude the recipient. Never counted in a preview --
	// such recipients are simply not the audience -- but the delivery worker
	// re-runs Evaluate before each send, where a grant expiring after
	// approval can move a queued recipient out of the audience, and that
	// skip needs a name too.
	SkipOutOfAudience SkipReason = "out_of_audience"
)

// SkipReasons lists every SkipReason in evaluation order, for reports that
// must show a zero count rather than omit a reason.
func SkipReasons() []SkipReason {
	return []SkipReason{SkipNoAccount, SkipPolicy, SkipUnsubscribed, SkipUnreachable}
}

// Selector is the server-side audience description a caller may submit.
// There is deliberately no field for a list of recipients: the audience is
// always computed from policy, never supplied.
type Selector struct {
	// Category is the notification category the broadcast belongs to; the
	// recipient's consent for exactly this category gates delivery.
	Category string `json:"category"`
	// Tiers is the set of effective tiers to target. Empty means clients
	// only -- admins are opted in explicitly, never by default.
	Tiers []string `json:"tiers,omitempty"`
	// ConnectedVia restricts the audience to users holding a live OAuth
	// grant for one of these client names (e.g. "Claude", "ChatGPT"),
	// compared case-insensitively. Empty means no restriction.
	ConnectedVia []string `json:"connected_via,omitempty"`
	// ActiveWithinDays restricts the audience to users seen (last login
	// capture) within this many days. Zero means no restriction.
	ActiveWithinDays int `json:"active_within_days,omitempty"`
}

// MaxActiveWithinDays bounds ActiveWithinDays so an absurd value cannot
// overflow the duration arithmetic.
const MaxActiveWithinDays = 3650

// ErrInvalidSelector wraps every selector validation failure.
var ErrInvalidSelector = errors.New("invalid broadcast selector")

// Normalize validates sel and returns its canonical form: lower-cased,
// de-duplicated, sorted lists, and the implicit default tier made explicit.
// Two selectors that describe the same audience normalize to the same value,
// which is what makes the selector hash a stable approval binding.
func (sel Selector) Normalize() (Selector, error) {
	out := Selector{Category: strings.TrimSpace(sel.Category), ActiveWithinDays: sel.ActiveWithinDays}
	known := false
	for _, c := range db.NotificationCategories() {
		if string(c) == out.Category {
			known = true
			break
		}
	}
	if !known {
		return Selector{}, fmt.Errorf("%w: unknown category %q", ErrInvalidSelector, sel.Category)
	}
	tiers := sel.Tiers
	if len(tiers) == 0 {
		tiers = []string{TierClient}
	}
	var err error
	out.Tiers, err = canonicalSet(tiers, func(t string) error {
		if t != TierClient && t != TierAdmin {
			return fmt.Errorf("%w: unknown tier %q", ErrInvalidSelector, t)
		}
		return nil
	})
	if err != nil {
		return Selector{}, err
	}
	out.ConnectedVia, err = canonicalSet(sel.ConnectedVia, func(c string) error {
		if c == "" {
			return fmt.Errorf("%w: empty connected_via entry", ErrInvalidSelector)
		}
		return nil
	})
	if err != nil {
		return Selector{}, err
	}
	if out.ActiveWithinDays < 0 || out.ActiveWithinDays > MaxActiveWithinDays {
		return Selector{}, fmt.Errorf("%w: active_within_days must be 0..%d", ErrInvalidSelector, MaxActiveWithinDays)
	}
	return out, nil
}

func canonicalSet(in []string, check func(string) error) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if err := check(v); err != nil {
			return nil, err
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}

// CanonicalJSON returns the canonical encoding of an already-normalized
// selector. Field order is fixed by the struct and the lists are sorted by
// Normalize, so the bytes are deterministic.
func (sel Selector) CanonicalJSON() (string, error) {
	b, err := json.Marshal(sel)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// NormalizeText applies the one normalization a broadcast text gets before it
// is hashed, previewed and delivered: CRLF/CR to LF and surrounding
// whitespace trimmed. The result is what is approved and what is sent, byte
// for byte.
func NormalizeText(text string) (string, error) {
	t := strings.ReplaceAll(text, "\r\n", "\n")
	t = strings.ReplaceAll(t, "\r", "\n")
	t = strings.TrimSpace(t)
	if t == "" {
		return "", errors.New("broadcast text is empty")
	}
	if !utf8.ValidString(t) {
		return "", errors.New("broadcast text is not valid UTF-8")
	}
	if n := utf8.RuneCountInString(t); n > MaxTextRunes {
		return "", fmt.Errorf("broadcast text is %d characters; Telegram allows at most %d", n, MaxTextRunes)
	}
	return t, nil
}

// Hash returns the hex SHA-256 of s. Used for both the content hash and the
// selector hash; each is computed over its canonical form only.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Policy carries the tier inputs the OAuth server resolves scopes from, so
// the audience's notion of "client" and "admin" is exactly the one a login
// would get. See TierOf.
type Policy struct {
	AdminTelegramIDs       map[int64]bool
	LookupAdminTelegramIDs map[int64]bool
	ClientTelegramIDs      map[int64]bool
	AutoApproveClients     bool
}

// TierOf resolves a recipient's effective tier with the same precedence as
// oauth.Server.ResolveScopes: admin, then lookup admin, then the client tier
// (explicit DB value wins over the env allowlist and auto-approve). It
// returns "" for anyone who is none of those -- including a banned user and
// a lookup-only operator identity, which a broadcast must never reach.
func (p Policy) TierOf(telegramID int64, rawAccessTier string) string {
	if p.AdminTelegramIDs[telegramID] {
		return TierAdmin
	}
	if p.LookupAdminTelegramIDs[telegramID] {
		return ""
	}
	switch rawAccessTier {
	case db.TierClient:
		return TierClient
	case db.TierNone:
		return ""
	default:
		if p.AutoApproveClients || p.ClientTelegramIDs[telegramID] {
			return TierClient
		}
		return ""
	}
}

// Decision is Evaluate's verdict for one recipient.
type Decision struct {
	// InAudience is false when the selector's targeting filters
	// (connected_via, active window) exclude the recipient outright; Reason
	// is then SkipOutOfAudience and Resolve does not count them.
	InAudience bool
	// Eligible is true when the recipient is in the audience and no skip
	// reason applies.
	Eligible bool
	Reason   SkipReason
}

// Evaluate decides one recipient against a normalized selector. The skip
// reasons are checked in a fixed order so a recipient who is both
// unsubscribed and unreachable is always reported the same way.
func Evaluate(sel Selector, f db.BroadcastRecipientFacts, p Policy, now time.Time) Decision {
	if len(sel.ConnectedVia) > 0 && !anyConnected(sel.ConnectedVia, f.ConnectedVia) {
		return Decision{Reason: SkipOutOfAudience}
	}
	if sel.ActiveWithinDays > 0 {
		cutoff := now.Add(-time.Duration(sel.ActiveWithinDays) * 24 * time.Hour)
		if f.LastSeenAt == nil || f.LastSeenAt.Before(cutoff) {
			return Decision{Reason: SkipOutOfAudience}
		}
	}
	if f.IdentityCapturedAt == nil {
		return Decision{InAudience: true, Reason: SkipNoAccount}
	}
	tier := p.TierOf(f.TelegramID, f.AccessTier)
	if tier == "" || !contains(sel.Tiers, tier) {
		return Decision{InAudience: true, Reason: SkipPolicy}
	}
	if db.ResolvePrefState(db.NotificationCategory(sel.Category), f.Prefs) != db.PrefSubscribed {
		return Decision{InAudience: true, Reason: SkipUnsubscribed}
	}
	switch f.Reachability {
	case notify.StateBlocked, notify.StateCannotInitiate:
		return Decision{InAudience: true, Reason: SkipUnreachable}
	}
	return Decision{InAudience: true, Eligible: true}
}

func anyConnected(want, have []string) bool {
	for _, h := range have {
		if contains(want, strings.ToLower(strings.TrimSpace(h))) {
			return true
		}
	}
	return false
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
