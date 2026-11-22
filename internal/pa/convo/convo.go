// Package convo holds the Personal Assistant's conversation state and
// consent types (issue #1313 slice b; threat model T5 and T13). It is a leaf
// package so that internal/db can implement Store without importing
// internal/pa, whose tests import internal/db.
//
// The rules it encodes:
//
//   - Every fragment of conversation state carries a provenance mark. Text
//     is only ever handed out together with that mark (Fragment.Text), and
//     the mark is bound into the ciphertext as AEAD additional data, so a
//     row whose mark was edited in the database no longer decrypts.
//   - Anything not positively marked user is external (I6, I9).
//   - A failed read is an error, never "no consent" or "empty state" (I9).
package convo

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"
)

// Provenance marks where a fragment came from (threat model T5). The zero
// value is unknown, and unknown is treated as external.
type Provenance string

const (
	ProvenanceUser     Provenance = "user"
	ProvenanceExternal Provenance = "external"
)

// Known reports whether p is one of the two marks this build writes.
func (p Provenance) Known() bool { return p == ProvenanceUser || p == ProvenanceExternal }

// Effective returns the provenance a gate must act on: only an explicit
// ProvenanceUser is user; everything else, including the zero value, is
// external (S1-I4).
func (p Provenance) Effective() Provenance {
	if p == ProvenanceUser {
		return ProvenanceUser
	}
	return ProvenanceExternal
}

// Kind says which part of an update (or of a run) a fragment holds.
type Kind string

const (
	// KindText is message.text.
	KindText Kind = "text"
	// KindCaption is a media caption: always external.
	KindCaption Kind = "caption"
	// KindReply is the text or caption of reply_to_message: always external.
	KindReply Kind = "reply"
	// KindQuote is the quote of a reply: always external.
	KindQuote Kind = "quote"
	// KindAssistant is model output, stored by the run loop (slice d1).
	KindAssistant Kind = "assistant"
	// KindTool is tool output, stored by the run loop when the dispatcher
	// returns a tool result to the worker (#1321): always external.
	KindTool Kind = "tool"
)

// Kinds lists every valid Kind, for stores that must find rows of any other.
func Kinds() []Kind {
	return []Kind{KindText, KindCaption, KindReply, KindQuote, KindAssistant, KindTool}
}

// Valid reports whether k is a kind this build knows.
func (k Kind) Valid() bool { return slices.Contains(Kinds(), k) }

// Taints reports whether storing a fragment of kind with mark prov taints
// its conversation (threat model T5, #1321): anything not exactly user is
// external content entering the conversation. Model output is the one
// exception (owner decision 2026-11-21): an answer written in a clean
// conversation saw no external content, and one written in a tainted
// conversation changes nothing, because the flag only ever rises.
//
// The decision does not trust the stored mark alone: a caption, reply,
// quote or tool output taints whatever mark it carries, as NewFragment
// would have marked it, so a store handed a SealedFragment built some
// other way still raises the flag.
func Taints(kind Kind, prov Provenance) bool {
	switch kind {
	case KindAssistant:
		return false
	case KindCaption, KindReply, KindQuote, KindTool:
		return true
	}
	return prov.Effective() != ProvenanceUser
}

// Fragment is one marked piece of conversation text. Its fields are
// unexported: the text cannot be read without its mark.
type Fragment struct {
	kind Kind
	prov Provenance
	text string
}

// NewFragment builds a fragment. A mark that is not exactly user is stored
// as external, so nothing unmarked can ever be written (S1-I4). Captions,
// replies, quotes and tool output are external whatever the caller says.
func NewFragment(kind Kind, prov Provenance, text string) Fragment {
	p := prov.Effective()
	switch kind {
	case KindCaption, KindReply, KindQuote, KindTool:
		p = ProvenanceExternal
	}
	return Fragment{kind: kind, prov: p, text: text}
}

// Text returns the fragment's text together with its effective mark. There
// is deliberately no accessor that returns the text alone.
func (f Fragment) Text() (string, Provenance) { return f.text, f.prov.Effective() }

// Provenance returns the effective mark.
func (f Fragment) Provenance() Provenance { return f.prov.Effective() }

// Kind returns the fragment's kind.
func (f Fragment) Kind() Kind { return f.kind }

// Errors shared by the store and its callers.
var (
	// ErrNotFound is the documented absence signal: the row does not exist.
	ErrNotFound = errors.New("pa convo: not found")
	// ErrUnreadable is any failure to read or interpret a row. It is never
	// treated as absence (I9).
	ErrUnreadable = errors.New("pa convo: state unreadable")
	// ErrStoreFault marks an ErrUnreadable that is the store's (a query,
	// begin or timeout failed) rather than the row's: nothing was observed,
	// so it must not count against the row's job (#1313 d1).
	ErrStoreFault = errors.New("pa convo: store fault")
	// ErrUnmarked is a stored fragment without a known provenance mark.
	// Unmarked state is never loaded (T5); PurgeUnmarkedPAState deletes it.
	ErrUnmarked = errors.New("pa convo: fragment without a provenance mark")
	// ErrInvalid is a write the store refuses before touching a row.
	ErrInvalid = errors.New("pa convo: invalid write")
)

// Conversation is one conversation row. ExpiresAt is CreatedAt plus the TTL
// at creation and never moves (owner decision 2026-11-18: not sliding).
type Conversation struct {
	ID        string
	Principal int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// SealedFragment is a fragment as stored: the mark and kind in clear (so
// the purge and the AAD check can see them), the text sealed.
type SealedFragment struct {
	ConversationID string
	Seq            int64
	Principal      int64
	Kind           Kind
	Provenance     Provenance
	Sealed         []byte
	CreatedAt      time.Time
}

// ConsentState is the state of a consent row.
type ConsentState string

const (
	ConsentAccepted  ConsentState = "accepted"
	ConsentWithdrawn ConsentState = "withdrawn"
)

// ConsentRecord is a principal's stored consent.
type ConsentRecord struct {
	Principal  int64
	Version    string
	TextSHA256 string
	State      ConsentState
	UpdatedAt  time.Time
}

// SweepResult counts what one SweepPAState pass deleted.
type SweepResult struct {
	Conversations, Fragments, Callbacks, Updates int64
	// LinkSecrets counts linking secrets deleted past their retention
	// (#1338).
	LinkSecrets int64
}

// Store is the persistence contract (implemented by *db.Store). Methods that
// take a *sql.Tx run inside the webhook's dedup transaction, so the state
// change and the update's dedup row commit or roll back together. Every
// lookup is keyed by principal (I10).
type Store interface {
	// LockPAPrincipal takes a lock on principal held until tx ends, so
	// updates of one principal apply one after another. Callers take it
	// before any other read in tx.
	LockPAPrincipal(ctx context.Context, tx *sql.Tx, principal int64) error
	// PAPrincipalDisabled reports whether an admin disabled the
	// principal's PA (T11, S1-F4). Only an absent row is false; any error
	// wraps ErrUnreadable (and ErrStoreFault for a failed read) and comes
	// with true.
	PAPrincipalDisabled(ctx context.Context, tx *sql.Tx, principal int64) (bool, error)
	// GetPAConsent returns ErrNotFound only when no row exists, and wraps
	// ErrUnreadable for every other failure.
	GetPAConsent(ctx context.Context, tx *sql.Tx, principal int64) (ConsentRecord, error)
	// AcceptPAConsent records consent to version/textSHA256.
	AcceptPAConsent(ctx context.Context, tx *sql.Tx, principal int64, version, textSHA256 string, now time.Time) error
	// WithdrawPAConsent marks consent withdrawn and deletes every
	// conversation, fragment and pending callback of the principal.
	WithdrawPAConsent(ctx context.Context, tx *sql.Tx, principal int64, now time.Time) error

	// OpenPAConversation returns the principal's open, unexpired
	// conversation, creating one (expires_at = now + ttl) if none exists.
	// A new conversation starts clean; an existing one keeps its taint.
	// A new row is the only way taint resets (#1321): /new, TTL expiry,
	// /forget and purge all end the old row, and nothing clears the flag
	// on a row in place.
	OpenPAConversation(ctx context.Context, tx *sql.Tx, principal int64, newID string, now time.Time, ttl time.Duration) (Conversation, error)
	// ClosePAConversations closes the principal's open conversation (/new):
	// it is never loaded again and the sweeper deletes it.
	ClosePAConversations(ctx context.Context, tx *sql.Tx, principal int64, now time.Time) error
	// ForgetPAConversations hard-deletes every conversation and fragment of
	// the principal (/forget), and every link secret of a link the
	// principal has not finished, so it cannot complete afterwards.
	ForgetPAConversations(ctx context.Context, tx *sql.Tx, principal int64) error
	// NextPAFragmentSeq returns the next sequence number in a conversation
	// of the principal.
	NextPAFragmentSeq(ctx context.Context, tx *sql.Tx, principal int64, conversationID string) (int64, error)
	// AppendPAFragment stores one sealed fragment. It refuses an unknown
	// mark or kind (ErrInvalid). A fragment that Taints marks its
	// conversation tainted in the same transaction, so the content and the
	// flag commit together or not at all.
	AppendPAFragment(ctx context.Context, tx *sql.Tx, f SealedFragment) error
	// ReadPAConversationTaint reports whether external content entered the
	// principal's conversation (T5, #1321). Any error, ErrNotFound included,
	// comes with true: a caller that cannot observe the flag acts on taint.
	ReadPAConversationTaint(ctx context.Context, principal int64, conversationID string) (bool, error)
	// LoadPAFragments returns the fragments of an open, unexpired
	// conversation of the principal in order. A conversation that is not
	// the principal's, closed or expired is ErrNotFound.
	LoadPAFragments(ctx context.Context, principal int64, conversationID string, now time.Time) ([]SealedFragment, error)

	// CreatePACallback stores an opaque callback id for the principal.
	CreatePACallback(ctx context.Context, tx *sql.Tx, principal int64, id, action string, expiresAt time.Time) error
	// ConsumePACallback deletes and returns the action of (principal, id)
	// if it exists and has not expired; otherwise ErrNotFound. Another
	// principal's id is ErrNotFound and is left untouched.
	ConsumePACallback(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (string, error)

	// PurgeUnmarkedPAState deletes every fragment without a known mark.
	PurgeUnmarkedPAState(ctx context.Context) (int64, error)
	// SweepPAState hard-deletes expired and closed conversations with their
	// fragments, expired callbacks, and pa_updates received before
	// updatesBefore.
	SweepPAState(ctx context.Context, now, updatesBefore time.Time) (SweepResult, error)
}
