package pa

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// DefaultConversationTTL and MaxConversationTTL bound PA_CONVERSATION_TTL.
// The TTL is anchored at creation (owner decision 2026-11-18), and the
// consent text promises at most 24 hours, so a longer TTL is refused.
const (
	DefaultConversationTTL = 24 * time.Hour
	MaxConversationTTL     = 24 * time.Hour
)

// ConsentPromptTTL is how long a consent button stays resolvable.
const ConsentPromptTTL = time.Hour

// UpdatesRetention is how long a pa_updates dedup row is kept: longer than
// Telegram's retry window (owner decision 2026-11-18: 48 hours).
const UpdatesRetention = 48 * time.Hour

// Reply is a server-templated answer to a command or a state change. The
// handler only names it; slice (c)'s Sender renders and sends it after the
// commit.
type Reply string

const (
	ReplyConsentPrompt    Reply = "consent_prompt"
	ReplyConsentAccepted  Reply = "consent_accepted"
	ReplyConsentWithdrawn Reply = "consent_withdrawn"
	ReplyConsentStale     Reply = "consent_stale"
	ReplyNewConversation  Reply = "new_conversation"
	ReplyForgotten        Reply = "forgotten"
	ReplyUnknownButton    Reply = "unknown_button"
)

// ReplyQueue records a reply in the update's transaction, so it is sent
// only if the state change it describes committed. button is the opaque
// callback_data of the reply's single button, or "".
type ReplyQueue interface {
	QueueReply(ctx context.Context, tx *sql.Tx, p Principal, r Reply, button string) error
}

// RunRequest is what the conversation layer hands the run loop: the
// principal, the conversation, and the consent version the update was
// admitted under. It carries no text; the run loads the marked fragments
// itself through Conversations.Load.
type RunRequest struct {
	UpdateID       int64
	Principal      Principal
	ConversationID string
	ConsentVersion string
}

// RunEnqueuer is the boundary to the model (slice d1). It is called only
// after consent was read and found current, and only inside the update's
// transaction (the d1 constraint: enqueue in the transaction, run after the
// commit). No other code path in this package reaches the model.
type RunEnqueuer interface {
	EnqueueRun(ctx context.Context, tx *sql.Tx, req RunRequest) error
}

// Errors from the conversation layer. None carries text or ids.
var (
	// ErrConsentRequired: no consent, a withdrawn one, or one to another
	// version or text. The run is refused and the principal is asked.
	ErrConsentRequired = errors.New("pa: consent to the current data-flow text is required")
	// ErrConsentUnreadable: the consent record could not be read. The run
	// is refused; this is never treated as either consent or its absence.
	ErrConsentUnreadable = errors.New("pa: consent record unreadable")
	// ErrConversationsConfig reports an unusable ConversationsConfig.
	ErrConversationsConfig = errors.New("pa: conversations need a store, a sealer and a TTL of at most 24h")
)

// Command names handled server-side (PR #1329 decision for slice b). They
// are recognised only in user-provenance text, so a forwarded "/forget" is
// just external text; they are never stored as fragments.
const (
	CommandNew     = "/new"
	CommandForget  = "/forget"
	CommandConsent = "/consent"
)

// Callback actions. The stored action binds the consent version and text
// hash the prompt showed, so a button pressed after the text changed does
// not accept a text the principal never saw.
const actionConsentAcceptPrefix = "consent_accept:"

// ConversationsConfig configures NewConversations.
type ConversationsConfig struct {
	Store  convo.Store
	Sealer *convo.Sealer
	// TTL is PA_CONVERSATION_TTL. Required, at most MaxConversationTTL.
	TTL time.Duration
	// Runs is the run loop; nil until slice (d1), in which case accepted
	// messages are stored and nothing runs.
	Runs RunEnqueuer
	// Replies is optional until slice (c) provides the sender.
	Replies ReplyQueue
	// Now defaults to time.Now.
	Now func() time.Time
}

// Conversations is the slice (b) update handler: consent, server-side
// commands, marked conversation state and opaque callbacks. It implements
// Handler and runs inside the webhook's dedup transaction.
type Conversations struct {
	store   convo.Store
	sealer  *convo.Sealer
	ttl     time.Duration
	runs    RunEnqueuer
	replies ReplyQueue
	now     func() time.Time
}

var _ Handler = (*Conversations)(nil)

// NewConversations builds the handler.
func NewConversations(cfg ConversationsConfig) (*Conversations, error) {
	if cfg.Store == nil || cfg.Sealer == nil || cfg.TTL <= 0 || cfg.TTL > MaxConversationTTL {
		return nil, ErrConversationsConfig
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Conversations{store: cfg.Store, sealer: cfg.Sealer, ttl: cfg.TTL, runs: cfg.Runs, replies: cfg.Replies, now: now}, nil
}

// HandleUpdate implements Handler. Any error rolls back the update's dedup
// row, so Telegram retries it; nothing ran.
func (c *Conversations) HandleUpdate(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	p := u.Principal()
	if p.IsZero() {
		return ErrNoPrincipal
	}
	// Serialise this principal's updates before reading anything. Without
	// it a message that read consent=accepted could commit its conversation
	// after a concurrent /consent withdraw or /forget had already committed,
	// leaving state the withdrawal never saw (S1-N4).
	if err := c.store.LockPAPrincipal(ctx, tx, p.TelegramID()); err != nil {
		return err
	}
	switch u.Kind() {
	case KindCallbackQuery:
		return c.handleCallback(ctx, tx, u)
	case KindMessage:
		return c.handleMessage(ctx, tx, u)
	default:
		return fmt.Errorf("pa: unexpected update kind %q", u.Kind())
	}
}

func (c *Conversations) handleMessage(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	p := u.Principal()
	frags := u.Fragments()
	if cmd, arg, ok := userCommand(frags); ok {
		return c.handleCommand(ctx, tx, p, cmd, arg)
	}
	// Consent first: without it nothing is stored and nothing runs (S1-N1).
	version, err := c.requireConsent(ctx, tx, p)
	if errors.Is(err, ErrConsentRequired) {
		return c.prompt(ctx, tx, p)
	}
	if err != nil {
		return err
	}
	if len(frags) == 0 {
		return nil
	}
	conv, err := c.store.OpenPAConversation(ctx, tx, p.TelegramID(), newOpaqueID(), c.now(), c.ttl)
	if err != nil {
		return err
	}
	seq, err := c.store.NextPAFragmentSeq(ctx, tx, p.TelegramID(), conv.ID)
	if err != nil {
		return err
	}
	now := c.now()
	for _, f := range frags {
		sf, err := c.sealer.Seal(p.TelegramID(), conv.ID, seq, f)
		if err != nil {
			return err
		}
		sf.CreatedAt = now
		if err := c.store.AppendPAFragment(ctx, tx, sf); err != nil {
			return err
		}
		seq++
	}
	if c.runs == nil {
		return nil
	}
	return c.runs.EnqueueRun(ctx, tx, RunRequest{
		UpdateID:       u.UpdateID(),
		Principal:      p,
		ConversationID: conv.ID,
		ConsentVersion: version,
	})
}

func (c *Conversations) handleCommand(ctx context.Context, tx *sql.Tx, p Principal, cmd, arg string) error {
	switch cmd {
	case CommandNew:
		if err := c.store.ClosePAConversations(ctx, tx, p.TelegramID(), c.now()); err != nil {
			return err
		}
		return c.reply(ctx, tx, p, ReplyNewConversation, "")
	case CommandForget:
		if err := c.store.ForgetPAConversations(ctx, tx, p.TelegramID()); err != nil {
			return err
		}
		return c.reply(ctx, tx, p, ReplyForgotten, "")
	case CommandConsent:
		switch arg {
		case "withdraw":
			if err := c.store.WithdrawPAConsent(ctx, tx, p.TelegramID(), c.now()); err != nil {
				return err
			}
			return c.reply(ctx, tx, p, ReplyConsentWithdrawn, "")
		default:
			// Anything else, "/consent accept" included, shows the text
			// with its button: consent is recorded only from a button bound
			// to the text the principal was shown (T13), never from typed
			// words that need not follow any prompt.
			return c.prompt(ctx, tx, p)
		}
	}
	return fmt.Errorf("pa: unhandled command %q", cmd)
}

func (c *Conversations) handleCallback(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	p := u.Principal()
	action, err := c.store.ConsumePACallback(ctx, tx, p.TelegramID(), u.CallbackData(), c.now())
	if errors.Is(err, convo.ErrNotFound) {
		// Unknown, expired, already used, or another principal's id: the
		// lookup is under (principal, id), so all four look the same.
		return c.reply(ctx, tx, p, ReplyUnknownButton, "")
	}
	if err != nil {
		return err
	}
	if !strings.HasPrefix(action, actionConsentAcceptPrefix) {
		// An action this build does not know: the id is consumed and the
		// press answered, never an error, which would roll the consume back
		// and have Telegram redeliver the update forever.
		return c.reply(ctx, tx, p, ReplyUnknownButton, "")
	}
	if action != consentAcceptAction() {
		// The text changed after the prompt was shown: ask again.
		if err := c.reply(ctx, tx, p, ReplyConsentStale, ""); err != nil {
			return err
		}
		return c.prompt(ctx, tx, p)
	}
	if err := c.store.AcceptPAConsent(ctx, tx, p.TelegramID(), convo.ConsentVersion, convo.ConsentTextSHA256(), c.now()); err != nil {
		return err
	}
	return c.reply(ctx, tx, p, ReplyConsentAccepted, "")
}

// prompt issues a consent button bound to the current version and text.
func (c *Conversations) prompt(ctx context.Context, tx *sql.Tx, p Principal) error {
	id := newOpaqueID()
	if err := c.store.CreatePACallback(ctx, tx, p.TelegramID(), id, consentAcceptAction(), c.now().Add(ConsentPromptTTL)); err != nil {
		return err
	}
	return c.reply(ctx, tx, p, ReplyConsentPrompt, id)
}

func (c *Conversations) reply(ctx context.Context, tx *sql.Tx, p Principal, r Reply, button string) error {
	if c.replies == nil {
		return nil
	}
	return c.replies.QueueReply(ctx, tx, p, r, button)
}

// requireConsent returns the consent version p agreed to, ErrConsentRequired,
// or ErrConsentUnreadable. It never turns a failed read into either answer
// (S1-N2).
func (c *Conversations) requireConsent(ctx context.Context, tx *sql.Tx, p Principal) (string, error) {
	rec, err := c.store.GetPAConsent(ctx, tx, p.TelegramID())
	switch {
	case errors.Is(err, convo.ErrNotFound):
		return "", ErrConsentRequired
	case err != nil:
		return "", fmt.Errorf("%w: %v", ErrConsentUnreadable, err)
	case !convo.Satisfied(rec):
		return "", ErrConsentRequired
	}
	return rec.Version, nil
}

// RequireConsent is the consent check the run loop repeats at claim and
// before each model turn (slice d1), in its own transaction.
func (c *Conversations) RequireConsent(ctx context.Context, tx *sql.Tx, p Principal) (string, error) {
	if p.IsZero() {
		return "", ErrNoPrincipal
	}
	return c.requireConsent(ctx, tx, p)
}

// Load returns the marked fragments of the run's conversation, keyed by the
// context's principal (I10). A fragment without a known mark fails the
// whole load (ErrUnmarked): unmarked state is never loaded (T5).
func (c *Conversations) Load(ctx context.Context, ec ExecutionContext) ([]convo.Fragment, error) {
	if !ec.Valid() {
		return nil, ErrInvalidContext
	}
	pid := ec.Principal().TelegramID()
	rows, err := c.store.LoadPAFragments(ctx, pid, ec.ConversationID(), c.now())
	if err != nil {
		return nil, err
	}
	out := make([]convo.Fragment, 0, len(rows))
	for _, r := range rows {
		f, err := c.sealer.Open(pid, r)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func consentAcceptAction() string {
	return actionConsentAcceptPrefix + convo.ConsentVersion + ":" + convo.ConsentTextSHA256()
}

// userCommand reports whether the message is a server-side command: its
// text fragment is user-provenance and its first word is one of ours
// (optionally addressed as /cmd@bot). A command message is handled whole;
// none of its fragments (a quoted reply, say) is stored.
func userCommand(frags []convo.Fragment) (cmd, arg string, ok bool) {
	for _, f := range frags {
		if f.Kind() != convo.KindText {
			continue
		}
		text, prov := f.Text()
		if prov != convo.ProvenanceUser {
			return "", "", false
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			return "", "", false
		}
		// Commands are case-insensitive, as Telegram treats them: a phone
		// keyboard's "/Forget" must not reach the model as text. The
		// @bot suffix is cut before folding.
		name, _, _ := strings.Cut(fields[0], "@")
		name = strings.ToLower(name)
		switch name {
		case CommandNew, CommandForget, CommandConsent:
			if len(fields) > 1 {
				arg = strings.ToLower(fields[1])
			}
			return name, arg, true
		}
		return "", "", false
	}
	return "", "", false
}

// newOpaqueID returns 128 random bits, base64url: 22 bytes, well within the
// 64-byte callback_data limit, and meaningless outside (principal, id).
func newOpaqueID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+).
	return base64.RawURLEncoding.EncodeToString(b)
}
