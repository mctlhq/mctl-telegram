package pa

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
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
	// ReplyRateLimited is queued once per rate window, on the first
	// message over the limit (#1313 slice d1).
	ReplyRateLimited Reply = "rate_limited"
	// ReplyMessageTooLong refuses a message part over jobs.MaxMessageChars;
	// nothing of the message is stored (S1-R1).
	ReplyMessageTooLong Reply = "message_too_long"
	// ReplyPrincipalDisabled refuses every update, other than /forget and
	// /consent withdraw, of a principal an admin disabled or one not on the
	// preview allowlist (T11, #1318). Nothing of the update is stored.
	ReplyPrincipalDisabled Reply = "principal_disabled"
)

// ReplyQueue records a reply in the update's transaction, so it is sent
// only if the state change it describes committed. updateID is the update
// that owes it; button is the opaque callback_data of the reply's single
// button, or "". *OutboxReplies is the production queue.
type ReplyQueue interface {
	QueueReply(ctx context.Context, tx *sql.Tx, p Principal, updateID int64, r Reply, button string) error
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

// Limiter counts each update of a principal against its rate window, in
// the update's transaction (#1313 slice d1, T10). *RunLoop implements it.
type Limiter interface {
	AdmitMessage(ctx context.Context, tx *sql.Tx, p Principal) (jobs.RateDecision, error)
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
	ErrConversationsConfig = errors.New("pa: conversations need a store, a sealer, an allowlist, a TTL of at most 24h, and a limiter with a run loop")
)

// Command names handled server-side (PR #1329 decision for slice b). They
// are recognised only in user-provenance text, so a forwarded "/forget" is
// just external text; they are never stored as fragments.
const (
	CommandNew     = "/new"
	CommandForget  = "/forget"
	CommandConsent = "/consent"
	// The account-linking commands (#1318 slice C2). The update's
	// transaction only admits them (consent, rate window); the linking
	// action runs after the commit (postcommit.go).
	CommandConnect     = "/connect"
	CommandDisconnect  = "/disconnect"
	CommandConnections = "/connections"
)

// LinkButtonPrefixes are the callback_data prefixes of the linking confirm
// card (linking.ConfirmCard). Such a button is not a pa_callbacks row: the
// linking flow consumes its own nonce after the commit.
var LinkButtonPrefixes = []string{"pa:lc:", "pa:lx:"}

// ReplyLinkingUnavailable answers a linking command when the server runs
// no linking flow (no PA server enabled).
const ReplyLinkingUnavailable Reply = "linking_unavailable"

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
	// Replies queues the conversation's own answers (*OutboxReplies in
	// production, #1348). Without it no consent prompt is ever sent, so
	// nobody can consent and nothing runs.
	Replies ReplyQueue
	// Limiter is the per-principal rate window. Required with Runs: a run
	// loop without a rate limit is refused.
	Limiter Limiter
	// Linking: the server runs the account-linking flow, so the linking
	// commands and buttons are handed to AfterCommit (LinkAction). Off,
	// a linking command is answered ReplyLinkingUnavailable and a linking
	// button ReplyUnknownButton.
	Linking bool
	// Allowed is the preview allowlist (PA_ALLOWED_PRINCIPALS). Required:
	// there is no "allow everyone" default, and an empty list allows
	// nobody.
	Allowed PrincipalAllowlist
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
	limiter Limiter
	linking bool
	allowed PrincipalAllowlist
	now     func() time.Time
}

var _ Handler = (*Conversations)(nil)

// NewConversations builds the handler.
func NewConversations(cfg ConversationsConfig) (*Conversations, error) {
	if cfg.Store == nil || cfg.Sealer == nil || cfg.Allowed == nil || cfg.TTL <= 0 || cfg.TTL > MaxConversationTTL ||
		(cfg.Runs != nil && cfg.Limiter == nil) {
		return nil, ErrConversationsConfig
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Conversations{store: cfg.Store, sealer: cfg.Sealer, ttl: cfg.TTL, runs: cfg.Runs, replies: cfg.Replies, limiter: cfg.Limiter,
		linking: cfg.Linking, allowed: cfg.Allowed, now: now}, nil
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
	// A principal not on the allowlist, or one an admin disabled, gets
	// the fixed refusal and nothing of the update is stored or queued
	// (T11, #1318). The refusal goes through the rate window like any
	// update and is sent only for the first update of the window: on a
	// preview almost everyone is refused, so one reply per update would let
	// any stranger flood the outbox and the bot's send rate. Without a
	// limiter (no run loop, so nothing can run) the refusal is silent.
	// /forget and /consent withdraw still run, so a refused principal can
	// always delete their data. A disable that cannot be read is an error:
	// the update rolls back and Telegram retries it.
	if !erasure(u) {
		refused, err := c.principalRefused(ctx, tx, p)
		if err != nil {
			return err
		}
		if refused {
			if c.limiter == nil {
				return nil
			}
			d, err := c.limiter.AdmitMessage(ctx, tx, p)
			if err != nil {
				return err
			}
			if d.First {
				return c.reply(ctx, tx, u, ReplyPrincipalDisabled, "")
			}
			return nil
		}
	}
	// The rate window counts every update, consent prompts and button
	// presses included (#1313 slice d1). /forget and /consent withdraw
	// always go through: the deletion runs first, and only its
	// confirmation is counted (erasureReply).
	if c.limiter != nil && !erasure(u) {
		d, err := c.limiter.AdmitMessage(ctx, tx, p)
		if err != nil {
			return err
		}
		if !d.Allowed {
			if d.Notify {
				return c.reply(ctx, tx, u, ReplyRateLimited, "")
			}
			return nil
		}
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
		return c.handleCommand(ctx, tx, u, cmd, arg)
	}
	// Size before anything is stored (S1-R1): a part over the Telegram
	// maximum is refused whole, not cut.
	for _, f := range frags {
		if text, _ := f.Text(); utf16Len(text) > jobs.MaxMessageChars {
			return c.reply(ctx, tx, u, ReplyMessageTooLong, "")
		}
	}
	// Consent first: without it nothing is stored and nothing runs (S1-N1).
	version, err := c.requireConsent(ctx, tx, p)
	if errors.Is(err, ErrConsentRequired) {
		return c.prompt(ctx, tx, u)
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
	// Every fragment that is not exactly user text (a forward, caption,
	// reply, quote, or an unknown mark) taints the conversation in this
	// transaction: AppendPAFragment raises the flag with the insert, so the
	// content and the taint commit together (T5, #1321).
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

func (c *Conversations) handleCommand(ctx context.Context, tx *sql.Tx, u VerifiedUpdate, cmd, arg string) error {
	p := u.Principal()
	switch cmd {
	case CommandNew:
		if err := c.store.ClosePAConversations(ctx, tx, p.TelegramID(), c.now()); err != nil {
			return err
		}
		return c.reply(ctx, tx, u, ReplyNewConversation, "")
	case CommandForget:
		if err := c.store.ForgetPAConversations(ctx, tx, p.TelegramID()); err != nil {
			return err
		}
		if err := c.retireLinks(ctx); err != nil {
			return err
		}
		return c.erasureReply(ctx, tx, u, ReplyForgotten)
	case CommandConsent:
		switch arg {
		case "withdraw":
			if err := c.store.WithdrawPAConsent(ctx, tx, p.TelegramID(), c.now()); err != nil {
				return err
			}
			if err := c.retireLinks(ctx); err != nil {
				return err
			}
			return c.erasureReply(ctx, tx, u, ReplyConsentWithdrawn)
		default:
			// Anything else, "/consent accept" included, shows the text
			// with its button: consent is recorded only from a button bound
			// to the text the principal was shown (T13), never from typed
			// words that need not follow any prompt.
			return c.prompt(ctx, tx, u)
		}
	case CommandConnect, CommandDisconnect, CommandConnections:
		return c.handleLinkCommand(ctx, tx, u, cmd, arg)
	}
	return fmt.Errorf("pa: unhandled command %q", cmd)
}

// handleLinkCommand admits a linking command in the update's transaction
// and leaves the action to AfterCommit: Manager.Begin and Disconnect take
// the principal lock this transaction holds (postcommit.go). Consent comes
// first, as for any message; the rate window has already counted it.
func (c *Conversations) handleLinkCommand(ctx context.Context, tx *sql.Tx, u VerifiedUpdate, cmd, arg string) error {
	if !c.linking {
		return c.reply(ctx, tx, u, ReplyLinkingUnavailable, "")
	}
	_, err := c.requireConsent(ctx, tx, u.Principal())
	if errors.Is(err, ErrConsentRequired) {
		return c.prompt(ctx, tx, u)
	}
	if err != nil {
		return err
	}
	return setPostCommit(ctx, LinkAction{Command: cmd, Arg: arg})
}

// retireLinks records, with linking on, that the principal's unfinished
// links are failed after the commit (LinkAction.Retire). The store already
// deleted their link secrets in this transaction.
func (c *Conversations) retireLinks(ctx context.Context) error {
	if !c.linking {
		return nil
	}
	return setPostCommit(ctx, LinkAction{Retire: true})
}

// linkButton reports whether data is a linking confirm card button.
func linkButton(data string) bool {
	for _, p := range LinkButtonPrefixes {
		if strings.HasPrefix(data, p) {
			return true
		}
	}
	return false
}

func (c *Conversations) handleCallback(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	p := u.Principal()
	if c.linking && linkButton(u.CallbackData()) {
		// The confirm card's nonce is the linking flow's, not a pa_callbacks
		// id: consuming it here would answer "unknown button" and the
		// card's press would never reach the flow. The flow checks the
		// nonce, its principal and its expiry after the commit.
		return setPostCommit(ctx, LinkAction{Button: true})
	}
	action, err := c.store.ConsumePACallback(ctx, tx, p.TelegramID(), u.CallbackData(), c.now())
	if errors.Is(err, convo.ErrNotFound) {
		// Unknown, expired, already used, or another principal's id: the
		// lookup is under (principal, id), so all four look the same.
		return c.reply(ctx, tx, u, ReplyUnknownButton, "")
	}
	if err != nil {
		return err
	}
	if !strings.HasPrefix(action, actionConsentAcceptPrefix) {
		// An action this build does not know: the id is consumed and the
		// press answered, never an error, which would roll the consume back
		// and have Telegram redeliver the update forever.
		return c.reply(ctx, tx, u, ReplyUnknownButton, "")
	}
	if action != consentAcceptAction() {
		// The text changed after the prompt was shown: ask again.
		if err := c.reply(ctx, tx, u, ReplyConsentStale, ""); err != nil {
			return err
		}
		return c.prompt(ctx, tx, u)
	}
	if err := c.store.AcceptPAConsent(ctx, tx, p.TelegramID(), convo.ConsentVersion, convo.ConsentTextSHA256(), c.now()); err != nil {
		return err
	}
	return c.reply(ctx, tx, u, ReplyConsentAccepted, "")
}

// principalRefused reports whether p may not use the PA: not on the
// allowlist, or disabled by an admin. A failed read of the disable is an
// error, never "enabled".
func (c *Conversations) principalRefused(ctx context.Context, tx *sql.Tx, p Principal) (bool, error) {
	if !c.allowed.Allowed(p.TelegramID()) {
		return true, nil
	}
	disabled, err := c.store.PAPrincipalDisabled(ctx, tx, p.TelegramID())
	if err != nil {
		return true, fmt.Errorf("pa: principal disable: %w", err)
	}
	return disabled, nil
}

// prompt issues a consent button bound to the current version and text.
func (c *Conversations) prompt(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	p := u.Principal()
	id := newOpaqueID()
	if err := c.store.CreatePACallback(ctx, tx, p.TelegramID(), id, consentAcceptAction(), c.now().Add(ConsentPromptTTL)); err != nil {
		return err
	}
	return c.reply(ctx, tx, u, ReplyConsentPrompt, id)
}

// erasureReply confirms /forget or /consent withdraw, which has already
// run: the deletion itself is never refused, rate-limited or blocked by
// the allowlist. Its confirmation is not free, though. It counts in the
// principal's rate window and is sent only while the window allows it
// (at most RateMessages per window, allowed and refused principals alike),
// then silently dropped, with no rate notice, so a stream of /forget cannot
// flood the outbox or the bot's send rate (#1318 review). Without a limiter
// (no run loop) the confirmation is silent, as the refusal is.
//
// An admission that cannot be read skips only the confirmation: it is
// logged and the erasure still commits, so /forget never depends on
// pa_rate. The admission runs under a savepoint that a failure rolls back,
// because on Postgres a failed statement would otherwise abort the whole
// transaction, the erasure with it.
func (c *Conversations) erasureReply(ctx context.Context, tx *sql.Tx, u VerifiedUpdate, r Reply) error {
	if c.limiter == nil {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT pa_erasure_admit`); err != nil {
		slog.Warn("pa: erasure confirmation skipped", "stage", "savepoint", "err", err)
		return nil
	}
	d, err := c.limiter.AdmitMessage(ctx, tx, u.Principal())
	if err != nil {
		if _, rerr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT pa_erasure_admit`); rerr != nil {
			// The transaction cannot be saved: the update rolls back and
			// Telegram retries it, erasure included.
			return fmt.Errorf("pa: erasure admission: %w (rollback: %v)", err, rerr)
		}
		slog.Warn("pa: erasure confirmation skipped", "stage", "admission", "err", err)
		return nil
	}
	if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT pa_erasure_admit`); err != nil {
		return fmt.Errorf("pa: erasure admission: release: %w", err)
	}
	if !d.Allowed {
		return nil
	}
	return c.reply(ctx, tx, u, r, "")
}

func (c *Conversations) reply(ctx context.Context, tx *sql.Tx, u VerifiedUpdate, r Reply, button string) error {
	if c.replies == nil {
		return nil
	}
	return c.replies.QueueReply(ctx, tx, u.Principal(), u.UpdateID(), r, button)
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
		case CommandNew, CommandForget, CommandConsent, CommandConnect, CommandDisconnect, CommandConnections:
			if len(fields) > 1 {
				arg = strings.ToLower(fields[1])
			}
			return name, arg, true
		}
		return "", "", false
	}
	return "", "", false
}

// erasure reports whether u is /forget or /consent withdraw from the
// principal, which the rate window never blocks.
func erasure(u VerifiedUpdate) bool {
	if u.Kind() != KindMessage {
		return false
	}
	cmd, arg, ok := userCommand(u.Fragments())
	return ok && (cmd == CommandForget || (cmd == CommandConsent && arg == "withdraw"))
}

// utf16Len counts UTF-16 code units, as Telegram does for its limits.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// newOpaqueID returns 128 random bits, base64url: 22 bytes, well within the
// 64-byte callback_data limit, and meaningless outside (principal, id).
func newOpaqueID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+).
	return base64.RawURLEncoding.EncodeToString(b)
}
