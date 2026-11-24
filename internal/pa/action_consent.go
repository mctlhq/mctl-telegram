package pa

// action_consent.go is the conversation layer's half of the consent to
// actions (#1320 slice P2-S14c; owner decision 2026-11-21).
//
// The consent to actions (convo.ActionConsentVersion) is a second record
// next to the data-flow consent. It is asked for only while
// PA_WRITES_ENABLED reads on, and only when the principal turns to
// actions: /permissions, or /consent once the data-flow consent is given.
// It is never asked on an ordinary message. A principal with the data-flow
// consent alone keeps every read and gets no write tool, no approval card
// and no standing permission.
//
// With writes off, or a switch that cannot be read, nothing here is
// reachable: no prompt is queued and every answer of the conversation
// layer is what it was before this file.
//
// Accepting is recorded only from the button of a prompt, bound to the
// version and the hash of the text that prompt showed, exactly as the
// data-flow consent is (T13, S1-N3). /consent withdraw withdraws both
// (db.WithdrawPAConsent). Turning writes off later leaves an acceptance
// in place; changing the text needs a new version, and every record of
// the old one then stops satisfying convo.ActionsSatisfied.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// The replies of the consent to actions.
const (
	ReplyActionConsentPrompt   Reply = "action_consent_prompt"
	ReplyActionConsentPromptRU Reply = "action_consent_prompt_ru"
	ReplyActionConsentAccepted Reply = "action_consent_accepted"
)

// actionConsentAcceptPrefix starts the stored action of an action-consent
// button. It is not a prefix of consentAcceptPrefix, nor that of it.
const actionConsentAcceptPrefix = "actions_accept:"

func actionConsentAcceptAction(ru bool) string {
	return actionConsentAcceptPrefix + convo.ActionConsentVersion + ":" + convo.ActionConsentTextSHA256For(ru)
}

// Errors of the action-consent check.
var (
	// ErrActionConsentRequired: no consent to actions, a withdrawn one, or
	// one to another version or text.
	ErrActionConsentRequired = errors.New("pa: consent to the current actions text is required")
	// ErrActionConsentUnreadable: the record could not be read. It is
	// never treated as consent, nor as its absence.
	ErrActionConsentUnreadable = errors.New("pa: action consent record unreadable")
)

// ActionConsentReader reads the consent to actions (*db.Store).
type ActionConsentReader interface {
	GetPAActionConsent(ctx context.Context, tx *sql.Tx, principal int64) (convo.ConsentRecord, error)
}

// RequireActionConsent returns nil when principal has consented to the
// current actions text, ErrActionConsentRequired when it has not, and
// ErrActionConsentUnreadable when that could not be read. Every place that
// offers, shows, grants or sends an action asks it in its own transaction.
func RequireActionConsent(ctx context.Context, tx *sql.Tx, store ActionConsentReader, principal int64) error {
	if store == nil || tx == nil || principal <= 0 {
		return fmt.Errorf("%w: no store, transaction or principal", ErrActionConsentUnreadable)
	}
	rec, err := store.GetPAActionConsent(ctx, tx, principal)
	switch {
	case errors.Is(err, convo.ErrNotFound):
		return ErrActionConsentRequired
	case err != nil:
		return fmt.Errorf("%w: %v", ErrActionConsentUnreadable, err)
	case !convo.ActionsSatisfied(rec):
		return ErrActionConsentRequired
	}
	return nil
}

// actionsOn reports whether PA_WRITES_ENABLED reads on for the
// conversation layer. Not wired or unreadable is off.
func (c *Conversations) actionsOn() bool {
	return writesOn(c.writes)
}

// promptActions queues the action-consent prompt with a button bound to
// the current version and to the text the prompt shows: Russian when the
// update's client is in Russian, else English, fixed here with the binding
// as prompt does for the data-flow consent.
func (c *Conversations) promptActions(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	p := u.Principal()
	ru := safetext.LangOf(u.LanguageCode()) == safetext.LangRU
	id := newOpaqueID()
	if err := c.store.CreatePACallback(ctx, tx, p.TelegramID(), id, actionConsentAcceptAction(ru), c.now().Add(ConsentPromptTTL)); err != nil {
		return err
	}
	r := ReplyActionConsentPrompt
	if ru {
		r = ReplyActionConsentPromptRU
	}
	return c.reply(ctx, tx, u, r, id)
}

// consentCommand answers /consent with anything but "withdraw". With
// writes off it is the data-flow prompt, as before. With writes on, a
// principal whose data-flow consent is current and whose consent to
// actions is not is shown the actions text; everyone else the data-flow
// text. A record that cannot be read fails the update.
func (c *Conversations) consentCommand(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	if !c.actionsOn() {
		return c.prompt(ctx, tx, u)
	}
	_, err := c.requireConsent(ctx, tx, u.Principal())
	if errors.Is(err, ErrConsentRequired) {
		return c.prompt(ctx, tx, u)
	}
	if err != nil {
		return err
	}
	err = RequireActionConsent(ctx, tx, c.store, u.Principal().TelegramID())
	if errors.Is(err, ErrActionConsentRequired) {
		return c.promptActions(ctx, tx, u)
	}
	if err != nil {
		return err
	}
	return c.prompt(ctx, tx, u)
}

// actionConsentButton handles a pressed action-consent button whose
// callback id was just consumed for the principal who pressed. The
// data-flow consent comes first: without it the principal is asked for
// that, and nothing is recorded. A button of an earlier text records
// nothing either (S1-N3).
//
// The press is honoured with writes off as well: the prompt was shown
// while they were on, and an acceptance outlives the switch.
func (c *Conversations) actionConsentButton(ctx context.Context, tx *sql.Tx, u VerifiedUpdate, action string) error {
	_, err := c.requireConsent(ctx, tx, u.Principal())
	if errors.Is(err, ErrConsentRequired) {
		return c.prompt(ctx, tx, u)
	}
	if err != nil {
		return err
	}
	var textSHA string
	switch action {
	case actionConsentAcceptAction(false):
		textSHA = convo.ActionConsentTextSHA256For(false)
	case actionConsentAcceptAction(true):
		textSHA = convo.ActionConsentTextSHA256For(true)
	default:
		// The text changed after the prompt was shown: ask again, while
		// there is still something to ask for.
		if err := c.reply(ctx, tx, u, ReplyConsentStale, ""); err != nil {
			return err
		}
		if !c.actionsOn() {
			return nil
		}
		return c.promptActions(ctx, tx, u)
	}
	if err := c.store.AcceptPAActionConsent(ctx, tx, u.Principal().TelegramID(), convo.ActionConsentVersion, textSHA, c.now()); err != nil {
		return err
	}
	return c.reply(ctx, tx, u, ReplyActionConsentAccepted, "")
}

// isActionConsentAction reports whether a stored callback action is an
// action-consent button's.
func isActionConsentAction(action string) bool {
	return strings.HasPrefix(action, actionConsentAcceptPrefix)
}

// WithheldReason says why a claim carries no write tool for a connection.
type WithheldReason string

const (
	// WithheldNone: nothing was withheld for consent or scope.
	WithheldNone WithheldReason = ""
	// WithheldWritesOff: PA_WRITES_ENABLED is off or could not be read.
	WithheldWritesOff WithheldReason = "writes_off"
	// WithheldConsent: the principal has not consented to actions.
	WithheldConsent WithheldReason = "action_consent"
	// WithheldScope: the connection holds no write scope (it was made
	// for reading, or the service narrowed the grant).
	WithheldScope WithheldReason = "write_scope"
)

// ActionStore is what ActionGate reads and writes (*db.Store).
type ActionStore interface {
	ActionConsentReader
	LockPAConnection(ctx context.Context, tx *sql.Tx, principal int64, id string) (connection.Connection, error)
	EnqueuePAOutbox(ctx context.Context, tx *sql.Tx, item jobs.OutboxItem, now time.Time) error
}

// ActionGate decides which write tools a claim may carry for one
// connection of a principal: none unless writes are on, the principal has
// consented to actions, and the connection holds the tool's scope. It is
// the seam the tool resolver uses when it starts to offer approve-tier
// tools (#1323); the card emitter, the write executor and /permissions
// make the same checks themselves and do not rely on what a claim held.
type ActionGate struct {
	store  ActionStore
	scopes connection.WriteScopes
	writes WritesSwitch
}

// NewActionGate builds the gate. scopes is the table of write tools and
// their scopes; nil is the compiled one (connection.DefaultWriteScopes).
func NewActionGate(store ActionStore, writes WritesSwitch, scopes *connection.WriteScopes) (*ActionGate, error) {
	if store == nil || writes == nil {
		return nil, errors.New("pa: action gate needs a store and the writes switch")
	}
	g := &ActionGate{store: store, writes: writes, scopes: connection.DefaultWriteScopes()}
	if scopes != nil {
		g.scopes = *scopes
	}
	return g, nil
}

// Offer returns the write tools of tools that a claim may carry for
// connectionID, in tx under the principal's lock, and why the others were
// left out. The checks run in the order a principal can act on them:
// the switch, the consent, the scope. Any failed read is an error and
// offers nothing; a connection that is not the principal's, or is not
// active, holds nothing.
func (g *ActionGate) Offer(ctx context.Context, tx *sql.Tx, principal int64, connectionID string, tools []string) ([]string, WithheldReason, error) {
	if len(tools) == 0 {
		return nil, WithheldNone, nil
	}
	if !writesOn(g.writes) {
		return nil, WithheldWritesOff, nil
	}
	err := RequireActionConsent(ctx, tx, g.store, principal)
	if errors.Is(err, ErrActionConsentRequired) {
		return nil, WithheldConsent, nil
	}
	if err != nil {
		return nil, WithheldConsent, err
	}
	conn, err := g.store.LockPAConnection(ctx, tx, principal, connectionID)
	if errors.Is(err, connection.ErrNotFound) {
		return nil, WithheldScope, nil
	}
	if err != nil {
		return nil, WithheldScope, fmt.Errorf("pa: action gate: connection: %w", err)
	}
	if conn.Principal != principal || conn.ID != connectionID || conn.State != connection.StateActive {
		return nil, WithheldScope, nil
	}
	var out []string
	for _, tool := range tools {
		if g.scopes.Holds(conn, tool) {
			out = append(out, tool)
		}
	}
	slices.Sort(out)
	if len(out) < len(tools) {
		return out, WithheldScope, nil
	}
	return out, WithheldNone, nil
}

// Notify queues, in tx, the fixed notice that matches why an action on
// connectionID was withheld: the consent to actions is missing, or the
// service must be connected again. The row is connection-level, so the
// principal gets each notice once per connection however often it is
// queued. Any other reason queues nothing.
func (g *ActionGate) Notify(ctx context.Context, tx *sql.Tx, principal int64, connectionID string, why WithheldReason, now time.Time) error {
	kind, ok := WithheldNotice(why)
	if !ok {
		return nil
	}
	return g.store.EnqueuePAOutbox(ctx, tx, jobs.OutboxItem{Principal: principal, Kind: kind, ConnectionID: connectionID}, now)
}

// WithheldNotice is the once-per-connection outbox kind for why.
func WithheldNotice(why WithheldReason) (jobs.OutboxKind, bool) {
	switch why {
	case WithheldConsent:
		return jobs.OutboxActionConsentNeeded, true
	case WithheldScope:
		return jobs.OutboxWriteScopeNeeded, true
	}
	return "", false
}
