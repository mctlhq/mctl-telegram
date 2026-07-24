package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/updates"
	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

const sentMarkerTTL = 2 * time.Minute

type account struct {
	userID int64
	tgID   int64
	mgr    *updates.Manager
}

type sentMessageKey struct {
	userID    int64
	messageID int64
}

type CommandRouter interface {
	HandleSavedText(ctx context.Context, userID int64, text string) error
}

type Listener struct {
	Store   *db.Store
	Queue   *queue.Queue
	Router  CommandRouter
	Metrics *metrics.Registry

	mu       sync.Mutex
	accounts map[int64]*account
	// sentMessages correlates server-assigned Telegram message ids returned by
	// programmatic sends with their outgoing update echoes. Entries are consumed
	// once and expire defensively so a missed echo cannot suppress a future
	// human message if Telegram eventually reuses an id after a session reset.
	sentMessages sync.Map // sentMessageKey -> time.Time
}

func New(store *db.Store, q *queue.Queue, router CommandRouter, m *metrics.Registry) *Listener {
	return &Listener{Store: store, Queue: q, Router: router, Metrics: m, accounts: make(map[int64]*account)}
}

// MarkSent implements telegram.AgentSentMarker. SendMessage calls it after
// Telegram assigns the message id and before returning to the tool handler.
func (l *Listener) MarkSent(userID, messageID int64) {
	if userID <= 0 || messageID <= 0 {
		return
	}
	l.sentMessages.Store(sentMessageKey{userID: userID, messageID: messageID}, time.Now())
}

func (l *Listener) consumeSent(userID, messageID int64) bool {
	key := sentMessageKey{userID: userID, messageID: messageID}
	v, ok := l.sentMessages.LoadAndDelete(key)
	if !ok {
		return false
	}
	markedAt, ok := v.(time.Time)
	return ok && time.Since(markedAt) <= sentMarkerTTL
}

func (l *Listener) SetAccount(userID, tgID int64) bool {
	if tgID == 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if a, ok := l.accounts[userID]; ok && a.tgID == tgID {
		return true
	}
	acct := &account{userID: userID, tgID: tgID}
	acct.mgr = updates.New(updates.Config{
		Handler:      l.dispatcherFor(acct),
		Storage:      &telegram.UpdateStateStore{UserID: userID, Store: l.Store},
		AccessHasher: &telegram.UpdateStateStore{UserID: userID, Store: l.Store},
	})
	l.accounts[userID] = acct
	return true
}

func (l *Listener) RemoveAccount(userID int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.accounts, userID)
}

func (l *Listener) ActiveUserIDs() []int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	ids := make([]int64, 0, len(l.accounts))
	for id := range l.accounts {
		ids = append(ids, id)
	}
	return ids
}

func (l *Listener) get(userID int64) (*account, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.accounts[userID]
	return a, ok
}

func (l *Listener) HandlerFor(userID int64) gotdtelegram.UpdateHandler {
	a, ok := l.get(userID)
	if !ok {
		return nil
	}
	return a.mgr
}

func (l *Listener) RunFor(ctx context.Context, userID int64, c *gotdtelegram.Client) error {
	a, ok := l.get(userID)
	if !ok {
		<-ctx.Done()
		return ctx.Err()
	}
	// updates.Manager retains its internal state after Run exits and rejects a
	// second Run as "already authorized". Pool reconnects invoke RunFor again on
	// the same account, so clear only the in-memory runtime state first; the DB
	// watermark remains intact and is reloaded by Run for gap recovery.
	a.mgr.Reset()
	return a.mgr.Run(ctx, c.API(), a.tgID, updates.AuthOptions{})
}

func (l *Listener) dispatcherFor(acct *account) tg.UpdateDispatcher {
	d := tg.NewUpdateDispatcher()
	d.OnNewMessage(func(ctx context.Context, e tg.Entities, u *tg.UpdateNewMessage) error {
		return l.onMessage(ctx, acct, e, u.Message, false)
	})
	d.OnEditMessage(func(ctx context.Context, e tg.Entities, u *tg.UpdateEditMessage) error {
		return l.onMessage(ctx, acct, e, u.Message, true)
	})
	return d
}

// onMessage returns persistence failures to updates.Manager. A nil return tells
// gotd it may advance PTS/seq, so swallowing a DB error here would permanently
// acknowledge and lose the update. Returning the error stops the manager; the
// supervisor reconnects and getDifference retries from the stored watermark.
func (l *Listener) onMessage(ctx context.Context, acct *account, ents tg.Entities, m tg.MessageClass, isEdit bool) error {
	msg, ok := m.(*tg.Message)
	if !ok {
		return nil
	}
	// Programmatic sends made through telegram.SendMessage are echoed back as
	// ordinary Out messages on the same user session. Consume their marker before
	// extraction so only a genuinely human outgoing message triggers takeover.
	if msg.Out && l.consumeSent(acct.userID, int64(msg.ID)) {
		return nil
	}
	ex, ok := ExtractMessage(acct.userID, acct.tgID, msg, ents, isEdit)
	if !ok {
		return nil
	}
	if err := l.persist(ctx, acct, ex); err != nil {
		slog.Warn("agent listener persist failed", "user_id", acct.userID, "kind", ex.Event.Kind, "err", err)
		return err
	}
	return nil
}

func (l *Listener) persist(ctx context.Context, acct *account, ex Extracted) error {
	switch ex.Event.Kind {
	case db.EventKindPrivateMessage, db.EventKindMessageEdit:
		username, displayName := senderIdentityFromMeta(ex.Event.Meta)
		conv, err := l.Store.EnsureConversation(ctx, acct.userID, ex.Event.ChatTGID, username, displayName)
		if err != nil {
			return fmt.Errorf("ensure conversation: %w", err)
		}
		// A no-op when ex.SenderAccessHash is 0 (see the method's doc
		// comment) — every inbound message from a peer we can still resolve
		// carries a usable hash, so this reaches a working value within one
		// exchange even for a conversation that predates this fix.
		if err := l.Store.SetConversationPeerAccessHash(ctx, acct.userID, ex.Event.ChatTGID, ex.SenderAccessHash); err != nil {
			return fmt.Errorf("set conversation peer access hash: %w", err)
		}
		if ex.Event.Kind == db.EventKindMessageEdit {
			// gotd delivers updates at least once — the SAME edit can arrive
			// again later (a reconnect/gap-recovery replay), and Queue.Ingest
			// already treats that redelivery as a no-op via its unique
			// event_id constraint. But this deny call has no such dedup of
			// its own: a Codex finding on #307 caught that a redelivered
			// edit re-runs DenyPendingActionsForConversation, which would
			// deny the FRESH, correctly-edited proposal the FIRST delivery's
			// job already produced — while the redelivered Ingest is a
			// no-op and creates nothing to replace it, leaving the
			// conversation with no valid pending action at all. Checking
			// whether this exact event_id was already ingested — the same
			// idempotency check EventKindOwnerOutgoing below already uses —
			// makes the whole block (deny + ingest) a no-op together on a
			// redelivery, not just the ingest half.
			if _, err := l.Store.GetIncomingEvent(ctx, acct.userID, ex.Event.EventID); err == nil {
				return nil
			} else if !errors.Is(err, db.ErrIncomingEventNotFound) {
				return fmt.Errorf("check existing edit event: %w", err)
			}
			// Must run BEFORE Queue.Ingest below, not after: Ingest publishes
			// the new job as immediately claimable, and Ingest/this deny are
			// two separate transactions, not one atomic unit. Denying AFTER
			// publishing left a window where a poller could claim that job,
			// propose a fresh (correctly-edited) reply, and have this same
			// deny call catch that brand-new action too — ordering, not a
			// synchronization primitive, is what closes the window. A draft
			// the agent already proposed from the pre-edit text must not go
			// out unchanged — deny it and let the new job (enqueued below,
			// carrying the edited event under its own :e<ts> event id)
			// produce a fresh proposal from the current text. Actions
			// already `executing` are left alone by design (see
			// DenyPendingActionsForConversation) — deliberately not treated
			// as an error here: a message edit racing an in-flight send is
			// expected, not exceptional.
			if _, err := l.Store.DenyPendingActionsForConversation(ctx, acct.userID, conv.ID,
				"source message edited"); err != nil {
				return fmt.Errorf("deny actions for edited message: %w", err)
			}
		}
		// Queue.Ingest atomically commits the event, job, and conversation's
		// last_incoming_at timestamp. Duplicate gotd redeliveries are a no-op and
		// therefore cannot make an old conversation look newly active.
		if _, _, err := l.Queue.Ingest(ctx, ex.Event, conv.ID); err != nil {
			return fmt.Errorf("ingest event and job: %w", err)
		}
		return nil

	case db.EventKindOwnerOutgoing:
		// Apply takeover before writing the audit event. Both operations are
		// idempotent; a crash between them causes redelivery and another state
		// write rather than leaving a committed event that suppresses takeover.
		if _, err := l.Store.GetIncomingEvent(ctx, acct.userID, ex.Event.EventID); err == nil {
			return nil
		} else if !errors.Is(err, db.ErrIncomingEventNotFound) {
			return fmt.Errorf("check owner event: %w", err)
		}
		conv, err := l.Store.GetConversationByPeer(ctx, acct.userID, ex.Event.ChatTGID)
		if err != nil && !errors.Is(err, db.ErrConversationNotFound) {
			return fmt.Errorf("lookup conversation for takeover: %w", err)
		}
		if err == nil {
			if err := l.Store.SetConversationState(ctx, acct.userID, conv.ID, db.ConversationTakenOver); err != nil {
				return fmt.Errorf("set taken over: %w", err)
			}
			// control.Router.handleTakeover (the explicit /mctl takeover
			// command) has always denied pending actions in the same breath
			// as the state transition — this automatically-detected
			// takeover path (the owner just replying directly, without
			// typing a command) did not, which a Codex finding on #307
			// caught as a real race: executor.send reads the conversation
			// and evaluates policy, then performs a separate approved→
			// executing CAS a few lines later; if this DenyPendingActionsFor-
			// Conversation call had never run at all, that CAS could land in
			// the gap and still succeed, sending the agent's reply on top of
			// the owner's own message. Calling it here closes that gap the
			// same way handleTakeover's does: the CAS and this UPDATE
			// contend on the SAME row's status column, so whichever commits
			// first wins and the other's WHERE clause simply stops matching
			// — ordinary optimistic concurrency, no new locking primitive
			// needed. Best-effort like handleTakeover's isn't (that one
			// propagates the error) — but here a failure must not block
			// insertAuditEvent below from ever running, or this idempotent
			// dedup check would keep re-attempting the same takeover
			// detection forever.
			if _, err := l.Store.DenyPendingActionsForConversation(ctx, acct.userID, conv.ID, "owner sent a message directly"); err != nil {
				slog.Warn("agent listener: deny pending actions on auto-detected takeover failed", "user_id", acct.userID, "conversation_id", conv.ID, "err", err)
			}
		}
		return l.insertAuditEvent(ctx, ex.Event)

	case db.EventKindSavedCommand:
		// Commands are delivered at-least-once. We first check the audit dedup
		// row, then execute the idempotent router, then persist the audit row.
		// A crash after routing but before the insert may repeat a command, but a
		// crash can no longer silently lose it. Control handlers must therefore
		// remain idempotent (approve/pause/continue/status already are).
		if _, err := l.Store.GetIncomingEvent(ctx, acct.userID, ex.Event.EventID); err == nil {
			return nil
		} else if !errors.Is(err, db.ErrIncomingEventNotFound) {
			return fmt.Errorf("check saved command event: %w", err)
		}
		if l.Router != nil && ex.SavedCommandText != "" {
			if err := l.Router.HandleSavedText(ctx, acct.userID, ex.SavedCommandText); err != nil {
				return fmt.Errorf("route saved command: %w", err)
			}
		}
		return l.insertAuditEvent(ctx, ex.Event)
	}
	return nil
}

func (l *Listener) insertAuditEvent(ctx context.Context, ev db.IncomingEvent) error {
	_, inserted, err := l.Store.InsertIncomingEvent(ctx, ev)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	if inserted && l.Metrics != nil {
		l.Metrics.AgentEventsReceivedTotal.WithLabelValues(ev.Kind).Inc()
	}
	return nil
}
