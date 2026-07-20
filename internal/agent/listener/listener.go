package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/updates"
	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

type account struct {
	userID int64
	tgID   int64
	mgr    *updates.Manager
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
}

func New(store *db.Store, q *queue.Queue, router CommandRouter, m *metrics.Registry) *Listener {
	return &Listener{Store: store, Queue: q, Router: router, Metrics: m, accounts: make(map[int64]*account)}
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
		// Queue.Ingest commits event + job together. If the touch below fails,
		// returning an error causes redelivery; the duplicate ingest is a no-op
		// and the touch is retried, repairing the timestamp.
		if _, _, err := l.Queue.Ingest(ctx, ex.Event, conv.ID); err != nil {
			return fmt.Errorf("ingest event and job: %w", err)
		}
		if err := l.Store.TouchConversationIncoming(ctx, acct.userID, conv.ID); err != nil {
			return fmt.Errorf("touch conversation: %w", err)
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
