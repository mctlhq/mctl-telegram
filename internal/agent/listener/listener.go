package listener

import (
	"context"
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
	return a.mgr.Run(ctx, c.API(), a.tgID, updates.AuthOptions{})
}

func (l *Listener) dispatcherFor(acct *account) tg.UpdateDispatcher {
	d := tg.NewUpdateDispatcher()
	d.OnNewMessage(func(ctx context.Context, e tg.Entities, u *tg.UpdateNewMessage) error {
		l.onMessage(ctx, acct, e, u.Message, false)
		return nil
	})
	d.OnEditMessage(func(ctx context.Context, e tg.Entities, u *tg.UpdateEditMessage) error {
		l.onMessage(ctx, acct, e, u.Message, true)
		return nil
	})
	return d
}

func (l *Listener) onMessage(ctx context.Context, acct *account, ents tg.Entities, m tg.MessageClass, isEdit bool) {
	msg, ok := m.(*tg.Message)
	if !ok {
		return
	}
	ex, ok := ExtractMessage(acct.userID, acct.tgID, msg, ents, isEdit)
	if !ok {
		return
	}
	if err := l.persist(ctx, acct, ex); err != nil {
		slog.Warn("agent listener persist failed", "user_id", acct.userID, "kind", ex.Event.Kind, "err", err)
	}
}

func (l *Listener) persist(ctx context.Context, acct *account, ex Extracted) error {
	switch ex.Event.Kind {
	case db.EventKindPrivateMessage, db.EventKindMessageEdit:
		username, displayName := senderIdentityFromMeta(ex.Event.Meta)
		conv, err := l.Store.EnsureConversation(ctx, acct.userID, ex.Event.ChatTGID, username, displayName)
		if err != nil {
			return fmt.Errorf("ensure conversation: %w", err)
		}
		// The listener must never split event persistence from job enqueue.
		// Queue.Ingest commits both rows in one transaction, so a crash cannot
		// leave an event that every redelivery deduplicates without a job.
		if _, _, err := l.Queue.Ingest(ctx, ex.Event, conv.ID); err != nil {
			return fmt.Errorf("ingest event and job: %w", err)
		}
		// Touch duplicates too: if an earlier successful ingest was followed by
		// a transient touch failure, gotd redelivery repairs the timestamp.
		if err := l.Store.TouchConversationIncoming(ctx, acct.userID, conv.ID); err != nil {
			return fmt.Errorf("touch conversation: %w", err)
		}
		return nil
	}

	// Owner-outgoing and Saved Messages events are durable audit/control events
	// but do not create agent jobs.
	_, inserted, err := l.Store.InsertIncomingEvent(ctx, ex.Event)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	if !inserted {
		return nil
	}
	if l.Metrics != nil {
		l.Metrics.AgentEventsReceivedTotal.WithLabelValues(ex.Event.Kind).Inc()
	}

	switch ex.Event.Kind {
	case db.EventKindOwnerOutgoing:
		conv, err := l.Store.GetConversationByPeer(ctx, acct.userID, ex.Event.ChatTGID)
		if err != nil {
			if err == db.ErrConversationNotFound {
				return nil
			}
			return fmt.Errorf("lookup conversation for takeover: %w", err)
		}
		if err := l.Store.SetConversationState(ctx, acct.userID, conv.ID, db.ConversationTakenOver); err != nil {
			return fmt.Errorf("set taken over: %w", err)
		}
	case db.EventKindSavedCommand:
		if l.Router != nil && ex.SavedCommandText != "" {
			if err := l.Router.HandleSavedText(ctx, acct.userID, ex.SavedCommandText); err != nil {
				slog.Warn("saved command routing failed", "user_id", acct.userID, "err", err)
			}
		}
	}
	return nil
}
