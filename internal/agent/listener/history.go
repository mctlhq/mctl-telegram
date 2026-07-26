package listener

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

type savedHistoryAPI interface {
	MessagesGetHistory(context.Context, *tg.MessagesGetHistoryRequest) (tg.MessagesMessagesClass, error)
}

func (l *Listener) runSavedHistoryPoller(ctx context.Context, acct *account, api savedHistoryAPI) {
	poll := func() {
		if err := l.pollSavedHistory(ctx, acct, api); err != nil && ctx.Err() == nil {
			// History RPC, FloodWait, and persistence/router failures are all
			// retried on a later tick. They must not tear down updates.Manager
			// or the same pinned client's inbound-DM path.
			slog.Warn("agent saved command history poll failed", "user_id", acct.userID, "err", err)
		}
	}

	poll()
	ticker := time.NewTicker(savedHistoryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

func (l *Listener) pollSavedHistory(ctx context.Context, acct *account, api savedHistoryAPI) error {
	cursor, found, err := l.Store.GetSavedCommandCursor(ctx, acct.userID)
	if err != nil {
		return err
	}
	if !found {
		return l.initializeSavedHistoryCursor(ctx, acct, api)
	}

	history, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
		Peer:      &tg.InputPeerSelf{},
		OffsetID:  int(cursor),
		AddOffset: -savedHistoryLimit,
		Limit:     savedHistoryLimit,
		MinID:     int(cursor),
	})
	if err != nil {
		return fmt.Errorf("get Saved Messages history: %w", err)
	}
	messages := historyMessages(history)
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].GetID() < messages[j].GetID()
	})

	for _, raw := range messages {
		messageID := int64(raw.GetID())
		if messageID <= cursor {
			continue
		}
		msg, ok := raw.(*tg.Message)
		if ok {
			// Do not gate this on msg.Out: unlike the live push path,
			// messages.getHistory against Peer: InputPeerSelf does not
			// reliably set it (see ExtractSavedHistoryMessage's doc comment).
			// consumeSent's own lookup is keyed by message id, not Out, so
			// dropping the guard here only widens which ids get checked --
			// harmless, since a ordinary (non-agent-sent) id is simply not
			// found in the marker store.
			if l.consumeSent(ctx, acct.userID, messageID) {
				if err := l.Store.AdvanceSavedCommandCursor(ctx, acct.userID, messageID); err != nil {
					return err
				}
				cursor = messageID
				continue
			}
			if ex, relevant := ExtractSavedHistoryMessage(acct.userID, acct.tgID, msg); relevant &&
				ex.Event.Kind == db.EventKindSavedCommand {
				if err := l.persistExtracted(ctx, acct, ex); err != nil {
					// Do not cross a command that did not finish routing. The
					// same message remains eligible on the next tick.
					return err
				}
			}
		}
		// Notes, notifications, forwards, media-only/service messages, and
		// messages that do not belong to the primary self dialog are ignored
		// but still advance the durable watermark.
		if err := l.Store.AdvanceSavedCommandCursor(ctx, acct.userID, messageID); err != nil {
			return err
		}
		cursor = messageID
	}
	return nil
}

func (l *Listener) initializeSavedHistoryCursor(ctx context.Context, acct *account, api savedHistoryAPI) error {
	history, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
		Peer:  &tg.InputPeerSelf{},
		Limit: 1,
	})
	if err != nil {
		return fmt.Errorf("get Saved Messages baseline: %w", err)
	}
	var latest int64
	for _, message := range historyMessages(history) {
		if id := int64(message.GetID()); id > latest {
			latest = id
		}
	}
	if err := l.Store.AdvanceSavedCommandCursor(ctx, acct.userID, latest); err != nil {
		return fmt.Errorf("save Saved Messages baseline: %w", err)
	}
	return nil
}

func historyMessages(history tg.MessagesMessagesClass) []tg.MessageClass {
	if history == nil {
		return nil
	}
	modified, ok := history.AsModified()
	if !ok {
		return nil
	}
	return modified.GetMessages()
}
