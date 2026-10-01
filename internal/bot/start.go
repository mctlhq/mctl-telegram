package bot

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// reasonBotStart is both the reason_code and the source recorded for a
// reachability observation made from a client-sent /start.
const reasonBotStart = "bot_start"

// StartHandler handles db.KindStartCommand updates. A /start can only reach the
// bot from a user who has started it and not blocked it, and the client sent it
// themselves, so it is reachability evidence without being a probe.
//
// It records reachability through the dispatch transaction and nothing else:
// no notification preference is touched, no message is sent, and no chat id,
// text or payload is logged. The rule itself lives in RecordBotStartTx, which
// the bot-start bridge endpoint calls too.
func StartHandler(store *db.Store) Handler {
	return HandlerFunc(func(ctx context.Context, tx *sql.Tx, d Delivery) (string, error) {
		if !d.ChatID.Valid {
			return db.OutcomeUnknownChat, nil
		}
		return RecordBotStartTx(ctx, store, tx, d.ChatID.Int64, d.UpdateID)
	})
}

// RecordBotStartTx is the one implementation of "a client-sent /start was
// observed": both the long-poll StartHandler and the bot-start bridge endpoint
// (mctl-agent forwards a /start it took off the bot's webhook) call it, so the
// rule cannot drift between the two ingestion paths.
//
// telegramID is the private chat id, which for a private chat is the user's
// Telegram id. updateID must name a row already accepted in bot_updates: its
// received_at is the observation time, so a late /start cannot overwrite a
// newer conclusive observation (see RecordInboundBotReachabilityTx).
//
// An unknown, non-positive or ambiguous Telegram id writes nothing and returns
// OutcomeUnknownChat. Nothing outside client_bot_reachability is written, in
// particular no notification preference: /start is not consent.
func RecordBotStartTx(ctx context.Context, store *db.Store, tx *sql.Tx, telegramID, updateID int64) (string, error) {
	if telegramID <= 0 {
		return db.OutcomeUnknownChat, nil
	}
	userID, err := store.UserIDByTelegramIDTx(ctx, tx, telegramID)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) || errors.Is(err, db.ErrTelegramIdentityAmbiguous) {
			return db.OutcomeUnknownChat, nil
		}
		return "", fmt.Errorf("start: resolve user: %w", err)
	}
	// The observation time is when the update was received, not now: a
	// swept or forwarded /start is dispatched late and must not overwrite a
	// newer conclusive observation (see RecordInboundBotReachabilityTx).
	observedAt, err := store.UpdateReceivedAtTx(ctx, tx, updateID)
	if err != nil {
		return "", fmt.Errorf("start: %w", err)
	}
	outcome := notify.DeliveryOutcome{State: notify.StateReachable, ReasonCode: reasonBotStart, Conclusive: true}
	applied, err := store.RecordInboundBotReachabilityTx(ctx, tx, userID, outcome, reasonBotStart, observedAt)
	if err != nil {
		return "", fmt.Errorf("start: record reachability: %w", err)
	}
	if !applied {
		// The stored observation is newer than this /start (a swept or
		// late-forwarded update): handled, nothing written.
		return db.OutcomeHandled, nil
	}
	return db.OutcomeReachabilityRecorded, nil
}
