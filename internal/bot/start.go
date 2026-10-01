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
// text or payload is logged.
func StartHandler(store *db.Store) Handler {
	return HandlerFunc(func(ctx context.Context, tx *sql.Tx, d Delivery) (string, error) {
		if !d.ChatID.Valid || d.ChatID.Int64 <= 0 {
			return db.OutcomeUnknownChat, nil
		}
		userID, err := store.UserIDByTelegramIDTx(ctx, tx, d.ChatID.Int64)
		if err != nil {
			if errors.Is(err, db.ErrUserNotFound) || errors.Is(err, db.ErrTelegramIdentityAmbiguous) {
				return db.OutcomeUnknownChat, nil
			}
			return "", fmt.Errorf("start: resolve user: %w", err)
		}
		// The observation time is when the update was received, not now: a
		// swept /start is dispatched late and must not overwrite a newer
		// conclusive observation (see RecordInboundBotReachabilityTx).
		observedAt, err := store.UpdateReceivedAtTx(ctx, tx, d.UpdateID)
		if err != nil {
			return "", fmt.Errorf("start: %w", err)
		}
		outcome := notify.DeliveryOutcome{State: notify.StateReachable, ReasonCode: reasonBotStart, Conclusive: true}
		applied, err := store.RecordInboundBotReachabilityTx(ctx, tx, userID, outcome, reasonBotStart, observedAt)
		if err != nil {
			return "", fmt.Errorf("start: record reachability: %w", err)
		}
		if !applied {
			// The stored observation is newer than this /start (a swept,
			// late-dispatched update): handled, nothing written.
			return db.OutcomeHandled, nil
		}
		return db.OutcomeReachabilityRecorded, nil
	})
}
