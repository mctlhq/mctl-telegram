package bot

import (
	"context"
	"errors"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// KnownChatFunc builds the resolver the registry uses to decide whether an
// update comes from a chat the platform recognises.
//
// A private chat's chat_id is the user's own Telegram id, so an existing
// identity lookup answers the question directly. ErrUserNotFound is the
// ordinary case -- anyone can message a public bot -- and is reported as
// "unknown" rather than as an error, so it is dropped and counted instead of
// logged. ErrTelegramIdentityAmbiguous is deliberately NOT treated as known:
// an id mapping to two users is a data problem, and acting on it would mean
// guessing which account an inbound message belongs to.
func KnownChatFunc(store *db.Store) func(ctx context.Context, chatID int64) (bool, error) {
	return func(ctx context.Context, chatID int64) (bool, error) {
		if chatID <= 0 {
			// Group and channel ids are negative, and 0 is not a chat. The
			// login bot is a 1:1 surface; neither is a chat we know.
			return false, nil
		}
		_, err := store.UserIDByTelegramID(ctx, chatID)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, db.ErrUserNotFound):
			return false, nil
		case errors.Is(err, db.ErrTelegramIdentityAmbiguous):
			return false, nil
		default:
			return false, err
		}
	}
}

// metricsCounter adapts the Prometheus registry to the receiver's Counter.
type metricsCounter struct{ m *metrics.Registry }

// CountUpdate implements Counter.
func (c metricsCounter) CountUpdate(kind, outcome string) {
	if c.m == nil || c.m.BotUpdatesTotal == nil {
		return
	}
	c.m.BotUpdatesTotal.WithLabelValues(kind, outcome).Inc()
}

// NewMetricsCounter returns a Counter backed by the metrics registry, or nil
// when there is no registry.
func NewMetricsCounter(m *metrics.Registry) Counter {
	if m == nil {
		return nil
	}
	return metricsCounter{m: m}
}
