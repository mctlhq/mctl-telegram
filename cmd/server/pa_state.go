package main

import (
	"context"
	"log/slog"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/sweeper"
)

// startPAState is the enable-time half of the PA conversation state (issue
// #1313 slice b). With PA_ENABLED off it does nothing at all. With it on it
// first deletes every fragment without a provenance mark (threat model T5:
// "state created before provenance marks existed is deleted when the PA is
// enabled") and only then starts the retention sweeper. A failed purge is
// returned so the server refuses to start rather than run beside unmarked
// state; the loader refuses such rows anyway, this makes them gone.
func startPAState(ctx context.Context, cfg *config.Config, store convo.Store) (bool, error) {
	if !cfg.PAEnabled {
		return false, nil
	}
	n, err := store.PurgeUnmarkedPAState(ctx)
	if err != nil {
		return false, err
	}
	if n > 0 {
		slog.Warn("pa state: purged unmarked fragments", "rows", n)
	}
	go sweeper.PAState(ctx, store)
	return true, nil
}
