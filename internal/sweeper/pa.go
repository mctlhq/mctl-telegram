package sweeper

import (
	"context"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// PAStateSweeperInterval is how often PAState() wakes up. Conversations live
// at most 24 hours from creation, so an hourly sweep keeps the real lifetime
// within TTL + 1h. Loading an expired conversation is refused on the request
// path regardless (LoadPAFragments checks expires_at), so the sweep is the
// hard delete, not the gate.
const PAStateSweeperInterval = time.Hour

// PAState hard-deletes Personal Assistant state past its lifetime until ctx
// is cancelled: expired or closed conversations with their fragments,
// expired callback ids, pa_updates dedup rows older than
// pa.UpdatesRetention (issue #1313, owner decision 2026-11-18), and linking
// secrets past db.PALinkSecretRetention after their expiry (#1338). It is
// started only when PA_ENABLED is true.
func PAState(ctx context.Context, store convo.Store) {
	ticker := time.NewTicker(PAStateSweeperInterval)
	defer ticker.Stop()
	PAStateSweepOnce(ctx, store, time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			PAStateSweepOnce(ctx, store, time.Now())
		}
	}
}

// PAStateSweepOnce runs one pass at now. Exported for the server's tests.
func PAStateSweepOnce(ctx context.Context, store convo.Store, now time.Time) {
	r, err := store.SweepPAState(ctx, now, now.Add(-pa.UpdatesRetention))
	if err != nil {
		slog.Warn("pa state sweep failed", "err", err)
		return
	}
	if r != (convo.SweepResult{}) {
		slog.Info("pa state sweep", "conversations", r.Conversations, "fragments", r.Fragments,
			"callbacks", r.Callbacks, "updates", r.Updates, "link_secrets", r.LinkSecrets)
	}
}
