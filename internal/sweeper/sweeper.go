// Package sweeper runs periodic maintenance jobs against the store. Today
// the only sweeper is for session TTL (idle + absolute); audit-log retention
// will land alongside M2.5.
package sweeper

import (
	"context"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// SessionSweeperInterval is how often Sessions() wakes up. One hour is fine
// granularity for 30-day idle / 90-day absolute TTLs and keeps the DB query
// rate negligible.
const SessionSweeperInterval = time.Hour

// Sessions runs Store.SweepExpiredSessions on an interval until ctx is
// cancelled. Logs the row count at info level so an operator can see TTL
// turnover in Loki without digging through the DB.
//
// The sweeper is best-effort: a query error logs and the loop continues —
// CheckSessionValid on the request path is the authoritative gate, so a
// missed sweep just means an expired row sits in storage a bit longer
// before the next per-request check flips it.
func Sessions(ctx context.Context, store *db.Store) {
	ticker := time.NewTicker(SessionSweeperInterval)
	defer ticker.Stop()
	// Run once immediately so a freshly-started pod doesn't wait an hour
	// before clearing any sessions that expired while we were down.
	sweepOnce(ctx, store)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepOnce(ctx, store)
		}
	}
}

func sweepOnce(ctx context.Context, store *db.Store) {
	rows, err := store.SweepExpiredSessions(ctx)
	if err != nil {
		slog.Warn("session sweep failed", "err", err)
		return
	}
	if rows > 0 {
		slog.Info("session sweep", "revoked_rows", rows)
	}
}
