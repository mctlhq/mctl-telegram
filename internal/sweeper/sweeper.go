// Package sweeper runs periodic maintenance jobs against the store: session
// TTL enforcement and audit-log retention. Both are best-effort — the
// per-request gates remain authoritative — and both log their row counts so
// an operator can observe turnover in Loki without poking the DB.
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

// AuditSweeperInterval is how often AuditLog() wakes up. Daily is plenty —
// the retention window is measured in days, so a missed sweep just leaves a
// handful of rows around for ~24h longer than promised.
const AuditSweeperInterval = 24 * time.Hour

// AuditLog runs Store.SweepAuditLog on an interval until ctx is cancelled.
// retention is the maximum age of a row before it's deleted; values <= 0
// (e.g. AUDIT_RETENTION_DAYS=0) are treated as "keep forever" and the
// sweep becomes a no-op without disabling the goroutine — keeps the
// operator-facing config simple.
func AuditLog(ctx context.Context, store *db.Store, retention time.Duration) {
	ticker := time.NewTicker(AuditSweeperInterval)
	defer ticker.Stop()
	auditSweepOnce(ctx, store, retention)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			auditSweepOnce(ctx, store, retention)
		}
	}
}

func auditSweepOnce(ctx context.Context, store *db.Store, retention time.Duration) {
	rows, err := store.SweepAuditLog(ctx, retention)
	if err != nil {
		slog.Warn("audit sweep failed", "err", err)
		return
	}
	if rows > 0 {
		slog.Info("audit sweep", "deleted_rows", rows, "retention", retention)
	}
}
