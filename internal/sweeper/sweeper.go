// Package sweeper runs periodic maintenance jobs against the store: session
// TTL enforcement, audit-log retention, and refresh-token expiry. All are
// best-effort — the per-request gates remain authoritative — and all log their
// row counts so an operator can observe turnover in Loki without poking the DB.
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
	idleRows, idleErr := store.SweepIdleSessions(ctx)
	if idleErr != nil {
		slog.Warn("idle session sweep failed", "err", idleErr)
	} else if idleRows > 0 {
		slog.Info("session sweep", "reason", "idle_expiry", "revoked_rows", idleRows)
	}

	absRows, absErr := store.SweepAbsoluteSessions(ctx)
	if absErr != nil {
		slog.Warn("absolute session sweep failed", "err", absErr)
	} else if absRows > 0 {
		slog.Info("session sweep", "reason", "absolute_expiry", "revoked_rows", absRows)
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

// RefreshTokenSweeperInterval is how often RefreshTokens() wakes up. Daily is
// plenty — refresh tokens live for weeks, so a missed sweep just leaves expired
// rows in the table ~24h longer; LookupRefreshToken still rejects them.
const RefreshTokenSweeperInterval = 24 * time.Hour

// RefreshTokens runs Store.SweepExpiredRefreshTokens on an interval until ctx
// is cancelled, deleting refresh-token rows past their absolute expiry. Like
// the other sweepers it is best-effort: the per-request LookupRefreshToken
// check is authoritative, so a failed sweep only delays table cleanup.
func RefreshTokens(ctx context.Context, store *db.Store) {
	ticker := time.NewTicker(RefreshTokenSweeperInterval)
	defer ticker.Stop()
	refreshTokenSweepOnce(ctx, store)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshTokenSweepOnce(ctx, store)
		}
	}
}

func refreshTokenSweepOnce(ctx context.Context, store *db.Store) {
	rows, err := store.SweepExpiredRefreshTokens(ctx)
	if err != nil {
		slog.Warn("refresh token sweep failed", "err", err)
		return
	}
	if rows > 0 {
		slog.Info("refresh token sweep", "deleted_rows", rows)
	}
}

// AgentRetentionSweeperInterval is how often AgentRetention() wakes up. Daily
// matches the other retention sweeps; the window is measured in days.
const AgentRetentionSweeperInterval = 24 * time.Hour

// AgentRetention runs Store.SweepAgentMessageBodies on an interval until ctx
// is cancelled, deleting incoming_events and conversation_messages rows older
// than retention. Unlike the other sweepers this one is a privacy control,
// not just table hygiene: the rows carry (encrypted) third-party message
// content that must not accumulate indefinitely. retention <= 0 keeps rows
// forever, matching the audit sweeper convention.
func AgentRetention(ctx context.Context, store *db.Store, retention time.Duration) {
	ticker := time.NewTicker(AgentRetentionSweeperInterval)
	defer ticker.Stop()
	agentRetentionSweepOnce(ctx, store, retention)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			agentRetentionSweepOnce(ctx, store, retention)
		}
	}
}

func agentRetentionSweepOnce(ctx context.Context, store *db.Store, retention time.Duration) {
	rows, err := store.SweepAgentMessageBodies(ctx, retention)
	if err != nil {
		slog.Warn("agent retention sweep failed", "err", err)
		return
	}
	if rows > 0 {
		slog.Info("agent retention sweep", "deleted_rows", rows, "retention", retention)
	}
}
