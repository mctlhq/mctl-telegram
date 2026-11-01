package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// StatsSnapshot is one sample of the public usage numbers, as rendered into
// the landing page and served by GET /api/stats. Every field is an aggregate
// over the whole deployment; nothing in it names a user, a peer or a message.
type StatsSnapshot struct {
	AccountsTotal     int64     `json:"accounts_total"`
	ToolCallsTotal    int64     `json:"tool_calls_total"`
	ActiveUsers30d    int64     `json:"active_users_30d"`
	SessionsConnected int64     `json:"sessions_connected"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// StatsCache holds the most recent successful StatsSnapshot. It starts empty
// and stays empty until the first sample succeeds: a page or endpoint that
// reads it before then gets ok=false and must hide the numbers, never render
// zeros. "Could not observe" is not "observed zero" (AGENTS.md).
type StatsCache struct {
	cur atomic.Pointer[StatsSnapshot]
}

// Get returns the latest snapshot and whether one exists.
func (c *StatsCache) Get() (StatsSnapshot, bool) {
	if c == nil {
		return StatsSnapshot{}, false
	}
	p := c.cur.Load()
	if p == nil {
		return StatsSnapshot{}, false
	}
	return *p, true
}

// Set replaces the cached snapshot.
func (c *StatsCache) Set(s StatsSnapshot) {
	snap := s
	c.cur.Store(&snap)
}

// StatsSource is the part of *db.Store the sampler needs.
type StatsSource interface {
	PublicStatsQuery(ctx context.Context, canaryTelegramIDs []int64) (db.PublicStats, error)
}

// SampleStats runs one PublicStatsQuery and, on success, stores the result
// in cache. On failure it logs and leaves the previous snapshot in place, so
// a transient database error never blanks the numbers on the page. It
// returns the error for callers that want it (tests, a one-shot refresh).
func SampleStats(ctx context.Context, src StatsSource, cache *StatsCache, canary []int64, now func() time.Time) error {
	qctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ps, err := src.PublicStatsQuery(qctx, canary)
	if err != nil {
		slog.Warn("public stats sample failed", "err", err)
		return err
	}
	cache.Set(StatsSnapshot{
		AccountsTotal:     ps.AccountsTotal,
		ToolCallsTotal:    ps.ToolCallsTotal,
		ActiveUsers30d:    ps.ActiveUsers30d,
		SessionsConnected: ps.SessionsConnected,
		UpdatedAt:         now().UTC(),
	})
	return nil
}

// StartStatsSampler samples once immediately and then every `every` until ctx
// is cancelled. every <= 0 disables the sampler (the cache stays empty and
// the landing page shows no numbers), which is how PUBLIC_STATS_REFRESH=0
// turns the feature off. Single-replica only: there is no coordination, each
// replica keeps its own cache, which is fine because every replica reads the
// same database.
func StartStatsSampler(ctx context.Context, src StatsSource, cache *StatsCache, canary []int64, every time.Duration) {
	if every <= 0 {
		slog.Info("public stats sampler disabled")
		return
	}
	go func() {
		_ = SampleStats(ctx, src, cache, canary, time.Now)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = SampleStats(ctx, src, cache, canary, time.Now)
			}
		}
	}()
	slog.Info("public stats sampler enabled", "every", every)
}

// StatsJSON serves GET /api/stats: the cached snapshot as JSON, publicly
// cacheable for a minute. It is mounted outside auth.Middleware on purpose.
// The body contains deployment-wide counts only. Before the first successful
// sample it answers 503 with Retry-After rather than a zero-filled body.
func StatsJSON(cache *StatsCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap, ok := cache.Get()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !ok {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "stats not yet available"})
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		_ = json.NewEncoder(w).Encode(snap)
	}
}
