package main

import (
	"context"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// startWorkerTokenRevocation builds the one revocation cache every worker-
// token provider shares and wires what #1346's alerting depends on: failed
// refresh reads counted, the snapshot age exported at scrape time, and the
// background refresher started on ctx (the server's lifetime). The refresher
// is what keeps the age honest without traffic: agent workers exit on their
// first 401 and crash-loop, so request-driven refreshes stop almost as soon
// as an outage starts.
//
// tick is nil in production, which uses a RevocationRefreshInterval ticker
// stopped when ctx ends; tests pass a manual channel. Either way the same
// RunRefresherOn loop runs, so a test of this function covers main's wiring.
func startWorkerTokenRevocation(ctx context.Context, store *db.Store, ttl time.Duration, m *metrics.Registry, tick <-chan time.Time) (*localjwt.RevocationCache, error) {
	cache := localjwt.NewRevocationCache(store, ttl)
	cache.SetRefreshErrorHook(m.WorkerTokenRevocationRefreshFailuresTotal.Inc)
	if err := m.RegisterWorkerTokenRevocationSnapshotAge(func() float64 {
		return cache.SnapshotAge().Seconds()
	}); err != nil {
		return nil, err
	}
	if tick == nil {
		t := time.NewTicker(localjwt.RevocationRefreshInterval)
		context.AfterFunc(ctx, t.Stop)
		tick = t.C
	}
	go cache.RunRefresherOn(ctx, tick)
	return cache, nil
}
