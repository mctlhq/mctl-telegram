package main

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func openRevocationWiringStore(t *testing.T, migrate bool) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+t.Name()+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !migrate {
		// A closed handle: every read fails, the shape of an unreachable store.
		_ = conn.Close()
		return &db.Store{DB: conn}
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &db.Store{DB: conn}
}

// scrapedSnapshotAge gathers the registry as /metrics does and returns the
// age gauge, failing the test when the server's wiring did not export it.
func scrapedSnapshotAge(t *testing.T, m *metrics.Registry) float64 {
	t.Helper()
	mfs, err := m.Prometheus.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == metrics.WorkerTokenRevocationSnapshotAgeName {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("%s not exported by the server's wiring", metrics.WorkerTokenRevocationSnapshotAgeName)
	return 0
}

func tickRefresher(t *testing.T, tick chan time.Time) {
	t.Helper()
	select {
	case tick <- time.Time{}:
	case <-time.After(3 * time.Second):
		t.Fatal("no refresher took the tick: the server wiring did not start it")
	}
}

// The wiring main uses, driven by a manual tick: the gauge is exported, the
// refresher is running (a revocation recorded after start reaches the cache
// through ticks alone, never through an inline refresh, because the snapshot
// it refreshes is never a TTL old), and the age it keeps stays within one
// refresh interval.
func TestStartWorkerTokenRevocation_RefresherKeepsExportedAgeFresh(t *testing.T) {
	store := openRevocationWiringStore(t, true)
	m := metrics.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tick := make(chan time.Time)
	cache, err := startWorkerTokenRevocation(ctx, store, time.Hour, m, tick)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := store.RevokeWorkerToken(ctx, "jti-wired", 1, "", 0); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	for range 3 { // the 2nd send proves a full refresh after the revocation
		tickRefresher(t, tick)
		if age := scrapedSnapshotAge(t, m); age > localjwt.RevocationRefreshInterval.Seconds() {
			t.Fatalf("exported age %.3fs, want <= %s while the refresher runs", age, localjwt.RevocationRefreshInterval)
		}
	}
	revoked, err := cache.IsRevoked(ctx, "jti-wired", 1, time.Now())
	if err != nil || !revoked {
		t.Fatalf("revocation recorded after start not loaded by the wired refresher: revoked=%v err=%v", revoked, err)
	}
}

// Production path (nil tick): with no token checked at all, an unreadable
// store is counted at once by the refresher's initial load, through the
// hook main wires.
func TestStartWorkerTokenRevocation_ProductionTickerCountsWithoutTraffic(t *testing.T) {
	store := openRevocationWiringStore(t, false)
	m := metrics.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := startWorkerTokenRevocation(ctx, store, time.Hour, m, nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for testutil.ToFloat64(m.WorkerTokenRevocationRefreshFailuresTotal) < 1 {
		if time.Now().After(deadline) {
			t.Fatal("no refresh failure counted without traffic: refresher not started or hook not wired")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if age := scrapedSnapshotAge(t, m); age < 0 {
		t.Fatalf("exported age %v, want >= 0 for a never-loaded cache", age)
	}
}
