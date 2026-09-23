package main

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

// The broadcast audience tiers must come from the same allowlists the OAuth
// server resolves scopes from; a swapped field would silently widen or
// narrow every "client"/"admin" campaign.
func TestBroadcastPolicyMirrorsLoginAllowlists(t *testing.T) {
	p := broadcastPolicy(&config.Config{
		TGLoginAdmins:       []int64{1},
		TGLoginLookupAdmins: []int64{2},
		TGLoginClients:      []int64{3},
		AutoApproveClients:  true,
	})
	if !p.AdminTelegramIDs[1] || len(p.AdminTelegramIDs) != 1 {
		t.Fatalf("admins = %v", p.AdminTelegramIDs)
	}
	if !p.LookupAdminTelegramIDs[2] || len(p.LookupAdminTelegramIDs) != 1 {
		t.Fatalf("lookup admins = %v", p.LookupAdminTelegramIDs)
	}
	if !p.ClientTelegramIDs[3] || len(p.ClientTelegramIDs) != 1 {
		t.Fatalf("clients = %v", p.ClientTelegramIDs)
	}
	if !p.AutoApproveClients {
		t.Fatal("AutoApproveClients not carried over")
	}
}

// The two shutdown-wait tests share the package-level broadcastWorker
// WaitGroup, so neither may run in parallel.

func TestWaitBroadcastWorkerReturnsWhenTheWorkerStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	broadcastWorker.Add(1)
	go func() {
		defer broadcastWorker.Done()
		<-ctx.Done()
		close(stopped)
	}()
	cancel()
	start := time.Now()
	waitBroadcastWorker(start.Add(5 * time.Second))
	select {
	case <-stopped:
	default:
		t.Fatal("wait returned before the worker stopped")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("wait ran into the deadline although the worker had stopped")
	}
}

func TestWaitBroadcastWorkerGivesUpAtTheDeadline(t *testing.T) {
	broadcastWorker.Add(1)
	defer broadcastWorker.Done()
	start := time.Now()
	waitBroadcastWorker(start.Add(50 * time.Millisecond))
	if d := time.Since(start); d > time.Second {
		t.Fatalf("waited %s past the deadline", d)
	}
}
