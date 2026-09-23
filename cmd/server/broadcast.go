package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/config"
)

// broadcastShutdownGrace bounds how long main waits for the delivery worker
// after the shutdown signal: one in-flight Bot API call (15 s) plus the few
// writes that record it and hand the rest of the batch back. It runs
// alongside the HTTP server's own 10 s drain and stays inside Kubernetes'
// default 30 s termination grace period.
const broadcastShutdownGrace = 20 * time.Second

// broadcastWorker tracks the one delivery worker goroutine, so main can let
// it finish its batch on shutdown instead of exiting under it.
var broadcastWorker sync.WaitGroup

func startBroadcastWorker(ctx context.Context, w *broadcast.Worker) {
	broadcastWorker.Add(1)
	go func() {
		defer broadcastWorker.Done()
		w.Run(ctx, broadcast.DefaultTickInterval)
	}()
}

// waitBroadcastWorker blocks until the worker has returned or deadline
// passes. Rows it could not finish stay in sending and are closed by the
// next instance's stale sweep -- never re-sent.
func waitBroadcastWorker(deadline time.Time) {
	done := make(chan struct{})
	go func() {
		broadcastWorker.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Until(deadline)):
		slog.Warn("broadcast: delivery worker did not stop before the shutdown deadline")
	}
}

// broadcastPolicy builds the audience tier policy from the same inputs the
// OAuth server resolves scopes from, so a broadcast's "client" and "admin"
// are exactly what a login would get.
func broadcastPolicy(cfg *config.Config) broadcast.Policy {
	return broadcast.Policy{
		AdminTelegramIDs:       telegramIDSet(cfg.TGLoginAdmins),
		LookupAdminTelegramIDs: telegramIDSet(cfg.TGLoginLookupAdmins),
		ClientTelegramIDs:      telegramIDSet(cfg.TGLoginClients),
		AutoApproveClients:     cfg.AutoApproveClients,
	}
}
