package main

import (
	"context"
	"log/slog"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/pa"
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
//
// links is the linking flow's sweep ((*linking.Service).ExpireStale). With
// PA_ENABLED on and links set, the linking sweeper runs beside the
// retention sweeper (#1338). links is nil when the server runs no linking
// flow (no PA server enabled; paRuntime.Links).
func startPAState(ctx context.Context, cfg *config.Config, store convo.Store, links sweeper.PALinkExpirer) (bool, error) {
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
	if links != nil {
		go sweeper.PALinks(ctx, links)
	}
	return true, nil
}

// paWebhookMetrics is what the getWebhookInfo monitor exports to
// (*metrics.Registry).
type paWebhookMetrics interface {
	pa.WebhookGauges
	StartPAWebhookMonitor()
}

// startPAWebhookMonitor starts the periodic getWebhookInfo check (issue
// #1313 slice d2, T4) when PA_ENABLED is true, and does nothing otherwise:
// with the PA off there is no webhook to watch, and no metric that could
// read as unreadable. It only reads; it never registers the webhook.
func startPAWebhookMonitor(ctx context.Context, cfg *config.Config, m paWebhookMetrics, baseURL string) (bool, error) {
	if !cfg.PAEnabled {
		return false, nil
	}
	mon, err := pa.NewWebhookMonitor(pa.WebhookMonitorConfig{
		BaseURL: baseURL, Token: cfg.PABotToken, ExpectedURL: cfg.PAWebhookURL, Gauges: m,
	})
	if err != nil {
		return false, err
	}
	m.StartPAWebhookMonitor()
	go mon.Run(ctx)
	return true, nil
}
