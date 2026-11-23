package pa

// webhookmonitor.go is the periodic getWebhookInfo check (issue #1313
// slice d2, threat model T4). Every interval it reads the bot's webhook
// state and exports what it saw. A read that fails is exported as
// unreadable (up = 0, ok = 0, the per-state series withdrawn), never as a
// healthy or an empty state (I9): what could not be observed is not
// reported as absent.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// WebhookMonitorInterval is how often the monitor reads getWebhookInfo.
const WebhookMonitorInterval = 5 * time.Minute

// WebhookObservation is the outcome of one check.
type WebhookObservation struct {
	// At is when the check ran.
	At time.Time
	// Readable is false when getWebhookInfo failed; every other field is
	// then zero and means nothing.
	Readable bool
	Info     WebhookInfo
	// Problems is CheckWebhook's result; empty means healthy.
	Problems []string
}

// WebhookGauges exports observations (*metrics.Registry implements it).
type WebhookGauges interface {
	ObservePAWebhookInfo(readable bool, problems []string, pendingUpdates int, lastErrorUnix int64, at time.Time)
}

// WebhookMonitorConfig configures NewWebhookMonitor.
type WebhookMonitorConfig struct {
	// HTTP is the client used for the Bot API; nil uses a bounded default.
	HTTP *http.Client
	// BaseURL is the Bot API origin; empty means DefaultBotAPIBaseURL.
	BaseURL string
	// Token is PA_BOT_TOKEN. Required.
	Token string
	// ExpectedURL is PA_WEBHOOK_URL. Required.
	ExpectedURL string
	// Gauges is required: a monitor nobody can see is not a monitor.
	Gauges   WebhookGauges
	Interval time.Duration
	Now      func() time.Time
}

// WebhookMonitor runs the check.
type WebhookMonitor struct {
	cfg WebhookMonitorConfig

	mu sync.Mutex
	// since is the time of the previous readable check: a delivery error
	// at or after it is new. Before the first readable check it is one
	// interval back, so an error from days ago does not alert at boot.
	since time.Time
}

// NewWebhookMonitor validates cfg.
func NewWebhookMonitor(cfg WebhookMonitorConfig) (*WebhookMonitor, error) {
	if cfg.Token == "" || cfg.ExpectedURL == "" || cfg.Gauges == nil {
		return nil, errors.New("pa webhook monitor: token, expected url and gauges are required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = WebhookMonitorInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &WebhookMonitor{cfg: cfg}, nil
}

// Check reads getWebhookInfo once and exports the result.
func (m *WebhookMonitor) Check(ctx context.Context) WebhookObservation {
	now := m.cfg.Now()
	info, err := GetWebhookInfo(ctx, m.cfg.HTTP, m.cfg.BaseURL, m.cfg.Token)
	if err != nil {
		// The error never carries the token (GetWebhookInfo redacts it).
		slog.Warn("pa webhook info unreadable", "err", err)
		m.cfg.Gauges.ObservePAWebhookInfo(false, nil, 0, 0, now)
		return WebhookObservation{At: now}
	}
	m.mu.Lock()
	since := m.since
	if since.IsZero() {
		since = now.Add(-m.cfg.Interval)
	}
	m.since = now
	m.mu.Unlock()
	problems := CheckWebhook(info, m.cfg.ExpectedURL, since)
	if len(problems) > 0 {
		// Problem names and counts only: never the URL Telegram reports
		// (it may be an attacker's) or the error text.
		slog.Warn("pa webhook problems", "problems", problems, "pending_update_count", info.PendingUpdateCount)
	}
	m.cfg.Gauges.ObservePAWebhookInfo(true, problems, info.PendingUpdateCount, info.LastErrorDate, now)
	return WebhookObservation{At: now, Readable: true, Info: info, Problems: problems}
}

// Run checks at once and then every interval until ctx ends.
func (m *WebhookMonitor) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	for {
		m.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
