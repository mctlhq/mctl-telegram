package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

const testPABotToken = "7000000001:pa-test-token-not-real-0123456789"

// TestStartPAWebhookMonitor_InertByDefault: with PA_ENABLED off the
// monitor does not start, calls nothing and exports nothing; with it on it
// reads getWebhookInfo (and only that) and exports the result.
func TestStartPAWebhookMonitor_InertByDefault(t *testing.T) {
	var calls atomic.Int32
	var otherMethod atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/getWebhookInfo") {
			otherMethod.Store(true)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"url":"https://pa.example/pa/bot/webhook","allowed_updates":["message","callback_query"]}}`))
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	exported := func(m *metrics.Registry) bool {
		mfs, err := m.Prometheus.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, mf := range mfs {
			if mf.GetName() == "mctl_pa_webhook_info_up" {
				return len(mf.GetMetric()) > 0
			}
		}
		return false
	}

	off := metrics.New()
	started, err := startPAWebhookMonitor(ctx, &config.Config{PABotToken: testPABotToken}, off, srv.URL)
	if err != nil || started {
		t.Fatalf("PA off: started=%v err=%v", started, err)
	}
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 0 || exported(off) {
		t.Fatal("PA off: the monitor ran")
	}

	on := metrics.New()
	cfg := &config.Config{PAEnabled: true, PABotToken: testPABotToken, PAWebhookURL: "https://pa.example/pa/bot/webhook"}
	started, err = startPAWebhookMonitor(ctx, cfg, on, srv.URL)
	if err != nil || !started {
		t.Fatalf("PA on: started=%v err=%v", started, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 || !exported(on) || otherMethod.Load() {
		t.Fatalf("PA on: calls=%d exported=%v other=%v", calls.Load(), exported(on), otherMethod.Load())
	}

	// A config without the expected URL is refused, not run unchecked.
	if _, err := startPAWebhookMonitor(ctx, &config.Config{PAEnabled: true, PABotToken: testPABotToken}, metrics.New(), srv.URL); err == nil {
		t.Fatal("monitor started without an expected URL")
	}
}
