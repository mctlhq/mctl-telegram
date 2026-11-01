package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/ui"
)

type fakeStatsSource struct {
	stats db.PublicStats
	err   error
	calls int
}

func (f *fakeStatsSource) PublicStatsQuery(context.Context, []int64) (db.PublicStats, error) {
	f.calls++
	return f.stats, f.err
}

func TestStatsJSON_EmptyCacheIs503NotZeros(t *testing.T) {
	cache := &StatsCache{}
	rec := httptest.NewRecorder()
	StatsJSON(cache).ServeHTTP(rec, httptest.NewRequest("GET", "/api/stats", nil))
	if rec.Code != 503 {
		t.Fatalf("empty cache: status %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("empty cache: Retry-After missing")
	}
	if strings.Contains(rec.Body.String(), `"tool_calls_total"`) {
		t.Errorf("empty cache must not serve a zero-filled body, got %s", rec.Body.String())
	}
}

func TestStatsJSON_ServesSnapshotCacheable(t *testing.T) {
	cache := &StatsCache{}
	at := time.Date(2026, 11, 1, 12, 30, 0, 0, time.UTC)
	cache.Set(StatsSnapshot{AccountsTotal: 97, ToolCallsTotal: 57339, ActiveUsers30d: 50, SessionsActive: 60, UpdatedAt: at})
	rec := httptest.NewRecorder()
	StatsJSON(cache).ServeHTTP(rec, httptest.NewRequest("GET", "/api/stats", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control = %q", cc)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	for k, want := range map[string]float64{"accounts_total": 97, "tool_calls_total": 57339, "active_users_30d": 50, "sessions_active": 60} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	if got["updated_at"] != "2026-11-01T12:30:00Z" {
		t.Errorf("updated_at = %v", got["updated_at"])
	}
	if len(got) != 5 {
		t.Errorf("body has %d keys, want exactly 5 aggregate fields: %v", len(got), got)
	}
}

func TestSampleStats_KeepsPreviousOnError(t *testing.T) {
	cache := &StatsCache{}
	src := &fakeStatsSource{stats: db.PublicStats{AccountsTotal: 1, ToolCallsTotal: 2, ActiveUsers30d: 3, SessionsActive: 4}}
	now := func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }
	if err := SampleStats(context.Background(), src, cache, nil, now); err != nil {
		t.Fatal(err)
	}
	first, ok := cache.Get()
	if !ok || first.ToolCallsTotal != 2 {
		t.Fatalf("first sample not stored: %+v ok=%v", first, ok)
	}
	src.err = errors.New("db down")
	src.stats = db.PublicStats{}
	if err := SampleStats(context.Background(), src, cache, nil, now); err == nil {
		t.Fatal("expected error from failing source")
	}
	after, ok := cache.Get()
	if !ok || after != first {
		t.Errorf("failed sample must leave the previous snapshot: got %+v ok=%v", after, ok)
	}
}

func TestStartStatsSampler_DisabledAndCancelled(t *testing.T) {
	// every <= 0: nothing runs, the cache stays empty, no goroutine starts.
	cache := &StatsCache{}
	src := &fakeStatsSource{stats: db.PublicStats{AccountsTotal: 1}}
	StartStatsSampler(context.Background(), src, cache, nil, 0)
	time.Sleep(20 * time.Millisecond)
	if _, ok := cache.Get(); ok || src.calls != 0 {
		t.Fatalf("disabled sampler must not sample: ok=%v calls=%d", ok, src.calls)
	}

	// Enabled: samples immediately, then stops ticking once ctx is cancelled.
	cache = &StatsCache{}
	src = &fakeStatsSource{stats: db.PublicStats{AccountsTotal: 1}}
	ctx, cancel := context.WithCancel(context.Background())
	StartStatsSampler(ctx, src, cache, nil, 5*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := cache.Get(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sampler never filled the cache")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	time.Sleep(30 * time.Millisecond)
	n := src.calls
	time.Sleep(50 * time.Millisecond)
	if src.calls != n {
		t.Errorf("sampler kept running after cancel: %d -> %d calls", n, src.calls)
	}
}

func TestLanding_StatsStripOnlyWhenSampled(t *testing.T) {
	cache := &StatsCache{}
	h := Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true, WithStats(cache))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `id="stats"`) {
		t.Fatal("strip rendered before any sample exists")
	}

	cache.Set(StatsSnapshot{AccountsTotal: 97, ToolCallsTotal: 57339, ActiveUsers30d: 50, SessionsActive: 60,
		UpdatedAt: time.Date(2026, 11, 1, 12, 30, 0, 0, time.UTC)})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()
	for _, must := range []string{
		`id="stats"`,
		`data-stat="tool_calls_total">57,339<`,
		`data-stat="accounts_total">97<`,
		`data-stat="active_users_30d">50<`,
		`data-stat="sessions_active">60<`,
		`datetime="2026-11-01T12:30:00Z"`,
		`12:30 UTC`,
		`fetch('/api/stats'`,
	} {
		if !strings.Contains(body, must) {
			t.Errorf("landing with stats missing %q", must)
		}
	}
	// The hero actions: Copy MCP URL is the primary control, Connect in
	// Claude is gone from the actions row.
	if !strings.Contains(body, `<button class="cta-btn" type="button" id="copy-mcp-url"`) {
		t.Error("Copy MCP URL is not the primary hero button")
	}
	if strings.Contains(body, `href="#claude">Connect in Claude</a>`) {
		t.Error("Connect in Claude button still in the hero actions")
	}

	// Without the option the page is unchanged: no strip even with a cache.
	plain := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).ServeHTTP(plain, httptest.NewRequest("GET", "/", nil))
	if strings.Contains(plain.Body.String(), `id="stats"`) {
		t.Error("strip rendered without WithStats")
	}
}

func TestFormatCount(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 7: "7", 97: "97", 999: "999", 1000: "1,000", 57339: "57,339", 1234567: "1,234,567", -1234: "-1,234"} {
		if got := ui.FormatCount(n); got != want {
			t.Errorf("FormatCount(%d) = %q, want %q", n, got, want)
		}
	}
}
