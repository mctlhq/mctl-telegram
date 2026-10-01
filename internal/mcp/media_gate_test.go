package mcp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMediaGate_NilIsUnlimited (T6) verifies a nil *mediaGate — the zero
// value every *Server not opted in via WithMediaConcurrency gets — imposes no
// limit at all, and does not panic on either acquire or release.
func TestMediaGate_NilIsUnlimited(t *testing.T) {
	var g *mediaGate
	for i := 0; i < 10; i++ {
		if err := g.acquire(context.Background()); err != nil {
			t.Fatalf("nil gate acquire() #%d = %v, want nil (unlimited)", i, err)
		}
	}
	g.release() // must not panic
}

// TestMediaGate_RefusesWhenFull (T6) verifies that once every slot is held, a
// further acquire waits up to the gate's own wait and then fails with
// errMediaBusy — and that no caller observing that error ever "started"
// anything (the gate itself performs no download; this documents the
// contract the tool handlers rely on). Uses its own gate with a shrunk wait
// (newMediaGateWithWait) rather than a shared package var, so it cannot race
// another test's gate goroutines.
func TestMediaGate_RefusesWhenFull(t *testing.T) {
	g := newMediaGateWithWait(1, nil, 50*time.Millisecond)
	if err := g.acquire(context.Background()); err != nil {
		t.Fatalf("first acquire() = %v, want nil", err)
	}
	start := time.Now()
	err := g.acquire(context.Background())
	elapsed := time.Since(start)
	if !errors.Is(err, errMediaBusy) {
		t.Fatalf("second acquire() = %v, want errMediaBusy", err)
	}
	if elapsed < g.wait {
		t.Errorf("acquire() returned after %v, want at least g.wait (%v)", elapsed, g.wait)
	}
	g.release()
}

// TestMediaGate_ReleasesOnAllPaths (T6) verifies that release() always frees
// the slot regardless of why the caller is releasing it (success, per-item
// error, systemic error, context cancellation are all just "the caller is
// done" from the gate's point of view) — a slot released can be re-acquired.
func TestMediaGate_ReleasesOnAllPaths(t *testing.T) {
	g := newMediaGate(1, nil)
	for i := 0; i < 5; i++ {
		if err := g.acquire(context.Background()); err != nil {
			t.Fatalf("acquire() #%d = %v, want nil", i, err)
		}
		g.release()
	}
	// One more acquire proves the last release actually freed the slot.
	if err := g.acquire(context.Background()); err != nil {
		t.Fatalf("final acquire() = %v, want nil (slot should have been freed)", err)
	}
	g.release()
}

// TestMediaGate_AcquireRespectsContextCancellation verifies a canceled
// context aborts the wait immediately rather than blocking the full
// admission wait. It keeps the 2s production wait on purpose: the canceled
// call never spends the wait, which only serves as the "returned immediately"
// threshold below, so a shrunken wait would just cut the headroom against a
// scheduling stall on a loaded -race runner.
func TestMediaGate_AcquireRespectsContextCancellation(t *testing.T) {
	g := newMediaGate(1, nil)
	if err := g.acquire(context.Background()); err != nil {
		t.Fatalf("first acquire() = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := g.acquire(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire(canceled ctx) = %v, want context.Canceled", err)
	}
	if elapsed >= g.wait {
		t.Errorf("acquire(canceled ctx) took %v, want to return immediately on cancellation", elapsed)
	}
	g.release()
}

// TestMediaGate_ConcurrentAcquireReleaseStaysWithinCapacity is a light
// concurrency smoke test: with n slots, at most n callers ever hold the gate
// at once, and every caller either gets in or times out — no panics, no
// stuck goroutines.
func TestMediaGate_ConcurrentAcquireReleaseStaysWithinCapacity(t *testing.T) {
	const slots = 2
	g := newMediaGate(slots, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	current, peak := 0, 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), g.wait+500*time.Millisecond)
			defer cancel()
			if err := g.acquire(ctx); err != nil {
				return
			}
			mu.Lock()
			current++
			if current > peak {
				peak = current
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			mu.Lock()
			current--
			mu.Unlock()
			g.release()
		}()
	}
	wg.Wait()
	if peak > slots {
		t.Errorf("peak concurrent holders = %d, want <= %d", peak, slots)
	}
}

// TestMediaGate_InFlightGaugeTracksHeldSlots pins that mctl_media_inflight
// rises on a successful acquire and falls on release, so the gauge the
// runbook sizes the pod from cannot drift.
func TestMediaGate_InFlightGaugeTracksHeldSlots(t *testing.T) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_media_inflight"})
	g := newMediaGate(1, gauge)
	if err := g.acquire(context.Background()); err != nil {
		t.Fatalf("acquire() = %v", err)
	}
	if got := testutil.ToFloat64(gauge); got != 1 {
		t.Errorf("gauge while holding a slot = %v, want 1", got)
	}
	g.release()
	if got := testutil.ToFloat64(gauge); got != 0 {
		t.Errorf("gauge after release = %v, want 0", got)
	}
}

// TestMediaGate_DefaultWaitIsTwoSeconds (T6) pins two contracts on the
// admission wait. First, the production value: newMediaGate must still
// install defaultMediaGateWait, and that const must still be 2s, so a test
// shrinking its own gate's wait cannot let it silently drift. Second, the
// guard in newMediaGateWithWait: a d <= 0 must fall back to the default, since
// an already-expired timer would make acquire refuse a free gate at random.
func TestMediaGate_DefaultWaitIsTwoSeconds(t *testing.T) {
	if defaultMediaGateWait != 2*time.Second {
		t.Fatalf("defaultMediaGateWait = %v, want 2s", defaultMediaGateWait)
	}
	g := newMediaGate(1, nil)
	if g.wait != defaultMediaGateWait {
		t.Errorf("newMediaGate(...).wait = %v, want defaultMediaGateWait (%v)", g.wait, defaultMediaGateWait)
	}
	// A d <= 0 must not reach the struct: an expired timer would make acquire
	// pick errMediaBusy at random on a free gate.
	for _, d := range []time.Duration{0, -time.Second} {
		if g := newMediaGateWithWait(1, nil, d); g.wait != defaultMediaGateWait {
			t.Errorf("newMediaGateWithWait(1, nil, %v).wait = %v, want defaultMediaGateWait", d, g.wait)
		}
	}
}
