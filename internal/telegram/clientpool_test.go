package telegram

import (
	"context"
	"testing"
	"time"
)

// TestClose_RemovesEntryUnderLock verifies the fix for the race condition
// flagged by codex on PR #2: Close() must remove the entry from p.entries
// while still holding the mutex, otherwise a concurrent acquire() can
// observe the doomed entry with stopped=false and reuse the client.
func TestClose_RemovesEntryUnderLock(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)

	canceled := make(chan struct{})
	_, cancel := context.WithCancel(context.Background())
	wrapped := func() {
		cancel()
		close(canceled)
	}

	// Hand-inject an entry as if a previous Borrow had populated it.
	// We deliberately leave stopped=false to model the race window.
	e := &entry{
		lastUsed: time.Now(),
		cancel:   wrapped,
		ready:    make(chan struct{}),
	}
	close(e.ready)
	p.mu.Lock()
	p.entries[42] = e
	p.mu.Unlock()

	if !p.Close(42) {
		t.Fatal("Close should report eviction when entry exists")
	}

	// After Close, the entry must be gone from the map and marked stopped.
	p.mu.Lock()
	_, present := p.entries[42]
	p.mu.Unlock()
	if present {
		t.Fatal("entry must be removed from map under the lock")
	}
	if !e.stopped {
		t.Fatal("entry must be marked stopped under the lock")
	}

	// And the cancel function must have been invoked.
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("Close did not invoke cancel within timeout")
	}
}

func TestClose_NoEntryReturnsFalse(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)
	if p.Close(999) {
		t.Fatal("Close on missing entry must return false")
	}
}

// TestRemoveAtomic_HoldsLockAcrossFn verifies the second-pass codex fix
// for PR #2: pool eviction + DB revoke must commit under the same mutex
// so a concurrent acquire() observes both effects atomically.
//
// Rather than driving an actual acquire() — which spins up a gotd client
// and dials Telegram — we probe the shared mutex directly: a goroutine
// races to grab p.mu while RemoveAtomic's fn is mid-flight. If RemoveAtomic
// truly holds the lock for the duration of fn, the goroutine cannot
// acquire it until fn returns.
func TestRemoveAtomic_HoldsLockAcrossFn(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)

	canceled := make(chan struct{})
	e := &entry{
		lastUsed: time.Now(),
		cancel:   func() { close(canceled) },
		ready:    make(chan struct{}),
	}
	close(e.ready)
	p.mu.Lock()
	p.entries[42] = e
	p.mu.Unlock()

	startProbe := make(chan struct{})
	probeAcquired := make(chan struct{})
	go func() {
		<-startProbe
		p.mu.Lock()
		close(probeAcquired)
		p.mu.Unlock()
	}()

	err := p.RemoveAtomic(42, func() error {
		close(startProbe)
		// Give the probe goroutine a chance to attempt p.mu.Lock().
		time.Sleep(50 * time.Millisecond)
		select {
		case <-probeAcquired:
			t.Error("probe acquired p.mu while RemoveAtomic's fn was running — lock not held")
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RemoveAtomic: %v", err)
	}

	// After RemoveAtomic returns, the probe must be able to acquire.
	select {
	case <-probeAcquired:
	case <-time.After(time.Second):
		t.Fatal("probe could not acquire p.mu after RemoveAtomic released it")
	}

	// The original entry is gone and its cancel was invoked.
	p.mu.Lock()
	_, present := p.entries[42]
	p.mu.Unlock()
	if present {
		t.Fatal("entry 42 should be evicted")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("cancel was not invoked after RemoveAtomic returned")
	}
}

func TestRemoveAtomic_ReturnsFnError(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)
	sentinel := errSentinel("boom")
	err := p.RemoveAtomic(7, func() error { return sentinel })
	if err == nil || err.Error() != "boom" {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

type errSentinel string

func (e errSentinel) Error() string { return string(e) }
