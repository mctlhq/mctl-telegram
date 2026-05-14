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
