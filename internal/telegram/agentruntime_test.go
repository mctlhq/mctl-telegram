package telegram

import (
	"context"
	"testing"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// fakeRuntime enables the agent path for a single user id.
type fakeRuntime struct {
	enabled int64
	ranFor  chan int64
}

func (f *fakeRuntime) HandlerFor(userID int64) gotdtelegram.UpdateHandler {
	if userID != f.enabled {
		return nil
	}
	return gotdtelegram.UpdateHandlerFunc(func(ctx context.Context, u tg.UpdatesClass) error {
		return nil
	})
}

func (f *fakeRuntime) RunFor(ctx context.Context, userID int64, c *gotdtelegram.Client) error {
	select {
	case f.ranFor <- userID:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestPinUnpin(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)
	if p.isPinned(7) {
		t.Fatal("fresh pool must not report pinned")
	}
	p.Pin(7)
	if !p.isPinned(7) {
		t.Fatal("Pin(7) not reflected")
	}
	if p.isPinned(8) {
		t.Fatal("pin must be per-user")
	}
	p.Unpin(7)
	if p.isPinned(7) {
		t.Fatal("Unpin(7) not reflected")
	}
}

func TestPin_EvictsUnwiredEntrySoListenerGetsRebuilt(t *testing.T) {
	rt := &fakeRuntime{enabled: 42, ranFor: make(chan int64, 1)}
	p := NewClientPool(1, "h", time.Minute, nil)

	// Simulate a client built BEFORE the agent runtime was wired: no runFn.
	e := &entry{lastUsed: time.Now(), cancel: func() {}, ready: make(chan struct{})}
	close(e.ready)
	p.mu.Lock()
	p.entries[42] = e
	p.mu.Unlock()

	// Pinning must evict it so the next Borrow rebuilds it with the handler;
	// otherwise GC (which now skips pinned ids) would keep the deaf client
	// alive forever.
	p.WithAgentRuntime(rt).Pin(42)
	p.mu.Lock()
	_, present := p.entries[42]
	p.mu.Unlock()
	if present {
		t.Fatal("Pin must evict an entry that has no update handler")
	}

	// Pinning again when there is no entry, or when the entry is already
	// wired, must be a no-op (the supervisor Pins on every tick).
	p.Pin(42)
	wired := &entry{lastUsed: time.Now(), cancel: func() {}, ready: make(chan struct{}),
		runFn: func(context.Context) error { return nil }}
	close(wired.ready)
	p.mu.Lock()
	p.entries[42] = wired
	p.mu.Unlock()
	p.Pin(42)
	p.mu.Lock()
	_, stillThere := p.entries[42]
	p.mu.Unlock()
	if !stillThere {
		t.Fatal("Pin must not churn an already-wired listener entry")
	}
}

func TestUnpin_StopsRunningListener(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)
	cancelled := make(chan struct{})
	e := &entry{
		lastUsed: time.Now(),
		cancel:   func() { close(cancelled) },
		ready:    make(chan struct{}),
		runFn:    func(context.Context) error { return nil },
	}
	close(e.ready)
	p.mu.Lock()
	p.entries[42] = e
	p.pinned[42] = struct{}{}
	p.mu.Unlock()

	// A disabled listener must stop consuming updates immediately, not linger
	// until IdleTimeout.
	p.Unpin(42)
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("Unpin did not cancel the running listener client")
	}
	if p.isPinned(42) {
		t.Fatal("Unpin must clear the pin")
	}
}

func TestAcquire_AgentRuntimeWiring(t *testing.T) {
	rt := &fakeRuntime{enabled: 42, ranFor: make(chan int64, 1)}
	p := NewClientPool(1, "h", time.Minute, nil).WithAgentRuntime(rt)

	// Agent-enabled user: entry carries a run callback.
	e, err := p.acquire(42)
	if err != nil {
		t.Fatalf("acquire enabled: %v", err)
	}
	if e.runFn == nil {
		t.Fatal("agent-enabled entry must have runFn")
	}

	// Plain user: default behavior, no run callback.
	e2, err := p.acquire(43)
	if err != nil {
		t.Fatalf("acquire plain: %v", err)
	}
	if e2.runFn != nil {
		t.Fatal("plain entry must not have runFn")
	}

	// Tear both down before their run goroutines attempt real dials.
	p.Close(42)
	p.Close(43)
}
