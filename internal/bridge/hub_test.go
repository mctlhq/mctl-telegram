package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

func TestHub_RegisterAndUnregister(t *testing.T) {
	h := NewHub()
	if h.HasDaemon(42) {
		t.Fatal("expected no daemon registered initially")
	}
	send := h.Register(42)
	if !h.HasDaemon(42) {
		t.Fatal("Register should make HasDaemon true")
	}
	h.Unregister(42)
	if h.HasDaemon(42) {
		t.Fatal("Unregister should drop the entry")
	}
	// And the send channel should be closed.
	if _, ok := <-send; ok {
		t.Fatal("send channel should be closed after Unregister")
	}
}

func TestHub_NewRegisterEvictsPrevious(t *testing.T) {
	h := NewHub()
	first := h.Register(42)
	second := h.Register(42)
	if first == second {
		t.Fatal("new Register should hand out a fresh channel")
	}
	if _, ok := <-first; ok {
		t.Fatal("previous send channel should be closed when a new daemon registers")
	}
	_ = second
}

func TestHub_CallReturnsResponse(t *testing.T) {
	h := NewHub()
	send := h.Register(7)

	// Drive the "daemon" side from a goroutine: drain the send channel,
	// echo the result back via Deliver with the same ID.
	go func() {
		env := <-send
		if env.Type != TypeCall {
			t.Errorf("expected TypeCall, got %s", env.Type)
		}
		h.Deliver(7, EncodeResponse(env.ID, json.RawMessage(`{"ok":true}`)))
	}()

	ctx := context.Background()
	got, err := h.Call(ctx, 7, EncodeCall("req-1", "list_dialogs", nil))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if got.Type != TypeResponse {
		t.Fatalf("expected TypeResponse, got %s", got.Type)
	}
	if string(got.Result) != `{"ok":true}` {
		t.Fatalf("unexpected result: %s", got.Result)
	}
}

func TestHub_CallNoDaemonConnected(t *testing.T) {
	h := NewHub()
	_, err := h.Call(context.Background(), 42, EncodeCall("x", "t", nil))
	if !errors.Is(err, ErrNoDaemonConnected) {
		t.Fatalf("expected ErrNoDaemonConnected, got %v", err)
	}
}

func TestHub_CallTimeoutWhenDaemonSilent(t *testing.T) {
	h := NewHub()
	send := h.Register(9)
	// Drain the send channel so Call's send doesn't block forever,
	// but don't reply — Call should time out via DeadlineCall.
	go func() { <-send }()

	// Short-circuit DeadlineCall locally for the test by deriving a
	// shorter context deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := h.Call(ctx, 9, EncodeCall("req-2", "t", nil))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	// Accept either ctx.DeadlineExceeded or ErrCallTimeout depending on
	// which fires first.
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrCallTimeout) {
		t.Fatalf("expected context.DeadlineExceeded or ErrCallTimeout, got %v", err)
	}
}

func TestHub_DeliverWithoutPendingIsNoop(t *testing.T) {
	h := NewHub()
	h.Register(1)
	// No pending call with this ID — Deliver should be a no-op, not panic.
	h.Deliver(1, EncodeResponse("never-issued", nil))
}

func TestHub_CallOverloadedReturnsError(t *testing.T) {
	h := NewHub()
	send := h.Register(42)

	// Drain the send channel so calls don't block on the send select.
	// We never reply so all calls will be stuck waiting for a response.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for range send {
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Launch maxPendingCalls goroutines that each start a Call; they will block
	// waiting for a response. The (maxPendingCalls+1)th call must return
	// ErrDaemonOverloaded immediately.
	ready := make(chan struct{}, maxPendingCalls)
	for i := 0; i < maxPendingCalls; i++ {
		go func(n int) {
			ready <- struct{}{}
			// These calls will block until ctx is cancelled.
			_, _ = h.Call(ctx, 42, EncodeCall(fmt.Sprintf("id-%d", n), "t", nil))
		}(i)
	}

	// Wait for all goroutines to have incremented pendingCount.
	for i := 0; i < maxPendingCalls; i++ {
		<-ready
	}
	// Give goroutines a moment to reach the pending counter increment.
	time.Sleep(20 * time.Millisecond)

	// The next call must be rejected immediately.
	_, err := h.Call(ctx, 42, EncodeCall("overload", "t", nil))
	if !errors.Is(err, ErrDaemonOverloaded) {
		t.Fatalf("expected ErrDaemonOverloaded when at capacity, got %v", err)
	}

	// Cancel the context to unblock all pending goroutines, then close send.
	cancel()
	h.Unregister(42)
	<-drainDone
}

func TestHub_WithMetrics_NoPanicOnRegisterUnregister(t *testing.T) {
	m := metrics.New()
	h := NewHub().WithMetrics(m)

	// Register a new user — gauge should go to 1.
	h.Register(10)
	// Re-register same user — gauge must stay at 1 (eviction, not add).
	h.Register(10)
	// Unregister — gauge should go back to 0.
	h.Unregister(10)

	// Register and unregister via UnregisterSend.
	send := h.Register(11)
	h.UnregisterSend(11, send)

	// Stale UnregisterSend should be a no-op (channel mismatch).
	h.Register(12)
	h.UnregisterSend(12, send) // wrong channel; should not decrement
	h.Unregister(12)
	// If the gauge double-decremented we'd go negative, but we can't
	// easily read a prometheus.Gauge value without the dto package here.
	// The test ensures no panics on all paths.
}
