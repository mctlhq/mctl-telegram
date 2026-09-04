package bridge

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestHub_CallRetirementWhileEnqueueBlocked deterministically places Call in
// the window that used to race close(dc.send): Call has already selected the
// daemon connection but cannot enqueue its envelope yet. Every retirement
// path must wake it with ErrNoDaemonConnected, never panic or leave it stuck.
func TestHub_CallRetirementWhileEnqueueBlocked(t *testing.T) {
	tests := []struct {
		name   string
		retire func(h *Hub, userID int64, deviceID string, send chan Envelope)
	}{
		{
			name: "unregister",
			retire: func(h *Hub, userID int64, _ string, _ chan Envelope) {
				h.Unregister(userID)
			},
		},
		{
			name: "unregister-send",
			retire: func(h *Hub, userID int64, _ string, send chan Envelope) {
				h.UnregisterSend(userID, send)
			},
		},
		{
			name: "evict-device",
			retire: func(h *Hub, userID int64, deviceID string, _ chan Envelope) {
				if !h.EvictDevice(userID, deviceID) {
					panic("expected device eviction")
				}
			},
		},
		{
			name: "register-replacement",
			retire: func(h *Hub, userID int64, _ string, _ chan Envelope) {
				h.Register(userID, "replacement")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const userID int64 = 42
			const deviceID = "dev-target"

			h := NewHub()
			send := h.Register(userID, deviceID)

			// Freeze the pump: fill its writer-facing buffer, then fill the
			// internal outbound buffer. The next Hub.Call must block in its
			// enqueue select until either capacity appears or dc.done closes.
			h.mu.Lock()
			dc := h.conn[userID]
			h.mu.Unlock()
			for i := 0; i < cap(dc.send); i++ {
				dc.send <- Envelope{Type: TypePing, ID: fmt.Sprintf("send-%d", i)}
			}
			for i := 0; i < cap(dc.outbound); i++ {
				dc.outbound <- Envelope{Type: TypePing, ID: fmt.Sprintf("queue-%d", i)}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := h.Call(ctx, userID, EncodeCall("blocked", "list_dialogs", nil))
				result <- err
			}()

			// Give the goroutine a scheduling turn. The buffers above make the
			// state deterministic: it cannot complete successfully because no
			// outbound capacity exists and no daemon response is possible.
			time.Sleep(10 * time.Millisecond)
			tt.retire(h, userID, deviceID, send)

			select {
			case err := <-result:
				if !errors.Is(err, ErrNoDaemonConnected) {
					t.Fatalf("Call after retirement: got %v, want ErrNoDaemonConnected", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Call remained stuck after connection retirement")
			}
		})
	}
}

// A call that was already delivered but is waiting for its response must also
// leave promptly when the exact connection is retired; otherwise revocation or
// replacement leaks the pending call until its normal tool deadline.
func TestHub_CallWaitingForReplyStopsOnRetirement(t *testing.T) {
	h := NewHub()
	send := h.Register(7, "dev-7")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := h.Call(ctx, 7, EncodeCall("req-1", "list_dialogs", nil))
		result <- err
	}()

	select {
	case <-send:
		// Envelope reached the writer-facing queue; deliberately do not reply.
	case <-time.After(time.Second):
		t.Fatal("call was not delivered to daemon")
	}

	if !h.EvictDevice(7, "dev-7") {
		t.Fatal("expected matching device eviction")
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrNoDaemonConnected) {
			t.Fatalf("Call after eviction: got %v, want ErrNoDaemonConnected", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending Call did not stop after eviction")
	}
}
