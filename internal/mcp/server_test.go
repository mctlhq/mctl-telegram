package mcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

func TestServer_WithVersion(t *testing.T) {
	s := &Server{}
	if got := s.WithVersion("1.2.3").Version; got != "1.2.3" {
		t.Fatalf("Version = %q, want %q", got, "1.2.3")
	}
}

func TestServer_WithVersion_EmptyLeavesUnset(t *testing.T) {
	s := &Server{}
	s.WithVersion("")
	if s.Version != "" {
		t.Fatalf("Version = %q, want empty (HTTPHandler applies the \"dev\" fallback)", s.Version)
	}
}

// TestWithMediaConcurrency (T4) covers WithMediaConcurrency's n<=0 "no gate"
// case and its n>0 "install a gate with n slots" case, including that the
// installed gate actually admits n holders and refuses the next.
func TestWithMediaConcurrency(t *testing.T) {
	for _, n := range []int{0, -1} {
		t.Run("unlimited", func(t *testing.T) {
			s := (&Server{}).WithMediaConcurrency(n)
			if s.mediaGate != nil {
				t.Fatalf("WithMediaConcurrency(%d).mediaGate = %v, want nil (unlimited)", n, s.mediaGate)
			}
			if err := s.mediaGate.acquire(context.Background()); err != nil {
				t.Errorf("acquire() on unlimited gate = %v, want nil", err)
			}
		})
	}

	t.Run("n=1 admits one and refuses the second", func(t *testing.T) {
		s := (&Server{}).WithMediaConcurrency(1)
		if s.mediaGate == nil {
			t.Fatal("WithMediaConcurrency(1).mediaGate = nil, want a gate")
		}
		s.mediaGate.wait = 50 * time.Millisecond
		if err := s.mediaGate.acquire(context.Background()); err != nil {
			t.Fatalf("first acquire() = %v, want nil", err)
		}
		if err := s.mediaGate.acquire(context.Background()); !errors.Is(err, errMediaBusy) {
			t.Errorf("second acquire() = %v, want errMediaBusy", err)
		}
	})

	t.Run("n=3 admits three", func(t *testing.T) {
		s := (&Server{}).WithMediaConcurrency(3)
		for i := 0; i < 3; i++ {
			if err := s.mediaGate.acquire(context.Background()); err != nil {
				t.Fatalf("acquire() #%d = %v, want nil", i, err)
			}
		}
	})
}

// TestWithMediaConcurrency_GaugeWiredInEitherOrder (T4) verifies the media
// gate's in-flight gauge ends up connected to a wired *metrics.Registry
// regardless of whether WithMetrics or WithMediaConcurrency runs first, and
// that the gate still enforces its limit with no gauge when no
// *metrics.Registry is ever wired.
func TestWithMediaConcurrency_GaugeWiredInEitherOrder(t *testing.T) {
	assertGaugeTracksOneHeldSlot := func(t *testing.T, s *Server, m *metrics.Registry) {
		t.Helper()
		if err := s.mediaGate.acquire(context.Background()); err != nil {
			t.Fatalf("acquire() = %v, want nil", err)
		}
		if got := testutil.ToFloat64(m.MediaInflight); got != 1 {
			t.Errorf("MediaInflight while holding a slot = %v, want 1", got)
		}
		s.mediaGate.release()
		if got := testutil.ToFloat64(m.MediaInflight); got != 0 {
			t.Errorf("MediaInflight after release = %v, want 0", got)
		}
	}

	t.Run("WithMetrics then WithMediaConcurrency", func(t *testing.T) {
		m := metrics.New()
		s := (&Server{}).WithMetrics(m).WithMediaConcurrency(1)
		assertGaugeTracksOneHeldSlot(t, s, m)
	})

	t.Run("WithMediaConcurrency then WithMetrics", func(t *testing.T) {
		m := metrics.New()
		s := (&Server{}).WithMediaConcurrency(1).WithMetrics(m)
		assertGaugeTracksOneHeldSlot(t, s, m)
	})

	t.Run("no metrics wired at all", func(t *testing.T) {
		s := (&Server{}).WithMediaConcurrency(1)
		// Shrink the wait so the refused second acquire below doesn't block
		// this test for the full 2s production default.
		s.mediaGate.wait = 50 * time.Millisecond
		if err := s.mediaGate.acquire(context.Background()); err != nil {
			t.Fatalf("acquire() = %v, want nil", err)
		}
		if err := s.mediaGate.acquire(context.Background()); !errors.Is(err, errMediaBusy) {
			t.Errorf("second acquire() = %v, want errMediaBusy", err)
		}
		s.mediaGate.release()
	})
}
