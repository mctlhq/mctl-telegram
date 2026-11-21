package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// purgeStore records PurgeUnmarkedPAState calls; every other method panics
// through the nil embedded interface, so a call to one fails the test.
type purgeStore struct {
	convo.Store
	purges int
	err    error
	swept  chan struct{}
}

func (p *purgeStore) SweepPAState(context.Context, time.Time, time.Time) (convo.SweepResult, error) {
	if p.swept != nil {
		close(p.swept)
		p.swept = nil
	}
	return convo.SweepResult{}, nil
}

func (p *purgeStore) PurgeUnmarkedPAState(context.Context) (int64, error) {
	p.purges++
	return 0, p.err
}

// TestStartPAState_InertByDefault: with PA_ENABLED off nothing touches PA
// state; with it on, unmarked state is purged before anything else starts,
// and a failed purge refuses to start.
func TestStartPAState_InertByDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the sweeper goroutine, if started, exits at once

	off := &purgeStore{}
	started, err := startPAState(ctx, &config.Config{}, off, nil)
	if err != nil || started || off.purges != 0 {
		t.Fatalf("off: started=%v err=%v purges=%d, want nothing", started, err, off.purges)
	}

	failing := &purgeStore{err: errors.New("db down")}
	started, err = startPAState(ctx, &config.Config{PAEnabled: true}, failing, nil)
	if err == nil || started || failing.purges != 1 {
		t.Fatalf("failing purge: started=%v err=%v purges=%d, want a refusal", started, err, failing.purges)
	}

	// Enabled with a working purge: purge first, then the sweeper runs.
	swept := make(chan struct{})
	ok := &purgeStore{swept: swept}
	started, err = startPAState(ctx, &config.Config{PAEnabled: true}, ok, nil)
	if err != nil || !started || ok.purges != 1 {
		t.Fatalf("enabled: started=%v err=%v purges=%d, want started after one purge", started, err, ok.purges)
	}
	select {
	case <-swept:
	case <-time.After(5 * time.Second):
		t.Fatal("enabled: the sweeper never ran")
	}
}

// linkExpirer signals its first ExpireStale call.
type linkExpirer struct{ called chan struct{} }

func (l *linkExpirer) ExpireStale(context.Context, int) (linking.SweepResult, error) {
	select {
	case l.called <- struct{}{}:
	default:
	}
	return linking.SweepResult{}, nil
}

// The linking sweep (#1338) starts beside the retention sweep when the PA is
// enabled and the server runs the linking flow, and never with PA_ENABLED
// off.
func TestStartPAState_StartsLinkingSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	off := &linkExpirer{called: make(chan struct{}, 1)}
	if started, err := startPAState(ctx, &config.Config{}, &purgeStore{}, off); err != nil || started {
		t.Fatalf("off: started=%v err=%v", started, err)
	}

	on := &linkExpirer{called: make(chan struct{}, 1)}
	if started, err := startPAState(ctx, &config.Config{PAEnabled: true}, &purgeStore{}, on); err != nil || !started {
		t.Fatalf("enabled: started=%v err=%v", started, err)
	}
	select {
	case <-on.called:
	case <-time.After(5 * time.Second):
		t.Fatal("enabled: the linking sweep never ran")
	}
	select {
	case <-off.called:
		t.Fatal("off: the linking sweep ran with PA_ENABLED off")
	default:
	}
}
