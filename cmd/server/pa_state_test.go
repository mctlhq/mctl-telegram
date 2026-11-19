package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
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
	started, err := startPAState(ctx, &config.Config{}, off)
	if err != nil || started || off.purges != 0 {
		t.Fatalf("off: started=%v err=%v purges=%d, want nothing", started, err, off.purges)
	}

	failing := &purgeStore{err: errors.New("db down")}
	started, err = startPAState(ctx, &config.Config{PAEnabled: true}, failing)
	if err == nil || started || failing.purges != 1 {
		t.Fatalf("failing purge: started=%v err=%v purges=%d, want a refusal", started, err, failing.purges)
	}

	// Enabled with a working purge: purge first, then the sweeper runs.
	swept := make(chan struct{})
	ok := &purgeStore{swept: swept}
	started, err = startPAState(ctx, &config.Config{PAEnabled: true}, ok)
	if err != nil || !started || ok.purges != 1 {
		t.Fatalf("enabled: started=%v err=%v purges=%d, want started after one purge", started, err, ok.purges)
	}
	select {
	case <-swept:
	case <-time.After(5 * time.Second):
		t.Fatal("enabled: the sweeper never ran")
	}
}
