package main

import (
	"context"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// purgeStore records PurgeUnmarkedPAState calls; every other method panics
// through the nil embedded interface, so a call to one fails the test.
type purgeStore struct {
	convo.Store
	purges int
	err    error
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
}
