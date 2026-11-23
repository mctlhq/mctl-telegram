package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/pa"
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

// lockSweepStore signals its first SweepPAPrincipalLocks call.
type lockSweepStore struct{ called chan time.Time }

func (l *lockSweepStore) SweepPAPrincipalLocks(_ context.Context, before time.Time) (int64, error) {
	select {
	case l.called <- before:
	default:
	}
	return 0, nil
}

// TestStartPALockSweep_Sweeps: startPALockSweep runs a pass at once, with
// the cutoff pa.UpdatesRetention back. That it runs with PA_ENABLED off is
// TestMainStartsPALockSweepUnconditionally's job.
func TestStartPALockSweep_Sweeps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &lockSweepStore{called: make(chan time.Time, 1)}
	startPALockSweep(ctx, s)
	select {
	case before := <-s.called:
		if d := time.Since(before); d < pa.UpdatesRetention || d > pa.UpdatesRetention+time.Minute {
			t.Fatalf("lock sweep cutoff %v ago, want pa.UpdatesRetention (%v)", d, pa.UpdatesRetention)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lock sweep never ran")
	}
}

// TestMainStartsPALockSweepUnconditionally: main starts the principal lock
// sweep (#1318) exactly once, at the top level of main rather than behind
// PA_ENABLED: it is not called from startPAState, and no `if` that reads
// PAEnabled encloses the call. A lock row an account deletion kept as its
// fence must go even after the PA is turned off.
func TestMainStartsPALockSweepUnconditionally(t *testing.T) {
	sites := 0
	var mainSrc []byte
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`(?m)^(\t*)startPALockSweep\(ctx, store\)\s*$`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		n := len(regexp.MustCompile(`startPALockSweep\(`).FindAllIndex(src, -1))
		if f == "pa_locks.go" {
			n-- // the definition
		}
		if n > 0 && f != "main.go" {
			t.Fatalf("startPALockSweep called from %s, want only main.go", f)
		}
		sites += n
		if f == "main.go" {
			mainSrc = src
		}
	}
	if sites != 1 {
		t.Fatalf("startPALockSweep call sites = %d, want exactly one, in main.go", sites)
	}
	m := call.FindSubmatchIndex(mainSrc)
	if m == nil {
		t.Fatal("main.go does not call startPALockSweep(ctx, store) as a statement of its own")
	}
	// The call must sit at main's top-level indentation (one tab), not
	// inside a block such as `if cfg.PAEnabled {`.
	if indent := mainSrc[m[2]:m[3]]; string(indent) != "\t" {
		t.Fatalf("startPALockSweep is indented %d tabs in main.go, want 1 (main's top level, behind no condition)", len(indent))
	}
	body := regexp.MustCompile(`(?s)\nfunc main\(\) \{\n(.*?)\n\}\n`).FindSubmatchIndex(mainSrc)
	if body == nil || m[0] < body[2] || m[1] > body[3] {
		t.Fatal("startPALockSweep is not called from func main")
	}
}
