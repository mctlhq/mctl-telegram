package agentworker

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// limitPoller serves a fixed queue of jobs and records the limit of each poll.
type limitPoller struct {
	mu     sync.Mutex
	queue  []JobEnvelope
	limits []int
}

func (p *limitPoller) PollEvents(ctx context.Context, limit int) ([]JobEnvelope, error) {
	p.mu.Lock()
	p.limits = append(p.limits, limit)
	n := min(limit, len(p.queue))
	out := append([]JobEnvelope(nil), p.queue[:n]...)
	p.queue = p.queue[n:]
	p.mu.Unlock()
	if n == 0 {
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Millisecond):
		}
	}
	return out, nil
}

type gateRunner struct {
	inflight, peak int32
	started        chan int64
	release        chan struct{}
	finished       int32
}

func (r *gateRunner) Run(ctx context.Context, job JobEnvelope) error {
	n := atomic.AddInt32(&r.inflight, 1)
	for {
		p := atomic.LoadInt32(&r.peak)
		if n <= p || atomic.CompareAndSwapInt32(&r.peak, p, n) {
			break
		}
	}
	r.started <- job.JobID
	<-r.release
	atomic.AddInt32(&r.inflight, -1)
	atomic.AddInt32(&r.finished, 1)
	return nil
}

func TestWorkerPool_RunsJobsOfDifferentConversationsTogether(t *testing.T) { // T2.1, T2.3
	p := &limitPoller{queue: []JobEnvelope{{JobID: 1, ConversationID: 1}, {JobID: 2, ConversationID: 2}, {JobID: 3, ConversationID: 3}}}
	r := &gateRunner{started: make(chan int64, 10), release: make(chan struct{})}
	w := NewWorker(p, r).WithConcurrency(2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Loop(ctx); close(done) }()
	for i := 0; i < 2; i++ {
		select {
		case <-r.started:
		case <-time.After(2 * time.Second):
			t.Fatal("two jobs were not in flight together")
		}
	}
	// Both slots are busy: the third job must not be claimed yet.
	time.Sleep(50 * time.Millisecond)
	p.mu.Lock()
	for _, l := range p.limits {
		if l > 2 {
			t.Fatalf("poll limit %d exceeds the free slots", l)
		}
	}
	remaining := len(p.queue)
	p.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("queue has %d jobs left, want 1 (no claim without a free slot)", remaining)
	}
	cancel()
	close(r.release) // T2.5: Loop returns only after the runners do
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Loop did not return")
	}
	if atomic.LoadInt32(&r.finished) < 2 {
		t.Fatalf("Loop returned with %d finished runners", r.finished)
	}
}

func TestWorkerPool_SameConversationNeverOverlaps(t *testing.T) { // defence in depth
	p := &limitPoller{queue: []JobEnvelope{{JobID: 1, ConversationID: 7}, {JobID: 2, ConversationID: 7}}}
	r := &gateRunner{started: make(chan int64, 10), release: make(chan struct{}, 10)}
	r.release <- struct{}{}
	r.release <- struct{}{}
	w := NewWorker(p, r).WithConcurrency(4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Loop(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&r.finished) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if atomic.LoadInt32(&r.finished) != 2 || atomic.LoadInt32(&r.peak) != 1 {
		t.Fatalf("finished=%d peak=%d, want 2 and 1", r.finished, r.peak)
	}
}

// handOffRunner blocks the first job it runs until release closes and then
// returns err1; every later job returns nil at once.
type handOffRunner struct {
	started chan int64
	release chan struct{}
	err1    error
	runs    int32
}

func (r *handOffRunner) Run(ctx context.Context, job JobEnvelope) error {
	r.started <- job.JobID
	if atomic.AddInt32(&r.runs, 1) == 1 {
		<-r.release
		return r.err1
	}
	return nil
}

// runHandOff runs two jobs of one conversation with concurrency 2, so job 2
// is claimed while job 1 still runs here, and returns the worker's log.
func runHandOff(t *testing.T, err1 error) string {
	t.Helper()
	var buf bytes.Buffer
	var mu sync.Mutex
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &limitPoller{queue: []JobEnvelope{{JobID: 1, ConversationID: 7}, {JobID: 2, ConversationID: 7}}}
	r := &handOffRunner{started: make(chan int64, 10), release: make(chan struct{}), err1: err1}
	w := NewWorker(p, r).WithConcurrency(2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Loop(ctx); close(done) }()
	waitStarted := func() int64 {
		select {
		case id := <-r.started:
			return id
		case <-time.After(2 * time.Second):
			t.Fatal("a job did not start")
			return 0
		}
	}
	first := waitStarted()
	// The other job is claimed in the same poll and waits at the gate.
	time.Sleep(50 * time.Millisecond)
	close(r.release)
	if second := waitStarted(); second == first {
		t.Fatalf("job %d started twice", first)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return buf.String()
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

const gateErrorMsg = "claimed a job of a conversation already running here"

func TestWorkerPool_HandOffAfterCompletedJobIsNotAnError(t *testing.T) { // #886
	log := runHandOff(t, nil)
	if strings.Contains(log, gateErrorMsg) {
		t.Fatalf("hand-off after a completed job logged the gate ERROR:\n%s", log)
	}
	if !strings.Contains(log, "waited for the previous job of this conversation to exit") {
		t.Fatalf("job 2 did not wait at the gate:\n%s", log)
	}
}

func TestWorkerPool_WaitBehindUncompletedJobIsAnError(t *testing.T) { // #886
	log := runHandOff(t, errors.New("turn failed"))
	if !strings.Contains(log, "level=ERROR") || !strings.Contains(log, gateErrorMsg) {
		t.Fatalf("waiting behind an uncompleted job did not log the gate ERROR:\n%s", log)
	}
}

func TestWorkerWithConcurrencyClamps(t *testing.T) {
	if got := NewWorker(nil, nil).WithConcurrency(0).concurrency; got != 1 {
		t.Fatalf("0 -> %d", got)
	}
	if got := NewWorker(nil, nil).WithConcurrency(99).concurrency; got != MaxConcurrency {
		t.Fatalf("99 -> %d", got)
	}
}
