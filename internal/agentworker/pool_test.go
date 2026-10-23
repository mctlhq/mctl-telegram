package agentworker

import (
	"context"
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

func TestWorkerWithConcurrencyClamps(t *testing.T) {
	if got := NewWorker(nil, nil).WithConcurrency(0).concurrency; got != 1 {
		t.Fatalf("0 -> %d", got)
	}
	if got := NewWorker(nil, nil).WithConcurrency(99).concurrency; got != MaxConcurrency {
		t.Fatalf("99 -> %d", got)
	}
}
