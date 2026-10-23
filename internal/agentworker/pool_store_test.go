package agentworker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// storePoller claims through a real db.Store, so the server's
// per-conversation claim rule, not only the worker's local guard, decides
// what runs.
type storePoller struct {
	s   *db.Store
	uid int64
}

func (p *storePoller) PollEvents(ctx context.Context, limit int) ([]JobEnvelope, error) {
	jobs, err := p.s.ClaimAgentJobs(ctx, "r", p.uid, limit)
	if err != nil {
		return nil, err
	}
	if len(jobs) == 0 {
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Millisecond):
		}
	}
	out := make([]JobEnvelope, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, JobEnvelope{JobID: j.ID, EventID: j.EventID, ConversationID: j.ConversationID, Attempt: j.Attempts})
	}
	return out, nil
}

// storeRunner records the in-flight count per conversation and completes
// each job in the store, which is what makes the next one claimable.
type storeRunner struct {
	s        *db.Store
	mu       sync.Mutex
	inflight map[int64]int
	peak     map[int64]int
	done     int
}

func (r *storeRunner) Run(ctx context.Context, job JobEnvelope) error {
	r.mu.Lock()
	r.inflight[job.ConversationID]++
	if r.inflight[job.ConversationID] > r.peak[job.ConversationID] {
		r.peak[job.ConversationID] = r.inflight[job.ConversationID]
	}
	r.mu.Unlock()
	time.Sleep(3 * time.Millisecond)
	r.mu.Lock()
	r.inflight[job.ConversationID]--
	r.mu.Unlock()
	if err := r.s.CompleteAgentJob(ctx, job.JobID, job.Attempt, db.JobCompleted, ""); err != nil {
		return err
	}
	r.mu.Lock()
	r.done++
	r.mu.Unlock()
	return nil
}

// T2.2: against a real store and its claim, two jobs of one conversation
// never overlap at any pool size; the peak per conversation is 1.
func TestWorkerPool_RealStoreSameConversationNeverOverlaps(t *testing.T) { // T2.2
	for _, n := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			ctx := context.Background()
			conn, err := db.Open(ctx, fmt.Sprintf("file:pool%d?mode=memory&cache=shared", n), 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := db.MigrateCached(ctx, conn); err != nil {
				t.Fatal(err)
			}
			c, err := crypto.New(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			s := &db.Store{DB: conn, Crypt: c}
			uid, err := s.EnsureUser(ctx, "owner", "", "test")
			if err != nil {
				t.Fatal(err)
			}
			const perConv = 4
			for _, peer := range []int64{555, 556} { // Alice, Bob
				conv, err := s.EnsureConversation(ctx, uid, peer, "peer", "Peer")
				if err != nil {
					t.Fatal(err)
				}
				for m := int64(0); m < perConv; m++ {
					if _, ok, err := s.InsertEventEnqueueJobAndTouch(ctx, db.IncomingEvent{
						EventID: fmt.Sprintf("evt:v1:1:%d:%d", peer, 10+m), UserID: uid, Kind: db.EventKindPrivateMessage,
						ChatTGID: peer, SenderTGID: peer, MessageID: 10 + m, Body: "hi",
					}, conv.ID); err != nil || !ok {
						t.Fatalf("enqueue: %v %v", ok, err)
					}
				}
			}
			r := &storeRunner{s: s, inflight: map[int64]int{}, peak: map[int64]int{}}
			w := NewWorker(&storePoller{s: s, uid: uid}, r).WithConcurrency(n)
			lctx, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() { _ = w.Loop(lctx); close(done) }()
			deadline := time.Now().Add(5 * time.Second)
			for {
				r.mu.Lock()
				finished := r.done
				r.mu.Unlock()
				if finished == 2*perConv {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("finished %d of %d jobs", finished, 2*perConv)
				}
				time.Sleep(2 * time.Millisecond)
			}
			cancel()
			<-done
			for conv, p := range r.peak {
				if p != 1 {
					t.Fatalf("conversation %d peaked at %d in flight", conv, p)
				}
			}
		})
	}
}
