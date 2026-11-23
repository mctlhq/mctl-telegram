package pa

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// typingRecorder records the typing statuses sent, per chat.
type typingRecorder struct {
	mu    sync.Mutex
	chats map[int64]int
	err   error
}

func (r *typingRecorder) SendTyping(_ context.Context, chat int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.chats == nil {
		r.chats = map[int64]int{}
	}
	r.chats[chat]++
	return r.err
}

func (r *typingRecorder) count(chat int64) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.chats[chat]
}

func withTyping(r *typingRecorder) rlOption {
	return func(c *RunLoopConfig, _ *runLoopHarness) { c.Typing = r }
}

// fastTyping shortens the status interval so a test sees it repeat.
func fastTyping(t *testing.T, l *RunLoop) {
	t.Helper()
	if l.typing == nil {
		t.Fatal("no typing tracker: RunLoopConfig.Typing was not wired")
	}
	l.typing.interval = 5 * time.Millisecond
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// settled checks that no status is sent any more: the count holds still
// over several intervals.
func settled(t *testing.T, r *typingRecorder, chat int64) int {
	t.Helper()
	n := r.count(chat)
	time.Sleep(50 * time.Millisecond)
	if m := r.count(chat); m != n {
		t.Fatalf("typing status still sent after the run stopped: %d -> %d", n, m)
	}
	return n
}

// TestRunLoop_TypingWhileRunning: a claimed run shows "typing" in the
// principal's chat, repeated while it runs, and the status stops when the
// reply arrives, before the answer is sent.
func TestRunLoop_TypingWhileRunning(t *testing.T) {
	rec := &typingRecorder{}
	h := newRunLoopHarness(t, withTyping(rec))
	fastTyping(t, h.loop)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	if rec.count(aliceID) != 0 {
		t.Fatal("typing before the run was claimed")
	}
	c := h.mustClaim()
	waitFor(t, "repeated typing status", func() bool { return rec.count(aliceID) >= 3 })
	if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 100}); w.Code != http.StatusOK {
		t.Fatalf("turn: %d %s", w.Code, w.Body)
	}
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "hi Alice"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
	if n := h.loop.typing.active(); n != 0 {
		t.Fatalf("status loops after the reply = %d, want 0", n)
	}
	settled(t, rec, aliceID)
	if got := h.sender.to(aliceID); len(got) != 1 || got[0] != "hi Alice" {
		t.Fatalf("sent %q", got)
	}
	if rec.count(bobID) != 0 {
		t.Fatal("typing shown in another principal's chat")
	}
}

// TestRunLoop_TypingStopsWhenRunStops: a run refused at a step (here its
// conversation closed) stops its status, as a reply would.
func TestRunLoop_TypingStopsWhenRunStops(t *testing.T) {
	rec := &typingRecorder{}
	h := newRunLoopHarness(t, withTyping(rec))
	fastTyping(t, h.loop)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	waitFor(t, "typing status", func() bool { return rec.count(aliceID) >= 1 })
	if _, err := h.convoHarness.store.DB.Exec(`UPDATE pa_conversations SET closed_at_ms = 1 WHERE principal = $1`, aliceID); err != nil {
		t.Fatal(err)
	}
	if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 100}); w.Code != http.StatusConflict {
		t.Fatalf("turn: %d", w.Code)
	}
	if n := h.loop.typing.active(); n != 0 {
		t.Fatalf("status loops after the run stopped = %d, want 0", n)
	}
	settled(t, rec, aliceID)
}

// TestRunLoop_NoTypingWithoutSender: Typing is optional; a run loop
// without it runs as before.
func TestRunLoop_NoTypingWithoutSender(t *testing.T) {
	h := newRunLoopHarness(t)
	if h.loop.typing != nil {
		t.Fatal("a typing tracker without a sender")
	}
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "hi"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
}

// TestTyping_Bounds: the status stops on its own after the idle bound, at
// the lease end, and on the first failed send.
func TestTyping_Bounds(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		var mu sync.Mutex
		now := time.Unix(1_000_000, 0)
		clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
		rec := &typingRecorder{}
		tr := newTypingTracker(rec, clock)
		tr.interval = time.Millisecond
		tr.start(aliceID, 1, time.Now().Add(time.Minute))
		waitFor(t, "typing status", func() bool { return rec.count(aliceID) >= 2 })
		// Activity within the bound keeps it alive.
		mu.Lock()
		now = now.Add(tr.idle - time.Second)
		mu.Unlock()
		tr.touch(1)
		mu.Lock()
		now = now.Add(tr.idle - time.Second)
		mu.Unlock()
		n := rec.count(aliceID)
		waitFor(t, "status after touch", func() bool { return rec.count(aliceID) > n })
		mu.Lock()
		now = now.Add(2 * time.Second)
		mu.Unlock()
		waitFor(t, "idle stop", func() bool { return tr.active() == 0 })
		settled(t, rec, aliceID)
	})
	t.Run("lease end", func(t *testing.T) {
		rec := &typingRecorder{}
		tr := newTypingTracker(rec, time.Now)
		tr.interval = time.Millisecond
		tr.start(aliceID, 1, time.Now().Add(20*time.Millisecond))
		waitFor(t, "lease stop", func() bool { return tr.active() == 0 })
		settled(t, rec, aliceID)
	})
	t.Run("send error", func(t *testing.T) {
		rec := &typingRecorder{err: errors.New("Forbidden: bot was blocked by the user")}
		tr := newTypingTracker(rec, time.Now)
		tr.interval = time.Millisecond
		tr.start(aliceID, 1, time.Now().Add(time.Minute))
		waitFor(t, "stop after a failed send", func() bool { return tr.active() == 0 })
		if n := settled(t, rec, aliceID); n != 1 {
			t.Fatalf("sends = %d, want 1", n)
		}
	})
	t.Run("one loop per job", func(t *testing.T) {
		rec := &typingRecorder{}
		tr := newTypingTracker(rec, time.Now)
		tr.interval = time.Hour
		tr.start(aliceID, 1, time.Now().Add(time.Minute))
		tr.start(aliceID, 1, time.Now().Add(time.Minute))
		waitFor(t, "first status", func() bool { return rec.count(aliceID) >= 1 })
		if tr.active() != 1 {
			t.Fatalf("loops = %d, want 1", tr.active())
		}
		tr.stop(1)
		tr.stop(1)
		if n := settled(t, rec, aliceID); n != 1 {
			t.Fatalf("sends = %d, want 1", n)
		}
	})
}

// TestRunLoop_TypingAfterQueuedRun: a message that queued a run shows the
// status once after its commit, before any worker claims the job. An
// update that queued nothing, a stale mark and a loop without a sender
// show nothing.
func TestRunLoop_TypingAfterQueuedRun(t *testing.T) {
	ctx := context.Background()
	rec := &typingRecorder{}
	h := newRunLoopHarness(t, withTyping(rec))
	h.consent(aliceID)
	h.loop.TypingAfter(ctx, aliceID)
	h.loop.WaitDeliveries()
	if n := rec.count(aliceID); n != 0 {
		t.Fatalf("typing after the consent flow, which queued no run = %d", n)
	}

	h.text(aliceID, "hello")
	h.loop.TypingAfter(ctx, bobID)
	h.loop.TypingAfter(ctx, aliceID)
	h.loop.TypingAfter(ctx, aliceID) // the mark is taken once
	h.loop.WaitDeliveries()
	if a, b := rec.count(aliceID), rec.count(bobID); a != 1 || b != 0 {
		t.Fatalf("typing shown: principal %d, another principal %d; want 1, 0", a, b)
	}
	h.finishRun("hi")

	// A mark whose transaction never committed is ignored once it is old.
	h.text(aliceID, "again")
	before := rec.count(aliceID) // the claimed run above showed its own
	h.now = h.now.Add(typingQueuedFor + time.Second)
	h.loop.TypingAfter(ctx, aliceID)
	h.loop.WaitDeliveries()
	if n := rec.count(aliceID); n != before {
		t.Fatalf("typing shown for a stale mark: %d -> %d", before, n)
	}

	// No sender: nothing, and no panic.
	plain := &RunLoop{}
	plain.TypingAfter(ctx, aliceID)
	plain.WaitDeliveries()
}
