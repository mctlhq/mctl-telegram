package pa

// typing.go shows "typing..." in the principal's chat while a run is in
// progress, so a message is not met with silence until the whole answer
// arrives. It is presentation only: it carries no text, decides nothing,
// and a failed or skipped status changes no run.
//
// The status is shown once when a message queues a run (TypingAfter). A
// run's repeated status starts when the worker is handed the job (serveClaim),
// is refreshed by every turn and tool admission, and stops when the reply
// arrives, when the run is stopped or released, after typingIdle with no
// activity, or at the lease end, whichever comes first. The idle bound
// also covers a run whose reply reaches another replica: that replica
// cannot stop this one's status, which then lapses on its own.

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// TypingSender shows the typing status in a private chat (*output.Sender).
type TypingSender interface {
	SendTyping(ctx context.Context, chatID int64) error
}

const (
	// typingInterval repeats the status inside Telegram's ~5s display.
	typingInterval = 4 * time.Second
	// typingIdle stops the status when the run shows no activity (claim,
	// turn, tool admission) for this long: a model call longer than this
	// leaves the chat quiet rather than "typing" forever.
	typingIdle = 2 * time.Minute
	// typingCallDeadline bounds one sendChatAction.
	typingCallDeadline = 5 * time.Second
)

type typingRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	last   time.Time // guarded by typingTracker.mu
}

// typingTracker runs at most one status loop per job.
type typingTracker struct {
	sender   TypingSender
	now      func() time.Time
	interval time.Duration
	idle     time.Duration

	mu   sync.Mutex
	runs map[int64]*typingRun // by job id
}

func newTypingTracker(sender TypingSender, now func() time.Time) *typingTracker {
	if sender == nil {
		return nil
	}
	return &typingTracker{sender: sender, now: now, interval: typingInterval, idle: typingIdle, runs: map[int64]*typingRun{}}
}

// start begins the status for job in principal's chat until until. A job
// that already has one is only refreshed.
func (t *typingTracker) start(principal, job int64, until time.Time) {
	if t == nil || principal <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if r, ok := t.runs[job]; ok {
		r.last = t.now()
		return
	}
	// The lease is on the run loop's clock; the timer runs on the remaining
	// time.
	ctx, cancel := context.WithTimeout(context.Background(), until.Sub(t.now()))
	r := &typingRun{cancel: cancel, done: make(chan struct{}), last: t.now()}
	t.runs[job] = r
	go t.loop(ctx, principal, job, r)
}

// TypingAfter shows the status once, after the update that queued a run
// committed, so the chat is not silent until a worker claims the job
// (serveClaim starts the repeated status). An update that queued no run,
// a command or a button, shows nothing. It never blocks the caller.
func (l *RunLoop) TypingAfter(ctx context.Context, principal int64) {
	t := l.typing
	if t == nil || principal <= 0 || !runQueuedIn(ctx) {
		return
	}
	l.pending.Add(1)
	go func() {
		defer l.pending.Done()
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), typingCallDeadline)
		defer cancel()
		if err := t.sender.SendTyping(cctx, principal); err != nil {
			slog.Debug("pa typing status not shown", "err", err)
		}
	}()
}

// touch records activity on job, keeping its status alive.
func (t *typingTracker) touch(job int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if r, ok := t.runs[job]; ok {
		r.last = t.now()
	}
	t.mu.Unlock()
}

// stop ends job's status and waits for its loop to exit, so no status is
// sent after the caller goes on to queue the answer.
func (t *typingTracker) stop(job int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	r, ok := t.runs[job]
	delete(t.runs, job)
	t.mu.Unlock()
	if ok {
		r.cancel()
		<-r.done
	}
}

// active reports how many status loops run (tests).
func (t *typingTracker) active() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.runs)
}

func (t *typingTracker) loop(ctx context.Context, principal, job int64, r *typingRun) {
	defer close(r.done)
	defer func() {
		t.mu.Lock()
		if t.runs[job] == r {
			delete(t.runs, job)
		}
		t.mu.Unlock()
		r.cancel()
	}()
	tick := time.NewTicker(t.interval)
	defer tick.Stop()
	for {
		t.mu.Lock()
		idle := t.now().Sub(r.last) > t.idle
		t.mu.Unlock()
		if idle {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, typingCallDeadline)
		err := t.sender.SendTyping(cctx, principal)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			// A blocked bot, a rate limit or a network failure: the status
			// is cosmetic, so it stops rather than retrying into a limit.
			slog.Debug("pa typing status stopped", "job_id", job, "err", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
