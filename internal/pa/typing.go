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

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
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
	// Draft presence (streaming.go), guarded by typingTracker.mu: the
	// loop shows typing until the first draft, then only re-sends the
	// last draft before it lapses. Nothing here is ever stored.
	ref     jobs.Ref
	drafted bool
	draft   safetext.Text
	draftAt time.Time
	pending *safetext.Text // a status to show, set by showStatus
	allow   *safetext.UserText
	wake    chan struct{}
	// sendMu serialises draft sends and ends them: stop sets stopped under
	// it, so no draft is sent after stop returns.
	sendMu  sync.Mutex
	stopped bool
}

// typingTracker runs at most one status loop per job.
type typingTracker struct {
	sender   TypingSender
	now      func() time.Time
	interval time.Duration
	idle     time.Duration
	// drafts, check and refresh are set by RunLoop when streaming is wired;
	// without drafts the tracker only shows typing.
	drafts  DraftSender
	check   func(ctx context.Context, ref jobs.Ref) error
	refresh time.Duration

	mu   sync.Mutex
	runs map[int64]*typingRun // by job id
}

func newTypingTracker(sender TypingSender, now func() time.Time) *typingTracker {
	if sender == nil {
		return nil
	}
	return &typingTracker{sender: sender, now: now, interval: typingInterval, idle: typingIdle, refresh: draftRefresh, runs: map[int64]*typingRun{}}
}

// start begins the status for job in principal's chat until until. A job
// that already has one is only refreshed.
func (t *typingTracker) start(principal, job int64, until time.Time) {
	t.begin(jobs.Ref{Principal: principal, JobID: job}, until)
}

// begin is start for a job's full ref, which the draft check needs.
func (t *typingTracker) begin(ref jobs.Ref, until time.Time) {
	principal, job := ref.Principal, ref.JobID
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
	r := &typingRun{cancel: cancel, done: make(chan struct{}), last: t.now(), ref: ref, wake: make(chan struct{}, 1)}
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
		r.sendMu.Lock()
		r.stopped = true
		r.sendMu.Unlock()
		r.cancel()
		<-r.done
	}
}

// sendDraft sends text as job's draft, unless the run was stopped. It
// never sends for a job with no presence run (other replica, stopped,
// idle): a draft needs a live run to be stopped with.
func (t *typingTracker) sendDraft(ctx context.Context, r *typingRun, principal int64, text safetext.Text) error {
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	if r.stopped || ctx.Err() != nil {
		return context.Canceled
	}
	cctx, cancel := context.WithTimeout(ctx, draftCallDeadline)
	defer cancel()
	if err := t.drafts.SendDraft(cctx, principal, draftID(r.ref), text); err != nil {
		return err
	}
	t.mu.Lock()
	r.drafted, r.draft, r.draftAt, r.last = true, text, t.now(), t.now()
	t.mu.Unlock()
	return nil
}

// draftID is the job's draft id: positive, and stable across attempts, so
// a retry animates the same draft.
func draftID(ref jobs.Ref) int64 { return ref.JobID }

// run returns job's live presence run.
func (t *typingTracker) run(job int64) *typingRun {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.runs[job]
}

// showDraft shows text as job's draft and stops its typing status. It
// reports whether the draft was sent.
func (t *typingTracker) showDraft(ctx context.Context, ref jobs.Ref, text safetext.Text) bool {
	if t == nil || t.drafts == nil {
		return false
	}
	r := t.run(ref.JobID)
	if r == nil {
		return false
	}
	t.mu.Lock()
	r.pending = nil
	t.mu.Unlock()
	return t.sendDraft(ctx, r, ref.Principal, text) == nil
}

// showStatus hands a server status to job's presence loop, which shows it
// as the job's draft. It never blocks the caller.
func (t *typingTracker) showStatus(ref jobs.Ref, text safetext.Text) {
	if t == nil || t.drafts == nil {
		return
	}
	t.mu.Lock()
	r := t.runs[ref.JobID]
	if r != nil {
		r.pending = &text
	}
	t.mu.Unlock()
	if r != nil {
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
}

// cachedAllow returns the job's cached allow-list. A later user message can
// only add tokens, so a cached list is a subset and fails closed.
func (t *typingTracker) cachedAllow(job int64) (safetext.UserText, bool) {
	if t == nil {
		return safetext.UserText{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if r := t.runs[job]; r != nil && r.allow != nil {
		return *r.allow, true
	}
	return safetext.UserText{}, false
}

func (t *typingTracker) setAllow(job int64, a safetext.UserText) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if r := t.runs[job]; r != nil {
		r.allow = &a
	}
	t.mu.Unlock()
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
		t.mu.Lock()
		pending, drafted, due := r.pending, r.drafted, r.drafted && t.now().Sub(r.draftAt) >= t.refresh
		last := r.draft
		r.pending = nil
		t.mu.Unlock()
		var err error
		switch {
		case t.drafts != nil && pending != nil:
			// A draft failure is cosmetic and never ends the loop.
			if derr := t.sendDraft(ctx, r, principal, *pending); derr != nil {
				slog.Debug("pa status draft not shown", "job_id", job, "err", derr)
			}
		case t.drafts != nil && drafted:
			if due {
				if t.check != nil {
					if cerr := t.check(ctx, r.ref); cerr != nil {
						return
					}
				}
				if derr := t.sendDraft(ctx, r, principal, last); derr != nil {
					slog.Debug("pa draft not refreshed", "job_id", job, "err", derr)
				}
			}
		default:
			cctx, cancel := context.WithTimeout(ctx, typingCallDeadline)
			err = t.sender.SendTyping(cctx, principal)
			cancel()
		}
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
		case <-r.wake:
		}
	}
}
