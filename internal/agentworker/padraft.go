package agentworker

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Draft batching defaults (to be tuned on preview).
const (
	paDraftMinInterval = time.Second
	paDraftMinDelta    = 64 // UTF-16 units
	paDraftTimeout     = 3 * time.Second
)

// paDrafter posts a job's growing answer text to the server as drafts. It
// is presentation only: latest text wins, one post is in flight at most,
// every failure is ignored, and it never changes the run's outcome. Close
// it before the reply is posted.
type paDrafter struct {
	w     *PAWorker
	token string
	ctx   context.Context
	stop  context.CancelFunc
	done  chan struct{}
	wake  chan struct{}

	minInterval time.Duration
	minDelta    int

	mu      sync.Mutex
	latest  string
	stopped bool
}

func newPADrafter(parent context.Context, w *PAWorker, token string) *paDrafter {
	ctx, cancel := context.WithCancel(parent)
	d := &paDrafter{
		w: w, token: token, ctx: ctx, stop: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1),
		minInterval: paDraftMinInterval, minDelta: paDraftMinDelta,
	}
	go d.loop()
	return d
}

// update records the accumulated text of the current model call. A text
// shorter than the previous one starts a new call's text.
func (d *paDrafter) update(text string) {
	d.mu.Lock()
	d.latest = text
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// close stops the drafter and waits for an in-flight post to end.
func (d *paDrafter) close() {
	d.mu.Lock()
	d.stopped = true
	d.mu.Unlock()
	d.stop()
	<-d.done
}

func (d *paDrafter) loop() {
	defer close(d.done)
	var (
		posted   string
		postedAt time.Time
		timer    = time.NewTimer(time.Hour)
	)
	defer timer.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.wake:
		case <-timer.C:
		}
		d.mu.Lock()
		text, stopped := d.latest, d.stopped
		d.mu.Unlock()
		if stopped || text == "" || text == posted {
			continue
		}
		if safetext.UTF16Len(text) > safetext.MaxPartUTF16 {
			// The server would skip it, and every longer text too.
			return
		}
		if posted != "" && len(text) >= len(posted) && safetext.UTF16Len(text)-safetext.UTF16Len(posted) < d.minDelta {
			continue
		}
		if wait := d.minInterval - time.Since(postedAt); !postedAt.IsZero() && wait > 0 {
			timer.Reset(wait)
			continue
		}
		postedAt = time.Now()
		ctx, cancel := context.WithTimeout(d.ctx, paDraftTimeout)
		_, err := d.w.post(ctx, PARouteDraft, d.token, map[string]string{"text": text}, nil)
		cancel()
		posted = text
		var he *paHTTPError
		if errors.As(err, &he) && (he.Status == http.StatusNotFound || he.Status == http.StatusConflict) {
			// Streaming is off or the run is over: no more drafts.
			return
		}
	}
}
