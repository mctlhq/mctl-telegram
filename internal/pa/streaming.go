package pa

// streaming.go is the flag and the sender seam of draft streaming (issue
// #1431): a presentation side channel next to the unchanged reply path. A
// draft is ephemeral, is never stored and never enters the outbox; the
// persisted answer still goes through serveReply and the outbox once.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// StreamingFlagEnv switches draft streaming on. It is re-read on every
// claim, draft, tool status and draft refresh: missing or empty is off,
// "true" is on, and anything else is unreadable, which is an error to the
// caller and never "on".
const StreamingFlagEnv = "PA_STREAMING_ENABLED"

// streamingOn reads the flag.
func streamingOn(getenv func(string) string) (bool, error) {
	switch v := strings.TrimSpace(getenv(StreamingFlagEnv)); v {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("pa: %s must be true or false", StreamingFlagEnv)
	}
}

// DraftSender shows a draft in a private chat (*output.Sender).
type DraftSender interface {
	SendDraft(ctx context.Context, chatID, draftID int64, text safetext.Text) error
}

const (
	// draftRefresh re-sends the last draft before Telegram lets it lapse
	// (about 30 s).
	draftRefresh = 20 * time.Second
	// draftCallDeadline bounds one sendMessageDraft.
	draftCallDeadline = 5 * time.Second
	// draftMinInterval and draftMaxPerJob cap the drafts one job may send.
	draftMinInterval = 700 * time.Millisecond
	draftMaxPerJob   = 120
	// maxDraftBody bounds a draft request: one part, even fully escaped.
	maxDraftBody = 6*safetext.MaxPartUTF16 + 1<<10
)

// errStreamingOff ends a job's draft presence when the flag is no longer on.
var errStreamingOff = errors.New("pa: streaming is off")

// draftLimiter caps the drafts one attempt of a job may ask for, whatever
// the worker does. It is in memory per replica, like the presence state.
// It counts every request that reaches it, shown or not, and keeps
// counting after the job stopped, so a worker that keeps posting for a
// stopped job is answered 429 and costs no further job read. Entries are
// forgotten draftLimiterTTL after their last request, which is longer than
// any lease.
type draftLimiter struct {
	minInterval time.Duration
	maxPerJob   int

	mu   sync.Mutex
	jobs map[draftKey]*draftCount
}

type draftKey struct {
	job     int64
	attempt int
}

type draftCount struct {
	last time.Time
	n    int
}

const (
	draftLimiterTTL   = time.Hour
	draftLimiterSweep = 1024 // entries above which allow sweeps old ones
)

func newDraftLimiter() *draftLimiter {
	return &draftLimiter{minInterval: draftMinInterval, maxPerJob: draftMaxPerJob, jobs: map[draftKey]*draftCount{}}
}

// allow reports whether ref's attempt may send a draft at now, and counts
// it.
func (d *draftLimiter) allow(ref jobs.Ref, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.jobs) > draftLimiterSweep {
		for k, c := range d.jobs {
			if now.Sub(c.last) > draftLimiterTTL {
				delete(d.jobs, k)
			}
		}
	}
	k := draftKey{ref.JobID, ref.Attempt}
	c := d.jobs[k]
	if c == nil {
		c = &draftCount{}
		d.jobs[k] = c
	}
	if c.n >= d.maxPerJob || (c.n > 0 && now.Sub(c.last) < d.minInterval) {
		return false
	}
	c.n++
	c.last = now
	return true
}
