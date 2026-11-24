package pa

// streaming.go is the flag and the sender seam of draft streaming (issue
// #1431): a presentation side channel next to the unchanged reply path. A
// draft is ephemeral, is never stored and never enters the outbox; the
// persisted answer still goes through serveReply and the outbox once.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// StreamingFlagEnv switches draft streaming on. It is re-read on every
// claim and every draft: missing or empty is off, "true" is on, and
// anything else is unreadable and fails closed (off).
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

// draftLimiter caps drafts per job, in memory like the presence state.
type draftLimiter struct {
	mu   sync.Mutex
	jobs map[int64]*draftCount
}

type draftCount struct {
	last time.Time
	n    int
}

func newDraftLimiter() *draftLimiter { return &draftLimiter{jobs: map[int64]*draftCount{}} }

// allow reports whether job may send a draft at now, and counts it.
func (d *draftLimiter) allow(job int64, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.jobs[job]
	if c == nil {
		c = &draftCount{}
		d.jobs[job] = c
	}
	if c.n >= draftMaxPerJob || (c.n > 0 && now.Sub(c.last) < draftMinInterval) {
		return false
	}
	c.n++
	c.last = now
	return true
}

func (d *draftLimiter) drop(job int64) {
	d.mu.Lock()
	delete(d.jobs, job)
	d.mu.Unlock()
}
