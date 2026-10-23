// Package turn implements the ConversationTurn v1 coalescer: a pure state
// machine that groups a burst of message events of one conversation into a
// single turn. It performs no I/O, never reads the clock and starts no
// goroutines; time is supplied by the caller through Event.At and Tick.
//
// In this slice nothing in production imports the package.
package turn

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// State is the lifecycle state of a turn.
type State string

const (
	StateCollecting State = "COLLECTING"
	StateReady      State = "READY"
	StateClaimed    State = "CLAIMED"
	StateDone       State = "DONE"
)

// ErrInvalidTransition is returned for any transition other than
// COLLECTING -> READY -> CLAIMED -> DONE, and for unknown turn ids.
var ErrInvalidTransition = errors.New("turn: invalid transition")

// Config holds the coalescing limits. Every limit must be positive.
type Config struct {
	QuietMS   int64
	MaxWaitMS int64
	MaxMsgs   int
	MaxBytes  int
}

// Event is one message event offered to the coalescer.
type Event struct {
	ID         string
	SessionKey string
	At         time.Time
	Bytes      int
}

// Turn is a group of events of one session.
type Turn struct {
	TurnID         string
	SessionKey     string
	SourceEventIDs []string // arrival order
	WindowOpenedAt time.Time
	LastEventAt    time.Time
	// Config snapshot taken when the turn was opened.
	QuietMS   int64
	MaxWaitMS int64
	MaxMsgs   int
	MaxBytes  int
	Bytes     int
	State     State
}

// SessionKey returns the session key for a conversation:
// "telegram:<user_id>:<peer_tg_id>", where user_id is users.id.
func SessionKey(userID, peerTGID int64) string {
	return "telegram:" + strconv.FormatInt(userID, 10) + ":" + strconv.FormatInt(peerTGID, 10)
}

// Coalescer groups events into turns. It is not safe for concurrent use.
type Coalescer struct {
	cfg   Config
	open  map[string]*Turn // session key -> COLLECTING turn
	turns map[string]*Turn // turn id -> turn
}

// New validates cfg and returns an empty Coalescer.
func New(cfg Config) (*Coalescer, error) {
	if cfg.QuietMS <= 0 || cfg.MaxWaitMS <= 0 || cfg.MaxMsgs <= 0 || cfg.MaxBytes <= 0 {
		return nil, fmt.Errorf("turn: all limits must be > 0: %+v", cfg)
	}
	return &Coalescer{cfg: cfg, open: map[string]*Turn{}, turns: map[string]*Turn{}}, nil
}

func turnID(sessionKey, firstEventID string) string {
	sum := sha256.Sum256([]byte(sessionKey + firstEventID))
	return "turn:v1:" + hex.EncodeToString(sum[:])[:24]
}

func ms(d time.Duration) int64 { return d.Milliseconds() }

// Offer adds ev to its session and returns the turns that became READY
// because of it (in order). The event's own turn is not in the result unless
// it was closed by this very event.
func (c *Coalescer) Offer(ev Event) []Turn {
	var closed []Turn
	if cur := c.open[ev.SessionKey]; cur != nil {
		joins := ms(ev.At.Sub(cur.LastEventAt)) <= cur.QuietMS &&
			ms(ev.At.Sub(cur.WindowOpenedAt)) <= cur.MaxWaitMS &&
			len(cur.SourceEventIDs)+1 <= cur.MaxMsgs &&
			cur.Bytes+ev.Bytes <= cur.MaxBytes
		if joins {
			cur.SourceEventIDs = append(cur.SourceEventIDs, ev.ID)
			cur.Bytes += ev.Bytes
			cur.LastEventAt = ev.At
			if len(cur.SourceEventIDs) >= cur.MaxMsgs {
				closed = append(closed, c.ready(cur))
			}
			return closed
		}
		closed = append(closed, c.ready(cur))
	}
	t := &Turn{
		TurnID:         turnID(ev.SessionKey, ev.ID),
		SessionKey:     ev.SessionKey,
		SourceEventIDs: []string{ev.ID},
		WindowOpenedAt: ev.At,
		LastEventAt:    ev.At,
		QuietMS:        c.cfg.QuietMS,
		MaxWaitMS:      c.cfg.MaxWaitMS,
		MaxMsgs:        c.cfg.MaxMsgs,
		MaxBytes:       c.cfg.MaxBytes,
		Bytes:          ev.Bytes,
		State:          StateCollecting,
	}
	c.turns[t.TurnID] = t
	c.open[t.SessionKey] = t
	// A single oversized event, or MaxMsgs == 1, forms its own READY turn.
	if t.Bytes >= t.MaxBytes || len(t.SourceEventIDs) >= t.MaxMsgs {
		closed = append(closed, c.ready(t))
	}
	return closed
}

// Tick closes every COLLECTING turn whose quiet window or maximum wait has
// passed at now, and returns them.
func (c *Coalescer) Tick(now time.Time) []Turn {
	var closed []Turn
	for _, t := range c.open {
		if ms(now.Sub(t.LastEventAt)) > t.QuietMS || ms(now.Sub(t.WindowOpenedAt)) > t.MaxWaitMS {
			closed = append(closed, c.ready(t))
		}
	}
	sortTurns(closed)
	return closed
}

func sortTurns(ts []Turn) {
	// insertion sort by (WindowOpenedAt, TurnID): deterministic output
	// regardless of map iteration order.
	for i := 1; i < len(ts); i++ {
		for j := i; j > 0 && less(ts[j], ts[j-1]); j-- {
			ts[j], ts[j-1] = ts[j-1], ts[j]
		}
	}
}

func less(a, b Turn) bool {
	if !a.WindowOpenedAt.Equal(b.WindowOpenedAt) {
		return a.WindowOpenedAt.Before(b.WindowOpenedAt)
	}
	return a.TurnID < b.TurnID
}

func (c *Coalescer) ready(t *Turn) Turn {
	t.State = StateReady
	delete(c.open, t.SessionKey)
	return snapshot(t)
}

func snapshot(t *Turn) Turn {
	cp := *t
	cp.SourceEventIDs = append([]string(nil), t.SourceEventIDs...)
	return cp
}

func (c *Coalescer) transition(id string, from, to State) error {
	t := c.turns[id]
	if t == nil || t.State != from {
		return fmt.Errorf("%w: %s -> %s for %q", ErrInvalidTransition, from, to, id)
	}
	t.State = to
	return nil
}

// Claim moves a READY turn to CLAIMED.
func (c *Coalescer) Claim(turnID string) error {
	return c.transition(turnID, StateReady, StateClaimed)
}

// Done moves a CLAIMED turn to DONE.
func (c *Coalescer) Done(turnID string) error {
	return c.transition(turnID, StateClaimed, StateDone)
}
