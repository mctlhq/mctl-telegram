// Package connectfunnel answers, for every OAuth authorization_code grant,
// whether the same user and client made a successful MCP call within a fixed
// window afterwards (issue #960). A grant the client never follows up on is
// the shape of the 2026-10-30 "action discovery failed" connector failure,
// which until now only showed up by reading logs by hand.
//
// The correlation is durable: every grant is a connect_first_call row, the
// first successful tools/list or tools/call closes it, and a reconciler
// classifies the rest once their window is over. The counter
// mctl_connect_first_call_total is incremented once per row, at the moment
// its outcome is decided, so neither a restart nor a retried call can replay
// or drop an outcome.
//
// An outcome the process could not observe is "unknown", never
// "none_within_window": a grant whose row could not be written, a window that
// straddles a process start (close failures in the previous process are
// gone), and a window during which a close failed in this one.
package connectfunnel

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

const (
	// Window is how long after a grant a successful call still counts as
	// the grant's first call.
	Window = 5 * time.Minute
	// Grace is how much longer than Window the reconciler waits before it
	// judges a row. It keeps a close that is still in flight at the edge of
	// the window, and the failure it may record, ahead of the judgement.
	Grace = time.Minute
	// Retention is how long a classified row is kept before the reconciler
	// deletes it.
	Retention = 7 * 24 * time.Hour
	// ReconcileInterval is how often Run classifies and sweeps.
	ReconcileInterval = time.Minute
)

// Bounded client labels. A raw client_id never reaches a metric.
const (
	ClientClaude  = "claude"
	ClientChatGPT = "chatgpt"
	ClientOther   = "other"
)

// Reasons attached to the unknown outcome.
const (
	// ReasonInsertError: the grant's row could not be written, so the grant
	// cannot be followed at all. Counted at grant time.
	ReasonInsertError = "insert_error"
	// ReasonRestart: the row was granted before this process started. A
	// close that failed in the previous process left no trace, so its
	// absence of a close proves nothing.
	ReasonRestart = "restart"
	// ReasonCloseError: a close failed in this process while the row's
	// window was open, so the call that would have closed it may have
	// happened.
	ReasonCloseError = "close_error"
)

// Clients, Outcomes and UnknownReasons are the closed label sets, exported so
// the metrics registry can pre-initialise every series at zero.
var (
	Clients        = []string{ClientClaude, ClientChatGPT, ClientOther}
	UnknownReasons = []string{ReasonInsertError, ReasonRestart, ReasonCloseError}
)

// Error operations, the label of the store-error counter.
const (
	OpInsert   = "insert"
	OpClose    = "close"
	OpClassify = "classify"
	OpSweep    = "sweep"
)

// Ops is the closed set of error operations.
var Ops = []string{OpInsert, OpClose, OpClassify, OpSweep}

// Store is the subset of *db.Store the tracker uses.
type Store interface {
	InsertConnectGrant(ctx context.Context, userID int64, clientID, client string, grantedAt time.Time) error
	CloseConnectGrants(ctx context.Context, userID int64, clientID string, callAt time.Time, window time.Duration, now time.Time) ([]string, error)
	ClassifyOpenConnectGrants(ctx context.Context, from, to time.Time, outcome, reason string, now time.Time) ([]string, error)
	SweepConnectGrants(ctx context.Context, cutoff time.Time) (int64, error)
}

// Metrics is the subset of metrics.Registry the tracker uses. reason is ""
// for ok and none_within_window.
type Metrics interface {
	CountConnectFirstCall(client, outcome, reason string)
	CountConnectFirstCallError(op string)
}

type pairKey struct {
	userID   int64
	clientID string
}

// pairState backs the negative cache that keeps an established connection's
// every call from issuing an UPDATE. noOpen says a close found no open row;
// a grant clears it. gen counts grants recorded for the pair, and a close sets
// noOpen only if gen did not move while it ran, so a grant that lands while a
// close is in flight is never hidden by that close's empty result.
type pairState struct {
	gen    uint64
	noOpen bool
}

// Tracker records grants and first calls and runs the reconciler. A nil
// *Tracker is valid and does nothing, so callers need no feature check.
type Tracker struct {
	store   Store
	metrics Metrics
	now     func() time.Time
	started time.Time

	mu    sync.Mutex
	pairs map[pairKey]*pairState
	// closeErrFrom and closeErrTo bound the calls whose close failed since
	// the reconciler last turned them into unknown outcomes. Zero means
	// none.
	closeErrFrom, closeErrTo time.Time
}

// New returns a tracker over store. metrics may be nil.
func New(store Store, metrics Metrics) *Tracker {
	return newTracker(store, metrics, time.Now)
}

func newTracker(store Store, metrics Metrics, now func() time.Time) *Tracker {
	return &Tracker{
		store:   store,
		metrics: metrics,
		now:     now,
		started: now().UTC(),
		pairs:   map[pairKey]*pairState{},
	}
}

// ClientLabel maps a redirect_uri to its bounded client label.
func ClientLabel(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return ClientOther
	}
	h := strings.ToLower(u.Hostname())
	switch {
	case hostMatches(h, "claude.ai", "anthropic.com"):
		return ClientClaude
	case hostMatches(h, "chatgpt.com", "openai.com"):
		return ClientChatGPT
	default:
		return ClientOther
	}
}

// hostMatches reports whether host equals one of domains or is a subdomain of
// one, so "notclaude.ai" does not pass for claude.ai.
func hostMatches(host string, domains ...string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Granted records one authorization_code grant. It never fails the grant: a
// row that cannot be written is counted at once as unknown/insert_error,
// because nothing later could classify it.
func (t *Tracker) Granted(ctx context.Context, userID int64, clientID, redirectURI string) {
	if t == nil {
		return
	}
	client := ClientLabel(redirectURI)
	if err := t.store.InsertConnectGrant(ctx, userID, clientID, client, t.now().UTC()); err != nil {
		slog.Warn("connect funnel: could not record grant", "client", client, "err", err)
		t.countError(OpInsert)
		t.count(client, db.ConnectOutcomeUnknown, ReasonInsertError)
		return
	}
	// After the insert has committed, never before: a close that reads the
	// new gen must also be able to see the new row.
	t.mu.Lock()
	st := t.pair(pairKey{userID, clientID})
	st.gen++
	st.noOpen = false
	t.mu.Unlock()
}

// Called records one successful tools/list or tools/call by userID through
// clientID and closes every open grant of that pair inside the window.
func (t *Tracker) Called(ctx context.Context, userID int64, clientID string) {
	if t == nil || userID == 0 || clientID == "" {
		return
	}
	key := pairKey{userID, clientID}
	t.mu.Lock()
	st := t.pair(key)
	if st.noOpen {
		t.mu.Unlock()
		return
	}
	gen := st.gen
	t.mu.Unlock()

	callAt := t.now().UTC()
	clients, err := t.store.CloseConnectGrants(ctx, userID, clientID, callAt, Window, callAt)
	if err != nil {
		slog.Warn("connect funnel: could not close grant", "err", err)
		t.countError(OpClose)
		t.mu.Lock()
		if t.closeErrFrom.IsZero() || callAt.Before(t.closeErrFrom) {
			t.closeErrFrom = callAt
		}
		if callAt.After(t.closeErrTo) {
			t.closeErrTo = callAt
		}
		t.mu.Unlock()
		return
	}
	for _, c := range clients {
		t.count(c, db.ConnectOutcomeOK, "")
	}
	if len(clients) == 0 {
		t.mu.Lock()
		if st.gen == gen {
			st.noOpen = true
		}
		t.mu.Unlock()
	}
}

func (t *Tracker) pair(key pairKey) *pairState {
	st, ok := t.pairs[key]
	if !ok {
		st = &pairState{}
		t.pairs[key] = st
	}
	return st
}

// Reconcile classifies every open row whose window, plus Grace, is over, and
// deletes classified rows past Retention. Unknown outcomes are decided first
// and a failure to decide them stops the pass before none_within_window is
// considered: a row whose close may have been lost must never be judged as
// having had no call.
func (t *Tracker) Reconcile(ctx context.Context) {
	if t == nil {
		return
	}
	now := t.now().UTC()
	judgeTo := now.Add(-Window - Grace)

	// Rows granted before this process started. Upper bounds passed to the
	// store are exclusive.
	if !t.classify(ctx, time.Time{}, minTime(judgeTo, t.started), db.ConnectOutcomeUnknown, ReasonRestart, now) {
		return
	}

	// Rows whose window contained a failed close: granted at most Window
	// before the first failed call and not after the last. Only the part of
	// that range that is past judgeTo is decided now; the range is cleared
	// once all of it is, and only if no new failure widened it meanwhile.
	t.mu.Lock()
	errFrom, errTo := t.closeErrFrom, t.closeErrTo
	t.mu.Unlock()
	if !errFrom.IsZero() {
		// The store's upper bound is exclusive; the grant made in the same
		// instant as the failed call is affected too. A microsecond is the
		// finest step Postgres keeps.
		if !t.classify(ctx, errFrom.Add(-Window), minTime(errTo.Add(time.Microsecond), judgeTo), db.ConnectOutcomeUnknown, ReasonCloseError, now) {
			return
		}
		if errTo.Before(judgeTo) {
			t.mu.Lock()
			if t.closeErrFrom.Equal(errFrom) && t.closeErrTo.Equal(errTo) {
				t.closeErrFrom, t.closeErrTo = time.Time{}, time.Time{}
			}
			t.mu.Unlock()
		}
	}

	// Every open row up to judgeTo that a failure could concern is decided
	// by now. A failure recorded after the snapshot above was for a call
	// made after now-Grace (callAt is taken before the store is asked), so
	// it concerns rows granted after judgeTo, which this pass leaves alone.
	if !t.classify(ctx, time.Time{}, judgeTo, db.ConnectOutcomeNone, "", now) {
		return
	}

	if n, err := t.store.SweepConnectGrants(ctx, now.Add(-Retention)); err != nil {
		slog.Warn("connect funnel: sweep failed", "err", err)
		t.countError(OpSweep)
	} else if n > 0 {
		slog.Info("connect funnel: swept classified grants", "deleted_rows", n)
	}
}

// classify runs one classification and counts what it decided. It reports
// whether the store answered.
func (t *Tracker) classify(ctx context.Context, from, to time.Time, outcome, reason string, now time.Time) bool {
	if !to.After(from) {
		return true
	}
	clients, err := t.store.ClassifyOpenConnectGrants(ctx, from, to, outcome, reason, now)
	if err != nil {
		slog.Warn("connect funnel: classification failed", "outcome", outcome, "reason", reason, "err", err)
		t.countError(OpClassify)
		return false
	}
	for _, c := range clients {
		t.count(c, outcome, reason)
	}
	if len(clients) > 0 {
		slog.Info("connect funnel: classified grants", "outcome", outcome, "reason", reason, "rows", len(clients))
	}
	return true
}

// Run reconciles every ReconcileInterval until ctx is done, starting with an
// immediate pass so rows left open while the pod was down are classified
// from their granted_at at once.
func (t *Tracker) Run(ctx context.Context) {
	if t == nil {
		return
	}
	ticker := time.NewTicker(ReconcileInterval)
	defer ticker.Stop()
	t.Reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.Reconcile(ctx)
		}
	}
}

func (t *Tracker) count(client, outcome, reason string) {
	if t.metrics != nil {
		t.metrics.CountConnectFirstCall(normalizeClient(client), outcome, reason)
	}
}

func (t *Tracker) countError(op string) {
	if t.metrics != nil {
		t.metrics.CountConnectFirstCallError(op)
	}
}

// normalizeClient keeps the label bounded even if a row carries a value from
// a future or hand-edited build.
func normalizeClient(c string) string {
	switch c {
	case ClientClaude, ClientChatGPT:
		return c
	default:
		return ClientOther
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
