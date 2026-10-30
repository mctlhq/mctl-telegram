package connectfunnel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// clock is a settable time source shared by a test and its trackers.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// countMetrics records every increment by "client/outcome/reason".
type countMetrics struct {
	mu     sync.Mutex
	counts map[string]int
	errs   map[string]int
}

func newCountMetrics() *countMetrics {
	return &countMetrics{counts: map[string]int{}, errs: map[string]int{}}
}

func (m *countMetrics) CountConnectFirstCall(client, outcome, reason string) {
	m.mu.Lock()
	m.counts[client+"/"+outcome+"/"+reason]++
	m.mu.Unlock()
}

func (m *countMetrics) CountConnectFirstCallError(op string) {
	m.mu.Lock()
	m.errs[op]++
	m.mu.Unlock()
}

// snapshot returns the non-zero counts, so a test states the complete set of
// outcomes it expects and any extra one fails it.
func (m *countMetrics) snapshot() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for k, v := range m.counts {
		out[k] = v
	}
	return out
}

// faultStore wraps a real store and fails the operations a test switches on.
type faultStore struct {
	*db.Store
	mu           sync.Mutex
	failInsert   bool
	failClose    bool
	failClassify map[string]bool // keyed by outcome+"/"+reason
	failSweep    bool
	beforeClose  func()
	closes       int
	hangClose    bool
	hangInsert   bool
}

func (f *faultStore) InsertConnectGrant(ctx context.Context, userID int64, clientID, client string, grantedAt time.Time) error {
	f.mu.Lock()
	fail, hang := f.failInsert, f.hangInsert
	f.mu.Unlock()
	if fail {
		return errors.New("injected insert failure")
	}
	if hang {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.Store.InsertConnectGrant(ctx, userID, clientID, client, grantedAt)
}

func (f *faultStore) CloseConnectGrants(ctx context.Context, userID int64, clientID string, callAt time.Time, window time.Duration, now time.Time) ([]string, error) {
	f.mu.Lock()
	fail, hook, hang := f.failClose, f.beforeClose, f.hangClose
	f.closes++
	f.mu.Unlock()
	if fail {
		return nil, errors.New("injected close failure")
	}
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	clients, err := f.Store.CloseConnectGrants(ctx, userID, clientID, callAt, window, now)
	if hook != nil {
		hook()
	}
	return clients, err
}

func (f *faultStore) ClassifyOpenConnectGrants(ctx context.Context, from, to time.Time, outcome, reason string, now time.Time) ([]string, error) {
	f.mu.Lock()
	fail := f.failClassify[outcome+"/"+reason]
	f.mu.Unlock()
	if fail {
		return nil, errors.New("injected classify failure")
	}
	return f.Store.ClassifyOpenConnectGrants(ctx, from, to, outcome, reason, now)
}

func (f *faultStore) SweepConnectGrants(ctx context.Context, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	fail := f.failSweep
	f.mu.Unlock()
	if fail {
		return 0, errors.New("injected sweep failure")
	}
	return f.Store.SweepConnectGrants(ctx, cutoff)
}

type fixture struct {
	store *faultStore
	clock *clock
	m     *countMetrics
	alice int64
	bob   int64
}

const (
	claudeClient  = "client-claude"
	chatgptClient = "client-chatgpt"
	claudeRedir   = "https://claude.ai/api/mcp/auth_callback"
	chatgptRedir  = "https://chatgpt.com/connector_platform_oauth_redirect"
)

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := &db.Store{DB: conn}
	alice, err := store.EnsureUser(ctx, "alice", "", "test")
	if err != nil {
		t.Fatalf("ensure alice: %v", err)
	}
	bob, err := store.EnsureUser(ctx, "bob", "", "test")
	if err != nil {
		t.Fatalf("ensure bob: %v", err)
	}
	return &fixture{
		store: &faultStore{Store: store, failClassify: map[string]bool{}},
		clock: &clock{t: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)},
		m:     newCountMetrics(),
		alice: alice,
		bob:   bob,
	}
}

func (f *fixture) tracker() *Tracker {
	return newTracker(f.store, f.m, f.clock.now)
}

// openRows counts rows still waiting for an outcome.
func (f *fixture) openRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM connect_first_call WHERE outcome IS NULL`).Scan(&n); err != nil {
		t.Fatalf("count open rows: %v", err)
	}
	return n
}

func (f *fixture) totalRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM connect_first_call`).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

func assertCounts(t *testing.T, m *countMetrics, want map[string]int) {
	t.Helper()
	got := m.snapshot()
	if len(got) != len(want) {
		t.Fatalf("counts = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("counts = %v, want %v", got, want)
		}
	}
}

// pastJudgement moves the clock to the point a grant made now is judged.
const pastJudgement = Window + Grace + time.Second

func TestCallWithinWindowCountsOkOnce(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(2 * time.Minute)
	tr.Called(ctx, f.alice, claudeClient)
	tr.Called(ctx, f.alice, claudeClient)
	f.clock.advance(pastJudgement)
	tr.Reconcile(ctx)
	tr.Reconcile(ctx)

	assertCounts(t, f.m, map[string]int{"claude/ok/": 1})
	if n := f.openRows(t); n != 0 {
		t.Fatalf("open rows = %d, want 0", n)
	}
}

func TestNoCallCountsNoneOnceAfterWindow(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, chatgptClient, chatgptRedir)
	// Inside the window, and inside the grace after it, nothing is judged.
	f.clock.advance(Window + Grace - time.Second)
	tr.Reconcile(ctx)
	assertCounts(t, f.m, map[string]int{})

	f.clock.advance(2 * time.Second)
	tr.Reconcile(ctx)
	tr.Reconcile(ctx)
	assertCounts(t, f.m, map[string]int{"chatgpt/none_within_window/": 1})
}

func TestCallAfterWindowDoesNotCountOk(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(Window + time.Second)
	tr.Called(ctx, f.alice, claudeClient)
	f.clock.advance(Grace)
	tr.Reconcile(ctx)

	assertCounts(t, f.m, map[string]int{"claude/none_within_window/": 1})
}

func TestCallMatchesOnlyItsOwnUserAndClient(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	tr.Called(ctx, f.bob, claudeClient)
	tr.Called(ctx, f.alice, chatgptClient)
	f.clock.advance(pastJudgement)
	tr.Reconcile(ctx)

	assertCounts(t, f.m, map[string]int{"claude/none_within_window/": 1})
}

// The negative cache must not hide a grant made after a call found nothing.
func TestCallAfterEmptyCloseStillClosesNewGrant(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Called(ctx, f.alice, claudeClient) // no grant yet: caches "no open row"
	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	tr.Called(ctx, f.alice, claudeClient)

	assertCounts(t, f.m, map[string]int{"claude/ok/": 1})
}

// A grant that commits while a close is in flight must not be hidden by that
// close's empty result.
func TestGrantDuringInFlightCloseIsNotCached(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	var once sync.Once
	f.store.beforeClose = func() {
		once.Do(func() { tr.Granted(ctx, f.alice, claudeClient, claudeRedir) })
	}
	tr.Called(ctx, f.alice, claudeClient) // finds nothing; the grant lands meanwhile
	f.store.mu.Lock()
	f.store.beforeClose = nil
	f.store.mu.Unlock()
	tr.Called(ctx, f.alice, claudeClient)

	assertCounts(t, f.m, map[string]int{"claude/ok/": 1})
}

// An established connection's calls stop reaching the store once a close
// has found nothing, and a call without an identity never reaches it.
func TestCallsWithoutOpenGrantSkipTheStore(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Called(ctx, 0, claudeClient)
	tr.Called(ctx, f.alice, "")
	if f.store.closes != 0 {
		t.Fatalf("closes without identity = %d, want 0", f.store.closes)
	}
	tr.Called(ctx, f.alice, claudeClient)
	tr.Called(ctx, f.alice, claudeClient)
	tr.Called(ctx, f.alice, claudeClient)
	if f.store.closes != 1 {
		t.Fatalf("closes for a pair with no open grant = %d, want 1", f.store.closes)
	}
}

func TestInsertErrorCountsUnknownAtOnce(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	f.store.failInsert = true
	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)

	assertCounts(t, f.m, map[string]int{"claude/unknown/insert_error": 1})
	if f.m.errs[OpInsert] != 1 {
		t.Fatalf("insert errors = %d, want 1", f.m.errs[OpInsert])
	}
}

func TestGrantBeforeRestartIsUnknown(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.tracker().Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(time.Minute)
	next := f.tracker() // the process restarted
	f.clock.advance(pastJudgement)
	next.Reconcile(ctx)

	assertCounts(t, f.m, map[string]int{"claude/unknown/restart": 1})
}

// A grant from before a restart is still closed by a call the new process
// sees: the row is durable, only close failures are lost.
func TestGrantBeforeRestartClosedAfterIt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.tracker().Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(time.Minute)
	next := f.tracker()
	next.Called(ctx, f.alice, claudeClient)
	f.clock.advance(pastJudgement)
	next.Reconcile(ctx)

	assertCounts(t, f.m, map[string]int{"claude/ok/": 1})
}

// Rows left open while the pod was down are classified on the next pass, from
// granted_at, not lost.
func TestRowsOpenDuringDowntimeAreClassified(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.tracker().Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(3 * time.Hour)
	f.tracker().Reconcile(ctx)

	assertCounts(t, f.m, map[string]int{"claude/unknown/restart": 1})
	if n := f.openRows(t); n != 0 {
		t.Fatalf("open rows = %d, want 0", n)
	}
}

func TestCloseErrorMakesWindowUnknownNotNone(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(time.Minute)
	f.store.failClose = true
	tr.Called(ctx, f.alice, claudeClient)
	f.store.failClose = false
	f.clock.advance(pastJudgement)
	tr.Reconcile(ctx)

	assertCounts(t, f.m, map[string]int{"claude/unknown/close_error": 1})
	if f.m.errs[OpClose] != 1 {
		t.Fatalf("close errors = %d, want 1", f.m.errs[OpClose])
	}

	// Once judged, the failure range is cleared: a later grant without a
	// call is none_within_window again.
	tr.Granted(ctx, f.bob, claudeClient, claudeRedir)
	f.clock.advance(pastJudgement)
	tr.Reconcile(ctx)
	assertCounts(t, f.m, map[string]int{"claude/unknown/close_error": 1, "claude/none_within_window/": 1})
}

// A close that hangs is cut off by CloseTimeout, and the timeout is a failed
// close: the row becomes unknown/close_error, not none_within_window. A
// hanging insert is cut off by InsertTimeout the same way.
func TestHangingStoreCallsAreBounded(t *testing.T) {
	if CloseTimeout >= Grace {
		t.Fatalf("CloseTimeout %v must be shorter than Grace %v", CloseTimeout, Grace)
	}
	f := newFixture(t)
	tr := f.tracker()
	if tr.closeTimeout != CloseTimeout || tr.insertTimeout != InsertTimeout {
		t.Fatalf("tracker timeouts = (%v, %v), want (%v, %v)", tr.closeTimeout, tr.insertTimeout, CloseTimeout, InsertTimeout)
	}
	tr.closeTimeout, tr.insertTimeout = 50*time.Millisecond, 50*time.Millisecond
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.store.hangClose = true
	start := time.Now()
	tr.Called(ctx, f.alice, claudeClient)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("close ran %v, want it cut off by the timeout", d)
	}
	f.store.hangClose = false
	f.clock.advance(pastJudgement)
	tr.Reconcile(ctx)
	assertCounts(t, f.m, map[string]int{"claude/unknown/close_error": 1})

	f.store.hangInsert = true
	tr.Granted(ctx, f.bob, claudeClient, claudeRedir)
	assertCounts(t, f.m, map[string]int{"claude/unknown/close_error": 1, "claude/unknown/insert_error": 1})
}

// A close failure concerns only grants made up to the failed call: a grant
// after it is judged none, and once the failure is judged its range is gone.
func TestCloseErrorDoesNotReachGrantsAfterIt(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(time.Minute)
	f.store.failClose = true
	tr.Called(ctx, f.alice, claudeClient)
	f.store.failClose = false
	f.clock.advance(time.Minute)
	tr.Granted(ctx, f.bob, chatgptClient, chatgptRedir)
	f.clock.advance(pastJudgement)
	tr.Reconcile(ctx)

	assertCounts(t, f.m, map[string]int{"claude/unknown/close_error": 1, "chatgpt/none_within_window/": 1})
	if !tr.closeErrFrom.IsZero() || !tr.closeErrTo.IsZero() {
		t.Fatalf("failure range not cleared after it was judged: [%v, %v]", tr.closeErrFrom, tr.closeErrTo)
	}
}

// A close failure concerns only grants up to Window before it: an older grant,
// whose window was over before the failure, is still judged none.
func TestCloseErrorDoesNotReachGrantsBeforeItsWindow(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(Window + time.Second)
	f.store.failClose = true
	tr.Called(ctx, f.bob, claudeClient)
	f.store.failClose = false
	f.clock.advance(pastJudgement)
	tr.Reconcile(ctx)

	assertCounts(t, f.m, map[string]int{"claude/none_within_window/": 1})
}

// A close failure whose affected grants are not all judged yet keeps its
// range until they are.
func TestCloseErrorRangeOutlivesAPassThatCannotJudgeItAll(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(4 * time.Minute)
	tr.Granted(ctx, f.bob, claudeClient, claudeRedir)
	f.clock.advance(30 * time.Second)
	f.store.failClose = true
	tr.Called(ctx, f.alice, chatgptClient) // fails; concerns both grants
	f.store.failClose = false

	// Alice's grant is past judgement here, Bob's is not.
	f.clock.advance(Window + Grace - 4*time.Minute - 30*time.Second + time.Second)
	tr.Reconcile(ctx)
	assertCounts(t, f.m, map[string]int{"claude/unknown/close_error": 1})

	f.clock.advance(4 * time.Minute)
	tr.Reconcile(ctx)
	assertCounts(t, f.m, map[string]int{"claude/unknown/close_error": 2})
}

// When the unknown outcomes cannot be decided, none_within_window must not be
// decided either.
func TestClassifyFailureOnUnknownBlocksNone(t *testing.T) {
	for _, reason := range []string{ReasonRestart, ReasonCloseError} {
		t.Run(reason, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			old := f.tracker()
			old.Granted(ctx, f.alice, claudeClient, claudeRedir)
			tr := f.tracker()
			if reason == ReasonRestart {
				f.clock.advance(time.Second)
				tr = f.tracker()
			}
			tr.Granted(ctx, f.bob, claudeClient, claudeRedir)
			f.clock.advance(time.Minute)
			f.store.failClose = true
			tr.Called(ctx, f.alice, chatgptClient)
			f.store.failClose = false

			f.store.failClassify[db.ConnectOutcomeUnknown+"/"+reason] = true
			f.clock.advance(pastJudgement)
			tr.Reconcile(ctx)
			assertCounts(t, f.m, map[string]int{})
			if f.m.errs[OpClassify] != 1 {
				t.Fatalf("classify errors = %d, want 1", f.m.errs[OpClassify])
			}

			f.store.failClassify[db.ConnectOutcomeUnknown+"/"+reason] = false
			tr.Reconcile(ctx)
			if got := f.m.snapshot()["claude/none_within_window/"]; got != 0 {
				t.Fatalf("none_within_window = %d, want 0: %v", got, f.m.snapshot())
			}
			if n := f.openRows(t); n != 0 {
				t.Fatalf("open rows = %d, want 0", n)
			}
		})
	}
}

// A failed none classification leaves the rows open for the next pass rather
// than dropping them.
func TestClassifyFailureOnNoneRetriesNextPass(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	f.clock.advance(pastJudgement)
	f.store.failClassify[db.ConnectOutcomeNone+"/"] = true
	tr.Reconcile(ctx)
	assertCounts(t, f.m, map[string]int{})

	f.store.failClassify[db.ConnectOutcomeNone+"/"] = false
	tr.Reconcile(ctx)
	assertCounts(t, f.m, map[string]int{"claude/none_within_window/": 1})
}

func TestRetentionDeletesOnlyOldClassifiedRows(t *testing.T) {
	f := newFixture(t)
	tr := f.tracker()
	ctx := context.Background()

	tr.Granted(ctx, f.alice, claudeClient, claudeRedir)
	tr.Called(ctx, f.alice, claudeClient) // classified ok at T0
	f.clock.advance(Retention - time.Hour)
	tr.Granted(ctx, f.alice, chatgptClient, chatgptRedir)
	tr.Called(ctx, f.alice, chatgptClient) // classified ok at T0+Retention-1h
	f.clock.advance(time.Hour - time.Second)
	tr.Reconcile(ctx)
	if n := f.totalRows(t); n != 2 {
		t.Fatalf("rows just inside retention = %d, want 2", n)
	}

	f.clock.advance(2 * time.Second)
	tr.Granted(ctx, f.bob, claudeClient, claudeRedir) // open, inside its window
	tr.Reconcile(ctx)
	if n := f.totalRows(t); n != 2 {
		t.Fatalf("rows after retention = %d, want 2 (the newer ok row and the open one)", n)
	}
	if n := f.openRows(t); n != 1 {
		t.Fatalf("open rows after retention = %d, want 1 (open rows are never swept)", n)
	}
	assertCounts(t, f.m, map[string]int{"claude/ok/": 1, "chatgpt/ok/": 1})
}

func TestClientLabel(t *testing.T) {
	for in, want := range map[string]string{
		"https://claude.ai/api/mcp/auth_callback":               ClientClaude,
		"https://www.anthropic.com/cb":                          ClientClaude,
		"https://chatgpt.com/connector_platform_oauth_redirect": ClientChatGPT,
		"https://platform.openai.com/cb":                        ClientChatGPT,
		"https://notclaude.ai/cb":                               ClientOther,
		"https://claude.ai.example.com/cb":                      ClientOther,
		"http://localhost:6274/oauth/callback":                  ClientOther,
		"::not a url":                                           ClientOther,
		"":                                                      ClientOther,
	} {
		if got := ClientLabel(in); got != want {
			t.Errorf("ClientLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNilTrackerIsInert(t *testing.T) {
	var tr *Tracker
	ctx := context.Background()
	tr.Granted(ctx, 1, "c", claudeRedir)
	tr.Called(ctx, 1, "c")
	tr.Reconcile(ctx)
}

// The registry pre-initialises exactly the series this package can produce,
// so increase() sees the first outcome and no label value goes unprimed.
func TestRegistryPrimesEveryOutcome(t *testing.T) {
	reg := metrics.New()
	want := map[string]bool{}
	for _, c := range Clients {
		want[c+"/"+db.ConnectOutcomeOK+"/"] = true
		want[c+"/"+db.ConnectOutcomeNone+"/"] = true
		for _, r := range UnknownReasons {
			want[c+"/"+db.ConnectOutcomeUnknown+"/"+r] = true
		}
	}
	got := map[string]bool{}
	for _, lv := range collectLabels(t, reg.ConnectFirstCallTotal) {
		got[lv["client"]+"/"+lv["outcome"]+"/"+lv["reason"]] = true
	}
	assertSameSet(t, "mctl_connect_first_call_total", got, want)

	wantOps := map[string]bool{}
	for _, op := range Ops {
		wantOps[op] = true
	}
	gotOps := map[string]bool{}
	for _, lv := range collectLabels(t, reg.ConnectFirstCallErrorsTotal) {
		gotOps[lv["op"]] = true
	}
	assertSameSet(t, "mctl_connect_first_call_errors_total", gotOps, wantOps)
}

func collectLabels(t *testing.T, c prometheus.Collector) []map[string]string {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() { c.Collect(ch); close(ch) }()
	var out []map[string]string
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		lv := map[string]string{}
		for _, l := range pb.GetLabel() {
			lv[l.GetName()] = l.GetValue()
		}
		out = append(out, lv)
	}
	return out
}

func assertSameSet(t *testing.T, name string, got, want map[string]bool) {
	t.Helper()
	var missing, extra []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("%s: missing %v, extra %v", name, missing, extra)
	}
}
