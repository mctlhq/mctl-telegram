//go:build l2finance

package control

// Finance Assistant L2 slice B (#1249) harness for the owner notifier and
// control router. Application-security evidence only:
// FINANCE_SECURITY_GATE=BLOCKED regardless of the exit status of this test
// binary. Slice B only; not L2 completion; no aggregation across slices.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

const (
	l2Pass           = "PASS"
	l2FailGap        = "FAIL/GAP"
	l2NotImplemented = "NOT-IMPLEMENTED"
	l2CannotObserve  = "CANNOT-OBSERVE"
)

var errL2ExternalDial = errors.New("l2finance: external dial refused")

var (
	l2SourceRev string
	l2RevRe     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// l2GuardDial allows only loopback TCP/UDP. It guards the default transport
// only; it is not a whole-process egress firewall.
func l2GuardDial(_ context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || strings.HasPrefix(network, "unix") {
		return nil, fmt.Errorf("%w: %s", errL2ExternalDial, addr)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%w: %s", errL2ExternalDial, addr)
	}
	var d net.Dialer
	return d.DialContext(context.Background(), network, addr)
}

func TestMain(m *testing.M) {
	l2SourceRev = os.Getenv("L2FINANCE_SOURCE_REV")
	if !l2RevRe.MatchString(l2SourceRev) {
		fmt.Fprintln(os.Stderr, "l2finance: L2FINANCE_SOURCE_REV must be a 40-hex commit sha")
		os.Exit(2)
	}
	_ = os.Unsetenv("TG_API_ID")
	_ = os.Unsetenv("TG_API_HASH")
	_ = os.Unsetenv("DATABASE_URL")
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errL2ExternalDial
		},
	}
	if tr, ok := http.DefaultTransport.(*http.Transport); ok {
		tr.DialContext = l2GuardDial
	}
	os.Exit(m.Run())
}

func l2Record(t testing.TB, id, outcome, evidence string) {
	t.Helper()
	t.Logf("L2RESULT id=%s outcome=%s rev=%s evidence=fixture_id=L2SYNTH-%s %s", id, outcome, l2SourceRev, id, evidence)
}

// expectGap records FAIL/GAP when the unsafe behaviour is observed and fails
// the test when it no longer reproduces.
func expectGap(t testing.TB, id string, observed bool, evidence string) {
	t.Helper()
	if !observed {
		t.Fatalf("%s: gap no longer reproduces; update rubric via reviewed PR", id)
	}
	l2Record(t, id, l2FailGap, evidence)
}

type l2Send struct {
	userID, randomID int64
	text             string
	viaRandomID      bool
}

// l2SelfSink is the fake SelfSender: it records sends and can inject errors.
// After a failing send the send IS recorded when recordOnFail is set,
// modelling a send that reached Telegram but whose answer was lost.
type l2SelfSink struct {
	mu           sync.Mutex
	sends        []l2Send
	failNext     int
	recordOnFail bool
	seenIDs      map[int64]bool
}

func (s *l2SelfSink) record(userID, randomID int64, text string, via bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if via && randomID != 0 {
		if s.seenIDs == nil {
			s.seenIDs = map[int64]bool{}
		}
		if s.seenIDs[randomID] {
			return 0, fmt.Errorf("random_id duplicate: %w", executor.ErrAlreadyDelivered)
		}
		s.seenIDs[randomID] = true
	}
	if s.failNext > 0 {
		s.failNext--
		if s.recordOnFail {
			s.sends = append(s.sends, l2Send{userID, randomID, text, via})
		}
		return 0, errors.New("l2finance: injected send failure")
	}
	s.sends = append(s.sends, l2Send{userID, randomID, text, via})
	return int64(len(s.sends)), nil
}

func (s *l2SelfSink) SendToSelf(_ context.Context, userID int64, text string) (int64, error) {
	return s.record(userID, 0, text, false)
}

func (s *l2SelfSink) SendToSelfWithRandomID(_ context.Context, userID, randomID int64, text string) (int64, error) {
	return s.record(userID, randomID, text, true)
}

func (s *l2SelfSink) snapshot() []l2Send {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]l2Send(nil), s.sends...)
}

// l2PeerSink stands for any non-owner recipient.
type l2PeerSink struct {
	mu    sync.Mutex
	texts []string
}

func (p *l2PeerSink) add(text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.texts = append(p.texts, text)
}

func (p *l2PeerSink) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.texts)
}

// l2LeakySink is the M3 mutation: it also copies every text to a peer.
type l2LeakySink struct {
	inner *l2SelfSink
	peer  *l2PeerSink
}

func (l *l2LeakySink) SendToSelf(ctx context.Context, userID int64, text string) (int64, error) {
	l.peer.add(text)
	return l.inner.SendToSelf(ctx, userID, text)
}

func (l *l2LeakySink) SendToSelfWithRandomID(ctx context.Context, userID, randomID int64, text string) (int64, error) {
	l.peer.add(text)
	return l.inner.SendToSelfWithRandomID(ctx, userID, randomID, text)
}

type l2NotifierHarness struct {
	store    *db.Store
	alice    int64
	carol    int64
	sink     *l2SelfSink
	peer     *l2PeerSink
	killOn   atomic.Bool
	notifier *Notifier
	router   *Router
}

func l2NewNotifierHarness(t *testing.T, wireKill bool) *l2NotifierHarness {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, fmt.Sprintf("file:l2_%d?mode=memory&cache=shared", time.Now().UnixNano()), 0, 0)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(testKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	h := &l2NotifierHarness{store: store, sink: &l2SelfSink{}, peer: &l2PeerSink{}}
	for name, dst := range map[string]*int64{"l2-alice": &h.alice, "l2-carol": &h.carol} {
		uid, err := store.EnsureUser(ctx, name, "", "test")
		if err != nil {
			t.Fatalf("ensure user: %v", err)
		}
		if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
			UserID: uid, Mode: db.AgentModeObserve, DisclosureText: "AI assistant.",
		}); err != nil {
			t.Fatalf("seed profile: %v", err)
		}
		*dst = uid
	}
	h.setSender(h.sink, wireKill)
	return h
}

func (h *l2NotifierHarness) setSender(s SelfSender, wireKill bool) {
	h.notifier = NewNotifier(h.store, s)
	if wireKill {
		h.notifier.GlobalKill = h.killOn.Load
	}
	h.router = NewRouter(h.store, &fakeApprover{}, h.notifier)
}

func (h *l2NotifierHarness) queue(t *testing.T, userID int64, body string) int64 {
	t.Helper()
	id, err := h.store.InsertOwnerNotification(context.Background(), db.OwnerNotification{
		UserID: userID, Kind: db.NotificationSummary, Body: body,
	})
	if err != nil {
		t.Fatalf("queue notification: %v", err)
	}
	return id
}

func (h *l2NotifierHarness) status(t *testing.T, id int64) string {
	t.Helper()
	var s string
	if err := h.store.DB.QueryRow(`SELECT status FROM owner_notifications WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatalf("notification status: %v", err)
	}
	return s
}

func (h *l2NotifierHarness) setMode(t *testing.T, userID int64, mode string) {
	t.Helper()
	p, err := h.store.GetAgentProfile(context.Background(), userID)
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	p.Mode = mode
	if err := h.store.UpsertAgentProfile(context.Background(), *p); err != nil {
		t.Fatalf("set mode: %v", err)
	}
}

// l2CheckOnlyOwnUser returns an error unless every send's text appears in
// want and was addressed to the mapped user, and every want entry was sent.
func l2CheckOnlyOwnUser(h *l2NotifierHarness, want map[string]int64) error {
	seen := map[string]bool{}
	for _, s := range h.sink.snapshot() {
		uid, ok := want[s.text]
		if !ok {
			return fmt.Errorf("unexpected text delivered to user %d", s.userID)
		}
		if s.userID != uid {
			return fmt.Errorf("text for user %d delivered to user %d", uid, s.userID)
		}
		seen[s.text] = true
	}
	if len(seen) != len(want) {
		return fmt.Errorf("delivered %d of %d expected texts", len(seen), len(want))
	}
	return nil
}

// l2CheckNoSend returns an error if anything reached the self sink.
func l2CheckNoSend(h *l2NotifierHarness) error {
	if n := len(h.sink.snapshot()); n != 0 {
		return fmt.Errorf("%d sends occurred", n)
	}
	return nil
}

// l2CheckNoPeerSink returns an error if anything reached the peer sink.
func l2CheckNoPeerSink(h *l2NotifierHarness) error {
	if n := h.peer.count(); n != 0 {
		return fmt.Errorf("peer sink received %d messages", n)
	}
	return nil
}
