//go:build l2finance

package listener

// Finance Assistant L2 slice B (#1249) harness for the Saved Messages
// listener. Application-security evidence only: FINANCE_SECURITY_GATE=BLOCKED
// regardless of the exit status of this test binary. Slice B only; not L2
// completion; no aggregation across slices.

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
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/control"
	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

const (
	l2Pass           = "PASS"
	l2FailGap        = "FAIL/GAP"
	l2NotImplemented = "NOT-IMPLEMENTED"
	l2CannotObserve  = "CANNOT-OBSERVE"
)

// l2BobTG is the synthetic foreign sender (persona Bob).
const l2BobTG = int64(600)

var errL2ExternalDial = errors.New("l2finance: external dial refused")

var (
	l2SourceRev string
	l2RevRe     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// l2GuardDial allows only loopback TCP/UDP and Unix sockets.
func l2GuardDial(_ context.Context, network, addr string) (net.Conn, error) {
	if strings.HasPrefix(network, "unix") {
		return nil, errL2ExternalDial
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
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

// l2Record emits one structured result line. A green exit status is harness
// success, never a security-gate pass.
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

// l2SelfSink is the fake SelfSender. It never touches a network.
type l2SelfSink struct {
	mu       sync.Mutex
	sends    []l2Send
	failNext int // number of upcoming sends that fail before being recorded
}

func (s *l2SelfSink) record(userID, randomID int64, text string, via bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext > 0 {
		s.failNext--
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

// l2PeerSink stands for any non-owner recipient. Nothing in the real wiring
// can reach it; it exists so a leak would be observable.
type l2PeerSink struct {
	mu    sync.Mutex
	texts []string
}

func (p *l2PeerSink) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.texts)
}

type l2Harness struct {
	store *db.Store
	uid   int64
	l     *Listener
	acct  *account
	sink  *l2SelfSink
	peer  *l2PeerSink
}

func l2NewHarness(t *testing.T) *l2Harness {
	t.Helper()
	ctx := context.Background()
	store := newListenerTestStore(t)
	uid, err := store.EnsureUser(ctx, "l2-alice", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeObserve, DisclosureText: "AI assistant.",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	sink := &l2SelfSink{}
	router := control.NewRouter(store, notFoundApprover{}, control.NewNotifier(store, sink))
	l := New(store, queue.New(store, "l2-test", nil), router, nil)
	return &l2Harness{
		store: store, uid: uid, l: l,
		acct: &account{userID: uid, tgID: selfTG},
		sink: sink, peer: &l2PeerSink{},
	}
}

func l2CountEvents(h *l2Harness, kind string) (int, error) {
	var n int
	q := `SELECT COUNT(*) FROM incoming_events WHERE user_id = $1`
	args := []any{h.uid}
	if kind != "" {
		q += ` AND kind = $2`
		args = append(args, kind)
	}
	if err := h.store.DB.QueryRow(q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// l2CheckSavedEvents returns an error unless exactly want saved_command
// events exist.
func l2CheckSavedEvents(h *l2Harness, want int) error {
	got, err := l2CountEvents(h, db.EventKindSavedCommand)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("saved_command events = %d, want %d", got, want)
	}
	return nil
}

// l2CheckRoutedOnce returns an error unless exactly want replies reached the
// owner's own Saved Messages and nothing reached the peer sink.
func l2CheckRoutedOnce(h *l2Harness, want int) error {
	sends := h.sink.snapshot()
	if len(sends) != want {
		return fmt.Errorf("replies = %d, want %d", len(sends), want)
	}
	for _, s := range sends {
		if s.userID != h.uid {
			return fmt.Errorf("reply addressed to user %d, want owner %d", s.userID, h.uid)
		}
	}
	if n := h.peer.count(); n != 0 {
		return fmt.Errorf("peer sink received %d messages", n)
	}
	return nil
}

// l2CheckNotRouted returns an error if any command was routed (a reply was
// sent) or a saved_command event was recorded.
func l2CheckNotRouted(h *l2Harness) error {
	if n := len(h.sink.snapshot()); n != 0 {
		return fmt.Errorf("command was routed: %d replies", n)
	}
	return l2CheckSavedEvents(h, 0)
}
