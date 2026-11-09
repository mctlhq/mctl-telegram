//go:build l2finance

package agentapi

// Finance Assistant L2 slice C (#1250) harness for the agent API.
// Application-security evidence only: FINANCE_SECURITY_GATE=BLOCKED regardless
// of the exit status of this test binary. Slice C only; not L2 completion; no
// aggregation across slices.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

const (
	l2Pass           = "PASS"
	l2FailGap        = "FAIL/GAP"
	l2NotImplemented = "NOT-IMPLEMENTED"
	l2CannotObserve  = "CANNOT-OBSERVE"
)

// Synthetic Telegram ids (checked unused with git grep -w at pinned rev).
const (
	l2AliceTG int64 = 91001
	l2BobTG   int64 = 91002
	l2CarolTG int64 = 91003
	l2DanaTG  int64 = 91004 // Carol's peer

	l2Marker  = "L2SYNTH-TXN-7f3a"
	l2Finance = l2Marker + " total 12.34 card ending 0000"
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
	t.Logf("L2RESULT id=%s outcome=%s rev=%s evidence=%s", id, outcome, l2SourceRev, evidence)
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

// l2PeerSink is an inert counter. The agent API Server has no sender, so no
// production path can reach it; it detects inadvertent direct sends only and
// cannot prove anything about the separate executor.
type l2PeerSink struct {
	mu    sync.Mutex
	texts []string
}

func (p *l2PeerSink) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.texts)
}

type l2APIHarness struct {
	t       *testing.T
	store   *db.Store
	router  *chi.Mux
	reg     *metrics.Registry
	peer    *l2PeerSink
	alice   int64
	carol   int64
	convA   *db.Conversation // Alice <-> Bob
	convC   *db.Conversation // Carol <-> Dana
	jobA    db.AgentJob
	jobC    db.AgentJob
	account *auth.Identity // Alice account identity
	jobID   *auth.Identity // Alice job-bound identity
	carolID *auth.Identity
}

func l2SafeName(s string) string {
	return regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(s, "_")
}

func l2NewAPIHarness(t *testing.T, mode, allowlist string) *l2APIHarness {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, fmt.Sprintf("file:l2c_%s?mode=memory&cache=shared", l2SafeName(t.Name())), 0, 0)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	crypt, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	h := &l2APIHarness{t: t, store: store, peer: &l2PeerSink{}, reg: metrics.New()}
	mk := func(name string, tg int64) int64 {
		uid, err := store.EnsureUser(ctx, name, "", "test")
		if err != nil {
			t.Fatalf("ensure user: %v", err)
		}
		if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
			UserID: uid, Mode: mode, DisclosureText: "AI assistant.", IntentAllowlist: allowlist,
		}); err != nil {
			t.Fatalf("seed profile: %v", err)
		}
		return uid
	}
	h.alice = mk("l2-alice", l2AliceTG)
	h.carol = mk("l2-carol", l2CarolTG)
	h.convA = h.conv(h.alice, l2BobTG, "bob", "Bob")
	h.convC = h.conv(h.carol, l2DanaTG, "dana", "Dana")
	h.jobA = h.claim(h.alice, "evt:l2c:a", h.convA.ID, l2BobTG)
	h.jobC = h.claim(h.carol, "evt:l2c:c", h.convC.ID, l2DanaTG)

	srv := New(store, queue.New(store, "l2c", nil), time.Minute, h.reg)
	h.router = chi.NewRouter()
	srv.Register(h.router)

	h.account = &auth.Identity{UserID: h.alice, Subject: "l2-alice", TelegramID: l2AliceTG}
	h.carolID = &auth.Identity{UserID: h.carol, Subject: "l2-carol", TelegramID: l2CarolTG}
	h.jobID = &auth.Identity{
		UserID: h.alice, Subject: "l2-alice", TelegramID: l2AliceTG,
		JobID: h.jobA.ID, JobAttempt: h.jobA.Attempts, ConversationID: h.convA.ID,
	}
	return h
}

func (h *l2APIHarness) conv(uid, peer int64, user, name string) *db.Conversation {
	h.t.Helper()
	c, err := h.store.EnsureConversation(context.Background(), uid, peer, user, name)
	if err != nil {
		h.t.Fatalf("ensure conversation: %v", err)
	}
	return c
}

func (h *l2APIHarness) claim(uid int64, eventID string, convID, sender int64) db.AgentJob {
	h.t.Helper()
	ctx := context.Background()
	if _, _, err := h.store.InsertIncomingEvent(ctx, db.IncomingEvent{
		EventID: eventID, UserID: uid, Kind: db.EventKindPrivateMessage,
		ChatTGID: sender, SenderTGID: sender, MessageID: 1, Body: "hello",
	}); err != nil {
		h.t.Fatalf("insert event: %v", err)
	}
	if _, ok, err := h.store.EnqueueAgentJob(ctx, eventID, uid, convID); err != nil || !ok {
		h.t.Fatalf("enqueue: ok=%v err=%v", ok, err)
	}
	jobs, err := h.store.ClaimAgentJobs(ctx, "l2c", uid, db.RuntimeOwn, 1)
	if err != nil || len(jobs) != 1 {
		h.t.Fatalf("claim: %v %v", jobs, err)
	}
	return jobs[0]
}

func (h *l2APIHarness) do(id *auth.Identity, method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			h.t.Fatalf("encode: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req = req.WithContext(auth.With(req.Context(), id))
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *l2APIHarness) count(query string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.store.DB.QueryRow(query, args...).Scan(&n); err != nil {
		h.t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// rowsFor counts agent_actions and owner_notifications rows for a user.
func (h *l2APIHarness) rowsFor(uid int64) (actions, notifs int) {
	return h.count(`SELECT COUNT(*) FROM agent_actions WHERE user_id = $1`, uid),
		h.count(`SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1`, uid)
}

func (h *l2APIHarness) noRows() bool {
	a1, n1 := h.rowsFor(h.alice)
	a2, n2 := h.rowsFor(h.carol)
	return a1+n1+a2+n2 == 0
}

// l2CaptureSlog installs handler as the default logger until cleanup.
func l2CaptureSlog(t testing.TB, handler slog.Handler) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// l2AssertNoMarker is the single leak assertion used by T10 and M4. It
// returns an error naming the first source (sorted) that contains the marker.
func l2AssertNoMarker(sources map[string]string) error {
	names := make([]string, 0, len(sources))
	for k := range sources {
		names = append(names, k)
	}
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, k := range names {
		if strings.Contains(sources[k], l2Marker) {
			return fmt.Errorf("marker found in %s", k)
		}
	}
	return nil
}
