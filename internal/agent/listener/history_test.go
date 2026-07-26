package listener

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/agent/control"
	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

type historyResult struct {
	messages []tg.MessageClass
	err      error
}

type fakeSavedHistoryAPI struct {
	mu       sync.Mutex
	results  []historyResult
	requests []*tg.MessagesGetHistoryRequest
}

func (f *fakeSavedHistoryAPI) MessagesGetHistory(_ context.Context, req *tg.MessagesGetHistoryRequest) (tg.MessagesMessagesClass, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copyReq := *req
	f.requests = append(f.requests, &copyReq)
	if len(f.results) == 0 {
		return &tg.MessagesMessages{}, nil
	}
	next := f.results[0]
	f.results = f.results[1:]
	if next.err != nil {
		return nil, next.err
	}
	return &tg.MessagesMessages{Messages: next.messages}, nil
}

type lockedRecordingRouter struct {
	mu    sync.Mutex
	calls int
	texts []string
	err   error
}

type notFoundApprover struct{}

func (notFoundApprover) Approve(context.Context, int64, string) error {
	return executor.ErrApprovalCodeNotFound
}

func (notFoundApprover) Reject(context.Context, int64, string) error {
	return executor.ErrApprovalCodeNotFound
}

type capturedSelfSender struct {
	texts []string
}

func (s *capturedSelfSender) SendToSelf(_ context.Context, _ int64, text string) (int64, error) {
	s.texts = append(s.texts, text)
	return 1, nil
}

func (s *capturedSelfSender) SendToSelfWithRandomID(_ context.Context, _, _ int64, text string) (int64, error) {
	s.texts = append(s.texts, text)
	return 1, nil
}

func (r *lockedRecordingRouter) HandleSavedText(_ context.Context, _ int64, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.texts = append(r.texts, text)
	return r.err
}

func (r *lockedRecordingRouter) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func savedHistoryMessage(id int, text string) *tg.Message {
	return &tg.Message{
		ID: id, Out: true,
		PeerID:  &tg.PeerUser{UserID: selfTG},
		Message: text,
	}
}

func cursorForTest(t *testing.T, store *db.Store, userID int64) int64 {
	t.Helper()
	got, found, err := store.GetSavedCommandCursor(context.Background(), userID)
	if err != nil {
		t.Fatalf("get cursor: %v", err)
	}
	if !found {
		t.Fatal("cursor row not found")
	}
	return got
}

func TestPollSavedHistory_FirstPollSetsBaselineWithoutReplay(t *testing.T) {
	ctx := context.Background()
	router := &lockedRecordingRouter{}
	l, store, acct := newTestListener(t, router)
	api := &fakeSavedHistoryAPI{results: []historyResult{{
		messages: []tg.MessageClass{savedHistoryMessage(50, "/mctl approve HISTORIC")},
	}}}

	if err := l.pollSavedHistory(ctx, acct, api); err != nil {
		t.Fatalf("baseline poll: %v", err)
	}
	if got := cursorForTest(t, store, acct.userID); got != 50 {
		t.Fatalf("baseline cursor = %d, want 50", got)
	}
	if router.callCount() != 0 {
		t.Fatalf("historical command routed %d times", router.callCount())
	}
	var events int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM incoming_events`).Scan(&events); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if events != 0 {
		t.Fatalf("historical command persisted: events=%d", events)
	}
	if len(api.requests) != 1 || api.requests[0].Limit != 1 {
		t.Fatalf("baseline request = %#v", api.requests)
	}
}

func TestPollSavedHistory_RoutesAndAuditsApprovalCommand(t *testing.T) {
	ctx := context.Background()
	router := &lockedRecordingRouter{}
	l, store, acct := newTestListener(t, router)
	if err := store.AdvanceSavedCommandCursor(ctx, acct.userID, 50); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
	api := &fakeSavedHistoryAPI{results: []historyResult{{
		messages: []tg.MessageClass{savedHistoryMessage(51, "/mctl approve WRONG-CODE")},
	}}}

	if err := l.pollSavedHistory(ctx, acct, api); err != nil {
		t.Fatalf("history poll: %v", err)
	}
	if router.callCount() != 1 {
		t.Fatalf("router calls = %d, want 1", router.callCount())
	}
	eventID := eventIDForMessage(acct.tgID, acct.tgID, 51, 0, "/mctl approve WRONG-CODE")
	event, err := store.GetIncomingEvent(ctx, acct.userID, eventID)
	if err != nil {
		t.Fatalf("get incoming event: %v", err)
	}
	if event.Kind != db.EventKindSavedCommand || event.Body != "/mctl approve WRONG-CODE" {
		t.Fatalf("event = %#v", event)
	}
	if got := cursorForTest(t, store, acct.userID); got != 51 {
		t.Fatalf("cursor = %d, want 51", got)
	}
	req := api.requests[0]
	if _, ok := req.Peer.(*tg.InputPeerSelf); !ok ||
		req.OffsetID != 50 || req.AddOffset != -savedHistoryLimit ||
		req.Limit != savedHistoryLimit || req.MinID != 50 {
		t.Fatalf("incremental request = %#v", req)
	}
}

func TestPollSavedHistory_InvalidApprovalGetsNormalReplyAndAudit(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if err := store.AdvanceSavedCommandCursor(ctx, acct.userID, 55); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
	sender := &capturedSelfSender{}
	l.Router = control.NewRouter(store, notFoundApprover{}, control.NewNotifier(store, sender))
	api := &fakeSavedHistoryAPI{results: []historyResult{{
		messages: []tg.MessageClass{savedHistoryMessage(56, "/mctl approve INVALID")},
	}}}

	if err := l.pollSavedHistory(ctx, acct, api); err != nil {
		t.Fatalf("history poll: %v", err)
	}
	if len(sender.texts) != 1 || !strings.Contains(sender.texts[0], "Could not approve") {
		t.Fatalf("normal invalid-code reply = %v", sender.texts)
	}
	eventID := eventIDForMessage(acct.tgID, acct.tgID, 56, 0, "/mctl approve INVALID")
	if _, err := store.GetIncomingEvent(ctx, acct.userID, eventID); err != nil {
		t.Fatalf("invalid approval was not audited: %v", err)
	}
}

func TestPollSavedHistory_PushAndHistoryRouteOnce(t *testing.T) {
	ctx := context.Background()
	router := &lockedRecordingRouter{}
	l, store, acct := newTestListener(t, router)
	if err := store.AdvanceSavedCommandCursor(ctx, acct.userID, 60); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
	msg := savedHistoryMessage(61, "/mctl status")
	api := &fakeSavedHistoryAPI{results: []historyResult{{
		messages: []tg.MessageClass{msg},
	}}}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs <- l.pollSavedHistory(ctx, acct, api)
	}()
	go func() {
		defer wg.Done()
		errs <- l.onMessage(ctx, acct, tg.Entities{}, msg, false)
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent delivery: %v", err)
		}
	}
	if router.callCount() != 1 {
		t.Fatalf("router calls = %d, want exactly 1", router.callCount())
	}
}

func TestPollSavedHistory_IgnoresNonCommandsAndAdvancesCursor(t *testing.T) {
	ctx := context.Background()
	router := &lockedRecordingRouter{}
	l, store, acct := newTestListener(t, router)
	if err := store.AdvanceSavedCommandCursor(ctx, acct.userID, 70); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	forwarded := savedHistoryMessage(72, "/mctl approve FORWARDED")
	forwarded.SetFwdFrom(tg.MessageFwdHeader{Date: 1})
	otherPeer := savedHistoryMessage(73, "/mctl status")
	otherPeer.PeerID = &tg.PeerUser{UserID: recruit}
	mediaOnly := savedHistoryMessage(74, "")
	agentNotification := savedHistoryMessage(75, "/mctl status")
	l.MarkSent(acct.userID, int64(agentNotification.ID))

	api := &fakeSavedHistoryAPI{results: []historyResult{{
		// Deliberately descending, matching Telegram's wire order. The poller
		// must process and advance in ascending id order.
		messages: []tg.MessageClass{
			agentNotification,
			mediaOnly,
			otherPeer,
			forwarded,
			savedHistoryMessage(71, "ordinary private note"),
		},
	}}}
	if err := l.pollSavedHistory(ctx, acct, api); err != nil {
		t.Fatalf("history poll: %v", err)
	}
	if router.callCount() != 0 {
		t.Fatalf("ignored messages routed %d commands", router.callCount())
	}
	if got := cursorForTest(t, store, acct.userID); got != 75 {
		t.Fatalf("cursor = %d, want 75", got)
	}
}

func TestPollSavedHistory_RouterErrorStopsCursorAndRetries(t *testing.T) {
	ctx := context.Background()
	router := &lockedRecordingRouter{err: errors.New("control database unavailable")}
	l, store, acct := newTestListener(t, router)
	if err := store.AdvanceSavedCommandCursor(ctx, acct.userID, 80); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
	command := savedHistoryMessage(82, "/mctl pause")
	api := &fakeSavedHistoryAPI{results: []historyResult{
		{messages: []tg.MessageClass{
			savedHistoryMessage(83, "after command"),
			command,
			savedHistoryMessage(81, "before command"),
		}},
		{messages: []tg.MessageClass{
			savedHistoryMessage(83, "after command"),
			command,
		}},
	}}

	if err := l.pollSavedHistory(ctx, acct, api); err == nil {
		t.Fatal("router failure was swallowed")
	}
	if got := cursorForTest(t, store, acct.userID); got != 81 {
		t.Fatalf("cursor crossed failed command: got %d, want 81", got)
	}
	router.mu.Lock()
	router.err = nil
	router.mu.Unlock()
	if err := l.pollSavedHistory(ctx, acct, api); err != nil {
		t.Fatalf("retry poll: %v", err)
	}
	if got := cursorForTest(t, store, acct.userID); got != 83 {
		t.Fatalf("cursor after retry = %d, want 83", got)
	}
	if router.callCount() != 2 {
		t.Fatalf("router calls = %d, want failed attempt + retry", router.callCount())
	}
}

func TestPollSavedHistory_PersistedCursorAvoidsReplayAfterRestart(t *testing.T) {
	ctx := context.Background()
	firstRouter := &lockedRecordingRouter{}
	first, store, acct := newTestListener(t, firstRouter)
	if err := store.AdvanceSavedCommandCursor(ctx, acct.userID, 90); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
	firstMessage := savedHistoryMessage(91, "/mctl status")
	if err := first.pollSavedHistory(ctx, acct, &fakeSavedHistoryAPI{results: []historyResult{{
		messages: []tg.MessageClass{firstMessage},
	}}}); err != nil {
		t.Fatalf("first process: %v", err)
	}

	secondRouter := &lockedRecordingRouter{}
	second := New(store, queue.New(store, "listener-restart-test", nil), secondRouter, nil)
	secondAcct := &account{userID: acct.userID, tgID: acct.tgID}
	if err := second.pollSavedHistory(ctx, secondAcct, &fakeSavedHistoryAPI{results: []historyResult{{
		messages: []tg.MessageClass{
			savedHistoryMessage(92, "/mctl leads"),
			firstMessage,
		},
	}}}); err != nil {
		t.Fatalf("restart process: %v", err)
	}
	if firstRouter.callCount() != 1 || secondRouter.callCount() != 1 {
		t.Fatalf("router calls before/after restart = %d/%d", firstRouter.callCount(), secondRouter.callCount())
	}
	if got := cursorForTest(t, store, acct.userID); got != 92 {
		t.Fatalf("restart cursor = %d, want 92", got)
	}
}

func TestPollSavedHistory_RPCFailureDoesNotBreakInboundDM(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if err := store.AdvanceSavedCommandCursor(ctx, acct.userID, 100); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
	api := &fakeSavedHistoryAPI{results: []historyResult{{err: errors.New("FLOOD_WAIT_5")}}}
	if err := l.pollSavedHistory(ctx, acct, api); err == nil {
		t.Fatal("history RPC error was swallowed by one-shot poll")
	}

	dm := &tg.Message{ID: 101, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Hello"}
	if err := l.onMessage(ctx, acct, ents(&tg.User{ID: recruit}), dm, false); err != nil {
		t.Fatalf("inbound DM after history failure: %v", err)
	}
	var jobs int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM agent_jobs`).Scan(&jobs); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if jobs != 1 {
		t.Fatalf("inbound DM jobs = %d, want 1", jobs)
	}
}

// TestPollSavedHistory_RoutesCommandWithOutFalse guards against a regression
// found live on 2026-07-26: messages.getHistory against Peer: InputPeerSelf
// does not reliably set Out the way the live push path's UpdateNewMessage
// does -- a real owner-typed /mctl command was observed coming back with
// Out: false, which the original ExtractMessage-based implementation
// silently misclassified as an ordinary inbound private_message (since its
// self-chat/command branch is gated on msg.Out) instead of routing it at
// all. ExtractSavedHistoryMessage must not depend on Out.
func TestPollSavedHistory_RoutesCommandWithOutFalse(t *testing.T) {
	ctx := context.Background()
	router := &lockedRecordingRouter{}
	l, store, acct := newTestListener(t, router)
	if err := store.AdvanceSavedCommandCursor(ctx, acct.userID, 100); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
	msg := &tg.Message{
		ID: 101, Out: false,
		PeerID:  &tg.PeerUser{UserID: selfTG},
		Message: "/mctl approve OUTFALSE",
	}
	api := &fakeSavedHistoryAPI{results: []historyResult{{messages: []tg.MessageClass{msg}}}}

	if err := l.pollSavedHistory(ctx, acct, api); err != nil {
		t.Fatalf("history poll: %v", err)
	}
	if router.callCount() != 1 {
		t.Fatalf("router calls = %d, want 1 (Out:false command was not routed)", router.callCount())
	}
	eventID := eventIDForMessage(acct.tgID, acct.tgID, 101, 0, "/mctl approve OUTFALSE")
	event, err := store.GetIncomingEvent(ctx, acct.userID, eventID)
	if err != nil {
		t.Fatalf("get incoming event: %v", err)
	}
	if event.Kind != db.EventKindSavedCommand {
		t.Fatalf("event kind = %q, want %q", event.Kind, db.EventKindSavedCommand)
	}
}
