package humaninput_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/control"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/humaninput"
	"github.com/mctlhq/mctl-telegram/internal/workctx"
)

const (
	aliceTGID = int64(700300)
	bobTGID   = int64(700301)
)

// fakeAPI is a scriptable mctl-api human-input relay.
type fakeAPI struct {
	mu sync.Mutex

	listByActor map[int64][]workctx.RequestView
	listErr     error
	getView     *workctx.RequestView
	getErr      error
	respondErr  error
	respondResp *workctx.ResponseView

	listCalls    int
	getCalls     int
	respondCalls []respondCall
}

type respondCall struct {
	actor     int64
	requestID string
	req       workctx.ResponseRequest
	idemKey   string
}

func (f *fakeAPI) ListHumanInput(_ context.Context, actor int64) ([]workctx.RequestView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listByActor[actor], nil
}

func (f *fakeAPI) GetHumanInput(_ context.Context, _ int64, _ string) (*workctx.RequestView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getView, nil
}

func (f *fakeAPI) RespondHumanInput(_ context.Context, actor int64, requestID string, r workctx.ResponseRequest, idem string) (*workctx.ResponseView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.respondCalls = append(f.respondCalls, respondCall{actor, requestID, r, idem})
	if f.respondErr != nil {
		return nil, f.respondErr
	}
	if f.respondResp != nil {
		return f.respondResp, nil
	}
	return &workctx.ResponseView{RequestID: requestID, State: workctx.HumanInputStateAnswered}, nil
}

type fakeSender struct {
	sent      []string
	randomIDs []int64
}

func (f *fakeSender) SendToSelf(_ context.Context, _ int64, text string) (int64, error) {
	f.sent = append(f.sent, text)
	return int64(1000 + len(f.sent)), nil
}

func (f *fakeSender) SendToSelfWithRandomID(_ context.Context, _, randomID int64, text string) (int64, error) {
	f.sent = append(f.sent, text)
	f.randomIDs = append(f.randomIDs, randomID)
	return int64(1000 + len(f.sent)), nil
}

type fakeApprover struct{ approve, reject []string }

func (f *fakeApprover) Approve(_ context.Context, _ int64, code string) error {
	f.approve = append(f.approve, code)
	return errors.New("not found")
}
func (f *fakeApprover) Reject(_ context.Context, _ int64, code string) error {
	f.reject = append(f.reject, code)
	return errors.New("not found")
}

type env struct {
	store    *db.Store
	uid      int64
	api      *fakeAPI
	sender   *fakeSender
	notifier *control.Notifier
	approver *fakeApprover
	router   *control.Router
	poller   *humaninput.Poller
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	crypt, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	uid, err := store.EnsureUserByTelegramID(ctx, aliceTGID, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := store.UpsertHumanInputActor(ctx, uid, aliceTGID); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	e := &env{store: store, uid: uid, api: &fakeAPI{listByActor: map[int64][]workctx.RequestView{}}, sender: &fakeSender{}, approver: &fakeApprover{}}
	e.notifier = control.NewNotifier(store, e.sender)
	e.router = control.NewRouter(store, e.approver, e.notifier)
	e.router.Input = &humaninput.Handler{Store: store, API: e.api, Replier: e.notifier}
	e.poller = &humaninput.Poller{Store: store, API: e.api}
	return e
}

func choiceReq(id, hash string) workctx.RequestView {
	return workctx.RequestView{
		RequestID: id, RequestHash: hash, Version: 1, Kind: workctx.HumanInputKindSingleChoice,
		State: workctx.HumanInputStatePending, Question: "Which interpretation?", Why: "Two readings exist.",
		Options:    []workctx.HumanInputOption{{ID: "opt-a", Label: "Alpha reading"}, {ID: "opt-b", Label: "Bravo reading"}},
		Deadline:   "2026-10-04T12:00:00Z",
		WorkItemID: "wi_1",
	}
}

// deliver runs the poller then the notifier and returns the delivered text.
func (e *env) deliver(t *testing.T) []string {
	t.Helper()
	ctx := context.Background()
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	before := len(e.sender.sent)
	if _, _, err := e.notifier.DeliverPending(ctx); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	return e.sender.sent[before:]
}

func (e *env) say(t *testing.T, msgID int64, text string) string {
	t.Helper()
	before := len(e.sender.sent)
	meta := control.SavedMeta{UserID: e.uid, SelfTGID: aliceTGID, ChatTGID: aliceTGID, TGMessageID: msgID}
	if err := e.router.HandleSavedText(context.Background(), meta, text); err != nil {
		t.Fatalf("handle %q: %v", text, err)
	}
	if len(e.sender.sent) != before+1 {
		t.Fatalf("replies for %q = %d, want 1", text, len(e.sender.sent)-before)
	}
	return e.sender.sent[len(e.sender.sent)-1]
}

func (e *env) codeOf(t *testing.T, msg string) string {
	t.Helper()
	i := strings.Index(msg, "/mctl input ")
	if i < 0 {
		t.Fatalf("no answer line in %q", msg)
	}
	f := strings.Fields(msg[i:])
	return f[2]
}

// T1.
func TestRenderSingleChoiceAndFreeText(t *testing.T) {
	v := choiceReq("hi_1", "h1")
	v.WorkRef = "mctlhq/mctl-telegram#571"
	got := humaninput.Render(v, "K7QM3R")
	for _, want := range []string{
		"INPUT REQUEST (not an approval)", "Work: mctlhq/mctl-telegram#571", "Question: Which interpretation?",
		"Why: Two readings exist.", "  1. Alpha reading", "  2. Bravo reading", "Deadline: 2026-10-04 12:00 UTC",
		"Answer: /mctl input K7QM3R <number>", "Ref: request hi_1 v1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("render missing %q in:\n%s", want, got)
		}
	}
	ft := workctx.RequestView{RequestID: "hi_2", RequestHash: "h2", Version: 3, Kind: workctx.HumanInputKindFreeText, Question: "Which branch name?"}
	got = humaninput.Render(ft, "ABCDEF")
	if !strings.Contains(got, "Answer: /mctl input ABCDEF <your answer>") || strings.Contains(got, "Options:") {
		t.Errorf("free text render:\n%s", got)
	}
}

// T11 (render half): unallowlisted wire fields never render; message capped.
func TestRenderIgnoresUnallowlistedAndCaps(t *testing.T) {
	var v workctx.RequestView
	wire := `{"request_id":"hi_1","request_hash":"h","kind":"free_text","question":"` + strings.Repeat("q", 5000) +
		`","why":"` + strings.Repeat("w", 5000) + `","prompt":"SECRET-PROMPT","reasoning":"SECRET-REASONING","logs":"SECRET-LOGS"}`
	if err := json.Unmarshal([]byte(wire), &v); err != nil {
		t.Fatal(err)
	}
	got := humaninput.Render(v, "ABCDEF")
	for _, s := range []string{"SECRET-PROMPT", "SECRET-REASONING", "SECRET-LOGS"} {
		if strings.Contains(got, s) {
			t.Errorf("render leaked %s", s)
		}
	}
	if n := len([]rune(got)); n > 4096 {
		t.Errorf("render is %d runes, want <= 4096", n)
	}
	if !strings.Contains(got, "Answer: /mctl input ABCDEF") {
		t.Error("answer line must survive the cap")
	}
}

// T2 + T6 (no resend after send) + T14.
func TestPollDedupAndDelivery(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.store.UpsertWorkItemBinding(ctx, db.WorkItemBinding{
		UserID: e.uid, ChatTGID: aliceTGID, RootTGMessageID: 5, WorkItemID: "wi_1",
		ExternalKey: "https://github.com/mctlhq/mctl-telegram/issues/571",
	}); err != nil {
		t.Fatal(err)
	}
	e.api.listByActor[aliceTGID] = []workctx.RequestView{choiceReq("hi_1", "h1")}
	for i := 0; i < 3; i++ {
		if err := e.poller.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// "Restart": a new Poller over the same DB.
	e.poller = &humaninput.Poller{Store: e.store, API: e.api}
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM owner_notifications WHERE kind = $1`, db.NotificationHumanInput).Scan(&n); err != nil || n != 1 {
		t.Fatalf("notifications = %d err=%v, want 1", n, err)
	}
	if _, _, err := e.notifier.DeliverPending(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.sender.sent) != 1 || !strings.Contains(e.sender.sent[0], "Work: mctlhq/mctl-telegram#571") {
		t.Fatalf("sent = %q", e.sender.sent)
	}
	// Sent rows are not resent.
	if _, _, err := e.notifier.DeliverPending(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.notifier.DeliverPending(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.sender.sent) != 1 {
		t.Fatalf("resent: %d messages", len(e.sender.sent))
	}
	open, _ := e.store.ListOpenHumanInputDeliveries(ctx, e.uid)
	if len(open) != 1 || open[0].State != db.HumanInputSent || open[0].TGMessageID == 0 {
		t.Fatalf("open = %+v", open)
	}
}

// T8.
func TestSupersededAndNoLongerActive(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.api.listByActor[aliceTGID] = []workctx.RequestView{choiceReq("hi_1", "h1")}
	first := e.deliver(t)
	if len(first) != 1 {
		t.Fatalf("first delivery = %d", len(first))
	}
	oldCode := e.codeOf(t, first[0])

	// New hash for the same request id: new code, old row superseded.
	e.api.listByActor[aliceTGID] = []workctx.RequestView{choiceReq("hi_1", "h2")}
	second := e.deliver(t)
	if len(second) != 1 {
		t.Fatalf("second delivery = %d", len(second))
	}
	newCode := e.codeOf(t, second[0])
	if newCode == oldCode {
		t.Fatal("new version must carry a new code")
	}
	old, _ := e.store.GetHumanInputDeliveryByCode(ctx, e.uid, oldCode)
	if old.State != db.HumanInputSuperseded {
		t.Fatalf("old state = %s", old.State)
	}

	// Request leaves the list: one follow-up, terminal row, no repeats.
	e.api.listByActor[aliceTGID] = nil
	follow := e.deliver(t)
	if len(follow) != 1 || !strings.HasPrefix(follow[0], humaninput.NoLongerActive) {
		t.Fatalf("follow-up = %q", follow)
	}
	if again := e.deliver(t); len(again) != 0 {
		t.Fatalf("second follow-up: %q", again)
	}
	cur, _ := e.store.GetHumanInputDeliveryByCode(ctx, e.uid, newCode)
	if cur.State != db.HumanInputInactive {
		t.Fatalf("state = %s", cur.State)
	}
}

// A failed list must not be read as "request gone".
func TestListFailureDoesNotRetireDeliveries(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.api.listByActor[aliceTGID] = []workctx.RequestView{choiceReq("hi_1", "h1")}
	e.deliver(t)
	e.api.listErr = &workctx.APIError{StatusCode: 503, Code: "unavailable"}
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("unexpected follow-up %q", got)
	}
	open, _ := e.store.ListOpenHumanInputDeliveries(ctx, e.uid)
	if len(open) != 1 {
		t.Fatalf("open = %d, want 1", len(open))
	}
}

// T9 (poll half).
func TestLinkNotFoundMakesActorDormant(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.api.listErr = fmt.Errorf("%w: x", workctx.ErrLinkNotFound)
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if e.api.listCalls != 1 {
		t.Fatalf("list calls = %d, want 1 (second poll skips the dormant actor)", e.api.listCalls)
	}
	if act, _ := e.store.ListPollableHumanInputActors(ctx, time.Now()); len(act) != 0 {
		t.Fatalf("actor still pollable: %+v", act)
	}
}

func TestKillSwitchSkipsPolling(t *testing.T) {
	e := newEnv(t)
	e.poller.GlobalKill = func() bool { return true }
	e.api.listByActor[aliceTGID] = []workctx.RequestView{choiceReq("hi_1", "h1")}
	if err := e.poller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.api.listCalls != 0 {
		t.Fatal("kill switch must stop polling")
	}
}

func deliveredCode(t *testing.T, e *env, reqs ...workctx.RequestView) string {
	t.Helper()
	e.api.listByActor[aliceTGID] = reqs
	got := e.deliver(t)
	if len(got) != 1 {
		t.Fatalf("delivered %d messages", len(got))
	}
	return e.codeOf(t, got[0])
}

// T3.
func TestAnswerBindsExactRequestAndStableIdemKey(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))
	reply := e.say(t, 77, "/mctl input "+strings.ToLower(code)+" 2")
	if !strings.HasPrefix(reply, "Answered by you: option 2.") || !strings.Contains(reply, "Agent will resume.") {
		t.Fatalf("reply = %q", reply)
	}
	if len(e.api.respondCalls) != 1 {
		t.Fatalf("respond calls = %d", len(e.api.respondCalls))
	}
	c := e.api.respondCalls[0]
	if c.actor != aliceTGID || c.requestID != "hi_1" || c.req.RequestHash != "h1" || c.req.Kind != "single_choice" || c.req.Value != "opt-b" {
		t.Fatalf("call = %+v", c)
	}
	row, _ := e.store.GetHumanInputDeliveryByCode(context.Background(), e.uid, code)
	if row.State != db.HumanInputAnswered {
		t.Fatalf("state = %s", row.State)
	}

	// Same Telegram message redelivered after the row was reset: same key.
	if _, err := e.store.DB.Exec(`UPDATE human_input_deliveries SET state = 'sent'`); err != nil {
		t.Fatal(err)
	}
	e.say(t, 77, "/mctl input "+code+" 2")
	if _, err := e.store.DB.Exec(`UPDATE human_input_deliveries SET state = 'sent'`); err != nil {
		t.Fatal(err)
	}
	e.say(t, 78, "/mctl input "+code+" 2")
	if len(e.api.respondCalls) != 3 {
		t.Fatalf("respond calls = %d", len(e.api.respondCalls))
	}
	if e.api.respondCalls[0].idemKey != e.api.respondCalls[1].idemKey {
		t.Error("idempotency key must be stable across redelivery of the same message")
	}
	if e.api.respondCalls[1].idemKey == e.api.respondCalls[2].idemKey {
		t.Error("idempotency key must differ for a different command message")
	}
}

func TestAnswerShapeValidationNeverCallsAPI(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))
	for _, in := range []string{"/mctl input " + code + " 0", "/mctl input " + code + " 3", "/mctl input " + code + " maybe", "/mctl input " + code} {
		reply := e.say(t, 80, in)
		if !strings.Contains(reply, "/mctl input") {
			t.Errorf("no usage hint for %q: %q", in, reply)
		}
	}
	if len(e.api.respondCalls) != 0 {
		t.Fatalf("respond calls = %d, want 0", len(e.api.respondCalls))
	}
	// An option id shown in the stored row is accepted too.
	e.say(t, 81, "/mctl input "+code+" opt-a")
	if len(e.api.respondCalls) != 1 || e.api.respondCalls[0].req.Value != "opt-a" {
		t.Fatalf("calls = %+v", e.api.respondCalls)
	}
}

func TestFreeTextAnswerCapAndWhitespace(t *testing.T) {
	e := newEnv(t)
	ft := workctx.RequestView{RequestID: "hi_2", RequestHash: "h2", Version: 1, Kind: workctx.HumanInputKindFreeText, Question: "Branch name?", MaxLength: 10}
	code := deliveredCode(t, e, ft)
	reply := e.say(t, 90, "/mctl input "+code+"   use  the   long branch name please  ")
	if len(e.api.respondCalls) != 1 {
		t.Fatalf("calls = %d", len(e.api.respondCalls))
	}
	if got := e.api.respondCalls[0].req.Value; got != "use  the  " {
		t.Errorf("value = %q, want first 10 runes with inner spacing kept", got)
	}
	if !strings.HasPrefix(reply, "Answered by you: use  the") {
		t.Errorf("reply = %q", reply)
	}
}

// T4.
func TestStaleHashRendersNoLongerActive(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))
	e.api.respondErr = fmt.Errorf("%w: %w", workctx.ErrRequestSuperseded, &workctx.APIError{StatusCode: 409, Code: "request_hash_mismatch"})
	if reply := e.say(t, 100, "/mctl input "+code+" 1"); reply != humaninput.NoLongerActive {
		t.Fatalf("reply = %q", reply)
	}
	row, _ := e.store.GetHumanInputDeliveryByCode(context.Background(), e.uid, code)
	if row.State != db.HumanInputSuperseded {
		t.Fatalf("state = %s", row.State)
	}
}

// T5.
func TestDoubleAnswer(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))
	e.say(t, 110, "/mctl input "+code+" 1")
	if reply := e.say(t, 111, "/mctl input "+code+" 1"); reply != "Already answered." {
		t.Fatalf("reply = %q", reply)
	}
	if len(e.api.respondCalls) != 1 {
		t.Fatalf("platform writes = %d, want 1", len(e.api.respondCalls))
	}
	// And the platform's own already_answered is rendered the same way.
	e2 := newEnv(t)
	code2 := deliveredCode(t, e2, choiceReq("hi_9", "h9"))
	e2.api.respondErr = fmt.Errorf("%w: %w", workctx.ErrAlreadyAnswered, &workctx.APIError{StatusCode: 409, Code: "already_answered"})
	if reply := e2.say(t, 112, "/mctl input "+code2+" 1"); reply != "Already answered." {
		t.Fatalf("reply = %q", reply)
	}
}

// T7.
func TestTimeoutAfterAcceptanceRendersCanonicalState(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))
	e.api.respondErr = errors.New("workctx: do request: context deadline exceeded")
	v := choiceReq("hi_1", "h1")
	v.State = workctx.HumanInputStateAnswered
	e.api.getView = &v
	reply := e.say(t, 120, "/mctl input "+code+" 1")
	if !strings.HasPrefix(reply, "Answered.") || strings.Contains(reply, "Agent will resume") {
		t.Fatalf("reply = %q", reply)
	}
	row, _ := e.store.GetHumanInputDeliveryByCode(context.Background(), e.uid, code)
	if row.State != db.HumanInputAnswered {
		t.Fatalf("state = %s", row.State)
	}

	// Both calls fail: never success.
	e2 := newEnv(t)
	code2 := deliveredCode(t, e2, choiceReq("hi_2", "h2"))
	e2.api.respondErr = errors.New("timeout")
	e2.api.getErr = errors.New("timeout")
	reply = e2.say(t, 121, "/mctl input "+code2+" 1")
	if reply != "Could not confirm; check again with /mctl input status "+code2 {
		t.Fatalf("reply = %q", reply)
	}
	if strings.Contains(strings.ToLower(reply), "answered by you") {
		t.Fatal("must not claim success")
	}
}

// T9 (submit half) and T10.
func TestNotEligibleIsNeutralAndNotTerminal(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))
	e.api.respondErr = fmt.Errorf("%w: %w", workctx.ErrNotEligible, &workctx.APIError{StatusCode: 403, Code: "not_eligible", Message: "policy detail eligible_group=ops"})
	reply := e.say(t, 130, "/mctl input "+code+" 1")
	if strings.Contains(reply, "policy") || strings.Contains(reply, "eligible_group") || strings.Contains(strings.ToLower(reply), "eligib") {
		t.Fatalf("reply reveals policy: %q", reply)
	}
	if len(e.api.respondCalls) != 1 {
		t.Fatalf("calls = %d (no retry expected)", len(e.api.respondCalls))
	}
	row, _ := e.store.GetHumanInputDeliveryByCode(context.Background(), e.uid, code)
	if row.Terminal() {
		t.Fatalf("a 403 must not mark the row terminal: %s", row.State)
	}
}

func TestSecondRespondentGetsNotActive(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))
	e.api.respondErr = fmt.Errorf("%w: %w", workctx.ErrRequestNotActive, &workctx.APIError{StatusCode: 409, Code: "request_not_active"})
	if reply := e.say(t, 140, "/mctl input "+code+" 2"); reply != humaninput.NoLongerActive {
		t.Fatalf("reply = %q", reply)
	}
	row, _ := e.store.GetHumanInputDeliveryByCode(context.Background(), e.uid, code)
	if row.State != db.HumanInputInactive {
		t.Fatalf("state = %s", row.State)
	}
}

func TestStatusRendersCanonicalState(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))
	v := choiceReq("hi_1", "h1")
	e.api.getView = &v
	if reply := e.say(t, 150, "/mctl input status "+code); reply != "Waiting for your answer." {
		t.Fatalf("pending reply = %q", reply)
	}
	if reply := e.say(t, 151, "/mctl input status"); !strings.HasPrefix(reply, code+": ") {
		t.Fatalf("list reply = %q", reply)
	}
	v.State = workctx.HumanInputStateExpired
	if reply := e.say(t, 152, "/mctl input status "+code); reply != humaninput.NoLongerActive {
		t.Fatalf("expired reply = %q", reply)
	}
	if reply := e.say(t, 153, "/mctl input status"); reply != "No open input requests." {
		t.Fatalf("empty reply = %q", reply)
	}
}

func TestUnlinkedSelfPeerFailsClosed(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))
	before := len(e.sender.sent)
	meta := control.SavedMeta{UserID: e.uid, SelfTGID: bobTGID, ChatTGID: bobTGID, TGMessageID: 5}
	if err := e.router.HandleSavedText(context.Background(), meta, "/mctl input "+code+" 1"); err != nil {
		t.Fatal(err)
	}
	if len(e.sender.sent) != before+1 || len(e.api.respondCalls) != 0 {
		t.Fatalf("replies=%d respond=%d", len(e.sender.sent)-before, len(e.api.respondCalls))
	}
}

// T12.
func TestApprovalIsolation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	code := deliveredCode(t, e, choiceReq("hi_1", "h1"))

	// An approval code typed as an answer does not resolve an agent action.
	reply := e.say(t, 160, "/mctl input AB23CD yes")
	if reply != humaninput.NoLongerActive {
		t.Fatalf("reply = %q", reply)
	}
	e.say(t, 161, "/mctl input "+code+" 1")
	if len(e.approver.approve)+len(e.approver.reject) != 0 {
		t.Fatalf("approval path invoked: %+v", e.approver)
	}
	// A human-input code is not an agent-action approval code.
	if _, err := e.store.GetAgentActionByCode(ctx, e.uid, code); err == nil {
		t.Fatal("human-input code resolved an agent action")
	}
	if e.api.respondCalls[0].req.Value == "yes" {
		t.Fatal("unexpected value")
	}
}

// T13.
func TestFlagOffIsUnknownCommand(t *testing.T) {
	e := newEnv(t)
	e.router.Input = nil
	baseline := e.say(t, 1, "/mctl frobnicate")
	for _, in := range []string{"/mctl input ABCDEF 1", "/mctl input status", "/mctl input"} {
		if got := e.say(t, 2, in); got != baseline {
			t.Errorf("%q reply = %q, want unknown-command reply", in, got)
		}
	}
	if e.api.listCalls+e.api.getCalls+len(e.api.respondCalls) != 0 {
		t.Fatal("flag off must make no human-input calls")
	}
}

// T11 (log half): neither poll nor answer logs question, option or answer text.
func TestLogsCarryNoContent(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newEnv(t)
	v := choiceReq("hi_1", "h1")
	v.Question = "ZQXQUESTIONTEXT"
	v.Options = []workctx.HumanInputOption{{ID: "opt-a", Label: "ZQXLABELONE"}, {ID: "opt-b", Label: "ZQXLABELTWO"}}
	code := deliveredCode(t, e, v)
	e.say(t, 170, "/mctl input "+code+" 2")

	ft := workctx.RequestView{RequestID: "hi_2", RequestHash: "h2", Version: 1, Kind: workctx.HumanInputKindFreeText, Question: "ZQXFREEQ"}
	code2 := deliveredCode(t, e, ft)
	e.say(t, 171, "/mctl input "+code2+" ZQXANSWERTEXT")
	e.api.respondErr = errors.New("boom")
	e.api.getErr = errors.New("boom")
	code3 := deliveredCode(t, e, workctx.RequestView{RequestID: "hi_3", RequestHash: "h3", Version: 1, Kind: workctx.HumanInputKindFreeText, Question: "ZQXFREEQ3"})
	e.say(t, 172, "/mctl input "+code3+" ZQXANSWERTWO")

	logs := buf.String()
	if logs == "" {
		t.Fatal("expected some log output")
	}
	for _, s := range []string{"ZQX"} {
		if strings.Contains(logs, s) {
			t.Fatalf("logs contain content marker %q:\n%s", s, logs)
		}
	}
}
