package humaninput_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/control"
	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/humaninput"
	"github.com/mctlhq/mctl-telegram/internal/workctx"
)

const (
	aliceTGID = int64(700300)
	bobTGID   = int64(700301)

	reqA = "hir-00000000000000a1"
	reqB = "hir-00000000000000b2"
	reqC = "hir-00000000000000c3"
)

// fakeMCTL is an httptest stand-in for mctl-api's human-input relay routes,
// speaking the pinned wire contract (docs/contracts/mctl-api-human-input.md):
// list {"items","count"}, the redacted request view, and the response result
// {request_id,status,state,detail}. The adapter talks to it through the real
// workctx.Client, so the wire shapes and error mapping are exercised end to
// end.
type fakeMCTL struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex
	// pending is what GET /human-input lists, per relayed Telegram id.
	pending map[int64][]workctx.RequestView
	// views is what GET /human-input/{id} returns (any state). A missing id
	// answers 404.
	views map[string]workctx.RequestView
	// listStatus, when non-zero, makes the list answer that status with
	// listBody (an error object).
	listStatus int
	listBody   string
	// getFail makes GET /human-input/{id} drop the connection.
	getFail bool
	// respond decides a POST .../response. nil means 200 accepted.
	respond func(actor int64, id string, body map[string]any) (int, any)

	lists, gets int
	posts       []post
	requests    atomic.Int64
	// getHang makes GET /human-input/{id} hang until the client gives up;
	// hungGets counts those calls.
	getHang  atomic.Bool
	hungGets atomic.Int64
}

type post struct {
	actor int64
	id    string
	body  map[string]any
	idem  string
}

func newFakeMCTL(t *testing.T) *fakeMCTL {
	f := &fakeMCTL{t: t, pending: map[int64][]workctx.RequestView{}, views: map[string]workctx.RequestView{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func dropConn(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("no hijacker")
	}
	conn, _, err := hj.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func (f *fakeMCTL) serve(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	if f.getHang.Load() && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/human-input/") {
		f.hungGets.Add(1)
		<-r.Context().Done()
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	actor, _ := strconv.ParseInt(r.Header.Get("X-MCTL-Surface-Actor"), 10, 64)
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/human-input")
	if !ok {
		f.t.Errorf("unexpected path %s", r.URL.Path)
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	switch {
	case r.Method == http.MethodGet && rest == "":
		f.lists++
		if f.listStatus != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.listStatus)
			_, _ = w.Write([]byte(f.listBody))
			return
		}
		items := f.pending[actor]
		if items == nil {
			items = []workctx.RequestView{}
		}
		writeJSON(w, 200, map[string]any{"items": items, "count": len(items)})
	case r.Method == http.MethodGet:
		f.gets++
		if f.getFail {
			dropConn(w)
			return
		}
		v, ok := f.views[strings.TrimPrefix(rest, "/")]
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "human-input request not found"})
			return
		}
		writeJSON(w, 200, v)
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/response"):
		id := strings.TrimSuffix(strings.TrimPrefix(rest, "/"), "/response")
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields() // as mctl-api does
		var body map[string]any
		if err := dec.Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid JSON body"})
			return
		}
		for k := range body {
			if k != "request_hash" && k != "value" && k != "surface" {
				writeJSON(w, 400, map[string]string{"error": "invalid JSON body: unknown field " + k})
				return
			}
		}
		f.posts = append(f.posts, post{actor: actor, id: id, body: body, idem: r.Header.Get("Idempotency-Key")})
		if f.respond == nil {
			writeJSON(w, 200, map[string]any{"request_id": id, "status": "accepted", "state": "resolved", "respondent": "github:alice"})
			return
		}
		status, out := f.respond(actor, id, body)
		if status == 0 {
			dropConn(w)
			return
		}
		writeJSON(w, status, out)
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

// publish lists reqs as pending for actor and makes each readable.
func (f *fakeMCTL) publish(actor int64, reqs ...workctx.RequestView) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending[actor] = reqs
	for _, r := range reqs {
		f.views[r.RequestID] = r
	}
}

// setState changes the canonical state of id (GET only).
func (f *fakeMCTL) setState(id, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.views[id]
	v.State = state
	f.views[id] = v
}

// with runs fn under the fake's lock, for scripting it from a test.
func (f *fakeMCTL) with(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fakeMCTL) getCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets
}

func (f *fakeMCTL) listCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists
}

func (f *fakeMCTL) postsCopy() []post {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]post(nil), f.posts...)
}

func (f *fakeMCTL) postCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.posts)
}

func rejection(id, state string) any {
	return map[string]any{"request_id": id, "status": "rejected", "state": state, "detail": "single_choice answer must be one of [SECRET-OPTION]", "respondent": "github:alice"}
}

type fakeSender struct {
	mu        sync.Mutex
	sent      []string
	randomIDs []int64
	// failSends makes the next N SendToSelfWithRandomID calls fail after
	// recording their random id (a crash or RPC failure mid-send).
	failSends int
}

func (f *fakeSender) SendToSelf(_ context.Context, _ int64, text string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, text)
	return int64(1000 + len(f.sent)), nil
}

func (f *fakeSender) SendToSelfWithRandomID(_ context.Context, _, randomID int64, text string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.randomIDs = append(f.randomIDs, randomID)
	if f.failSends > 0 {
		f.failSends--
		return 0, errors.New("send failed")
	}
	f.sent = append(f.sent, text)
	return int64(1000 + len(f.sent)), nil
}

// recordingApprover counts every Approve/Reject that reaches the approval
// path. inner, when set, is the real executor the call is forwarded to.
type recordingApprover struct {
	approve, reject []string
	inner           control.Approver
}

func (f *recordingApprover) Approve(ctx context.Context, uid int64, code string) error {
	f.approve = append(f.approve, code)
	if f.inner != nil {
		return f.inner.Approve(ctx, uid, code)
	}
	return executor.ErrApprovalCodeNotFound
}

func (f *recordingApprover) Reject(ctx context.Context, uid int64, code string) error {
	f.reject = append(f.reject, code)
	if f.inner != nil {
		return f.inner.Reject(ctx, uid, code)
	}
	return executor.ErrApprovalCodeNotFound
}

type env struct {
	store    *db.Store
	uid      int64
	api      *fakeMCTL
	client   *workctx.Client
	sender   *fakeSender
	notifier *control.Notifier
	approver *recordingApprover
	router   *control.Router
	poller   *humaninput.Poller
}

var dbSeq atomic.Int64

func newStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	// A distinct named in-memory database per env: an unnamed shared-cache
	// DSN would give every env in the process the same database.
	dsn := fmt.Sprintf("file:humaninput_%s_%d?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()), dbSeq.Add(1))
	conn, err := db.Open(ctx, dsn, 0, 0)
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
	return db.NewStore(conn, crypt)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	store := newStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, aliceTGID, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := store.UpsertHumanInputActor(ctx, uid, aliceTGID); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	api := newFakeMCTL(t)
	e := &env{store: store, uid: uid, api: api, client: workctx.NewClient(api.srv.URL, "tok", "tenant", nil), sender: &fakeSender{}, approver: &recordingApprover{}}
	e.notifier = control.NewNotifier(store, e.sender)
	e.router = control.NewRouter(store, e.approver, e.notifier)
	h, p := humaninput.New(true, humaninput.Deps{Store: store, API: e.client, Replier: e.notifier})
	e.router.Input = h
	e.poller = p
	// Every test ends by asserting no answer ever reached the approval path.
	t.Cleanup(func() {
		if n := len(e.approver.approve) + len(e.approver.reject); n != 0 && !t.Failed() {
			t.Errorf("approval path invoked %d time(s): %+v", n, e.approver)
		}
	})
	return e
}

func yes() *bool { b := true; return &b }

func choiceReq(id, hash string) workctx.RequestView {
	return workctx.RequestView{
		RequestID: id, RequestHash: hash, RequestVersion: 1, Round: 1, ResponseType: workctx.HumanInputTypeSingleChoice,
		State: workctx.HumanInputStatePending, Question: "Which interpretation?", Reason: "Two readings exist.",
		Options:    []string{"Alpha reading", "Bravo reading"},
		ExpiresAt:  "2026-10-04T12:00:00Z",
		WorkItemID: "wi_1", CanRespond: yes(),
	}
}

func freeReq(id, hash, question string) workctx.RequestView {
	return workctx.RequestView{
		RequestID: id, RequestHash: hash, RequestVersion: 1, Round: 1, ResponseType: workctx.HumanInputTypeFreeText,
		State: workctx.HumanInputStatePending, Question: question, ExpiresAt: "2026-10-04T12:00:00Z", CanRespond: yes(),
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

func (e *env) sayAs(t *testing.T, uid, tgID, msgID int64, text string) string {
	t.Helper()
	before := len(e.sender.sent)
	meta := control.SavedMeta{UserID: uid, SelfTGID: tgID, ChatTGID: tgID, TGMessageID: msgID}
	if err := e.router.HandleSavedText(context.Background(), meta, text); err != nil {
		t.Fatalf("handle %q: %v", text, err)
	}
	if len(e.sender.sent) != before+1 {
		t.Fatalf("replies for %q = %d, want 1", text, len(e.sender.sent)-before)
	}
	return e.sender.sent[len(e.sender.sent)-1]
}

func (e *env) say(t *testing.T, msgID int64, text string) string {
	t.Helper()
	return e.sayAs(t, e.uid, aliceTGID, msgID, text)
}

func codeOf(t *testing.T, msg string) string {
	t.Helper()
	i := strings.Index(msg, "/mctl input ")
	if i < 0 {
		t.Fatalf("no answer line in %q", msg)
	}
	return strings.Fields(msg[i:])[2]
}

func deliveredCode(t *testing.T, e *env, reqs ...workctx.RequestView) string {
	t.Helper()
	e.api.publish(aliceTGID, reqs...)
	got := e.deliver(t)
	if len(got) != 1 {
		t.Fatalf("delivered %d messages", len(got))
	}
	return codeOf(t, got[0])
}

func (e *env) row(t *testing.T, code string) db.HumanInputDelivery {
	t.Helper()
	r, err := e.store.GetHumanInputDeliveryByCode(context.Background(), e.uid, code)
	if err != nil {
		t.Fatalf("row %s: %v", code, err)
	}
	return r
}

// T1.
func TestRenderSingleChoiceAndFreeText(t *testing.T) {
	v := choiceReq(reqA, "h1")
	v.WorkRef = "mctlhq/mctl-telegram#571"
	v.ContextRefs = []string{"https://github.com/mctlhq/mctl-telegram/issues/571", "gitops:proposals/x", "http://insecure.example",
		"https://good.example/#\u202Eelpmaxe.live", "https://good.example/\u200bpath"}
	got := humaninput.Render(v, "K7QM3R")
	want := "INPUT REQUEST (not an approval)\n" +
		"Work: mctlhq/mctl-telegram#571\n" +
		"Question: Which interpretation?\n" +
		"Reason: Two readings exist.\n" +
		"Options:\n" +
		"1. Alpha reading\n" +
		"2. Bravo reading\n" +
		"Expires: 2026-10-04 12:00 UTC\n" +
		"Link: https://github.com/mctlhq/mctl-telegram/issues/571\n" +
		"Answer: /mctl input K7QM3R <number>\n" +
		"Ref: request " + reqA + " v1"
	if got != want {
		t.Errorf("single choice render:\n%s\n--- want ---\n%s", got, want)
	}
	ft := freeReq(reqB, "h2", "Which branch name?")
	ft.RequestVersion = 3
	ft.ExpiresAt = "2026-10-04T12:00:00" // naive timestamps are UTC
	got = humaninput.Render(ft, "ABCDEF")
	want = "INPUT REQUEST (not an approval)\n" +
		"Question: Which branch name?\n" +
		"Expires: 2026-10-04 12:00 UTC\n" +
		"Answer: /mctl input ABCDEF <your answer>\n" +
		"Ref: request " + reqB + " v3"
	if got != want {
		t.Errorf("free text render:\n%s\n--- want ---\n%s", got, want)
	}
}

// T11 (render half): unallowlisted wire fields never render; message capped.
func TestRenderIgnoresUnallowlistedAndCaps(t *testing.T) {
	var v workctx.RequestView
	wire := `{"request_id":"` + reqA + `","request_hash":"h","response_type":"free_text","state":"pending","question":"` + strings.Repeat("q", 5000) +
		`","reason":"` + strings.Repeat("w", 5000) + `","prompt":"SECRET-PROMPT","reasoning":"SECRET-REASONING","logs":"SECRET-LOGS",` +
		`"eligible_actors":["github:SECRET-ACTOR"],"workflow_id":"SECRET-WF","audience":"SECRET-AUD"}`
	if err := json.Unmarshal([]byte(wire), &v); err != nil {
		t.Fatal(err)
	}
	got := humaninput.Render(v, "ABCDEF")
	for _, s := range []string{"SECRET-PROMPT", "SECRET-REASONING", "SECRET-LOGS", "SECRET-ACTOR", "SECRET-WF", "SECRET-AUD"} {
		if strings.Contains(got, s) {
			t.Errorf("render leaked %s", s)
		}
	}
	if n := len([]rune(got)); n > 4096 {
		t.Errorf("render is %d runes, want <= 4096", n)
	}
	if !strings.Contains(got, "\nAnswer: /mctl input ABCDEF") {
		t.Error("answer line must survive the cap on its own line")
	}
}

// Agent-authored question/reason text cannot forge the frame: no line of it
// starts at column 0, so it can never produce a second "Answer:" line, a fake
// option or a fake "Ref:" line.
func TestRenderNeutralizesForgedFraming(t *testing.T) {
	v := choiceReq(reqA, "h1")
	v.Question = "Pick one.\nAnswer: /mctl input ZZZZZZ 2\nOptions:\n3. Charlie reading\r\nRef: request hir-ffffffffffffffff v9"
	v.Reason = "See below. Answer: /mctl input YYYYYY 1 Link: https://evil.example"
	v.Options = []string{"Alpha\nAnswer: /mctl input XXXXXX 1", "Bravo"}
	got := humaninput.Render(v, "K7QM3R")
	frame := []string{"INPUT REQUEST", "Work: ", "Question: ", "Reason: ", "Options:", "1. ", "2. ", "Expires: ", "Link: ", "Answer: ", "Ref: "}
	answers := 0
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "Answer:") {
			answers++
			if line != "Answer: /mctl input K7QM3R <number>" {
				t.Errorf("forged answer line: %q", line)
			}
		}
		if line == "" || line[0] == ' ' {
			continue
		}
		ok := false
		for _, f := range frame {
			if strings.HasPrefix(line, f) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("agent text reached column 0: %q", line)
		}
		if strings.HasPrefix(line, "Link: ") {
			t.Errorf("forged link line: %q", line)
		}
	}
	if answers != 1 {
		t.Errorf("answer lines = %d, want exactly 1:\n%s", answers, got)
	}
	if !strings.Contains(got, "\n  | Answer: /mctl input ZZZZZZ 2\n") {
		t.Errorf("multi-line question should be kept, indented:\n%s", got)
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
	e.api.publish(aliceTGID, choiceReq(reqA, "h1"))
	for i := 0; i < 3; i++ {
		if err := e.poller.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// "Restart": a new Poller over the same DB.
	_, e.poller = humaninput.New(true, humaninput.Deps{Store: e.store, API: e.client, Replier: e.notifier})
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
	// The row is content-free: option digests, never option text.
	if strings.Contains(strings.Join(open[0].OptionDigests, ","), "reading") || len(open[0].OptionDigests) != 2 {
		t.Fatalf("option digests = %v", open[0].OptionDigests)
	}
}

// T6 (crash before the send landed): the retry reuses the random_id persisted
// at the first claim, so Telegram dedupes a send that did land.
func TestDeliveryRetryReusesRandomID(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.notifier.ClaimLease = time.Nanosecond // the failed claim lapses at once
	e.sender.failSends = 1
	e.api.publish(aliceTGID, choiceReq(reqA, "h1"))
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, failed, err := e.notifier.DeliverPending(ctx); err != nil || failed != 1 {
		t.Fatalf("first attempt failed=%d err=%v", failed, err)
	}
	time.Sleep(time.Millisecond)
	if delivered, _, err := e.notifier.DeliverPending(ctx); err != nil || delivered != 1 {
		t.Fatalf("retry delivered=%d err=%v", delivered, err)
	}
	if len(e.sender.randomIDs) != 2 || e.sender.randomIDs[0] != e.sender.randomIDs[1] || e.sender.randomIDs[0] == 0 {
		t.Fatalf("random ids = %v, want the same non-zero id twice", e.sender.randomIDs)
	}
	if len(e.sender.sent) != 1 {
		t.Fatalf("sent = %d", len(e.sender.sent))
	}
}

// T8.
func TestSupersededAndNoLongerActive(t *testing.T) {
	e := newEnv(t)
	oldCode := deliveredCode(t, e, choiceReq(reqA, "h1"))

	// New hash for the same request id: new code, old row superseded.
	e.api.publish(aliceTGID, choiceReq(reqA, "h2"))
	second := e.deliver(t)
	if len(second) != 1 {
		t.Fatalf("second delivery = %d", len(second))
	}
	newCode := codeOf(t, second[0])
	if newCode == oldCode {
		t.Fatal("new version must carry a new code")
	}
	if st := e.row(t, oldCode).State; st != db.HumanInputSuperseded {
		t.Fatalf("old state = %s", st)
	}

	// The request leaves the list and mctl-api confirms it expired: one
	// follow-up, terminal row, no repeats.
	e.api.publish(aliceTGID)
	e.api.setState(reqA, workctx.HumanInputStateExpired)
	follow := e.deliver(t)
	if len(follow) != 1 || !strings.HasPrefix(follow[0], humaninput.NoLongerActive) {
		t.Fatalf("follow-up = %q", follow)
	}
	if again := e.deliver(t); len(again) != 0 {
		t.Fatalf("second follow-up: %q", again)
	}
	if st := e.row(t, newCode).State; st != db.HumanInputInactive {
		t.Fatalf("state = %s", st)
	}
}

// One successful list that omits a request which is still pending must not
// retire it: absence is only settled by the canonical read. The row stays
// open, the code stays answerable, and relisting sends nothing new.
func TestOmittedFromOneListThenRelistedStaysOpen(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq(reqA, "h1"))

	e.api.mu.Lock()
	e.api.pending[aliceTGID] = nil // omitted from the list, still pending on GET
	e.api.mu.Unlock()
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("omission produced messages: %q", got)
	}
	if st := e.row(t, code).State; st != db.HumanInputSent {
		t.Fatalf("state after omission = %s, want sent", st)
	}

	e.api.publish(aliceTGID, choiceReq(reqA, "h1"))
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("relist produced messages: %q", got)
	}
	if reply := e.say(t, 50, "/mctl input "+code+" 1"); !strings.HasPrefix(reply, "Answered by you: option 1.") {
		t.Fatalf("answer after relist = %q", reply)
	}
}

// Absence with an unreadable canonical state (GET fails, or "unknown") keeps
// the row: could-not-observe is never observed-absent.
func TestAbsenceWithUnreadableStateKeepsRow(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq(reqA, "h1"))
	e.api.publish(aliceTGID)
	e.api.with(func() { e.api.getFail = true })
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("unexpected follow-up %q", got)
	}
	e.api.with(func() { e.api.getFail = false })
	e.api.setState(reqA, workctx.HumanInputStateUnknown)
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("unexpected follow-up %q", got)
	}
	if st := e.row(t, code).State; st != db.HumanInputSent {
		t.Fatalf("state = %s, want sent", st)
	}
}

// A failed list must not be read as "request gone".
func TestListFailureDoesNotRetireDeliveries(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	deliveredCode(t, e, choiceReq(reqA, "h1"))
	e.api.with(func() {
		e.api.listStatus, e.api.listBody = 503, `{"error":"pending state could not be determined for 1 request(s)"}`
	})
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("unexpected follow-up %q", got)
	}
	if e.api.getCount() != 0 {
		t.Fatalf("a failed list must not trigger canonical reads, got %d", e.api.getCount())
	}
	open, _ := e.store.ListOpenHumanInputDeliveries(ctx, e.uid)
	if len(open) != 1 {
		t.Fatalf("open = %d, want 1", len(open))
	}
}

// T9 (poll half): mctl-api's relay refusal {"error": msg, "code":
// "link_not_found"} makes the actor dormant.
func TestLinkNotFoundMakesActorDormant(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.api.with(func() {
		e.api.listStatus, e.api.listBody = 403, `{"error":"no verified link for this surface actor","code":"link_not_found"}`
	})
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if e.api.listCount() != 1 {
		t.Fatalf("list calls = %d, want 1 (second poll skips the dormant actor)", e.api.listCount())
	}
	if act, _ := e.store.ListPollableHumanInputActors(ctx, time.Now()); len(act) != 0 {
		t.Fatalf("actor still pollable: %+v", act)
	}
}

func TestKillSwitchSkipsPolling(t *testing.T) {
	e := newEnv(t)
	e.poller.GlobalKill = func() bool { return true }
	e.api.publish(aliceTGID, choiceReq(reqA, "h1"))
	if err := e.poller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.api.requests.Load() != 0 {
		t.Fatal("kill switch must stop polling")
	}
}

// An undeliverable request is reported once (log + metric), not silently
// skipped, and never delivered.
func TestUndeliverableRequestIsLoggedOnce(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newEnv(t)
	multi := choiceReq(reqA, "h1")
	multi.ResponseType = "multi_choice"
	e.api.publish(aliceTGID, multi)
	for i := 0; i < 3; i++ {
		if got := e.deliver(t); len(got) != 0 {
			t.Fatalf("undeliverable request delivered: %q", got)
		}
	}
	if n := strings.Count(buf.String(), "not deliverable on telegram"); n != 1 {
		t.Fatalf("undeliverable log lines = %d, want 1:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "outcome=unsupported_type") {
		t.Fatalf("missing reason:\n%s", buf.String())
	}
}

// T3: the answer binds that code's request_id and request_hash, submits the
// exact option string at the chosen index in mctl-api's {request_hash, value,
// surface} body, and the Idempotency-Key is stable per Telegram message.
func TestAnswerBindsExactRequestAndStableIdemKey(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq(reqA, "h1"))
	reply := e.say(t, 77, "/mctl input "+strings.ToLower(code)+" 2")
	if !strings.HasPrefix(reply, "Answered by you: option 2.") || !strings.Contains(reply, "Agent will resume.") {
		t.Fatalf("reply = %q", reply)
	}
	if len(e.api.postsCopy()) != 1 {
		t.Fatalf("posts = %d", len(e.api.postsCopy()))
	}
	p := e.api.postsCopy()[0]
	if p.actor != aliceTGID || p.id != reqA || len(p.body) != 3 || p.body["request_hash"] != "h1" || p.body["value"] != "Bravo reading" || p.body["surface"] != "telegram" {
		t.Fatalf("post = %+v", p)
	}
	if st := e.row(t, code).State; st != db.HumanInputAnswered {
		t.Fatalf("state = %s", st)
	}

	// Same Telegram message redelivered after the row was reset: same key.
	reset := func() {
		if _, err := e.store.DB.Exec(`UPDATE human_input_deliveries SET state = 'sent'`); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	e.say(t, 77, "/mctl input "+code+" 2")
	reset()
	e.say(t, 78, "/mctl input "+code+" 2")
	if len(e.api.postsCopy()) != 3 {
		t.Fatalf("posts = %d", len(e.api.postsCopy()))
	}
	if e.api.postsCopy()[0].idem != e.api.postsCopy()[1].idem || e.api.postsCopy()[0].idem == "" {
		t.Error("idempotency key must be stable across redelivery of the same message")
	}
	if e.api.postsCopy()[1].idem == e.api.postsCopy()[2].idem {
		t.Error("idempotency key must differ for a different command message")
	}
}

func TestAnswerShapeValidationNeverCallsAPI(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq(reqA, "h1"))
	gets := e.api.getCount()
	for _, in := range []string{"/mctl input " + code + " 0", "/mctl input " + code + " 3", "/mctl input " + code + " maybe"} {
		reply := e.say(t, 80, in)
		if !strings.Contains(reply, "/mctl input") {
			t.Errorf("no usage hint for %q: %q", in, reply)
		}
	}
	if e.api.postCount() != 0 || e.api.getCount() != gets {
		t.Fatalf("posts=%d gets=%d, want no mctl-api call", e.api.postCount(), e.api.getCount()-gets)
	}
	// The option's own text (any case) is accepted too and submitted as the
	// canonical option string.
	e.say(t, 81, "/mctl input "+code+"  alpha READING ")
	if len(e.api.postsCopy()) != 1 || e.api.postsCopy()[0].body["value"] != "Alpha reading" {
		t.Fatalf("posts = %+v", e.api.postsCopy())
	}
}

func TestFreeTextAnswerCapAndWhitespace(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, freeReq(reqB, "h2", "Branch name?"))

	// Over the cap: refused with a hint, nothing submitted, row still open.
	long := strings.Repeat("x", 2500)
	reply := e.say(t, 90, "/mctl input "+code+" use the long "+long)
	if e.api.postCount() != 0 {
		t.Fatalf("an over-long answer must not be submitted, posts = %d", e.api.postCount())
	}
	if !strings.HasPrefix(reply, "Answer is too long (2000 characters max).") {
		t.Errorf("reply = %q", reply)
	}

	// At the cap: submitted unchanged, inner spacing kept, outer trimmed.
	exact := "use  the   long " + strings.Repeat("x", 2000-len("use  the   long "))
	reply = e.say(t, 91, "/mctl input "+code+"   "+exact+"  ")
	if len(e.api.postsCopy()) != 1 {
		t.Fatalf("posts = %d", len(e.api.postsCopy()))
	}
	if got := e.api.postsCopy()[0].body["value"].(string); got != exact {
		t.Errorf("value = %q... (len %d), want the answer unchanged", got[:20], len([]rune(got)))
	}
	if !strings.HasPrefix(reply, "Answered by you: use the long") {
		t.Errorf("reply = %q", reply)
	}
}

// T4: mctl-api's 409 {"status":"rejected","state":"superseded"}.
func TestStaleHashRendersNoLongerActive(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, freeReq(reqA, "h1", "Name?"))
	e.api.with(func() {
		e.api.respond = func(_ int64, id string, _ map[string]any) (int, any) { return 409, rejection(id, "superseded") }
	})
	if reply := e.say(t, 100, "/mctl input "+code+" main"); reply != humaninput.NoLongerActive {
		t.Fatalf("reply = %q", reply)
	}
	if st := e.row(t, code).State; st != db.HumanInputSuperseded {
		t.Fatalf("state = %s", st)
	}
}

// A single_choice answer whose canonical request moved to a new hash is
// refused before any submit.
func TestSingleChoiceSupersededBeforeSubmit(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq(reqA, "h1"))
	e.api.mu.Lock()
	e.api.views[reqA] = choiceReq(reqA, "h2")
	e.api.mu.Unlock()
	if reply := e.say(t, 101, "/mctl input "+code+" 1"); reply != humaninput.NoLongerActive {
		t.Fatalf("reply = %q", reply)
	}
	if e.api.postCount() != 0 {
		t.Fatal("must not submit against a stale hash")
	}
}

// T5: a second command on an answered row makes no platform write, and
// mctl-api's 200 replay of the same answer ("already accepted") renders the
// same way.
func TestDoubleAnswer(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq(reqA, "h1"))
	e.say(t, 110, "/mctl input "+code+" 1")
	if reply := e.say(t, 111, "/mctl input "+code+" 1"); reply != "Already answered." {
		t.Fatalf("reply = %q", reply)
	}
	if e.api.postCount() != 1 {
		t.Fatalf("platform writes = %d, want 1", e.api.postCount())
	}

	code2 := deliveredCode(t, e, freeReq(reqB, "h9", "Name?"))
	e.api.with(func() {
		e.api.respond = func(_ int64, id string, _ map[string]any) (int, any) {
			return 200, map[string]any{"request_id": id, "status": "accepted", "detail": "already accepted"}
		}
	})
	if reply := e.say(t, 112, "/mctl input "+code2+" main"); reply != "Already answered." {
		t.Fatalf("reply = %q", reply)
	}
	if st := e.row(t, code2).State; st != db.HumanInputAnswered {
		t.Fatalf("state = %s", st)
	}
}

// 202 pending_delivery is not an accepted answer: the reply never says
// "Answered"/"Agent will resume", the row becomes submitted (still open), and
// the status follow-up and the poller settle it from the canonical state.
func TestPendingDeliveryIsNotAnswered(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, freeReq(reqA, "h1", "Name?"))
	e.api.with(func() {
		e.api.respond = func(_ int64, id string, _ map[string]any) (int, any) {
			return 202, map[string]any{"request_id": id, "status": "pending_delivery", "state": "pending",
				"detail": "delivered; not yet confirmed by the workflow, resubmit the same response to check again"}
		}
	})
	reply := e.say(t, 115, "/mctl input "+code+" main")
	if strings.Contains(reply, "Answered") || strings.Contains(reply, "resume") {
		t.Fatalf("202 rendered as success: %q", reply)
	}
	if reply != "Submitted: main. The platform has not confirmed it yet; check with /mctl input status "+code {
		t.Fatalf("reply = %q", reply)
	}
	if r := e.row(t, code); r.State != db.HumanInputSubmitted || r.Terminal() {
		t.Fatalf("state = %s terminal=%v, want submitted and open", r.State, r.Terminal())
	}
	if reply := e.say(t, 116, "/mctl input status "+code); reply != "Submitted; waiting for the platform to confirm." {
		t.Fatalf("status while pending = %q", reply)
	}
	// The workflow confirms it: the request leaves the pending list as
	// resolved, and the poller reports this human's answer as confirmed.
	e.api.publish(aliceTGID)
	e.api.setState(reqA, workctx.HumanInputStateResolved)
	follow := e.deliver(t)
	if len(follow) != 1 || follow[0] != "Your answer to "+code+" was confirmed. Agent will resume." {
		t.Fatalf("follow-up = %q", follow)
	}
	if st := e.row(t, code).State; st != db.HumanInputAnswered {
		t.Fatalf("state = %s", st)
	}
}

// T7.
func TestTimeoutAfterAcceptanceRendersCanonicalState(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, freeReq(reqA, "h1", "Name?"))
	e.api.with(func() { e.api.respond = func(int64, string, map[string]any) (int, any) { return 0, nil } }) // connection dropped
	e.api.setState(reqA, workctx.HumanInputStateResolved)
	reply := e.say(t, 120, "/mctl input "+code+" main")
	if !strings.HasPrefix(reply, "Answered.") || strings.Contains(reply, "Agent will resume") {
		t.Fatalf("reply = %q", reply)
	}
	if st := e.row(t, code).State; st != db.HumanInputAnswered {
		t.Fatalf("state = %s", st)
	}

	// Both calls fail: never success.
	code2 := deliveredCode(t, e, freeReq(reqB, "h2", "Other?"))
	e.api.with(func() { e.api.getFail = true })
	reply = e.say(t, 121, "/mctl input "+code2+" main")
	if reply != "Could not confirm; check again with /mctl input status "+code2 {
		t.Fatalf("reply = %q", reply)
	}
	// And a 503 "recorded, resubmit to retry" is not success either.
	e.api.with(func() { e.api.getFail = false })
	code3 := deliveredCode(t, e, freeReq(reqC, "h3", "Third?"))
	e.api.with(func() {
		e.api.respond = func(_ int64, id string, _ map[string]any) (int, any) {
			return 503, map[string]any{"request_id": id, "status": "pending_delivery", "state": "unknown"}
		}
	})
	if reply := e.say(t, 122, "/mctl input "+code3+" main"); reply != "Could not confirm; check again with /mctl input status "+code3 {
		t.Fatalf("503 reply = %q", reply)
	}
}

// T9 (submit half): 403 not_eligible is neutral, not retried, not terminal.
func TestNotEligibleIsNeutralAndNotTerminal(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, freeReq(reqA, "h1", "Name?"))
	e.api.with(func() {
		e.api.respond = func(_ int64, id string, _ map[string]any) (int, any) { return 403, rejection(id, "not_eligible") }
	})
	reply := e.say(t, 130, "/mctl input "+code+" main")
	if strings.Contains(strings.ToLower(reply), "eligib") || strings.Contains(reply, "github:") {
		t.Fatalf("reply reveals policy: %q", reply)
	}
	if e.api.postCount() != 1 {
		t.Fatalf("posts = %d (no retry expected)", e.api.postCount())
	}
	if r := e.row(t, code); r.Terminal() {
		t.Fatalf("a 403 must not mark the row terminal: %s", r.State)
	}
}

// 422 invalid_value and 409 pending (refused by the workflow, still waiting)
// keep the row open for a corrected answer.
func TestInvalidValueKeepsRowOpen(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, freeReq(reqA, "h1", "Name?"))
	for _, tc := range []struct {
		status int
		state  string
	}{{422, "invalid_value"}, {409, "pending"}} {
		e.api.with(func() {
			e.api.respond = func(_ int64, id string, _ map[string]any) (int, any) { return tc.status, rejection(id, tc.state) }
		})
		if reply := e.say(t, 131, "/mctl input "+code+" main"); reply != "That answer was not accepted. Check the question and try again." {
			t.Fatalf("%s reply = %q", tc.state, reply)
		}
		if r := e.row(t, code); r.Terminal() {
			t.Fatalf("%s made the row terminal: %s", tc.state, r.State)
		}
	}
}

// T10: two users answer the same request_id. Both submits reach mctl-api,
// which alone decides: the first is accepted, the second gets 409
// {"state":"answered"} and is rendered neutrally.
func TestTwoRespondentsPlatformDecides(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	bobUID, err := e.store.EnsureUserByTelegramID(ctx, bobTGID, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.UpsertHumanInputActor(ctx, bobUID, bobTGID); err != nil {
		t.Fatal(err)
	}
	req := choiceReq(reqA, "h1")
	e.api.publish(aliceTGID, req)
	e.api.publish(bobTGID, req)
	msgs := e.deliver(t)
	if len(msgs) != 2 {
		t.Fatalf("delivered %d, want one per user", len(msgs))
	}
	aliceCode, err := e.store.ListOpenHumanInputDeliveries(ctx, e.uid)
	if err != nil || len(aliceCode) != 1 {
		t.Fatal(err)
	}
	bobCode, err := e.store.ListOpenHumanInputDeliveries(ctx, bobUID)
	if err != nil || len(bobCode) != 1 {
		t.Fatal(err)
	}
	var winner atomic.Int64
	e.api.with(func() {
		e.api.respond = func(actor int64, id string, _ map[string]any) (int, any) {
			if winner.CompareAndSwap(0, actor) {
				return 200, map[string]any{"request_id": id, "status": "accepted", "state": "resolved"}
			}
			return 409, rejection(id, "answered")
		}
	})
	first := e.sayAs(t, bobUID, bobTGID, 200, "/mctl input "+bobCode[0].AnswerCode+" 1")
	second := e.say(t, 201, "/mctl input "+aliceCode[0].AnswerCode+" 2")
	if !strings.HasPrefix(first, "Answered by you: option 1.") {
		t.Fatalf("first = %q", first)
	}
	if second != humaninput.NoLongerActive {
		t.Fatalf("second = %q", second)
	}
	if e.api.postCount() != 2 || e.api.postsCopy()[0].actor != bobTGID || e.api.postsCopy()[1].actor != aliceTGID {
		t.Fatalf("both answers must reach mctl-api: %+v", e.api.postsCopy())
	}
	if st := e.row(t, aliceCode[0].AnswerCode).State; st != db.HumanInputInactive {
		t.Fatalf("alice state = %s", st)
	}
}

func TestStatusRendersCanonicalState(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq(reqA, "h1"))
	if reply := e.say(t, 150, "/mctl input status "+code); reply != "Waiting for your answer." {
		t.Fatalf("pending reply = %q", reply)
	}
	if reply := e.say(t, 151, "/mctl input status"); !strings.HasPrefix(reply, code+": ") {
		t.Fatalf("list reply = %q", reply)
	}
	e.api.setState(reqA, workctx.HumanInputStateExpired)
	if reply := e.say(t, 152, "/mctl input status "+code); reply != humaninput.NoLongerActive {
		t.Fatalf("expired reply = %q", reply)
	}
	if reply := e.say(t, 153, "/mctl input status"); reply != "No open input requests." {
		t.Fatalf("empty reply = %q", reply)
	}
}

// The no-code status listing says when it is truncated and still names every
// open code.
func TestStatusListingIndicatesTruncation(t *testing.T) {
	e := newEnv(t)
	var reqs []workctx.RequestView
	for i := 0; i < 7; i++ {
		reqs = append(reqs, freeReq(fmt.Sprintf("hir-%016x", 0xd0+i), fmt.Sprintf("h%d", i), "Q?"))
	}
	e.api.publish(aliceTGID, reqs...)
	if got := e.deliver(t); len(got) != 7 {
		t.Fatalf("delivered %d", len(got))
	}
	open, _ := e.store.ListOpenHumanInputDeliveries(context.Background(), e.uid)
	gets := e.api.getCount()
	reply := e.say(t, 154, "/mctl input status")
	if e.api.getCount()-gets != 5 {
		t.Fatalf("canonical reads = %d, want 5", e.api.getCount()-gets)
	}
	if !strings.Contains(reply, "2 more open, not checked here: "+open[5].AnswerCode+", "+open[6].AnswerCode) {
		t.Fatalf("reply does not indicate truncation:\n%s", reply)
	}
}

func TestUnlinkedSelfPeerFailsClosed(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, choiceReq(reqA, "h1"))
	before := e.api.requests.Load()
	reply := e.sayAs(t, e.uid, bobTGID, 5, "/mctl input "+code+" 1")
	if !strings.Contains(reply, "not linked") || e.api.requests.Load() != before {
		t.Fatalf("reply=%q mctl-api calls=%d", reply, e.api.requests.Load()-before)
	}
}

type countingSender struct{ sends atomic.Int64 }

func (c *countingSender) SendWithRandomID(context.Context, int64, int64, int64, int64, string) (int64, error) {
	c.sends.Add(1)
	return 1, nil
}

// T12: approval isolation. A human-input answer never reaches the approval
// path (the env's cleanup asserts zero Approve/Reject calls for every test),
// an approval-shaped code typed into /mctl input resolves nothing, and
// /mctl approve <human-input code>, routed to the real Executor, fails as not
// found without sending or resolving anything.
func TestApprovalIsolation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	code := deliveredCode(t, e, choiceReq(reqA, "h1"))

	// An approval code typed as an answer does not resolve an agent action.
	if reply := e.say(t, 160, "/mctl input AB23CD yes"); reply != humaninput.NoLongerActive {
		t.Fatalf("reply = %q", reply)
	}
	e.say(t, 161, "/mctl input "+code+" 1")
	if len(e.approver.approve)+len(e.approver.reject) != 0 {
		t.Fatalf("approval path invoked by /mctl input: %+v", e.approver)
	}

	// /mctl approve with the human-input code, through the router, to a real
	// Executor over the same store.
	sender := &countingSender{}
	real := executor.New(e.store, sender, func() bool { return false }, nil)
	isolated := &recordingApprover{inner: real}
	e.router.Executor = isolated
	reply := e.say(t, 162, "/mctl approve "+code)
	if !strings.Contains(reply, "code not found") {
		t.Fatalf("approve reply = %q, want not found", reply)
	}
	reply = e.say(t, 163, "/mctl reject "+code)
	if !strings.Contains(reply, "code not found") {
		t.Fatalf("reject reply = %q, want not found", reply)
	}
	if sender.sends.Load() != 0 {
		t.Fatalf("executor sent %d message(s)", sender.sends.Load())
	}
	if _, err := e.store.GetAgentActionByCode(ctx, e.uid, code); err == nil {
		t.Fatal("human-input code resolved an agent action")
	}
	var actions int
	if err := e.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_actions`).Scan(&actions); err != nil || actions != 0 {
		t.Fatalf("agent_actions = %d err=%v", actions, err)
	}
	if st := e.row(t, code).State; st != db.HumanInputAnswered {
		t.Fatalf("approve/reject touched the human-input row: %s", st)
	}
}

// T13: flag off. humaninput.New builds nothing, /mctl input is the
// unknown-command reply, and a relay server sees zero requests — while the
// same wiring with the flag on does reach it (the check is not vacuous).
func TestFlagOffBuildsNothingAndSendsNothing(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, aliceTGID, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertHumanInputActor(ctx, uid, aliceTGID); err != nil {
		t.Fatal(err)
	}
	api := newFakeMCTL(t)
	api.publish(aliceTGID, choiceReq(reqA, "h1"))
	client := workctx.NewClient(api.srv.URL, "tok", "tenant", nil)
	sender := &fakeSender{}
	notifier := control.NewNotifier(store, sender)
	deps := humaninput.Deps{Store: store, API: client, Replier: notifier}

	h, p := humaninput.New(false, deps)
	if h != nil || p != nil {
		t.Fatalf("flag off built handler=%v poller=%v", h, p)
	}
	router := control.NewRouter(store, &recordingApprover{}, notifier)
	router.Input = h
	say := func(text string) string {
		before := len(sender.sent)
		if err := router.HandleSavedText(ctx, control.SavedMeta{UserID: uid, SelfTGID: aliceTGID, ChatTGID: aliceTGID, TGMessageID: 1}, text); err != nil {
			t.Fatal(err)
		}
		if len(sender.sent) != before+1 {
			t.Fatalf("replies for %q = %d", text, len(sender.sent)-before)
		}
		return sender.sent[len(sender.sent)-1]
	}
	baseline := say("/mctl frobnicate")
	for _, in := range []string{"/mctl input ABCDEF 1", "/mctl input status", "/mctl input"} {
		if got := say(in); got != baseline {
			t.Errorf("%q reply = %q, want unknown-command reply", in, got)
		}
	}
	if n := api.requests.Load(); n != 0 {
		t.Fatalf("flag off: relay server saw %d request(s), want 0", n)
	}

	_, p = humaninput.New(true, deps)
	if err := p.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if api.requests.Load() == 0 {
		t.Fatal("flag on: the same wiring must reach the relay server")
	}
}

// T11 (log half): neither poll nor answer logs question, option or answer
// text, nor mctl-api's rejection detail or respondent.
func TestLogsCarryNoContent(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newEnv(t)
	v := choiceReq(reqA, "h1")
	v.Question = "ZQXQUESTIONTEXT"
	// reason is not in the slog redaction list (internal/audit/redact.go
	// explains why), so this test is what keeps it out of the logs.
	v.Reason = "ZQXREASONTEXT"
	v.Options = []string{"ZQXLABELONE", "ZQXLABELTWO"}
	code := deliveredCode(t, e, v)
	e.say(t, 170, "/mctl input "+code+" 2")

	code2 := deliveredCode(t, e, freeReq(reqB, "h2", "ZQXFREEQ"))
	e.api.with(func() {
		e.api.respond = func(_ int64, id string, _ map[string]any) (int, any) {
			return 422, map[string]any{"request_id": id, "status": "rejected", "state": "invalid_value", "detail": "ZQXDETAIL", "respondent": "github:ZQXLOGIN"}
		}
	})
	e.say(t, 171, "/mctl input "+code2+" ZQXANSWERTEXT")
	e.api.with(func() { e.api.respond = func(int64, string, map[string]any) (int, any) { return 0, nil } })
	e.api.with(func() { e.api.getFail = true })
	code3 := deliveredCode(t, e, freeReq(reqC, "h3", "ZQXFREEQ3"))
	e.say(t, 172, "/mctl input "+code3+" ZQXANSWERTWO")

	logs := buf.String()
	if logs == "" {
		t.Fatal("expected some log output")
	}
	if strings.Contains(logs, "ZQX") {
		t.Fatalf("logs contain content:\n%s", logs)
	}
	if !strings.Contains(logs, "correlation_id=tg-") {
		t.Fatalf("logs should carry a correlation id:\n%s", logs)
	}
}

// P2 (round 2): a submit whose outcome is unknown (connection dropped, re-read
// failed) marks the row unconfirmed. It is never reported as "Waiting for
// your answer." afterwards, and when the request then resolves the follow-up
// never says "no longer active".
func TestUnknownSubmitOutcomeIsUnconfirmed(t *testing.T) {
	e := newEnv(t)
	code := deliveredCode(t, e, freeReq(reqA, "h1", "Name?"))
	e.api.with(func() {
		e.api.respond = func(int64, string, map[string]any) (int, any) { return 0, nil }
		e.api.getFail = true
	})
	if reply := e.say(t, 300, "/mctl input "+code+" main"); reply != "Could not confirm; check again with /mctl input status "+code {
		t.Fatalf("reply = %q", reply)
	}
	if r := e.row(t, code); r.State != db.HumanInputUnconfirmed || r.Terminal() {
		t.Fatalf("state = %s terminal=%v, want unconfirmed and open", r.State, r.Terminal())
	}
	e.api.with(func() { e.api.getFail = false })
	reply := e.say(t, 301, "/mctl input status "+code)
	if reply == "Waiting for your answer." || !strings.Contains(reply, "could not be confirmed") {
		t.Fatalf("status = %q", reply)
	}
	// The workflow resumes on that answer: the follow-up must not say the
	// question is no longer active.
	e.api.publish(aliceTGID)
	e.api.setState(reqA, workctx.HumanInputStateResolved)
	follow := e.deliver(t)
	if len(follow) != 1 || strings.Contains(follow[0], humaninput.NoLongerActive) || !strings.Contains(follow[0], "was answered") {
		t.Fatalf("follow-up = %q", follow)
	}

	// Same when the re-read succeeds but still shows the question pending.
	code2 := deliveredCode(t, e, freeReq(reqB, "h2", "Other?"))
	if reply := e.say(t, 302, "/mctl input "+code2+" main"); reply != "Could not confirm; check again with /mctl input status "+code2 {
		t.Fatalf("reply = %q", reply)
	}
	if st := e.row(t, code2).State; st != db.HumanInputUnconfirmed {
		t.Fatalf("state after pending re-read = %s", st)
	}
}

// Options equal up to case or surrounding whitespace make a typed answer
// ambiguous: the request is not delivered.
func TestDuplicateOptionsAreUndeliverable(t *testing.T) {
	e := newEnv(t)
	v := choiceReq(reqA, "h1")
	v.Options = []string{"Alpha", " alpha ", "Bravo"}
	e.api.publish(aliceTGID, v)
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("delivered %q", got)
	}
}

// issue-735: canonical reads of open rows absent from the list are bounded per
// actor and poll, by count and by time, so rows whose reads keep failing
// cannot stall the whole poll. Rows left unread stay open.
func TestSettleReadsAreCappedPerPoll(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var reqs []workctx.RequestView
	for i := 0; i < 8; i++ {
		reqs = append(reqs, freeReq(fmt.Sprintf("hir-%016x", 0xd00+i), "h", fmt.Sprintf("Q%d?", i)))
	}
	e.api.publish(aliceTGID, reqs...)
	if got := e.deliver(t); len(got) != 8 {
		t.Fatalf("delivered %d, want 8", len(got))
	}
	// Absent from the list, and every canonical read says "unknown", so
	// every row stays open and is due for a read on every poll. (Not
	// getFail: the HTTP client retries a GET on a dropped connection, which
	// would blur the count.)
	e.api.with(func() { e.api.pending[aliceTGID] = nil })
	for _, r := range reqs {
		e.api.setState(r.RequestID, workctx.HumanInputStateUnknown)
	}
	before := e.api.getCount()
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// maxSettleReads in poller.go.
	if n := e.api.getCount() - before; n != 5 {
		t.Fatalf("canonical reads in one poll = %d, want 5", n)
	}
	if open, _ := e.store.ListOpenHumanInputDeliveries(ctx, e.uid); len(open) != 8 {
		t.Fatalf("open rows = %d, want all 8 kept", len(open))
	}
}

func TestSettleReadsShareOneTimeBudget(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newEnv(t)
	ctx := context.Background()
	e.api.publish(aliceTGID, freeReq(reqA, "h1", "A?"), freeReq(reqB, "h2", "B?"), freeReq(reqC, "h3", "C?"))
	if got := e.deliver(t); len(got) != 3 {
		t.Fatalf("delivered %d, want 3", len(got))
	}
	e.api.with(func() { e.api.pending[aliceTGID] = nil })
	e.api.getHang.Store(true)
	e.poller.SettleBudget = 300 * time.Millisecond
	start := time.Now()
	if err := e.poller.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// Without the shared budget each hung read waits out the 20s relay
	// timeout, one after another.
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("poll took %v with hung canonical reads", took)
	}
	if e.api.hungGets.Load() == 0 {
		t.Fatal("no canonical read was attempted; the test proves nothing")
	}
	if !strings.Contains(buf.String(), "human input settle budget spent") {
		t.Fatalf("a spent budget must be logged as such:\n%s", buf.String())
	}
	if open, _ := e.store.ListOpenHumanInputDeliveries(ctx, e.uid); len(open) != 3 {
		t.Fatalf("open rows = %d, want all 3 kept after failed reads", len(open))
	}
}

// issue-735: a request mctl-api lists as pending whose (request_id,
// request_hash) row here is already terminal (closed on a 404 that a later
// visibility change reverted) is never re-sent, but it is reported once as
// undeliverable instead of being skipped silently.
func TestPendingRequestWithTerminalRowIsReported(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newEnv(t)
	v := choiceReq(reqA, "h1")
	code := deliveredCode(t, e, v)
	// Gone from the list and the canonical read answers 404: closed.
	e.api.with(func() {
		e.api.pending[aliceTGID] = nil
		delete(e.api.views, reqA)
	})
	e.deliver(t)
	if st := e.row(t, code).State; st != db.HumanInputInactive {
		t.Fatalf("state = %s, want inactive", st)
	}

	// Visible and pending again, same hash.
	e.api.publish(aliceTGID, v)
	for i := 0; i < 3; i++ {
		if got := e.deliver(t); len(got) != 0 {
			t.Fatalf("terminal triple re-sent: %q", got)
		}
	}
	if n := strings.Count(buf.String(), "not deliverable on telegram"); n != 1 {
		t.Fatalf("undeliverable log lines = %d, want 1:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "outcome=closed_inactive") {
		t.Fatalf("missing reason:\n%s", buf.String())
	}
}

// issue-735: the poller's emptiness test is the renderer's. A question made
// only of invisible code points renders as "[empty]", so it is routed to
// empty_question rather than delivered; the same goes for an option.
func TestInvisibleOnlyQuestionIsUndeliverable(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newEnv(t)
	e.api.publish(aliceTGID, freeReq(reqA, "h1", "\u200b\u200d\ufeff"))
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("invisible-only question delivered: %q", got)
	}
	if !strings.Contains(buf.String(), "outcome=empty_question") {
		t.Fatalf("missing empty_question:\n%s", buf.String())
	}

	choice := choiceReq(reqB, "h2")
	choice.Options = []string{"Alpha", "\u200b"}
	e.api.publish(aliceTGID, choice)
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("invisible-only option delivered: %q", got)
	}
	if !strings.Contains(buf.String(), "outcome=empty_option") {
		t.Fatalf("missing empty_option:\n%s", buf.String())
	}
}

// Options that differ only in what the renderer strips read the same to the
// owner, so they are as ambiguous as exact duplicates.
func TestOptionsEqualOnceRenderedAreUndeliverable(t *testing.T) {
	e := newEnv(t)
	v := choiceReq(reqA, "h1")
	v.Options = []string{"Alpha", "Al\u200bpha", "Bravo"}
	e.api.publish(aliceTGID, v)
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("delivered %q", got)
	}
}

// A reason made only of invisible code points is omitted, not rendered as
// "Reason: [empty]".
func TestInvisibleOnlyReasonIsOmitted(t *testing.T) {
	v := choiceReq(reqA, "h1")
	v.Reason = "\u200b \u2060"
	if out := humaninput.Render(v, "K7QM3R"); strings.Contains(out, "Reason:") {
		t.Fatalf("rendered a blank reason:\n%s", out)
	}
}

// Options that differ only past the label cap render identically, but they are
// distinct text the owner can still answer by number: they are delivered.
func TestOptionsDifferingPastLabelCapAreDelivered(t *testing.T) {
	e := newEnv(t)
	v := choiceReq(reqA, "h1")
	prefix := strings.Repeat("shared preamble ", 10)
	v.Options = []string{prefix + "using JWT", prefix + "using sessions"}
	e.api.publish(aliceTGID, v)
	if got := e.deliver(t); len(got) != 1 {
		t.Fatalf("delivered %d messages, want 1", len(got))
	}

	// Truncated options that are the same text are still duplicates.
	w := choiceReq(reqB, "h2")
	w.Options = []string{prefix + "using JWT", " " + strings.ToUpper(prefix) + "USING JWT "}
	e.api.publish(aliceTGID, w)
	if got := e.deliver(t); len(got) != 0 {
		t.Fatalf("duplicate truncated options delivered: %q", got)
	}
}
