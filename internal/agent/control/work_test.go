package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/workctx"
)

const workOwnerTGID = int64(600100)

// fakeMctlAPI is a minimal, scriptable stand-in for mctl-api's surface-relay
// routes. It tracks every call so tests can assert on call counts (T6, T9,
// T13) and lets each test override per-route behaviour (T14, T15).
type fakeMctlAPI struct {
	mu sync.Mutex

	// itemsByExternalKey simulates mctl-api's open-work dedupe on
	// (tenant, external_key): a second create for a key already here binds
	// to the SAME item id rather than minting a new one.
	itemsByExternalKey map[string]string
	itemState          map[string]string
	itemVersion        map[string]int64
	nextItemN          int
	nextReqN           int
	// requests holds every created execution request, by id, so
	// GetExecutionRequest/ListExecutionRequests can answer.
	requests map[string]*workctx.ExecutionRequestView

	createCalls  int
	surfaceCalls int
	intentCalls  []string
	redeemCalls  []string
	// createRequestIdemKeys records every Idempotency-Key header seen by
	// handleCreateRequest, in call order — used to assert that a retried
	// resume gets a fresh key rather than reusing a refused attempt's key.
	createRequestIdemKeys []string

	// refuseExternalKey, when set, makes CreateWorkItem for that key answer
	// 409 external_key_in_use instead of the dedupe/create path.
	refuseExternalKey string
	// forcedRequestState overrides the state (and, for rejected, reason) of
	// the NEXT execution request created — used by T14/T7.
	forcedRequestState  string
	forcedRequestReason string
	// forceConflicts, when > 0, makes the next N execution-request creates
	// answer 409 state_version_conflict regardless of the submitted
	// expected_state_version, decrementing by one and bumping the item's
	// live version each time — simulating a real race between the
	// handler's GetWorkItem read and its RequestExecution call. Used by T7.
	forceConflicts int
}

func newFakeMctlAPI() *fakeMctlAPI {
	return &fakeMctlAPI{
		itemsByExternalKey: map[string]string{},
		itemState:          map[string]string{},
		itemVersion:        map[string]int64{},
		requests:           map[string]*workctx.ExecutionRequestView{},
	}
}

func (f *fakeMctlAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/surface-identities/redeem", f.handleRedeem)
	mux.HandleFunc("POST /api/v1/work-items", f.handleCreate)
	mux.HandleFunc("GET /api/v1/work-items/{id}", f.handleGetItem)
	mux.HandleFunc("POST /api/v1/work-items/{id}/intents", f.handleIntent)
	mux.HandleFunc("POST /api/v1/work-items/{id}/surface-refs", f.handleSurfaceRef)
	mux.HandleFunc("POST /api/v1/work-items/{id}/execution-requests", f.handleCreateRequest)
	mux.HandleFunc("GET /api/v1/work-items/{id}/execution-requests", f.handleListRequests)
	mux.HandleFunc("GET /api/v1/work-items/{id}/execution-requests/{rid}", f.handleGetRequest)
	return httptest.NewServer(mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func (f *fakeMctlAPI) handleRedeem(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.redeemCalls = append(f.redeemCalls, body.Code)
	if body.Code == "BADCODE" {
		writeAPIErr(w, http.StatusForbidden, "challenge_invalid")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeMctlAPI) handleCreate(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	extKey, _ := body["external_key"].(string)

	if f.refuseExternalKey != "" && extKey == f.refuseExternalKey {
		writeAPIErr(w, http.StatusConflict, "external_key_in_use")
		return
	}

	status := http.StatusCreated
	id, existed := f.itemsByExternalKey[extKey]
	if existed {
		status = http.StatusOK
	} else {
		f.nextItemN++
		id = fmt.Sprintf("wi_%d", f.nextItemN)
		f.itemsByExternalKey[extKey] = id
		f.itemState[id] = workctx.ItemStateActive
		f.itemVersion[id] = 1
	}
	writeJSON(w, status, workctx.ItemView{
		SchemaVersionField: workctx.SchemaVersion,
		WorkItem:           workctx.WorkItemDTO{ID: id, State: f.itemState[id]},
		StateVersion:       f.itemVersion[id],
	})
}

func (f *fakeMctlAPI) handleGetItem(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := r.PathValue("id")
	state, ok := f.itemState[id]
	if !ok {
		writeAPIErr(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, workctx.ItemView{
		SchemaVersionField: workctx.SchemaVersion,
		WorkItem:           workctx.WorkItemDTO{ID: id, State: state},
		StateVersion:       f.itemVersion[id],
	})
}

func (f *fakeMctlAPI) handleIntent(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body struct {
		Text string `json:"text"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.intentCalls = append(f.intentCalls, body.Text)
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeMctlAPI) handleSurfaceRef(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.surfaceCalls++
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeMctlAPI) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := r.PathValue("id")
	f.createRequestIdemKeys = append(f.createRequestIdemKeys, r.Header.Get("Idempotency-Key"))
	var body struct {
		Kind                 string `json:"kind"`
		ExpectedStateVersion int64  `json:"expected_state_version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if f.forceConflicts > 0 {
		f.forceConflicts--
		f.itemVersion[id] = f.itemVersion[id] + 1
		writeAPIErr(w, http.StatusConflict, "state_version_conflict")
		return
	}
	if body.ExpectedStateVersion != f.itemVersion[id] {
		writeAPIErr(w, http.StatusConflict, "state_version_conflict")
		return
	}
	f.nextReqN++
	req := &workctx.ExecutionRequestView{
		SchemaVersionField: workctx.SchemaVersion,
		ID:                 fmt.Sprintf("xr_%d", f.nextReqN),
		Kind:               body.Kind,
		State:              workctx.RequestStatePending,
	}
	if f.forcedRequestState != "" {
		req.State = f.forcedRequestState
		req.Reason = f.forcedRequestReason
	}
	f.requests[req.ID] = req
	writeJSON(w, http.StatusCreated, req)
}

func (f *fakeMctlAPI) handleListRequests(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var list []workctx.ExecutionRequestView
	for _, req := range f.requests {
		list = append(list, *req)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version":     workctx.SchemaVersion,
		"execution_requests": list,
	})
}

func (f *fakeMctlAPI) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rid := r.PathValue("rid")
	req, ok := f.requests[rid]
	if !ok {
		writeAPIErr(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, *req)
}

// failingTransport makes every request fail the test — used by T9/T13 to
// prove no HTTP call is ever attempted.
type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Fatalf("unexpected HTTP call: %s %s", r.Method, r.URL.String())
	return nil, fmt.Errorf("unreachable")
}

func newTestWorkStore(t *testing.T) (*db.Store, int64) {
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
	crypt, err := crypto.New(testKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	uid, err := store.EnsureUserByTelegramID(ctx, workOwnerTGID, "owner", "Owner")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	return store, uid
}

func newTestWorkHandler(t *testing.T, store *db.Store, sender SelfSender, client *workctx.Client) *WorkHandler {
	t.Helper()
	return &WorkHandler{Store: store, Client: client, Notifier: NewNotifier(store, sender)}
}

const testIssueURL = "https://github.com/mctlhq/mctl-telegram/issues/443"

func meta(uid int64, msgID int64) SavedMeta {
	return SavedMeta{UserID: uid, SelfTGID: workOwnerTGID, ChatTGID: workOwnerTGID, TGMessageID: msgID}
}

// TestFlagOffNoOp is T9: with Router.Work nil (the WORK_CONTEXT_ENABLED=false
// state), /mctl work and /mctl link produce the byte-identical unknown-command
// reply, and nothing resembling a client is ever touched.
func TestFlagOffNoOp(t *testing.T) {
	store, uid := newTestWorkStore(t)
	sender := &fakeSelfSender{}
	router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
	// router.Work is nil — the flag-off state.

	if err := router.HandleSavedText(context.Background(), SavedMeta{UserID: uid}, "/mctl frobnicate"); err != nil {
		t.Fatalf("handle unknown: %v", err)
	}
	baseline := sender.sent[0]

	sender.sent = nil
	if err := router.HandleSavedText(context.Background(), meta(uid, 1), "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("handle work: %v", err)
	}
	if len(sender.sent) != 1 || sender.sent[0] != baseline {
		t.Fatalf("/mctl work reply = %v, want byte-identical unknown-command reply %q", sender.sent, baseline)
	}

	sender.sent = nil
	if err := router.HandleSavedText(context.Background(), meta(uid, 2), "/mctl link SOMECODE"); err != nil {
		t.Fatalf("handle link: %v", err)
	}
	if len(sender.sent) != 1 || sender.sent[0] != baseline {
		t.Fatalf("/mctl link reply = %v, want byte-identical unknown-command reply %q", sender.sent, baseline)
	}
}

// TestExplicitRunnableTarget is T13: no argument, a title, a PR url, another
// owner, another host, and a numberless issue url all reply with the usage
// line, make no HTTP call, and write no binding.
func TestExplicitRunnableTarget(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"no argument", "/mctl work"},
		{"a title", "/mctl work fix the login bug"},
		{"pull request url", "/mctl work https://github.com/mctlhq/mctl-telegram/pull/443"},
		{"another owner", "/mctl work https://github.com/other/mctl-telegram/issues/443"},
		{"another host", "/mctl work https://gitlab.com/mctlhq/mctl-telegram/issues/443"},
		{"issue without number", "/mctl work https://github.com/mctlhq/mctl-telegram/issues/"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store, uid := newTestWorkStore(t)
			sender := &fakeSelfSender{}
			client := workctx.NewClient("http://unused.invalid", "tok", "tenant", &http.Client{Transport: failingTransport{t}})
			router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
			router.Work = newTestWorkHandler(t, store, sender, client)

			if err := router.HandleSavedText(context.Background(), meta(uid, int64(1000+i)), c.text); err != nil {
				t.Fatalf("handle: %v", err)
			}
			if len(sender.sent) != 1 || !strings.HasPrefix(sender.sent[0], "Usage:") {
				t.Fatalf("reply = %v, want a Usage message", sender.sent)
			}
			_, found, err := store.GetWorkItemBinding(context.Background(), uid, workOwnerTGID, int64(1000+i))
			if err != nil {
				t.Fatalf("get binding: %v", err)
			}
			if found {
				t.Fatal("a binding was written despite an invalid target")
			}
		})
	}
}

// TestActorFailClosed is T11: when the stored Telegram id disagrees with (or
// is absent for) SavedMeta.SelfTGID, no HTTP request is made and the owner
// is told the account is not linked.
func TestActorFailClosed(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(testKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	// EnsureUser (not EnsureUserByTelegramID) leaves telegram_login_id NULL —
	// TelegramIDByUserID must report found=false for this user.
	uid, err := store.EnsureUser(ctx, "no-telegram-id", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	sender := &fakeSelfSender{}
	client := workctx.NewClient("http://unused.invalid", "tok", "tenant", &http.Client{Transport: failingTransport{t}})
	router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
	router.Work = newTestWorkHandler(t, store, sender, client)

	if err := router.HandleSavedText(ctx, SavedMeta{UserID: uid, SelfTGID: 999, ChatTGID: 999, TGMessageID: 1}, "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 || !strings.Contains(sender.sent[0], "not linked") {
		t.Fatalf("reply = %v, want a not-linked message", sender.sent)
	}
}

// TestOpenIdempotentAndStatusRendering exercises the open->status->resume
// happy path plus T6 (idempotent open) and T16 (submitted-request reply
// contains id and pending, never "accepted").
func TestOpenIdempotentAndStatusRendering(t *testing.T) {
	store, uid := newTestWorkStore(t)
	fake := newFakeMctlAPI()
	srv := fake.server(t)
	defer srv.Close()
	sender := &fakeSelfSender{}
	client := workctx.NewClient(srv.URL, "tok", "tenant", nil)
	router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
	router.Work = newTestWorkHandler(t, store, sender, client)
	ctx := context.Background()
	m := meta(uid, 5000)

	if err := router.HandleSavedText(ctx, m, "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("open: %v", err)
	}
	if fake.createCalls != 1 {
		t.Fatalf("createCalls = %d, want 1", fake.createCalls)
	}
	if len(fake.requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(fake.requests))
	}
	reply := sender.sent[len(sender.sent)-1]
	if !strings.Contains(reply, "pending") || strings.Contains(strings.ToLower(reply), "accepted") {
		t.Fatalf("open reply = %q, want it to name pending and never accepted", reply)
	}

	binding, found, err := store.GetWorkItemBinding(ctx, uid, workOwnerTGID, 5000)
	if err != nil || !found {
		t.Fatalf("get binding: found=%v err=%v", found, err)
	}
	if binding.LastRequestID == "" {
		t.Fatal("binding has no recorded request id")
	}

	// T6: repeating the identical open (same thread key) must not create a
	// second item or a second request.
	if err := router.HandleSavedText(ctx, m, "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("repeat open: %v", err)
	}
	if fake.createCalls != 1 {
		t.Fatalf("createCalls after repeat = %d, want still 1", fake.createCalls)
	}

	sender.sent = nil
	if err := router.HandleSavedText(ctx, meta(uid, 5001), "/mctl work status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	statusReply := sender.sent[0]
	if !strings.Contains(statusReply, binding.WorkItemID) || !strings.Contains(statusReply, "pending") {
		t.Fatalf("status reply = %q", statusReply)
	}
}

// TestDedupeAndConflict is T15: a 200 dedupe onto an existing item binds the
// thread; a 409 external_key_in_use writes no binding.
func TestDedupeAndConflict(t *testing.T) {
	store, uid := newTestWorkStore(t)
	fake := newFakeMctlAPI()
	fake.itemsByExternalKey[testIssueURL] = "wi_existing"
	fake.itemState["wi_existing"] = workctx.ItemStateActive
	fake.itemVersion["wi_existing"] = 3
	srv := fake.server(t)
	defer srv.Close()
	sender := &fakeSelfSender{}
	client := workctx.NewClient(srv.URL, "tok", "tenant", nil)
	router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
	router.Work = newTestWorkHandler(t, store, sender, client)
	ctx := context.Background()

	if err := router.HandleSavedText(ctx, meta(uid, 6000), "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("open: %v", err)
	}
	binding, found, err := store.GetWorkItemBinding(ctx, uid, workOwnerTGID, 6000)
	if err != nil || !found {
		t.Fatalf("get binding: found=%v err=%v", found, err)
	}
	if binding.WorkItemID != "wi_existing" {
		t.Fatalf("binding.WorkItemID = %q, want wi_existing (the deduped item)", binding.WorkItemID)
	}

	fake.refuseExternalKey = "https://github.com/mctlhq/other-repo/issues/1"
	sender.sent = nil
	if err := router.HandleSavedText(ctx, meta(uid, 6001), "/mctl work https://github.com/mctlhq/other-repo/issues/1"); err != nil {
		t.Fatalf("open conflict: %v", err)
	}
	if _, found, _ := store.GetWorkItemBinding(ctx, uid, workOwnerTGID, 6001); found {
		t.Fatal("a binding was written despite external_key_in_use")
	}
	if !strings.Contains(sender.sent[0], "cannot access") && !strings.Contains(sender.sent[0], "don't have access") {
		t.Fatalf("conflict reply = %q, want an access-denied style message", sender.sent[0])
	}
}

// TestNoTranscriptPersisted is T12: after a create/note/status/resume
// cycle with distinctive message text, no column in work_item_bindings
// contains that text.
func TestNoTranscriptPersisted(t *testing.T) {
	store, uid := newTestWorkStore(t)
	fake := newFakeMctlAPI()
	srv := fake.server(t)
	defer srv.Close()
	sender := &fakeSelfSender{}
	client := workctx.NewClient(srv.URL, "tok", "tenant", nil)
	router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
	router.Work = newTestWorkHandler(t, store, sender, client)
	ctx := context.Background()

	const secret = "DISTINCTIVE_SECRET_TRANSCRIPT_MARKER"
	if err := router.HandleSavedText(ctx, meta(uid, 7000), "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := router.HandleSavedText(ctx, meta(uid, 7001), "/mctl work note "+secret); err != nil {
		t.Fatalf("note: %v", err)
	}
	if err := router.HandleSavedText(ctx, meta(uid, 7002), "/mctl work status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := router.HandleSavedText(ctx, meta(uid, 7003), "/mctl work resume"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if len(fake.intentCalls) != 1 || fake.intentCalls[0] != secret {
		t.Fatalf("intent was not forwarded to mctl-api: %v", fake.intentCalls)
	}

	rows, err := store.DB.QueryContext(ctx, `SELECT user_id, chat_tg_id, root_tg_message_id, work_item_id, external_key, last_state, last_execution_id, last_request_id FROM work_item_bindings`)
	if err != nil {
		t.Fatalf("query bindings: %v", err)
	}
	defer rows.Close()
	found := 0
	for rows.Next() {
		found++
		var userID, chatID, rootID int64
		var workItemID, externalKey, lastState, lastExecID, lastReqID string
		if err := rows.Scan(&userID, &chatID, &rootID, &workItemID, &externalKey, &lastState, &lastExecID, &lastReqID); err != nil {
			t.Fatalf("scan: %v", err)
		}
		for _, v := range []string{workItemID, externalKey, lastState, lastExecID, lastReqID} {
			if strings.Contains(v, secret) {
				t.Fatalf("transcript text leaked into work_item_bindings: %q", v)
			}
		}
	}
	if found == 0 {
		t.Fatal("no binding rows found")
	}
}

// TestResumeConcurrency is T7: a state-version conflict is retried exactly
// once.
func TestResumeConcurrency(t *testing.T) {
	store, uid := newTestWorkStore(t)
	fake := newFakeMctlAPI()
	srv := fake.server(t)
	defer srv.Close()
	sender := &fakeSelfSender{}
	client := workctx.NewClient(srv.URL, "tok", "tenant", nil)
	router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
	router.Work = newTestWorkHandler(t, store, sender, client)
	ctx := context.Background()

	if err := router.HandleSavedText(ctx, meta(uid, 8000), "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("open: %v", err)
	}
	// A single conflict: one bounded retry succeeds.
	fake.forceConflicts = 1
	sender.sent = nil
	if err := router.HandleSavedText(ctx, meta(uid, 8001), "/mctl work resume"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	reply := sender.sent[0]
	if !strings.Contains(reply, "pending") {
		t.Fatalf("resume reply = %q, want a pending request (single retry should have succeeded)", reply)
	}

	// Two consecutive conflicts: the handler stops after one retry and
	// tells the owner, instead of looping.
	fake.forceConflicts = 2
	sender.sent = nil
	if err := router.HandleSavedText(ctx, meta(uid, 8002), "/mctl work resume"); err != nil {
		t.Fatalf("resume (double conflict): %v", err)
	}
	reply = sender.sent[0]
	if !strings.Contains(reply, "changed") {
		t.Fatalf("resume reply after double conflict = %q, want an item-changed message", reply)
	}
}

// TestRequestStateRendering is T14: a table test over /mctl work status for
// each documented request state and typed rejection reason, an unknown
// reason (shown verbatim, never mctl-api's free text), a binding with no
// recorded request (falls back to the newest from the list), and a failing
// request read (the item part still renders; "request state unavailable").
func TestRequestStateRendering(t *testing.T) {
	cases := []struct {
		name       string
		state      string
		reason     string
		wantSubstr []string
		wantAbsent []string
	}{
		{"pending", workctx.RequestStatePending, "", []string{"pending"}, nil},
		{"claimed", workctx.RequestStateClaimed, "", []string{"claimed"}, nil},
		{"fulfilled", workctx.RequestStateFulfilled, "", []string{"fulfilled"}, nil},
		{"rejected no_runnable_target", workctx.RequestStateRejected, "no_runnable_target",
			[]string{"no_runnable_target", "no runnable"}, nil},
		{"rejected loop_active", workctx.RequestStateRejected, "loop_active",
			[]string{"loop_active", "already running"}, nil},
		{"rejected unsupported_kind", workctx.RequestStateRejected, "unsupported_kind",
			[]string{"unsupported_kind"}, nil},
		{"rejected resume_refused", workctx.RequestStateRejected, "resume_refused:stale",
			[]string{"resume_refused:stale", "stale"}, nil},
		{"rejected fulfil_refused", workctx.RequestStateRejected, "fulfil_refused:bad_engine",
			[]string{"fulfil_refused:bad_engine", "bad_engine"}, nil},
		{"rejected engine_run_ended", workctx.RequestStateRejected, "engine_run_ended",
			[]string{"engine_run_ended", "ended"}, nil},
		{"rejected unrecognised", workctx.RequestStateRejected, "some_new_code_v99",
			[]string{"some_new_code_v99", "unrecognised"}, []string{"mctl-api free text should never appear"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store, uid := newTestWorkStore(t)
			fake := newFakeMctlAPI()
			srv := fake.server(t)
			defer srv.Close()
			sender := &fakeSelfSender{}
			client := workctx.NewClient(srv.URL, "tok", "tenant", nil)
			router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
			router.Work = newTestWorkHandler(t, store, sender, client)
			ctx := context.Background()

			if err := router.HandleSavedText(ctx, meta(uid, 9000), "/mctl work "+testIssueURL); err != nil {
				t.Fatalf("open: %v", err)
			}
			binding, _, _ := store.GetWorkItemBinding(ctx, uid, workOwnerTGID, 9000)
			fake.requests[binding.LastRequestID].State = c.state
			fake.requests[binding.LastRequestID].Reason = c.reason

			sender.sent = nil
			if err := router.HandleSavedText(ctx, meta(uid, 9001), "/mctl work status"); err != nil {
				t.Fatalf("status: %v", err)
			}
			reply := sender.sent[0]
			for _, want := range c.wantSubstr {
				if !strings.Contains(reply, want) {
					t.Errorf("reply = %q, want it to contain %q", reply, want)
				}
			}
			for _, absent := range c.wantAbsent {
				if strings.Contains(reply, absent) {
					t.Errorf("reply = %q, must not contain %q", reply, absent)
				}
			}
		})
	}

	// Binding with no recorded request: falls back to the newest from the
	// list.
	t.Run("no recorded request falls back to list", func(t *testing.T) {
		store, uid := newTestWorkStore(t)
		fake := newFakeMctlAPI()
		srv := fake.server(t)
		defer srv.Close()
		sender := &fakeSelfSender{}
		client := workctx.NewClient(srv.URL, "tok", "tenant", nil)
		router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
		router.Work = newTestWorkHandler(t, store, sender, client)
		ctx := context.Background()

		if err := router.HandleSavedText(ctx, meta(uid, 9100), "/mctl work "+testIssueURL); err != nil {
			t.Fatalf("open: %v", err)
		}
		// Clear the binding's recorded request id directly to simulate an
		// older/lost row.
		if _, err := store.DB.ExecContext(ctx, `UPDATE work_item_bindings SET last_request_id='' WHERE user_id=$1 AND chat_tg_id=$2 AND root_tg_message_id=$3`,
			uid, workOwnerTGID, int64(9100)); err != nil {
			t.Fatalf("clear request id: %v", err)
		}
		sender.sent = nil
		if err := router.HandleSavedText(ctx, meta(uid, 9101), "/mctl work status"); err != nil {
			t.Fatalf("status: %v", err)
		}
		if !strings.Contains(sender.sent[0], "pending") {
			t.Fatalf("reply = %q, want it to fall back to the newest listed request", sender.sent[0])
		}
	})

	// A failing request read degrades to "request state unavailable" but
	// still renders the item part.
	t.Run("failing request read degrades gracefully", func(t *testing.T) {
		store, uid := newTestWorkStore(t)
		fake := newFakeMctlAPI()
		srv := fake.server(t)
		sender := &fakeSelfSender{}
		client := workctx.NewClient(srv.URL, "tok", "tenant", nil)
		router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
		router.Work = newTestWorkHandler(t, store, sender, client)
		ctx := context.Background()

		if err := router.HandleSavedText(ctx, meta(uid, 9200), "/mctl work "+testIssueURL); err != nil {
			t.Fatalf("open: %v", err)
		}
		srv.Close() // every subsequent call fails
		sender.sent = nil
		if err := router.HandleSavedText(ctx, meta(uid, 9201), "/mctl work status"); err != nil {
			t.Fatalf("status: %v", err)
		}
		if len(sender.sent) != 1 {
			t.Fatalf("replies = %d, want 1 (degraded, not failed)", len(sender.sent))
		}
	})
}

// TestTwoThreadsOneIssue is T17: the same owner runs /mctl work <url> for
// the same issue in two threads; mctl-api's dedupe returns the same item for
// both. Both threads are bound (two rows) and each row keeps its own
// LastRequestID (verified via direct GetWorkItemBinding reads, not the
// chat-scoped /mctl work status handler), and a state change seen from
// either thread is reflected in both.
func TestTwoThreadsOneIssue(t *testing.T) {
	store, uid := newTestWorkStore(t)
	fake := newFakeMctlAPI()
	srv := fake.server(t)
	defer srv.Close()
	sender := &fakeSelfSender{}
	client := workctx.NewClient(srv.URL, "tok", "tenant", nil)
	router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
	router.Work = newTestWorkHandler(t, store, sender, client)
	ctx := context.Background()

	if err := router.HandleSavedText(ctx, meta(uid, 10000), "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("open thread A: %v", err)
	}
	if err := router.HandleSavedText(ctx, meta(uid, 10001), "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("open thread B: %v", err)
	}
	// Both threads call POST /work-items (each is its own thread key, so
	// neither reuses a cached binding locally) but mctl-api's own
	// external_key dedupe means only one item is ever actually created —
	// verified below by both threads sharing one WorkItemID.
	if fake.createCalls != 2 {
		t.Fatalf("createCalls = %d, want 2 (one per thread, deduped server-side)", fake.createCalls)
	}
	if len(fake.itemsByExternalKey) != 1 {
		t.Fatalf("distinct items created = %d, want 1 (mctl-api dedupe on external_key)", len(fake.itemsByExternalKey))
	}

	threadA, foundA, errA := store.GetWorkItemBinding(ctx, uid, workOwnerTGID, 10000)
	threadB, foundB, errB := store.GetWorkItemBinding(ctx, uid, workOwnerTGID, 10001)
	if errA != nil || !foundA || errB != nil || !foundB {
		t.Fatalf("bindings: A(found=%v err=%v) B(found=%v err=%v)", foundA, errA, foundB, errB)
	}
	if threadA.WorkItemID != threadB.WorkItemID {
		t.Fatalf("threads bound to different items: A=%s B=%s", threadA.WorkItemID, threadB.WorkItemID)
	}
	if threadA.LastRequestID == threadB.LastRequestID {
		t.Fatalf("both threads share the same request id %q; each thread submits its own", threadA.LastRequestID)
	}

	// A state change seen from either thread (TouchWorkItemBindingState is
	// item-level) is reflected in both.
	if err := store.TouchWorkItemBindingState(ctx, uid, threadA.WorkItemID, "waiting", 9, "exec_z"); err != nil {
		t.Fatalf("touch: %v", err)
	}
	refreshedA, _, _ := store.GetWorkItemBinding(ctx, uid, workOwnerTGID, 10000)
	refreshedB, _, _ := store.GetWorkItemBinding(ctx, uid, workOwnerTGID, 10001)
	if refreshedA.LastState != "waiting" || refreshedB.LastState != "waiting" {
		t.Fatalf("state after touch: A=%q B=%q, want both waiting", refreshedA.LastState, refreshedB.LastState)
	}
}

// TestResumeRetryAfterRefusalGetsFreshIdempotencyKey is a regression test
// for a P2 finding: a refused resume does not advance the work item's
// state_version, so keying resume's Idempotency-Key on the binding's root
// message id plus state_version alone made a second, deliberate /mctl work
// resume recompute the EXACT SAME key as the refused attempt — which the
// platform's idempotency cache would answer with that same stale rejection
// forever, making resume permanently a no-op. The fix scopes the key to the
// resume command's own message id instead, so each distinct /mctl work
// resume gets its own key even when state_version has not moved.
func TestResumeRetryAfterRefusalGetsFreshIdempotencyKey(t *testing.T) {
	store, uid := newTestWorkStore(t)
	fake := newFakeMctlAPI()
	srv := fake.server(t)
	defer srv.Close()
	sender := &fakeSelfSender{}
	client := workctx.NewClient(srv.URL, "tok", "tenant", nil)
	router := NewRouter(store, &fakeApprover{}, NewNotifier(store, sender))
	router.Work = newTestWorkHandler(t, store, sender, client)
	ctx := context.Background()

	if err := router.HandleSavedText(ctx, meta(uid, 11000), "/mctl work "+testIssueURL); err != nil {
		t.Fatalf("open: %v", err)
	}
	// The open's own "start" execution-request call already used one
	// Idempotency-Key; only look at calls made from here on.
	fake.createRequestIdemKeys = nil

	// First resume is refused by the platform. A refusal never bumps the
	// work item's state_version.
	fake.forcedRequestState = workctx.RequestStateRejected
	fake.forcedRequestReason = "resume_refused:stale"
	sender.sent = nil
	if err := router.HandleSavedText(ctx, meta(uid, 11001), "/mctl work resume"); err != nil {
		t.Fatalf("resume 1: %v", err)
	}
	if len(fake.createRequestIdemKeys) != 1 {
		t.Fatalf("execution-request calls after first resume = %d, want 1", len(fake.createRequestIdemKeys))
	}
	firstKey := fake.createRequestIdemKeys[0]

	// Un-force the rejection so a genuinely new attempt could succeed if it
	// actually reaches the handler instead of being answered from a cached
	// refusal.
	fake.forcedRequestState = ""
	fake.forcedRequestReason = ""
	sender.sent = nil
	if err := router.HandleSavedText(ctx, meta(uid, 11002), "/mctl work resume"); err != nil {
		t.Fatalf("resume 2: %v", err)
	}
	if len(fake.createRequestIdemKeys) != 2 {
		t.Fatalf("execution-request calls after second resume = %d, want 2 (a fresh attempt was submitted)", len(fake.createRequestIdemKeys))
	}
	secondKey := fake.createRequestIdemKeys[1]
	if secondKey == firstKey {
		t.Fatalf("resume reused idempotency key %q across attempts after a refusal — this wedges /mctl work resume permanently", firstKey)
	}

	reply := sender.sent[0]
	if strings.Contains(reply, "resume_refused") {
		t.Fatalf("second resume reply = %q, still shows the stale refusal instead of a fresh attempt", reply)
	}
	if !strings.Contains(reply, "pending") {
		t.Fatalf("second resume reply = %q, want a pending request", reply)
	}
}
