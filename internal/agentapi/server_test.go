package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// testCryptKey is a fixed 32-byte key so encrypted columns (event bodies,
// action payloads, notification bodies) round-trip in tests instead of
// panicking on a nil crypto.Crypter — several handlers under test touch
// these columns.
func testCryptKey() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// testHarness bundles a Server mounted on a real chi.Router (so {param}
// routes are exercised exactly as in production) plus the underlying store
// and a ready-made identity for the seeded user.
type testHarness struct {
	t      *testing.T
	srv    *Server
	store  *db.Store
	router *chi.Mux
	userID int64
	id     *auth.Identity
}

func newHarness(t *testing.T) *testHarness {
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
	crypt, err := crypto.New(testCryptKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	uid, err := store.EnsureUser(ctx, "owner", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	q := queue.New(store, "test-replica", nil)
	srv := New(store, q, time.Minute, nil).WithLongPollTimeout(150 * time.Millisecond)

	router := chi.NewRouter()
	srv.Register(router)

	return &testHarness{
		t: t, srv: srv, store: store, router: router, userID: uid,
		id: &auth.Identity{UserID: uid, Subject: "tg:1", TelegramID: 1},
	}
}

// do performs an authenticated request (the harness's identity is seeded
// into the context, bypassing auth.Middleware — this package's handlers only
// ever read auth.From(ctx), matching internal/bridge/tokenhandler_test.go's
// pattern) and returns the recorder.
func (h *testHarness) do(method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			h.t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req = req.WithContext(auth.With(req.Context(), h.id))
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *testHarness) doAnon(method, path string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

// doAs is like do but authenticates as an arbitrary identity rather than the
// harness's default seeded user — used for cross-user isolation tests.
func (h *testHarness) doAs(id *auth.Identity, method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			h.t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req = req.WithContext(auth.With(req.Context(), id))
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *testHarness) seedProfile(mode string) {
	h.t.Helper()
	if err := h.store.UpsertAgentProfile(context.Background(), db.AgentProfile{
		UserID: h.userID, Mode: mode, DisclosureText: "I'm an AI assistant.",
	}); err != nil {
		h.t.Fatalf("seed profile: %v", err)
	}
}

func (h *testHarness) seedConversation(peerTGID int64) *db.Conversation {
	h.t.Helper()
	conv, err := h.store.EnsureConversation(context.Background(), h.userID, peerTGID, "peer", "Peer")
	if err != nil {
		h.t.Fatalf("seed conversation: %v", err)
	}
	return conv
}

func (h *testHarness) seedJob(eventID string, convID int64) int64 {
	h.t.Helper()
	ctx := context.Background()
	if _, _, err := h.store.InsertIncomingEvent(ctx, db.IncomingEvent{
		EventID: eventID, UserID: h.userID, Kind: db.EventKindPrivateMessage,
		ChatTGID: 1, SenderTGID: 1, MessageID: 1, Body: "hello",
	}); err != nil {
		h.t.Fatalf("insert event: %v", err)
	}
	jobID, enqueued, err := h.store.EnqueueAgentJob(ctx, eventID, h.userID, convID)
	if err != nil || !enqueued {
		h.t.Fatalf("enqueue: id=%d enqueued=%v err=%v", jobID, enqueued, err)
	}
	return jobID
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(dst); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
}

func TestHandlers_RequireAuth(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		method, path string
	}{
		{"GET", "/events"},
		{"POST", "/jobs/claim"},
		{"GET", "/event/evt:1"},
		{"GET", "/conversations/1/context"},
		{"GET", "/recruiters/555"},
		{"GET", "/leads/1"},
		{"GET", "/policy"},
		{"GET", "/jobs/1"},
		{"POST", "/leads"},
		{"POST", "/actions/propose_reply"},
		{"POST", "/actions/request_owner_approval"},
		{"POST", "/notify/summary"},
		{"POST", "/autopilot/pause"},
		{"POST", "/jobs/1/complete"},
	} {
		rec := h.doAnon(tc.method, tc.path)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestHandleGetJob_ReturnsMinimalDurableStatus(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:status", conv.ID)

	rec := h.do("GET", "/jobs/"+itoaTest(jobID), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pending status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var pending jobStatusResponse
	decodeBody(t, rec, &pending)
	if pending.JobID != jobID || pending.Status != db.JobPending || pending.Attempt != 0 {
		t.Fatalf("pending response = %#v", pending)
	}

	claim := h.do("POST", "/jobs/claim", nil)
	if claim.Code != http.StatusOK {
		t.Fatalf("claim status = %d", claim.Code)
	}
	rec = h.do("GET", "/jobs/"+itoaTest(jobID), nil)
	var processing jobStatusResponse
	decodeBody(t, rec, &processing)
	if processing.Status != db.JobProcessing || processing.Attempt != 1 {
		t.Fatalf("processing response = %#v", processing)
	}

	complete := h.do("POST", "/jobs/"+itoaTest(jobID)+"/complete", completeJobRequest{
		Attempt: 1, Status: db.JobIgnored,
	})
	if complete.Code != http.StatusOK {
		t.Fatalf("complete status = %d, body=%s", complete.Code, complete.Body.String())
	}
	rec = h.do("GET", "/jobs/"+itoaTest(jobID), nil)
	var terminal jobStatusResponse
	decodeBody(t, rec, &terminal)
	if terminal.Status != db.JobIgnored || terminal.Attempt != 1 {
		t.Fatalf("terminal response = %#v", terminal)
	}
}

func TestHandleGetJob_IsScopedToCaller(t *testing.T) {
	h := newHarness(t)
	otherUID, err := h.store.EnsureUser(context.Background(), "job-owner-other", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, _, err := h.store.InsertIncomingEvent(context.Background(), db.IncomingEvent{
		EventID: "evt:v1:2:999:status", UserID: otherUID, Kind: db.EventKindPrivateMessage,
		ChatTGID: 999, SenderTGID: 999, MessageID: 1, Body: "private",
	}); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	jobID, _, err := h.store.EnqueueAgentJob(context.Background(), "evt:v1:2:999:status", otherUID, 0)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	rec := h.do("GET", "/jobs/"+itoaTest(jobID), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user status = %d, want 404", rec.Code)
	}
}

func TestHandleClaimJobs_TimesOutEmpty(t *testing.T) {
	h := newHarness(t)
	rec := h.do("POST", "/jobs/claim", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	decodeBody(t, rec, &body)
	if len(body.Jobs) != 0 {
		t.Fatalf("jobs = %v, want empty", body.Jobs)
	}
}

func TestHandleClaimJobs_ClaimsQueuedJob(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:1", conv.ID)

	rec := h.do("POST", "/jobs/claim", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	decodeBody(t, rec, &body)
	if len(body.Jobs) != 1 || body.Jobs[0].JobID != jobID {
		t.Fatalf("jobs = %+v, want one job with id %d", body.Jobs, jobID)
	}
	if body.Jobs[0].Attempt != 1 {
		t.Fatalf("attempt = %d, want 1", body.Jobs[0].Attempt)
	}

	// A second poll must not re-claim the same (now-processing) job.
	rec2 := h.do("POST", "/jobs/claim", nil)
	var body2 struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	decodeBody(t, rec2, &body2)
	if len(body2.Jobs) != 0 {
		t.Fatalf("second poll jobs = %v, want empty (already claimed)", body2.Jobs)
	}
}

// TestHandleClaimJobs_ScopedToCaller guards against the P1 found in review: a
// worker authenticated for one account must never be able to claim, and
// thereby see the event_id/conversation_id of, another account's job.
func TestHandleClaimJobs_ScopedToCaller(t *testing.T) {
	h := newHarness(t)
	otherUID, err := h.store.EnsureUser(context.Background(), "other-owner", "", "test")
	if err != nil {
		t.Fatalf("ensure second user: %v", err)
	}
	otherConv, err := h.store.EnsureConversation(context.Background(), otherUID, 999, "other-peer", "Other")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	if _, _, err := h.store.InsertIncomingEvent(context.Background(), db.IncomingEvent{
		EventID: "evt:v1:2:999:1", UserID: otherUID, Kind: db.EventKindPrivateMessage,
		ChatTGID: 999, SenderTGID: 999, MessageID: 1, Body: "someone else's message",
	}); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if _, enq, err := h.store.EnqueueAgentJob(context.Background(), "evt:v1:2:999:1", otherUID, otherConv.ID); err != nil || !enq {
		t.Fatalf("enqueue: enq=%v err=%v", enq, err)
	}

	// The harness's default identity (a DIFFERENT user) must see nothing —
	// not even a hint that another account has a pending job.
	rec := h.do("POST", "/jobs/claim", nil)
	var body struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	decodeBody(t, rec, &body)
	if len(body.Jobs) != 0 {
		t.Fatalf("cross-user claim leaked jobs = %+v, want empty", body.Jobs)
	}

	// The actual owner CAN claim it.
	otherID := &auth.Identity{UserID: otherUID, Subject: "tg:2", TelegramID: 2}
	rec2 := h.doAs(otherID, "POST", "/jobs/claim", nil)
	var body2 struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	decodeBody(t, rec2, &body2)
	if len(body2.Jobs) != 1 {
		t.Fatalf("owner's own claim = %+v, want exactly one job", body2.Jobs)
	}
}

func TestHandleLegacyEvents_IsDeprecatedAndClaims(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:legacy", conv.ID)

	rec := h.do("GET", "/events", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Deprecation"); got != "@1785024000" {
		t.Fatalf("Deprecation = %q, want @1785024000", got)
	}
	if got := rec.Header().Get("Sunset"); got != "Thu, 31 Dec 2026 23:59:59 GMT" {
		t.Fatalf("Sunset = %q", got)
	}
	if got := rec.Header().Get("Link"); got != `</api/agent/v1/jobs/claim>; rel="successor-version"` {
		t.Fatalf("Link = %q", got)
	}
	var body struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	decodeBody(t, rec, &body)
	if len(body.Jobs) != 1 || body.Jobs[0].JobID != jobID {
		t.Fatalf("jobs = %+v, want one job with id %d", body.Jobs, jobID)
	}

	// The replacement endpoint is not itself deprecated.
	rec = h.do("POST", "/jobs/claim", nil)
	if got := rec.Header().Get("Deprecation"); got != "" {
		t.Fatalf("POST Deprecation = %q, want empty", got)
	}
}

func TestHandleGetEvent(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	h.seedJob("evt:v1:1:555:1", conv.ID)

	rec := h.do("GET", "/event/evt:v1:1:555:1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var ev eventResponse
	decodeBody(t, rec, &ev)
	if ev.Body != "hello" {
		t.Fatalf("body = %q, want %q", ev.Body, "hello")
	}

	rec404 := h.do("GET", "/event/evt:does-not-exist", nil)
	if rec404.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec404.Code)
	}
}

func TestHandleProposeReply_NoProfile(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, Text: "hi",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleProposeReply_ObserveModeRequiresApproval(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv := h.seedConversation(555)

	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, Intent: "discovery", Text: "Thanks for reaching out!",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp actionResponse
	decodeBody(t, rec, &resp)
	if resp.Decision != string(policy.RequireApproval) {
		t.Fatalf("decision = %q, want require_approval", resp.Decision)
	}
	if resp.Status != db.ActionPendingApproval {
		t.Fatalf("status = %q, want pending_approval", resp.Status)
	}
	if len(resp.ApprovalCode) != 6 {
		t.Fatalf("approval code = %q, want 6 chars", resp.ApprovalCode)
	}

	action, err := h.store.GetAgentActionByCode(context.Background(), h.userID, resp.ApprovalCode)
	if err != nil {
		t.Fatalf("lookup by code: %v", err)
	}
	if action.ID != resp.ActionID {
		t.Fatalf("action id = %d, want %d", action.ID, resp.ActionID)
	}
}

// TestHandleProposeReply_RedeliveryReturnsSameApprovalCode guards against
// the P1 found in review: InsertAgentAction is idempotent per
// (job_id, action_type), so a redelivered job (worker crashed after
// propose_reply but before completing the job, sweeper requeues it, worker
// calls propose_reply again) must get back the code ACTUALLY stored on the
// row — not a fresh one the DB never saw, which would send the owner a code
// that /mctl approve can never match. The redelivery is simulated as it
// really happens — a requeue that bumps the job's claimed attempt — not a
// bare repeat of the same request, so this also exercises
// InsertAgentAction's attempt-fencing (see its doc comment) alongside the
// dedup path: the second call's higher attempt must still resolve to the
// same pre-existing row via the (job_id, action_type) index, not be rejected
// as stale.
func TestHandleProposeReply_RedeliveryReturnsSameApprovalCode(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:redelivery", conv.ID)
	// Claim it first, like a real worker would via POST /jobs/claim — propose_reply
	// is only ever called while the job is actively processing.
	claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}

	req := proposeReplyRequest{ConversationID: conv.ID, JobID: jobID, Attempt: claimed[0].Attempts, Text: "Thanks for reaching out!"}

	rec1 := h.do("POST", "/actions/propose_reply", req)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first propose status = %d, body=%s", rec1.Code, rec1.Body.String())
	}
	var resp1 actionResponse
	decodeBody(t, rec1, &resp1)

	// Simulate a crash-and-requeue redelivery: the sweeper retries the job
	// (bumping its attempt) and a worker reclaims it under the new attempt,
	// without the first call ever reaching /jobs/{id}/complete.
	if _, err := h.store.RetryAgentJob(context.Background(), jobID, claimed[0].Attempts, "worker crashed"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, err := h.store.DB.ExecContext(context.Background(),
		`UPDATE agent_jobs SET next_run_at = $1 WHERE id = $2`, time.Now().UTC(), jobID,
	); err != nil {
		t.Fatalf("unbackoff: %v", err)
	}
	reclaimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim: jobs=%+v err=%v", reclaimed, err)
	}
	req.Attempt = reclaimed[0].Attempts

	rec2 := h.do("POST", "/actions/propose_reply", req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second propose status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	var resp2 actionResponse
	decodeBody(t, rec2, &resp2)

	if resp2.ActionID != resp1.ActionID {
		t.Fatalf("redelivery action id = %d, want the original %d", resp2.ActionID, resp1.ActionID)
	}
	if resp2.ApprovalCode != resp1.ApprovalCode {
		t.Fatalf("redelivery approval code = %q, want the original %q (must match what's actually stored)",
			resp2.ApprovalCode, resp1.ApprovalCode)
	}

	// The code the caller was told about must be the one actually looked up
	// by /mctl approve <code> — this is the real assertion the P1 was about.
	action, err := h.store.GetAgentActionByCode(context.Background(), h.userID, resp2.ApprovalCode)
	if err != nil {
		t.Fatalf("lookup by returned code: %v", err)
	}
	if action.ID != resp1.ActionID {
		t.Fatalf("code resolves to action %d, want %d", action.ID, resp1.ActionID)
	}
}

func TestHandleProposeReply_RedeliveryUsesPersistedActionState(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:policy-changed-redelivery", conv.ID)
	claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}
	req := proposeReplyRequest{
		ConversationID: conv.ID, JobID: jobID, Attempt: claimed[0].Attempts,
		Intent: "discovery", Text: "Thanks for reaching out!",
	}

	first := h.do("POST", "/actions/propose_reply", req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	var original actionResponse
	decodeBody(t, first, &original)
	if original.Status != db.ActionPendingApproval || original.ApprovalCode == "" {
		t.Fatalf("original response=%+v, want pending approval with code", original)
	}

	if err := h.store.UpsertAgentProfile(context.Background(), db.AgentProfile{
		UserID: h.userID, Mode: db.AgentModeGuarded,
		DisclosureText: "I'm an AI assistant.", IntentAllowlist: "discovery",
	}); err != nil {
		t.Fatalf("switch profile to allow: %v", err)
	}
	if _, err := h.store.RetryAgentJob(context.Background(), jobID, claimed[0].Attempts, "worker crashed"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, err := h.store.DB.ExecContext(context.Background(),
		`UPDATE agent_jobs SET next_run_at = $1 WHERE id = $2`, time.Now().UTC(), jobID,
	); err != nil {
		t.Fatalf("unbackoff: %v", err)
	}
	reclaimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim: jobs=%+v err=%v", reclaimed, err)
	}
	req.Attempt = reclaimed[0].Attempts
	replay := h.do("POST", "/actions/propose_reply", req)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	var got actionResponse
	decodeBody(t, replay, &got)
	if got.ActionID != original.ActionID {
		t.Fatalf("action id=%d, want persisted %d", got.ActionID, original.ActionID)
	}
	if got.Decision != db.PolicyRequireApproval || got.Status != db.ActionPendingApproval {
		t.Fatalf("replay decision/status=%q/%q, want persisted require_approval/pending_approval", got.Decision, got.Status)
	}
	if got.ApprovalCode != original.ApprovalCode {
		t.Fatalf("approval code=%q, want persisted %q", got.ApprovalCode, original.ApprovalCode)
	}

	var notifications int
	if err := h.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM owner_notifications WHERE action_id = $1`, original.ActionID,
	).Scan(&notifications); err != nil {
		t.Fatalf("count notifications: %v", err)
	}
	if notifications != 1 {
		t.Fatalf("notifications=%d, want one idempotent approval notification", notifications)
	}
}

// TestHandleProposeReply_NotificationEnqueueFailureFailsJobTiedCall covers a
// Codex finding on #307: a transient InsertOwnerNotification failure used to
// be logged and swallowed, still returning 200 — the action was durably
// persisted but the owner had no way to ever learn its approval code, since
// (contrary to the removed comment's claim) neither /mctl leads nor
// /mctl show surfaces a pending action's code. For a job-tied request this
// is safe to turn into a real failure: InsertAgentAction is idempotent on
// (job_id, action_type) and InsertOwnerNotification is idempotent on
// action_id, so a caller retry after a 500 cannot create a duplicate action
// or a duplicate notification — it lands on the exact same rows.
func TestHandleProposeReply_NotificationEnqueueFailureFailsJobTiedCall(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:notif-fail", conv.ID)
	claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}
	req := proposeReplyRequest{
		ConversationID: conv.ID, JobID: jobID, Attempt: claimed[0].Attempts,
		Text: "Thanks for reaching out!",
	}

	// Force InsertOwnerNotification to fail with a genuine SQL error (not a
	// validation error) by renaming its target table out from under it —
	// the preceding InsertAgentAction call (a different table) still
	// succeeds, exactly reproducing "the action is durably persisted but the
	// notification insert fails transiently".
	if _, err := h.store.DB.ExecContext(context.Background(),
		`ALTER TABLE owner_notifications RENAME TO owner_notifications_gone`); err != nil {
		t.Fatalf("rename table: %v", err)
	}

	rec := h.do("POST", "/actions/propose_reply", req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when the notification cannot be queued, body=%s", rec.Code, rec.Body.String())
	}

	if _, err := h.store.GetAgentJob(context.Background(), h.userID, jobID); err != nil {
		t.Fatalf("job should still exist for retry: %v", err)
	}

	// Restore the table and retry — must land on the SAME action/approval
	// code (idempotent), not mint a second draft.
	if _, err := h.store.DB.ExecContext(context.Background(),
		`ALTER TABLE owner_notifications_gone RENAME TO owner_notifications`); err != nil {
		t.Fatalf("restore table: %v", err)
	}
	rec2 := h.do("POST", "/actions/propose_reply", req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200, body=%s", rec2.Code, rec2.Body.String())
	}
	var resp actionResponse
	decodeBody(t, rec2, &resp)
	action2, err := h.store.GetAgentActionByCode(context.Background(), h.userID, resp.ApprovalCode)
	if err != nil {
		t.Fatalf("lookup by code: %v", err)
	}
	if action2.ID != resp.ActionID {
		t.Fatalf("code resolves to action %d, want %d", action2.ID, resp.ActionID)
	}
	notifs, err := h.store.ListPendingOwnerNotifications(context.Background(), 50)
	if err != nil {
		t.Fatalf("list pending notifications: %v", err)
	}
	if len(notifs) != 1 {
		t.Fatalf("pending notifications = %d, want exactly 1 (no duplicate from the retry)", len(notifs))
	}
}

func TestHandleProposeReply_StandaloneActionAndNotificationAreAtomic(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv := h.seedConversation(555)
	req := proposeReplyRequest{
		ConversationID: conv.ID,
		Text:           "Thanks for reaching out!",
	}

	if _, err := h.store.DB.ExecContext(context.Background(),
		`ALTER TABLE owner_notifications RENAME TO owner_notifications_gone`); err != nil {
		t.Fatalf("rename table: %v", err)
	}

	rec := h.do("POST", "/actions/propose_reply", req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when the notification cannot be queued, body=%s", rec.Code, rec.Body.String())
	}

	var actions int
	if err := h.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM agent_actions WHERE user_id = $1`, h.userID,
	).Scan(&actions); err != nil {
		t.Fatalf("count actions: %v", err)
	}
	if actions != 0 {
		t.Fatalf("actions=%d, want transaction rollback after notification failure", actions)
	}

	if _, err := h.store.DB.ExecContext(context.Background(),
		`ALTER TABLE owner_notifications_gone RENAME TO owner_notifications`); err != nil {
		t.Fatalf("restore table: %v", err)
	}

	rec = h.do("POST", "/actions/propose_reply", req)
	if rec.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp actionResponse
	decodeBody(t, rec, &resp)
	if resp.Status != db.ActionPendingApproval || resp.ApprovalCode == "" {
		t.Fatalf("response status/code=%q/%q, want pending approval with code", resp.Status, resp.ApprovalCode)
	}

	if err := h.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM agent_actions WHERE user_id = $1`, h.userID,
	).Scan(&actions); err != nil {
		t.Fatalf("count actions after retry: %v", err)
	}
	if actions != 1 {
		t.Fatalf("actions=%d, want one committed action", actions)
	}

	var notifications int
	if err := h.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM owner_notifications WHERE action_id = $1`, resp.ActionID,
	).Scan(&notifications); err != nil {
		t.Fatalf("count notifications: %v", err)
	}
	if notifications != 1 {
		t.Fatalf("notifications=%d, want one committed notification", notifications)
	}
}

func TestHandleProposeReply_DeniesURLInReply(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv := h.seedConversation(555)

	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, Text: "Check out https://example.com for details",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp actionResponse
	decodeBody(t, rec, &resp)
	if resp.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", resp.Decision)
	}
	if resp.ApprovalCode != "" {
		t.Fatalf("approval code = %q, want empty on deny", resp.ApprovalCode)
	}
}

func TestHandleProposeReply_UnknownConversation(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: 999999, Text: "hi",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleJobComplete_RequiresPersistedAction(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:2", conv.ID)
	// Claim it first, like a real worker would via POST /jobs/claim.
	if _, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1); err != nil {
		t.Fatalf("claim: %v", err)
	}

	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/complete", completeJobRequest{
		Attempt: 1, Status: db.JobCompleted,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (no action persisted yet), body=%s", rec.Code, rec.Body.String())
	}

	// Now propose a reply (persists an action tied to the job), then complete
	// should succeed.
	proposeRec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, JobID: jobID, Attempt: 1, Text: "Thanks!",
	})
	if proposeRec.Code != http.StatusOK {
		t.Fatalf("propose status = %d, body=%s", proposeRec.Code, proposeRec.Body.String())
	}
	var proposed actionResponse
	decodeBody(t, proposeRec, &proposed)

	rec2 := h.do("POST", "/jobs/"+itoaTest(jobID)+"/complete", completeJobRequest{
		Attempt: 1, Status: db.JobCompleted, ResultActionID: int64Ptr(proposed.ActionID),
	})
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec2.Code, rec2.Body.String())
	}
	statusRec := h.do("GET", "/jobs/"+itoaTest(jobID), nil)
	var completed jobStatusResponse
	decodeBody(t, statusRec, &completed)
	if completed.ResultActionID != proposed.ActionID || completed.ResultLeadID != 0 {
		t.Fatalf("completed result refs = action:%d lead:%d, want action:%d",
			completed.ResultActionID, completed.ResultLeadID, proposed.ActionID)
	}
}

func TestHandleJobComplete_LegacyRolloutBridge(t *testing.T) {
	h := newHarness(t)
	h.srv.AllowLegacyJobCompletion = true
	jobID := h.seedJob("evt:v1:1:1:legacy-complete", 0)
	claimed, err := h.store.ClaimAgentJobs(context.Background(), "legacy-worker", h.userID, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}

	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/complete", completeJobRequest{
		Attempt: claimed[0].Attempts, Status: db.JobCompleted,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Deprecation") == "" || rec.Header().Get("Sunset") == "" {
		t.Fatalf("missing deprecation headers: %v", rec.Header())
	}
}

func TestHandleJobComplete_FailedNeedsNoAction(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:3", conv.ID)
	if _, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1); err != nil {
		t.Fatalf("claim: %v", err)
	}
	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/complete", completeJobRequest{
		Attempt: 1, Status: db.JobFailed, Note: "model error",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAutopilotPause_TogglesBothWays(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeGuarded)

	rec := h.do("POST", "/autopilot/pause", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]bool
	decodeBody(t, rec, &body)
	if !body["autopilot_paused"] {
		t.Fatalf("expected paused=true by default")
	}

	rec2 := h.do("POST", "/autopilot/pause", autopilotPauseRequest{Paused: boolPtr(false)})
	decodeBody(t, rec2, &body)
	if body["autopilot_paused"] {
		t.Fatalf("expected paused=false after explicit resume")
	}
}

func TestHandlePolicy_NoProfile404(t *testing.T) {
	h := newHarness(t)
	rec := h.do("GET", "/policy", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleRecruiterProfile_NotConfigured(t *testing.T) {
	h := newHarness(t)
	rec := h.do("GET", "/recruiters/555", nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

// fakeOwnerProfileProvider records the internal tenant id used for lookup.
type fakeOwnerProfileProvider struct {
	gotUserID int64
	err       error
}

func (f *fakeOwnerProfileProvider) PublicProfile(_ context.Context, userID, _ int64) (map[string]any, error) {
	f.gotUserID = userID
	if f.err != nil {
		return nil, f.err
	}
	return map[string]any{"identity": map[string]any{"name": "Jane Doe"}}, nil
}

func TestHandleRecruiterProfile_TenantWithoutDocumentNotFound(t *testing.T) {
	h := newHarness(t)
	h.srv.WithProfile(&fakeOwnerProfileProvider{err: db.ErrAgentOwnerProfileNotFound})
	rec := h.do("GET", "/recruiters/555", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleRecruiterProfile_UsesAuthenticatedTenant(t *testing.T) {
	h := newHarness(t)
	provider := &fakeOwnerProfileProvider{}
	h.srv.WithProfile(provider)
	rec := h.do("GET", "/recruiters/555", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if provider.gotUserID != h.userID {
		t.Fatalf("provider user id = %d, want authenticated internal user id %d", provider.gotUserID, h.userID)
	}
}

func TestHandleSaveLead_RoundTrip(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	rec := h.do("POST", "/leads", saveLeadRequest{
		ConversationID: conv.ID, Company: "Acme", Role: "Backend Engineer",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]int64
	decodeBody(t, rec, &body)

	rec2 := h.do("GET", "/leads/"+itoaTest(body["lead_id"]), nil)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec2.Code)
	}
	var lead leadDTO
	decodeBody(t, rec2, &lead)
	if lead.Company != "Acme" {
		t.Fatalf("company = %q, want Acme", lead.Company)
	}
}

func TestHandleRequestOwnerApproval_AlwaysAllowed(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	rec := h.do("POST", "/actions/request_owner_approval", ownerNotifyRequest{
		Text: "Should I mention my current salary?",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleNotifySummary(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)

	rec := h.do("POST", "/notify/summary", ownerNotifyRequest{
		Text: "Recruiter from Acme reached out about a Backend role.",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]int64
	decodeBody(t, rec, &body)
	if body["action_id"] == 0 || body["notification_id"] == 0 {
		t.Fatalf("body = %v, want non-zero action_id and notification_id", body)
	}

	action, err := h.store.GetAgentAction(context.Background(), h.userID, body["action_id"])
	if err != nil {
		t.Fatalf("lookup action: %v", err)
	}
	if action.ActionType != db.ActionTypeOwnerSummary {
		t.Fatalf("action type = %q, want %q", action.ActionType, db.ActionTypeOwnerSummary)
	}

	rec2 := h.do("POST", "/notify/summary", ownerNotifyRequest{Text: ""})
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("empty text status = %d, want 400", rec2.Code)
	}
}

// TestHandleOwnerFacing_KillSwitchBlocksNotification guards against the P2
// found in review: handleOwnerFacing used to ignore policy.Evaluate's
// verdict entirely, so an engaged AGENT_KILL_SWITCH still let the two
// owner-messaging endpoints insert an executed action and queue a
// notification. The kill switch must actually stop them.
func TestHandleOwnerFacing_KillSwitchBlocksNotification(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	h.srv.GlobalKill = true

	rec := h.do("POST", "/notify/summary", ownerNotifyRequest{Text: "Daily digest"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (denial is a normal response, not an error), body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		ActionID       int64  `json:"action_id"`
		NotificationID int64  `json:"notification_id"`
		Decision       string `json:"decision"`
	}
	decodeBody(t, rec, &body)
	if body.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", body.Decision)
	}
	if body.NotificationID != 0 {
		t.Fatalf("notification_id = %d, want 0 (kill switch must block the notification too)", body.NotificationID)
	}
	action, err := h.store.GetAgentAction(context.Background(), h.userID, body.ActionID)
	if err != nil {
		t.Fatalf("lookup action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("action status = %q, want denied", action.Status)
	}

	// Confirm no notification row was queued at all, not just that the
	// response omitted it.
	notifs, err := h.store.DB.QueryContext(context.Background(),
		`SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1`, h.userID)
	if err != nil {
		t.Fatalf("count notifications: %v", err)
	}
	defer notifs.Close()
	var count int
	if notifs.Next() {
		if err := notifs.Scan(&count); err != nil {
			t.Fatalf("scan count: %v", err)
		}
	}
	if count != 0 {
		t.Fatalf("owner_notifications count = %d, want 0", count)
	}
}

// TestHandleOwnerFacing_RedeliveryDoesNotDuplicateNotification guards
// against the P2 found in review: InsertAgentAction is idempotent per
// (job_id, action_type), but InsertOwnerNotification previously had no such
// guard, so a redelivered job (worker crashed after notify/summary but
// before completing it) would queue a second copy of the same notification.
func TestHandleOwnerFacing_RedeliveryDoesNotDuplicateNotification(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:notify-redelivery", conv.ID)
	claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}

	req := ownerNotifyRequest{JobID: jobID, Attempt: claimed[0].Attempts, Text: "Recruiter from Acme reached out."}

	rec1 := h.do("POST", "/notify/summary", req)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first status = %d, body=%s", rec1.Code, rec1.Body.String())
	}
	var body1 map[string]int64
	decodeBody(t, rec1, &body1)

	rec2 := h.do("POST", "/notify/summary", req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	var body2 map[string]int64
	decodeBody(t, rec2, &body2)

	if body2["action_id"] != body1["action_id"] {
		t.Fatalf("redelivery action_id = %d, want the original %d", body2["action_id"], body1["action_id"])
	}
	if body2["notification_id"] != body1["notification_id"] {
		t.Fatalf("redelivery notification_id = %d, want the original %d (must not queue a duplicate)",
			body2["notification_id"], body1["notification_id"])
	}

	var count int
	if err := h.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1`, h.userID,
	).Scan(&count); err != nil {
		t.Fatalf("count notifications: %v", err)
	}
	if count != 1 {
		t.Fatalf("owner_notifications count = %d, want exactly 1", count)
	}
}

func TestHandleOwnerFacing_RedeliveryUsesPersistedActionState(t *testing.T) {
	t.Run("denied action stays denied after kill switch is lifted", func(t *testing.T) {
		h := newHarness(t)
		h.seedProfile(db.AgentModeObserve)
		conv := h.seedConversation(555)
		jobID := h.seedJob("evt:v1:1:555:notify-denied-replay", conv.ID)
		claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
		if err != nil || len(claimed) != 1 {
			t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
		}
		req := ownerNotifyRequest{
			JobID: jobID, Attempt: claimed[0].Attempts,
			Text: "Original summary",
		}

		h.srv.GlobalKill = true
		first := h.do("POST", "/notify/summary", req)
		if first.Code != http.StatusOK {
			t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
		}
		var original struct {
			ActionID int64  `json:"action_id"`
			Decision string `json:"decision"`
		}
		decodeBody(t, first, &original)
		if original.Decision != db.PolicyDeny {
			t.Fatalf("first decision=%q, want deny", original.Decision)
		}

		h.srv.GlobalKill = false
		req.Text = "Changed replay text"
		replay := h.do("POST", "/notify/summary", req)
		if replay.Code != http.StatusOK {
			t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
		}
		var got struct {
			ActionID       int64  `json:"action_id"`
			NotificationID int64  `json:"notification_id"`
			Decision       string `json:"decision"`
		}
		decodeBody(t, replay, &got)
		if got.ActionID != original.ActionID || got.Decision != db.PolicyDeny || got.NotificationID != 0 {
			t.Fatalf("replay=%+v, want original denied action without notification", got)
		}
	})

	t.Run("executed action keeps original body after kill switch engages", func(t *testing.T) {
		h := newHarness(t)
		h.seedProfile(db.AgentModeObserve)
		conv := h.seedConversation(555)
		jobID := h.seedJob("evt:v1:1:555:notify-executed-replay", conv.ID)
		claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
		if err != nil || len(claimed) != 1 {
			t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
		}
		req := ownerNotifyRequest{
			JobID: jobID, Attempt: claimed[0].Attempts,
			Text: "Original summary",
		}

		first := h.do("POST", "/notify/summary", req)
		if first.Code != http.StatusOK {
			t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
		}
		var original struct {
			ActionID       int64 `json:"action_id"`
			NotificationID int64 `json:"notification_id"`
		}
		decodeBody(t, first, &original)

		h.srv.GlobalKill = true
		req.Text = "Changed replay text"
		replay := h.do("POST", "/notify/summary", req)
		if replay.Code != http.StatusOK {
			t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
		}
		var got struct {
			ActionID       int64 `json:"action_id"`
			NotificationID int64 `json:"notification_id"`
		}
		decodeBody(t, replay, &got)
		if got != original {
			t.Fatalf("replay=%+v, want original ids %+v", got, original)
		}

		notifs, err := h.store.ListPendingOwnerNotifications(context.Background(), 10)
		if err != nil {
			t.Fatalf("list notifications: %v", err)
		}
		if len(notifs) != 1 || notifs[0].Body != "Original summary" {
			t.Fatalf("notifications=%+v, want one notification with original persisted body", notifs)
		}
	})
}

// TestHandleProposeReply_RejectsMismatchedJobConversation guards against the
// P1-adjacent P2 found in review: a worker must not be able to pair a job
// tied to one conversation with a different conversation_id in the request
// body — that would evaluate policy against the wrong conversation while
// persisting a result against the unrelated job.
func TestHandleProposeReply_RejectsMismatchedJobConversation(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv1 := h.seedConversation(555)
	conv2 := h.seedConversation(556)
	jobID := h.seedJob("evt:v1:1:555:mismatch", conv1.ID) // job tied to conv1

	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv2.ID, JobID: jobID, Text: "hi", // but body claims conv2
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleJobComplete_LeadOnlyJobCanComplete guards against the P2 found
// in review: a job whose only durable result is a saved lead (no reply
// proposed, no owner notification sent) must still be completable — the
// 409 invariant is "some durable result exists", not "an agent_actions row
// exists specifically".
func TestHandleJobComplete_LeadOnlyJobCanComplete(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:lead-only", conv.ID)
	claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}

	leadRec := h.do("POST", "/leads", saveLeadRequest{
		ConversationID: conv.ID, JobID: jobID, Attempt: claimed[0].Attempts, Company: "Acme",
	})
	if leadRec.Code != http.StatusOK {
		t.Fatalf("save lead status = %d, body=%s", leadRec.Code, leadRec.Body.String())
	}
	var saved map[string]int64
	decodeBody(t, leadRec, &saved)

	completeRec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/complete", completeJobRequest{
		Attempt: claimed[0].Attempts, Status: db.JobCompleted, ResultLeadID: int64Ptr(saved["lead_id"]),
	})
	if completeRec.Code != http.StatusOK {
		t.Fatalf("complete status = %d, want 200 (lead save alone should satisfy the invariant), body=%s",
			completeRec.Code, completeRec.Body.String())
	}
}

func TestHandleConversationContext(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)

	// No lead yet: "lead" must be null, not an error.
	rec := h.do("GET", "/conversations/"+itoaTest(conv.ID)+"/context", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Conversation conversationDTO          `json:"conversation"`
		Messages     []conversationMessageDTO `json:"messages"`
		Lead         *leadDTO                 `json:"lead"`
	}
	decodeBody(t, rec, &body)
	if body.Conversation.ID != conv.ID {
		t.Fatalf("conversation id = %d, want %d", body.Conversation.ID, conv.ID)
	}
	if body.Lead != nil {
		t.Fatalf("lead = %+v, want nil before any lead is saved", body.Lead)
	}

	// Save a lead, then the context response must surface it.
	if _, err := h.store.UpsertJobLead(context.Background(), db.JobLead{
		UserID: h.userID, ConversationID: conv.ID, Company: "Acme",
	}); err != nil {
		t.Fatalf("upsert lead: %v", err)
	}
	rec2 := h.do("GET", "/conversations/"+itoaTest(conv.ID)+"/context", nil)
	decodeBody(t, rec2, &body)
	if body.Lead == nil || body.Lead.Company != "Acme" {
		t.Fatalf("lead = %+v, want company Acme", body.Lead)
	}

	// limit query param is honored and bounded.
	rec3 := h.do("GET", "/conversations/"+itoaTest(conv.ID)+"/context?limit=abc", nil)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("bad limit status = %d, want 400", rec3.Code)
	}

	rec404 := h.do("GET", "/conversations/999999/context", nil)
	if rec404.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec404.Code)
	}
}

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(v int64) *int64 { return &v }

// itoaTest formats an int64 for URL path construction in tests.
func itoaTest(v int64) string {
	return strconv.FormatInt(v, 10)
}
